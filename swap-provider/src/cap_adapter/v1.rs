//! The `version` wire of Paykit Capabilities §8.1 and §13.1 over `direct/1`.
//!
//! Each kind becomes the same [`SwapMessage`] the older wire's does, so the engine and its native
//! types are unchanged. The owner is the connection's authenticated sender: a commit's `sig` is
//! checked when present, and not required until Paykit v0.2.

use super::CapState;
use crate::{handle_message, now_unix, ExecCtx, SharedOffer};
use bitcoin::hashes::{sha256, Hash};
use serde_json::Value;
use std::sync::Arc;
use swap_common::messages::Quote as NativeQuote;
use swap_common::messages::*;
use swap_common::paykit_cap::v1::*;
use swap_common::paykit_cap::v1::{Quote, OWNER_REF_MAX_LEN};
use swap_common::paykit_cap::{jcs, seal_invoice};
use swap_common::SwapDirection;
use tracing::{info, warn};
use uuid::Uuid;

pub(crate) use swap_common::paykit_cap::v1::is_v1;

/// How many replies are kept for retries. A retry comes within seconds of its first try.
const REPLIES_KEPT: usize = 1024;

/// Terms this provider signed, for the owner they name.
pub(crate) struct Issued {
    terms: Terms,
}

/// A reply kept for a retry of the same event.
pub(crate) struct Replied {
    sender: String,
    event_id: Uuid,
    /// What the event said, so a different message reusing its id is not answered as a retry.
    digest: [u8; 32],
    /// `None` while the event is still being answered.
    reply: Option<Message>,
}

/// Marks an event as being answered, and clears the mark unless an answer was kept for it,
/// including when the answer is dropped by its timeout.
struct InFlight<'a> {
    cap: &'a CapState,
    sender: &'a str,
    event_id: Uuid,
}

impl InFlight<'_> {
    fn keep(&self, reply: &Message) {
        let mut replies = self
            .cap
            .v1_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(kept) = replies
            .iter_mut()
            .find(|r| names(r, self.sender, self.event_id))
        {
            kept.reply = Some(reply.clone());
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut replies = self
            .cap
            .v1_replies
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        replies.retain(|r| r.reply.is_some() || !names(r, self.sender, self.event_id));
    }
}

impl CapState {
    fn envelope(&self, flow_id: Uuid) -> Envelope {
        Envelope::new(PROVIDER_APP_ID, flow_id, self.generation())
    }

    fn refusal(&self, to: Answering, code: RejectCode, reason: impl Into<String>) -> Message {
        Message::Refusal(Refusal {
            envelope: self.envelope(to.flow_id),
            event_id: Uuid::new_v4(),
            rfq_event_id: to.rfq,
            commit_event_id: to.commit,
            body: RefusalBody {
                code: code.as_str().into(),
                reason: reason.into(),
            },
        })
    }
}

/// The event a reply answers.
#[derive(Clone, Copy)]
struct Answering {
    flow_id: Uuid,
    rfq: Option<Uuid>,
    commit: Option<Uuid>,
}

/// Answer one request in the `version` wire.
pub(crate) async fn handle(
    ctx: ExecCtx,
    offer: SharedOffer,
    request: pubky_transport::p2p::DirectRpc,
) {
    let reply = answer(&ctx, offer, &request.remote_key, request.message).await;
    match serde_json::to_vec(&reply) {
        Ok(bytes) => {
            let _ = request.reply.send(bytes);
        }
        Err(error) => warn!("could not encode a paykit-cap reply: {error}"),
    }
}

async fn answer(ctx: &ExecCtx, offer: SharedOffer, sender: &str, value: Value) -> Message {
    let cap = &ctx.cap;
    let unread = Answering {
        flow_id: value
            .get("flow_id")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
        rfq: None,
        commit: None,
    };
    let digest = match jcs(&value) {
        Ok(bytes) => sha256::Hash::hash(&bytes).to_byte_array(),
        Err(error) => {
            return cap.refusal(unread, RejectCode::InvalidRequest, error.to_string());
        }
    };
    let message = match Message::parse(value) {
        Ok(message) => message,
        Err(error) => {
            return cap.refusal(
                unread,
                RejectCode::InvalidRequest,
                format!("unreadable: {error}"),
            )
        }
    };
    let envelope = message.envelope().clone();
    let event_id = message.event_id();
    if !envelope.supported() {
        return cap.refusal(
            unread,
            RejectCode::UnsupportedProtocol,
            format!("this provider speaks version {VERSION} of {PROFILE}"),
        );
    }
    let in_flight = match begin(cap, sender, event_id, digest, envelope.flow_id) {
        Ok(in_flight) => in_flight,
        Err(reply) => return *reply,
    };
    let reply = match message {
        Message::Rfq(rfq) => quote(ctx, offer, sender, rfq).await,
        Message::Commit(commit) => contract(ctx, offer, sender, *commit).await,
        Message::StatusRequest(request) => status(ctx, offer, sender, request).await,
        _ => cap.refusal(unread, RejectCode::InvalidRequest, "not a request kind"),
    };
    // A quote or a contract is the answer to that event. A refusal may not be: the same event
    // retried later can be admitted.
    if matches!(reply, Message::Quote(_) | Message::Contract(_)) {
        in_flight.keep(&reply);
    }
    reply
}

/// Mark `event_id` from `sender` as being answered. A retry instead gets the reply already sent,
/// or a refusal while the first try is still being answered or when the id names another
/// message. The check and the mark share one lock, so two tries cannot both be admitted.
fn begin<'a>(
    cap: &'a CapState,
    sender: &'a str,
    event_id: Uuid,
    digest: [u8; 32],
    flow_id: Uuid,
) -> Result<InFlight<'a>, Box<Message>> {
    let mut replies = cap.v1_replies.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(kept) = replies.iter().find(|r| names(r, sender, event_id)) {
        let to = Answering {
            flow_id,
            rfq: None,
            commit: None,
        };
        let reply = match (&kept.reply, kept.digest == digest) {
            (Some(reply), true) => reply.clone(),
            (None, true) => cap.refusal(
                to,
                RejectCode::Pending,
                "this event is still being answered",
            ),
            (_, false) => cap.refusal(
                to,
                RejectCode::InvalidRequest,
                "event_id already names another message",
            ),
        };
        return Err(Box::new(reply));
    }
    // Only a finished reply makes room. Dropping the mark of an event still being answered would
    // admit another message under its id beside it.
    if replies.len() >= REPLIES_KEPT {
        if let Some(oldest) = replies.iter().position(|r| r.reply.is_some()) {
            replies.remove(oldest);
        }
    }
    replies.push_back(Replied {
        sender: sender.to_string(),
        event_id,
        digest,
        reply: None,
    });
    Ok(InFlight {
        cap,
        sender,
        event_id,
    })
}

fn names(replied: &Replied, sender: &str, event_id: Uuid) -> bool {
    replied.event_id == event_id && pubky_transport::same_pubky(&replied.sender, sender)
}

/// Run `message` through the engine as `sender` and read its one reply.
async fn engine(
    ctx: &ExecCtx,
    offer: Option<&SwapOffer>,
    sender: &str,
    message: SwapMessage,
) -> Option<SwapMessage> {
    let (reply_to, replied) = tokio::sync::oneshot::channel();
    let mut ctx = ctx.clone();
    ctx.transport = Arc::new(ctx.transport.root_key(reply_to));
    if let Err(error) = handle_message(&ctx, offer, sender, message).await {
        warn!("could not handle paykit-cap request: {error:#}");
    }
    replied
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn refusal_from(cap: &CapState, to: Answering, reject: Reject) -> Message {
    let code = reject.code().unwrap_or(RejectCode::InternalError);
    cap.refusal(to, code, reject.reason)
}

async fn quote(ctx: &ExecCtx, offer: SharedOffer, sender: &str, rfq: Rfq) -> Message {
    let cap = &ctx.cap;
    let to = Answering {
        flow_id: rfq.envelope.flow_id,
        rfq: Some(rfq.event_id),
        commit: None,
    };
    if !atomicity_met(&rfq.atomicity_min) {
        return cap.refusal(
            to,
            RejectCode::AtomicityUnsupported,
            format!("{ATOMICITY} does not meet {}", rfq.atomicity_min),
        );
    }
    let current = offer.read().await.clone();
    // Without an offer the engine refuses with `pricing_unavailable`.
    if let Some(current) = &current {
        if !is_edge(current, &rfq.body) {
            return cap.refusal(
                to,
                RejectCode::UnsupportedRoute,
                format!(
                    "no {:?} edge from {} to {}",
                    rfq.body.dir, rfq.body.from, rfq.body.to
                ),
            );
        }
    }
    let now = now_unix();
    if rfq.valid_until <= now {
        return cap.refusal(to, RejectCode::InvalidRequest, "the rfq has expired");
    }
    let request = QuoteRequest {
        request_id: Some(rfq.event_id),
        offer_id: rfq.body.offer_id,
        client_pkarr: sender.to_string(),
        direction: rfq.body.dir,
        amount_sat: rfq.body.amount_sat.0,
        protocol_version: PROTOCOL_VERSION,
        // The RFQ has no `features`: every reverse owner on this wire takes the claimable hint,
        // which its wake grant needs.
        features: claimable_hint(rfq.body.dir),
    };
    let reply = engine(
        ctx,
        current.as_ref(),
        sender,
        SwapMessage::QuoteRequest(request),
    )
    .await;
    let native = match reply {
        Some(SwapMessage::Quote(native)) => native,
        Some(SwapMessage::Reject(reject)) => return refusal_from(cap, to, reject),
        _ => return cap.refusal(to, RejectCode::InternalError, "no reply"),
    };
    let lock_profiles = current
        .as_ref()
        .map(swap_common::cap_descriptor::lock_profiles)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| serde_json::from_value(Value::String(p)).ok())
        .collect();
    let (signer, generation) = cap.signing();
    let mut quote = Quote {
        envelope: Envelope::new(PROVIDER_APP_ID, rfq.envelope.flow_id, generation),
        event_id: Uuid::new_v4(),
        rfq_event_id: rfq.event_id,
        body: QuoteBody {
            quote_id: native.quote_id,
            offer_id: native.offer_id,
            dir: native.direction,
            amount_sat: Sat(native.amount_sat),
            service_fee_sat: Sat(native.fee_sat.saturating_sub(native.onchain_fee_sat)),
            onchain_fee_sat: Sat(native.onchain_fee_sat),
            total_sat: Sat(native.total_sat),
            htlc_timeout_blocks: native.htlc_timeout_blocks,
            required_confirmations: native.required_confirmations,
            fund_within_secs: native.fund_within_secs,
            lock_profiles,
        },
        atomicity: ATOMICITY.into(),
        valid_until: native.valid_until_unix,
        sig: String::new(),
    };
    let terms = terms(sender, &rfq, &cap.provider, &quote);
    let hash = match terms.hash() {
        Ok(hash) => hash,
        Err(error) => {
            warn!("could not hash paykit-cap terms: {error}");
            return cap.refusal(to, RejectCode::InternalError, "could not sign the quote");
        }
    };
    quote.sig = sign(signer.as_ref(), &hash);
    let mut issued = cap.v1_terms.lock().await;
    issued.retain(|_, issued| issued.terms.quote.valid_until > now);
    issued.insert(hex::encode(hash), Issued { terms });
    Message::Quote(quote)
}

fn claimable_hint(direction: SwapDirection) -> Vec<String> {
    match direction {
        SwapDirection::Reverse => vec![CLAIMABLE_HINT_FEATURE.to_string()],
        SwapDirection::Submarine => Vec::new(),
    }
}

async fn contract(ctx: &ExecCtx, offer: SharedOffer, sender: &str, commit: Commit) -> Message {
    let cap = &ctx.cap;
    let to = Answering {
        flow_id: commit.envelope.flow_id,
        rfq: None,
        commit: Some(commit.event_id),
    };
    let refuse = |code: RejectCode, reason: String| cap.refusal(to, code, reason);
    if !commit.body.owner_ref_is_valid() {
        return refuse(
            RejectCode::InvalidRequest,
            format!("owner_ref must be at most {OWNER_REF_MAX_LEN} printable ASCII characters"),
        );
    }
    let terms = match terms_for(ctx, sender, &commit).await {
        Ok(terms) => terms,
        Err((code, reason)) => return refuse(code, reason),
    };
    if commit.sig.is_some() {
        // Generation 0 is the root key the connection authenticated, as it is for the provider.
        let key = match commit.envelope.key_generation {
            0 => pubky_transport::p2p::pubky_to_endpoint_id(sender)
                .map(|id| Some(*id.as_bytes()))
                .map_err(anyhow::Error::from),
            generation => (cap.owner_keys)(sender.to_string(), generation).await,
        };
        let checked = match key {
            Ok(Some(key)) => commit.verify_owner(&key).map_err(|e| e.to_string()),
            Ok(None) => Err(format!(
                "no capability signing key for generation {}",
                commit.envelope.key_generation
            )),
            Err(error) => Err(format!("could not read the owner's delegation: {error:#}")),
        };
        if let Err(reason) = checked {
            return refuse(
                RejectCode::InvalidRequest,
                format!("owner signature: {reason}"),
            );
        }
    }
    let quote = &terms.quote.body;
    if !quote.lock_profiles.contains(&commit.body.lock_profile) {
        return refuse(
            RejectCode::InvalidRequest,
            "the lock profile is not one the quote offers".into(),
        );
    }
    let request = SwapRequest {
        script_type: commit.body.lock_profile,
        quote_id: quote.quote_id,
        client_pkarr: sender.to_string(),
        direction: quote.dir,
        payment_hash_hex: commit.body.payment_hash.clone(),
        client_claim_pubkey_hex: commit.body.claim_pubkey.clone(),
        client_refund_pubkey_hex: commit.body.refund_pubkey.clone(),
        invoice: commit.body.invoice.clone(),
        owner_ref: commit.body.owner_ref.clone(),
    };
    let current = offer.read().await.clone();
    let reply = engine(
        ctx,
        current.as_ref(),
        sender,
        SwapMessage::SwapRequest(request),
    )
    .await;
    match reply {
        Some(SwapMessage::SwapAccept(accept)) => match stored_contract(ctx, &commit, &accept) {
            Ok(contract) => Message::Contract(Box::new(contract)),
            Err(error) => {
                warn!("could not sign a paykit-cap contract: {error:#}");
                refuse(
                    RejectCode::InternalError,
                    "could not sign the contract".into(),
                )
            }
        },
        Some(SwapMessage::Reject(reject)) if reject.code() == Some(RejectCode::Pending) => {
            match reject.swap_id {
                Some(swap_id) => Message::Status(Status {
                    envelope: cap.envelope(commit.envelope.flow_id),
                    event_id: Uuid::new_v4(),
                    commit_event_id: Some(commit.event_id),
                    leg: 0,
                    body: StatusBody {
                        swap_id,
                        state: swap_common::paykit_cap::STATE_PENDING.into(),
                        detail: swap_common::paykit_cap::STATE_PENDING.into(),
                        reference: None,
                    },
                }),
                None => refusal_from(cap, to, reject),
            }
        }
        Some(SwapMessage::Reject(reject)) => refusal_from(cap, to, reject),
        _ => refuse(RejectCode::InternalError, "no reply".into()),
    }
}

/// The terms `commit` names, for `sender` and the commit's flow and generation. Terms this run
/// issued are taken from memory. Otherwise the commit must carry them signed by this provider,
/// and the quote goes back in the book if the book no longer holds it (#103).
async fn terms_for(
    ctx: &ExecCtx,
    sender: &str,
    commit: &Commit,
) -> Result<Terms, (RejectCode, String)> {
    let cap = &ctx.cap;
    let invalid = |reason: &str| (RejectCode::InvalidRequest, reason.to_string());
    let held = cap
        .v1_terms
        .lock()
        .await
        .get(&commit.terms_hash)
        .map(|issued| issued.terms.clone());
    let terms = match (held, &commit.quote) {
        (Some(terms), _) => terms,
        (None, Some(signed)) => {
            if signed.terms.provider != cap.provider {
                return Err(invalid("the quote names another provider"));
            }
            match cap.own_key(signed.terms.provider_key_generation) {
                Some(key) => signed
                    .check(commit, &key)
                    .map_err(|e| invalid(&format!("signed quote refused: {e}")))?,
                // A restart drops the keys of earlier generations, but a contract stored for
                // this very commit shows its terms were checked under one.
                None if contracted(ctx, commit, &signed.terms)? => {}
                None => return Err(invalid("the quote is not signed by this provider")),
            }
            signed.terms.clone()
        }
        (None, None) => {
            return Err((
                RejectCode::QuoteExpired,
                "unknown terms: send the signed quote with the commit".into(),
            ))
        }
    };
    if !pubky_transport::same_pubky(&terms.owner, sender) {
        return Err(invalid("the terms name another owner"));
    }
    if terms.profile != commit.envelope.profile || terms.flow_id != commit.envelope.flow_id {
        return Err(invalid("terms for another profile or flow"));
    }
    if terms.owner_key_generation != commit.envelope.key_generation {
        return Err(invalid("terms for another key generation"));
    }
    restore_quote(ctx, sender, &terms).await?;
    Ok(terms)
}

/// Whether `terms` are `commit`'s and the swap for their quote stored a contract for `commit`.
/// `commit_hash` covers `terms_hash`, so those are the terms that contract was signed on.
fn contracted(ctx: &ExecCtx, commit: &Commit, terms: &Terms) -> Result<bool, (RejectCode, String)> {
    let check = || -> anyhow::Result<bool> {
        if hex::encode(terms.hash()?) != commit.terms_hash {
            return Ok(false);
        }
        let commit_hash = hex::encode(commit.commit_hash()?);
        let record = crate::swap_for_quote(ctx.store.as_ref(), terms.quote.body.quote_id)?;
        Ok(record
            .and_then(|record| record.cap_v1_contract)
            .is_some_and(|stored| stored.commit_hash == commit_hash))
    };
    check().map_err(|error| {
        warn!("could not look up the contract for a commit: {error:#}");
        (
            RejectCode::InternalError,
            "could not check the quote".into(),
        )
    })
}

/// Put `terms`' quote back in the book when the book no longer holds it. The request that
/// follows runs every admission check as before.
async fn restore_quote(
    ctx: &ExecCtx,
    sender: &str,
    terms: &Terms,
) -> Result<(), (RejectCode, String)> {
    let body = &terms.quote.body;
    if ctx.quotes.lock().await.holds(body.quote_id) {
        return Ok(());
    }
    match crate::swap_for_quote(ctx.store.as_ref(), body.quote_id) {
        // The engine answers a replay of that swap from its record, and refuses anything else.
        // Checked before expiry, so a lost contract can be fetched again after the quote ends.
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => {
            warn!(
                "could not look up swaps for quote {}: {error:#}",
                body.quote_id
            );
            return Err((
                RejectCode::InternalError,
                "could not check the quote".into(),
            ));
        }
    }
    let now = now_unix();
    if terms.quote.valid_until <= now {
        return Err((
            RejectCode::QuoteExpired,
            "the signed quote has expired".into(),
        ));
    }
    let native = NativeQuote {
        request_id: None,
        quote_id: body.quote_id,
        offer_id: body.offer_id,
        direction: body.dir,
        amount_sat: body.amount_sat.0,
        fee_sat: body.service_fee_sat.0 + body.onchain_fee_sat.0,
        service_fee_sat: body.service_fee_sat.0,
        onchain_fee_sat: body.onchain_fee_sat.0,
        fee_rate_sat_vb: 0,
        total_sat: body.total_sat.0,
        htlc_timeout_blocks: body.htlc_timeout_blocks,
        required_confirmations: body.required_confirmations,
        valid_until_unix: terms.quote.valid_until,
        fund_within_secs: body.fund_within_secs,
        protocol_version: PROTOCOL_VERSION,
    };
    // Every reverse quote on this wire took the claimable hint when it was issued.
    let issued = crate::IssuedQuote::signed(sender, &native, body.dir == SwapDirection::Reverse);
    if ctx.quotes.lock().await.restore(body.quote_id, issued, now) {
        info!("Took back signed quote {} from {sender}", body.quote_id);
    }
    Ok(())
}

/// The contract stored with the swap for this commit, signing and storing one first if there is
/// none. The first one stored stands, so a replayed commit gets the bytes the first one got after
/// a restart or a rotation.
fn stored_contract(
    ctx: &ExecCtx,
    commit: &Commit,
    accept: &SwapAccept,
) -> anyhow::Result<Contract> {
    let commit_hash = hex::encode(commit.commit_hash()?);
    let stored = || -> anyhow::Result<Option<Contract>> {
        Ok(ctx
            .store
            .get(accept.swap_id)?
            .and_then(|record| record.cap_v1_contract)
            .filter(|stored| stored.commit_hash == commit_hash))
    };
    if let Some(stored) = stored()? {
        return Ok(stored);
    }
    let signed = signed_contract(&ctx.cap, commit, accept)?;
    ctx.store.mutate(accept.swap_id, &mut |record| {
        if record.cap_v1_contract.is_none() {
            record.cap_v1_contract = Some(signed.clone());
        }
    })?;
    Ok(stored()?.unwrap_or(signed))
}

/// The contract for `accept`. The event id is derived from the commit's.
fn signed_contract(
    cap: &CapState,
    commit: &Commit,
    accept: &SwapAccept,
) -> Result<Contract, swap_common::paykit_cap::CapError> {
    let (signer, generation) = cap.signing();
    let commit_hash = hex::encode(commit.commit_hash()?);
    let invoice_blob = seal_invoice(signer.as_ref(), accept);
    let body = contract_body(accept, invoice_blob.as_ref())?;
    let hash = contract_hash(&commit_hash, &body)?;
    let mut seed = b"paykit-cap/contract/event_id\0".to_vec();
    seed.extend(commit.event_id.as_bytes());
    seed.extend(accept.swap_id.as_bytes());
    let digest = sha256::Hash::hash(&seed).to_byte_array();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(Contract {
        envelope: Envelope::new(PROVIDER_APP_ID, commit.envelope.flow_id, generation),
        event_id: uuid::Builder::from_random_bytes(id).into_uuid(),
        commit_event_id: commit.event_id,
        commit_hash,
        body,
        sig: sign(signer.as_ref(), &hash),
        invoice_blob,
        lock: lock(accept),
    })
}

async fn status(
    ctx: &ExecCtx,
    offer: SharedOffer,
    sender: &str,
    request: StatusRequest,
) -> Message {
    let cap = &ctx.cap;
    let to = Answering {
        flow_id: request.envelope.flow_id,
        rfq: None,
        commit: None,
    };
    let native = SwapStatusRequest {
        request_id: Some(request.event_id),
        swap_id: request.body.swap_id,
        quote_id: request.body.quote_id,
    };
    let current = offer.read().await.clone();
    let reply = engine(
        ctx,
        current.as_ref(),
        sender,
        SwapMessage::SwapStatusRequest(native),
    )
    .await;
    match reply {
        Some(SwapMessage::SwapStatusSnapshot(snapshot)) => {
            Message::Status(status_of(cap, request.envelope.flow_id, None, &snapshot))
        }
        Some(SwapMessage::Reject(reject)) => refusal_from(cap, to, reject),
        _ => cap.refusal(to, RejectCode::InternalError, "no reply"),
    }
}

/// `snapshot` as a `paykit-cap.status`.
pub(crate) fn status_of(
    cap: &CapState,
    flow_id: Uuid,
    commit_event_id: Option<Uuid>,
    snapshot: &SwapStatusSnapshot,
) -> Status {
    let leg = snapshot.state.leg_status(
        snapshot.accept.direction,
        snapshot.funding_txid_hex.is_some(),
        false,
    );
    let name = |value: serde_json::Result<Value>| {
        value
            .ok()
            .and_then(|v| {
                v.as_str()
                    .or_else(|| v.get("state").and_then(Value::as_str))
                    .map(str::to_string)
            })
            .unwrap_or_default()
    };
    Status {
        envelope: cap.envelope(flow_id),
        event_id: Uuid::new_v4(),
        commit_event_id,
        leg: 0,
        body: StatusBody {
            swap_id: snapshot.accept.swap_id,
            state: name(serde_json::to_value(leg)),
            detail: name(serde_json::to_value(&snapshot.state)),
            reference: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full cache makes room from finished replies, so an event still being answered keeps
    /// its mark and its id cannot be reused beside it.
    #[test]
    fn a_full_cache_keeps_the_mark_of_an_event_being_answered() {
        let cap = CapState::ephemeral();
        let sender = pubky_transport::identity_from_secret(&[1; 32]);
        let answering = Uuid::new_v4();
        let _mark = begin(&cap, &sender, answering, [1; 32], Uuid::nil()).unwrap();
        for _ in 0..REPLIES_KEPT {
            let event_id = Uuid::new_v4();
            let done = begin(&cap, &sender, event_id, [2; 32], Uuid::nil()).unwrap();
            let to = Answering {
                flow_id: Uuid::nil(),
                rfq: Some(event_id),
                commit: None,
            };
            done.keep(&cap.refusal(to, RejectCode::InvalidRequest, "answered"));
        }
        let reused = begin(&cap, &sender, answering, [3; 32], Uuid::nil());
        match reused.err().as_deref() {
            Some(Message::Refusal(refusal)) => assert_eq!(refusal.body.code, "invalid_request"),
            Some(other) => panic!("expected a refusal, got {other:?}"),
            None => panic!("a second message was admitted under an id still being answered"),
        }
    }
}
