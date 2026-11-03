//! The `paykit-cap.*` kinds for `swap/1` at the provider edge.
//!
//! Each kind becomes a [`SwapMessage`] for `handle_message`, and its reply becomes a kind again.
//! The engine never sees a kind, and the owner is always the carrier's authenticated sender.

use std::collections::HashMap;
use std::sync::Arc;
use swap_common::paykit_cap::CapSigner;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Signed terms by quote id, held as long as the quote they answer.
// Only `direct/1` reads these, and it needs `iroh`.
#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
struct IssuedTerms {
    owner: String,
    terms_hash: String,
    expires_at_unix: u64,
}

#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
pub(crate) struct CapState {
    signer: Arc<dyn CapSigner>,
    /// This provider's pubky, which every quote it signs names beside the owner's.
    provider: String,
    terms: Mutex<HashMap<Uuid, IssuedTerms>>,
}

impl CapState {
    pub(crate) fn new(signer: Arc<dyn CapSigner>, provider: String) -> Self {
        Self {
            signer,
            provider,
            terms: Mutex::new(HashMap::new()),
        }
    }

    /// This provider's pubky, as its signed quotes name it.
    #[cfg(all(test, feature = "iroh"))]
    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    /// A key nobody holds, for builds and tests that never sign anything they keep.
    #[cfg(any(test, not(feature = "iroh")))]
    pub(crate) fn ephemeral() -> Self {
        let secret: [u8; 32] = rand::random();
        Self::new(
            Arc::new(swap_common::paykit_cap::Ed25519Signer::from_secret(&secret)),
            pubky_transport::identity_from_secret(&secret),
        )
    }
}

#[cfg(feature = "iroh")]
pub(crate) use direct::handle_cap_request;

#[cfg(feature = "iroh")]
mod direct {
    use super::*;
    use crate::{handle_message, now_unix, ExecCtx, SharedOffer};
    use swap_common::messages::*;
    use swap_common::paykit_cap::*;
    use swap_common::SwapDirection;
    use tracing::{info, warn};

    /// What the request was, for translating its reply.
    enum Asked {
        Quote(RfqConstraints),
        Commit(Box<Commit>),
        Status,
    }

    fn refusal(code: RejectCode, reason: impl Into<String>) -> CapMessage {
        CapMessage::Refusal(Refusal {
            code: code.as_str().into(),
            reason: reason.into(),
            request_id: None,
            quote_id: None,
            swap_id: None,
        })
    }

    /// Answer one `paykit-cap.*` request from the root key that authenticated the connection.
    pub(crate) async fn handle_cap_request(
        mut ctx: ExecCtx,
        offer: SharedOffer,
        request: pubky_transport::p2p::DirectRpc,
    ) {
        let sender = request.remote_key;
        let reply = match serde_json::from_value::<CapMessage>(request.message) {
            Ok(message) => answer(&mut ctx, offer, &sender, message).await,
            Err(error) => refusal(RejectCode::InvalidRequest, format!("unreadable: {error}")),
        };
        match serde_json::to_vec(&reply) {
            Ok(bytes) => {
                let _ = request.reply.send(bytes);
            }
            Err(error) => warn!("could not encode a paykit-cap reply: {error}"),
        }
    }

    async fn answer(
        ctx: &mut ExecCtx,
        offer: SharedOffer,
        sender: &str,
        message: CapMessage,
    ) -> CapMessage {
        let (asked, message) = match message {
            CapMessage::Rfq(rfq) => (
                Asked::Quote(rfq.constraints.clone()),
                SwapMessage::QuoteRequest(QuoteRequest {
                    request_id: rfq.request_id,
                    offer_id: rfq.constraints.offer_id,
                    client_pkarr: sender.to_string(),
                    direction: rfq.constraints.direction,
                    amount_sat: rfq.constraints.amount_sat,
                    protocol_version: rfq.protocol_version,
                    features: rfq.features,
                }),
            ),
            CapMessage::Commit(commit) => {
                let issued = ctx.cap.terms.lock().await;
                // Terms this provider signed for someone else, or never signed, are refused.
                // Unknown terms after a restart go on to the engine, which replays a swap it
                // already holds and refuses a quote it no longer knows.
                if let Some(terms) = issued.get(&commit.commit.quote_id) {
                    if !pubky_transport::same_pubky(&terms.owner, sender)
                        || terms.terms_hash != commit.terms_hash
                    {
                        return CapMessage::Refusal(Refusal {
                            code: RejectCode::InvalidRequest.as_str().into(),
                            reason: "terms_hash does not match the signed quote".into(),
                            request_id: None,
                            quote_id: Some(commit.commit.quote_id),
                            swap_id: None,
                        });
                    }
                }
                drop(issued);
                if let Some(proof) = &commit.quote {
                    if let Err(refusal) = restore_quote(ctx, sender, &commit, proof).await {
                        return CapMessage::Refusal(refusal);
                    }
                }
                let request = commit.commit.clone().into_request(sender);
                (
                    Asked::Commit(Box::new(commit)),
                    SwapMessage::SwapRequest(request),
                )
            }
            CapMessage::StatusRequest(request) => {
                (Asked::Status, SwapMessage::SwapStatusRequest(request))
            }
            _ => return refusal(RejectCode::InvalidRequest, "not a request kind"),
        };

        let (reply_to, replied) = tokio::sync::oneshot::channel();
        let current = offer.read().await.clone();
        ctx.transport = Arc::new(ctx.transport.root_key(reply_to));
        if let Err(error) = handle_message(ctx, current.as_ref(), sender, message).await {
            warn!("could not handle paykit-cap request: {error:#}");
        }
        let Some(reply) = replied
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SwapMessage>(&bytes).ok())
        else {
            return refusal(RejectCode::InternalError, "no reply");
        };
        match translate(ctx, sender, asked, reply).await {
            Ok(reply) => reply,
            Err(error) => {
                warn!("could not sign a paykit-cap reply: {error:#}");
                refusal(RejectCode::InternalError, "could not sign the reply")
            }
        }
    }

    async fn translate(
        ctx: &ExecCtx,
        sender: &str,
        asked: Asked,
        reply: SwapMessage,
    ) -> anyhow::Result<CapMessage> {
        Ok(match (asked, reply) {
            (Asked::Quote(rfq), SwapMessage::Quote(quote)) => {
                let parties = Parties {
                    owner: sender.to_string(),
                    provider: ctx.cap.provider.clone(),
                };
                let signed = sign_quote(ctx.cap.signer.as_ref(), &parties, &rfq, &quote)?;
                let now = now_unix();
                let mut issued = ctx.cap.terms.lock().await;
                issued.retain(|_, terms| terms.expires_at_unix > now);
                issued.insert(
                    quote.quote_id,
                    IssuedTerms {
                        owner: sender.to_string(),
                        terms_hash: signed.terms_hash.clone(),
                        expires_at_unix: quote.valid_until_unix,
                    },
                );
                CapMessage::Quote(signed)
            }
            (Asked::Commit(commit), SwapMessage::SwapAccept(accept)) => {
                CapMessage::Contract(stored_contract(ctx, &commit, &accept)?)
            }
            (Asked::Commit(commit), SwapMessage::Reject(reject))
                if reject.code() == Some(RejectCode::Pending) =>
            {
                CapMessage::Status(Box::new(Status {
                    request_id: None,
                    swap_id: reject.swap_id,
                    quote_id: Some(commit.commit.quote_id),
                    state: STATE_PENDING.into(),
                    reference: None,
                    snapshot: None,
                    contract: None,
                }))
            }
            (Asked::Status, SwapMessage::SwapStatusSnapshot(mut snapshot)) => {
                let contract = ctx
                    .store
                    .get(snapshot.accept.swap_id)?
                    .and_then(|record| record.cap_contract);
                if contract.is_some() {
                    snapshot.accept.invoice = None;
                }
                CapMessage::Status(Box::new(Status {
                    request_id: snapshot.request_id,
                    swap_id: Some(snapshot.accept.swap_id),
                    quote_id: Some(snapshot.accept.quote_id),
                    // `SwapState` serializes as `{"state": .., "detail": ..}`.
                    state: serde_json::to_value(&snapshot.state)?["state"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    reference: None,
                    snapshot: Some(snapshot),
                    contract,
                }))
            }
            // Every refusal passes through with its code, including the three a commit may
            // get (liquidity_unavailable, rate_limited, access_denied).
            (_, SwapMessage::Reject(reject)) => CapMessage::Refusal(reject.into()),
            (_, other) => {
                anyhow::bail!("unexpected reply {:?}", std::mem::discriminant(&other))
            }
        })
    }

    /// Put a quote this provider signed back in its book when the book no longer holds it, after
    /// a restart or because a full book evicted it (#103). The request that follows runs every
    /// admission check as before. A quote a swap already used, or one this run already redeemed,
    /// is not put back: an identical replay still gets its contract, and anything else is refused.
    async fn restore_quote(
        ctx: &ExecCtx,
        sender: &str,
        commit: &Commit,
        proof: &QuoteProof,
    ) -> Result<(), Refusal> {
        let quote_id = commit.commit.quote_id;
        if ctx.quotes.lock().await.holds(quote_id) {
            return Ok(());
        }
        let refuse = |code: RejectCode, reason: String| Refusal {
            code: code.as_str().into(),
            reason,
            request_id: None,
            quote_id: Some(quote_id),
            swap_id: None,
        };
        let parties = Parties {
            owner: sender.to_string(),
            provider: ctx.cap.provider.clone(),
        };
        if let Err(error) = proof.check(&parties, &ctx.cap.signer.public_key_hex(), commit) {
            return Err(refuse(
                RejectCode::InvalidRequest,
                format!("signed quote refused: {error}"),
            ));
        }
        let quote = &proof.signed.quote;
        let now = now_unix();
        if quote.valid_until_unix <= now {
            return Err(refuse(
                RejectCode::QuoteExpired,
                "the signed quote has expired".into(),
            ));
        }
        match crate::swap_for_quote(ctx.store.as_ref(), quote_id) {
            // The engine answers a replay of that swap from its record, and refuses anything else.
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(error) => {
                warn!("could not look up swaps for quote {quote_id}: {error:#}");
                return Err(refuse(
                    RejectCode::InternalError,
                    "could not check the quote".into(),
                ));
            }
        }
        let claimable_hint = quote.direction == SwapDirection::Reverse
            && proof
                .rfq
                .features
                .iter()
                .any(|f| f == CLAIMABLE_HINT_FEATURE);
        let issued = crate::IssuedQuote::signed(sender, quote, claimable_hint);
        if ctx.quotes.lock().await.restore(quote_id, issued, now) {
            info!("Took back signed quote {quote_id} from {sender}");
        }
        Ok(())
    }

    /// The contract stored with the swap, signing and storing one first if there is none. The
    /// first one stored stands, so a replayed commit gets the bytes the first one got.
    fn stored_contract(
        ctx: &ExecCtx,
        commit: &Commit,
        accept: &SwapAccept,
    ) -> anyhow::Result<ContractReply> {
        if let Some(stored) = stored(ctx, accept)? {
            return Ok(stored);
        }
        let signed = sign_contract(
            ctx.cap.signer.as_ref(),
            &commit.terms_hash,
            &commit.commit,
            accept,
        )?;
        ctx.store.mutate(accept.swap_id, &mut |record| {
            if record.cap_contract.is_none() {
                record.cap_contract = Some(signed.clone());
            }
        })?;
        Ok(stored(ctx, accept)?.unwrap_or(signed))
    }

    fn stored(ctx: &ExecCtx, accept: &SwapAccept) -> anyhow::Result<Option<ContractReply>> {
        let unsigned = SwapAccept {
            invoice: None,
            ..accept.clone()
        };
        Ok(ctx
            .store
            .get(accept.swap_id)?
            .and_then(|record| record.cap_contract)
            .filter(|stored| stored.signed.contract.accept == unsigned))
    }
}
