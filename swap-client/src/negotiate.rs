//! Offer, quote, creation and status requests to one provider, over whichever transport both
//! sides support.
//!
//! With `Negotiation::Auto` a request goes over the iroh `direct/1` protocol first. The QUIC
//! handshake authenticates this client's root Pubky key, so the provider needs no homeserver to
//! answer it, and the reply comes back on the same stream. A provider that predates the protocol,
//! or cannot be reached over iroh, refuses the connection before anything is sent, and the client
//! then uses Pubky DMs for the rest of the run. `Negotiation::Iroh` never falls back and
//! `Negotiation::Dm` never tries iroh.
//!
//! A request that fails after it may have reached the provider is sent again, identically, once
//! over iroh and then over DMs. Every request here is read-only or idempotent for the same
//! authenticated key: a repeated creation returns the original acceptance, whichever transport
//! carries it. If a repeated creation is refused, the swap is looked up by its quote before the
//! refusal is believed.

use anyhow::{anyhow, Error, Result};
use pubky_transport::Transport;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use swap_common::messages::*;
use tokio::sync::OnceCell;
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

/// Which transport carries requests to the provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Negotiation {
    /// iroh when the provider supports it, Pubky DMs otherwise.
    #[default]
    Auto,
    /// iroh only.
    Iroh,
    /// Pubky DMs only.
    Dm,
}

impl std::str::FromStr for Negotiation {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "iroh" => Ok(Self::Iroh),
            "dm" => Ok(Self::Dm),
            other => Err(anyhow!("unknown negotiation transport: {other}")),
        }
    }
}

/// Why an exchange produced no reply.
#[derive(Debug)]
pub enum ExchangeError {
    /// Nothing reached the provider.
    NotSent(Error),
    /// The provider may have received and acted on the request.
    Uncertain(Error),
}

impl ExchangeError {
    fn into_inner(self) -> Error {
        match self {
            Self::NotSent(error) | Self::Uncertain(error) => error,
        }
    }
}

/// One request and its reply: a message `expected` accepts, or a [`SwapMessage::Reject`].
#[allow(async_fn_in_trait)]
pub trait Channel {
    const NAME: &'static str;
    async fn exchange(
        &self,
        request: &SwapMessage,
        expected: fn(&SwapMessage) -> bool,
    ) -> std::result::Result<SwapMessage, ExchangeError>;
}

/// A transport this build does not have.
pub enum Unavailable {}

impl Channel for Unavailable {
    const NAME: &'static str = "unavailable";
    async fn exchange(
        &self,
        _: &SwapMessage,
        _: fn(&SwapMessage) -> bool,
    ) -> std::result::Result<SwapMessage, ExchangeError> {
        match *self {}
    }
}

/// Requests over iroh, authenticated as this client's root key.
#[cfg(feature = "iroh")]
pub struct IrohChannel {
    client: pubky_transport::p2p::DirectRpcClient,
}

#[cfg(feature = "iroh")]
impl IrohChannel {
    pub async fn new(secret: [u8; 32], provider: &str) -> Result<Self> {
        let client = pubky_transport::p2p::DirectRpcClient::new(secret, provider).await?;
        Ok(Self { client })
    }

    /// Connections set up so far, for telling cold requests from warm ones.
    pub fn connections_established(&self) -> usize {
        self.client.connections_established()
    }

    pub async fn close(&self) {
        self.client.close().await;
    }
}

#[cfg(feature = "iroh")]
impl Channel for IrohChannel {
    const NAME: &'static str = "iroh";
    async fn exchange(
        &self,
        request: &SwapMessage,
        expected: fn(&SwapMessage) -> bool,
    ) -> std::result::Result<SwapMessage, ExchangeError> {
        use pubky_transport::TransportError;
        let envelope = pubky_transport::p2p::DirectRequest {
            message: serde_json::to_value(request)
                .map_err(|error| ExchangeError::NotSent(error.into()))?,
        };
        let bytes = match self.client.request(&envelope).await {
            Ok(bytes) => bytes,
            Err(error @ TransportError::NotSent(_)) => {
                return Err(ExchangeError::NotSent(error.into()))
            }
            Err(error) => return Err(ExchangeError::Uncertain(error.into())),
        };
        let reply: SwapMessage = serde_json::from_slice(&bytes)
            .map_err(|error| ExchangeError::Uncertain(anyhow!("unreadable reply: {error}")))?;
        if matches!(reply, SwapMessage::Reject(_)) || expected(&reply) {
            Ok(reply)
        } else {
            Err(ExchangeError::Uncertain(anyhow!(
                "provider replied with an unexpected message"
            )))
        }
    }
}

/// Requests over encrypted Pubky DMs, polling the conversation for the reply.
pub struct DmChannel {
    transport: Transport,
    provider: String,
    signed_in: bool,
    /// Rung before the first request, so a provider that does not follow us starts polling.
    doorbell: Option<[u8; 32]>,
    ready: OnceCell<()>,
    reply_timeout: Duration,
}

impl DmChannel {
    /// `signed_in` says whether `transport` has already signed in to its homeserver.
    pub fn new(
        transport: Transport,
        provider: &str,
        signed_in: bool,
        doorbell: Option<[u8; 32]>,
    ) -> Self {
        Self {
            transport,
            provider: provider.to_string(),
            signed_in,
            doorbell,
            ready: OnceCell::new(),
            reply_timeout: Duration::from_secs(30),
        }
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Sign in, skip the conversation's history and ring the doorbell, once.
    async fn prepare(&self) -> Result<()> {
        self.ready
            .get_or_try_init(|| async {
                if !self.signed_in {
                    self.transport.sign_in().await?;
                }
                self.transport.add_known_peer(self.provider.clone());
                // Everything already in this conversation belongs to an earlier run, and none of
                // it answers a request this run has not sent yet.
                if let Err(e) = self.transport.mark_conversation_seen(&self.provider).await {
                    warn!("could not read the existing conversation with the provider ({e}); a reply from an earlier run may be picked up instead of this one's");
                }
                ring_doorbell(self.doorbell, &self.provider).await;
                Ok::<_, Error>(())
            })
            .await
            .map(|_| ())
    }
}

impl Channel for DmChannel {
    const NAME: &'static str = "Pubky DMs";
    async fn exchange(
        &self,
        request: &SwapMessage,
        expected: fn(&SwapMessage) -> bool,
    ) -> std::result::Result<SwapMessage, ExchangeError> {
        self.prepare().await.map_err(ExchangeError::NotSent)?;
        self.transport
            .send(&self.provider, request)
            .await
            .map_err(|error| ExchangeError::Uncertain(error.into()))?;
        let deadline = Instant::now() + self.reply_timeout;
        while Instant::now() <= deadline {
            let messages = self
                .transport
                .receive_from::<SwapMessage>(&self.provider)
                .await
                .unwrap_or_default();
            for message in messages {
                if matches!(message, SwapMessage::Reject(_)) || expected(&message) {
                    return Ok(message);
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
        Err(ExchangeError::Uncertain(anyhow!(
            "timed out waiting for provider response"
        )))
    }
}

#[cfg(feature = "iroh")]
async fn ring_doorbell(secret: Option<[u8; 32]>, provider: &str) {
    let Some(secret) = secret else { return };
    match pubky_transport::p2p::ring_provider(secret, provider).await {
        Ok(()) => info!("Rang provider iroh doorbell; it should start polling us"),
        Err(e) => warn!("iroh rendezvous ring failed ({e}); relying on the provider following us"),
    }
}

#[cfg(not(feature = "iroh"))]
async fn ring_doorbell(_: Option<[u8; 32]>, _: &str) {}

/// A reply and whether any attempt before it may have reached the provider without answering.
struct Exchanged {
    reply: SwapMessage,
    uncertain: bool,
}

/// Sends each request over the preferred transport, falling back as the module docs describe.
pub struct Negotiator<P, F> {
    preferred: Option<P>,
    fallback: Option<F>,
    preferred_unavailable: AtomicBool,
}

const RECOVERY_WINDOW: Duration = Duration::from_secs(60);
const RECOVERY_POLL: Duration = Duration::from_millis(500);

impl<P: Channel, F: Channel> Negotiator<P, F> {
    pub fn new(preferred: Option<P>, fallback: Option<F>) -> Self {
        Self {
            preferred,
            fallback,
            preferred_unavailable: AtomicBool::new(false),
        }
    }

    pub fn preferred(&self) -> Option<&P> {
        self.preferred.as_ref()
    }

    pub fn fallback(&self) -> Option<&F> {
        self.fallback.as_ref()
    }

    async fn exchange(
        &self,
        request: &SwapMessage,
        expected: fn(&SwapMessage) -> bool,
    ) -> std::result::Result<Exchanged, ExchangeError> {
        let mut uncertain = false;
        let mut last_error = None;
        if let Some(preferred) = self.preferred.as_ref() {
            // One resend: a stream that broke may simply need a new connection.
            for _ in 0..2 {
                if self.preferred_unavailable.load(Ordering::Relaxed) {
                    break;
                }
                match preferred.exchange(request, expected).await {
                    Ok(reply) => return Ok(Exchanged { reply, uncertain }),
                    Err(ExchangeError::NotSent(error)) => {
                        if self.fallback.is_some() {
                            warn!("{} unavailable ({error}); using {}", P::NAME, F::NAME);
                        }
                        self.preferred_unavailable.store(true, Ordering::Relaxed);
                        last_error = Some(error);
                    }
                    Err(ExchangeError::Uncertain(error)) => {
                        warn!("{} request failed ({error}); sending it again", P::NAME);
                        uncertain = true;
                        last_error = Some(error);
                    }
                }
            }
        }
        let error = match self.fallback.as_ref() {
            Some(fallback) => match fallback.exchange(request, expected).await {
                Ok(reply) => return Ok(Exchanged { reply, uncertain }),
                Err(ExchangeError::Uncertain(error)) => {
                    uncertain = true;
                    error
                }
                Err(ExchangeError::NotSent(error)) => error,
            },
            None => last_error.unwrap_or_else(|| anyhow!("no transport to the provider")),
        };
        Err(if uncertain {
            ExchangeError::Uncertain(error)
        } else {
            ExchangeError::NotSent(error)
        })
    }

    /// The provider's current offer.
    pub async fn offer(&self) -> Result<SwapOffer> {
        let request_id = Some(Uuid::new_v4());
        let request = SwapMessage::OfferRequest(OfferRequest { request_id });
        let expected =
            |m: &SwapMessage| matches!(m, SwapMessage::Offer(o) if o.request_id.is_some());
        match self
            .exchange(&request, expected)
            .await
            .map_err(ExchangeError::into_inner)?
            .reply
        {
            SwapMessage::Offer(offer) if offer.request_id == request_id => Ok(offer),
            SwapMessage::Offer(_) => Err(anyhow!("offer answers a different request")),
            other => Err(rejection(other)),
        }
    }

    pub async fn quote(&self, request: &QuoteRequest) -> Result<Quote> {
        let message = SwapMessage::QuoteRequest(request.clone());
        let expected = |m: &SwapMessage| matches!(m, SwapMessage::Quote(_));
        match self
            .exchange(&message, expected)
            .await
            .map_err(ExchangeError::into_inner)?
            .reply
        {
            // An older provider does not echo the identifier.
            SwapMessage::Quote(quote)
                if quote.request_id.is_none() || quote.request_id == request.request_id =>
            {
                Ok(quote)
            }
            SwapMessage::Quote(_) => Err(anyhow!("quote answers a different request")),
            other => Err(rejection(other)),
        }
    }

    /// Create the swap, or recover the one an earlier attempt already created.
    pub async fn create(&self, request: &SwapRequest) -> Result<SwapAccept> {
        let message = SwapMessage::SwapRequest(request.clone());
        let expected = |m: &SwapMessage| matches!(m, SwapMessage::SwapAccept(_));
        let accept = match self.exchange(&message, expected).await {
            Ok(Exchanged {
                reply: SwapMessage::SwapAccept(accept),
                ..
            }) => accept,
            // The first attempt may have been admitted while the resend was refused.
            Ok(Exchanged {
                reply,
                uncertain: true,
            }) => self.recover(request.quote_id, rejection(reply)).await?,
            Ok(Exchanged { reply, .. }) => return Err(rejection(reply)),
            Err(ExchangeError::Uncertain(error)) => self.recover(request.quote_id, error).await?,
            Err(ExchangeError::NotSent(error)) => return Err(error),
        };
        if accept.quote_id != request.quote_id {
            return Err(anyhow!("acceptance is for a different quote"));
        }
        Ok(accept)
    }

    /// Look up a creation that may have been admitted. The provider spends the quote before it
    /// persists the swap, so `not_found` and `pending` are only believed once `RECOVERY_WINDOW`
    /// has passed.
    async fn recover(&self, quote_id: Uuid, cause: Error) -> Result<SwapAccept> {
        let deadline = Instant::now() + RECOVERY_WINDOW;
        loop {
            let query = SwapStatusRequest {
                request_id: Some(Uuid::new_v4()),
                swap_id: None,
                quote_id: Some(quote_id),
            };
            let message = SwapMessage::SwapStatusRequest(query.clone());
            let expected = |m: &SwapMessage| matches!(m, SwapMessage::SwapStatusSnapshot(_));
            match self.exchange(&message, expected).await.map(|e| e.reply) {
                Ok(SwapMessage::SwapStatusSnapshot(snapshot))
                    if snapshot.request_id == query.request_id =>
                {
                    info!("recovered swap {} by its quote", snapshot.accept.swap_id);
                    return Ok(snapshot.accept);
                }
                Ok(SwapMessage::Reject(Reject { code, .. }))
                    if !matches!(code.as_deref(), Some("not_found" | "pending")) =>
                {
                    return Err(cause);
                }
                Err(ExchangeError::NotSent(_)) => return Err(cause),
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(cause.context(format!(
                    "the provider may have created a swap for quote {quote_id}; query its status before requesting another"
                )));
            }
            sleep(RECOVERY_POLL).await;
        }
    }

    pub async fn status(&self, request: &SwapStatusRequest) -> Result<SwapStatusSnapshot> {
        let message = SwapMessage::SwapStatusRequest(request.clone());
        let expected = |m: &SwapMessage| matches!(m, SwapMessage::SwapStatusSnapshot(_));
        match self
            .exchange(&message, expected)
            .await
            .map_err(ExchangeError::into_inner)?
            .reply
        {
            SwapMessage::SwapStatusSnapshot(snapshot)
                if snapshot.request_id == request.request_id =>
            {
                Ok(snapshot)
            }
            SwapMessage::SwapStatusSnapshot(_) => {
                Err(anyhow!("status answers a different request"))
            }
            other => Err(rejection(other)),
        }
    }
}

fn rejection(reply: SwapMessage) -> Error {
    match reply {
        SwapMessage::Reject(reject) => anyhow!("provider rejected: {}", reject.reason),
        _ => anyhow!("provider replied with an unexpected message"),
    }
}

#[cfg(feature = "iroh")]
pub type Preferred = IrohChannel;
#[cfg(not(feature = "iroh"))]
pub type Preferred = Unavailable;

/// A negotiator for `provider` as configured, and this client's Pubky.
pub async fn connect(
    identity: &swap_config::Identity,
    provider: &str,
    preference: Negotiation,
    rendezvous_iroh: bool,
) -> Result<(Negotiator<Preferred, DmChannel>, String)> {
    #[cfg(feature = "iroh")]
    {
        let secret = pubky_transport::identity::secret_from_recovery(
            identity.method,
            &identity.value,
            &identity.passphrase,
        )?;
        let client_pkarr = pubky_transport::identity_from_secret(&secret);
        let preferred = match preference {
            Negotiation::Dm => None,
            Negotiation::Auto => match IrohChannel::new(secret, provider).await {
                Ok(channel) => Some(channel),
                Err(e) => {
                    warn!("iroh unavailable ({e}); using Pubky DMs");
                    None
                }
            },
            Negotiation::Iroh => Some(IrohChannel::new(secret, provider).await?),
        };
        // Signing in waits until a request actually needs DMs.
        let fallback = (preference != Negotiation::Iroh).then(|| {
            Transport::unsigned(secret).map(|transport| {
                DmChannel::new(
                    transport,
                    provider,
                    false,
                    rendezvous_iroh.then_some(secret),
                )
            })
        });
        let fallback = fallback.transpose()?;
        Ok((Negotiator::new(preferred, fallback), client_pkarr))
    }
    #[cfg(not(feature = "iroh"))]
    {
        if preference == Negotiation::Iroh {
            return Err(anyhow!(
                "negotiation = \"iroh\" needs a build with the `iroh` feature"
            ));
        }
        if rendezvous_iroh {
            warn!("--rendezvous-iroh set but this build lacks the `iroh` feature; ignoring");
        }
        let transport = match identity.method {
            "file" => Transport::from_recovery_file(&identity.value, &identity.passphrase).await?,
            _ => {
                Transport::from_recovery_phrase(&identity.value, Some(&identity.passphrase)).await?
            }
        };
        let client_pkarr = transport.public_key_string();
        let fallback = DmChannel::new(transport, provider, true, None);
        Ok((Negotiator::new(None, Some(fallback)), client_pkarr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use swap_common::SwapDirection;

    /// A provider that admits one swap per quote and replays it for the same request.
    #[derive(Default)]
    struct Provider {
        accepted: Mutex<HashMap<Uuid, (SwapRequest, SwapAccept)>>,
        creations: AtomicUsize,
        /// Refuse a creation whose quote was already spent, as a provider still admitting the
        /// first attempt does when the resend races it.
        refuse_replays: AtomicBool,
        /// Status queries answered `pending` before the admitted swap is reported.
        pending_status_replies: AtomicUsize,
    }

    impl Provider {
        fn handle(&self, request: &SwapMessage) -> SwapMessage {
            match request {
                SwapMessage::SwapRequest(request) => {
                    let mut accepted = self.accepted.lock().unwrap();
                    if let Some((original, accept)) = accepted.get(&request.quote_id) {
                        if original == request && !self.refuse_replays.load(Ordering::SeqCst) {
                            return SwapMessage::SwapAccept(accept.clone());
                        }
                        return reject("unknown or expired quote");
                    }
                    self.creations.fetch_add(1, Ordering::SeqCst);
                    let accept = acceptance(request.quote_id);
                    accepted.insert(request.quote_id, (request.clone(), accept.clone()));
                    SwapMessage::SwapAccept(accept)
                }
                SwapMessage::SwapStatusRequest(query) => {
                    let pending = &self.pending_status_replies;
                    if pending.load(Ordering::SeqCst) > 0 {
                        pending.fetch_sub(1, Ordering::SeqCst);
                        return SwapMessage::Reject(Reject {
                            code: Some("pending".into()),
                            request_id: None,
                            swap_id: None,
                            quote_id: None,
                            reason: "invoice creation is pending".into(),
                        });
                    }
                    let accepted = self.accepted.lock().unwrap();
                    match query.quote_id.and_then(|id| accepted.get(&id)) {
                        Some((_, accept)) => SwapMessage::SwapStatusSnapshot(SwapStatusSnapshot {
                            request_id: query.request_id,
                            accept: accept.clone(),
                            network: swap_common::NetworkSpec::Regtest,
                            state: swap_common::SwapState::Created,
                            funding_txid_hex: None,
                            funding_vout: None,
                            spend_txid_hex: None,
                            required_confirmations: 1,
                            updated_at_unix: 0,
                            observed_at_unix: 0,
                        }),
                        None => reject("unknown swap"),
                    }
                }
                SwapMessage::QuoteRequest(request) => SwapMessage::Quote(Quote {
                    request_id: request.request_id,
                    quote_id: Uuid::new_v4(),
                    offer_id: Uuid::nil(),
                    direction: request.direction,
                    amount_sat: request.amount_sat,
                    fee_sat: 0,
                    service_fee_sat: 0,
                    onchain_fee_sat: 0,
                    fee_rate_sat_vb: 1,
                    total_sat: request.amount_sat,
                    htlc_timeout_blocks: 144,
                    required_confirmations: 1,
                    valid_until_unix: u64::MAX,
                    protocol_version: PROTOCOL_VERSION,
                }),
                _ => reject("unsupported"),
            }
        }
    }

    fn reject(reason: &str) -> SwapMessage {
        SwapMessage::Reject(Reject {
            code: None,
            request_id: None,
            swap_id: None,
            quote_id: None,
            reason: reason.into(),
        })
    }

    fn acceptance(quote_id: Uuid) -> SwapAccept {
        serde_json::from_value(serde_json::json!({
            "quote_id": quote_id,
            "swap_id": Uuid::new_v4(),
            "direction": "reverse",
            "htlc_script_hex": "",
            "htlc_address": "",
            "onchain_amount_sat": 1000,
            "timeout_block_height": 100,
            "provider_pubkey_hex": "",
        }))
        .unwrap()
    }

    #[derive(Clone, Copy)]
    enum Fault {
        /// Refused before anything was sent, as a provider without the protocol does.
        NotSent,
        /// Handled by the provider, then the reply was lost.
        LostReply,
    }

    struct Fake {
        provider: Arc<Provider>,
        faults: Mutex<VecDeque<Fault>>,
        seen: Mutex<Vec<SwapMessage>>,
    }

    impl Fake {
        fn new(provider: &Arc<Provider>, faults: impl IntoIterator<Item = Fault>) -> Self {
            Self {
                provider: provider.clone(),
                faults: Mutex::new(faults.into_iter().collect()),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<serde_json::Value> {
            let seen = self.seen.lock().unwrap();
            seen.iter()
                .map(|m| serde_json::to_value(m).unwrap())
                .collect()
        }
    }

    struct Iroh(Fake);
    struct Dm(Fake);

    async fn fake_exchange(
        fake: &Fake,
        request: &SwapMessage,
    ) -> std::result::Result<SwapMessage, ExchangeError> {
        let fault = fake.faults.lock().unwrap().pop_front();
        if let Some(Fault::NotSent) = fault {
            return Err(ExchangeError::NotSent(anyhow!("no application protocol")));
        }
        fake.seen
            .lock()
            .unwrap()
            .push(serde_json::from_value(serde_json::to_value(request).unwrap()).unwrap());
        let reply = fake.provider.handle(request);
        match fault {
            Some(Fault::LostReply) => Err(ExchangeError::Uncertain(anyhow!("connection lost"))),
            _ => Ok(reply),
        }
    }

    impl Channel for Iroh {
        const NAME: &'static str = "iroh";
        async fn exchange(
            &self,
            request: &SwapMessage,
            _: fn(&SwapMessage) -> bool,
        ) -> std::result::Result<SwapMessage, ExchangeError> {
            fake_exchange(&self.0, request).await
        }
    }

    impl Channel for Dm {
        const NAME: &'static str = "dm";
        async fn exchange(
            &self,
            request: &SwapMessage,
            _: fn(&SwapMessage) -> bool,
        ) -> std::result::Result<SwapMessage, ExchangeError> {
            fake_exchange(&self.0, request).await
        }
    }

    fn quote_request() -> QuoteRequest {
        QuoteRequest {
            request_id: Some(Uuid::new_v4()),
            offer_id: Uuid::nil(),
            client_pkarr: "client".into(),
            direction: SwapDirection::Reverse,
            amount_sat: 50_000,
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        }
    }

    fn swap_request(quote_id: Uuid) -> SwapRequest {
        SwapRequest {
            script_type: Default::default(),
            quote_id,
            client_pkarr: "client".into(),
            direction: SwapDirection::Reverse,
            payment_hash_hex: "00".repeat(32),
            client_claim_pubkey_hex: Some("02".repeat(33)),
            client_refund_pubkey_hex: None,
            invoice: None,
        }
    }

    fn negotiator(
        provider: &Arc<Provider>,
        iroh: impl IntoIterator<Item = Fault>,
        dm: Option<Vec<Fault>>,
    ) -> Negotiator<Iroh, Dm> {
        Negotiator::new(
            Some(Iroh(Fake::new(provider, iroh))),
            dm.map(|faults| Dm(Fake::new(provider, faults))),
        )
    }

    #[tokio::test]
    async fn a_supporting_provider_is_negotiated_with_entirely_over_iroh() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(&provider, [], Some(vec![]));
        let quote = negotiator.quote(&quote_request()).await.unwrap();
        let accept = negotiator
            .create(&swap_request(quote.quote_id))
            .await
            .unwrap();
        let status = SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: None,
            quote_id: Some(quote.quote_id),
        };
        let snapshot = negotiator.status(&status).await.unwrap();
        assert_eq!(snapshot.accept.swap_id, accept.swap_id);
        assert_eq!(negotiator.preferred().unwrap().0.seen().len(), 3);
        // DMs were never touched, so nothing signed in or polled.
        assert!(negotiator.fallback().unwrap().0.seen().is_empty());
    }

    #[tokio::test]
    async fn an_older_provider_is_used_over_dms_for_the_whole_run() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(&provider, [Fault::NotSent], Some(vec![]));
        let quote = negotiator.quote(&quote_request()).await.unwrap();
        negotiator
            .create(&swap_request(quote.quote_id))
            .await
            .unwrap();
        assert!(negotiator.preferred().unwrap().0.seen().is_empty());
        assert_eq!(negotiator.fallback().unwrap().0.seen().len(), 2);
    }

    #[tokio::test]
    async fn iroh_only_never_falls_back() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(&provider, [Fault::NotSent], None);
        assert!(negotiator.quote(&quote_request()).await.is_err());
        assert!(negotiator.quote(&quote_request()).await.is_err());
    }

    #[tokio::test]
    async fn a_lost_creation_reply_is_recovered_without_a_second_swap() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(&provider, [Fault::LostReply], Some(vec![]));
        let request = swap_request(Uuid::new_v4());
        let accept = negotiator.create(&request).await.unwrap();
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        // The resend was the identical request, so it named the same quote and keys.
        let seen = negotiator.preferred().unwrap().0.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1]);
        let stored = provider.accepted.lock().unwrap()[&request.quote_id]
            .1
            .swap_id;
        assert_eq!(accept.swap_id, stored);
    }

    #[tokio::test]
    async fn a_creation_that_keeps_failing_over_iroh_is_replayed_over_dms() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(
            &provider,
            [Fault::LostReply, Fault::LostReply],
            Some(vec![]),
        );
        let request = swap_request(Uuid::new_v4());
        let accept = negotiator.create(&request).await.unwrap();
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        let over_dm = negotiator.fallback().unwrap().0.seen();
        assert_eq!(
            over_dm,
            vec![serde_json::to_value(SwapMessage::SwapRequest(request.clone())).unwrap()]
        );
        let stored = provider.accepted.lock().unwrap()[&request.quote_id]
            .1
            .swap_id;
        assert_eq!(accept.swap_id, stored);
    }

    #[tokio::test]
    async fn a_refused_resend_is_checked_against_status_before_it_is_believed() {
        let provider = Arc::new(Provider::default());
        provider.refuse_replays.store(true, Ordering::SeqCst);
        let negotiator = negotiator(&provider, [Fault::LostReply], Some(vec![]));
        let request = swap_request(Uuid::new_v4());
        let accept = negotiator.create(&request).await.unwrap();
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        let stored = provider.accepted.lock().unwrap()[&request.quote_id]
            .1
            .swap_id;
        assert_eq!(accept.swap_id, stored);
    }

    #[tokio::test]
    async fn a_lost_reply_on_every_transport_is_recovered_through_status() {
        let provider = Arc::new(Provider::default());
        provider.refuse_replays.store(true, Ordering::SeqCst);
        provider.pending_status_replies.store(1, Ordering::SeqCst);
        let negotiator = negotiator(
            &provider,
            [Fault::LostReply, Fault::LostReply],
            Some(vec![Fault::LostReply]),
        );
        let request = swap_request(Uuid::new_v4());
        let accept = negotiator.create(&request).await.unwrap();
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        let stored = provider.accepted.lock().unwrap()[&request.quote_id]
            .1
            .swap_id;
        assert_eq!(accept.swap_id, stored);
    }

    #[tokio::test]
    async fn a_plain_rejection_is_final_and_not_retried_elsewhere() {
        let provider = Arc::new(Provider::default());
        provider.refuse_replays.store(true, Ordering::SeqCst);
        let negotiator = negotiator(&provider, [], Some(vec![]));
        let request = swap_request(Uuid::new_v4());
        negotiator.create(&request).await.unwrap();
        let error = negotiator.create(&request).await.unwrap_err();
        assert!(
            error.to_string().contains("unknown or expired quote"),
            "{error}"
        );
        assert_eq!(negotiator.preferred().unwrap().0.seen().len(), 2);
        assert!(negotiator.fallback().unwrap().0.seen().is_empty());
    }
}
