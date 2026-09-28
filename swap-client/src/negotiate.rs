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
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use swap_common::messages::*;
use swap_common::store::{JsonFileSwapStore, SwapRole, SwapStore};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use tokio::time::sleep;
use tokio::time::Instant;
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

    /// Complete transport delivery after the application has persisted the outcome.
    fn acknowledge(&self, _request: &SwapMessage) -> Result<()> {
        Ok(())
    }

    async fn close(&self) {}

    async fn maintain(&self) {}
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
    async fn close(&self) {
        self.client.close().await;
    }
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
        if reply_matches(request, &reply)
            && (matches!(reply, SwapMessage::Reject(_)) || expected(&reply))
        {
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
    /// Rung before the first request, so a provider that does not follow us starts polling.
    doorbell: Option<[u8; 32]>,
    ready: OnceCell<()>,
    reply_timeout: Duration,
    exchanges: AsyncMutex<()>,
    receipts: Mutex<HashMap<String, Vec<pubky_transport::Receipt>>>,
    accepted_store: Option<JsonFileSwapStore>,
}

impl DmChannel {
    /// The compatibility sign-in argument is ignored; the bounded mutation engine owns sessions.
    pub fn new(
        transport: Transport,
        provider: &str,
        _signed_in: bool,
        doorbell: Option<[u8; 32]>,
    ) -> Self {
        Self {
            transport,
            provider: provider.to_string(),
            doorbell,
            ready: OnceCell::new(),
            reply_timeout: Duration::from_secs(30),
            exchanges: AsyncMutex::new(()),
            receipts: Mutex::new(HashMap::new()),
            accepted_store: None,
        }
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    fn recorded_acceptance(&self, reply: &SwapMessage) -> Result<bool> {
        let Some(store) = &self.accepted_store else {
            return Ok(false);
        };
        let records = store.load_all_checked()?;
        Ok(records.iter().any(|record| {
            record.role == SwapRole::Client
                && pubky_transport::same_pubky(&record.peer, &self.provider)
                && match reply {
                    SwapMessage::SwapAccept(accept) => record.swap_accept.as_ref() == Some(accept),
                    SwapMessage::SwapStatusSnapshot(snapshot) => {
                        record.swap_accept.as_ref() == Some(&snapshot.accept)
                    }
                    SwapMessage::SwapStatusUpdate(update) => record
                        .swap_accept
                        .as_ref()
                        .is_some_and(|accept| accept.swap_id == update.swap_id),
                    _ => false,
                }
        }))
    }

    async fn maintain_outbox(&self) {
        let result = async {
            if let Some(store) = &self.accepted_store {
                for record in store.load_all_checked()? {
                    if record.role == SwapRole::Client
                        && pubky_transport::same_pubky(&record.peer, &self.provider)
                    {
                        if let Some(request) = &record.swap_request {
                            let scope = SwapMessage::SwapRequest(request.clone()).delivery_scope();
                            match crate::store::cleanup_deadline(&record) {
                                Some(deadline) => self.transport.complete_scope(
                                    &self.provider,
                                    &scope,
                                    deadline,
                                )?,
                                None => self.transport.reopen_scope(&self.provider, &scope)?,
                            }
                        }
                    }
                }
            }
            self.transport.process_outbox(crate::now_unix(), 8).await?;
            Ok::<_, Error>(())
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(2), result).await,
            Ok(Ok(()))
        ) {
            warn!("message maintenance remains pending for the next connection");
        }
    }

    /// Register the peer and ring the doorbell once. Pending replies survive process restarts.
    async fn prepare(&self) -> Result<()> {
        self.ready
            .get_or_try_init(|| async {
                self.transport.register_peer(&self.provider, true)?;
                ring_doorbell(self.doorbell, &self.provider).await;
                Ok::<_, Error>(())
            })
            .await
            .map(|_| ())
    }
}

impl Channel for DmChannel {
    const NAME: &'static str = "Pubky DMs";

    async fn close(&self) {
        self.maintain().await;
    }

    async fn maintain(&self) {
        if self.ready.get().is_some() {
            self.maintain_outbox().await;
        }
    }

    fn acknowledge(&self, request: &SwapMessage) -> Result<()> {
        let mut receipts = self
            .receipts
            .lock()
            .map_err(|_| anyhow!("reply receipts poisoned"))?;
        if let Some(pending) = receipts.get_mut(&request_key(request)) {
            for receipt in pending.iter() {
                receipt.acknowledge()?;
            }
            pending.clear();
        }
        receipts.remove(&request_key(request));
        Ok(())
    }

    async fn exchange(
        &self,
        request: &SwapMessage,
        expected: fn(&SwapMessage) -> bool,
    ) -> std::result::Result<SwapMessage, ExchangeError> {
        let deadline = Instant::now() + self.reply_timeout;
        let exchange = async {
            let _guard = self.exchanges.lock().await;
            self.prepare().await.map_err(ExchangeError::NotSent)?;
            self.transport
                .send_with_scope(&self.provider, &request_scope(request), request)
                .await
                .map_err(|error| ExchangeError::Uncertain(error.into()))?;
            loop {
                let messages = self
                    .transport
                    .poll_from::<SwapMessage>(&self.provider)
                    .await
                    .map_err(|error| ExchangeError::Uncertain(error.into()))?;
                let mut matched = None;
                let mut matched_receipts = Vec::new();
                let mut unresolved = false;
                for inbound in messages {
                    // An earlier status reply can recover this exact creation after a crash.
                    let reply = match (request, inbound.message) {
                        (
                            SwapMessage::SwapRequest(request),
                            SwapMessage::SwapStatusSnapshot(snapshot),
                        ) if snapshot.accept.quote_id == request.quote_id => {
                            SwapMessage::SwapAccept(snapshot.accept)
                        }
                        (_, reply) => reply,
                    };
                    if reply_matches(request, &reply)
                        && (matches!(reply, SwapMessage::Reject(_)) || expected(&reply))
                    {
                        if let Some(previous) = &matched {
                            if acceptance_conflicts(previous, &reply) {
                                return Err(ExchangeError::Uncertain(anyhow!(
                                    "provider sent conflicting correlated replies"
                                )));
                            }
                        }
                        if read_only_reply(&reply) {
                            inbound
                                .receipt
                                .acknowledge()
                                .map_err(|error| ExchangeError::Uncertain(error.into()))?;
                        } else {
                            matched_receipts.push(inbound.receipt);
                        }
                        if matched.is_none() || !matches!(reply, SwapMessage::Reject(_)) {
                            matched = Some(reply);
                        }
                    } else if read_only_reply(&reply)
                        || self
                            .recorded_acceptance(&reply)
                            .map_err(ExchangeError::Uncertain)?
                    {
                        inbound
                            .receipt
                            .acknowledge()
                            .map_err(|error| ExchangeError::Uncertain(error.into()))?;
                    } else {
                        // Never discard a creation reply just to advance the bounded inbox.
                        unresolved = true;
                    }
                }
                if let Some(reply) = matched {
                    self.receipts
                        .lock()
                        .map_err(|_| ExchangeError::Uncertain(anyhow!("reply receipts poisoned")))?
                        .entry(request_key(request))
                        .or_default()
                        .extend(matched_receipts);
                    return Ok(reply);
                }
                if unresolved {
                    return Err(ExchangeError::Uncertain(anyhow!("an unrecorded creation reply is pending; recover the earlier swap before negotiating another")));
                }
                sleep(Duration::from_millis(200)).await;
            }
        };
        match tokio::time::timeout_at(deadline, exchange).await {
            Ok(result) => result,
            Err(_) => Err(ExchangeError::Uncertain(anyhow!(
                "timed out waiting for provider response"
            ))),
        }
    }
}

fn acceptance_conflicts(first: &SwapMessage, second: &SwapMessage) -> bool {
    fn acceptance(message: &SwapMessage) -> Option<&SwapAccept> {
        match message {
            SwapMessage::SwapAccept(accept) => Some(accept),
            SwapMessage::SwapStatusSnapshot(snapshot) => Some(&snapshot.accept),
            _ => None,
        }
    }
    matches!((acceptance(first), acceptance(second)), (Some(first), Some(second)) if first != second)
}

fn read_only_reply(reply: &SwapMessage) -> bool {
    matches!(
        reply,
        SwapMessage::Offer(_)
            | SwapMessage::Quote(_)
            | SwapMessage::Reject(_)
            | SwapMessage::SwapStatusUpdate(_)
    )
}

fn request_key(request: &SwapMessage) -> String {
    match request {
        SwapMessage::OfferRequest(r) => format!("offer:{:?}", r.request_id),
        SwapMessage::QuoteRequest(r) => format!("request:{:?}", r.request_id),
        SwapMessage::SwapRequest(r) => format!("quote:{}", r.quote_id),
        SwapMessage::SwapStatusRequest(r) => r
            .quote_id
            .map(|id| format!("quote:{id}"))
            .unwrap_or_else(|| format!("swap:{:?}", r.swap_id)),
        _ => "unsupported".into(),
    }
}

fn request_scope(request: &SwapMessage) -> String {
    request.delivery_scope()
}

/// Match identity as well as message kind before consuming a response.
pub fn reply_matches(request: &SwapMessage, reply: &SwapMessage) -> bool {
    match (request, reply) {
        (SwapMessage::OfferRequest(r), SwapMessage::Offer(v)) => {
            r.request_id.is_some() && v.request_id == r.request_id
        }
        (SwapMessage::QuoteRequest(r), SwapMessage::Quote(v)) => {
            r.request_id.is_some() && v.request_id == r.request_id
        }
        (SwapMessage::SwapRequest(r), SwapMessage::SwapAccept(v)) => v.quote_id == r.quote_id,
        (SwapMessage::SwapStatusRequest(r), SwapMessage::SwapStatusSnapshot(v)) => {
            r.request_id.is_some()
                && v.request_id == r.request_id
                && r.quote_id.is_none_or(|id| v.accept.quote_id == id)
                && r.swap_id.is_none_or(|id| v.accept.swap_id == id)
        }
        (SwapMessage::OfferRequest(r), SwapMessage::Reject(v)) => {
            r.request_id.is_some() && v.request_id == r.request_id
        }
        (SwapMessage::QuoteRequest(r), SwapMessage::Reject(v)) => {
            r.request_id.is_some() && v.request_id == r.request_id
        }
        (SwapMessage::SwapRequest(r), SwapMessage::Reject(v)) => v.quote_id == Some(r.quote_id),
        (SwapMessage::SwapStatusRequest(r), SwapMessage::Reject(v)) => {
            r.request_id.is_some() && v.request_id == r.request_id
        }
        _ => false,
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

    pub fn acknowledge(&self, request: &SwapMessage) -> Result<()> {
        if let Some(channel) = &self.preferred {
            channel.acknowledge(request)?;
        }
        if let Some(channel) = &self.fallback {
            channel.acknowledge(request)?;
        }
        Ok(())
    }

    pub async fn close(&self) {
        if let Some(channel) = &self.preferred {
            channel.close().await;
        }
        if let Some(channel) = &self.fallback {
            channel.close().await;
        }
    }

    /// Bounded maintenance runs alongside execution and is canceled when the caller completes.
    pub(crate) async fn maintenance(&self) {
        loop {
            sleep(Duration::from_secs(10)).await;
            if let Some(channel) = &self.fallback {
                channel.maintain().await;
            }
        }
    }

    /// Recover a creation whose exact request was persisted by an earlier process.
    pub async fn recover_creation(&self, request: &SwapRequest) -> Result<SwapAccept> {
        negotiation_deadline(self.recover_creation_within_deadline(request)).await
    }

    async fn recover_creation_within_deadline(&self, request: &SwapRequest) -> Result<SwapAccept> {
        // A crash may precede publication. Replay the saved request without changing its keys.
        let message = SwapMessage::SwapRequest(request.clone());
        let expected = |reply: &SwapMessage| matches!(reply, SwapMessage::SwapAccept(_));
        match self.exchange(&message, expected).await {
            Ok(Exchanged {
                reply: SwapMessage::SwapAccept(accept),
                ..
            }) if accept.quote_id == request.quote_id => Ok(accept),
            Ok(Exchanged { reply, .. }) => self.recover(request.quote_id, rejection(reply)).await,
            Err(error) => self.recover(request.quote_id, error.into_inner()).await,
        }
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
        negotiation_deadline(self.offer_within_deadline()).await
    }

    async fn offer_within_deadline(&self) -> Result<SwapOffer> {
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
            SwapMessage::Offer(offer) if offer.request_id == request_id => {
                self.acknowledge(&request)?;
                Ok(offer)
            }
            SwapMessage::Offer(_) => Err(anyhow!("offer answers a different request")),
            other => Err(rejection(other)),
        }
    }

    pub async fn quote(&self, request: &QuoteRequest) -> Result<Quote> {
        negotiation_deadline(self.quote_within_deadline(request)).await
    }

    async fn quote_within_deadline(&self, request: &QuoteRequest) -> Result<Quote> {
        let message = SwapMessage::QuoteRequest(request.clone());
        let expected = |m: &SwapMessage| matches!(m, SwapMessage::Quote(_));
        match self
            .exchange(&message, expected)
            .await
            .map_err(ExchangeError::into_inner)?
            .reply
        {
            SwapMessage::Quote(quote)
                if request.request_id.is_some() && quote.request_id == request.request_id =>
            {
                self.acknowledge(&message)?;
                Ok(quote)
            }
            SwapMessage::Quote(_) => Err(anyhow!("quote answers a different request")),
            other => Err(rejection(other)),
        }
    }

    /// Create the swap, or recover the one an earlier attempt already created.
    pub async fn create(&self, request: &SwapRequest) -> Result<SwapAccept> {
        negotiation_deadline(self.create_within_deadline(request)).await
    }

    async fn create_within_deadline(&self, request: &SwapRequest) -> Result<SwapAccept> {
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
    /// has passed. Only a refusal of this status query is final: DMs also deliver late replies to
    /// earlier requests, and a transport that failed may come back while the provider restarts.
    async fn recover(&self, quote_id: Uuid, cause: Error) -> Result<SwapAccept> {
        let deadline = Instant::now() + RECOVERY_WINDOW;
        loop {
            self.preferred_unavailable.store(false, Ordering::Relaxed);
            let query = SwapStatusRequest {
                request_id: Some(Uuid::new_v4()),
                swap_id: None,
                quote_id: Some(quote_id),
            };
            let message = SwapMessage::SwapStatusRequest(query.clone());
            let expected = |m: &SwapMessage| matches!(m, SwapMessage::SwapStatusSnapshot(_));
            match tokio::time::timeout_at(deadline, self.exchange(&message, expected))
                .await
                .unwrap_or_else(|_| {
                    Err(ExchangeError::Uncertain(anyhow!(
                        "recovery deadline elapsed"
                    )))
                })
                .map(|e| e.reply)
            {
                Ok(SwapMessage::SwapStatusSnapshot(snapshot))
                    if snapshot.request_id == query.request_id
                        && snapshot.accept.quote_id == quote_id =>
                {
                    info!("recovered swap {} by its quote", snapshot.accept.swap_id);
                    return Ok(snapshot.accept);
                }
                Ok(SwapMessage::Reject(Reject {
                    code, request_id, ..
                })) if request_id == query.request_id
                    && !matches!(code.as_deref(), Some("not_found" | "pending")) =>
                {
                    return Err(cause);
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(cause.context(format!(
                    "the provider may have created a swap for quote {quote_id}; query its status before requesting another"
                )));
            }
            tokio::time::sleep_until((Instant::now() + RECOVERY_POLL).min(deadline)).await;
        }
    }

    pub async fn status(&self, request: &SwapStatusRequest) -> Result<SwapStatusSnapshot> {
        negotiation_deadline(self.status_within_deadline(request)).await
    }

    async fn status_within_deadline(
        &self,
        request: &SwapStatusRequest,
    ) -> Result<SwapStatusSnapshot> {
        let message = SwapMessage::SwapStatusRequest(request.clone());
        let expected = |m: &SwapMessage| matches!(m, SwapMessage::SwapStatusSnapshot(_));
        match self
            .exchange(&message, expected)
            .await
            .map_err(ExchangeError::into_inner)?
            .reply
        {
            SwapMessage::SwapStatusSnapshot(snapshot)
                if request.request_id.is_some()
                    && snapshot.request_id == request.request_id
                    && request
                        .quote_id
                        .is_none_or(|id| snapshot.accept.quote_id == id)
                    && request
                        .swap_id
                        .is_none_or(|id| snapshot.accept.swap_id == id) =>
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

async fn negotiation_deadline<T>(
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(RECOVERY_WINDOW, future)
        .await
        .map_err(|_| {
            anyhow!(
                "negotiation deadline elapsed; any persisted creation remains pending for recovery"
            )
        })?
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
    connect_inner(identity, provider, preference, rendezvous_iroh, None).await
}

pub async fn connect_durable(
    identity: &swap_config::Identity,
    provider: &str,
    preference: Negotiation,
    rendezvous_iroh: bool,
    data_dir: &Path,
) -> Result<(Negotiator<Preferred, DmChannel>, String)> {
    connect_inner(
        identity,
        provider,
        preference,
        rendezvous_iroh,
        Some(data_dir),
    )
    .await
}

async fn connect_inner(
    identity: &swap_config::Identity,
    provider: &str,
    preference: Negotiation,
    rendezvous_iroh: bool,
    data_dir: Option<&Path>,
) -> Result<(Negotiator<Preferred, DmChannel>, String)> {
    let provider = pubky_transport::canonical_pubky(provider)?;
    let provider = provider.as_str();
    #[cfg(feature = "iroh")]
    let secret = pubky_transport::identity::secret_from_recovery(
        identity.method,
        &identity.value,
        &identity.passphrase,
    )?;
    let transport =
        Transport::unsigned_from_recovery(identity.method, &identity.value, &identity.passphrase)?;
    let client_pkarr = transport.public_key_string();
    #[cfg(feature = "iroh")]
    let doorbell = rendezvous_iroh.then_some(secret);
    #[cfg(not(feature = "iroh"))]
    let doorbell = None;
    let dm = || -> Result<DmChannel> {
        let mut transport = transport;
        let mut accepted_store = None;
        if let Some(data_dir) = data_dir {
            let journal = data_dir
                .join("transport")
                .join(&client_pkarr)
                .join(provider);
            transport = transport
                .with_receive_journal(journal.join("inbox.json"))?
                .with_outbox(journal.join("outbox.json"))?;
            accepted_store = Some(JsonFileSwapStore::new(data_dir.join("swaps"))?);
        }
        let mut channel = DmChannel::new(transport, provider, false, doorbell);
        channel.accepted_store = accepted_store;
        Ok(channel)
    };
    #[cfg(feature = "iroh")]
    {
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
        let fallback = match (preference != Negotiation::Iroh).then(dm).transpose() {
            Ok(fallback) => fallback,
            Err(error) => {
                if let Some(channel) = &preferred {
                    channel.close().await;
                }
                return Err(error);
            }
        };
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
        let fallback = dm()?;
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
        /// Not delivered; a late, uncorrelated refusal of an earlier request came back instead.
        StaleReject,
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
        match fault {
            Some(Fault::NotSent) => {
                return Err(ExchangeError::NotSent(anyhow!("no application protocol")))
            }
            Some(Fault::StaleReject) => return Ok(reject("unknown or expired quote")),
            _ => {}
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
    async fn recovery_ignores_late_rejections_and_retries_a_transport_that_was_down() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(
            &provider,
            [Fault::NotSent, Fault::NotSent],
            Some(vec![Fault::LostReply, Fault::StaleReject]),
        );
        let request = swap_request(Uuid::new_v4());
        let accept = negotiator.create(&request).await.unwrap();
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        // The second status query went over iroh once it was reachable again.
        assert_eq!(negotiator.preferred().unwrap().0.seen().len(), 1);
        let stored = provider.accepted.lock().unwrap()[&request.quote_id]
            .1
            .swap_id;
        assert_eq!(accept.swap_id, stored);
    }

    #[tokio::test]
    async fn an_unsent_status_query_does_not_end_recovery() {
        let provider = Arc::new(Provider::default());
        let negotiator = negotiator(
            &provider,
            [Fault::LostReply, Fault::LostReply, Fault::NotSent],
            None,
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

    #[tokio::test]
    async fn restarting_before_publication_replays_the_saved_creation() {
        let provider = Arc::new(Provider::default());
        let request = swap_request(Uuid::new_v4());
        let saved: SwapRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        let negotiator = negotiator(&provider, [], Some(vec![]));
        negotiator.recover_creation(&saved).await.unwrap();
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
        assert_eq!(
            negotiator.preferred().unwrap().0.seen(),
            vec![serde_json::to_value(SwapMessage::SwapRequest(request)).unwrap()]
        );
    }

    #[tokio::test]
    async fn restarting_after_publication_checks_a_refused_replay_against_status() {
        let provider = Arc::new(Provider::default());
        let request = swap_request(Uuid::new_v4());
        let original = provider.handle(&SwapMessage::SwapRequest(request.clone()));
        provider.refuse_replays.store(true, Ordering::SeqCst);
        let negotiator = negotiator(&provider, [], Some(vec![]));
        let recovered = negotiator.recover_creation(&request).await.unwrap();
        let SwapMessage::SwapAccept(original) = original else {
            panic!("expected acceptance")
        };
        assert_eq!(original, recovered);
        assert_eq!(provider.creations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unmatched_read_only_replies_do_not_discard_creation_outcomes() {
        let quote = Provider::default().handle(&SwapMessage::QuoteRequest(quote_request()));
        assert!(read_only_reply(&quote));
        assert!(!read_only_reply(&SwapMessage::SwapAccept(acceptance(
            Uuid::new_v4()
        ))));
        assert!(read_only_reply(&reject("creation outcome")));
        let first = SwapMessage::SwapRequest(swap_request(Uuid::new_v4()));
        let unrelated = SwapMessage::SwapAccept(acceptance(Uuid::new_v4()));
        assert!(!reply_matches(&first, &unrelated));
        assert!(
            request_scope(&SwapMessage::QuoteRequest(quote_request())).starts_with("ephemeral:")
        );
        assert!(request_scope(&first).starts_with("quote:"));
    }

    #[tokio::test]
    async fn waiting_for_an_exchange_slot_obeys_the_reply_deadline() {
        let transport = Transport::unsigned([7; 32]).unwrap();
        let provider = pubky_transport::identity_from_secret(&[8; 32]);
        let mut channel = DmChannel::new(transport, &provider, false, None);
        channel.reply_timeout = Duration::from_millis(20);
        let _guard = channel.exchanges.lock().await;
        let request = SwapMessage::QuoteRequest(quote_request());
        let started = Instant::now();
        let result = channel
            .exchange(&request, |reply| matches!(reply, SwapMessage::Quote(_)))
            .await;
        assert!(matches!(result, Err(ExchangeError::Uncertain(_))));
        assert!(started.elapsed() < Duration::from_millis(750));
        assert_eq!(channel.transport().homeserver_requests(), 0);
    }

    #[tokio::test]
    async fn durable_connections_open_journals_without_signing_in_and_release_them_on_drop() {
        let dir = std::env::temp_dir().join(format!("client-dm-journals-{}", Uuid::new_v4()));
        let identity = swap_config::Identity { method: "phrase",
            value: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: String::new() };
        let provider = pubky_transport::identity_from_secret(&[8; 32]);
        let (negotiator, owner) =
            connect_durable(&identity, &provider, Negotiation::Dm, false, &dir)
                .await
                .unwrap();
        assert_eq!(
            negotiator
                .fallback()
                .unwrap()
                .transport()
                .homeserver_requests(),
            0
        );
        assert!(dir.join("transport").join(owner).join(&provider).is_dir());
        negotiator.close().await;
        drop(negotiator);
        let (reopened, _) = connect_durable(&identity, &provider, Negotiation::Dm, false, &dir)
            .await
            .unwrap();
        assert_eq!(
            reopened
                .fallback()
                .unwrap()
                .transport()
                .homeserver_requests(),
            0
        );
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct Never;
    impl Channel for Never {
        const NAME: &'static str = "pending test channel";
        async fn exchange(
            &self,
            _: &SwapMessage,
            _: fn(&SwapMessage) -> bool,
        ) -> std::result::Result<SwapMessage, ExchangeError> {
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn every_public_negotiation_operation_has_one_total_deadline() {
        let negotiator = Negotiator::<_, Unavailable>::new(Some(Never), None);
        let request = swap_request(Uuid::new_v4());
        let status = SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: None,
            quote_id: Some(request.quote_id),
        };
        let start = Instant::now();
        assert!(negotiator
            .offer()
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        assert!(negotiator
            .quote(&quote_request())
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        assert!(negotiator
            .create(&request)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        assert!(negotiator
            .recover_creation(&request)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        assert!(negotiator
            .status(&status)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        assert_eq!(start.elapsed(), RECOVERY_WINDOW * 5);
    }

    struct LateReply {
        canceled: AtomicUsize,
    }
    struct DropCount<'a>(&'a AtomicUsize);
    impl Drop for DropCount<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Channel for LateReply {
        const NAME: &'static str = "late test channel";
        async fn exchange(
            &self,
            request: &SwapMessage,
            _: fn(&SwapMessage) -> bool,
        ) -> std::result::Result<SwapMessage, ExchangeError> {
            let _guard = DropCount(&self.canceled);
            sleep(RECOVERY_WINDOW + Duration::from_secs(1)).await;
            let SwapMessage::SwapRequest(request) = request else {
                panic!("creation expected")
            };
            Ok(SwapMessage::SwapAccept(acceptance(request.quote_id)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn late_replies_are_canceled_at_the_total_deadline_without_detached_work() {
        let negotiator = Negotiator::<_, Unavailable>::new(
            Some(LateReply {
                canceled: AtomicUsize::new(0),
            }),
            None,
        );
        let start = Instant::now();
        assert!(negotiator
            .create(&swap_request(Uuid::new_v4()))
            .await
            .is_err());
        assert_eq!(start.elapsed(), RECOVERY_WINDOW);
        assert_eq!(
            negotiator
                .preferred()
                .unwrap()
                .canceled
                .load(Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn repeated_pending_rejections_never_need_a_durable_acceptance_receipt() {
        let quote_id = Uuid::new_v4();
        for _ in 0..64 {
            let request_id = Some(Uuid::new_v4());
            let request = SwapMessage::SwapStatusRequest(SwapStatusRequest {
                request_id,
                swap_id: None,
                quote_id: Some(quote_id),
            });
            let reply = SwapMessage::Reject(Reject {
                request_id,
                quote_id: Some(quote_id),
                swap_id: None,
                code: Some("pending".into()),
                reason: "creation pending".into(),
            });
            assert!(reply_matches(&request, &reply));
            assert!(
                read_only_reply(&reply),
                "a correlated pending reply must be acknowledged immediately"
            );
        }
        assert!(!read_only_reply(&SwapMessage::SwapAccept(acceptance(
            quote_id
        ))));
    }

    #[test]
    fn retry_replies_may_change_read_only_fields_but_not_accepted_contracts() {
        let provider = Provider::default();
        let quote_request = SwapMessage::QuoteRequest(quote_request());
        let first = provider.handle(&quote_request);
        let second = provider.handle(&quote_request);
        assert_ne!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(&second).unwrap()
        );
        assert!(!acceptance_conflicts(&first, &second));

        let request = swap_request(Uuid::new_v4());
        let accepted = provider.handle(&SwapMessage::SwapRequest(request.clone()));
        let query = SwapMessage::SwapStatusRequest(SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: None,
            quote_id: Some(request.quote_id),
        });
        let first = provider.handle(&query);
        let mut second = first.clone();
        let SwapMessage::SwapStatusSnapshot(snapshot) = &mut second else {
            panic!("snapshot expected")
        };
        snapshot.observed_at_unix = 1234;
        snapshot.updated_at_unix = 1233;
        snapshot.state = swap_common::SwapState::LockupPending;
        assert!(!acceptance_conflicts(&first, &second));
        assert!(!acceptance_conflicts(&accepted, &second));
        let SwapMessage::SwapStatusSnapshot(snapshot) = &mut second else {
            unreachable!()
        };
        snapshot.accept.onchain_amount_sat += 1;
        assert!(acceptance_conflicts(&first, &second));
        assert!(acceptance_conflicts(&accepted, &second));
    }
}
