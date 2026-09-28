//! Direct P2P rendezvous over [iroh](https://docs.rs/iroh) (feature `iroh`).
//!
//! iroh provides NAT-holepunched, relay-fallback QUIC connections addressed by an ed25519
//! **endpoint id**, and can discover peers via pkarr / the mainline DHT (the same foundation the
//! pubky stack already uses). We reuse the swap identity as the iroh identity: an endpoint built
//! from the pubky's ed25519 secret has `endpoint_id == pubky` (see [`iroh_identity_equals_pubky`]
//! test), so:
//!
//! * a client can address a provider directly by the provider's pubky, and
//! * the provider learns the *authenticated* client pubky from the QUIC handshake, with no signed
//!   hello payload needed (the handshake proves the client holds that key).
//!
//! ## Role in a swap
//!
//! The legacy protocol is **rendezvous only**. The provider accepts a connection, reads the remote pubky, adds it
//! to its poll set, and the actual swap runs over pubky-DM (then eviction, see
//! [`Transport::evict_peer`](crate::Transport::evict_peer)). A returning client simply reconnects,
//! which is what makes eviction lossless. iroh handles NAT traversal (holepunch + relay fallback),
//! so the provider does not need a manually forwarded port.
//!
//! The separate session ALPNs carry encrypted requests for Ring-authorized clients. Their
//! transport key is verified against a scoped homeserver authorization before the application
//! handles each request. `session/1` carries one request per connection; `session/2` carries many,
//! and clients fall back to `session/1` against providers that predate it.
//!
//! `direct/1` uses the `session/2` framing for requests from a root Pubky key. The QUIC handshake
//! authenticates that key, so no homeserver lookup is made, and the request carries no account or
//! scope: it can never act under a scoped session's authorization. Legacy rendezvous is unchanged.

use iroh::endpoint::{presets, ConnectOptions, Connection, QuicTransportConfig, VarInt};
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey as IrohPublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::debug;

use crate::{Result, TransportError};

/// Install process-lifetime JVM and application context pointers for Android DNS.
#[cfg(target_os = "android")]
pub use iroh::dns::install_android_jni_context;

/// ALPN identifying the pubky-swap rendezvous protocol. Both ends must present the same string or
/// iroh aborts the connection.
pub const SWAP_ALPN: &[u8] = b"pubky-swap/rendezvous/1";

/// Encrypted request/reply transport for scoped Pubky sessions: one request per connection.
pub const SESSION_ALPN: &[u8] = b"pubky-swap/session/1";
/// The same request framing as [`SESSION_ALPN`], with any number of request streams per
/// connection. Clients offer both, so a provider that only knows `session/1` still negotiates.
pub const SESSION_MULTIPLEX_ALPN: &[u8] = b"pubky-swap/session/2";
/// Requests from the root key the connection authenticated, with the [`SESSION_MULTIPLEX_ALPN`]
/// stream limits. Providers that predate it refuse the handshake, before any request is sent.
pub const DIRECT_ALPN: &[u8] = b"pubky-swap/direct/1";
const MAX_RPC_BYTES: usize = 64 * 1024;

/// Inbound connections held at once, rendezvous and session together.
const MAX_CONNECTIONS: usize = 32;
/// Request streams one session connection may have open at once. Enforced by QUIC flow control,
/// so a client past the limit waits to open a stream instead of being refused.
const MAX_SESSION_STREAMS: u32 = 8;
/// Longest a session connection may sit with no open request stream.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest one request may take, from its stream being accepted to its reply being acknowledged.
const SESSION_STREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// Shorter than the provider's idle timeout, so a client does not pick a connection the provider
/// is about to close. Requests that race a close anyway fail rather than being resent.
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const CLIENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest a client waits for a new connection. Nothing has been sent by then, so a caller can
/// move on to another transport well before the request deadline.
const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Stream reset code for a request the provider did not answer.
const REQUEST_REJECTED: u32 = 1;

/// An authenticated transport connection awaiting application authorization.
pub struct SessionRpc {
    pub remote_key: String,
    pub request: crate::session_rpc::SessionRequest,
    pub reply: oneshot::Sender<Vec<u8>>,
}

/// Request envelope on [`DIRECT_ALPN`]. The sender is the connection's remote key, never a field.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectRequest {
    pub message: serde_json::Value,
}

/// A request from the root key that authenticated the connection. It needs no further
/// authorization and grants none beyond what that key already owns.
pub struct DirectRpc {
    pub remote_key: String,
    pub message: serde_json::Value,
    pub reply: oneshot::Sender<Vec<u8>>,
}

/// Convert a pkarr pubky string to an iroh endpoint id (both are the same 32-byte ed25519 key).
pub fn pubky_to_endpoint_id(pubky: &str) -> Result<EndpointId> {
    let pk = pkarr::PublicKey::try_from(pubky)
        .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
    IrohPublicKey::from_bytes(&pk.to_bytes())
        .map_err(|e| TransportError::Iroh(format!("endpoint id from pubky: {e}")))
}

/// Convert an iroh endpoint id back to a pkarr pubky string.
pub fn endpoint_id_to_pubky(id: &EndpointId) -> Result<String> {
    let pk = pkarr::PublicKey::try_from(&id.as_bytes()[..])
        .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
    Ok(pk.to_string())
}

/// Build an iroh endpoint whose id equals the pubky derived from `secret`. `accepting` endpoints
/// advertise the swap ALPN so they can receive rendezvous connections.
async fn build_endpoint(secret: [u8; 32], alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(SecretKey::from_bytes(&secret));
    if !alpns.is_empty() {
        builder = builder
            .alpns(alpns)
            .transport_config(accepting_transport_config());
    }
    builder
        .bind()
        .await
        .map_err(|e| TransportError::Iroh(format!("bind endpoint: {e}")))
}

fn accepting_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_SESSION_STREAMS))
        .build()
}

/// Provider-side iroh rendezvous endpoint. Accepts inbound connections and reports the pubky of
/// each connecting client (authenticated by the QUIC handshake) via [`next_peer`](Self::next_peer).
pub struct RendezvousServer {
    endpoint: Endpoint,
    peers: mpsc::Receiver<String>,
    requests: mpsc::Receiver<SessionRpc>,
    direct: mpsc::Receiver<DirectRpc>,
}

impl RendezvousServer {
    /// Bind an endpoint whose id is `secret`'s public key (== the provider pubky), publish it via
    /// iroh discovery, and start accepting rendezvous connections.
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        Self::bind_protocols(secret, vec![SWAP_ALPN.to_vec()]).await
    }

    /// Accept legacy rendezvous, scoped-session and direct requests on the same endpoint.
    pub async fn bind_with_sessions(secret: [u8; 32]) -> Result<Self> {
        // The server picks the first ALPN in this list that the client offers.
        Self::bind_protocols(
            secret,
            vec![
                SWAP_ALPN.to_vec(),
                SESSION_MULTIPLEX_ALPN.to_vec(),
                SESSION_ALPN.to_vec(),
                DIRECT_ALPN.to_vec(),
            ],
        )
        .await
    }

    async fn bind_protocols(secret: [u8; 32], alpns: Vec<Vec<u8>>) -> Result<Self> {
        let endpoint = build_endpoint(secret, alpns).await?;
        let (tx, rx) = mpsc::channel(256);
        let (request_tx, requests) = mpsc::channel(16);
        let (direct_tx, direct) = mpsc::channel(16);
        let handlers = Handlers {
            session: request_tx,
            direct: direct_tx,
        };
        spawn_accept_loop(endpoint.clone(), tx, handlers, SessionLimits::default());
        Ok(Self {
            endpoint,
            peers: rx,
            requests,
            direct,
        })
    }

    /// This endpoint's own pubky (== the provider pubky).
    pub fn pubky(&self) -> Result<String> {
        endpoint_id_to_pubky(&self.endpoint.id())
    }

    /// Await the next client pubky that connected for a swap. `None` once the endpoint is closed.
    pub async fn next_peer(&mut self) -> Option<String> {
        self.peers.recv().await
    }

    /// Await a legacy peer, a session request or a direct request without competing borrows.
    pub async fn next_event(&mut self) -> Option<RendezvousEvent> {
        tokio::select! {
            peer = self.peers.recv() => peer.map(RendezvousEvent::Peer),
            request = self.requests.recv() => request.map(RendezvousEvent::Session),
            request = self.direct.recv() => request.map(RendezvousEvent::Direct),
        }
    }

    /// Close the endpoint (stops the accept loop).
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// Inbound transport work. Session requests still require homeserver authorization; direct
/// requests are already authenticated as their remote key.
pub enum RendezvousEvent {
    Peer(String),
    Session(SessionRpc),
    Direct(DirectRpc),
}

/// Where each request protocol delivers its requests.
#[derive(Clone)]
pub(crate) struct Handlers {
    pub(crate) session: mpsc::Sender<SessionRpc>,
    pub(crate) direct: mpsc::Sender<DirectRpc>,
}

#[derive(Clone)]
enum Handler {
    Session(mpsc::Sender<SessionRpc>),
    Direct(mpsc::Sender<DirectRpc>),
}

impl Handler {
    /// Hand one request to the application, or `None` if it is malformed or nobody is listening.
    async fn dispatch(
        &self,
        remote_key: String,
        bytes: &[u8],
    ) -> Option<oneshot::Receiver<Vec<u8>>> {
        let (reply, result) = oneshot::channel();
        match self {
            Self::Session(requests) => {
                let request = serde_json::from_slice(bytes).ok()?;
                let rpc = SessionRpc {
                    remote_key,
                    request,
                    reply,
                };
                requests.send(rpc).await.ok()?;
            }
            Self::Direct(requests) => {
                let request: DirectRequest = serde_json::from_slice(bytes).ok()?;
                let rpc = DirectRpc {
                    remote_key,
                    message: request.message,
                    reply,
                };
                requests.send(rpc).await.ok()?;
            }
        }
        Some(result)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SessionLimits {
    idle: Duration,
    stream: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            idle: SESSION_IDLE_TIMEOUT,
            stream: SESSION_STREAM_TIMEOUT,
        }
    }
}

fn spawn_accept_loop(
    endpoint: Endpoint,
    tx: mpsc::Sender<String>,
    handlers: Handlers,
    limits: SessionLimits,
) {
    tokio::spawn(async move {
        let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        while let Some(incoming) = endpoint.accept().await {
            let Ok(permit) = capacity.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let tx = tx.clone();
            let handlers = handlers.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let conn = match tokio::time::timeout(Duration::from_secs(10), incoming).await {
                    Ok(Ok(c)) => c,
                    _ => {
                        debug!("rendezvous: incoming connection failed");
                        return;
                    }
                };
                if conn.alpn() == SESSION_ALPN || conn.alpn() == SESSION_MULTIPLEX_ALPN {
                    serve_session(conn, Handler::Session(handlers.session), limits).await;
                    return;
                }
                if conn.alpn() == DIRECT_ALPN {
                    serve_session(conn, Handler::Direct(handlers.direct), limits).await;
                    return;
                }
                match endpoint_id_to_pubky(&conn.remote_id()) {
                    Ok(pubky) => {
                        // The authenticated remote id is all we need; hand it upward and release
                        // the connection so the swap can proceed over pubky-DM.
                        let _ = tx.send(pubky).await;
                        conn.close(0u32.into(), b"registered");
                    }
                    Err(e) => debug!("rendezvous: unusable remote id: {e}"),
                }
            });
        }
    });
}

/// Serve request streams until the peer leaves or the connection stops being useful.
///
/// Each stream becomes its own request, so the provider authorizes every request on its own and
/// an open connection never stands in for a current authorization.
async fn serve_session(conn: Connection, handler: Handler, limits: SessionLimits) {
    let Ok(remote_key) = endpoint_id_to_pubky(&conn.remote_id()) else {
        conn.close(0u32.into(), b"unusable remote id");
        return;
    };
    if conn.alpn() == SESSION_ALPN {
        if let Ok(Ok((send, receive))) = tokio::time::timeout(limits.stream, conn.accept_bi()).await
        {
            serve_stream(remote_key, send, receive, handler, limits.stream).await;
        }
        conn.close(0u32.into(), b"request complete");
        return;
    }
    // Dropping the set on exit aborts streams still running, which resets them.
    let mut streams = JoinSet::new();
    // Streams that always time out keep a connection busy without ever being idle, so a
    // connection also closes once it has gone this long without delivering a reply.
    let unproductive = limits.idle + limits.stream;
    let mut last_reply = Instant::now();
    loop {
        tokio::select! {
            accepted = conn.accept_bi() => {
                let Ok((send, receive)) = accepted else { return };
                streams.spawn(serve_stream(
                    remote_key.clone(),
                    send,
                    receive,
                    handler.clone(),
                    limits.stream,
                ));
            }
            Some(finished) = streams.join_next(), if !streams.is_empty() => {
                if matches!(finished, Ok(true)) {
                    last_reply = Instant::now();
                }
            }
            () = tokio::time::sleep(limits.idle), if streams.is_empty() => {
                conn.close(0u32.into(), b"idle");
                return;
            }
            () = tokio::time::sleep_until(last_reply + unproductive) => {
                conn.close(0u32.into(), b"no replies");
                return;
            }
        }
    }
}

/// Answer one request stream. Returns whether the reply was delivered.
async fn serve_stream(
    remote_key: String,
    mut send: iroh::endpoint::SendStream,
    mut receive: iroh::endpoint::RecvStream,
    handler: Handler,
    timeout: Duration,
) -> bool {
    let exchange = async {
        let bytes = receive.read_to_end(MAX_RPC_BYTES).await.ok()?;
        let result = handler.dispatch(remote_key, &bytes).await?;
        let bytes = result.await.ok()?;
        if bytes.len() > MAX_RPC_BYTES {
            return None;
        }
        send.write_all(&bytes).await.ok()?;
        send.finish().ok()?;
        // Resolves once the client has acknowledged the whole reply.
        send.stopped().await.ok()?;
        Some(())
    };
    let delivered = matches!(tokio::time::timeout(timeout, exchange).await, Ok(Some(())));
    if !delivered {
        // A dropped send stream finishes cleanly, which would read as an empty reply.
        let _ = send.reset(REQUEST_REJECTED.into());
    }
    delivered
}

/// A request protocol an [`RpcClient`] can speak.
pub trait RpcProtocol {
    type Request: Serialize;
    /// Carries many requests per connection.
    const ALPN: &'static [u8];
    /// An older single-request ALPN also offered, for providers that predate [`Self::ALPN`].
    const SINGLE_REQUEST_ALPN: Option<&'static [u8]>;
}

/// Scoped-session requests, authorized by the provider against the account's homeserver.
pub enum Session {}

impl RpcProtocol for Session {
    type Request = crate::session_rpc::SessionRequest;
    const ALPN: &'static [u8] = SESSION_MULTIPLEX_ALPN;
    const SINGLE_REQUEST_ALPN: Option<&'static [u8]> = Some(SESSION_ALPN);
}

/// Requests from a root Pubky key, authenticated by the connection alone.
pub enum Direct {}

impl RpcProtocol for Direct {
    type Request = DirectRequest;
    const ALPN: &'static [u8] = DIRECT_ALPN;
    const SINGLE_REQUEST_ALPN: Option<&'static [u8]> = None;
}

pub type SessionRpcClient = RpcClient<Session>;
pub type DirectRpcClient = RpcClient<Direct>;

/// Request/reply client for one provider, reusing one endpoint and, while it stays healthy, one
/// connection.
///
/// A request is sent at most once. If a request fails after its stream opened, the provider may
/// have acted on it, so the error goes to the caller, who recovers through swap status or
/// creation replay, and that holds for a request that is cancelled or runs past its deadline too.
/// The next request opens a new connection if the old one has closed. A cancelled request only
/// abandons its own stream, so other requests keep the connection.
///
/// A failure that certainly sent nothing, such as a provider that refuses the protocol, is
/// [`TransportError::NotSent`], so a caller may take the request elsewhere.
pub struct RpcClient<P> {
    endpoint: Endpoint,
    provider: EndpointAddr,
    pooled: tokio::sync::Mutex<Option<Pooled>>,
    requests: Semaphore,
    idle_timeout: Duration,
    request_timeout: Duration,
    connect_timeout: Duration,
    connections: AtomicUsize,
    protocol: PhantomData<fn() -> P>,
}

struct Pooled {
    conn: Connection,
    last_used: Instant,
}

impl<P: RpcProtocol> RpcClient<P> {
    /// Bind an endpoint for `secret`'s key. No connection is made until the first
    /// request.
    pub async fn new(secret: [u8; 32], provider: &str) -> Result<Self> {
        let provider = pubky_to_endpoint_id(provider)?.into();
        let endpoint = build_endpoint(secret, vec![]).await?;
        Ok(Self::with_endpoint(endpoint, provider))
    }

    fn with_endpoint(endpoint: Endpoint, provider: EndpointAddr) -> Self {
        Self {
            endpoint,
            provider,
            pooled: tokio::sync::Mutex::new(None),
            requests: Semaphore::new(MAX_SESSION_STREAMS as usize),
            idle_timeout: CLIENT_IDLE_TIMEOUT,
            request_timeout: CLIENT_REQUEST_TIMEOUT,
            connect_timeout: CLIENT_CONNECT_TIMEOUT,
            connections: AtomicUsize::new(0),
            protocol: PhantomData,
        }
    }

    /// Connections this client has established, including any to a single-request provider.
    pub fn connections_established(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    /// Send one bounded request and wait for its reply.
    pub async fn request(&self, request: &P::Request) -> Result<Vec<u8>> {
        use crate::session_rpc::session_error;
        let bytes = serde_json::to_vec(request)?;
        if bytes.len() > MAX_RPC_BYTES {
            return Err(TransportError::NotSent("request is too large".into()));
        }
        let sent = AtomicBool::new(false);
        let operation = async {
            let _slot = self
                .requests
                .acquire()
                .await
                .map_err(|_| TransportError::NotSent("client closed".into()))?;
            let mut reconnected = false;
            loop {
                let conn = self.checkout().await?;
                // Opening a stream sends nothing, so failing here cannot have delivered the request.
                let Ok((mut send, mut receive)) = conn.open_bi().await else {
                    self.discard(&conn).await;
                    if reconnected {
                        return Err(TransportError::NotSent(
                            "could not open request stream".into(),
                        ));
                    }
                    reconnected = true;
                    continue;
                };
                sent.store(true, Ordering::Relaxed);
                let reply = async {
                    send.write_all(&bytes)
                        .await
                        .map_err(|_| session_error("could not send request"))?;
                    send.finish()
                        .map_err(|_| session_error("could not finish request"))?;
                    receive
                        .read_to_end(MAX_RPC_BYTES)
                        .await
                        .map_err(|_| session_error("request failed before its reply arrived"))
                }
                .await;
                self.checkin(&conn).await;
                return reply;
            }
        };
        match tokio::time::timeout(self.request_timeout, operation).await {
            Ok(result) => result,
            Err(_) if !sent.load(Ordering::Relaxed) => Err(TransportError::NotSent(
                "timed out before the request was sent".into(),
            )),
            Err(_) => Err(session_error("request timed out")),
        }
    }

    /// Close the pooled connection and the endpoint. Requests still running fail.
    pub async fn close(&self) {
        if let Some(pooled) = self.pooled.lock().await.take() {
            pooled.conn.close(0u32.into(), b"client closed");
        }
        self.endpoint.close().await;
    }

    async fn checkout(&self) -> Result<Connection> {
        // Held while connecting, so concurrent requests share one setup.
        let mut pooled = self.pooled.lock().await;
        if let Some(current) = pooled.as_mut() {
            if current.conn.close_reason().is_none()
                && current.last_used.elapsed() < self.idle_timeout
            {
                current.last_used = Instant::now();
                return Ok(current.conn.clone());
            }
        }
        *pooled = None;
        let options = ConnectOptions::new().with_additional_alpns(
            P::SINGLE_REQUEST_ALPN
                .map(<[u8]>::to_vec)
                .into_iter()
                .collect(),
        );
        let unavailable = || {
            TransportError::NotSent(
                "provider does not support this protocol or is unavailable".into(),
            )
        };
        let connect = async {
            self.endpoint
                .connect_with_opts(self.provider.clone(), P::ALPN, options)
                .await
                .map_err(|_| unavailable())?
                .await
                .map_err(|_| unavailable())
        };
        let conn = tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| unavailable())??;
        self.connections.fetch_add(1, Ordering::Relaxed);
        if conn.alpn() == P::ALPN {
            *pooled = Some(Pooled {
                conn: conn.clone(),
                last_used: Instant::now(),
            });
        }
        Ok(conn)
    }

    async fn checkin(&self, conn: &Connection) {
        if conn.alpn() != P::ALPN {
            conn.close(0u32.into(), b"reply received");
            return;
        }
        if let Some(current) = self.pooled.lock().await.as_mut() {
            if current.conn.stable_id() == conn.stable_id() {
                current.last_used = Instant::now();
            }
        }
    }

    async fn discard(&self, conn: &Connection) {
        let mut pooled = self.pooled.lock().await;
        if pooled
            .as_ref()
            .is_some_and(|current| current.conn.stable_id() == conn.stable_id())
        {
            *pooled = None;
        }
    }
}

/// Send one bounded request over a connection authenticated to the provider's Pubky.
///
/// Each call sets up its own endpoint and connection. Callers making more than one request
/// should keep a [`SessionRpcClient`].
pub async fn session_request(
    secret: [u8; 32],
    provider: &str,
    request: &crate::session_rpc::SessionRequest,
) -> Result<Vec<u8>> {
    let client = SessionRpcClient::new(secret, provider).await?;
    let result = client.request(request).await;
    client.close().await;
    result
}

/// Client-side: connect to a provider by its pubky so the provider learns our (authenticated)
/// pubky and starts polling us over pubky-DM. We send nothing; the handshake carries our identity.
pub async fn ring_provider(secret: [u8; 32], provider_pubky: &str) -> Result<()> {
    let endpoint = build_endpoint(secret, vec![]).await?;
    let target: EndpointAddr = pubky_to_endpoint_id(provider_pubky)?.into();
    let conn = endpoint
        .connect(target, SWAP_ALPN)
        .await
        .map_err(|e| TransportError::Iroh(format!("connect to provider: {e}")))?;
    conn.close(0u32.into(), b"registered");
    endpoint.close().await;
    Ok(())
}

#[cfg(test)]
pub(crate) mod fixture {
    //! A session provider and clients on loopback, with no discovery or relays.

    use super::*;
    use std::net::SocketAddr;

    pub(crate) async fn local_endpoint(
        secret: [u8; 32],
        alpns: Vec<Vec<u8>>,
        address: &str,
    ) -> Endpoint {
        // Rebinding a closed provider's address waits for its tasks to drop their handles.
        for _ in 0..50 {
            let bound = Endpoint::builder(presets::Minimal)
                .secret_key(SecretKey::from_bytes(&secret))
                .clear_ip_transports()
                .bind_addr(address)
                .unwrap()
                .alpns(alpns.clone())
                .transport_config(accepting_transport_config())
                .bind()
                .await;
            if let Ok(endpoint) = bound {
                return endpoint;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("could not bind {address}");
    }

    pub(crate) struct Provider {
        pub(crate) endpoint: Endpoint,
        pub(crate) requests: mpsc::Receiver<SessionRpc>,
        pub(crate) direct: mpsc::Receiver<DirectRpc>,
    }

    impl Provider {
        pub(crate) async fn start(secret: [u8; 32], limits: SessionLimits) -> Self {
            Self::start_at(secret, limits, "127.0.0.1:0".parse().unwrap()).await
        }

        pub(crate) async fn start_at(
            secret: [u8; 32],
            limits: SessionLimits,
            address: SocketAddr,
        ) -> Self {
            let alpns = vec![
                SESSION_MULTIPLEX_ALPN.to_vec(),
                SESSION_ALPN.to_vec(),
                DIRECT_ALPN.to_vec(),
            ];
            let endpoint = local_endpoint(secret, alpns, &address.to_string()).await;
            let (peers, _) = mpsc::channel(1);
            let (session, requests) = mpsc::channel(16);
            let (direct, direct_requests) = mpsc::channel(16);
            spawn_accept_loop(
                endpoint.clone(),
                peers,
                Handlers { session, direct },
                limits,
            );
            Self {
                endpoint,
                requests,
                direct: direct_requests,
            }
        }

        pub(crate) fn addr(endpoint: &Endpoint) -> EndpointAddr {
            EndpointAddr::new(endpoint.id()).with_ip_addr(endpoint.bound_sockets()[0])
        }

        pub(crate) async fn client<P: RpcProtocol>(&self, secret: [u8; 32]) -> RpcClient<P> {
            Self::client_for(&self.endpoint, secret).await
        }

        pub(crate) async fn client_for<P: RpcProtocol>(
            provider: &Endpoint,
            secret: [u8; 32],
        ) -> RpcClient<P> {
            let endpoint = local_endpoint(secret, vec![], "127.0.0.1:0").await;
            RpcClient::with_endpoint(endpoint, Self::addr(provider))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::session_rpc::SessionRequest;
    use fixture::{local_endpoint, Provider};

    fn request(message: impl Into<serde_json::Value>) -> SessionRequest {
        SessionRequest {
            owner: crate::identity_from_secret(&[8; 32]),
            scope: "/pub/bitkit.to/bitkit/wallet/".into(),
            message: message.into(),
        }
    }

    /// Replies to every request with its own message, and reports each message it saw.
    fn echo(
        mut provider: mpsc::Receiver<SessionRpc>,
    ) -> mpsc::UnboundedReceiver<serde_json::Value> {
        let (seen, messages) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(rpc) = provider.recv().await {
                let _ = seen.send(rpc.request.message.clone());
                let _ = rpc
                    .reply
                    .send(serde_json::to_vec(&rpc.request.message).unwrap());
            }
        });
        messages
    }

    fn echoed(message: impl Into<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&message.into()).unwrap()
    }

    fn closed_with(error: iroh::endpoint::ConnectionError, reason: &[u8]) -> bool {
        matches!(error, iroh::endpoint::ConnectionError::ApplicationClosed(close) if close.reason.as_ref() == reason)
    }

    #[tokio::test]
    async fn single_request_clients_negotiate_session_1_and_get_one_reply() {
        let Provider {
            endpoint: server,
            mut requests,
            ..
        } = Provider::start([1; 32], SessionLimits::default()).await;
        let client = local_endpoint([7; 32], vec![], "127.0.0.1:0").await;
        let operation = async {
            // The published client offers only session/1.
            let conn = client
                .connect(Provider::addr(&server), SESSION_ALPN)
                .await
                .unwrap();
            assert_eq!(conn.alpn(), SESSION_ALPN);
            let (mut send, mut receive) = conn.open_bi().await.unwrap();
            let claimed_owner = crate::identity_from_secret(&[8; 32]);
            send.write_all(&serde_json::to_vec(&request("example")).unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            let request = requests.recv().await.unwrap();
            assert_eq!(request.remote_key, crate::identity_from_secret(&[7; 32]));
            assert_ne!(request.remote_key, claimed_owner);
            assert_eq!(request.request.owner, claimed_owner);
            request.reply.send(b"verified reply".to_vec()).unwrap();
            assert_eq!(
                receive.read_to_end(MAX_RPC_BYTES).await.unwrap(),
                b"verified reply"
            );
            // The provider still ends a session/1 connection after its one request.
            assert!(closed_with(conn.closed().await, b"request complete"));
        };
        tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .unwrap();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn repeated_requests_share_one_connection() {
        let provider = Provider::start([1; 32], SessionLimits::default()).await;
        let client = provider.client::<Session>([2; 32]).await;
        let _seen = echo(provider.requests);
        for i in 0..5 {
            assert_eq!(client.request(&request(i)).await.unwrap(), echoed(i));
        }
        assert_eq!(client.connections_established(), 1);
        client.close().await;
        provider.endpoint.close().await;
    }

    #[tokio::test]
    async fn simultaneous_requests_get_their_own_replies() {
        let Provider {
            endpoint,
            mut requests,
            ..
        } = Provider::start([1; 32], SessionLimits::default()).await;
        let client = Provider::client_for::<Session>(&endpoint, [2; 32]).await;
        let count = MAX_SESSION_STREAMS as usize;
        // Hold every request until all have arrived, then answer in reverse order.
        let responder = tokio::spawn(async move {
            let mut pending = Vec::new();
            while pending.len() < count {
                pending.push(requests.recv().await.unwrap());
            }
            for rpc in pending.into_iter().rev() {
                let reply = format!("reply to {}", rpc.request.message);
                rpc.reply.send(reply.into_bytes()).unwrap();
            }
        });
        let replies = futures::future::join_all((0..count).map(|i| {
            let client = &client;
            async move { (i, client.request(&request(i)).await.unwrap()) }
        }));
        for (i, reply) in tokio::time::timeout(Duration::from_secs(10), replies)
            .await
            .unwrap()
        {
            assert_eq!(reply, format!("reply to {i}").into_bytes());
        }
        responder.await.unwrap();
        assert_eq!(client.connections_established(), 1);
        client.close().await;
        endpoint.close().await;
    }

    #[tokio::test]
    async fn providers_that_only_speak_session_1_get_a_connection_per_request() {
        // The single-request provider as published before session/2 existed.
        let legacy = local_endpoint([1; 32], vec![SESSION_ALPN.to_vec()], "127.0.0.1:0").await;
        let server = legacy.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    let conn = incoming.await.unwrap();
                    let (mut send, mut receive) = conn.accept_bi().await.unwrap();
                    let bytes = receive.read_to_end(MAX_RPC_BYTES).await.unwrap();
                    let request: SessionRequest = serde_json::from_slice(&bytes).unwrap();
                    send.write_all(&serde_json::to_vec(&request.message).unwrap())
                        .await
                        .unwrap();
                    send.finish().unwrap();
                    let _ = send.stopped().await;
                    conn.close(0u32.into(), b"request complete");
                });
            }
        });
        let client = Provider::client_for::<Session>(&legacy, [2; 32]).await;
        for i in 0..3 {
            assert_eq!(client.request(&request(i)).await.unwrap(), echoed(i));
        }
        assert_eq!(client.connections_established(), 3);
        client.close().await;
        legacy.close().await;
    }

    #[tokio::test]
    async fn a_request_whose_reply_is_lost_is_not_sent_again() {
        let Provider {
            endpoint,
            mut requests,
            ..
        } = Provider::start([1; 32], SessionLimits::default()).await;
        let address = endpoint.bound_sockets()[0];
        let client = Provider::client_for::<Session>(&endpoint, [2; 32]).await;

        // The provider receives the creation request and goes away before replying.
        let create = request("create");
        let (reply, received) = tokio::join!(client.request(&create), async {
            let rpc = requests.recv().await.unwrap();
            endpoint.close().await;
            rpc
        });
        assert!(reply.is_err());
        // The socket stays bound while any handle to the endpoint is alive.
        drop((endpoint, requests, received));

        // It comes back at the same address. The next request reconnects, and the provider
        // sees only that request: recovering the creation is left to swap status.
        let restarted = Provider::start_at([1; 32], SessionLimits::default(), address).await;
        let mut seen = echo(restarted.requests);
        assert_eq!(
            client.request(&request("status")).await.unwrap(),
            echoed("status")
        );
        assert_eq!(seen.recv().await.unwrap(), "status");
        assert!(seen.try_recv().is_err());
        assert_eq!(client.connections_established(), 2);
        client.close().await;
        restarted.endpoint.close().await;
    }

    #[tokio::test]
    async fn requests_that_outlive_their_deadline_fail_without_closing_the_connection() {
        let Provider {
            endpoint,
            mut requests,
            ..
        } = Provider::start([1; 32], SessionLimits::default()).await;
        let mut client = Provider::client_for::<Session>(&endpoint, [2; 32]).await;
        client.request_timeout = Duration::from_millis(300);
        let slow = request("slow");
        let (unanswered, _held) = tokio::join!(client.request(&slow), async {
            requests.recv().await.unwrap()
        });
        let error = unanswered.unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
        let _seen = echo(requests);
        assert_eq!(
            client.request(&request("next")).await.unwrap(),
            echoed("next")
        );
        assert_eq!(client.connections_established(), 1);
        client.close().await;
        endpoint.close().await;
    }

    #[tokio::test]
    async fn idle_and_stalled_connections_are_closed() {
        let limits = SessionLimits {
            idle: Duration::from_millis(1000),
            stream: Duration::from_millis(300),
        };
        let provider = Provider::start([1; 32], limits).await;
        let target = Provider::addr(&provider.endpoint);
        let raw = local_endpoint([3; 32], vec![], "127.0.0.1:0").await;

        // A connection that never opens a stream.
        let idle = raw
            .connect(target.clone(), SESSION_MULTIPLEX_ALPN)
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), idle.closed()).await;
        assert!(closed_with(closed.unwrap(), b"idle"));

        // A stream that never finishes its request is reset at the stream deadline.
        let stalled = raw
            .connect(target.clone(), SESSION_MULTIPLEX_ALPN)
            .await
            .unwrap();
        let (mut send, mut receive) = stalled.open_bi().await.unwrap();
        send.write_all(b"{\"owner\"").await.unwrap();
        let read = tokio::time::timeout(Duration::from_secs(5), receive.read_to_end(MAX_RPC_BYTES))
            .await
            .unwrap();
        assert!(matches!(
            read,
            Err(iroh::endpoint::ReadToEndError::Read(iroh::endpoint::ReadError::Reset(code)))
                if code == REQUEST_REJECTED.into()
        ));

        // Stalled streams opened back to back are never idle, but still never deliver a reply.
        let spammer = async {
            let mut open = Vec::new();
            loop {
                if let Ok((mut send, receive)) = stalled.open_bi().await {
                    let _ = send.write_all(b"{").await;
                    open.push((send, receive));
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let closed = tokio::select! {
            closed = stalled.closed() => closed,
            () = spammer => unreachable!(),
            () = tokio::time::sleep(Duration::from_secs(5)) => panic!("stalled connection stayed open"),
        };
        assert!(closed_with(closed, b"no replies"));

        // A pooled client notices the provider closed its idle connection and reconnects.
        let _seen = echo(provider.requests);
        let mut client = Provider::client_for::<Session>(&provider.endpoint, [2; 32]).await;
        client.idle_timeout = Duration::from_secs(60);
        assert_eq!(client.request(&request(1)).await.unwrap(), echoed(1));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(client.request(&request(2)).await.unwrap(), echoed(2));
        assert_eq!(client.connections_established(), 2);
        client.close().await;
        raw.close().await;
        provider.endpoint.close().await;
    }

    fn percentiles(mut samples: Vec<Duration>) -> (Duration, Duration) {
        samples.sort();
        let at = |q: f64| samples[((samples.len() - 1) as f64 * q).round() as usize];
        (at(0.5), at(0.95))
    }

    async fn selected_path<P: RpcProtocol>(client: &RpcClient<P>) -> &'static str {
        let pooled = client.pooled.lock().await;
        let Some(pooled) = pooled.as_ref() else {
            return "none";
        };
        let paths = pooled.conn.paths();
        let selected = paths.iter().find(|path| path.is_selected());
        match selected {
            Some(path) if path.is_relay() => "relayed",
            Some(_) => "direct",
            None => "unknown",
        }
    }

    fn direct(message: impl Into<serde_json::Value>) -> DirectRequest {
        DirectRequest {
            message: message.into(),
        }
    }

    /// Replies to every direct request with its own message.
    fn echo_direct(mut provider: mpsc::Receiver<DirectRpc>) {
        tokio::spawn(async move {
            while let Some(rpc) = provider.recv().await {
                let _ = rpc.reply.send(serde_json::to_vec(&rpc.message).unwrap());
            }
        });
    }

    /// Cold requests pay for an endpoint and a connection each, as `session_request` does. Warm
    /// requests reuse one client after its first request.
    async fn measure<P, F, Fut>(
        label: &str,
        provider: &EndpointAddr,
        client_endpoint: F,
        make: fn(serde_json::Value) -> P::Request,
    ) where
        P: RpcProtocol,
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Endpoint>,
    {
        const SAMPLES: usize = 40;
        let mut cold = Vec::new();
        let mut cold_setups = 0;
        for i in 0..SAMPLES {
            let started = Instant::now();
            let client = RpcClient::<P>::with_endpoint(client_endpoint().await, provider.clone());
            client.request(&make(i.into())).await.unwrap();
            cold.push(started.elapsed());
            cold_setups += client.connections_established();
            client.close().await;
        }
        let client = RpcClient::<P>::with_endpoint(client_endpoint().await, provider.clone());
        client.request(&make("first".into())).await.unwrap();
        let mut warm = Vec::new();
        for i in 0..SAMPLES {
            let started = Instant::now();
            client.request(&make(i.into())).await.unwrap();
            warm.push(started.elapsed());
        }
        let path = selected_path(&client).await;
        let setups = client.connections_established();
        client.close().await;
        let (cold_p50, cold_p95) = percentiles(cold);
        let (warm_p50, warm_p95) = percentiles(warm);
        eprintln!(
            "{label}: cold p50 {cold_p50:?} p95 {cold_p95:?}, {cold_setups} setups for {SAMPLES} requests; \
             warm p50 {warm_p50:?} p95 {warm_p95:?}, {setups} setup for {} requests, path {path}",
            SAMPLES + 1
        );
    }

    /// Run with `cargo test -p pubky-transport --features iroh --lib request_latency -- --ignored
    /// --nocapture`. The relayed half uses n0's public relays and is skipped without them. Every
    /// request is answered in process, so none of these reach a homeserver.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn request_latency() {
        let provider = Provider::start([1; 32], SessionLimits::default()).await;
        let _seen = echo(provider.requests);
        echo_direct(provider.direct);
        let target = Provider::addr(&provider.endpoint);
        let loopback = || local_endpoint([2; 32], vec![], "127.0.0.1:0");
        measure::<Session, _, _>(
            "session, direct path (loopback)",
            &target,
            loopback,
            request,
        )
        .await;
        measure::<Direct, _, _>(
            "root key, direct path (loopback)",
            &target,
            loopback,
            direct,
        )
        .await;
        provider.endpoint.close().await;

        let server = Endpoint::builder(presets::N0)
            .secret_key(SecretKey::from_bytes(&[1; 32]))
            .alpns(vec![
                SESSION_MULTIPLEX_ALPN.to_vec(),
                SESSION_ALPN.to_vec(),
                DIRECT_ALPN.to_vec(),
            ])
            .transport_config(accepting_transport_config())
            .bind()
            .await
            .unwrap();
        if tokio::time::timeout(Duration::from_secs(20), server.online())
            .await
            .is_err()
        {
            eprintln!("relayed: skipped, no relay reachable");
            return;
        }
        let relay = server.addr().relay_urls().next().unwrap().clone();
        let target = EndpointAddr::new(server.id()).with_relay_url(relay);
        let (peers, _) = mpsc::channel(1);
        let (session, pending) = mpsc::channel(16);
        let (direct_tx, direct_pending) = mpsc::channel(16);
        let handlers = Handlers {
            session,
            direct: direct_tx,
        };
        spawn_accept_loop(server.clone(), peers, handlers, SessionLimits::default());
        let _seen = echo(pending);
        echo_direct(direct_pending);
        // Without IP transports the client can only reach the provider through the relay.
        let relayed = || async {
            Endpoint::builder(presets::N0)
                .secret_key(SecretKey::from_bytes(&[2; 32]))
                .clear_ip_transports()
                .bind()
                .await
                .unwrap()
        };
        measure::<Session, _, _>("session, relayed (n0 relay)", &target, relayed, request).await;
        measure::<Direct, _, _>("root key, relayed (n0 relay)", &target, relayed, direct).await;
        server.close().await;
    }

    #[tokio::test]
    async fn direct_requests_are_attributed_to_the_connecting_root_key() {
        let Provider {
            endpoint,
            mut requests,
            direct: mut root_requests,
        } = Provider::start([1; 32], SessionLimits::default()).await;
        let client = Provider::client_for::<Direct>(&endpoint, [5; 32]).await;
        let responder = tokio::spawn(async move {
            for _ in 0..3 {
                let rpc = root_requests.recv().await.unwrap();
                assert_eq!(rpc.remote_key, crate::identity_from_secret(&[5; 32]));
                let _ = rpc.reply.send(serde_json::to_vec(&rpc.message).unwrap());
            }
        });
        for i in 0..3 {
            assert_eq!(client.request(&direct(i)).await.unwrap(), echoed(i));
        }
        responder.await.unwrap();
        // Nothing arrived as a session request, which would need a homeserver authorization.
        assert!(requests.try_recv().is_err());
        assert_eq!(client.connections_established(), 1);
        client.close().await;
        endpoint.close().await;
    }

    #[tokio::test]
    async fn session_and_direct_envelopes_are_not_interchangeable() {
        let Provider {
            endpoint,
            mut requests,
            direct: mut root_requests,
        } = Provider::start([1; 32], SessionLimits::default()).await;
        let raw = local_endpoint([3; 32], vec![], "127.0.0.1:0").await;
        let target = Provider::addr(&endpoint);
        let session_body = serde_json::to_vec(&request("claimed account")).unwrap();
        let direct_body = serde_json::to_vec(&direct("no account")).unwrap();
        for (alpn, body) in [
            (DIRECT_ALPN, &session_body),
            (SESSION_MULTIPLEX_ALPN, &direct_body),
        ] {
            let conn = raw.connect(target.clone(), alpn).await.unwrap();
            let (mut send, mut receive) = conn.open_bi().await.unwrap();
            send.write_all(body).await.unwrap();
            send.finish().unwrap();
            let read =
                tokio::time::timeout(Duration::from_secs(5), receive.read_to_end(MAX_RPC_BYTES))
                    .await
                    .unwrap();
            assert!(matches!(
                read,
                Err(iroh::endpoint::ReadToEndError::Read(iroh::endpoint::ReadError::Reset(code)))
                    if code == REQUEST_REJECTED.into()
            ));
            conn.close(0u32.into(), b"done");
        }
        assert!(requests.try_recv().is_err());
        assert!(root_requests.try_recv().is_err());
        raw.close().await;
        endpoint.close().await;
    }

    #[tokio::test]
    async fn an_unreachable_provider_is_reported_as_not_sent() {
        let silent = local_endpoint([1; 32], vec![DIRECT_ALPN.to_vec()], "127.0.0.1:0").await;
        let target = Provider::addr(&silent);
        // Nothing accepts, so the handshake never completes.
        let endpoint = local_endpoint([2; 32], vec![], "127.0.0.1:0").await;
        let mut client = DirectRpcClient::with_endpoint(endpoint, target);
        client.connect_timeout = Duration::from_millis(300);
        let error = client.request(&direct("quote")).await.unwrap_err();
        assert!(matches!(error, TransportError::NotSent(_)), "{error}");
        client.close().await;
        silent.close().await;
    }

    #[tokio::test]
    async fn providers_without_the_direct_protocol_fail_before_anything_is_sent() {
        // A provider as published before direct/1 existed.
        let alpns = vec![SESSION_MULTIPLEX_ALPN.to_vec(), SESSION_ALPN.to_vec()];
        let legacy = local_endpoint([1; 32], alpns, "127.0.0.1:0").await;
        let (peers, _) = mpsc::channel(1);
        let (session, mut requests) = mpsc::channel(16);
        let (direct_tx, _direct) = mpsc::channel(16);
        let handlers = Handlers {
            session,
            direct: direct_tx,
        };
        spawn_accept_loop(legacy.clone(), peers, handlers, SessionLimits::default());
        let client = Provider::client_for::<Direct>(&legacy, [2; 32]).await;
        let error = client.request(&direct("quote")).await.unwrap_err();
        assert!(matches!(error, TransportError::NotSent(_)), "{error}");
        assert!(requests.try_recv().is_err());
        client.close().await;
        legacy.close().await;
    }

    /// The crux of the design: an iroh endpoint built from the pubky's ed25519 secret has an
    /// endpoint id byte-identical to the pubky. This is what lets a client address a provider by
    /// pubky and lets the provider read a client's pubky straight off the connection.
    #[test]
    fn iroh_identity_equals_pubky() {
        let secret = [9u8; 32];
        let pubky = pkarr::Keypair::from_secret_key(&secret)
            .public_key()
            .to_string();
        let iroh_id = SecretKey::from_bytes(&secret).public();

        // Round-trips in both directions.
        assert_eq!(endpoint_id_to_pubky(&iroh_id).unwrap(), pubky);
        assert_eq!(pubky_to_endpoint_id(&pubky).unwrap(), iroh_id);
    }

    /// End-to-end: a client connects and the provider learns its authenticated pubky. Ignored by
    /// default because it stands up two real iroh endpoints (and by default uses n0 discovery /
    /// relay infrastructure).
    #[tokio::test]
    #[ignore]
    async fn provider_learns_client_pubky() {
        use std::time::Duration;

        let provider_secret = [3u8; 32];
        let client_secret = [4u8; 32];

        let mut server = RendezvousServer::bind(provider_secret).await.unwrap();
        let provider_pubky = server.pubky().unwrap();
        let expected_client = pkarr::Keypair::from_secret_key(&client_secret)
            .public_key()
            .to_string();

        // Connect from the client side by the provider's pubky (resolved via discovery).
        ring_provider(client_secret, &provider_pubky).await.unwrap();

        let got = tokio::time::timeout(Duration::from_secs(15), server.next_peer())
            .await
            .expect("timed out waiting for the provider to learn the client pubky");
        assert_eq!(got, Some(expected_client));
        server.close().await;
    }
}
