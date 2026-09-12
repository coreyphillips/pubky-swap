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
//! The separate `session/1` ALPN carries encrypted requests for Ring-authorized
//! clients. Its transport key is verified against a scoped homeserver authorization
//! before the application handles requests. Legacy rendezvous is unchanged.

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey as IrohPublicKey, SecretKey};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tracing::debug;

use crate::{Result, TransportError};

/// Install process-lifetime JVM and application context pointers for Android DNS.
#[cfg(target_os = "android")]
pub use iroh::dns::install_android_jni_context;

/// ALPN identifying the pubky-swap rendezvous protocol. Both ends must present the same string or
/// iroh aborts the connection.
pub const SWAP_ALPN: &[u8] = b"pubky-swap/rendezvous/1";

/// Encrypted request/reply transport for scoped Pubky sessions.
pub const SESSION_ALPN: &[u8] = b"pubky-swap/session/1";
const MAX_RPC_BYTES: usize = 64 * 1024;

/// An authenticated transport connection awaiting application authorization.
pub struct SessionRpc {
    pub remote_key: String,
    pub request: crate::session_rpc::SessionRequest,
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
        builder = builder.alpns(alpns);
    }
    builder
        .bind()
        .await
        .map_err(|e| TransportError::Iroh(format!("bind endpoint: {e}")))
}

/// Provider-side iroh rendezvous endpoint. Accepts inbound connections and reports the pubky of
/// each connecting client (authenticated by the QUIC handshake) via [`next_peer`](Self::next_peer).
pub struct RendezvousServer {
    endpoint: Endpoint,
    peers: mpsc::Receiver<String>,
    requests: mpsc::Receiver<SessionRpc>,
}

impl RendezvousServer {
    /// Bind an endpoint whose id is `secret`'s public key (== the provider pubky), publish it via
    /// iroh discovery, and start accepting rendezvous connections.
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        Self::bind_protocols(secret, vec![SWAP_ALPN.to_vec()]).await
    }

    /// Accept legacy rendezvous and scoped-session requests on the same endpoint.
    pub async fn bind_with_sessions(secret: [u8; 32]) -> Result<Self> {
        Self::bind_protocols(secret, vec![SWAP_ALPN.to_vec(), SESSION_ALPN.to_vec()]).await
    }

    async fn bind_protocols(secret: [u8; 32], alpns: Vec<Vec<u8>>) -> Result<Self> {
        let endpoint = build_endpoint(secret, alpns).await?;
        let (tx, rx) = mpsc::channel(256);
        let (request_tx, requests) = mpsc::channel(16);
        spawn_accept_loop(endpoint.clone(), tx, request_tx);
        Ok(Self {
            endpoint,
            peers: rx,
            requests,
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

    /// Await either a legacy peer or a session request without competing borrows.
    pub async fn next_event(&mut self) -> Option<RendezvousEvent> {
        tokio::select! {
            peer = self.peers.recv() => peer.map(RendezvousEvent::Peer),
            request = self.requests.recv() => request.map(RendezvousEvent::Session),
        }
    }

    /// Close the endpoint (stops the accept loop).
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// Inbound transport work. Session requests still require homeserver authorization.
pub enum RendezvousEvent {
    Peer(String),
    Session(SessionRpc),
}

fn spawn_accept_loop(
    endpoint: Endpoint,
    tx: mpsc::Sender<String>,
    requests: mpsc::Sender<SessionRpc>,
) {
    tokio::spawn(async move {
        let capacity = Arc::new(Semaphore::new(32));
        while let Some(incoming) = endpoint.accept().await {
            let Ok(permit) = capacity.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let tx = tx.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let conn = match tokio::time::timeout(Duration::from_secs(10), incoming).await {
                    Ok(Ok(c)) => c,
                    _ => {
                        debug!("rendezvous: incoming connection failed");
                        return;
                    }
                };
                if conn.alpn() == SESSION_ALPN {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(60),
                        serve_session(&conn, requests),
                    )
                    .await;
                    conn.close(0u32.into(), b"request complete");
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

async fn serve_session(
    conn: &iroh::endpoint::Connection,
    requests: mpsc::Sender<SessionRpc>,
) -> Result<()> {
    use crate::session_rpc::session_error;
    let remote_key = endpoint_id_to_pubky(&conn.remote_id())?;
    let (mut send, mut receive) = conn
        .accept_bi()
        .await
        .map_err(|_| session_error("missing request stream"))?;
    let bytes = receive
        .read_to_end(MAX_RPC_BYTES)
        .await
        .map_err(|_| session_error("invalid session request"))?;
    let request = serde_json::from_slice(&bytes)?;
    let (reply, result) = oneshot::channel();
    requests
        .send(SessionRpc {
            remote_key,
            request,
            reply,
        })
        .await
        .map_err(|_| session_error("provider unavailable"))?;
    let bytes = result
        .await
        .map_err(|_| session_error("request rejected"))?;
    if bytes.len() > MAX_RPC_BYTES {
        return Err(session_error("session reply is too large"));
    }
    send.write_all(&bytes)
        .await
        .map_err(|_| session_error("could not send reply"))?;
    send.finish()
        .map_err(|_| session_error("could not finish reply"))?;
    let _ = send.stopped().await;
    Ok(())
}

/// Send one bounded request over a connection authenticated to the provider's Pubky.
pub async fn session_request(
    secret: [u8; 32],
    provider: &str,
    request: &crate::session_rpc::SessionRequest,
) -> Result<Vec<u8>> {
    use crate::session_rpc::session_error;
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > MAX_RPC_BYTES {
        return Err(session_error("session request is too large"));
    }
    let endpoint = build_endpoint(secret, vec![]).await?;
    let result = async {
        let target: EndpointAddr = pubky_to_endpoint_id(provider)?.into();
        let conn = endpoint.connect(target, SESSION_ALPN).await.map_err(|_| {
            session_error("provider does not support session swaps or is unavailable")
        })?;
        let (mut send, mut receive) = conn
            .open_bi()
            .await
            .map_err(|_| session_error("could not open request stream"))?;
        send.write_all(&bytes)
            .await
            .map_err(|_| session_error("could not send request"))?;
        send.finish()
            .map_err(|_| session_error("could not finish request"))?;
        let reply = receive
            .read_to_end(MAX_RPC_BYTES)
            .await
            .map_err(|_| session_error("session swap request failed"))?;
        conn.close(0u32.into(), b"reply received");
        Ok(reply)
    }
    .await;
    endpoint.close().await;
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_rpc_authenticates_transport_key_and_returns_one_reply() {
        let server = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .alpns(vec![SESSION_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[7; 32]))
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();
        let target = EndpointAddr::new(server.id()).with_ip_addr(server.bound_sockets()[0]);
        let (peers, _) = mpsc::channel(1);
        let (requests, mut pending) = mpsc::channel(1);
        spawn_accept_loop(server.clone(), peers, requests);
        let operation = async {
            let conn = client.connect(target, SESSION_ALPN).await.unwrap();
            let (mut send, mut receive) = conn.open_bi().await.unwrap();
            let claimed_owner = crate::identity_from_secret(&[8; 32]);
            let request = crate::session_rpc::SessionRequest {
                owner: claimed_owner.clone(),
                scope: "/pub/bitkit.to/bitkit/wallet/".into(),
                message: serde_json::json!({"request_id": "example"}),
            };
            send.write_all(&serde_json::to_vec(&request).unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            let request = pending.recv().await.unwrap();
            assert_eq!(request.remote_key, crate::identity_from_secret(&[7; 32]));
            assert_ne!(request.remote_key, claimed_owner);
            assert_eq!(request.request.owner, claimed_owner);
            request.reply.send(b"verified reply".to_vec()).unwrap();
            assert_eq!(
                receive.read_to_end(MAX_RPC_BYTES).await.unwrap(),
                b"verified reply"
            );
            conn.close(0u32.into(), b"complete");
        };
        tokio::time::timeout(Duration::from_secs(10), operation)
            .await
            .unwrap();
        client.close().await;
        server.close().await;
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
