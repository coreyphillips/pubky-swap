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
//! This is **rendezvous only**. The provider accepts a connection, reads the remote pubky, adds it
//! to its poll set, and the actual swap runs over pubky-DM (then eviction, see
//! [`Transport::evict_peer`](crate::Transport::evict_peer)). A returning client simply reconnects,
//! which is what makes eviction lossless. iroh handles NAT traversal (holepunch + relay fallback),
//! so the provider does not need a manually forwarded port.

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey as IrohPublicKey, SecretKey};
use tokio::sync::mpsc;
use tracing::debug;

use crate::{Result, TransportError};

/// Install process-lifetime JVM and application context pointers for Android DNS.
#[cfg(target_os = "android")]
pub use iroh::dns::install_android_jni_context;

/// ALPN identifying the pubky-swap rendezvous protocol. Both ends must present the same string or
/// iroh aborts the connection.
pub const SWAP_ALPN: &[u8] = b"pubky-swap/rendezvous/1";

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
async fn build_endpoint(secret: [u8; 32], accepting: bool) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(SecretKey::from_bytes(&secret));
    if accepting {
        builder = builder.alpns(vec![SWAP_ALPN.to_vec()]);
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
}

impl RendezvousServer {
    /// Bind an endpoint whose id is `secret`'s public key (== the provider pubky), publish it via
    /// iroh discovery, and start accepting rendezvous connections.
    pub async fn bind(secret: [u8; 32]) -> Result<Self> {
        let endpoint = build_endpoint(secret, true).await?;
        let (tx, rx) = mpsc::channel(256);
        spawn_accept_loop(endpoint.clone(), tx);
        Ok(Self {
            endpoint,
            peers: rx,
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

    /// Close the endpoint (stops the accept loop).
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

fn spawn_accept_loop(endpoint: Endpoint, tx: mpsc::Sender<String>) {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("rendezvous: incoming connection failed: {e}");
                        return;
                    }
                };
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

/// Client-side: connect to a provider by its pubky so the provider learns our (authenticated)
/// pubky and starts polling us over pubky-DM. We send nothing; the handshake carries our identity.
pub async fn ring_provider(secret: [u8; 32], provider_pubky: &str) -> Result<()> {
    let endpoint = build_endpoint(secret, false).await?;
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
