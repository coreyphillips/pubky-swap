//! Generic transport over [`pubky_messenger`].
//!
//! This is a message-type-agnostic extraction of the transport used in
//! `bitcoin-batch-coordinator`. It provides end-to-end encrypted direct messages and
//! peer discovery via the Pubky follow graph, while leaving the wire message type up to
//! the caller — `send`/`receive` are generic over any `serde` type. That keeps this crate
//! free of any Bitcoin/Lightning dependency so it can be shared across projects.

use pkarr::PublicKey;
use pubky_messenger::PrivateMessengerClient;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use std::fs;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, warn};

#[cfg(feature = "dht")]
pub mod rendezvous;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("transport error: {0}")]
    Messenger(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid pkarr public key: {0}")]
    InvalidPubkey(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// DHT rendezvous error (feature `dht`; see [`rendezvous`]).
    #[error("dht error: {0}")]
    Dht(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// Transport layer wrapper for pubky-messenger.
pub struct Transport {
    messenger: PrivateMessengerClient,
    /// Peers to poll for messages (a coordinator/provider polls all known peers).
    known_peers: Arc<RwLock<HashSet<String>>>,
    /// Processed message IDs, for deduplication across polls.
    processed_messages: Arc<RwLock<HashSet<String>>>,
}

/// Soft cap on the dedup set so it cannot grow without bound over long sessions.
const MAX_PROCESSED_IDS: usize = 10_000;

impl Transport {
    /// Create a transport from a Pubky recovery file + passphrase.
    pub async fn from_recovery_file(recovery_path: &str, passphrase: &str) -> Result<Self> {
        let recovery_bytes = fs::read(recovery_path)?;
        let messenger =
            PrivateMessengerClient::from_recovery_file(&recovery_bytes, Some(passphrase))
                .map_err(|e| TransportError::Messenger(format!("create messenger: {e}")))?;
        messenger
            .sign_in()
            .await
            .map_err(|e| TransportError::Messenger(format!("sign in: {e}")))?;
        Ok(Self::wrap(messenger))
    }

    /// Create a transport from a Pubky recovery phrase (+ optional passphrase).
    pub async fn from_recovery_phrase(mnemonic: &str, passphrase: Option<&str>) -> Result<Self> {
        let messenger = PrivateMessengerClient::from_recovery_phrase(mnemonic, passphrase, None)
            .map_err(|e| TransportError::Messenger(format!("create messenger: {e}")))?;
        messenger
            .sign_in()
            .await
            .map_err(|e| TransportError::Messenger(format!("sign in: {e}")))?;
        Ok(Self::wrap(messenger))
    }

    fn wrap(messenger: PrivateMessengerClient) -> Self {
        Self {
            messenger,
            known_peers: Arc::new(RwLock::new(HashSet::new())),
            processed_messages: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// This transport's own public key (pkarr) string.
    pub fn public_key_string(&self) -> String {
        self.messenger.public_key_string()
    }

    /// Track a peer so it is polled by [`receive_all`].
    pub fn add_known_peer(&self, peer_pkarr: String) {
        if let Ok(mut peers) = self.known_peers.write() {
            peers.insert(peer_pkarr);
        }
    }

    /// Snapshot of currently known peers.
    pub fn get_known_peers(&self) -> Vec<String> {
        self.known_peers
            .read()
            .map(|p| p.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Discover peers (users *we* follow) from the Pubky follow graph.
    ///
    /// This reads our own outbound follow list (`pubky://<self>/pub/pubky.app/follows/`), i.e.
    /// the accounts we have chosen to follow — not our followers. Pubky stores each follow
    /// record under the follower's own homeserver, so there is no reverse "who follows me"
    /// lookup here; finding inbound followers needs an external indexer (e.g. Nexus).
    pub async fn discover_peers(&self) -> Result<Vec<String>> {
        let followed = self
            .messenger
            .get_followed_users()
            .await
            .map_err(|e| TransportError::Messenger(format!("get followed users: {e}")))?;
        let mut discovered = Vec::new();
        for user in followed {
            self.add_known_peer(user.pubky.clone());
            discovered.push(user.pubky);
        }
        Ok(discovered)
    }

    /// Follow a pubky (used to opt peers into the follow graph / marketplace).
    pub async fn follow(&self, pubky: &str) -> Result<()> {
        self.messenger
            .put_follow(pubky)
            .await
            .map_err(|e| TransportError::Messenger(format!("follow {pubky}: {e}")))?;
        Ok(())
    }

    /// Unfollow a pubky and drop it from the known-peer set.
    pub async fn unfollow(&self, pubky: &str) -> Result<()> {
        self.messenger
            .delete_follow(pubky)
            .await
            .map_err(|e| TransportError::Messenger(format!("unfollow {pubky}: {e}")))?;
        if let Ok(mut peers) = self.known_peers.write() {
            peers.remove(pubky);
        }
        Ok(())
    }

    /// Send a serializable message to a peer (encrypted by the messenger).
    pub async fn send<M: Serialize>(&self, peer_pkarr: &str, msg: &M) -> Result<()> {
        let payload = serde_json::to_string(msg)?;
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
        self.messenger
            .send_message(&peer, &payload)
            .await
            .map_err(|e| TransportError::Messenger(format!("send dm: {e}")))?;
        Ok(())
    }

    /// Receive and deserialize new (non-duplicate) messages from a specific peer.
    ///
    /// Messages that fail to deserialize into `M` are skipped (they may be a different
    /// message type from the same peer); they are not marked processed, so a caller
    /// expecting a different type can still read them.
    pub async fn receive_from<M: DeserializeOwned>(&self, peer_pkarr: &str) -> Result<Vec<M>> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
        let messages = self
            .messenger
            .get_messages(&peer)
            .await
            .map_err(|e| TransportError::Messenger(format!("get messages: {e}")))?;

        let mut parsed = Vec::new();
        for msg in messages {
            let message_id = format!(
                "{}-{}-{}",
                peer_pkarr,
                msg.timestamp,
                blake3::hash(msg.content.as_bytes()).to_hex()
            );

            let is_duplicate = self
                .processed_messages
                .read()
                .map(|p| p.contains(&message_id))
                .unwrap_or(false);
            if is_duplicate {
                continue;
            }

            match serde_json::from_str::<M>(&msg.content) {
                Ok(parsed_msg) => {
                    if let Ok(mut processed) = self.processed_messages.write() {
                        if processed.len() >= MAX_PROCESSED_IDS {
                            debug!("processed_messages cap reached; clearing dedup set");
                            processed.clear();
                        }
                        processed.insert(message_id);
                    }
                    self.add_known_peer(peer_pkarr.to_string());
                    parsed.push(parsed_msg);
                }
                Err(e) => {
                    // Not necessarily an error: could be a different message type.
                    debug!("could not parse message from {peer_pkarr} as expected type: {e}");
                }
            }
        }
        Ok(parsed)
    }

    /// Receive new messages from all known peers concurrently.
    pub async fn receive_all<M: DeserializeOwned>(&self) -> Result<Vec<(String, M)>> {
        use futures::future::join_all;

        let peers = self.get_known_peers();
        if peers.is_empty() {
            return Ok(Vec::new());
        }

        let futures = peers.iter().map(|peer| {
            let peer = peer.clone();
            async move {
                let res = self.receive_from::<M>(&peer).await;
                (peer, res)
            }
        });

        let mut all = Vec::new();
        for (peer, res) in join_all(futures).await {
            match res {
                Ok(msgs) => all.extend(msgs.into_iter().map(|m| (peer.clone(), m))),
                Err(e) => debug!("failed to receive from {peer}: {e}"),
            }
        }
        Ok(all)
    }

    /// Delete all messages exchanged with a peer (cleanup), and forget their dedup ids.
    pub async fn clear_messages_with_peer(&self, peer_pkarr: &str) -> Result<()> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
        self.messenger
            .clear_messages(&peer)
            .await
            .map_err(|e| TransportError::Messenger(format!("clear messages: {e}")))?;
        if let Ok(mut processed) = self.processed_messages.write() {
            processed.retain(|id| !id.starts_with(&format!("{peer_pkarr}-")));
        }
        Ok(())
    }

    /// Clear messages with all known peers.
    pub async fn clear_all_messages(&self) -> Result<()> {
        for peer in self.get_known_peers() {
            if let Err(e) = self.clear_messages_with_peer(&peer).await {
                warn!("failed to clear messages with {peer}: {e}");
            }
        }
        if let Ok(mut processed) = self.processed_messages.write() {
            processed.clear();
        }
        Ok(())
    }
}

/// The messaging surface the swap protocol needs from a transport.
///
/// [`Transport`] (encrypted Pubky DMs) is the implementation used today. Naming the surface as a
/// trait is the seam that lets the same `swap-provider` / `swap-client` protocol run over an
/// alternative transport later, e.g. an authenticated, holepunched P2P stream located via the
/// [`rendezvous`] module on the mainline DHT, without touching the swap state machine, HTLC
/// scripting, or persisted store.
///
/// Discovery and execution have different needs: discovery wants to be real-time (a client
/// walking up to a listening provider), while execution spans blocks/hours and must survive
/// disconnects and restarts. A DHT stream suits the former; the durable store-and-forward DMs
/// modelled here remain the safer choice for the latter, so a deployment may use both.
///
/// The trait is intentionally not object-safe (the message type is generic per call, matching
/// [`Transport`]); it is a static seam for generic code, not a `dyn` boundary.
#[allow(async_fn_in_trait)]
pub trait SwapTransport {
    /// This transport's own public key (pkarr) string.
    fn public_key_string(&self) -> String;
    /// Track a peer so it is polled by [`receive_all`](Self::receive_all).
    fn add_known_peer(&self, peer_pkarr: String);
    /// Snapshot of currently known peers.
    fn get_known_peers(&self) -> Vec<String>;
    /// Send a serializable message to a peer.
    async fn send<M: Serialize>(&self, peer_pkarr: &str, msg: &M) -> Result<()>;
    /// Receive new (non-duplicate) messages from a specific peer.
    async fn receive_from<M: DeserializeOwned>(&self, peer_pkarr: &str) -> Result<Vec<M>>;
    /// Receive new messages from all known peers.
    async fn receive_all<M: DeserializeOwned>(&self) -> Result<Vec<(String, M)>>;
}

impl SwapTransport for Transport {
    fn public_key_string(&self) -> String {
        Transport::public_key_string(self)
    }
    fn add_known_peer(&self, peer_pkarr: String) {
        Transport::add_known_peer(self, peer_pkarr)
    }
    fn get_known_peers(&self) -> Vec<String> {
        Transport::get_known_peers(self)
    }
    async fn send<M: Serialize>(&self, peer_pkarr: &str, msg: &M) -> Result<()> {
        Transport::send(self, peer_pkarr, msg).await
    }
    async fn receive_from<M: DeserializeOwned>(&self, peer_pkarr: &str) -> Result<Vec<M>> {
        Transport::receive_from(self, peer_pkarr).await
    }
    async fn receive_all<M: DeserializeOwned>(&self) -> Result<Vec<(String, M)>> {
        Transport::receive_all(self).await
    }
}
