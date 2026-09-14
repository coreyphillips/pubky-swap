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
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

mod inbox;

#[cfg(feature = "iroh")]
pub mod p2p;

#[cfg(feature = "iroh")]
pub mod session_rpc;

#[cfg(feature = "iroh")]
pub mod identity;

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
    /// iroh P2P rendezvous error (feature `iroh`; see [`p2p`]).
    #[error("iroh error: {0}")]
    Iroh(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// Unix seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How far before a peer joined the poll set its messages are still worth reading.
///
/// Message timestamps have one-second granularity and are set by the sender, so a request written
/// in the same second the doorbell rang can carry a slightly earlier stamp than the moment this
/// side recorded. Generous enough to absorb that and some clock skew, and far short of the
/// backlog this exists to discard.
const POLL_FROM_GRACE_SECS: u64 = 120;

/// A tracked peer in the poll set.
#[derive(Debug, Clone)]
struct PeerEntry {
    /// Pinned peers are never idle-reaped (e.g. operator-curated follows loaded by
    /// [`Transport::discover_peers`], or a client's configured provider). They are still removed
    /// by an explicit [`Transport::evict_peer`].
    pinned: bool,
    /// Last time we added or read a message from this peer, for idle reaping.
    last_seen: Instant,
    /// Unix seconds when this peer entered the poll set, and therefore the point from which its
    /// messages are ours to answer. See [`Transport::receive_from`].
    polling_from: u64,
}

/// The set of peers a transport polls, with pin + idle-reaping bookkeeping. Extracted from
/// [`Transport`] so its lifecycle logic is unit-testable without a live messenger.
#[derive(Default)]
struct PeerSet {
    peers: RwLock<HashMap<String, PeerEntry>>,
}

impl PeerSet {
    /// When this peer entered the poll set, in Unix seconds.
    fn polling_from(&self, pubky: &str) -> Option<u64> {
        self.peers.read().ok()?.get(pubky).map(|e| e.polling_from)
    }

    /// Insert a peer or bump its last-seen time. `pinned` only ever sets the pin flag (a touch
    /// never un-pins an already-pinned peer).
    fn touch_or_add(&self, pubky: String, pinned: bool) {
        if let Ok(mut peers) = self.peers.write() {
            peers
                .entry(pubky)
                .and_modify(|e| {
                    e.last_seen = Instant::now();
                    if pinned {
                        e.pinned = true;
                    }
                })
                .or_insert(PeerEntry {
                    pinned,
                    last_seen: Instant::now(),
                    polling_from: now_unix(),
                });
        }
    }

    /// Polled peers by canonical key, since a peer may be tracked under a prefixed spelling.
    fn canonical_keys(&self) -> HashSet<String> {
        self.peers
            .read()
            .map(|p| {
                p.keys()
                    .map(|k| canonical_pubky(k).unwrap_or_else(|_| k.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn all(&self) -> Vec<String> {
        self.peers
            .read()
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn idle_unpinned(&self, ttl: Duration) -> Vec<String> {
        let now = Instant::now();
        self.peers
            .read()
            .map(|peers| {
                peers
                    .iter()
                    .filter(|(_, e)| !e.pinned && now.duration_since(e.last_seen) >= ttl)
                    .map(|(p, _)| p.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn remove(&self, pubky: &str) {
        if let Ok(mut peers) = self.peers.write() {
            peers.remove(pubky);
        }
    }
}

/// Whether two pkarr strings name the same key.
///
/// Peer strings arrive from several places (the follow graph, the iroh doorbell, a field a peer
/// filled in itself), and only the key they encode is meaningful, so they are compared as keys
/// where both parse. Anything that does not parse falls back to an exact string match, which is
/// what a caller comparing two identifiers it minted itself expects.
pub fn same_pubky(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    matches!((PublicKey::try_from(a), PublicKey::try_from(b)), (Ok(x), Ok(y)) if x == y)
}

/// Normalize a bare public key or a Pubky identity prefix to its z32 encoding.
/// Resource paths and unrelated URL schemes are not identity inputs.
pub fn canonical_pubky(value: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    let key = if value.len() == 52 {
        value
    } else {
        value
            .strip_prefix("pubky://")
            .or_else(|| value.strip_prefix("pubky:"))
            .or_else(|| value.strip_prefix("pubky"))
            .or_else(|| value.strip_prefix("pk:"))
            .unwrap_or(value)
    };
    if key.len() != 52 {
        return Err(TransportError::InvalidPubkey(
            "expected a public key".into(),
        ));
    }
    PublicKey::try_from(key)
        .map(|key| key.to_string())
        .map_err(|error| TransportError::InvalidPubkey(error.to_string()))
}

/// Derive the public identity directly from an existing Ed25519 secret.
pub fn identity_from_secret(secret: &[u8; 32]) -> String {
    pkarr::Keypair::from_secret_key(secret)
        .public_key()
        .to_string()
}

/// Transport layer wrapper for pubky-messenger.
pub struct Transport {
    messenger: PrivateMessengerClient,
    /// Peers to poll for messages (a coordinator/provider polls all known peers).
    known_peers: Arc<PeerSet>,
    /// What has been delivered and acknowledged, per peer.
    inboxes: inbox::Inboxes,
}

/// A message returned by [`Transport::poll_from`] or [`Transport::poll_all`].
#[derive(Debug, Clone)]
pub struct Inbound<M> {
    pub peer: String,
    pub message: M,
    pub receipt: Receipt,
}

/// Identifies a delivered message for [`Transport::acknowledge`].
#[derive(Debug, Clone)]
pub struct Receipt {
    peer: PublicKey,
    id: pubky_messenger::MessageId,
}

impl Transport {
    /// Sign into an existing account using its Ed25519 secret without deriving another key.
    /// The account must already be registered with a homeserver.
    pub async fn from_secret_key(secret: [u8; 32]) -> Result<Self> {
        let messenger = PrivateMessengerClient::new(pkarr::Keypair::from_secret_key(&secret))
            .map_err(|error| TransportError::Messenger(format!("create messenger: {error}")))?;
        messenger
            .sign_in()
            .await
            .map_err(|error| TransportError::Messenger(format!("sign in: {error}")))?;
        Ok(Self::wrap(messenger))
    }

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
        let known_peers = Arc::new(PeerSet::default());
        let polled = known_peers.clone();
        Self {
            messenger,
            known_peers,
            inboxes: inbox::Inboxes::sparing(move || polled.canonical_keys()),
        }
    }

    /// This transport's own public key (pkarr) string.
    pub fn public_key_string(&self) -> String {
        self.messenger.public_key_string()
    }

    /// Track a peer so it is polled by [`receive_all`], and refresh its last-seen time.
    ///
    /// If the peer is already tracked its pinned status is preserved; this only bumps last-seen
    /// (so re-adding a pinned peer does not unpin it).
    pub fn add_known_peer(&self, peer_pkarr: String) {
        self.known_peers.touch_or_add(peer_pkarr, false);
    }

    /// Track a peer and mark it pinned, so it is polled but never idle-reaped (only an explicit
    /// [`evict_peer`](Self::evict_peer) removes it). Use for operator-curated follows and a
    /// client's configured provider.
    pub fn pin_peer(&self, peer_pkarr: String) {
        self.known_peers.touch_or_add(peer_pkarr, true);
    }

    /// Snapshot of currently known peers.
    pub fn get_known_peers(&self) -> Vec<String> {
        self.known_peers.all()
    }

    /// Unpinned peers whose last activity is older than `ttl` (candidates for idle reaping).
    pub fn idle_unpinned_peers(&self, ttl: Duration) -> Vec<String> {
        self.known_peers.idle_unpinned(ttl)
    }

    /// Stop tracking a peer: drop it from the in-memory poll set and best-effort remove any
    /// follow relationship (so the persistent follow graph does not grow without bound). A
    /// failed `delete_follow` is logged, not propagated, so the peer is always removed from the
    /// poll set. Removes pinned peers too.
    pub async fn evict_peer(&self, pubky: &str) {
        self.known_peers.remove(pubky);
        if let Err(e) = self.messenger.delete_follow(pubky).await {
            debug!("evict_peer: best-effort unfollow of {pubky} failed: {e}");
        }
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
            // Operator-curated follows are pinned: polled, but not idle-reaped.
            self.pin_peer(user.pubky.clone());
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
        self.known_peers.remove(pubky);
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

    /// Treat everything already in a conversation as read, without downloading any of it.
    ///
    /// A fresh process has no receive state for a conversation that already has a history on the
    /// homeserver. For a request/response exchange, that history is a wrong answer: a client that
    /// asked a provider for a price yesterday, and asks again today, is handed yesterday's quote
    /// and refuses it as expired, having never seen the reply to the question it actually asked.
    ///
    /// Call this immediately before sending a request. It only lists the conversation, and a reply
    /// can only be written after the request it answers, so it cannot hide that reply.
    pub async fn mark_conversation_seen(&self, peer_pkarr: &str) -> Result<usize> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
        let marked = self
            .inboxes
            .acknowledge_listed(&self.messenger, &peer)
            .await?;
        debug!("marked {marked} existing message(s) from {peer_pkarr} as already seen");
        Ok(marked)
    }

    /// Receive, deserialize and acknowledge new messages from a specific peer.
    ///
    /// Acknowledging on receipt suits a caller that has nothing to redo if it stops before acting
    /// on a message. One that does should use [`poll_from`](Self::poll_from) and acknowledge after
    /// dispatch.
    pub async fn receive_from<M: DeserializeOwned>(&self, peer_pkarr: &str) -> Result<Vec<M>> {
        let inbound = self.poll_from(peer_pkarr).await?;
        let mut messages = Vec::with_capacity(inbound.len());
        for m in inbound {
            self.acknowledge(&m.receipt).await;
            messages.push(m.message);
        }
        Ok(messages)
    }

    /// Messages from a peer that have not been acknowledged, oldest first.
    ///
    /// A message is returned by every poll until [`acknowledge`](Self::acknowledge) is called with
    /// its receipt. Only the first delivery downloads it. Messages that do not deserialize into `M`
    /// are acknowledged here.
    pub async fn poll_from<M: DeserializeOwned>(
        &self,
        peer_pkarr: &str,
    ) -> Result<Vec<Inbound<M>>> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;

        // Anything sent before this peer joined the poll set belongs to a conversation that had
        // already ended.
        //
        // Receive state lives in this process and starts empty, so a provider that restarted, or
        // that dropped a returning peer's state, would otherwise read that peer's whole history
        // and answer every request in it again: one quote request drew nine quotes, eight of them
        // for amounts nobody was asking about any more. The client refuses a quote whose amount
        // does not match, so this cost correctness rather than money, but it made a swap after any
        // restart a matter of luck.
        //
        // Discarding them loses nothing: a client waits thirty seconds for a reply before giving
        // up, and a quote expires within minutes, so a message that predates our interest in this
        // peer has nobody left listening for its answer. A swap that was accepted is recovered
        // from the provider's store by a status request, not by rereading the message.
        let floor = self
            .known_peers
            .polling_from(peer_pkarr)
            .map(|t| t.saturating_sub(POLL_FROM_GRACE_SECS));

        let delivered = self.inboxes.poll(&self.messenger, &peer, floor).await?;
        let mut parsed = Vec::with_capacity(delivered.len());
        for d in delivered {
            match serde_json::from_str::<M>(&d.message.content) {
                Ok(message) => {
                    self.add_known_peer(peer_pkarr.to_string());
                    parsed.push(Inbound {
                        peer: peer_pkarr.to_string(),
                        message,
                        receipt: Receipt {
                            peer: peer.clone(),
                            id: d.id,
                        },
                    });
                }
                Err(e) => {
                    // Deserialization is deterministic, so a message that does not parse now will
                    // not parse on the next poll either. That is the shape a counterparty running
                    // something newer takes: one message this build does not understand.
                    warn!(
                        "discarding a message from {peer_pkarr} that this build cannot parse \
                         ({e}); the sender may be running a newer protocol"
                    );
                    self.inboxes.acknowledge(&peer, &[d.id]).await;
                }
            }
        }
        Ok(parsed)
    }

    /// Stop delivering a message returned by [`poll_from`](Self::poll_from) or
    /// [`poll_all`](Self::poll_all).
    pub async fn acknowledge(&self, receipt: &Receipt) {
        self.inboxes
            .acknowledge(&receipt.peer, std::slice::from_ref(&receipt.id))
            .await;
    }

    /// Unacknowledged messages from all known peers, polled concurrently.
    pub async fn poll_all<M: DeserializeOwned>(&self) -> Result<Vec<Inbound<M>>> {
        use futures::future::join_all;

        let peers = self.get_known_peers();
        let polls = peers.iter().map(|peer| async move {
            let res = self.poll_from::<M>(peer).await;
            (peer, res)
        });

        let mut all = Vec::new();
        for (peer, res) in join_all(polls).await {
            match res {
                Ok(msgs) => all.extend(msgs),
                Err(e) => debug!("failed to receive from {peer}: {e}"),
            }
        }
        Ok(all)
    }

    /// Receive and acknowledge new messages from all known peers concurrently.
    pub async fn receive_all<M: DeserializeOwned>(&self) -> Result<Vec<(String, M)>> {
        let inbound = self.poll_all::<M>().await?;
        let mut all = Vec::with_capacity(inbound.len());
        for m in inbound {
            self.acknowledge(&m.receipt).await;
            all.push((m.peer, m.message));
        }
        Ok(all)
    }

    /// Delete this side's messages in a conversation with a peer (cleanup).
    ///
    /// Receive state needs no change: acknowledgements for deleted messages drop out at the next
    /// listing.
    pub async fn clear_messages_with_peer(&self, peer_pkarr: &str) -> Result<()> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(format!("{e}")))?;
        self.messenger
            .clear_messages(&peer)
            .await
            .map_err(|e| TransportError::Messenger(format!("clear messages: {e}")))?;
        Ok(())
    }

    /// Clear messages with all known peers.
    pub async fn clear_all_messages(&self) -> Result<()> {
        for peer in self.get_known_peers() {
            if let Err(e) = self.clear_messages_with_peer(&peer).await {
                warn!("failed to clear messages with {peer}: {e}");
            }
        }
        Ok(())
    }
}

/// The messaging surface the swap protocol needs from a transport.
///
/// [`Transport`] (encrypted Pubky DMs) is the implementation used today. Naming the surface as a
/// trait is the seam that lets the same `swap-provider` / `swap-client` protocol run over an
/// alternative transport later, e.g. the authenticated, holepunched iroh QUIC stream in the
/// [`p2p`] module, without touching the swap state machine, HTLC scripting, or persisted store.
///
/// Discovery and execution have different needs: discovery wants to be real-time (a client
/// walking up to a listening provider), while execution spans blocks/hours and must survive
/// disconnects and restarts. A holepunched stream suits the former; the durable
/// store-and-forward DMs modelled here remain the safer choice for the latter, so a deployment
/// may use both.
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

#[cfg(test)]
mod poll_window_tests {
    use super::*;

    /// A peer's backlog is not ours to answer.
    ///
    /// The regression: a provider that restarted, or that re-added a returning peer when it rang
    /// the doorbell, read that peer's whole conversation and answered every request in it again.
    /// One quote request drew nine quotes.
    #[test]
    fn a_peer_is_only_polled_from_the_moment_it_joined() {
        let peers = PeerSet::default();
        peers.touch_or_add("peer".into(), false);

        let joined = peers
            .polling_from("peer")
            .expect("a tracked peer records when it joined");
        assert!(joined > 0, "the join time is recorded in Unix seconds");

        // A week-old request predates our interest in this peer by far more than the grace.
        let week_old = joined - 7 * 24 * 3600;
        assert!(
            week_old < joined.saturating_sub(POLL_FROM_GRACE_SECS),
            "a backlog is discarded"
        );

        // A request written in the same second the doorbell rang, or a little before it, is the
        // one we were actually woken for.
        for skew in [0, 1, 30, POLL_FROM_GRACE_SECS - 1] {
            let fresh = joined - skew;
            assert!(
                fresh >= joined.saturating_sub(POLL_FROM_GRACE_SECS),
                "a message {skew}s before the peer joined must still be read"
            );
        }
    }

    /// Touching a peer must not move the window: a peer that keeps talking would otherwise have
    /// its own in-flight messages fall behind a floor that kept advancing.
    #[test]
    fn the_window_is_set_once_and_does_not_advance() {
        let peers = PeerSet::default();
        peers.touch_or_add("peer".into(), false);
        let first = peers.polling_from("peer").unwrap();
        peers.touch_or_add("peer".into(), true);
        assert_eq!(peers.polling_from("peer"), Some(first));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_prefixes_normalize_without_accepting_resource_paths() {
        let key = "q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro";
        for prefix in ["", "pubky", "pubky:", "pubky://", "pk:"] {
            assert_eq!(canonical_pubky(&format!(" {prefix}{key}/ ")).unwrap(), key);
        }
        for invalid in [
            String::new(),
            format!("https://{key}"),
            format!("pubky://{key}/pub/profile.json"),
            format!("pubky://{key}?query=value"),
            "0".repeat(52),
        ] {
            assert!(canonical_pubky(&invalid).is_err());
        }
    }

    #[test]
    fn pubkys_are_compared_as_keys_not_as_text() {
        let key = pkarr::Keypair::random().public_key().to_string();
        let other = pkarr::Keypair::random().public_key().to_string();
        assert!(same_pubky(&key, &key));
        assert!(!same_pubky(&key, &other));
        // The same key wearing the URL clothes the follow graph hands out.
        assert!(same_pubky(&key, &format!("pubky://{key}")));
        assert!(same_pubky(&format!("{key}/"), &key));
        // Neither side parses: an exact match is all there is to go on.
        assert!(same_pubky("peer-a", "peer-a"));
        assert!(!same_pubky("peer-a", "peer-b"));
        assert!(!same_pubky("", &key));
    }

    #[test]
    fn touch_add_and_list() {
        let set = PeerSet::default();
        set.touch_or_add("a".into(), false);
        set.touch_or_add("b".into(), true);
        let mut all = set.all();
        all.sort();
        assert_eq!(all, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn pinned_peers_are_never_idle_reaped() {
        let set = PeerSet::default();
        set.touch_or_add("dynamic".into(), false);
        set.touch_or_add("pinned".into(), true);
        // ttl == 0 => every peer counts as idle, but pinned ones are excluded.
        let idle = set.idle_unpinned(Duration::ZERO);
        assert_eq!(idle, vec!["dynamic".to_string()]);
    }

    #[test]
    fn touch_does_not_unpin() {
        let set = PeerSet::default();
        set.touch_or_add("p".into(), true);
        set.touch_or_add("p".into(), false); // a plain re-add / touch must not clear the pin
        assert!(set.idle_unpinned(Duration::ZERO).is_empty());
    }

    #[test]
    fn fresh_peer_not_reaped_under_positive_ttl() {
        let set = PeerSet::default();
        set.touch_or_add("a".into(), false);
        // A just-added peer is not idle for an hour.
        assert!(set.idle_unpinned(Duration::from_secs(3600)).is_empty());
    }

    #[test]
    fn prefixed_peers_are_protected_under_their_canonical_key() {
        let key = pkarr::Keypair::random().public_key().to_string();
        let set = PeerSet::default();
        set.touch_or_add(format!("pk:{key}"), false);
        assert!(set.canonical_keys().contains(&key));
    }

    #[test]
    fn remove_drops_peer() {
        let set = PeerSet::default();
        set.touch_or_add("a".into(), false);
        set.remove("a");
        assert!(set.all().is_empty());
    }
}
