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
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

#[cfg(test)]
mod delivery_tests;
mod inbox;
mod journal;
pub mod outbox;
pub mod poll;
pub use poll::{PeerInbox, PollConfig, PollStats};

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
    /// A request that certainly never left this process, so it is safe to send it another way.
    #[error("request not sent: {0}")]
    NotSent(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A tracked peer in the poll set.
#[derive(Debug, Clone)]
struct PeerEntry {
    /// Pinned peers are never idle-reaped (e.g. operator-curated follows loaded by
    /// [`Transport::discover_peers`], or a client's configured provider). They are still removed
    /// by an explicit [`Transport::evict_peer`].
    pinned: bool,
    /// Last time we added or read a message from this peer, for idle reaping.
    last_seen: Instant,
}

/// The set of peers a transport polls, with pin + idle-reaping bookkeeping. Extracted from
/// [`Transport`] so its lifecycle logic is unit-testable without a live messenger.
#[derive(Default)]
struct PeerSet {
    peers: RwLock<HashMap<String, PeerEntry>>,
}

impl PeerSet {
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
                });
        }
    }

    /// Bump a tracked peer's last-seen time. Unlike [`touch_or_add`](Self::touch_or_add), a peer
    /// that is no longer tracked stays gone.
    fn touch(&self, pubky: &str) {
        if let Ok(mut peers) = self.peers.write() {
            if let Some(entry) = peers.get_mut(pubky) {
                entry.last_seen = Instant::now();
            }
        }
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
    inboxes: Arc<inbox::Inboxes>,
    poll_waker: Arc<poll::PollWaker>,
    outbox: Option<outbox::Outbox>,
    resource_locks: Mutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
}

impl Transport {
    /// Sign into an existing account using its Ed25519 secret without deriving another key.
    /// The account must already be registered with a homeserver.
    pub async fn from_secret_key(secret: [u8; 32]) -> Result<Self> {
        let transport = Self::unsigned(secret)?;
        transport.sign_in().await?;
        Ok(transport)
    }

    /// A transport for `secret` that has not contacted its homeserver. Sending and polling need
    /// [`sign_in`](Self::sign_in) first, so a caller that may never use DMs can defer it.
    pub fn unsigned(secret: [u8; 32]) -> Result<Self> {
        let messenger = PrivateMessengerClient::new(pkarr::Keypair::from_secret_key(&secret))
            .map_err(|error| TransportError::Messenger(format!("create messenger: {error}")))?;
        Ok(Self::wrap(messenger))
    }

    /// Restore a messenger identity without contacting its homeserver.
    pub fn unsigned_from_recovery(method: &str, value: &str, passphrase: &str) -> Result<Self> {
        let messenger = match method {
            "file" => {
                PrivateMessengerClient::from_recovery_file(&fs::read(value)?, Some(passphrase))
            }
            "phrase" => PrivateMessengerClient::from_recovery_phrase(value, Some(passphrase), None),
            _ => return Err(TransportError::Messenger("unknown recovery method".into())),
        }
        .map_err(|_| TransportError::Messenger("could not restore messenger identity".into()))?;
        Ok(Self::wrap(messenger))
    }

    /// Sign in to the account's homeserver.
    pub async fn sign_in(&self) -> Result<()> {
        self.messenger
            .sign_in()
            .await
            .map_err(|error| TransportError::Messenger(format!("sign in: {error}")))?;
        Ok(())
    }

    /// Create a transport from a Pubky recovery file + passphrase.
    pub async fn from_recovery_file(recovery_path: &str, passphrase: &str) -> Result<Self> {
        let recovery_bytes = fs::read(recovery_path)?;
        let messenger =
            PrivateMessengerClient::from_recovery_file(&recovery_bytes, Some(passphrase))
                .map_err(|e| TransportError::Messenger(format!("create messenger: {e}")))?;
        let transport = Self::wrap(messenger);
        transport.sign_in().await?;
        Ok(transport)
    }

    /// Create a transport from a Pubky recovery phrase (+ optional passphrase).
    pub async fn from_recovery_phrase(mnemonic: &str, passphrase: Option<&str>) -> Result<Self> {
        let messenger = PrivateMessengerClient::from_recovery_phrase(mnemonic, passphrase, None)
            .map_err(|e| TransportError::Messenger(format!("create messenger: {e}")))?;
        let transport = Self::wrap(messenger);
        transport.sign_in().await?;
        Ok(transport)
    }

    fn wrap(messenger: PrivateMessengerClient) -> Self {
        Self {
            messenger,
            known_peers: Arc::new(PeerSet::default()),
            inboxes: Arc::new(inbox::Inboxes::default()),
            poll_waker: Arc::default(),
            outbox: None,
            resource_locks: Mutex::default(),
        }
    }

    /// Restore pending deliveries and peers, including doorbells received before the first read.
    pub fn with_receive_journal(mut self, path: impl AsRef<std::path::Path>) -> Result<Self> {
        let inboxes = inbox::Inboxes::open(path.as_ref(), &self.public_key_string())?;
        for (peer, pinned) in inboxes.registered() {
            self.known_peers.touch_or_add(peer, pinned);
        }
        self.inboxes = Arc::new(inboxes);
        Ok(self)
    }

    /// Restore encrypted outgoing work. The journal must belong to this identity and process.
    pub fn with_outbox(mut self, path: impl AsRef<std::path::Path>) -> Result<Self> {
        let outbox = outbox::Outbox::open(path)?;
        outbox.check_owner(&self.public_key_string())?;
        self.outbox = Some(outbox);
        Ok(self)
    }

    /// Message-storage HTTP attempts and bytes, including retries and storage sessions.
    /// SDK account, profile and follow operations are outside these counters.
    pub fn request_stats(&self) -> pubky_messenger::RequestStats {
        self.messenger.request_stats()
    }

    pub fn homeserver_requests(&self) -> u64 {
        let stats = self.request_stats();
        [
            stats.list,
            stats.get,
            stats.put,
            stats.delete,
            stats.session,
        ]
        .iter()
        .map(|method| method.attempts)
        .sum()
    }

    /// Persist one stable encrypted resource before publishing it. Retrying identical scope and
    /// content reuses its ID and bytes, including after an ambiguous HTTP outcome or restart.
    pub async fn send_with_scope<M: Serialize>(
        &self,
        peer: &str,
        scope: &str,
        message: &M,
    ) -> Result<()> {
        if self.outbox.is_none() {
            return self.send(&canonical_pubky(peer)?, message).await;
        }
        let prepared = self.prepare_scoped(peer, scope, message)?;
        self.publish_saved(&prepared, false).await
    }

    /// Reserve outgoing bytes without network I/O. A worker may publish after the caller saves
    /// its durable outcome; repeated reservations reuse the same resource.
    pub fn enqueue_with_scope<M: Serialize>(
        &self,
        peer: &str,
        scope: &str,
        message: &M,
    ) -> Result<()> {
        self.prepare_scoped(peer, scope, message).map(|_| ())
    }

    fn prepare_scoped<M: Serialize>(
        &self,
        peer: &str,
        scope: &str,
        message: &M,
    ) -> Result<pubky_messenger::PreparedMessage> {
        let peer = canonical_pubky(peer)?;
        let outbox = self
            .outbox
            .as_ref()
            .ok_or_else(|| TransportError::Messenger("outbox is not configured".into()))?;
        outbox.check_owner(&self.public_key_string())?;
        let key = PublicKey::try_from(peer.as_str())
            .map_err(|error| TransportError::InvalidPubkey(error.to_string()))?;
        let payload = serde_json::to_string(message)?;
        let ephemeral_scope = scope
            .starts_with("ephemeral:")
            .then(|| format!("{scope}:{}", blake3::hash(payload.as_bytes()).to_hex()));
        let scope = ephemeral_scope.as_deref().unwrap_or(scope);
        let expiry = scope
            .starts_with("ephemeral:")
            .then(|| unix_time().saturating_add(10 * 60));
        let prepared = outbox.prepare_with_expiry(&peer, scope, &payload, expiry, || {
            self.messenger.prepare_message(&key, &payload)
        })?;
        Ok(prepared)
    }

    /// Detect previously prepared DM traffic without contacting a homeserver.
    pub fn has_outbox_scope(&self, peer: &str, scope: &str) -> Result<bool> {
        let Some(outbox) = &self.outbox else {
            return Ok(false);
        };
        outbox.check_owner(&self.public_key_string())?;
        outbox.has_scope(&canonical_pubky(peer)?, scope)
    }

    /// Schedule only this application's owned resources after a durable terminal transition.
    /// The caller must retain swap recovery records and replay protection independently.
    pub fn complete_scope(&self, peer: &str, scope: &str, eligible_after: u64) -> Result<()> {
        if let Some(outbox) = &self.outbox {
            outbox.check_owner(&self.public_key_string())?;
            outbox.complete_scope(&canonical_pubky(peer)?, scope, eligible_after)?;
        }
        Ok(())
    }

    /// Revoke deferred cleanup after a reorg or an uncertain application transition.
    pub fn reopen_scope(&self, peer: &str, scope: &str) -> Result<()> {
        if let Some(outbox) = &self.outbox {
            outbox.check_owner(&self.public_key_string())?;
            outbox.reopen_scope(&canonical_pubky(peer)?, scope)?;
        }
        Ok(())
    }

    /// Run a bounded batch of durable retries and exact-resource cleanup. Errors retain work.
    /// Each operation has a total deadline in addition to the messenger's attempt deadlines.
    pub async fn process_outbox(&self, now: u64, limit: usize) -> Result<()> {
        use futures::{stream, StreamExt};
        let Some(outbox) = &self.outbox else {
            return Ok(());
        };
        outbox.check_owner(&self.public_key_string())?;
        let pending = outbox.due_pending(now, limit)?;
        let cleanup = outbox.eligible_cleanup(now, limit)?;
        let publications = stream::iter(
            pending
                .into_iter()
                .map(|prepared| async move { self.publish_saved(&prepared, true).await }),
        )
        .buffer_unordered(4)
        .collect::<Vec<_>>();
        let deletions = stream::iter(cleanup.into_iter().map(|prepared| async move {
            let lock = self.resource_lock(prepared.id())?;
            let _guard = lock.lock().await;
            outbox.check_owner(&self.public_key_string())?;
            if !outbox.can_cleanup(prepared.id(), now)? {
                return Ok(());
            }
            let peer = PublicKey::try_from(prepared.recipient())
                .map_err(|error| TransportError::InvalidPubkey(error.to_string()))?;
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                self.messenger.delete_message(prepared.id(), &peer),
            )
            .await;
            match result {
                Ok(Ok(())) => outbox.remove_deleted(&[prepared.id().to_owned()], now),
                _ => {
                    outbox.mark_cleanup_failed(prepared.id(), now)?;
                    Err(TransportError::Messenger(
                        "message cleanup will retry".into(),
                    ))
                }
            }
        }))
        .buffer_unordered(4)
        .collect::<Vec<_>>();
        let (published, deleted) = tokio::join!(publications, deletions);
        for result in published.into_iter().chain(deleted) {
            result?;
        }
        Ok(())
    }

    fn resource_lock(&self, id: &str) -> Result<Arc<tokio::sync::Mutex<()>>> {
        let mut locks = self
            .resource_locks
            .lock()
            .map_err(|_| TransportError::Messenger("message operation lock poisoned".into()))?;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(id).and_then(std::sync::Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(id.to_owned(), Arc::downgrade(&lock));
        Ok(lock)
    }

    async fn publish_saved(
        &self,
        prepared: &pubky_messenger::PreparedMessage,
        background: bool,
    ) -> Result<()> {
        let outbox = self
            .outbox
            .as_ref()
            .ok_or_else(|| TransportError::Messenger("outbox is not configured".into()))?;
        let lock = self.resource_lock(prepared.id())?;
        let _guard = lock.lock().await;
        outbox.check_owner(&self.public_key_string())?;
        if !outbox.can_publish(prepared.id(), unix_time())? {
            return if background {
                Ok(())
            } else {
                Err(TransportError::Messenger(
                    "message scope has expired".into(),
                ))
            };
        }
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            self.messenger.publish_message(prepared),
        )
        .await;
        match result {
            Ok(Ok(_)) => outbox.mark_published(prepared.id()),
            _ => {
                outbox.mark_failed(prepared.id(), unix_time())?;
                Err(TransportError::Messenger(
                    "message publication will retry".into(),
                ))
            }
        }
    }

    /// Persist peer registration before scheduling its first poll.
    pub fn register_peer(&self, peer: &str, pinned: bool) -> Result<()> {
        let peer = canonical_pubky(peer)?;
        self.inboxes.register(&peer, pinned)?;
        self.known_peers.touch_or_add(peer.clone(), pinned);
        self.poll_waker.wake(&peer);
        Ok(())
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
        if self.register_peer(&peer_pkarr, false).is_err() {
            warn!("could not persist peer registration");
        }
    }

    /// Track a peer and mark it pinned, so it is polled but never idle-reaped (only an explicit
    /// [`evict_peer`](Self::evict_peer) removes it). Use for operator-curated follows and a
    /// client's configured provider.
    pub fn pin_peer(&self, peer_pkarr: String) {
        if self.register_peer(&peer_pkarr, true).is_err() {
            warn!("could not persist pinned peer registration");
        }
    }

    /// Snapshot of currently known peers.
    pub fn get_known_peers(&self) -> Vec<String> {
        self.known_peers.all()
    }

    /// Unpinned peers whose last activity is older than `ttl` (candidates for idle reaping).
    pub fn idle_unpinned_peers(&self, ttl: Duration) -> Vec<String> {
        self.known_peers
            .idle_unpinned(ttl)
            .into_iter()
            .filter(|peer| !self.inboxes.has_pending(peer))
            .collect()
    }

    /// Stop tracking a peer: drop it from the in-memory poll set and best-effort remove any
    /// follow relationship (so the persistent follow graph does not grow without bound). A
    /// failed `delete_follow` is logged, not propagated, so the peer is always removed from the
    /// poll set. Removes pinned peers too.
    pub async fn evict_peer(&self, pubky: &str) {
        match self.inboxes.evict(pubky) {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => {
                warn!("could not persist peer eviction");
                return;
            }
        }
        self.known_peers.remove(pubky);
        self.poll_waker.changed();
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
            self.register_peer(&user.pubky, true)?;
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
        let pubky = canonical_pubky(pubky)?;
        if !self.inboxes.evict(&pubky)? {
            return Err(TransportError::Messenger(
                "peer still has pending delivery work".into(),
            ));
        }
        self.known_peers.remove(&pubky);
        self.poll_waker.changed();
        self.messenger
            .delete_follow(&pubky)
            .await
            .map_err(|e| TransportError::Messenger(format!("unfollow: {e}")))
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

    /// List and acknowledge old replies before a new legacy request. New protocols should use
    /// request correlation and explicit receipts instead of clearing a conversation boundary.
    pub async fn mark_conversation_seen(&self, peer_pkarr: &str) -> Result<usize> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(e.to_string()))?;
        self.inboxes
            .acknowledge_listed(&self.messenger, &peer)
            .await
    }

    /// Receive leased messages. Drop or release a receipt to retry; acknowledge after handling.
    pub async fn poll_from<M: DeserializeOwned>(
        &self,
        peer_pkarr: &str,
    ) -> Result<Vec<Inbound<M>>> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(e.to_string()))?;
        self.register_peer(peer_pkarr, false)?;
        let result = self.inboxes.poll(&self.messenger, &peer).await?;
        if !result.is_empty() {
            self.known_peers.touch(&peer.to_string());
        }
        Ok(result)
    }

    /// Compatibility helper that acknowledges each message on delivery.
    pub async fn receive_from<M: DeserializeOwned>(&self, peer: &str) -> Result<Vec<M>> {
        let messages = self.poll_from(peer).await?;
        for inbound in &messages {
            self.acknowledge(&inbound.receipt)?;
        }
        Ok(messages
            .into_iter()
            .map(|inbound| inbound.message)
            .collect())
    }

    pub async fn receive_all_with_receipts<M: DeserializeOwned>(&self) -> Result<Vec<Inbound<M>>> {
        let mut messages = Vec::new();
        for peer in self.get_known_peers() {
            messages.extend(self.poll_from(&peer).await?);
        }
        Ok(messages)
    }

    /// Compatibility helper. Providers should use the independent peer scheduler instead.
    pub async fn receive_all<M: DeserializeOwned>(&self) -> Result<Vec<(String, M)>> {
        let messages = self.receive_all_with_receipts().await?;
        for inbound in &messages {
            self.acknowledge(&inbound.receipt)?;
        }
        Ok(messages
            .into_iter()
            .map(|inbound| (inbound.peer, inbound.message))
            .collect())
    }

    /// Independently schedule bounded polls, delivering one peer as soon as its read completes.
    pub fn receiver<M: DeserializeOwned + 'static>(
        self: &Arc<Self>,
        config: PollConfig,
    ) -> PeerInbox<Inbound<M>> {
        let peers = self.known_peers.clone();
        let transport = self.clone();
        PeerInbox::new(
            config,
            Box::new(move || peers.all()),
            Box::new(move |peer| {
                let transport = transport.clone();
                Box::pin(async move {
                    // A removed peer must not be registered again by a stale scheduled poll.
                    if !transport.get_known_peers().contains(&peer) {
                        return Ok(Vec::new());
                    }
                    let key = PublicKey::try_from(peer.as_str())
                        .map_err(|e| TransportError::InvalidPubkey(e.to_string()))?;
                    let messages = transport
                        .inboxes
                        .poll_registered(&transport.messenger, &key)
                        .await?;
                    if !messages.is_empty() {
                        transport.known_peers.touch(&peer);
                    }
                    Ok(messages)
                })
            }),
            self.poll_waker.clone(),
        )
    }

    /// Persist the handled outcome before releasing this message's delivery lease.
    pub fn acknowledge(&self, receipt: &Receipt) -> Result<()> {
        self.inboxes.acknowledge(receipt)
    }
    pub fn release(&self, receipt: &Receipt) {
        self.inboxes.release(receipt);
    }
    pub fn has_pending_messages(&self, peer: &str) -> bool {
        self.inboxes.has_pending(peer)
    }

    /// Delete locally published conversation messages. Receive acknowledgments are retained.
    pub async fn clear_messages_with_peer(&self, peer_pkarr: &str) -> Result<()> {
        let peer = PublicKey::try_from(peer_pkarr)
            .map_err(|e| TransportError::InvalidPubkey(e.to_string()))?;
        self.messenger
            .clear_messages(&peer)
            .await
            .map_err(|e| TransportError::Messenger(format!("clear messages: {e}")))
    }

    pub async fn clear_all_messages(&self) -> Result<()> {
        for peer in self.get_known_peers() {
            self.clear_messages_with_peer(&peer).await?;
        }
        Ok(())
    }
}

/// One message and its exclusive delivery lease.
#[derive(Debug)]
pub struct Inbound<M> {
    pub peer: String,
    pub message: M,
    pub receipt: Receipt,
}

/// Dropping the receipt makes unacknowledged work available to a later poll.
pub struct Receipt {
    peer: String,
    id: pubky_messenger::MessageId,
    lease: u64,
    journal: Arc<Mutex<journal::Journal>>,
    leases: Arc<Mutex<HashMap<pubky_messenger::MessageId, u64>>>,
}

impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receipt").finish_non_exhaustive()
    }
}

impl Receipt {
    /// Resource identity for audit and scoped retention, independent of the message payload.
    pub fn message_id(&self) -> &pubky_messenger::MessageId {
        &self.id
    }

    /// Record successful processing before releasing this delivery lease.
    pub fn acknowledge(&self) -> Result<()> {
        self.journal
            .lock()
            .unwrap()
            .acknowledge(&self.peer, std::slice::from_ref(&self.id))?;
        let mut leases = self.leases.lock().unwrap();
        if leases.get(&self.id) == Some(&self.lease) {
            leases.remove(&self.id);
        }
        Ok(())
    }
}

impl Drop for Receipt {
    fn drop(&mut self) {
        let mut leases = self.leases.lock().unwrap();
        if leases.get(&self.id) == Some(&self.lease) {
            leases.remove(&self.id);
        }
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

    /// A homeserver that cannot be reached must fail the read, not look like an empty
    /// conversation, or the poller backs off as if the peer were merely quiet.
    #[tokio::test]
    async fn an_unreachable_homeserver_is_a_failed_read_not_an_empty_one() {
        let mut builder = pubky_messenger::pubky::Client::builder();
        // Resolution goes only to a relay that refuses connections, so neither conversation
        // listing can reach a homeserver.
        builder.pkarr(|pkarr| {
            pkarr
                .no_default_network()
                .relays(&["http://127.0.0.1:1"])
                .expect("relay url parses")
        });
        let client = builder.build().expect("pubky client builds");
        let transport = Transport::wrap(PrivateMessengerClient::with_client(
            pkarr::Keypair::random(),
            client,
        ));
        let peer = pkarr::Keypair::random().public_key().to_string();

        let read = transport.receive_from::<serde_json::Value>(&peer).await;
        assert!(
            matches!(read, Err(TransportError::Messenger(_))),
            "expected a messenger error, got {read:?}"
        );
        assert!(transport.mark_conversation_seen(&peer).await.is_err());
    }

    #[test]
    fn transport_restart_restores_a_doorbell_before_any_message_is_read() {
        let path = std::env::temp_dir().join(format!(
            "swap-peer-{}.json",
            pkarr::Keypair::random().public_key()
        ));
        let key = pkarr::Keypair::random();
        let peer = pkarr::Keypair::random().public_key().to_string();
        let transport = Transport::wrap(PrivateMessengerClient::new(key.clone()).unwrap())
            .with_receive_journal(&path)
            .unwrap();
        transport.register_peer(&peer, false).unwrap();
        drop(transport);
        let restored = Transport::wrap(PrivateMessengerClient::new(key).unwrap())
            .with_receive_journal(&path)
            .unwrap();
        assert_eq!(restored.get_known_peers(), vec![peer]);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn remove_drops_peer() {
        let set = PeerSet::default();
        set.touch_or_add("a".into(), false);
        set.remove("a");
        assert!(set.all().is_empty());
    }
}
