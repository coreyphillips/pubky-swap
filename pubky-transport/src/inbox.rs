//! Per-peer receive state over the messenger's incremental API.
//!
//! Every poll lists both copies of a conversation, which is cheap, and downloads only bodies this
//! process has not already dealt with. Delivery is tracked by message resource (publisher and
//! URL), never by filename order or timestamp: names are random, and timestamps are set by the
//! sender with one-second granularity.
//!
//! A message is in one of three places:
//!
//! - unlisted by any poll so far: it is found by the next listing, wherever its name sorts;
//! - delivered and not yet acknowledged: returned by every poll, from memory, until the caller
//!   acknowledges it after dispatch;
//! - acknowledged: never downloaded again while it stays listed.
//!
//! Receive state lives in memory. A restarted process, or a returning peer whose inbox was dropped
//! to keep retention bounded, downloads that peer's side of the conversation once more. What it may act on
//! is then decided by the caller's timestamp floor (when the peer joined the poll set), not by what
//! this module remembers, so losing the state costs requests and never revives stale work.
//!
//! Messages this side published are acknowledged from the listing and never downloaded. Nothing
//! reads its own requests back.

use futures::lock::Mutex as AsyncMutex;
use pkarr::PublicKey;
use pubky_messenger::{
    DecryptedMessage, Discovery, FetchFailure, MessageId, PendingMessage, PrivateMessengerClient,
    ReceiveState, ReceivedMessage, ReceivedMessages,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::debug;

use crate::{Result, TransportError};

/// Inboxes kept for peers, including ones no longer polled. A returning peer whose inbox was kept
/// costs a listing rather than a download of its whole history. Inboxes of polled peers are never
/// dropped, so the cap can be exceeded.
pub(crate) const MAX_RETAINED_INBOXES: usize = 1024;

/// The part of the messenger an inbox needs, so the delivery rules can be tested without a
/// homeserver.
#[allow(async_fn_in_trait)]
pub(crate) trait Mailbox {
    fn own_pubky(&self) -> String;
    async fn discover(&self, peer: &PublicKey, state: &mut ReceiveState) -> Result<Discovery>;
    async fn retrieve(
        &self,
        peer: &PublicKey,
        pending: &[PendingMessage],
    ) -> Result<ReceivedMessages>;
}

impl Mailbox for PrivateMessengerClient {
    fn own_pubky(&self) -> String {
        self.public_key_string()
    }

    async fn discover(&self, peer: &PublicKey, state: &mut ReceiveState) -> Result<Discovery> {
        self.discover_messages(peer, state)
            .await
            .map_err(|e| TransportError::Messenger(format!("list messages: {e}")))
    }

    async fn retrieve(
        &self,
        peer: &PublicKey,
        pending: &[PendingMessage],
    ) -> Result<ReceivedMessages> {
        self.retrieve_messages(peer, pending)
            .await
            .map_err(|e| TransportError::Messenger(format!("retrieve messages: {e}")))
    }
}

/// A message from a peer that has been delivered and awaits acknowledgement.
#[derive(Debug, Clone)]
pub(crate) struct Delivered {
    pub id: MessageId,
    pub message: DecryptedMessage,
}

#[derive(Default)]
struct Inbox {
    state: ReceiveState,
    /// Bodies delivered but not acknowledged, so redelivering them costs no request. Only ever
    /// holds messages still listed, so it is bounded by the conversation.
    delivered: HashMap<MessageId, DecryptedMessage>,
}

impl Inbox {
    fn acknowledge(&mut self, id: &MessageId) {
        self.delivered.remove(id);
        // Under the default write-once policy only the identity is recorded.
        self.state.acknowledge(&ReceivedMessage {
            id: id.clone(),
            message: None,
            etag: None,
            updated: false,
        });
    }
}

struct Slot {
    inbox: Arc<AsyncMutex<Inbox>>,
    last_used: u64,
}

#[derive(Default)]
struct Slots {
    by_peer: HashMap<String, Slot>,
    clock: u64,
}

pub(crate) struct Inboxes {
    slots: Mutex<Slots>,
    /// The canonical keys of peers still polled. Their inboxes are never dropped: the caller's
    /// floor for a polled peer is when it joined, so a fresh inbox would deliver everything it
    /// acknowledged since.
    polled: Box<dyn Fn() -> HashSet<String> + Send + Sync>,
}

impl Default for Inboxes {
    fn default() -> Self {
        Self::sparing(HashSet::new)
    }
}

impl Inboxes {
    pub(crate) fn sparing(polled: impl Fn() -> HashSet<String> + Send + Sync + 'static) -> Self {
        Self {
            slots: Mutex::default(),
            polled: Box::new(polled),
        }
    }

    fn inbox(&self, peer: &str) -> Arc<AsyncMutex<Inbox>> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots.clock += 1;
        let now = slots.clock;
        if let Some(slot) = slots.by_peer.get_mut(peer) {
            slot.last_used = now;
            return slot.inbox.clone();
        }
        if slots.by_peer.len() >= MAX_RETAINED_INBOXES {
            let polled = (self.polled)();
            // Trim to below the cap, which polled peers may have pushed it past. An inbox in use
            // is shared with the caller holding it; dropping ours only means the next caller
            // starts a fresh one.
            while slots.by_peer.len() >= MAX_RETAINED_INBOXES {
                let Some(oldest) = slots
                    .by_peer
                    .iter()
                    .filter(|(peer, _)| !polled.contains(*peer))
                    .min_by_key(|(_, slot)| slot.last_used)
                    .map(|(peer, _)| peer.clone())
                else {
                    break;
                };
                slots.by_peer.remove(&oldest);
            }
        }
        let inbox = Arc::new(AsyncMutex::new(Inbox::default()));
        slots.by_peer.insert(
            peer.to_string(),
            Slot {
                inbox: inbox.clone(),
                last_used: now,
            },
        );
        inbox
    }

    #[cfg(test)]
    fn retained(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .by_peer
            .len()
    }

    /// Messages from `peer` not yet acknowledged, oldest first.
    ///
    /// Anything stamped before `floor` is acknowledged without being delivered. Listings and
    /// bodies that could not be read are logged and left for the next poll.
    pub(crate) async fn poll<B: Mailbox>(
        &self,
        mailbox: &B,
        peer: &PublicKey,
        floor: Option<u64>,
    ) -> Result<Vec<Delivered>> {
        let own = mailbox.own_pubky();
        let inbox = self.inbox(&peer.to_string());
        let mut inbox = inbox.lock().await;
        let Discovery { pending, failures } = mailbox.discover(peer, &mut inbox.state).await?;
        log_failures(peer, &failures);

        // A directory that failed to list says nothing about whether its messages still exist.
        if failures.is_empty() {
            let listed: HashSet<&MessageId> = pending.iter().map(|p| &p.id).collect();
            inbox.delivered.retain(|id, _| listed.contains(id));
        }

        let mut order = Vec::new();
        let mut fetch = Vec::new();
        for p in &pending {
            if p.id.publisher == own {
                inbox.acknowledge(&p.id);
            } else {
                if !inbox.delivered.contains_key(&p.id) {
                    fetch.push(p.clone());
                }
                order.push(p.id.clone());
            }
        }

        if !fetch.is_empty() {
            let received = mailbox.retrieve(peer, &fetch).await?;
            log_failures(peer, &received.failures);
            for r in received.messages {
                match r.message {
                    Some(message) => {
                        inbox.delivered.insert(r.id, message);
                    }
                    None => {
                        debug!("acknowledging a message from {peer} that does not decrypt");
                        inbox.acknowledge(&r.id);
                    }
                }
            }
        }

        if !failures.is_empty() {
            // Held bodies were listed before, so a failed listing does not withhold them.
            let listed: HashSet<MessageId> = order.iter().cloned().collect();
            order.extend(
                inbox
                    .delivered
                    .keys()
                    .filter(|id| !listed.contains(*id))
                    .cloned(),
            );
        }

        let mut out = Vec::new();
        for id in order {
            let Some(message) = inbox.delivered.get(&id) else {
                // Not retrieved this time: deleted since listing, or failed and retried later.
                continue;
            };
            if floor.is_some_and(|floor| message.timestamp < floor) {
                inbox.acknowledge(&id);
                continue;
            }
            out.push(Delivered {
                message: message.clone(),
                id,
            });
        }
        // Stable, so same-second messages keep listing order.
        out.sort_by_key(|d| d.message.timestamp);
        Ok(out)
    }

    pub(crate) async fn acknowledge(&self, peer: &PublicKey, ids: &[MessageId]) {
        let inbox = self.inbox(&peer.to_string());
        let mut inbox = inbox.lock().await;
        for id in ids {
            inbox.acknowledge(id);
        }
    }

    /// Acknowledge everything currently listed in the conversation, downloading nothing.
    ///
    /// Returns how many messages were newly acknowledged. Directories that could not be listed
    /// are an error, after everything that was listed has been acknowledged.
    pub(crate) async fn acknowledge_listed<B: Mailbox>(
        &self,
        mailbox: &B,
        peer: &PublicKey,
    ) -> Result<usize> {
        let inbox = self.inbox(&peer.to_string());
        let mut inbox = inbox.lock().await;
        let Discovery { pending, failures } = mailbox.discover(peer, &mut inbox.state).await?;
        for p in &pending {
            inbox.acknowledge(&p.id);
        }
        match failures.first() {
            None => Ok(pending.len()),
            Some(failure) => Err(TransportError::Messenger(format!(
                "list messages: {} listing(s) unread, including {failure}",
                failures.len()
            ))),
        }
    }
}

fn log_failures(peer: &PublicKey, failures: &[FetchFailure]) {
    for failure in failures {
        debug!("reading the conversation with {peer}: {failure}");
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A two-party conversation held in memory, counting requests and charging each one a fixed
    //! latency on Tokio's clock.

    use super::*;
    use pkarr::Keypair;
    use std::time::Duration;

    pub(crate) const LATENCY: Duration = Duration::from_millis(50);
    /// Bodies retrieved concurrently per conversation, as the messenger's default allows.
    const CONCURRENT_BODIES: usize = 8;

    #[derive(Clone)]
    struct Stored {
        id: MessageId,
        message: DecryptedMessage,
        fails: u32,
    }

    #[derive(Default)]
    pub(crate) struct Counts {
        pub listings: usize,
        pub bodies: usize,
    }

    #[derive(Default)]
    struct Shared {
        messages: Vec<Stored>,
        /// Published once the next listing has been taken, as if written while it was read.
        after_listing: Vec<Stored>,
        next_name: u64,
        counts: Counts,
    }

    #[derive(Clone)]
    pub(crate) struct Conversation {
        shared: Arc<Mutex<Shared>>,
    }

    /// One participant's view of a [`Conversation`].
    pub(crate) struct Side {
        conversation: Conversation,
        pub key: Keypair,
    }

    impl Conversation {
        pub(crate) fn new() -> Self {
            Self {
                shared: Arc::new(Mutex::new(Shared::default())),
            }
        }

        pub(crate) fn side(&self, key: &Keypair) -> Side {
            Side {
                conversation: self.clone(),
                key: key.clone(),
            }
        }

        fn stored(shared: &mut Shared, from: &Keypair, timestamp: u64, content: &str) -> Stored {
            shared.next_name += 1;
            // Random-looking names, so listing order says nothing about publication order.
            let name = blake3::hash(&shared.next_name.to_le_bytes()).to_hex();
            let publisher = from.public_key().to_string();
            Stored {
                id: MessageId {
                    url: format!("pubky://{publisher}/pub/private_messages/{name}.json"),
                    publisher: publisher.clone(),
                },
                message: DecryptedMessage {
                    sender: publisher,
                    content: content.to_string(),
                    timestamp,
                    verified: true,
                },
                fails: 0,
            }
        }

        pub(crate) fn publish(&self, from: &Keypair, timestamp: u64, content: &str) -> MessageId {
            let mut shared = self.shared.lock().unwrap();
            let stored = Self::stored(&mut shared, from, timestamp, content);
            let id = stored.id.clone();
            shared.messages.push(stored);
            id
        }

        pub(crate) fn publish_during_next_listing(
            &self,
            from: &Keypair,
            timestamp: u64,
            content: &str,
        ) {
            let mut shared = self.shared.lock().unwrap();
            let stored = Self::stored(&mut shared, from, timestamp, content);
            shared.after_listing.push(stored);
        }

        /// The next `times` requests for `id`'s body fail.
        pub(crate) fn fail_body(&self, id: &MessageId, times: u32) {
            let mut shared = self.shared.lock().unwrap();
            if let Some(m) = shared.messages.iter_mut().find(|m| &m.id == id) {
                m.fails = times;
            }
        }

        pub(crate) fn len(&self) -> usize {
            self.shared.lock().unwrap().messages.len()
        }

        /// Every stored message, as a read that acknowledges nothing would see it.
        pub(crate) fn all_pending(&self) -> Vec<PendingMessage> {
            let shared = self.shared.lock().unwrap();
            shared
                .messages
                .iter()
                .map(|m| PendingMessage {
                    id: m.id.clone(),
                    acknowledged_etag: None,
                })
                .collect()
        }

        pub(crate) fn take_counts(&self) -> Counts {
            std::mem::take(&mut self.shared.lock().unwrap().counts)
        }
    }

    impl Mailbox for Side {
        fn own_pubky(&self) -> String {
            self.key.public_key().to_string()
        }

        async fn discover(&self, _peer: &PublicKey, state: &mut ReceiveState) -> Result<Discovery> {
            let pending = {
                let mut shared = self.conversation.shared.lock().unwrap();
                // Both directories are listed concurrently, one request each.
                shared.counts.listings += 2;
                let pending = shared
                    .messages
                    .iter()
                    .filter(|m| !state.is_acknowledged(&m.id))
                    .map(|m| PendingMessage {
                        id: m.id.clone(),
                        acknowledged_etag: None,
                    })
                    .collect();
                let late = std::mem::take(&mut shared.after_listing);
                shared.messages.extend(late);
                pending
            };
            tokio::time::sleep(LATENCY).await;
            Ok(Discovery {
                pending,
                failures: Vec::new(),
            })
        }

        async fn retrieve(
            &self,
            _peer: &PublicKey,
            pending: &[PendingMessage],
        ) -> Result<ReceivedMessages> {
            let mut messages = Vec::new();
            let mut failures = Vec::new();
            {
                let mut shared = self.conversation.shared.lock().unwrap();
                shared.counts.bodies += pending.len();
                for p in pending {
                    let Some(stored) = shared.messages.iter_mut().find(|m| m.id == p.id) else {
                        continue;
                    };
                    if stored.fails > 0 {
                        stored.fails -= 1;
                        failures.push(FetchFailure {
                            url: p.id.url.clone(),
                            attempts: 1,
                            reason: pubky_messenger::FailureReason::Status(503),
                        });
                        continue;
                    }
                    messages.push(ReceivedMessage {
                        id: stored.id.clone(),
                        message: Some(stored.message.clone()),
                        etag: None,
                        updated: false,
                    });
                }
            }
            let rounds = pending.len().div_ceil(CONCURRENT_BODIES) as u32;
            tokio::time::sleep(LATENCY * rounds).await;
            Ok(ReceivedMessages { messages, failures })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;
    use pkarr::Keypair;

    struct Pair {
        conversation: Conversation,
        provider: Side,
        client: Side,
    }

    fn pair() -> Pair {
        let conversation = Conversation::new();
        let provider = conversation.side(&Keypair::random());
        let client = conversation.side(&Keypair::random());
        Pair {
            conversation,
            provider,
            client,
        }
    }

    fn contents(delivered: &[Delivered]) -> Vec<&str> {
        delivered
            .iter()
            .map(|d| d.message.content.as_str())
            .collect()
    }

    async fn poll_and_ack(
        inboxes: &Inboxes,
        me: &Side,
        peer: &Side,
        floor: Option<u64>,
    ) -> Vec<Delivered> {
        let peer_key = peer.key.public_key();
        let delivered = inboxes.poll(me, &peer_key, floor).await.unwrap();
        let ids: Vec<_> = delivered.iter().map(|d| d.id.clone()).collect();
        inboxes.acknowledge(&peer_key, &ids).await;
        delivered
    }

    #[tokio::test(start_paused = true)]
    async fn an_unchanged_conversation_downloads_no_bodies_again() {
        let p = pair();
        p.conversation.publish(&p.client.key, 10, "request");
        p.conversation.publish(&p.provider.key, 11, "reply");
        let inboxes = Inboxes::default();

        let first = poll_and_ack(&inboxes, &p.provider, &p.client, None).await;
        assert_eq!(contents(&first), ["request"]);
        let counts = p.conversation.take_counts();
        // The provider's own reply is acknowledged from the listing, not downloaded.
        assert_eq!((counts.listings, counts.bodies), (2, 1));

        for _ in 0..3 {
            assert!(poll_and_ack(&inboxes, &p.provider, &p.client, None)
                .await
                .is_empty());
        }
        let counts = p.conversation.take_counts();
        assert_eq!((counts.listings, counts.bodies), (6, 0));
    }

    /// The old deduplication key was peer, timestamp and content hash, so two identical messages
    /// in the same second were one message.
    #[tokio::test(start_paused = true)]
    async fn identical_messages_in_the_same_second_are_both_delivered() {
        let p = pair();
        p.conversation.publish(&p.client.key, 10, "status?");
        p.conversation.publish(&p.client.key, 10, "status?");
        p.conversation.publish(&p.client.key, 10, "other");
        let inboxes = Inboxes::default();

        let delivered = poll_and_ack(&inboxes, &p.provider, &p.client, None).await;
        assert_eq!(delivered.len(), 3);
        assert!(poll_and_ack(&inboxes, &p.provider, &p.client, None)
            .await
            .is_empty());
    }

    /// The old set was cleared outright at 10,000 entries, after which every message still in the
    /// conversation came back as new.
    #[tokio::test(start_paused = true)]
    async fn a_history_longer_than_the_old_dedup_cap_is_never_redelivered() {
        let p = pair();
        for i in 0..10_050 {
            p.conversation.publish(&p.client.key, i, "old");
        }
        let inboxes = Inboxes::default();

        assert_eq!(
            poll_and_ack(&inboxes, &p.provider, &p.client, None)
                .await
                .len(),
            10_050
        );
        p.conversation.publish(&p.client.key, 20_000, "new");
        assert_eq!(
            contents(&poll_and_ack(&inboxes, &p.provider, &p.client, None).await),
            ["new"]
        );
        assert_eq!(p.conversation.take_counts().bodies, 10_051);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unacknowledged_message_is_redelivered_without_another_download() {
        let p = pair();
        p.conversation.publish(&p.client.key, 10, "request");
        let inboxes = Inboxes::default();
        let peer = p.client.key.public_key();

        // Received, then not dispatched: nothing to act on yet.
        let first = inboxes.poll(&p.provider, &peer, None).await.unwrap();
        assert_eq!(contents(&first), ["request"]);
        let again = inboxes.poll(&p.provider, &peer, None).await.unwrap();
        assert_eq!(contents(&again), ["request"]);
        assert_eq!(p.conversation.take_counts().bodies, 1);

        inboxes.acknowledge(&peer, &[again[0].id.clone()]).await;
        assert!(inboxes
            .poll(&p.provider, &peer, None)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_fails_to_download_is_retried_on_the_next_poll() {
        let p = pair();
        let id = p.conversation.publish(&p.client.key, 10, "request");
        p.conversation.fail_body(&id, 1);
        let inboxes = Inboxes::default();

        assert!(poll_and_ack(&inboxes, &p.provider, &p.client, None)
            .await
            .is_empty());
        assert_eq!(
            contents(&poll_and_ack(&inboxes, &p.provider, &p.client, None).await),
            ["request"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_written_during_the_first_listing_is_found_by_the_next() {
        let p = pair();
        p.conversation.publish(&p.client.key, 10, "before");
        p.conversation
            .publish_during_next_listing(&p.client.key, 11, "during");
        let inboxes = Inboxes::default();

        assert_eq!(
            contents(&poll_and_ack(&inboxes, &p.provider, &p.client, None).await),
            ["before"]
        );
        assert_eq!(
            contents(&poll_and_ack(&inboxes, &p.provider, &p.client, None).await),
            ["during"]
        );
    }

    /// A restart, or an inbox dropped for retention, starts from an empty state. The floor, not
    /// the state, decides what is current.
    #[tokio::test(start_paused = true)]
    async fn a_fresh_inbox_acknowledges_history_below_the_floor_without_delivering_it() {
        let p = pair();
        p.conversation
            .publish(&p.client.key, 1_000, "yesterday's quote request");
        p.conversation
            .publish(&p.client.key, 90_000, "current request");
        let restarted = Inboxes::default();

        let delivered = poll_and_ack(&restarted, &p.provider, &p.client, Some(89_880)).await;
        assert_eq!(contents(&delivered), ["current request"]);
        assert!(
            poll_and_ack(&restarted, &p.provider, &p.client, Some(89_880))
                .await
                .is_empty()
        );
        assert_eq!(p.conversation.take_counts().bodies, 2);
    }

    /// A request received just before a crash and not yet handled is still stamped after a floor
    /// set by the restart, so it is delivered again.
    #[tokio::test(start_paused = true)]
    async fn work_received_before_a_crash_is_delivered_after_restart() {
        let p = pair();
        p.conversation.publish(&p.client.key, 1_000, "swap request");
        let before_crash = Inboxes::default();
        let peer = p.client.key.public_key();
        assert_eq!(
            before_crash
                .poll(&p.provider, &peer, Some(900))
                .await
                .unwrap()
                .len(),
            1
        );
        drop(before_crash);

        let after_restart = Inboxes::default();
        let floor = 1_030 - crate::POLL_FROM_GRACE_SECS;
        assert_eq!(
            contents(
                &after_restart
                    .poll(&p.provider, &peer, Some(floor))
                    .await
                    .unwrap()
            ),
            ["swap request"]
        );
    }

    /// Re-adding a peer moves its floor forward. A kept inbox skips the download of what it already
    /// acknowledged, and anything that arrived while the peer was away is judged by the new floor.
    #[tokio::test(start_paused = true)]
    async fn a_returning_peer_costs_a_listing_and_revives_nothing() {
        let p = pair();
        p.conversation.publish(&p.client.key, 100, "first swap");
        let inboxes = Inboxes::default();
        poll_and_ack(&inboxes, &p.provider, &p.client, Some(0)).await;

        // Evicted; a stale request arrives while nobody polls; the peer returns much later.
        p.conversation
            .publish(&p.client.key, 200, "abandoned quote request");
        p.conversation.take_counts();
        p.conversation.publish(&p.client.key, 5_000, "second swap");
        let delivered = poll_and_ack(&inboxes, &p.provider, &p.client, Some(4_880)).await;

        assert_eq!(contents(&delivered), ["second swap"]);
        assert_eq!(p.conversation.take_counts().bodies, 2);
    }

    /// The client's pre-request sync lists, downloads nothing, and cannot hide the reply: the
    /// request is sent only after the listing completes, so its reply is a new resource.
    #[tokio::test(start_paused = true)]
    async fn acknowledging_the_listing_downloads_nothing_and_leaves_the_next_reply() {
        let p = pair();
        for i in 0..50 {
            p.conversation
                .publish(&p.provider.key, i, "earlier run's quote");
        }
        let inboxes = Inboxes::default();
        let provider = p.provider.key.public_key();

        assert_eq!(
            inboxes
                .acknowledge_listed(&p.client, &provider)
                .await
                .unwrap(),
            50
        );
        p.conversation.publish(&p.client.key, 100, "quote request");
        p.conversation
            .publish(&p.provider.key, 100, "this run's quote");

        assert_eq!(
            contents(&poll_and_ack(&inboxes, &p.client, &p.provider, None).await),
            ["this run's quote"]
        );
        assert_eq!(p.conversation.take_counts().bodies, 1);
    }

    #[test]
    fn retained_inboxes_are_bounded() {
        let inboxes = Inboxes::default();
        for i in 0..MAX_RETAINED_INBOXES + 10 {
            inboxes.inbox(&format!("peer-{i}"));
        }
        assert_eq!(inboxes.retained(), MAX_RETAINED_INBOXES);
    }

    #[test]
    fn the_cap_is_restored_once_polled_peers_leave() {
        let polled = Arc::new(Mutex::new(HashSet::new()));
        let inboxes = Inboxes::sparing({
            let polled = polled.clone();
            move || polled.lock().unwrap().clone()
        });
        for i in 0..MAX_RETAINED_INBOXES + 10 {
            let peer = format!("peer-{i}");
            polled.lock().unwrap().insert(peer.clone());
            inboxes.inbox(&peer);
        }
        polled.lock().unwrap().clear();
        inboxes.inbox("newcomer");
        assert_eq!(inboxes.retained(), MAX_RETAINED_INBOXES);
    }

    #[tokio::test(start_paused = true)]
    async fn a_polled_peer_keeps_its_inbox_past_the_cap() {
        let p = pair();
        let client = p.client.key.public_key().to_string();
        let inboxes = Inboxes::sparing(move || HashSet::from([client.clone()]));
        p.conversation.publish(&p.client.key, 100, "quote request");
        poll_and_ack(&inboxes, &p.provider, &p.client, Some(0)).await;

        for i in 0..MAX_RETAINED_INBOXES + 10 {
            inboxes.inbox(&format!("peer-{i}"));
        }

        assert!(poll_and_ack(&inboxes, &p.provider, &p.client, Some(0))
            .await
            .is_empty());
    }

    /// Requests and simulated time for repeated swaps between the same client and provider, as the
    /// conversation grows. Each swap: the client syncs and sends a request, the provider polls,
    /// replies, and polls twice more while the client polls until it has the reply. Both
    /// processes are long-lived except the client, which is a fresh run per swap.
    ///
    /// `full history` is the same schedule reading every body on every poll, which is what
    /// `get_messages` did. Print with
    /// `cargo test -p pubky-transport --lib swap_request_counts -- --nocapture`.
    #[tokio::test(start_paused = true)]
    async fn swap_request_counts() {
        use tokio::time::Instant;

        let p = pair();
        let provider_inboxes = Inboxes::default();
        let provider = p.provider.key.public_key();
        let client = p.client.key.public_key();
        let mut table = vec![
            format!("Latency: {LATENCY:?} per request, 8 bodies at a time."),
            "| swap | history | method | listings | bodies | elapsed |".to_string(),
            "|---|---|---|---|---|---|".to_string(),
        ];
        let mut rows = Vec::new();

        // Earlier conversation, already handled by this provider process.
        for i in 0..100 {
            p.conversation.publish(&p.client.key, i, "old request");
            p.conversation.publish(&p.provider.key, i, "old reply");
        }
        poll_and_ack(&provider_inboxes, &p.provider, &p.client, None).await;
        p.conversation.take_counts();

        for swap in 1..=5u64 {
            let history = p.conversation.len();
            let ts = 1_000 * swap;

            let start = Instant::now();
            let client_inboxes = Inboxes::default();
            client_inboxes
                .acknowledge_listed(&p.client, &provider)
                .await
                .unwrap();
            p.conversation.publish(&p.client.key, ts, "request");
            let request = poll_and_ack(&provider_inboxes, &p.provider, &p.client, None).await;
            assert_eq!(contents(&request), ["request"]);
            p.conversation.publish(&p.provider.key, ts, "reply");
            let reply = poll_and_ack(&client_inboxes, &p.client, &p.provider, None).await;
            assert_eq!(contents(&reply), ["reply"]);
            for _ in 0..2 {
                assert!(
                    poll_and_ack(&provider_inboxes, &p.provider, &p.client, None)
                        .await
                        .is_empty()
                );
            }
            let incremental = (p.conversation.take_counts(), start.elapsed());

            // The same five reads, downloading every body each time.
            let start = Instant::now();
            let everything = p.conversation.all_pending();
            for (side, peer) in [
                (&p.client, &provider),
                (&p.provider, &client),
                (&p.client, &provider),
                (&p.provider, &client),
                (&p.provider, &client),
            ] {
                side.discover(peer, &mut ReceiveState::default())
                    .await
                    .unwrap();
                side.retrieve(peer, &everything).await.unwrap();
            }
            let full = (p.conversation.take_counts(), start.elapsed());

            for (method, (counts, elapsed)) in
                [("incremental", incremental), ("full history", full)]
            {
                table.push(format!(
                    "| {swap} | {history} | {method} | {} | {} | {elapsed:?} |",
                    counts.listings, counts.bodies
                ));
                rows.push((swap, history, method, counts.listings, counts.bodies));
            }
        }
        println!("{}", table.join("\n"));

        for (swap, history, method, listings, bodies) in rows {
            let expected = match method {
                // The request and the reply, however long the conversation has grown.
                "incremental" => (10, 2),
                _ => (10, 5 * (history + 2)),
            };
            assert_eq!((listings, bodies), expected, "swap {swap}, {method}");
        }
    }
}
