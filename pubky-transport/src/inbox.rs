//! Incremental resource delivery with durable pending bodies and explicit acknowledgment.
//!
//! Sender clocks do not decide delivery. Each received resource remains pending until its
//! handler acknowledges it. A dropped receipt releases its lease for another delivery.

use crate::{journal::Journal, Inbound, Receipt, Result, TransportError};
use pkarr::PublicKey;
use pubky_messenger::{
    Discovery, MessageId, PendingMessage, PrivateMessengerClient, ReceiveState, ReceivedMessages,
};
use serde::de::DeserializeOwned;
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::Mutex as AsyncMutex;

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
            .map_err(|_| TransportError::Messenger("message discovery failed".into()))
    }
    async fn retrieve(
        &self,
        peer: &PublicKey,
        pending: &[PendingMessage],
    ) -> Result<ReceivedMessages> {
        self.retrieve_messages(peer, pending)
            .await
            .map_err(|_| TransportError::Messenger("message retrieval failed".into()))
    }
}

#[derive(Default)]
pub(crate) struct Inboxes {
    journal: Arc<Mutex<Journal>>,
    leases: Arc<Mutex<HashMap<MessageId, u64>>>,
    next_lease: AtomicU64,
    // Network work for one peer is serialized. Slots are removed on eviction when unused.
    polls: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl Inboxes {
    pub fn open(path: &Path, owner: &str) -> Result<Self> {
        Ok(Self {
            journal: Arc::new(Mutex::new(Journal::open(path, owner)?)),
            ..Self::default()
        })
    }

    pub fn registered(&self) -> Vec<(String, bool)> {
        self.journal.lock().unwrap().registered()
    }
    pub fn register(&self, peer: &str, pinned: bool) -> Result<()> {
        self.journal.lock().unwrap().register(peer, pinned)
    }
    pub fn has_pending(&self, peer: &str) -> bool {
        !self.journal.lock().unwrap().record(peer).pending.is_empty()
    }
    pub fn evict(&self, peer: &str) -> Result<bool> {
        let mut polls = self.polls.lock().unwrap();
        if polls
            .get(peer)
            .is_some_and(|slot| Arc::strong_count(slot) > 1)
        {
            return Ok(false);
        }
        let removed = self.journal.lock().unwrap().unregister(peer)?;
        if removed {
            polls.remove(peer);
        }
        Ok(removed)
    }

    pub fn acknowledge(&self, receipt: &Receipt) -> Result<()> {
        receipt.acknowledge()
    }
    pub fn release(&self, receipt: &Receipt) {
        let mut leases = self.leases.lock().unwrap();
        if leases.get(&receipt.id) == Some(&receipt.lease) {
            leases.remove(&receipt.id);
        }
    }

    pub async fn poll<B: Mailbox, M: DeserializeOwned>(
        &self,
        mailbox: &B,
        peer: &PublicKey,
    ) -> Result<Vec<Inbound<M>>> {
        self.read(mailbox, peer, false).await
    }

    pub async fn poll_registered<B: Mailbox, M: DeserializeOwned>(
        &self,
        mailbox: &B,
        peer: &PublicKey,
    ) -> Result<Vec<Inbound<M>>> {
        self.read(mailbox, peer, true).await
    }

    async fn read<B: Mailbox, M: DeserializeOwned>(
        &self,
        mailbox: &B,
        peer: &PublicKey,
        require_registered: bool,
    ) -> Result<Vec<Inbound<M>>> {
        self.journal
            .lock()
            .unwrap()
            .check_owner(&mailbox.own_pubky())?;
        let name = peer.to_string();
        let slot = {
            let mut polls = self.polls.lock().unwrap();
            // Registration and eviction use this same lock boundary. A stale scheduler fetch
            // cannot revive a peer removed before its read started.
            if require_registered && !self.journal.lock().unwrap().record(&name).registered {
                return Ok(Vec::new());
            }
            polls.entry(name.clone()).or_default().clone()
        };
        let _poll = slot.lock().await;
        // Resume durable work even if its publisher is offline or has deleted the resource.
        let held = self.deliver(&name)?;
        if !held.is_empty() {
            return Ok(held);
        }
        let (mut state, available) = {
            let journal = self.journal.lock().unwrap();
            let record = journal.record(&name);
            let mut state = record.acknowledged;
            for pending in &record.pending {
                state.acknowledge(pending);
            }
            (state, journal.available(&name))
        };
        if available == 0 {
            return Ok(Vec::new());
        }
        let discovered = mailbox.discover(peer, &mut state).await?;
        let mut selected = Vec::new();
        for pending in discovered.pending {
            if pending.id.publisher == name {
                selected.push(pending);
            }
            if selected.len() >= available {
                break;
            }
        }
        let listing_failed = !discovered.failures.is_empty();
        if selected.is_empty() && listing_failed {
            return Err(TransportError::Messenger(
                "conversation listing incomplete".into(),
            ));
        }
        if !selected.is_empty() {
            let received = mailbox.retrieve(peer, &selected).await?;
            let failed = !received.failures.is_empty();
            self.journal
                .lock()
                .unwrap()
                .remember(&name, received.messages)?;
            let delivered = self.deliver(&name)?;
            if delivered.is_empty() && (failed || listing_failed) {
                return Err(TransportError::Messenger(
                    "conversation retrieval incomplete".into(),
                ));
            }
            return Ok(delivered);
        }
        Ok(Vec::new())
    }

    fn deliver<M: DeserializeOwned>(&self, peer: &str) -> Result<Vec<Inbound<M>>> {
        let mut journal = self.journal.lock().unwrap();
        journal.ensure_healthy()?;
        let pending = journal.record(peer).pending;
        let mut delivered = Vec::new();
        for resource in pending {
            if self.leases.lock().unwrap().contains_key(&resource.id) {
                continue;
            }
            let Some(body) = resource.message else {
                continue;
            };
            // Only authenticated messages from this peer and its own resource directory
            // reach protocol decoding. Rejected resources are recorded before being skipped.
            if !body.verified || body.sender != peer || resource.id.publisher != peer {
                journal.acknowledge(peer, &[resource.id])?;
                continue;
            }
            let message = match serde_json::from_str(&body.content) {
                Ok(message) => message,
                Err(_) => {
                    // Invalid protocol data is a deterministic terminal outcome, saved first.
                    journal.acknowledge(peer, &[resource.id])?;
                    continue;
                }
            };
            let lease = self.next_lease.fetch_add(1, Ordering::Relaxed);
            self.leases
                .lock()
                .unwrap()
                .insert(resource.id.clone(), lease);
            delivered.push(Inbound {
                peer: peer.to_string(),
                message,
                receipt: Receipt {
                    peer: peer.to_string(),
                    id: resource.id,
                    lease,
                    journal: self.journal.clone(),
                    leases: self.leases.clone(),
                },
            });
        }
        Ok(delivered)
    }

    #[cfg(test)]
    pub(super) async fn acknowledge_listed<B: Mailbox>(
        &self,
        mailbox: &B,
        peer: &PublicKey,
    ) -> Result<usize> {
        self.journal
            .lock()
            .unwrap()
            .check_owner(&mailbox.own_pubky())?;
        let name = peer.to_string();
        let mut state = self.journal.lock().unwrap().record(&name).acknowledged;
        let discovered = mailbox.discover(peer, &mut state).await?;
        if !discovered.failures.is_empty() {
            return Err(TransportError::Messenger(
                "conversation listing incomplete".into(),
            ));
        }
        let ids: Vec<_> = discovered.pending.into_iter().map(|p| p.id).collect();
        self.journal.lock().unwrap().acknowledge(&name, &ids)?;
        Ok(ids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_messenger::{DecryptedMessage, ReceivedMessage};
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicUsize},
    };

    #[derive(Default)]
    struct Mail {
        messages: Mutex<Vec<ReceivedMessage>>,
        offline: AtomicBool,
        bodies: AtomicUsize,
    }
    impl Mail {
        fn add(&self, peer: &PublicKey, name: usize, timestamp: u64, content: &str) {
            self.messages.lock().unwrap().push(ReceivedMessage {
                id: MessageId {
                    publisher: peer.to_string(),
                    url: format!("pubky://{peer}/{name}.json"),
                },
                message: Some(DecryptedMessage {
                    sender: peer.to_string(),
                    timestamp,
                    content: content.into(),
                    verified: true,
                }),
                etag: None,
                updated: false,
            });
        }
    }
    impl Mailbox for Mail {
        fn own_pubky(&self) -> String {
            owner()
        }
        async fn discover(&self, peer: &PublicKey, state: &mut ReceiveState) -> Result<Discovery> {
            if self.offline.load(Ordering::Relaxed) {
                return Err(TransportError::Messenger("offline".into()));
            }
            Ok(Discovery {
                pending: self
                    .messages
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|m| m.id.publisher == peer.to_string() && !state.is_acknowledged(&m.id))
                    .map(|m| PendingMessage {
                        id: m.id.clone(),
                        acknowledged_etag: None,
                    })
                    .collect(),
                failures: vec![],
            })
        }
        async fn retrieve(
            &self,
            _: &PublicKey,
            pending: &[PendingMessage],
        ) -> Result<ReceivedMessages> {
            self.bodies.fetch_add(pending.len(), Ordering::Relaxed);
            Ok(ReceivedMessages {
                messages: self
                    .messages
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|m| pending.iter().any(|p| p.id == m.id))
                    .cloned()
                    .collect(),
                failures: vec![],
            })
        }
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "swap-inbox-{}",
                pkarr::Keypair::random().public_key()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn journal(&self) -> PathBuf {
            self.0.join("receive.json")
        }
        fn block_writes(&self) {
            fs::rename(self.journal(), self.0.join("receive.saved")).unwrap();
            fs::create_dir(self.journal()).unwrap();
        }
        fn allow_writes(&self) {
            fs::remove_dir(self.journal()).unwrap();
            fs::rename(self.0.join("receive.saved"), self.journal()).unwrap();
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn peer() -> PublicKey {
        pkarr::Keypair::random().public_key()
    }

    fn owner() -> String {
        pkarr::Keypair::from_secret_key(&[42; 32])
            .public_key()
            .to_string()
    }

    #[test]
    fn a_journal_has_one_live_owner_and_rejects_another_identity() {
        let dir = Directory::new();
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        assert!(Inboxes::open(&dir.journal(), &owner()).is_err());
        drop(inbox);
        assert!(Inboxes::open(&dir.journal(), &peer().to_string()).is_err());
        assert!(Inboxes::open(&dir.journal(), &owner()).is_ok());
    }

    #[tokio::test]
    async fn pending_body_and_peer_survive_restart_and_publisher_deletion() {
        let dir = Directory::new();
        let peer = peer();
        let mail = Mail::default();
        // Sender timestamps are neither receive cursors nor recovery deadlines.
        mail.add(&peer, 1, 1, "7");
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        inbox.register(&peer.to_string(), false).unwrap();
        let first = inbox.poll::<_, u32>(&mail, &peer).await.unwrap();
        assert_eq!(first[0].message, 7);
        drop(first);
        drop(inbox);
        mail.messages.lock().unwrap().clear();
        mail.offline.store(true, Ordering::Relaxed);
        let restored = Inboxes::open(&dir.journal(), &owner()).unwrap();
        assert_eq!(restored.registered(), vec![(peer.to_string(), false)]);
        let repeated = restored.poll::<_, u32>(&mail, &peer).await.unwrap();
        assert_eq!(repeated[0].message, 7);
        repeated[0].receipt.acknowledge().unwrap();
        drop(repeated);
        drop(restored);
        let restored = Inboxes::open(&dir.journal(), &owner()).unwrap();
        assert!(!restored.has_pending(&peer.to_string()));
    }

    #[tokio::test]
    async fn registration_before_first_read_survives_restart() {
        let dir = Directory::new();
        let peer = peer();
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        inbox.register(&peer.to_string(), false).unwrap();
        drop(inbox);
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        let mail = Mail::default();
        mail.add(&peer, 1, 0, "1");
        assert_eq!(inbox.registered(), vec![(peer.to_string(), false)]);
        assert_eq!(
            inbox.poll::<_, u32>(&mail, &peer).await.unwrap()[0].message,
            1
        );
    }

    #[tokio::test]
    async fn equal_payloads_are_distinct_resources_and_acknowledged_bodies_stay_unread() {
        let dir = Directory::new();
        let peer = peer();
        let mail = Mail::default();
        mail.add(&peer, 1, u64::MAX, "1");
        mail.add(&peer, 2, u64::MAX, "1");
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        let messages = inbox.poll::<_, u32>(&mail, &peer).await.unwrap();
        assert_eq!(messages.len(), 2);
        for inbound in messages {
            inbound.receipt.acknowledge().unwrap();
        }
        drop(inbox);
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().is_empty());
        assert_eq!(mail.bodies.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn failed_pending_save_never_exposes_a_delivery() {
        let dir = Directory::new();
        let peer = peer();
        let mail = Mail::default();
        mail.add(&peer, 1, 1, "1");
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        dir.block_writes();
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.is_err());
        assert!(!inbox.has_pending(&peer.to_string()));
        dir.allow_writes();
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.is_err());
        drop(inbox);
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        assert_eq!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failed_acknowledgment_remains_pending_across_restart() {
        let dir = Directory::new();
        let peer = peer();
        let mail = Mail::default();
        mail.add(&peer, 1, 1, "1");
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        let messages = inbox.poll::<_, u32>(&mail, &peer).await.unwrap();
        dir.block_writes();
        assert!(messages[0].receipt.acknowledge().is_err());
        dir.allow_writes();
        assert!(messages[0].receipt.acknowledge().is_err());
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.is_err());
        drop(messages);
        drop(inbox);
        let inbox = Inboxes::open(&dir.journal(), &owner()).unwrap();
        assert_eq!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn lease_drop_and_release_return_pending_work_without_downloads() {
        let peer = peer();
        let mail = Mail::default();
        mail.add(&peer, 1, 1, "1");
        let inbox = Inboxes::default();
        let first = inbox.poll::<_, u32>(&mail, &peer).await.unwrap();
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().is_empty());
        inbox.release(&first[0].receipt);
        let second = inbox.poll::<_, u32>(&mail, &peer).await.unwrap();
        drop(first);
        // Releasing or dropping an earlier lease cannot release a newer delivery of the same ID.
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().is_empty());
        drop(second);
        assert_eq!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().len(), 1);
        assert_eq!(mail.bodies.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn per_peer_capacity_defers_work_until_handlers_finish() {
        let peer = peer();
        let mail = Mail::default();
        for id in 0..100 {
            mail.add(&peer, id, 1, &id.to_string());
        }
        let inbox = Inboxes::default();
        let first = inbox.poll::<_, u32>(&mail, &peer).await.unwrap();
        assert_eq!(first.len(), crate::journal::MAX_PENDING_PER_PEER);
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().is_empty());
        let mut seen = std::collections::HashSet::new();
        for inbound in first {
            seen.insert(inbound.message);
            inbound.receipt.acknowledge().unwrap();
        }
        while seen.len() < 100 {
            for inbound in inbox.poll::<_, u32>(&mail, &peer).await.unwrap() {
                assert!(seen.insert(inbound.message));
                inbound.receipt.acknowledge().unwrap();
            }
        }
        assert_eq!(mail.bodies.load(Ordering::Relaxed), 100);
    }

    #[tokio::test]
    async fn global_capacity_never_evicts_pending_work() {
        let mail = Mail::default();
        let inbox = Inboxes::default();
        let mut held = Vec::new();
        for _ in 0..32 {
            let peer = peer();
            for id in 0..32 {
                mail.add(&peer, id, 1, "1");
            }
            held.extend(inbox.poll::<_, u32>(&mail, &peer).await.unwrap());
        }
        assert_eq!(held.len(), crate::journal::MAX_PENDING);
        let waiting = peer();
        mail.add(&waiting, 1, 1, "2");
        assert!(inbox
            .poll::<_, u32>(&mail, &waiting)
            .await
            .unwrap()
            .is_empty());
        held.pop().unwrap().receipt.acknowledge().unwrap();
        assert_eq!(
            inbox.poll::<_, u32>(&mail, &waiting).await.unwrap()[0].message,
            2
        );
        assert_eq!(held.len(), crate::journal::MAX_PENDING - 1);
    }

    #[tokio::test]
    async fn acknowledged_history_beyond_old_dedup_limit_is_not_replayed() {
        let peer = peer();
        let mail = Mail::default();
        for id in 0..10050 {
            mail.add(&peer, id, 1, "1");
        }
        let inbox = Inboxes::default();
        // Save a history checkpoint in one transaction, as a migrated completed conversation.
        let ids: Vec<_> = mail
            .messages
            .lock()
            .unwrap()
            .iter()
            .map(|m| m.id.clone())
            .collect();
        inbox
            .journal
            .lock()
            .unwrap()
            .acknowledge(&peer.to_string(), &ids)
            .unwrap();
        assert!(inbox.poll::<_, u32>(&mail, &peer).await.unwrap().is_empty());
        assert_eq!(mail.bodies.load(Ordering::Relaxed), 0);
        mail.add(&peer, 10051, 0, "2");
        assert_eq!(
            inbox.poll::<_, u32>(&mail, &peer).await.unwrap()[0].message,
            2
        );
    }

    #[tokio::test]
    async fn a_stale_scheduled_read_does_not_revive_an_evicted_peer() {
        let peer = peer();
        let mail = Mail::default();
        mail.add(&peer, 1, 0, "1");
        let inbox = Inboxes::default();
        inbox.register(&peer.to_string(), false).unwrap();
        assert!(inbox.evict(&peer.to_string()).unwrap());
        assert!(inbox
            .poll_registered::<_, u32>(&mail, &peer)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(mail.bodies.load(Ordering::Relaxed), 0);
        assert!(inbox.registered().is_empty());
    }
}
