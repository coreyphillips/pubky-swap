//! Durable encrypted publication and explicitly scheduled, resource-scoped cleanup.

use crate::{Result, TransportError};
use fs2::FileExt;
use pubky_messenger::{FailureReason, PreparedMessage};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const VERSION: u8 = 1;
const MAX_ENTRIES: usize = 1024;
const MAX_EPHEMERAL_ENTRIES: usize = 768;
const MAX_BATCH: usize = 64;
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PAYLOAD: usize = 128 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Sanitized cause of a publication or cleanup failure. No URL, payload or credential is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryFailure {
    #[error("temporary HTTP status {0}")]
    TemporaryHttp(u16),
    #[error("message storage is unavailable")]
    TransportUnavailable,
    #[error("message storage request timed out")]
    TimedOut,
    #[error("authentication requires attention (HTTP {0})")]
    Authentication(u16),
    #[error("permanent HTTP status {0}")]
    PermanentHttp(u16),
    #[error("invalid message storage request or response")]
    InvalidRequest,
}

impl DeliveryFailure {
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::TemporaryHttp(_) | Self::TransportUnavailable | Self::TimedOut
        )
    }

    pub(crate) fn from_reason(reason: &FailureReason) -> Self {
        match reason {
            FailureReason::Status(status) | FailureReason::Authentication(status)
                if matches!(status, 408 | 429 | 500..=599) =>
            {
                Self::TemporaryHttp(*status)
            }
            FailureReason::Authentication(status) => Self::Authentication(*status),
            FailureReason::Status(status @ (401 | 403)) => Self::Authentication(*status),
            FailureReason::Status(status) => Self::PermanentHttp(*status),
            FailureReason::TimedOut => Self::TimedOut,
            FailureReason::Transport(_) => Self::TransportUnavailable,
            FailureReason::ListingStalled
            | FailureReason::ListingTooLong
            | FailureReason::OutsideConversation => Self::InvalidRequest,
        }
    }
}

/// The independently scheduled operation whose state is being inspected or resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOperation {
    #[error("publication")]
    Publication,
    #[error("cleanup")]
    Cleanup,
}

/// One durable resource's delivery state, without its encrypted or decrypted body.
/// Last failures are historical; the pause flags describe whether attention is required now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxStatus {
    pub id: String,
    pub peer: String,
    pub scope: String,
    pub published: bool,
    pub attempts: u32,
    pub next_retry_at: u64,
    pub publication_failure: Option<DeliveryFailure>,
    pub publication_paused: bool,
    pub cleanup_after: Option<u64>,
    pub cleanup_attempts: u32,
    pub next_cleanup_at: u64,
    pub cleanup_failure: Option<DeliveryFailure>,
    pub cleanup_paused: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    owner: Option<String>,
    entries: Vec<Entry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    peer: String,
    scope: String,
    content_digest: [u8; 32],
    prepared: PreparedMessage,
    published: bool,
    attempts: u32,
    next_retry_at: u64,
    cleanup_after: Option<u64>,
    cleanup_attempts: u32,
    next_cleanup_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication_failure: Option<DeliveryFailure>,
    #[serde(default, skip_serializing_if = "is_false")]
    publication_paused: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleanup_failure: Option<DeliveryFailure>,
    #[serde(default, skip_serializing_if = "is_false")]
    cleanup_paused: bool,
}

struct State {
    journal: Journal,
    write_failed: bool,
}

/// Owns one journal. Network calls run after methods return and never hold its lock.
///
/// Publication success means storage succeeded, not that the peer consumed the message.
/// The application retains replay protection and recovery state separately from this journal.
pub struct Outbox {
    path: PathBuf,
    state: Mutex<State>,
    _file_lock: File,
}

impl Outbox {
    /// Open or create an exclusive journal. Corrupt, unsupported and permissive files fail closed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = parent(&path)?;
        let mut directories = fs::DirBuilder::new();
        directories.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directories.mode(0o700);
        }
        directories.create(parent)?;
        let lock_path = path.with_extension("outbox-lock");
        check_file(&lock_path)?;
        let file_lock = private_options().create(true).open(lock_path)?;
        FileExt::try_lock_exclusive(&file_lock)?;
        let journal = match read_journal(&path)? {
            Some(journal) => journal,
            None => {
                let journal = Journal {
                    version: VERSION,
                    ..Journal::default()
                };
                persist(&path, &journal)?;
                journal
            }
        };
        validate(&journal)?;
        Ok(Self {
            path,
            state: Mutex::new(State {
                journal,
                write_failed: false,
            }),
            _file_lock: file_lock,
        })
    }

    /// Reject a journal belonging to another active messenger identity before publication or deletion.
    pub fn check_owner(&self, owner: &str) -> Result<()> {
        canonical_peer(owner)?;
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart the transport to recover",
            ));
        }
        if state
            .journal
            .owner
            .as_deref()
            .is_some_and(|saved| saved != owner)
        {
            return Err(invalid(
                "saved message delivery state belongs to another identity",
            ));
        }
        Ok(())
    }

    /// Whether a scope has owned resources, including prepared publications not yet sent.
    pub fn has_scope(&self, peer: &str, scope: &str) -> Result<bool> {
        validate_scope(peer, scope)?;
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart to recover",
            ));
        }
        Ok(state
            .journal
            .entries
            .iter()
            .any(|entry| entry.peer == peer && entry.scope == scope))
    }

    /// Reserve encrypted bytes before I/O. Repeated peer, scope and content reuse the saved resource.
    ///
    /// The preparation closure must perform no network I/O. It runs only for a new reservation.
    pub fn prepare<F, E>(
        &self,
        peer: &str,
        scope: &str,
        content: &str,
        prepare: F,
    ) -> Result<PreparedMessage>
    where
        F: FnOnce() -> std::result::Result<PreparedMessage, E>,
        E: std::fmt::Display,
    {
        self.prepare_with_expiry(peer, scope, content, None, prepare)
    }

    /// Reserve bytes and optional cleanup eligibility in one durable write.
    /// Identical reservations fill a missing deadline but never extend an existing one.
    pub fn prepare_with_expiry<F, E>(
        &self,
        peer: &str,
        scope: &str,
        content: &str,
        eligible_after: Option<u64>,
        prepare: F,
    ) -> Result<PreparedMessage>
    where
        F: FnOnce() -> std::result::Result<PreparedMessage, E>,
        E: std::fmt::Display,
    {
        validate_scope(peer, scope)?;
        let digest = *blake3::hash(content.as_bytes()).as_bytes();
        self.update(|journal| {
            if let Some(entry) = journal.entries.iter_mut().find(|entry| {
                entry.peer == peer && entry.scope == scope && entry.content_digest == digest
            }) {
                let changed = entry.cleanup_after.is_none() && eligible_after.is_some();
                if changed {
                    entry.cleanup_after = eligible_after;
                }
                return Ok((entry.prepared.clone(), changed));
            }
            if scope.starts_with("ephemeral:")
                && journal
                    .entries
                    .iter()
                    .filter(|entry| entry.scope.starts_with("ephemeral:"))
                    .count()
                    >= MAX_EPHEMERAL_ENTRIES
            {
                return Err(invalid("read-only delivery capacity reached; retry later"));
            }
            if journal.entries.len() >= MAX_ENTRIES {
                return Err(invalid("outbox is full; pending work was retained"));
            }
            if journal.entries.iter().any(|entry| {
                entry.peer == peer && entry.scope == scope && entry.cleanup_after.is_some()
            }) {
                return Err(invalid("outbox scope has already completed"));
            }
            let prepared = prepare().map_err(|_| invalid("message preparation failed"))?;
            if prepared.recipient() != peer {
                return Err(invalid(
                    "prepared message recipient does not match outbox peer",
                ));
            }
            if journal
                .owner
                .as_deref()
                .is_some_and(|owner| owner != prepared.owner())
            {
                return Err(invalid("prepared message belongs to another outbox owner"));
            }
            journal.owner = Some(prepared.owner().to_owned());
            journal.entries.push(Entry {
                peer: peer.to_owned(),
                scope: scope.to_owned(),
                content_digest: digest,
                prepared: prepared.clone(),
                published: false,
                attempts: 0,
                next_retry_at: 0,
                cleanup_after: eligible_after,
                cleanup_attempts: 0,
                next_cleanup_at: 0,
                publication_failure: None,
                publication_paused: false,
                cleanup_failure: None,
                cleanup_paused: false,
            });
            validate(journal)?;
            // Leave room for timestamps and counters in later recovery/cleanup updates.
            if serde_json::to_vec(journal)?.len() as u64 + journal.entries.len() as u64 * 512
                > MAX_BYTES
            {
                return Err(invalid(
                    "outbox byte capacity reached; pending work was retained",
                ));
            }
            Ok((prepared, true))
        })
    }

    /// Persist storage success. A later concurrent failure cannot reverse this state.
    pub fn mark_published(&self, id: &str) -> Result<()> {
        self.update(|journal| {
            let entry = find_entry(journal, id)?;
            let changed = !entry.published || entry.publication_paused;
            entry.published = true;
            entry.publication_paused = false;
            Ok(((), changed))
        })
    }

    /// Recheck under the caller's per-resource network lock before starting publication.
    /// A removed resource or one whose cleanup deadline arrived must not be published again.
    pub fn can_publish(&self, id: &str, now: u64) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart the transport to recover",
            ));
        }
        let Some(entry) = state
            .journal
            .entries
            .iter()
            .find(|entry| entry.prepared.id() == id)
        else {
            return Ok(false);
        };
        if entry.publication_paused {
            return Err(TransportError::Delivery {
                operation: DeliveryOperation::Publication,
                failure: entry
                    .publication_failure
                    .unwrap_or(DeliveryFailure::InvalidRequest),
            });
        }
        Ok(!cleanup_due(entry, now))
    }

    /// Persist the last failure. Only temporary failures are retried automatically.
    /// A later failure never reverses an already confirmed publication.
    pub fn mark_failed(&self, id: &str, now: u64, failure: DeliveryFailure) -> Result<()> {
        self.update(|journal| {
            let entry = find_entry(journal, id)?;
            if cleanup_due(entry, now) {
                return Ok(((), false));
            }
            let mut changed = entry.publication_failure != Some(failure)
                || entry.publication_paused == failure.is_retryable();
            entry.publication_failure = Some(failure);
            entry.publication_paused = !failure.is_retryable();
            if !entry.published && entry.next_retry_at <= now {
                retry(&mut entry.attempts, &mut entry.next_retry_at, now);
                changed = true;
            }
            Ok(((), changed))
        })
    }

    /// Return at most 64 pending resources whose durable retry time has arrived.
    pub fn due_pending(&self, now: u64, limit: usize) -> Result<Vec<PreparedMessage>> {
        self.select(
            limit,
            |entry| {
                !entry.published
                    && !entry.publication_paused
                    && entry.next_retry_at <= now
                    && !cleanup_due(entry, now)
            },
            |entry| entry.next_retry_at,
        )
    }

    /// Schedule existing resources after the application durably records terminal completion.
    /// The first retention deadline is retained on repeated calls, and no peer-wide delete occurs.
    pub fn complete_scope(&self, peer: &str, scope: &str, eligible_after: u64) -> Result<()> {
        validate_scope(peer, scope)?;
        self.update(|journal| {
            let mut changed = false;
            for entry in &mut journal.entries {
                if entry.peer == peer && entry.scope == scope && entry.cleanup_after.is_none() {
                    entry.cleanup_after = Some(eligible_after);
                    changed = true;
                }
            }
            Ok(((), changed))
        })
    }

    /// Cancel deferred deletion and schedule exact-byte repair after a swap reopens.
    /// A deletion already in flight may still succeed, so publication must be retried durably.
    pub fn reopen_scope(&self, peer: &str, scope: &str) -> Result<()> {
        validate_scope(peer, scope)?;
        self.update(|journal| {
            let mut changed = false;
            for entry in &mut journal.entries {
                if entry.peer == peer && entry.scope == scope && entry.cleanup_after.is_some() {
                    entry.cleanup_after = None;
                    entry.cleanup_attempts = 0;
                    entry.next_cleanup_at = 0;
                    entry.published = false;
                    entry.attempts = 0;
                    entry.next_retry_at = 0;
                    changed = true;
                }
            }
            Ok(((), changed))
        })
    }

    /// Return exact owned resources eligible for deletion, including ambiguous publications.
    pub fn eligible_cleanup(&self, now: u64, limit: usize) -> Result<Vec<PreparedMessage>> {
        self.select(
            limit,
            |entry| {
                cleanup_due(entry, now) && !entry.cleanup_paused && entry.next_cleanup_at <= now
            },
            |entry| {
                entry
                    .next_cleanup_at
                    .max(entry.cleanup_after.unwrap_or(u64::MAX))
            },
        )
    }

    /// Recheck a queued deletion after obtaining its network operation lock.
    pub fn can_cleanup(&self, id: &str, now: u64) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart to recover",
            ));
        }
        Ok(state.journal.entries.iter().any(|entry| {
            entry.prepared.id() == id
                && cleanup_due(entry, now)
                && !entry.cleanup_paused
                && entry.next_cleanup_at <= now
        }))
    }

    /// Persist a cleanup failure independently of publication state and its retry schedule.
    pub fn mark_cleanup_failed(&self, id: &str, now: u64, failure: DeliveryFailure) -> Result<()> {
        self.update(|journal| {
            let entry = find_entry(journal, id)?;
            if !cleanup_due(entry, now) {
                return Ok(((), false));
            }
            let mut changed = entry.cleanup_failure != Some(failure)
                || entry.cleanup_paused == failure.is_retryable();
            entry.cleanup_failure = Some(failure);
            entry.cleanup_paused = !failure.is_retryable();
            if entry.next_cleanup_at <= now {
                retry(&mut entry.cleanup_attempts, &mut entry.next_cleanup_at, now);
                changed = true;
            }
            Ok(((), changed))
        })
    }

    /// Inspect bounded durable state. Failure details never include URLs or message bodies.
    pub fn status(&self) -> Result<Vec<OutboxStatus>> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart to recover",
            ));
        }
        Ok(state
            .journal
            .entries
            .iter()
            .map(|entry| OutboxStatus {
                id: entry.prepared.id().to_owned(),
                peer: entry.peer.clone(),
                scope: entry.scope.clone(),
                published: entry.published,
                attempts: entry.attempts,
                next_retry_at: entry.next_retry_at,
                publication_failure: entry.publication_failure,
                publication_paused: entry.publication_paused,
                cleanup_after: entry.cleanup_after,
                cleanup_attempts: entry.cleanup_attempts,
                next_cleanup_at: entry.next_cleanup_at,
                cleanup_failure: entry.cleanup_failure,
                cleanup_paused: entry.cleanup_paused,
            })
            .collect())
    }

    /// Deliberately resume one operation after addressing its failure. Performs no network I/O.
    /// Retains exact bytes, completion eligibility, attempt history and the last failure category.
    pub fn retry(&self, id: &str, operation: DeliveryOperation, now: u64) -> Result<()> {
        self.update(|journal| {
            let entry = find_entry(journal, id)?;
            match operation {
                DeliveryOperation::Publication => {
                    if cleanup_due(entry, now) {
                        return Err(invalid(
                            "cannot retry a publication after cleanup eligibility",
                        ));
                    }
                    entry.publication_paused = false;
                    entry.published = false;
                    entry.next_retry_at = now;
                }
                DeliveryOperation::Cleanup => {
                    if entry.cleanup_after.is_none() {
                        return Err(invalid("cannot retry cleanup before scope completion"));
                    }
                    entry.cleanup_paused = false;
                    entry.next_cleanup_at = now;
                }
            }
            Ok(((), true))
        })
    }

    /// Forget only eligible IDs whose remote deletion succeeded. Missing IDs are already complete.
    /// Call this with successes from a partial deletion report, never with all attempted IDs.
    pub fn remove_deleted(&self, ids: &[String], now: u64) -> Result<()> {
        let ids: HashSet<&str> = ids.iter().map(String::as_str).collect();
        self.update(|journal| {
            for entry in &journal.entries {
                if ids.contains(entry.prepared.id()) && !cleanup_due(entry, now) {
                    return Err(invalid(
                        "cannot remove an outbox resource before cleanup eligibility",
                    ));
                }
            }
            let previous = journal.entries.len();
            journal
                .entries
                .retain(|entry| !ids.contains(entry.prepared.id()));
            Ok(((), previous != journal.entries.len()))
        })
    }

    fn select(
        &self,
        limit: usize,
        predicate: impl Fn(&Entry) -> bool,
        order: impl Fn(&Entry) -> u64,
    ) -> Result<Vec<PreparedMessage>> {
        let state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart the transport to recover",
            ));
        }
        let mut entries: Vec<_> = state
            .journal
            .entries
            .iter()
            .filter(|entry| predicate(entry))
            .collect();
        entries.sort_by_key(|entry| order(entry));
        Ok(entries
            .into_iter()
            .take(limit.min(MAX_BATCH))
            .map(|entry| entry.prepared.clone())
            .collect())
    }

    fn update<T>(&self, change: impl FnOnce(&mut Journal) -> Result<(T, bool)>) -> Result<T> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("outbox lock poisoned"))?;
        if state.write_failed {
            return Err(invalid(
                "message delivery state could not be saved; restart the transport to recover",
            ));
        }
        let mut candidate = state.journal.clone();
        let (value, changed) = change(&mut candidate)?;
        if changed {
            if let Err(error) = persist(&self.path, &candidate) {
                // A failed directory sync may follow a successful rename. Do not keep using stale state.
                state.write_failed = true;
                return Err(error);
            }
            state.journal = candidate;
        }
        Ok(value)
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

fn invalid(message: &str) -> TransportError {
    TransportError::Messenger(message.to_owned())
}

fn find_entry<'a>(journal: &'a mut Journal, id: &str) -> Result<&'a mut Entry> {
    journal
        .entries
        .iter_mut()
        .find(|entry| entry.prepared.id() == id)
        .ok_or_else(|| invalid("unknown outbox resource"))
}

fn cleanup_due(entry: &Entry, now: u64) -> bool {
    entry.cleanup_after.is_some_and(|deadline| deadline <= now)
}

fn retry(attempts: &mut u32, next: &mut u64, now: u64) {
    *attempts = attempts.saturating_add(1);
    let delay = 1u64
        .checked_shl(attempts.saturating_sub(1))
        .unwrap_or(u64::MAX)
        .min(300);
    *next = now.saturating_add(delay);
}

fn validate_scope(peer: &str, scope: &str) -> Result<()> {
    if scope.is_empty() || scope.len() > 512 || scope.chars().any(char::is_control) {
        return Err(invalid("invalid outbox scope"));
    }
    canonical_peer(peer)
}

fn canonical_peer(peer: &str) -> Result<()> {
    let key = pkarr::PublicKey::try_from(peer).map_err(|_| invalid("invalid outbox identity"))?;
    if key.to_string() != peer {
        return Err(invalid("noncanonical outbox identity"));
    }
    Ok(())
}

fn validate(journal: &Journal) -> Result<()> {
    if journal.version != VERSION || journal.entries.len() > MAX_ENTRIES {
        return Err(invalid("unsupported or oversized outbox journal"));
    }
    if let Some(owner) = &journal.owner {
        canonical_peer(owner)?;
    }
    let mut ids = HashSet::new();
    let mut reservations = HashSet::new();
    for entry in &journal.entries {
        validate_scope(&entry.peer, &entry.scope)?;
        for (paused, failure) in [
            (entry.publication_paused, entry.publication_failure),
            (entry.cleanup_paused, entry.cleanup_failure),
        ] {
            if paused && failure.is_none_or(DeliveryFailure::is_retryable) {
                return Err(invalid("invalid paused outbox failure"));
            }
        }
        let prepared = &entry.prepared;
        prepared
            .validate()
            .map_err(|_| invalid("saved encrypted message authentication failed"))?;
        if prepared.version() != 1
            || prepared.recipient() != entry.peer
            || Some(prepared.owner()) != journal.owner.as_deref()
            || prepared.payload().is_empty()
            || prepared.payload().len() > MAX_PAYLOAD
            || prepared.id().is_empty()
            || prepared.id().len() > 128
            || !prepared
                .id()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !ids.insert(prepared.id())
            || !reservations.insert((&entry.peer, &entry.scope, entry.content_digest))
        {
            return Err(invalid("invalid outbox resource association"));
        }
    }
    Ok(())
}

fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| invalid("outbox path must include its directory"))
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn check_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Err(invalid("outbox path must be a regular file"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(invalid(
                        "outbox files must not be accessible to other users",
                    ));
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_journal(path: &Path) -> Result<Option<Journal>> {
    check_file(path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("outbox journal exceeds byte limit"));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(TransportError::from)
}

fn persist(path: &Path, journal: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec(journal)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("outbox journal exceeds byte limit"));
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("outbox-{}-{sequence}.tmp", std::process::id()));
    let mut file = private_options().create_new(true).open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent(path)?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_messenger::{Keypair, PrivateMessengerClient};

    struct Fixture {
        directory: tempfile::TempDir,
        client: PrivateMessengerClient,
        peer: pkarr::PublicKey,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                directory: tempfile::tempdir().unwrap(),
                client: PrivateMessengerClient::new(Keypair::from_secret_key(&[1; 32])).unwrap(),
                peer: Keypair::from_secret_key(&[2; 32]).public_key(),
            }
        }
        fn path(&self) -> PathBuf {
            self.directory.path().join("outbox.json")
        }
        fn open(&self) -> Outbox {
            Outbox::open(self.path()).unwrap()
        }
        fn reserve(&self, outbox: &Outbox, scope: &str, content: &str) -> PreparedMessage {
            outbox
                .prepare(&self.peer.to_string(), scope, content, || {
                    self.client.prepare_message(&self.peer, content)
                })
                .unwrap()
        }
    }

    #[test]
    fn failure_categories_preserve_retry_policy_without_sensitive_details() {
        use pubky_messenger::{FailureReason as Reason, FetchFailure};
        for status in [408, 429, 500, 503, 599] {
            for reason in [Reason::Status(status), Reason::Authentication(status)] {
                let failure = DeliveryFailure::from_reason(&reason);
                assert_eq!(failure, DeliveryFailure::TemporaryHttp(status));
                assert!(failure.is_retryable());
            }
        }
        for status in [401, 403] {
            assert_eq!(
                DeliveryFailure::from_reason(&Reason::Status(status)),
                DeliveryFailure::Authentication(status)
            );
            assert!(!DeliveryFailure::from_reason(&Reason::Authentication(status)).is_retryable());
        }
        for status in [400, 404, 409, 413] {
            assert_eq!(
                DeliveryFailure::from_reason(&Reason::Status(status)),
                DeliveryFailure::PermanentHttp(status)
            );
        }
        assert!(DeliveryFailure::from_reason(&Reason::TimedOut).is_retryable());
        let fetch = FetchFailure {
            url: "pubky://private-resource".to_owned(),
            attempts: 3,
            reason: Reason::Transport("private-credential".to_owned()),
        };
        assert_eq!(
            crate::storage_failure(&fetch),
            DeliveryFailure::TransportUnavailable
        );
        #[derive(Debug, thiserror::Error)]
        #[error("wrapped storage error")]
        struct Wrapped(#[source] FetchFailure);
        assert_eq!(
            crate::storage_failure(&Wrapped(fetch)),
            DeliveryFailure::TransportUnavailable
        );
        let error = TransportError::Delivery {
            operation: DeliveryOperation::Publication,
            failure: DeliveryFailure::TransportUnavailable,
        };
        assert!(!format!("{error:?}: {error}").contains("private-"));
        assert_eq!(
            crate::storage_failure(&std::io::Error::other("private-credential")),
            DeliveryFailure::InvalidRequest
        );
        for reason in [
            Reason::ListingStalled,
            Reason::ListingTooLong,
            Reason::OutsideConversation,
        ] {
            assert_eq!(
                DeliveryFailure::from_reason(&reason),
                DeliveryFailure::InvalidRequest
            );
        }
    }

    #[test]
    fn permanent_publication_failures_survive_restart_until_deliberately_resumed() {
        for failure in [
            DeliveryFailure::Authentication(401),
            DeliveryFailure::PermanentHttp(413),
            DeliveryFailure::InvalidRequest,
        ] {
            let fixture = Fixture::new();
            let outbox = fixture.open();
            let original = fixture.reserve(&outbox, "swap:funded", "acceptance");
            outbox.mark_failed(original.id(), 100, failure).unwrap();
            drop(outbox);
            let outbox = fixture.open();
            assert!(outbox.due_pending(u64::MAX, 64).unwrap().is_empty());
            assert!(
                matches!(outbox.can_publish(original.id(), 200), Err(TransportError::Delivery { operation: DeliveryOperation::Publication, failure: observed }) if observed == failure)
            );
            let retry = fixture.reserve(&outbox, "swap:funded", "acceptance");
            assert_eq!(retry.id(), original.id());
            assert_eq!(retry.payload(), original.payload());
            assert!(outbox.status().unwrap()[0].publication_paused);
            outbox
                .retry(original.id(), DeliveryOperation::Publication, 200)
                .unwrap();
            drop(outbox);
            let outbox = fixture.open();
            let status = &outbox.status().unwrap()[0];
            assert!(!status.publication_paused);
            assert_eq!(status.publication_failure, Some(failure));
            assert_eq!(status.attempts, 1);
            let resumed = outbox.due_pending(200, 1).unwrap();
            assert_eq!(resumed[0].id(), original.id());
            assert_eq!(resumed[0].payload(), original.payload());
            outbox.mark_published(original.id()).unwrap();
            let status = &outbox.status().unwrap()[0];
            assert!(status.published);
            assert!(!status.publication_paused);
            assert_eq!(status.publication_failure, Some(failure));
        }
    }

    #[test]
    fn temporary_failures_restore_automatic_retry_and_preserve_last_category() {
        for failure in [
            DeliveryFailure::TemporaryHttp(429),
            DeliveryFailure::TemporaryHttp(503),
            DeliveryFailure::TransportUnavailable,
            DeliveryFailure::TimedOut,
        ] {
            let fixture = Fixture::new();
            let outbox = fixture.open();
            let original = fixture.reserve(&outbox, "swap:pending", "request");
            outbox.mark_failed(original.id(), 100, failure).unwrap();
            drop(outbox);
            let outbox = fixture.open();
            let status = &outbox.status().unwrap()[0];
            assert!(!status.publication_paused);
            assert_eq!(status.publication_failure, Some(failure));
            assert!(outbox.due_pending(100, 1).unwrap().is_empty());
            assert_eq!(outbox.due_pending(101, 1).unwrap()[0].id(), original.id());
        }
    }

    #[test]
    fn paused_cleanup_is_independent_and_requires_its_own_explicit_retry() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = fixture.reserve(&outbox, "swap:complete", "acceptance");
        outbox.mark_published(original.id()).unwrap();
        outbox
            .complete_scope(&fixture.peer.to_string(), "swap:complete", 100)
            .unwrap();
        outbox
            .mark_cleanup_failed(original.id(), 100, DeliveryFailure::Authentication(403))
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        let status = &outbox.status().unwrap()[0];
        assert!(status.published);
        assert!(status.cleanup_paused);
        assert!(!status.publication_paused);
        assert_eq!(
            status.cleanup_failure,
            Some(DeliveryFailure::Authentication(403))
        );
        assert!(outbox.eligible_cleanup(u64::MAX, 1).unwrap().is_empty());
        assert!(!outbox.can_cleanup(original.id(), 200).unwrap());
        assert!(outbox
            .retry(original.id(), DeliveryOperation::Publication, 200)
            .is_err());
        outbox
            .retry(original.id(), DeliveryOperation::Cleanup, 200)
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        assert_eq!(
            outbox.eligible_cleanup(200, 1).unwrap()[0].id(),
            original.id()
        );
        outbox
            .mark_cleanup_failed(original.id(), 200, DeliveryFailure::TemporaryHttp(429))
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        let status = &outbox.status().unwrap()[0];
        assert!(status.published);
        assert!(!status.cleanup_paused);
        assert_eq!(status.cleanup_attempts, 2);
        assert_eq!(
            status.cleanup_failure,
            Some(DeliveryFailure::TemporaryHttp(429))
        );
        assert!(outbox.eligible_cleanup(201, 1).unwrap().is_empty());
        assert_eq!(
            outbox.eligible_cleanup(202, 1).unwrap()[0].id(),
            original.id()
        );
    }

    #[test]
    fn a_failed_replay_keeps_confirmed_publication_and_reopening_keeps_pauses() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = fixture.reserve(&outbox, "swap:funded", "acceptance");
        outbox.mark_published(original.id()).unwrap();
        outbox
            .mark_failed(original.id(), 100, DeliveryFailure::Authentication(401))
            .unwrap();
        let status = &outbox.status().unwrap()[0];
        assert!(status.published);
        assert!(status.publication_paused);
        assert_eq!(
            status.publication_failure,
            Some(DeliveryFailure::Authentication(401))
        );
        outbox
            .complete_scope(&fixture.peer.to_string(), "swap:funded", 200)
            .unwrap();
        outbox
            .reopen_scope(&fixture.peer.to_string(), "swap:funded")
            .unwrap();
        assert!(outbox.due_pending(300, 1).unwrap().is_empty());
        outbox
            .retry(original.id(), DeliveryOperation::Publication, 300)
            .unwrap();
        let resumed = outbox.due_pending(300, 1).unwrap();
        assert_eq!(resumed[0].id(), original.id());
        assert_eq!(resumed[0].payload(), original.payload());
    }

    #[test]
    fn version_one_without_failure_fields_keeps_all_existing_delivery_state() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = fixture.reserve(&outbox, "swap:accepted", "acceptance");
        outbox.mark_published(original.id()).unwrap();
        outbox
            .complete_scope(&fixture.peer.to_string(), "swap:accepted", 1000)
            .unwrap();
        drop(outbox);
        let mut saved: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.path()).unwrap()).unwrap();
        let entry = saved["entries"][0].as_object_mut().unwrap();
        for field in [
            "publication_failure",
            "publication_paused",
            "cleanup_failure",
            "cleanup_paused",
        ] {
            entry.remove(field);
        }
        entry.insert("attempts".into(), 7.into());
        entry.insert("next_retry_at".into(), 123.into());
        entry.insert("cleanup_attempts".into(), 3.into());
        entry.insert("next_cleanup_at".into(), 1001.into());
        fs::write(fixture.path(), serde_json::to_vec(&saved).unwrap()).unwrap();
        let outbox = fixture.open();
        let status = &outbox.status().unwrap()[0];
        assert!(status.published);
        assert_eq!((status.attempts, status.next_retry_at), (7, 123));
        assert_eq!((status.cleanup_attempts, status.next_cleanup_at), (3, 1001));
        assert_eq!(status.cleanup_after, Some(1000));
        assert_eq!(status.publication_failure, None);
        assert_eq!(status.cleanup_failure, None);
        assert!(!status.publication_paused && !status.cleanup_paused);
        outbox
            .mark_cleanup_failed(original.id(), 1001, DeliveryFailure::PermanentHttp(405))
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        let restored = fixture.reserve(&outbox, "swap:accepted", "acceptance");
        assert_eq!(restored.id(), original.id());
        assert_eq!(restored.payload(), original.payload());
        let status = &outbox.status().unwrap()[0];
        assert_eq!((status.attempts, status.next_retry_at), (7, 123));
        assert!(status.published && status.cleanup_paused);
        assert_eq!(
            status.cleanup_failure,
            Some(DeliveryFailure::PermanentHttp(405))
        );
    }

    #[tokio::test]
    async fn paused_transport_work_and_direct_replays_make_no_storage_requests() {
        let directory = tempfile::tempdir().unwrap();
        let peer = Keypair::from_secret_key(&[9; 32]).public_key().to_string();
        let transport = crate::Transport::unsigned([8; 32])
            .unwrap()
            .with_outbox(directory.path().join("outbox.json"))
            .unwrap();
        transport
            .enqueue_with_scope(&peer, "swap:funded", &7_u32)
            .unwrap();
        transport
            .enqueue_with_scope(&peer, "swap:complete", &8_u32)
            .unwrap();
        let outbox = transport.outbox.as_ref().unwrap();
        let entries = outbox.status().unwrap();
        outbox
            .mark_failed(&entries[0].id, 100, DeliveryFailure::PermanentHttp(413))
            .unwrap();
        outbox.complete_scope(&peer, "swap:complete", 100).unwrap();
        outbox
            .mark_cleanup_failed(&entries[1].id, 100, DeliveryFailure::Authentication(401))
            .unwrap();
        transport.process_outbox(200, 64).await.unwrap();
        assert!(matches!(
            transport
                .send_with_scope(&peer, "swap:funded", &7_u32)
                .await,
            Err(TransportError::Delivery {
                operation: DeliveryOperation::Publication,
                failure: DeliveryFailure::PermanentHttp(413)
            })
        ));
        assert_eq!(transport.homeserver_requests(), 0);
        assert_eq!(transport.outbox_status().unwrap().len(), 2);
        transport
            .retry_outbox(&entries[0].id, DeliveryOperation::Publication)
            .unwrap();
        assert!(!transport.outbox_status().unwrap()[0].publication_paused);
        assert!(transport.outbox_status().unwrap()[1].cleanup_paused);
    }

    #[test]
    fn ephemeral_reservation_persists_its_first_expiry_with_the_resource() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = outbox
            .prepare_with_expiry(
                &fixture.peer.to_string(),
                "ephemeral:quote",
                "quote",
                Some(100),
                || fixture.client.prepare_message(&fixture.peer, "quote"),
            )
            .unwrap();
        drop(outbox);

        let outbox = fixture.open();
        assert!(outbox.eligible_cleanup(99, 10).unwrap().is_empty());
        assert_eq!(
            outbox.eligible_cleanup(100, 10).unwrap()[0].id(),
            original.id()
        );
        let retry = outbox
            .prepare_with_expiry(
                &fixture.peer.to_string(),
                "ephemeral:quote",
                "quote",
                Some(200),
                || -> Result<PreparedMessage> { panic!("retry must retain the resource") },
            )
            .unwrap();
        assert_eq!(retry.id(), original.id());
        assert_eq!(retry.payload(), original.payload());
        drop(outbox);

        let outbox = fixture.open();
        assert_eq!(
            outbox.eligible_cleanup(100, 10).unwrap()[0].id(),
            original.id()
        );
        assert!(outbox.due_pending(100, 10).unwrap().is_empty());
    }

    #[test]
    fn retry_atomically_fills_a_missing_expiry_without_replacing_the_resource() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = fixture.reserve(&outbox, "ephemeral:quote", "quote");
        assert!(outbox.eligible_cleanup(100, 10).unwrap().is_empty());
        let retry = outbox
            .prepare_with_expiry(
                &fixture.peer.to_string(),
                "ephemeral:quote",
                "quote",
                Some(100),
                || -> Result<PreparedMessage> { panic!("existing bytes must be preserved") },
            )
            .unwrap();
        assert_eq!(retry.id(), original.id());
        assert_eq!(retry.payload(), original.payload());
        drop(outbox);

        let outbox = fixture.open();
        assert_eq!(
            outbox.eligible_cleanup(100, 10).unwrap()[0].id(),
            original.id()
        );
        let repeated = fixture.reserve(&outbox, "ephemeral:quote", "quote");
        assert_eq!(repeated.id(), original.id());
        assert_eq!(
            outbox.eligible_cleanup(100, 10).unwrap()[0].id(),
            original.id()
        );
    }

    #[test]
    fn restart_reuses_exact_resource_before_and_after_publication() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = fixture.reserve(&outbox, "swap-a", "secret request");
        let serialized = fs::read_to_string(fixture.path()).unwrap();
        assert!(!serialized.contains("secret request"));
        drop(outbox);
        let outbox = fixture.open();
        let retry = outbox
            .prepare(
                &fixture.peer.to_string(),
                "swap-a",
                "secret request",
                || -> Result<PreparedMessage> { panic!("existing reservation must be reused") },
            )
            .unwrap();
        assert_eq!(original.id(), retry.id());
        assert_eq!(original.payload(), retry.payload());
        assert_eq!(outbox.due_pending(0, 10).unwrap().len(), 1);
        outbox.mark_published(original.id()).unwrap();
        outbox
            .mark_failed(original.id(), 20, DeliveryFailure::TransportUnavailable)
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        assert!(outbox.due_pending(100, 10).unwrap().is_empty());
        assert_eq!(
            fixture.reserve(&outbox, "swap-a", "secret request").id(),
            original.id()
        );
    }

    #[test]
    fn retry_schedule_survives_restart_without_burning_future_attempts() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let prepared = fixture.reserve(&outbox, "swap-a", "request");
        outbox
            .mark_failed(prepared.id(), 100, DeliveryFailure::TransportUnavailable)
            .unwrap();
        outbox
            .mark_failed(prepared.id(), 100, DeliveryFailure::TransportUnavailable)
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        assert!(outbox.due_pending(100, 1).unwrap().is_empty());
        assert_eq!(outbox.due_pending(101, 1).unwrap()[0].id(), prepared.id());
        outbox
            .mark_failed(prepared.id(), 101, DeliveryFailure::TransportUnavailable)
            .unwrap();
        assert!(outbox.due_pending(102, 1).unwrap().is_empty());
        assert_eq!(outbox.due_pending(103, 1).unwrap().len(), 1);
        let entry = &outbox.state.lock().unwrap().journal.entries[0];
        assert_eq!(entry.attempts, 2);
    }

    #[test]
    fn scoped_cleanup_preserves_other_swaps_and_partial_failures() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let first = fixture.reserve(&outbox, "swap-a", "request");
        let second = fixture.reserve(&outbox, "swap-a", "response");
        let other = fixture.reserve(&outbox, "swap-b", "request");
        outbox
            .complete_scope(&fixture.peer.to_string(), "swap-a", 100)
            .unwrap();
        outbox
            .complete_scope(&fixture.peer.to_string(), "swap-a", 999)
            .unwrap();
        assert!(outbox.eligible_cleanup(99, 10).unwrap().is_empty());
        assert!(outbox.can_publish(first.id(), 99).unwrap());
        assert!(!outbox.can_publish(first.id(), 100).unwrap());
        assert_eq!(outbox.eligible_cleanup(100, 10).unwrap().len(), 2);
        assert_eq!(outbox.due_pending(100, 10).unwrap()[0].id(), other.id());
        assert!(outbox
            .remove_deleted(&[other.id().to_owned()], 100)
            .is_err());
        outbox
            .remove_deleted(&[first.id().to_owned()], 100)
            .unwrap();
        assert!(!outbox.can_publish(first.id(), 99).unwrap());
        outbox
            .mark_cleanup_failed(second.id(), 100, DeliveryFailure::TransportUnavailable)
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        assert!(outbox.eligible_cleanup(100, 10).unwrap().is_empty());
        assert_eq!(
            outbox.eligible_cleanup(101, 10).unwrap()[0].id(),
            second.id()
        );
        outbox
            .remove_deleted(&[second.id().to_owned()], 101)
            .unwrap();
        assert!(outbox.eligible_cleanup(1000, 10).unwrap().is_empty());
        assert_eq!(outbox.due_pending(1000, 10).unwrap()[0].id(), other.id());
    }

    #[test]
    fn reopened_swaps_revoke_cleanup_without_changing_the_saved_resource() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let original = fixture.reserve(&outbox, "quote:a", "acceptance");
        outbox.mark_published(original.id()).unwrap();
        outbox
            .complete_scope(&fixture.peer.to_string(), "quote:a", 100)
            .unwrap();
        outbox
            .reopen_scope(&fixture.peer.to_string(), "quote:a")
            .unwrap();
        drop(outbox);
        let outbox = fixture.open();
        assert!(outbox.eligible_cleanup(1000, 10).unwrap().is_empty());
        assert!(!outbox.can_cleanup(original.id(), 1000).unwrap());
        assert_eq!(outbox.due_pending(0, 10).unwrap()[0].id(), original.id());
        let restored = fixture.reserve(&outbox, "quote:a", "acceptance");
        assert_eq!(original.id(), restored.id());
        assert_eq!(original.payload(), restored.payload());
        outbox.mark_published(original.id()).unwrap();
        outbox
            .reopen_scope(&fixture.peer.to_string(), "quote:a")
            .unwrap();
        assert!(outbox.due_pending(1000, 10).unwrap().is_empty());
        outbox
            .complete_scope(&fixture.peer.to_string(), "quote:a", 2000)
            .unwrap();
        assert!(outbox.eligible_cleanup(1999, 10).unwrap().is_empty());
        assert_eq!(
            outbox.eligible_cleanup(2000, 10).unwrap()[0].id(),
            original.id()
        );
    }

    #[test]
    fn late_deletion_results_after_reopening_preserve_durable_publication_repair() {
        for successful_delete in [true, false] {
            let fixture = Fixture::new();
            let outbox = fixture.open();
            let original = fixture.reserve(&outbox, "quote:a", "acceptance");
            outbox
                .mark_failed(original.id(), 90, DeliveryFailure::TransportUnavailable)
                .unwrap();
            outbox.mark_published(original.id()).unwrap();
            outbox
                .complete_scope(&fixture.peer.to_string(), "quote:a", 100)
                .unwrap();
            assert!(outbox.can_cleanup(original.id(), 100).unwrap());

            // The application reopens while the prior deletion awaits its remote outcome.
            outbox
                .reopen_scope(&fixture.peer.to_string(), "quote:a")
                .unwrap();
            if successful_delete {
                assert!(outbox
                    .remove_deleted(&[original.id().to_owned()], 100)
                    .is_err());
            } else {
                outbox
                    .mark_cleanup_failed(original.id(), 100, DeliveryFailure::TransportUnavailable)
                    .unwrap();
            }
            drop(outbox);

            let outbox = fixture.open();
            assert!(outbox.eligible_cleanup(100, 10).unwrap().is_empty());
            let repair = outbox.due_pending(0, 10).unwrap();
            assert_eq!(repair.len(), 1);
            assert_eq!(repair[0].id(), original.id());
            assert_eq!(repair[0].payload(), original.payload());
            let state = outbox.state.lock().unwrap();
            assert_eq!(state.journal.entries[0].attempts, 0);
            assert_eq!(state.journal.entries[0].next_retry_at, 0);
        }
    }

    #[test]
    fn failed_persistence_never_exposes_success_or_continues_from_stale_state() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let prepared = fixture.reserve(&outbox, "swap-a", "request");
        let original = fs::read(fixture.path()).unwrap();
        fs::remove_file(fixture.path()).unwrap();
        fs::create_dir(fixture.path()).unwrap();
        assert!(outbox.mark_published(prepared.id()).is_err());
        assert!(!outbox.state.lock().unwrap().journal.entries[0].published);
        assert!(outbox.due_pending(0, 1).is_err());
        drop(outbox);
        fs::remove_dir(fixture.path()).unwrap();
        private_options()
            .create_new(true)
            .open(fixture.path())
            .unwrap()
            .write_all(&original)
            .unwrap();
        assert_eq!(
            fixture.open().due_pending(0, 1).unwrap()[0].id(),
            prepared.id()
        );
    }

    #[test]
    fn admission_never_evicts_pending_work_and_batches_are_bounded() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let prepared = fixture.reserve(&outbox, "swap-a", "request");
        // Fill in one transaction to test the capacity invariant without quadratic disk work.
        {
            let mut state = outbox.state.lock().unwrap();
            let template = state.journal.entries[0].clone();
            state.journal.entries = (0..MAX_ENTRIES)
                .map(|index| {
                    let mut entry = template.clone();
                    entry.scope = format!("swap-{index}");
                    entry.prepared = fixture
                        .client
                        .prepare_message(&fixture.peer, "request")
                        .unwrap();
                    entry
                })
                .collect();
            persist(&outbox.path, &state.journal).unwrap();
        }
        assert!(outbox
            .prepare(&fixture.peer.to_string(), "new", "request", || Ok::<
                _,
                TransportError,
            >(
                prepared.clone()
            ))
            .is_err());
        assert_eq!(outbox.due_pending(0, usize::MAX).unwrap().len(), MAX_BATCH);
        drop(outbox);
        assert_eq!(
            fixture.open().state.lock().unwrap().journal.entries.len(),
            MAX_ENTRIES
        );
    }

    #[test]
    fn read_only_backlog_leaves_room_for_creation_replies() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        fixture.reserve(&outbox, "ephemeral:first", "quote");
        {
            let mut state = outbox.state.lock().unwrap();
            let template = state.journal.entries[0].clone();
            state.journal.entries = (0..MAX_EPHEMERAL_ENTRIES)
                .map(|index| {
                    let mut entry = template.clone();
                    entry.scope = format!("ephemeral:{index}");
                    entry.prepared = fixture
                        .client
                        .prepare_message(&fixture.peer, "quote")
                        .unwrap();
                    entry
                })
                .collect();
            persist(&outbox.path, &state.journal).unwrap();
        }
        assert!(outbox
            .prepare(
                &fixture.peer.to_string(),
                "ephemeral:another",
                "quote",
                || { fixture.client.prepare_message(&fixture.peer, "quote") }
            )
            .is_err());
        let acceptance = fixture.reserve(&outbox, "quote:accepted", "acceptance");
        drop(outbox);
        let restored = fixture.open();
        let state = restored.state.lock().unwrap();
        assert_eq!(state.journal.entries.len(), MAX_EPHEMERAL_ENTRIES + 1);
        assert!(state
            .journal
            .entries
            .iter()
            .any(|entry| entry.prepared.id() == acceptance.id()));
    }

    #[test]
    fn simultaneous_reservations_prepare_one_durable_resource() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        let prepared = fixture
            .client
            .prepare_message(&fixture.peer, "request")
            .unwrap();
        let calls = AtomicU64::new(0);
        std::thread::scope(|threads| {
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    threads.spawn(|| {
                        outbox
                            .prepare(&fixture.peer.to_string(), "swap-a", "request", || {
                                calls.fetch_add(1, Ordering::SeqCst);
                                Ok::<_, TransportError>(prepared.clone())
                            })
                            .unwrap()
                    })
                })
                .collect();
            for task in tasks {
                assert_eq!(task.join().unwrap().id(), prepared.id());
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(outbox);
        assert_eq!(fixture.open().due_pending(0, 10).unwrap().len(), 1);
    }

    #[test]
    fn competing_owners_and_corrupt_files_fail_closed() {
        let fixture = Fixture::new();
        let outbox = fixture.open();
        assert!(Outbox::open(fixture.path()).is_err());
        fixture.reserve(&outbox, "swap-a", "request");
        outbox
            .check_owner(&Keypair::from_secret_key(&[1; 32]).public_key().to_string())
            .unwrap();
        assert!(outbox.check_owner(&fixture.peer.to_string()).is_err());
        let stranger = PrivateMessengerClient::new(Keypair::from_secret_key(&[3; 32])).unwrap();
        assert!(outbox
            .prepare(&fixture.peer.to_string(), "swap-b", "request", || stranger
                .prepare_message(&fixture.peer, "request"))
            .is_err());
        drop(outbox);
        fs::write(fixture.path(), b"invalid").unwrap();
        assert!(Outbox::open(fixture.path()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(fixture.path()).unwrap().permissions().mode() & 0o777,
                0o600
            );
            fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Outbox::open(fixture.path()).is_err());
        }
    }
}
