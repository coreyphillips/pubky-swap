//! Durable peer registration, pending bodies and acknowledged resource identities.
//!
//! Updates reach disk before memory changes. A failed write cannot acknowledge work or expose
//! an unrecorded delivery. Pending capacity applies admission backpressure, never eviction.

use crate::{Result, TransportError};
use fs2::FileExt;
use pkarr::PublicKey;
use pubky_messenger::{MessageId, ReceiveState, ReceivedMessage};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const VERSION: u32 = 2;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub(crate) const MAX_PENDING: usize = 1024;
pub(crate) const MAX_PENDING_PER_PEER: usize = 32;
const MAX_REGISTERED_PEERS: usize = 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerRecord {
    pub registered: bool,
    pub pinned: bool,
    pub acknowledged: ReceiveState,
    pub pending: Vec<ReceivedMessage>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    version: u32,
    owner: Option<String>,
    peers: BTreeMap<String, PeerRecord>,
}

pub(crate) struct Journal {
    path: Option<PathBuf>,
    records: Records,
    write_failed: bool,
    _file_lock: Option<File>,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            path: None,
            records: Records {
                version: VERSION,
                owner: None,
                peers: BTreeMap::new(),
            },
            write_failed: false,
            _file_lock: None,
        }
    }
}

impl Journal {
    pub fn open(path: &Path, owner: &str) -> Result<Self> {
        canonical_pubky(owner)?;
        let mut directories = fs::DirBuilder::new();
        directories.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directories.mode(0o700);
        }
        directories.create(parent(path))?;
        let lock_path = path.with_extension("receive-lock");
        check_file(&lock_path)?;
        let file_lock = private_options().create(true).open(lock_path)?;
        FileExt::try_lock_exclusive(&file_lock)?;
        check_file(path)?;
        let records: Records = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let records = Records {
                    owner: Some(owner.to_owned()),
                    ..Self::default().records
                };
                persist(path, &records)?;
                records
            }
            Err(error) => return Err(error.into()),
        };
        if records.version != VERSION {
            return Err(TransportError::Messenger(
                "unsupported receive journal version".into(),
            ));
        }
        if records.owner.as_deref() != Some(owner) {
            return Err(invalid("receive journal belongs to another identity"));
        }
        let pending: usize = records
            .peers
            .values()
            .map(|record| record.pending.len())
            .sum();
        if pending > MAX_PENDING {
            return Err(invalid("receive journal exceeds pending capacity"));
        }
        for (peer, record) in &records.peers {
            canonical_pubky(peer)?;
            if record.pending.len() > MAX_PENDING_PER_PEER {
                return Err(invalid("receive journal exceeds peer pending capacity"));
            }
        }
        Ok(Self {
            path: Some(path.to_path_buf()),
            records,
            write_failed: false,
            _file_lock: Some(file_lock),
        })
    }

    pub fn ensure_healthy(&self) -> Result<()> {
        if self.write_failed {
            return Err(invalid(
                "received message state could not be saved; restart the transport to recover",
            ));
        }
        Ok(())
    }

    pub fn check_owner(&self, owner: &str) -> Result<()> {
        self.ensure_healthy()?;
        canonical_pubky(owner)?;
        if self
            .records
            .owner
            .as_deref()
            .is_some_and(|saved| saved != owner)
        {
            return Err(invalid("receive journal belongs to another identity"));
        }
        Ok(())
    }

    pub fn registered(&self) -> Vec<(String, bool)> {
        self.records
            .peers
            .iter()
            .filter(|(_, r)| r.registered || !r.pending.is_empty())
            .map(|(peer, r)| (peer.clone(), r.pinned))
            .collect()
    }

    pub fn record(&self, peer: &str) -> PeerRecord {
        self.records.peers.get(peer).cloned().unwrap_or_default()
    }

    pub fn register(&mut self, peer: &str, pinned: bool) -> Result<()> {
        self.ensure_healthy()?;
        canonical_pubky(peer)?;
        let record = self.record(peer);
        if record.registered && (!pinned || record.pinned) {
            return Ok(());
        }
        if !record.registered && self.registered().len() >= MAX_REGISTERED_PEERS {
            return Err(TransportError::Messenger(
                "receive peer capacity reached".into(),
            ));
        }
        self.update(|records| {
            let record = records.peers.entry(peer.to_string()).or_default();
            record.registered = true;
            record.pinned |= pinned;
        })
    }

    pub fn unregister(&mut self, peer: &str) -> Result<bool> {
        self.ensure_healthy()?;
        if !self.record(peer).pending.is_empty() {
            return Ok(false);
        }
        self.update(|records| {
            if let Some(record) = records.peers.get_mut(peer) {
                record.registered = false;
            }
        })?;
        Ok(true)
    }

    pub fn available(&self, peer: &str) -> usize {
        let total: usize = self.records.peers.values().map(|r| r.pending.len()).sum();
        MAX_PENDING
            .saturating_sub(total)
            .min(MAX_PENDING_PER_PEER.saturating_sub(self.record(peer).pending.len()))
    }

    pub fn remember(&mut self, peer: &str, received: Vec<ReceivedMessage>) -> Result<()> {
        self.ensure_healthy()?;
        canonical_pubky(peer)?;
        let existing = self.record(peer);
        let available = self.available(peer);
        let mut pending = Vec::new();
        let mut discarded = Vec::new();
        for message in received {
            if existing.acknowledged.is_acknowledged(&message.id)
                || existing.pending.iter().any(|p| p.id == message.id)
                || pending.iter().any(|p: &ReceivedMessage| p.id == message.id)
                || discarded
                    .iter()
                    .any(|p: &ReceivedMessage| p.id == message.id)
            {
                continue;
            }
            if message.message.is_none() {
                discarded.push(message);
            } else if pending.len() < available {
                pending.push(message);
            }
        }
        if pending.is_empty() && discarded.is_empty() {
            return Ok(());
        }
        self.update(|records| {
            let record = records.peers.entry(peer.to_string()).or_default();
            record.pending.extend(pending);
            for message in discarded {
                record.acknowledged.acknowledge(&message);
            }
        })
    }

    pub fn acknowledge(&mut self, peer: &str, ids: &[MessageId]) -> Result<()> {
        self.ensure_healthy()?;
        canonical_pubky(peer)?;
        if ids.is_empty() {
            return Ok(());
        }
        self.update(|records| {
            let record = records.peers.entry(peer.to_string()).or_default();
            for id in ids {
                record.acknowledged.acknowledge(&ReceivedMessage {
                    id: id.clone(),
                    message: None,
                    etag: None,
                    updated: false,
                });
            }
            record.pending.retain(|message| !ids.contains(&message.id));
        })
    }

    fn update(&mut self, apply: impl FnOnce(&mut Records)) -> Result<()> {
        self.ensure_healthy()?;
        let mut next = self.records.clone();
        apply(&mut next);
        if let Some(path) = &self.path {
            if let Err(error) = persist(path, &next) {
                // Rename may have succeeded before directory synchronization failed.
                self.write_failed = true;
                return Err(error);
            }
        }
        self.records = next;
        Ok(())
    }
}

fn invalid(message: &str) -> TransportError {
    TransportError::Messenger(message.to_owned())
}

fn canonical_pubky(value: &str) -> Result<()> {
    let key =
        PublicKey::try_from(value).map_err(|_| invalid("invalid receive journal identity"))?;
    if key.to_string() != value {
        return Err(invalid("receive journal identity is not canonical"));
    }
    Ok(())
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

fn check_file(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        return Err(invalid("receive journal must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("receive journal requires private file permissions"));
        }
    }
    Ok(())
}

fn persist(path: &Path, records: &Records) -> Result<()> {
    check_file(path)?;
    let bytes = serde_json::to_vec(records)?;
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = PathBuf::from(temporary);
    let mut file = private_options().create_new(true).open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        File::open(parent(path))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
