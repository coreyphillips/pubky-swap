//! What became of each delivered message, kept on disk so a restarted process can tell work it
//! already handled from work it read but never dispatched.
//!
//! The dedup set in memory starts empty after a restart, and a sender's timestamp cannot answer
//! that question: a request handled a minute ago looks as fresh as one nobody has answered yet,
//! and a request read just before a long outage looks as stale as last week's history.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Entries kept at most. Handled entries go first, oldest first, then pending ones.
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    /// Handed to the caller and not yet acknowledged.
    Pending,
    /// Acknowledged, so never delivered again.
    Handled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    id: String,
    peer: String,
    timestamp: u64,
    outcome: Outcome,
}

pub(crate) struct Journal {
    path: PathBuf,
    entries: HashMap<String, Entry>,
    /// Changed since the last successful save.
    dirty: bool,
}

impl Journal {
    /// Load the journal at `path`, or start an empty one if there is none yet.
    pub(crate) fn open(path: &Path) -> std::io::Result<Self> {
        let entries: Vec<Entry> = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("receive journal {}: {e}", path.display()),
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries: entries.into_iter().map(|e| (e.id.clone(), e)).collect(),
            dirty: false,
        })
    }

    /// Whether memory holds state the file does not, so nothing may be delivered on its strength.
    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(crate) fn outcome(&self, id: &str) -> Option<Outcome> {
        self.entries.get(id).map(|e| e.outcome)
    }

    /// Returns whether anything changed.
    pub(crate) fn record(
        &mut self,
        id: &str,
        peer: &str,
        timestamp: u64,
        outcome: Outcome,
    ) -> bool {
        if self.outcome(id) == Some(outcome) {
            return false;
        }
        self.entries.insert(
            id.to_string(),
            Entry {
                id: id.to_string(),
                peer: peer.to_string(),
                timestamp,
                outcome,
            },
        );
        self.dirty = true;
        true
    }

    /// Mark a delivered message handled. Returns whether anything changed.
    pub(crate) fn acknowledge(&mut self, id: &str) -> bool {
        match self.entries.get_mut(id) {
            Some(entry) if entry.outcome == Outcome::Pending => {
                entry.outcome = Outcome::Handled;
                self.dirty = true;
                true
            }
            _ => false,
        }
    }

    /// Peers with work that was delivered and never acknowledged.
    pub(crate) fn pending_peers(&self) -> Vec<String> {
        let mut peers: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.outcome == Outcome::Pending)
            .map(|e| e.peer.clone())
            .collect();
        peers.sort();
        peers.dedup();
        peers
    }

    /// Returns whether anything changed.
    pub(crate) fn forget_peer(&mut self, peer: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|_, e| e.peer != peer);
        self.dirty |= self.entries.len() != before;
        self.entries.len() != before
    }

    /// Drop what is no longer needed, then write the journal atomically.
    ///
    /// A handled message stamped below its peer's floor is filtered out by the floor anyway, and
    /// floors only move forward, so its entry can go. `floor` gives that floor for a peer.
    pub(crate) fn save(&mut self, floor: impl Fn(&str) -> u64) -> std::io::Result<()> {
        self.entries
            .retain(|_, e| e.outcome == Outcome::Pending || e.timestamp >= floor(&e.peer));
        if self.entries.len() > MAX_ENTRIES {
            let mut oldest: Vec<(bool, u64, String)> = self
                .entries
                .values()
                .map(|e| (e.outcome == Outcome::Pending, e.timestamp, e.id.clone()))
                .collect();
            oldest.sort();
            for (_, _, id) in oldest.into_iter().take(self.entries.len() - MAX_ENTRIES) {
                self.entries.remove(&id);
            }
        }

        let entries: Vec<&Entry> = self.entries.values().collect();
        let bytes = serde_json::to_vec(&entries)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        // Only one writer per journal: saves run under the transport's lock on it.
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            // The journal names counterparties and when they wrote, so keep it from other users.
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        // Without syncing the directory a machine crash can undo the rename. Windows cannot
        // open a directory as a file, so this is unix only.
        #[cfg(unix)]
        {
            let dir = match self.path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d,
                _ => Path::new("."),
            };
            fs::File::open(dir)?.sync_all()?;
        }
        self.dirty = false;
        Ok(())
    }
}
