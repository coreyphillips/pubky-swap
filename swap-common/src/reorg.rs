//! Chain-reorganization detection and finality.
//!
//! A reorg can invalidate something a swap relied on — most dangerously, a funding output a
//! provider treated as confirmed before paying a (irreversible) Lightning invoice, or a
//! claim/refund that was mined and then orphaned. Two tools guard against that:
//!
//! - [`FINALITY_DEPTH`]: callers treat an output as final only once it is this many blocks deep,
//!   so a shallow confirmation that a small reorg could undo is never acted on irreversibly.
//! - [`ReorgMonitor`]: tracks `(height, block hash)` checkpoints and flags when a previously-seen
//!   height's hash changes (or the tip rolls back), reporting the fork height so in-flight swaps
//!   can be re-validated.

use crate::chain::ChainWatcher;
use crate::error::Result;
use bitcoin::BlockHash;
use std::collections::BTreeMap;

/// Confirmations at which an output is treated as final (reorg-safe enough to act on
/// irreversibly). Conservative default; operators on mainnet should prefer a higher value via the
/// provider's `required_confirmations` for funding.
pub const FINALITY_DEPTH: u32 = 2;

/// How many blocks below the tip a monitor keeps under watch.
///
/// A reorg deeper than a handful of blocks is close to unheard of on Bitcoin, and one shallower
/// than this is what a swap actually has to survive. Watching a fixed window rather than only the
/// tip is what makes a reorg that replaces a *non-tip* block visible at all: sampling the tip
/// every thirty seconds only ever records heights that happened to be the tip when the sample
/// was taken, and a chain that reorganises two blocks back and immediately extends leaves no
/// trace in that record.
pub const WATCHED_DEPTH: u16 = 24;

/// Tracks block-hash continuity to detect reorganizations.
///
/// Call [`observe`](ReorgMonitor::observe) periodically. It reads the hashes of the last
/// [`WATCHED_DEPTH`] blocks in one request and compares them to what it saw last time. A height
/// whose hash changed, or a tip that has moved backwards, means the chain reorganised at or below
/// that height, which is returned as the fork height. Checkpoints at or above a detected fork are
/// discarded so the same reorg is not reported twice.
#[derive(Debug, Default)]
pub struct ReorgMonitor {
    checkpoints: BTreeMap<u32, BlockHash>,
    max_checkpoints: usize,
}

impl ReorgMonitor {
    /// A monitor retaining up to `max_checkpoints` recent height to hash samples.
    pub fn new(max_checkpoints: usize) -> Self {
        Self {
            checkpoints: BTreeMap::new(),
            max_checkpoints: max_checkpoints.max(1),
        }
    }

    /// Sample the chain and report the lowest height at which a reorg was detected since the last
    /// observation, if any. `Ok(None)` means no reorg.
    pub fn observe(&mut self, chain: &dyn ChainWatcher) -> Result<Option<u32>> {
        let tip = chain.tip_height()?;
        let start = tip.saturating_sub(u32::from(WATCHED_DEPTH).saturating_sub(1));
        let hashes = chain.block_hashes_from(start, WATCHED_DEPTH)?;
        let observed: BTreeMap<u32, BlockHash> = hashes
            .into_iter()
            .enumerate()
            .map(|(i, h)| (start.saturating_add(i as u32), h))
            .collect();

        let mut fork: Option<u32> = None;
        for (&height, &old_hash) in &self.checkpoints {
            if height > tip {
                // The chain is now shorter than when we recorded this height, so it was rolled
                // back.
                fork = Some(fork.map_or(height, |f| f.min(height)));
                continue;
            }
            // Only heights the current sample actually covers can be compared. One below the
            // window is not evidence of anything: it is simply older than what was asked for.
            if let Some(current) = observed.get(&height) {
                if *current != old_hash {
                    fork = Some(fork.map_or(height, |f| f.min(height)));
                }
            }
        }

        // Drop checkpoints at or above the fork so a future observe() starts clean above it.
        if let Some(fork_height) = fork {
            self.checkpoints.retain(|&h, _| h < fork_height);
        }

        self.checkpoints.extend(observed);
        while self.checkpoints.len() > self.max_checkpoints {
            let Some(&lowest) = self.checkpoints.keys().next() else {
                break;
            };
            self.checkpoints.remove(&lowest);
        }

        Ok(fork)
    }

    /// Number of retained checkpoints (for tests and introspection).
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    use crate::chain::mock::MockChain;

    /// A distinct block hash per (height, generation), so a test can flip a height's hash.
    fn hash(height: u32, generation: u8) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[0] = generation;
        bytes[1..5].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_byte_array(bytes)
    }

    /// Script a contiguous chain up to `tip`, deep enough to fill the watched window.
    fn chain_to(tip: u32, generation: u8) -> MockChain {
        let chain = MockChain::new();
        chain.set_tip(tip);
        for h in tip.saturating_sub(u32::from(WATCHED_DEPTH))..=tip {
            chain.set_block_hash(h, hash(h, generation));
        }
        chain
    }

    #[test]
    fn no_reorg_when_hashes_are_stable() {
        let chain = chain_to(100, 1);
        let mut mon = ReorgMonitor::new(100);
        assert_eq!(mon.observe(&chain).unwrap(), None);
        chain.set_tip(101);
        chain.set_block_hash(101, hash(101, 1));
        assert_eq!(mon.observe(&chain).unwrap(), None);
    }

    #[test]
    fn detects_hash_change_at_a_seen_height() {
        let chain = chain_to(100, 1);
        let mut mon = ReorgMonitor::new(100);
        assert_eq!(mon.observe(&chain).unwrap(), None);

        // Same height, different hash: a reorg replaced block 100.
        chain.set_block_hash(100, hash(100, 2));
        assert_eq!(mon.observe(&chain).unwrap(), Some(100));
        // The same reorg isn't reported again.
        assert_eq!(mon.observe(&chain).unwrap(), None);
    }

    /// The case that only a window can see.
    ///
    /// A chain that replaces a block two back and immediately extends past it never presents a
    /// changed *tip* hash, so a monitor that samples only the tip records nothing unusual and the
    /// swaps built on that block are never re-validated.
    #[test]
    fn detects_a_reorg_below_the_tip() {
        let chain = chain_to(100, 1);
        let mut mon = ReorgMonitor::new(100);
        assert_eq!(mon.observe(&chain).unwrap(), None);

        // Blocks 98 and 99 are replaced and the chain extends to a new 100 and 101. The tip is
        // higher than before, and everything about it looks like ordinary progress.
        chain.set_block_hash(98, hash(98, 2));
        chain.set_block_hash(99, hash(99, 2));
        chain.set_block_hash(100, hash(100, 2));
        chain.set_tip(101);
        chain.set_block_hash(101, hash(101, 2));

        assert_eq!(
            mon.observe(&chain).unwrap(),
            Some(98),
            "the fork is reported at its lowest replaced height, not at the tip"
        );
    }

    #[test]
    fn detects_tip_rollback() {
        let chain = chain_to(105, 1);
        let mut mon = ReorgMonitor::new(100);
        assert_eq!(mon.observe(&chain).unwrap(), None);

        // Tip drops below a recorded checkpoint: a rollback.
        chain.set_tip(103);
        assert_eq!(mon.observe(&chain).unwrap(), Some(104));
    }

    #[test]
    fn a_watcher_without_block_hashes_records_nothing() {
        // A watcher that cannot answer for block hashes cannot detect reorgs. That used to be the
        // trait's default, so a production watcher could arrive here by forgetting a method;
        // now it takes saying so.
        let chain = MockChain::new().with_tip(10);
        let mut mon = ReorgMonitor::new(100);
        assert_eq!(mon.observe(&chain).unwrap(), None);
        assert_eq!(mon.checkpoint_count(), 0);
    }
}
