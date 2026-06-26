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

/// Tracks block-hash continuity to detect reorganizations.
///
/// Call [`observe`](ReorgMonitor::observe) periodically. It records the current tip's hash and,
/// against the watcher's current best chain, checks every retained checkpoint: if a height's hash
/// changed, or the tip dropped below a checkpoint, the chain reorganized at or below the lowest
/// such height — returned as the fork height. Checkpoints at/above a detected fork are discarded so
/// the same reorg isn't reported twice.
#[derive(Debug, Default)]
pub struct ReorgMonitor {
    checkpoints: BTreeMap<u32, BlockHash>,
    max_checkpoints: usize,
}

impl ReorgMonitor {
    /// A monitor retaining up to `max_checkpoints` recent height→hash samples.
    pub fn new(max_checkpoints: usize) -> Self {
        Self {
            checkpoints: BTreeMap::new(),
            max_checkpoints: max_checkpoints.max(1),
        }
    }

    /// Sample the chain and report the lowest height at which a reorg was detected since the last
    /// observation, if any. `Ok(None)` means no reorg (or the watcher doesn't expose block hashes).
    pub fn observe(&mut self, chain: &dyn ChainWatcher) -> Result<Option<u32>> {
        let tip = chain.tip_height()?;

        // Detect changes against retained checkpoints.
        let mut fork: Option<u32> = None;
        for (&height, &old_hash) in &self.checkpoints {
            if height > tip {
                // The chain is now shorter than when we recorded this height → it was rolled back.
                fork = Some(fork.map_or(height, |f| f.min(height)));
                continue;
            }
            if let Some(current) = chain.block_hash_at(height)? {
                if current != old_hash {
                    fork = Some(fork.map_or(height, |f| f.min(height)));
                }
            }
        }

        // Drop checkpoints at/above the fork so a future observe() starts clean above it.
        if let Some(fork_height) = fork {
            self.checkpoints.retain(|&h, _| h < fork_height);
        }

        // Record the current tip.
        if let Some(hash) = chain.block_hash_at(tip)? {
            self.checkpoints.insert(tip, hash);
            while self.checkpoints.len() > self.max_checkpoints {
                if let Some(&lowest) = self.checkpoints.keys().next() {
                    self.checkpoints.remove(&lowest);
                } else {
                    break;
                }
            }
        }

        Ok(fork)
    }

    /// Number of retained checkpoints (for tests / introspection).
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::FundingUtxo;
    use bitcoin::hashes::Hash;
    use bitcoin::{OutPoint, Script, Transaction, Txid};
    use std::sync::Mutex;

    /// A chain whose tip height and per-height block hashes are scriptable, to simulate reorgs.
    struct FakeChain {
        tip: Mutex<u32>,
        // height -> hash byte (so we can flip a height's hash to simulate a reorg)
        hashes: Mutex<std::collections::HashMap<u32, u8>>,
    }
    impl FakeChain {
        fn new() -> Self {
            Self {
                tip: Mutex::new(0),
                hashes: Mutex::new(std::collections::HashMap::new()),
            }
        }
        fn set_tip(&self, h: u32) {
            *self.tip.lock().unwrap() = h;
        }
        fn set_hash(&self, height: u32, byte: u8) {
            self.hashes.lock().unwrap().insert(height, byte);
        }
    }
    impl ChainWatcher for FakeChain {
        fn tip_height(&self) -> Result<u32> {
            Ok(*self.tip.lock().unwrap())
        }
        fn find_funding(&self, _: &Script, _: u64) -> Result<Option<FundingUtxo>> {
            Ok(None)
        }
        fn find_spend(&self, _: &Script, _: &OutPoint) -> Result<Option<Transaction>> {
            Ok(None)
        }
        fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
            Ok(tx.txid())
        }
        fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>> {
            if height > *self.tip.lock().unwrap() {
                return Ok(None);
            }
            let byte = *self.hashes.lock().unwrap().get(&height).unwrap_or(&0);
            let mut bytes = [0u8; 32];
            bytes[0] = byte;
            bytes[1] = height as u8;
            Ok(Some(BlockHash::from_byte_array(bytes)))
        }
    }

    #[test]
    fn no_reorg_when_hashes_are_stable() {
        let chain = FakeChain::new();
        let mut mon = ReorgMonitor::new(10);
        chain.set_tip(100);
        chain.set_hash(100, 1);
        assert_eq!(mon.observe(&chain).unwrap(), None);
        chain.set_tip(101);
        chain.set_hash(101, 1);
        assert_eq!(mon.observe(&chain).unwrap(), None);
    }

    #[test]
    fn detects_hash_change_at_a_seen_height() {
        let chain = FakeChain::new();
        let mut mon = ReorgMonitor::new(10);
        chain.set_tip(100);
        chain.set_hash(100, 1);
        assert_eq!(mon.observe(&chain).unwrap(), None);

        // Same height, different hash → a reorg replaced block 100.
        chain.set_hash(100, 2);
        assert_eq!(mon.observe(&chain).unwrap(), Some(100));
        // The same reorg isn't reported again.
        assert_eq!(mon.observe(&chain).unwrap(), None);
    }

    #[test]
    fn detects_tip_rollback() {
        let chain = FakeChain::new();
        let mut mon = ReorgMonitor::new(10);
        chain.set_tip(105);
        chain.set_hash(105, 1);
        assert_eq!(mon.observe(&chain).unwrap(), None);

        // Tip drops below a recorded checkpoint → rollback.
        chain.set_tip(103);
        chain.set_hash(103, 1);
        assert_eq!(mon.observe(&chain).unwrap(), Some(105));
    }

    #[test]
    fn opts_out_when_no_block_hashes() {
        // A watcher returning None for block_hash_at never reports a reorg.
        struct NoHashes;
        impl ChainWatcher for NoHashes {
            fn tip_height(&self) -> Result<u32> {
                Ok(10)
            }
            fn find_funding(&self, _: &Script, _: u64) -> Result<Option<FundingUtxo>> {
                Ok(None)
            }
            fn find_spend(&self, _: &Script, _: &OutPoint) -> Result<Option<Transaction>> {
                Ok(None)
            }
            fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
                Ok(tx.txid())
            }
        }
        let mut mon = ReorgMonitor::new(10);
        assert_eq!(mon.observe(&NoHashes).unwrap(), None);
        assert_eq!(mon.checkpoint_count(), 0);
    }
}
