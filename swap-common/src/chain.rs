//! Chain observation needed to drive a swap: find the funding UTXO, count confirmations,
//! learn the tip height (for timeouts), and broadcast claim/refund transactions.
//!
//! The trait is synchronous because the Electrum client is blocking; an async runtime
//! should call these via `spawn_blocking`. An [`ElectrumWatcher`] implementation is provided
//! behind the `electrum` feature.

use crate::error::Result;
use bitcoin::{OutPoint, Script, Transaction, Txid};

/// A confirmed-or-mempool funding output of an HTLC.
#[derive(Debug, Clone)]
pub struct FundingUtxo {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    /// 0 while unconfirmed (in the mempool).
    pub confirmations: u32,
}

/// Minimal chain access for the swap state machine. `Send + Sync` so a watcher can be shared
/// (behind `Arc`) with spawned per-swap driver tasks.
pub trait ChainWatcher: Send + Sync {
    /// Current best block height.
    fn tip_height(&self) -> Result<u32>;

    /// Find an unspent output paying exactly `expected_value_sat` to `spk` (the HTLC P2WSH
    /// scriptPubKey), if one exists.
    fn find_funding(&self, spk: &Script, expected_value_sat: u64) -> Result<Option<FundingUtxo>>;

    /// Find the transaction (if any) that spends `outpoint`. Used to detect the
    /// counterparty's claim (so the preimage can be recovered) or refund. `spk` is the
    /// HTLC scriptPubKey, used to scan history.
    fn find_spend(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<Transaction>>;

    /// Broadcast a transaction, returning its txid.
    fn broadcast(&self, tx: &Transaction) -> Result<Txid>;

    /// Estimate the fee rate (sat/vB) to confirm within `target_blocks`. `Ok(None)` means the
    /// backend has no estimate (e.g. on regtest, where `estimatefee` returns the `-1` sentinel),
    /// in which case callers fall back to their configured fee floor. The default returns
    /// `Ok(None)` so watchers (and test mocks) without estimation need no change.
    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>> {
        let _ = target_blocks;
        Ok(None)
    }

    /// Confirmations of transaction `txid` (which we expect spends one of our outputs, hence the
    /// `spk` to scan its history): `Some(0)` if still in the mempool, `Some(n)` if mined `n` deep,
    /// `None` if not found (e.g. dropped/replaced). Used by fee-bump loops to stop once a
    /// claim/refund confirms. The default returns `Some(1)` so watchers (and test mocks) that
    /// don't track confirmations treat a broadcast as immediately final and don't spin.
    fn tx_confirmations(&self, spk: &Script, txid: &Txid) -> Result<Option<u32>> {
        let _ = (spk, txid);
        Ok(Some(1))
    }
}

#[cfg(feature = "electrum")]
mod electrum;
#[cfg(feature = "electrum")]
pub use electrum::ElectrumWatcher;
