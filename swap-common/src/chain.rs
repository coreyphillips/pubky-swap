//! Chain observation needed to drive a swap: find the funding UTXO, count confirmations,
//! learn the tip height (for timeouts), and broadcast claim/refund transactions.
//!
//! The trait is synchronous because the Electrum client is blocking; async callers wrap these in
//! [`run_blocking`] so they don't stall the runtime. An [`ElectrumWatcher`] implementation is
//! provided behind the `electrum` feature.

use crate::error::Result;
use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};

/// A confirmation count large enough that any finality check treats a transaction as final.
///
/// This exists **for tests**, and only for tests. It used to be the default return value of
/// `tx_confirmations`, which meant any watcher that forgot to override that method reported
/// every transaction as buried a million blocks deep: every finality check passed instantly, the
/// fee-bump loop returned on its first poll, and reorg detection was silently off. Convenient for
/// mocks, catastrophic for anything real, and nothing about the type system said so.
///
/// The trait methods are required now. A mock that genuinely does not care about depth can say so
/// explicitly by returning this.
pub const ASSUMED_FINAL_CONFIRMATIONS: u32 = 1_000_000;

/// Run a blocking [`ChainWatcher`] call without stalling the async runtime.
///
/// The watcher methods are synchronous (the Electrum client blocks), so calling them directly in an
/// async driver would block a runtime worker. On a multi-threaded runtime this uses
/// `block_in_place`, which signals the runtime to keep other tasks progressing on sibling workers;
/// on a current-thread runtime (e.g. `#[tokio::test]`, or no runtime at all) it just runs inline,
/// since `block_in_place` would panic there. Borrowed data is fine — nothing needs to be `'static`.
pub fn run_blocking<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// A confirmed-or-mempool funding output of an HTLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingUtxo {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    /// 0 while unconfirmed (in the mempool).
    pub confirmations: u32,
}

/// An output that has paid an HTLC script at some point, whether or not it is still unspent.
///
/// [`FundingUtxo`] answers "what can still be spent", which is the right question while a swap is
/// running and the wrong one when a restarted driver asks whether it already funded. A
/// counterparty that has claimed leaves nothing unspent, so "no UTXO" and "never funded" look
/// identical, and they call for opposite actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalOutput {
    pub outpoint: OutPoint,
    pub value_sat: u64,
    /// 0 while unconfirmed (in the mempool).
    pub confirmations: u32,
    /// The transaction that spent it, if it has been spent.
    pub spent_by: Option<Txid>,
}

/// Minimal chain access for the swap state machine. `Send + Sync` so a watcher can be shared
/// (behind `Arc`) with spawned per-swap driver tasks.
pub trait ChainWatcher: Send + Sync {
    /// Current best block height.
    fn tip_height(&self) -> Result<u32>;

    /// Find an unspent output paying exactly `expected_value_sat` to `spk` (the HTLC P2WSH
    /// scriptPubKey), if one exists.
    ///
    /// Prefer [`find_outputs`](ChainWatcher::find_outputs) plus [`select_funding`] for anything
    /// that is about to act on the result: this reports "nothing" for an underpayment, an
    /// overpayment, and a double payment alike, which are three different situations.
    fn find_funding(&self, spk: &Script, expected_value_sat: u64) -> Result<Option<FundingUtxo>>;

    /// Every unspent output paying `spk`, whatever its value.
    ///
    /// The caller classifies them with [`select_funding`]. Separating "what is there" from "is it
    /// what we expected" is what lets a driver tell an underpayment from an empty address.
    fn find_outputs(&self, spk: &Script) -> Result<Vec<FundingUtxo>>;

    /// Every output that has *ever* paid `spk`, including ones already spent.
    ///
    /// This is the resume question, and only history can answer it. A provider that broadcast a
    /// funding transaction and crashed before recording its outpoint comes back knowing only that
    /// a funding *may* exist. [`find_outputs`](ChainWatcher::find_outputs) reports nothing both
    /// when the broadcast never happened and when the counterparty has already claimed, and
    /// funding again in the second case hands them a second HTLC they hold the preimage for.
    ///
    /// Required, not defaulted: a watcher that answered `Ok(vec![])` here would put the driver
    /// back on exactly the branch this exists to prevent.
    fn find_historical_outputs(&self, spk: &Script) -> Result<Vec<HistoricalOutput>>;

    /// Whether this specific outpoint is still unspent, and how deep.
    ///
    /// Once a funding has been chosen it is pinned: every later check asks about that outpoint
    /// rather than re-running a value match, which could otherwise silently switch to a different
    /// output after a reorg.
    fn outpoint_status(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<FundingUtxo>>;

    /// Find the transaction (if any) that spends `outpoint`. Used to detect the
    /// counterparty's claim (so the preimage can be recovered) or refund. `spk` is the
    /// HTLC scriptPubKey, used to scan history.
    fn find_spend(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<Transaction>>;

    /// Broadcast a transaction, returning its txid.
    fn broadcast(&self, tx: &Transaction) -> Result<Txid>;

    /// Estimate the fee rate (sat/vB) to confirm within `target_blocks`. `Ok(None)` means the
    /// backend has no estimate (e.g. on regtest, where `estimatefee` returns the `-1` sentinel),
    /// in which case callers fall back to their configured fee floor.
    ///
    /// Required, not defaulted. A silent `Ok(None)` here means every spend is priced at the
    /// operator's floor no matter what the mempool is doing, which is not a decision a watcher
    /// should be able to make by omission.
    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>>;

    /// Confirmations of transaction `txid` (which we expect spends one of our outputs, hence the
    /// `spk` to scan its history): `Some(0)` if still in the mempool, `Some(n)` if mined `n` deep,
    /// `None` if not found (dropped, reorged out, or beaten by a conflicting spend).
    ///
    /// Required, not defaulted: this is the measurement every finality check is built on.
    fn tx_confirmations(&self, spk: &Script, txid: &Txid) -> Result<Option<u32>>;

    /// Block hash at `height` in the watcher's best chain (`None` if the height is unknown or
    /// above the tip). A previously-seen height whose hash changed means the chain reorganized at
    /// or below it.
    ///
    /// Required, not defaulted: a watcher that quietly returns `None` here has reorg detection
    /// switched off, which is not something to arrive at by forgetting a method.
    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>>;

    /// Cheap liveness probe, used by startup checks to fail loudly on an unreachable backend
    /// rather than at the first swap.
    fn health_check(&self) -> Result<()> {
        self.tip_height().map(|_| ())
    }
}

/// What was found paying an HTLC's scriptPubKey.
///
/// `find_funding` used to answer with the first unspent output whose value matched **exactly**,
/// which quietly conflated several very different situations. An HTLC address is public from the
/// moment it is in a `SwapAccept`, so anyone can pay it; a counterparty can overpay, underpay, or
/// pay twice; and a single "no funding yet" answer covered all of them. Naming them means a
/// driver can refuse to act on the ones that are not safe instead of waiting forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingSelection {
    /// Nothing paying this script yet.
    None,
    /// Exactly the expected amount.
    Exact(FundingUtxo),
    /// More than expected, within tolerance. Safe to proceed: the surplus is swept along with
    /// the rest, and refusing would strand it.
    Overpaid { utxo: FundingUtxo, excess_sat: u64 },
    /// Less than expected. Never safe to act on: the counterparty has not put up what the swap
    /// is priced on.
    Underpaid { got_sat: u64 },
    /// So far over that it is more likely a mistake than a tip. Left for the timeout to refund.
    ExcessiveOverpay { got_sat: u64 },
    /// Several outputs pay this script. The spend builders take a single input, so this is
    /// refused rather than half-handled; the counterparty refunds at the timeout.
    Multiple(Vec<FundingUtxo>),
}

/// Pick which historical output to drive, out of those that could be a swap's funding.
///
/// More than one is possible: an HTLC address is public from the moment it is in a `SwapAccept`,
/// and a resumed run that funded twice would leave two. The spend builders take a single input, so
/// only one can be driven, and the one to prefer is whichever the counterparty claimed: its spend
/// carries the preimage, which is what settles the Lightning leg.
///
/// `Ok(None)` means nothing here could be this swap's funding.
pub fn select_recorded_funding(
    chain: &dyn ChainWatcher,
    htlc_spk: &Script,
    payment_hash: &[u8; 32],
    expected_sat: u64,
    history: &[HistoricalOutput],
) -> Result<Option<OutPoint>> {
    let mut candidates: Vec<&HistoricalOutput> = history
        .iter()
        .filter(|h| h.value_sat == expected_sat)
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }
    // Deepest first, so the choice does not change with the order a server happens to return.
    candidates.sort_by(|a, b| {
        b.confirmations
            .cmp(&a.confirmations)
            .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
            .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
    });

    if candidates.len() > 1 {
        for c in &candidates {
            let Some(tx) = chain.find_spend(htlc_spk, &c.outpoint)? else {
                continue;
            };
            if crate::onchain::extract_preimage(&tx, &c.outpoint, payment_hash).is_some() {
                return Ok(Some(c.outpoint));
            }
        }
    }
    Ok(Some(candidates[0].outpoint))
}

/// How much overpayment to accept before treating it as a mistake.
pub const DEFAULT_MAX_OVERPAY_SAT: u64 = 10_000;

/// Classify the outputs paying an HTLC script against what the swap expects.
pub fn select_funding(
    utxos: &[FundingUtxo],
    expected_sat: u64,
    max_overpay_sat: u64,
) -> FundingSelection {
    match utxos.len() {
        0 => return FundingSelection::None,
        1 => {}
        _ => return FundingSelection::Multiple(utxos.to_vec()),
    }
    let utxo = utxos[0].clone();
    match utxo.value_sat.cmp(&expected_sat) {
        std::cmp::Ordering::Equal => FundingSelection::Exact(utxo),
        std::cmp::Ordering::Less => FundingSelection::Underpaid {
            got_sat: utxo.value_sat,
        },
        std::cmp::Ordering::Greater => {
            let excess = utxo.value_sat - expected_sat;
            if excess <= max_overpay_sat {
                FundingSelection::Overpaid {
                    utxo,
                    excess_sat: excess,
                }
            } else {
                FundingSelection::ExcessiveOverpay {
                    got_sat: utxo.value_sat,
                }
            }
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod mock;

#[cfg(feature = "electrum")]
mod electrum;
#[cfg(feature = "electrum")]
pub use electrum::{ElectrumConfig, ElectrumWatcher};

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn utxo(value_sat: u64, vout: u32) -> FundingUtxo {
        FundingUtxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([vout as u8; 32]),
                vout,
            },
            value_sat,
            confirmations: 1,
        }
    }

    /// `find_funding` answered with the first unspent output matching **exactly**, so an
    /// underpayment, an overpayment, and a double payment all looked identical to an address
    /// nobody had paid. An HTLC address is public from the moment it is in a `SwapAccept`, so
    /// those are not hypothetical.
    #[test]
    fn funding_outcomes_are_told_apart() {
        let expected = 100_000;
        let tol = DEFAULT_MAX_OVERPAY_SAT;

        assert_eq!(select_funding(&[], expected, tol), FundingSelection::None);
        assert!(matches!(
            select_funding(&[utxo(expected, 0)], expected, tol),
            FundingSelection::Exact(_)
        ));

        // Short by a satoshi: never safe to act on, because the swap is priced on the full
        // amount. This used to be indistinguishable from "not funded yet", so a driver would
        // wait out the whole timeout instead of saying what was wrong.
        assert_eq!(
            select_funding(&[utxo(expected - 1, 0)], expected, tol),
            FundingSelection::Underpaid {
                got_sat: expected - 1
            }
        );

        // A small overpayment is safe: it is swept along with the rest, and refusing would
        // strand it.
        match select_funding(&[utxo(expected + 500, 0)], expected, tol) {
            FundingSelection::Overpaid { excess_sat, .. } => assert_eq!(excess_sat, 500),
            other => panic!("expected an accepted overpayment, got {other:?}"),
        }
        // At the tolerance exactly.
        assert!(matches!(
            select_funding(&[utxo(expected + tol, 0)], expected, tol),
            FundingSelection::Overpaid { .. }
        ));
        // Beyond it, more likely a mistake than a tip; leave it to the timeout refund.
        assert!(matches!(
            select_funding(&[utxo(expected + tol + 1, 0)], expected, tol),
            FundingSelection::ExcessiveOverpay { .. }
        ));

        // Two payments to the same public address. The spend builders take one input, so this is
        // refused rather than half-handled.
        match select_funding(&[utxo(expected, 0), utxo(expected, 1)], expected, tol) {
            FundingSelection::Multiple(v) => assert_eq!(v.len(), 2),
            other => panic!("expected multiple outputs, got {other:?}"),
        }
    }
}
