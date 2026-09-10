//! A scriptable [`ChainWatcher`] for tests.
//!
//! This exists because the trait's methods used to have defaults, and those defaults were not
//! neutral: `tx_confirmations` returned a million, so any watcher that did not override it
//! reported every transaction as final on the first poll, and `block_hash_at` returned `None`,
//! which silently switches reorg detection off. Both were there so a hand-rolled test mock could
//! implement four methods instead of seven, and the price was that a production watcher could
//! make either mistake by omission.
//!
//! The methods are required now, and this is what pays for that: one mock every test can
//! configure, instead of six that each answered a different subset.
//!
//! Behaviour a test does not configure is the *safe* answer, not the convenient one. An
//! unconfigured `tx_confirmations` reports "not found" rather than "buried forever", so a test
//! that forgets to script a confirmation sees a loop that keeps trying, which is what production
//! would do.

use super::{ChainWatcher, FundingUtxo, HistoricalOutput};
use crate::error::Result;
use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};
use std::collections::HashMap;
use std::sync::Mutex;

/// A chain whose every answer is set by the test.
#[derive(Default)]
pub struct MockChain {
    tip: Mutex<u32>,
    outputs: Mutex<Vec<FundingUtxo>>,
    /// Outputs that paid the script and have since been spent. Unspent ones do not need listing
    /// here: they are derived from `outputs`, so a test only names what it wants to be gone.
    spent_outputs: Mutex<Vec<HistoricalOutput>>,
    spend: Mutex<Option<Transaction>>,
    /// Consumed one entry per `tx_confirmations` call; the last entry repeats.
    confirmations: Mutex<Vec<Option<u32>>>,
    confirmation_idx: Mutex<usize>,
    estimate: Mutex<Option<u64>>,
    block_hashes: Mutex<HashMap<u32, BlockHash>>,
    broadcasts: Mutex<Vec<Transaction>>,
    /// When set, every broadcast after the first fails, to exercise the CPFP fallback.
    reject_replacements: Mutex<bool>,
    /// Consumed one entry per `tip_height` call, the last repeating. Empty means `tip` is fixed.
    ///
    /// Blocks arrive while a driver runs, and some of what a driver decides depends on where the
    /// tip is *at that moment*: whether there is still a window to act in, and whether a timeout
    /// has passed. A fixed tip can only model one of those per test.
    tips: Mutex<Vec<u32>>,
    tip_idx: Mutex<usize>,
}

impl MockChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tip(self, height: u32) -> Self {
        *self.tip.lock().unwrap() = height;
        self
    }

    pub fn with_funding(self, utxo: FundingUtxo) -> Self {
        self.outputs.lock().unwrap().push(utxo);
        self
    }

    pub fn with_outputs(self, utxos: Vec<FundingUtxo>) -> Self {
        *self.outputs.lock().unwrap() = utxos;
        self
    }

    /// An output that paid the HTLC script and has already been spent, so it appears in the
    /// chain's history but in no UTXO set. This is the shape a resumed driver has to survive.
    pub fn with_spent_output(self, outpoint: OutPoint, value_sat: u64, spent_by: Txid) -> Self {
        self.spent_outputs.lock().unwrap().push(HistoricalOutput {
            outpoint,
            value_sat,
            confirmations: 1,
            spent_by: Some(spent_by),
        });
        self
    }

    pub fn with_spend(self, tx: Transaction) -> Self {
        *self.spend.lock().unwrap() = Some(tx);
        self
    }

    /// Script the tip, one height per `tip_height` call, the last repeating.
    ///
    /// Use it when a driver has to see the chain advance: funding while the window is open and
    /// then reaching the timeout, for instance, which is two different answers to the same call.
    pub fn with_tips(self, seq: Vec<u32>) -> Self {
        *self.tips.lock().unwrap() = seq;
        self
    }

    /// Script the confirmation answers, one per call, the last repeating.
    pub fn with_confirmations(self, seq: Vec<Option<u32>>) -> Self {
        *self.confirmations.lock().unwrap() = seq;
        self
    }

    /// Report this transaction as final on every check.
    pub fn always_final(self) -> Self {
        self.with_confirmations(vec![Some(super::ASSUMED_FINAL_CONFIRMATIONS)])
    }

    pub fn with_fee_estimate(self, sat_per_vb: Option<u64>) -> Self {
        *self.estimate.lock().unwrap() = sat_per_vb;
        self
    }

    pub fn with_block_hash(self, height: u32, hash: BlockHash) -> Self {
        self.block_hashes.lock().unwrap().insert(height, hash);
        self
    }

    pub fn rejecting_replacements(self) -> Self {
        *self.reject_replacements.lock().unwrap() = true;
        self
    }

    pub fn set_tip(&self, height: u32) {
        *self.tip.lock().unwrap() = height;
    }

    pub fn set_spend(&self, tx: Option<Transaction>) {
        *self.spend.lock().unwrap() = tx;
    }

    pub fn set_block_hash(&self, height: u32, hash: BlockHash) {
        self.block_hashes.lock().unwrap().insert(height, hash);
    }

    pub fn broadcasts(&self) -> Vec<Transaction> {
        self.broadcasts.lock().unwrap().clone()
    }

    pub fn broadcast_count(&self) -> usize {
        self.broadcasts.lock().unwrap().len()
    }
}

impl ChainWatcher for MockChain {
    fn tip_height(&self) -> Result<u32> {
        let tips = self.tips.lock().unwrap();
        if tips.is_empty() {
            return Ok(*self.tip.lock().unwrap());
        }
        let mut idx = self.tip_idx.lock().unwrap();
        let height = tips[(*idx).min(tips.len() - 1)];
        *idx += 1;
        Ok(height)
    }

    fn find_funding(&self, _spk: &Script, expected_value_sat: u64) -> Result<Option<FundingUtxo>> {
        Ok(self
            .outputs
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.value_sat == expected_value_sat)
            .cloned())
    }

    fn find_outputs(&self, _spk: &Script) -> Result<Vec<FundingUtxo>> {
        Ok(self.outputs.lock().unwrap().clone())
    }

    fn find_historical_outputs(&self, _spk: &Script) -> Result<Vec<HistoricalOutput>> {
        // Anything still unspent is also part of the history, so a test that scripts a UTXO gets
        // a coherent answer here without saying so twice.
        let mut all: Vec<HistoricalOutput> = self
            .outputs
            .lock()
            .unwrap()
            .iter()
            .map(|u| HistoricalOutput {
                outpoint: u.outpoint,
                value_sat: u.value_sat,
                confirmations: u.confirmations,
                spent_by: None,
            })
            .collect();
        for spent in self.spent_outputs.lock().unwrap().iter() {
            if let Some(existing) = all.iter_mut().find(|h| h.outpoint == spent.outpoint) {
                *existing = spent.clone();
            } else {
                all.push(spent.clone());
            }
        }
        Ok(all)
    }

    fn outpoint_status(&self, _spk: &Script, outpoint: &OutPoint) -> Result<Option<FundingUtxo>> {
        Ok(self
            .outputs
            .lock()
            .unwrap()
            .iter()
            .find(|u| &u.outpoint == outpoint)
            .cloned())
    }

    fn find_spend(&self, _spk: &Script, _outpoint: &OutPoint) -> Result<Option<Transaction>> {
        Ok(self.spend.lock().unwrap().clone())
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let mut b = self.broadcasts.lock().unwrap();
        b.push(tx.clone());
        if *self.reject_replacements.lock().unwrap() && b.len() > 1 {
            return Err(crate::error::SwapError::Other(
                "replacement rejected".into(),
            ));
        }
        Ok(tx.compute_txid_compat())
    }

    fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<Option<u64>> {
        Ok(*self.estimate.lock().unwrap())
    }

    fn tx_confirmations(&self, _spk: &Script, _txid: &Txid) -> Result<Option<u32>> {
        let seq = self.confirmations.lock().unwrap();
        if seq.is_empty() {
            // Not configured: "we cannot see it", which keeps a caller trying rather than
            // letting it believe an unscripted transaction is buried.
            return Ok(None);
        }
        let mut idx = self.confirmation_idx.lock().unwrap();
        let v = *seq.get(*idx).unwrap_or_else(|| seq.last().unwrap());
        *idx += 1;
        Ok(v)
    }

    fn block_hashes_from(&self, start_height: u32, count: u16) -> Result<Vec<BlockHash>> {
        let tip = *self.tip.lock().unwrap();
        let hashes = self.block_hashes.lock().unwrap();
        let mut out = Vec::new();
        for h in start_height..start_height.saturating_add(u32::from(count)) {
            if h > tip {
                break;
            }
            match hashes.get(&h) {
                Some(hash) => out.push(*hash),
                // A height the test did not script is a gap, and the monitor must not read a gap
                // as a changed hash. Stopping is the honest answer: the range came back short.
                None => break,
            }
        }
        Ok(out)
    }

    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>> {
        if height > *self.tip.lock().unwrap() {
            return Ok(None);
        }
        Ok(self.block_hashes.lock().unwrap().get(&height).copied())
    }
}

/// A chain that answers every call with a transient failure until it is told to recover.
///
/// This is the whole of what a backend outage looks like from inside a driver: not a special code
/// path, just every call returning [`SwapError::Transient`](crate::error::SwapError::Transient)
/// until the server is back. Wrapping a [`MockChain`] rather than replacing it keeps the recovered
/// behaviour exactly the behaviour the other tests exercise.
pub struct FlakyChain<C> {
    inner: C,
    /// Failures left to serve. `u32::MAX` is an outage with no end scripted.
    remaining: Mutex<u32>,
    /// Calls that were failed, so a test can show the outage was real.
    failed_calls: Mutex<u32>,
}

impl<C: ChainWatcher> FlakyChain<C> {
    /// A chain that fails its next `failures` calls.
    pub fn new(inner: C, failures: u32) -> Self {
        Self {
            inner,
            remaining: Mutex::new(failures),
            failed_calls: Mutex::new(0),
        }
    }

    /// The backend comes back.
    pub fn recover(&self) {
        *self.remaining.lock().unwrap() = 0;
    }

    /// The chain underneath, for the assertions a test makes about it.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// How many calls the outage has failed.
    pub fn failed_calls(&self) -> u32 {
        *self.failed_calls.lock().unwrap()
    }

    fn gate(&self) -> Result<()> {
        let mut remaining = self.remaining.lock().unwrap();
        if *remaining == 0 {
            return Ok(());
        }
        *remaining = remaining.saturating_sub(1);
        let mut failed = self.failed_calls.lock().unwrap();
        *failed += 1;
        Err(crate::error::SwapError::transient(
            "electrum",
            "connection refused",
        ))
    }
}

impl<C: ChainWatcher> ChainWatcher for FlakyChain<C> {
    fn tip_height(&self) -> Result<u32> {
        self.gate()?;
        self.inner.tip_height()
    }
    fn find_funding(&self, spk: &Script, expected_value_sat: u64) -> Result<Option<FundingUtxo>> {
        self.gate()?;
        self.inner.find_funding(spk, expected_value_sat)
    }
    fn find_outputs(&self, spk: &Script) -> Result<Vec<FundingUtxo>> {
        self.gate()?;
        self.inner.find_outputs(spk)
    }
    fn find_historical_outputs(&self, spk: &Script) -> Result<Vec<HistoricalOutput>> {
        self.gate()?;
        self.inner.find_historical_outputs(spk)
    }
    fn outpoint_status(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<FundingUtxo>> {
        self.gate()?;
        self.inner.outpoint_status(spk, outpoint)
    }
    fn find_spend(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<Transaction>> {
        self.gate()?;
        self.inner.find_spend(spk, outpoint)
    }
    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        self.gate()?;
        self.inner.broadcast(tx)
    }
    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>> {
        self.gate()?;
        self.inner.estimate_fee_rate(target_blocks)
    }
    fn tx_confirmations(&self, spk: &Script, txid: &Txid) -> Result<Option<u32>> {
        self.gate()?;
        self.inner.tx_confirmations(spk, txid)
    }
    fn block_hashes_from(&self, start_height: u32, count: u16) -> Result<Vec<BlockHash>> {
        self.gate()?;
        self.inner.block_hashes_from(start_height, count)
    }
    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>> {
        self.gate()?;
        self.inner.block_hash_at(height)
    }
}

/// Bridged the `txid()` / `compute_txid()` rename across `bitcoin` versions. The rename has since
/// happened, and the shim did its job: this is the one place the mock needed touching.
trait TxidCompat {
    fn compute_txid_compat(&self) -> Txid;
}

impl TxidCompat for Transaction {
    fn compute_txid_compat(&self) -> Txid {
        self.compute_txid()
    }
}
