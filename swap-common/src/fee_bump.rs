//! Replace-by-fee bumping and reorg-resilient confirmation for HTLC claim/refund spends.
//!
//! Claim and refund transactions are built RBF-signalling (see [`crate::onchain`]). Under mempool
//! congestion a spend at the initial fee may not confirm before its deadline (a claim races the
//! counterparty's refund timeout; a refund must land before funds are otherwise stuck), so
//! [`confirm_or_bump`] keeps it confirming: while it sits in the mempool it re-broadcasts at a
//! higher fee; if it is dropped or **reorged out** after confirming it re-broadcasts at the current
//! fee; and it only returns once the spend is buried `min_confirmations` deep (reorg-safe).

use crate::chain::{run_blocking, ChainWatcher};
use crate::error::Result;
use crate::onchain::{bumped_fee_rate, resolve_fee_rate};
use bitcoin::{Script, Transaction, Txid};
use std::time::Duration;
use tracing::{debug, warn};

/// Default cap on the number of RBF fee bumps for a single claim/refund spend.
pub const MAX_FEE_BUMPS: u32 = 10;

/// Broadcast a spend and keep it confirming under fee pressure and across reorgs.
///
/// - `build(rate)` produces the signed spend for a fee rate (sat/vB); it returns an error when the
///   fee would push the output below dust, which ends fee escalation gracefully.
/// - `fee_target_blocks` / `floor_rate_sat_vb` size the initial fee; `max_bumps` caps fee bumps.
/// - `min_confirmations` is the depth at which the spend is considered final (reorg-safe).
///
/// Returns the txid of the confirmed spend.
#[allow(clippy::too_many_arguments)]
pub async fn confirm_or_bump(
    chain: &dyn ChainWatcher,
    htlc_spk: &Script,
    fee_target_blocks: u16,
    floor_rate_sat_vb: u64,
    poll: Duration,
    max_bumps: u32,
    min_confirmations: u32,
    mut build: impl FnMut(u64) -> Result<Transaction>,
) -> Result<Txid> {
    let est = run_blocking(|| chain.estimate_fee_rate(fee_target_blocks)).unwrap_or(None);
    let mut rate = resolve_fee_rate(est, floor_rate_sat_vb);
    let initial = build(rate)?;
    let mut txid = run_blocking(|| chain.broadcast(&initial))?;
    let mut bumps = 0u32;
    let mut had_confirmation = false;

    loop {
        match run_blocking(|| chain.tx_confirmations(htlc_spk, &txid))? {
            // Buried deep enough — final.
            Some(c) if c >= min_confirmations => return Ok(txid),
            // Dropped from mempool and chain. If it had confirmed, a reorg orphaned it; either
            // way, get it back in at the current fee.
            None => {
                if had_confirmation {
                    warn!("spend {txid} disappeared after confirming (reorg?); re-broadcasting");
                } else {
                    debug!("spend {txid} dropped from mempool; re-broadcasting");
                }
                let tx = build(rate)?;
                if let Ok(id) = run_blocking(|| chain.broadcast(&tx)) {
                    txid = id;
                }
            }
            // In the mempool (not yet mined): consider an RBF fee bump.
            Some(0) => {
                if bumps < max_bumps {
                    let est =
                        run_blocking(|| chain.estimate_fee_rate(fee_target_blocks)).unwrap_or(None);
                    let next_rate = bumped_fee_rate(rate, est);
                    // `build` errors only if the higher fee would dust the output — then we can't
                    // raise it any further, so let the current tx ride.
                    if next_rate > rate {
                        if let Ok(replacement) = build(next_rate) {
                            if let Ok(id) = run_blocking(|| chain.broadcast(&replacement)) {
                                debug!("fee-bumped spend -> {id} at {next_rate} sat/vB");
                                txid = id;
                                rate = next_rate;
                                bumps += 1;
                            }
                        }
                    }
                }
            }
            // Mined but not yet final — just wait for more confirmations.
            Some(_) => had_confirmation = true,
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::FundingUtxo;
    use bitcoin::absolute::LockTime;
    use bitcoin::{OutPoint, Transaction, TxOut};
    use std::sync::Mutex;

    /// A chain mock that walks the broadcast tx through a scripted sequence of confirmation
    /// states (one per `tx_confirmations` call), and offers a fee estimate.
    struct ScriptedChain {
        confs: Vec<Option<u32>>,
        idx: Mutex<usize>,
        broadcasts: Mutex<Vec<Txid>>,
        estimate: Option<u64>,
    }
    impl ScriptedChain {
        fn new(confs: Vec<Option<u32>>, estimate: Option<u64>) -> Self {
            Self {
                confs,
                idx: Mutex::new(0),
                broadcasts: Mutex::new(Vec::new()),
                estimate,
            }
        }
    }
    impl ChainWatcher for ScriptedChain {
        fn tip_height(&self) -> Result<u32> {
            Ok(100)
        }
        fn find_funding(&self, _: &Script, _: u64) -> Result<Option<FundingUtxo>> {
            Ok(None)
        }
        fn find_spend(&self, _: &Script, _: &OutPoint) -> Result<Option<Transaction>> {
            Ok(None)
        }
        fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
            let txid = tx.txid();
            self.broadcasts.lock().unwrap().push(txid);
            Ok(txid)
        }
        fn estimate_fee_rate(&self, _t: u16) -> Result<Option<u64>> {
            Ok(self.estimate)
        }
        fn tx_confirmations(&self, _: &Script, _: &Txid) -> Result<Option<u32>> {
            let mut i = self.idx.lock().unwrap();
            let v = *self.confs.get(*i).unwrap_or(self.confs.last().unwrap());
            *i += 1;
            Ok(v)
        }
    }

    fn tx_paying(value: u64) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value,
                script_pubkey: bitcoin::ScriptBuf::from_hex(
                    "0014abababababababababababababababababababab",
                )
                .unwrap(),
            }],
        }
    }

    fn spk() -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap()
    }

    #[tokio::test]
    async fn bumps_while_in_mempool_then_finalizes() {
        // Mempool (0) for two checks, then 2 confirmations (>= min). No estimate → +25% bumps.
        let chain = ScriptedChain::new(vec![Some(0), Some(0), Some(2)], None);
        confirm_or_bump(
            &chain,
            spk().as_script(),
            3,
            5,
            Duration::from_millis(0),
            10,
            2,
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        // initial broadcast + at least one bump while in mempool.
        assert!(chain.broadcasts.lock().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn rebroadcasts_when_reorged_out() {
        // Confirms (1), then disappears (None = reorged out), then finalizes (2).
        let chain = ScriptedChain::new(vec![Some(1), None, Some(2)], Some(50));
        confirm_or_bump(
            &chain,
            spk().as_script(),
            3,
            5,
            Duration::from_millis(0),
            10,
            2,
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        // initial broadcast + a re-broadcast after the reorg dropped it.
        assert!(
            chain.broadcasts.lock().unwrap().len() >= 2,
            "must re-broadcast after a reorg drops the confirmed spend"
        );
    }

    #[tokio::test]
    async fn returns_immediately_when_already_final() {
        let chain = ScriptedChain::new(vec![Some(6)], Some(50));
        confirm_or_bump(
            &chain,
            spk().as_script(),
            3,
            5,
            Duration::from_millis(0),
            10,
            2,
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        assert_eq!(
            chain.broadcasts.lock().unwrap().len(),
            1,
            "no bumps once final"
        );
    }
}
