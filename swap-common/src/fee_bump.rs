//! Replace-by-fee bumping for HTLC claim/refund spends.
//!
//! Claim and refund transactions are built RBF-signalling (see [`crate::onchain`]). Under mempool
//! congestion a spend at the initial fee may not confirm before its deadline (a claim races the
//! counterparty's refund timeout; a refund must land before funds are otherwise stuck), so
//! [`confirm_or_bump`] keeps it confirming: it re-broadcasts the same spend at a higher fee until
//! it is mined, the fee can't be raised any further (the swept output would hit dust), or a bump
//! limit is reached.

use crate::chain::ChainWatcher;
use crate::error::Result;
use crate::onchain::{bumped_fee_rate, resolve_fee_rate};
use bitcoin::{Script, Transaction, Txid};
use std::time::Duration;
use tracing::{debug, warn};

/// Default cap on the number of RBF bumps for a single claim/refund spend.
pub const MAX_FEE_BUMPS: u32 = 10;

/// Broadcast a spend and keep it confirming under fee pressure.
///
/// - `build(rate)` produces the signed spend for a fee rate (sat/vB); it returns an error when the
///   fee would push the output below dust, which ends escalation gracefully.
/// - `fee_target_blocks` / `floor_rate_sat_vb` size the initial fee (a live estimate clamped to the
///   floor); `max_bumps` caps how many times the fee is raised.
///
/// Returns the txid of the last broadcast spend (best effort if it hasn't confirmed by `max_bumps`).
pub async fn confirm_or_bump(
    chain: &dyn ChainWatcher,
    htlc_spk: &Script,
    fee_target_blocks: u16,
    floor_rate_sat_vb: u64,
    poll: Duration,
    max_bumps: u32,
    mut build: impl FnMut(u64) -> Result<Transaction>,
) -> Result<Txid> {
    let est = chain.estimate_fee_rate(fee_target_blocks).unwrap_or(None);
    let mut rate = resolve_fee_rate(est, floor_rate_sat_vb);
    let mut txid = chain.broadcast(&build(rate)?)?;
    let mut bumps = 0u32;

    loop {
        if let Some(confirmations) = chain.tx_confirmations(htlc_spk, &txid)? {
            if confirmations >= 1 {
                return Ok(txid);
            }
        }
        if bumps >= max_bumps {
            return Ok(txid); // best effort — stop escalating, let the last tx ride
        }

        tokio::time::sleep(poll).await;

        let est = chain.estimate_fee_rate(fee_target_blocks).unwrap_or(None);
        let next_rate = bumped_fee_rate(rate, est);
        if next_rate <= rate {
            continue; // already at the cap — keep waiting on the current tx
        }
        match build(next_rate) {
            Ok(replacement) => match chain.broadcast(&replacement) {
                Ok(id) => {
                    debug!("fee-bumped spend {txid} -> {id} at {next_rate} sat/vB");
                    txid = id;
                    rate = next_rate;
                    bumps += 1;
                }
                Err(e) => warn!("fee-bump re-broadcast rejected (keeping current tx): {e}"),
            },
            // Can't raise the fee any further without dusting the output; the current tx is our
            // best shot.
            Err(_) => return Ok(txid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::FundingUtxo;
    use bitcoin::absolute::LockTime;
    use bitcoin::{OutPoint, Transaction, TxOut};
    use std::sync::Mutex;

    /// A chain mock that reports the broadcast tx as unconfirmed for the first `confirm_after`
    /// polls, then confirmed — and always offers a rising fee estimate so bumps are warranted.
    struct BumpChain {
        confirm_after: u32,
        checks: Mutex<u32>,
        broadcasts: Mutex<Vec<Txid>>,
        estimate: Option<u64>,
    }

    impl ChainWatcher for BumpChain {
        fn tip_height(&self) -> Result<u32> {
            Ok(100)
        }
        fn find_funding(&self, _spk: &Script, _v: u64) -> Result<Option<FundingUtxo>> {
            Ok(None)
        }
        fn find_spend(&self, _spk: &Script, _o: &OutPoint) -> Result<Option<Transaction>> {
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
        fn tx_confirmations(&self, _spk: &Script, _txid: &Txid) -> Result<Option<u32>> {
            let mut c = self.checks.lock().unwrap();
            *c += 1;
            Ok(Some(if *c > self.confirm_after { 1 } else { 0 }))
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

    #[tokio::test]
    async fn bumps_until_confirmed() {
        // Unconfirmed for the first 2 checks, then confirmed. Each build encodes the fee rate in
        // the output value so successive bumps produce distinct txids.
        let chain = BumpChain {
            confirm_after: 2,
            checks: Mutex::new(0),
            broadcasts: Mutex::new(Vec::new()),
            estimate: None, // force the +25% minimum bump path
        };
        let spk =
            bitcoin::ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap();

        let txid = confirm_or_bump(
            &chain,
            spk.as_script(),
            3,
            5,
            Duration::from_millis(0),
            10,
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();

        let broadcasts = chain.broadcasts.lock().unwrap();
        // One initial broadcast + bumps while unconfirmed; the returned txid is the last one.
        assert!(broadcasts.len() >= 2, "expected at least one bump");
        assert_eq!(*broadcasts.last().unwrap(), txid);
    }

    #[tokio::test]
    async fn returns_immediately_when_first_check_is_confirmed() {
        let chain = BumpChain {
            confirm_after: 0, // confirmed on the very first check
            checks: Mutex::new(0),
            broadcasts: Mutex::new(Vec::new()),
            estimate: Some(50),
        };
        let spk =
            bitcoin::ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap();

        confirm_or_bump(
            &chain,
            spk.as_script(),
            3,
            5,
            Duration::from_millis(0),
            10,
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();

        assert_eq!(
            chain.broadcasts.lock().unwrap().len(),
            1,
            "no bumps once confirmed"
        );
    }
}
