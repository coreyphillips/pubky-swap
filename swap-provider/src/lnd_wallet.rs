//! An [`OnchainWallet`] backed by LND's own on-chain wallet (feature `lnd`).
//!
//! Instead of a separate BDK wallet + seed, the provider funds reverse-swap HTLCs straight from
//! LND's on-chain balance and sweeps claims/refunds back into it. The claim/refund transactions are
//! still built and signed by the swap engine (they spend via the HTLC branch keys, not LND's keys);
//! LND is only used for the plain funding send and to supply a sweep address.
//!
//! `OnchainWallet` is synchronous but LND's gRPC is async, so calls are bridged onto the running
//! Tokio runtime: the future is `spawn`ed and the (blocking) trait method waits on a channel. This
//! is safe because the drivers already invoke wallet methods via `chain::run_blocking`
//! (`block_in_place`), so blocking the calling worker doesn't stall the runtime.

use anyhow::anyhow;
use bitcoin::{Address, OutPoint, ScriptBuf, Transaction};
use lightning_backend::{LndBackend, LndConfig};
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use swap_common::wallet::OnchainWallet;
use swap_common::{Result, SwapError};

/// LND's minimum relay fee rate (sat per 1000 weight units).
const MIN_SAT_PER_KW: i64 = 253;

pub struct LndWallet {
    backend: Arc<LndBackend>,
    receive_spk: ScriptBuf,
    fee_rate_sat_vb: u64,
}

impl LndWallet {
    /// Connect to LND and cache a sweep address. `fee_rate_sat_vb` is the rate used for HTLC
    /// funding sends.
    pub async fn connect(config: LndConfig, fee_rate_sat_vb: u64) -> anyhow::Result<Self> {
        let backend = Arc::new(
            LndBackend::connect(config)
                .await
                .map_err(|e| anyhow!("LND connect: {e}"))?,
        );
        let addr = backend
            .new_address()
            .await
            .map_err(|e| anyhow!("LND new_address: {e}"))?;
        let receive_spk =
            parse_address_spk(&addr).map_err(|e| anyhow!("LND sweep address: {e}"))?;
        Ok(Self {
            backend,
            receive_spk,
            fee_rate_sat_vb,
        })
    }
}

impl OnchainWallet for LndWallet {
    fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint> {
        let backend = self.backend.clone();
        let pk_script = htlc_spk.to_bytes();
        let spk = htlc_spk.clone();
        let sat_per_kw = sat_per_kw(self.fee_rate_sat_vb);
        block_on(async move {
            let raw = backend
                .send_outputs(pk_script, amount_sat as i64, sat_per_kw)
                .await
                .map_err(|e| SwapError::Other(format!("LND send_outputs: {e}")))?;
            let tx: Transaction = bitcoin::consensus::deserialize(&raw)
                .map_err(|e| SwapError::Other(format!("decode LND funding tx: {e}")))?;
            funding_outpoint(&tx, &spk)
                .ok_or_else(|| SwapError::Other("funding output not found in LND tx".into()))
        })
    }

    fn receive_destination(&self) -> ScriptBuf {
        self.receive_spk.clone()
    }

    // cpfp_bump uses the trait default (None): claim/refund are RBF-bumped by the swap engine; a
    // CPFP path via LND's BumpFee is a possible future addition.
}

/// Parse an LND-supplied address into its scriptPubKey, trusting the node's own network.
fn parse_address_spk(addr: &str) -> std::result::Result<ScriptBuf, String> {
    Address::from_str(addr)
        .map_err(|e| e.to_string())
        .map(|a| a.assume_checked().script_pubkey())
}

/// Convert a sat/vB rate to LND's `sat_per_kw` (sat per 1000 weight units): 1 vByte = 4 WU, so
/// 1000 WU = 250 vBytes. Floored at LND's minimum relay rate.
fn sat_per_kw(fee_rate_sat_vb: u64) -> i64 {
    (fee_rate_sat_vb.saturating_mul(250) as i64).max(MIN_SAT_PER_KW)
}

/// Locate the output of `tx` paying `spk` and return its outpoint.
fn funding_outpoint(tx: &Transaction, spk: &ScriptBuf) -> Option<OutPoint> {
    tx.output
        .iter()
        .position(|o| &o.script_pubkey == spk)
        .map(|vout| OutPoint {
            txid: tx.txid(),
            vout: vout as u32,
        })
}

/// Bridge a `Send + 'static` future onto the running Tokio runtime, blocking the caller until it
/// completes. Safe under `block_in_place` (the drivers' `run_blocking`); errors if no runtime.
fn block_on<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                let _ = tx.send(fut.await);
            });
        }
        Err(_) => {
            return Err(SwapError::Other(
                "LndWallet requires a Tokio runtime".into(),
            ))
        }
    }
    rx.recv()
        .map_err(|e| SwapError::Other(format!("LND wallet worker dropped: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::TxOut;

    #[test]
    fn finds_the_funding_output() {
        let spk = ScriptBuf::from_hex(
            "0020abababababababababababababababababababababababababababababababab",
        )
        .unwrap();
        let other = ScriptBuf::from_hex("0014cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap();
        let tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: 1000,
                    script_pubkey: other,
                },
                TxOut {
                    value: 50_000,
                    script_pubkey: spk.clone(),
                },
            ],
        };
        let op = funding_outpoint(&tx, &spk).expect("must find the output");
        assert_eq!(op.vout, 1);
        assert_eq!(op.txid, tx.txid());
        // A script we didn't pay isn't found.
        let missing = ScriptBuf::from_hex("0014ffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(funding_outpoint(&tx, &missing).is_none());
    }

    #[test]
    fn sat_per_kw_conversion_and_floor() {
        assert_eq!(sat_per_kw(10), 2500); // 10 sat/vB -> 2500 sat/kw
        assert_eq!(sat_per_kw(5), 1250);
        assert_eq!(sat_per_kw(1), 253); // 250 < 253 floor
        assert_eq!(sat_per_kw(0), 253);
    }
}
