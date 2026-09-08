//! An [`OnchainWallet`](swap_common::wallet::OnchainWallet) backed by LND's own on-chain wallet
//! (feature `lnd`).
//!
//! Lets a provider (or client) fund HTLCs and sweep claims/refunds from its LND node's on-chain
//! balance instead of a separate BDK seed. The claim/refund transactions are still built and signed
//! by the swap engine (they spend via the HTLC branch keys, not LND's keys); LND only does the
//! plain funding send and supplies a sweep address.
//!
//! `OnchainWallet` is synchronous but LND's gRPC is async, so calls are bridged onto the running
//! Tokio runtime: the future is `spawn`ed and the (blocking) trait method waits on a channel. This
//! is safe because the drivers invoke wallet methods via `chain::run_blocking` (`block_in_place`).

use crate::{LndBackend, LndConfig};
use bitcoin::{Address, OutPoint, ScriptBuf, Transaction, Txid};
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use swap_common::wallet::OnchainWallet;
use swap_common::{Result, SwapError};

/// LND's minimum relay fee rate (sat per 1000 weight units).
const MIN_SAT_PER_KW: i64 = 253;

pub struct LndWallet {
    backend: Arc<LndBackend>,
    /// A sweep destination resolved at connect time.
    ///
    /// `receive_destination` is infallible and is called from async code with no blocking
    /// bridge, so it cannot ask the node for a fresh address. It hands out this one, and callers
    /// that want a fresh address per swap use [`LndWallet::fresh_receive_spk`] before they start.
    receive_spk: ScriptBuf,
    fee_rate_sat_vb: u64,
}

impl LndWallet {
    /// Connect to LND and cache a sweep address. `fee_rate_sat_vb` is the rate used for HTLC
    /// funding sends.
    pub async fn connect(
        config: LndConfig,
        fee_rate_sat_vb: u64,
    ) -> std::result::Result<Self, String> {
        let backend = Arc::new(
            LndBackend::connect(config)
                .await
                .map_err(|e| e.to_string())?,
        );
        let addr = backend.new_address().await.map_err(|e| e.to_string())?;
        let receive_spk = parse_address_spk(&addr)?;
        Ok(Self {
            backend,
            receive_spk,
            fee_rate_sat_vb,
        })
    }
}

impl LndWallet {
    /// Ask the node for a fresh sweep address.
    ///
    /// The cached one is reused for every swap in a process's lifetime, which links an
    /// operator's whole book on chain to anyone watching. Callers that can afford an async call
    /// should take a fresh address per swap.
    pub async fn fresh_receive_spk(&self) -> std::result::Result<ScriptBuf, String> {
        let addr = self
            .backend
            .new_address()
            .await
            .map_err(|e| e.to_string())?;
        parse_address_spk(&addr)
    }
}

impl OnchainWallet for LndWallet {
    fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint> {
        let backend = self.backend.clone();
        let pk_script = htlc_spk.to_bytes();
        let spk = htlc_spk.clone();
        // A live estimate, floored at the operator's configured rate. Funding at a static floor
        // means a funding transaction that does not confirm when the mempool is busy, and a
        // counterparty waiting on an HTLC that never appears.
        let sat_per_kw = self.funding_sat_per_kw();
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

    fn cpfp_bump(&self, parent: OutPoint, fee_rate_sat_vb: u64) -> Result<Option<Txid>> {
        // The claim and refund transactions are built and signed by the swap engine, not by LND,
        // so LND cannot replace them. It can spend their output at a high fee and pull them in,
        // which is what `BumpFee` does for an output the wallet owns.
        //
        // Without this an `--wallet lnd` provider had no CPFP fallback at all, which is the
        // configuration the Umbrel packaging recommends precisely because it avoids a second seed.
        let backend = self.backend.clone();
        let txid = parent.txid.to_string();
        let vout = parent.vout;
        match block_on(async move {
            backend
                .bump_fee(&txid, vout, fee_rate_sat_vb)
                .await
                .map_err(|e| SwapError::transient("LND bump_fee", e))
        }) {
            Ok(()) => {
                // BumpFee reports success without naming the child transaction. The caller only
                // uses the txid for logging, and the fee has been bumped either way.
                Ok(None)
            }
            Err(e) => {
                tracing::debug!("LND could not CPFP {parent}: {e}");
                Ok(None)
            }
        }
    }
}

/// Parse an LND-supplied address into its scriptPubKey, trusting the node's own network.
fn parse_address_spk(addr: &str) -> std::result::Result<ScriptBuf, String> {
    Address::from_str(addr)
        .map_err(|e| e.to_string())
        .map(|a| a.assume_checked().script_pubkey())
}

impl LndWallet {
    /// The funding fee rate in LND's units: a live estimate where the node offers one, never
    /// below the operator's floor.
    fn funding_sat_per_kw(&self) -> i64 {
        let backend = self.backend.clone();
        let estimated = block_on(async move {
            backend
                .estimate_fee_sat_per_kw(3)
                .await
                .map_err(|e| SwapError::transient("LND fee estimate", e))
        })
        .ok()
        .flatten()
        .unwrap_or(0);
        estimated.max(sat_per_kw(self.fee_rate_sat_vb))
    }
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

/// How long to wait for a bridged call before giving up.
///
/// A bound is not optional here: without one, a runtime that stops polling leaves the caller
/// blocked on a channel receive that will never complete, with no log line and no way out.
const BRIDGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Bridge a `Send + 'static` future onto the running Tokio runtime, blocking the caller until it
/// completes.
///
/// This spawns onto the current runtime and blocks the calling thread on a channel, which is only
/// sound when some *other* thread can drive the spawned task. On a multi-thread runtime the
/// drivers' `run_blocking` uses `block_in_place`, which hands the worker off, so a sibling worker
/// runs it and the arrangement holds.
///
/// On a **current-thread** runtime it does not. `run_blocking` there runs the closure inline on
/// the only thread there is, so blocking it means the spawned task can never be polled: not an
/// error, a permanent deadlock, with nothing in the logs. That is a plausible configuration
/// (`#[tokio::test]` defaults to it), so it is refused explicitly rather than left to hang.
fn block_on<F, T>(fut: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    use tokio::runtime::RuntimeFlavor;

    let handle = match tokio::runtime::Handle::try_current() {
        Ok(h) => h,
        Err(_) => {
            return Err(SwapError::Permanent(
                "LndWallet requires a Tokio runtime".into(),
            ))
        }
    };
    if handle.runtime_flavor() != RuntimeFlavor::MultiThread {
        return Err(SwapError::Permanent(
            "LndWallet requires a multi-thread Tokio runtime; on a current-thread runtime the \
             blocking bridge would deadlock rather than fail"
                .into(),
        ));
    }

    let (tx, rx) = std::sync::mpsc::channel();
    handle.spawn(async move {
        let _ = tx.send(fut.await);
    });
    match rx.recv_timeout(BRIDGE_TIMEOUT) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(SwapError::transient(
            "LND wallet call",
            format!("no response within {BRIDGE_TIMEOUT:?}"),
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(SwapError::transient(
            "LND wallet call",
            "the worker task was dropped",
        )),
    }
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
        let missing = ScriptBuf::from_hex("0014ffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(funding_outpoint(&tx, &missing).is_none());
    }

    #[test]
    fn sat_per_kw_conversion_and_floor() {
        assert_eq!(sat_per_kw(10), 2500);
        assert_eq!(sat_per_kw(5), 1250);
        assert_eq!(sat_per_kw(1), 253);
        assert_eq!(sat_per_kw(0), 253);
    }
}
