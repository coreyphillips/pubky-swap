//! [`OnchainWallet`] over beignet's HTTP daemon.

use crate::blocking::BlockingBridge;
use crate::http::{BeignetHttp, Retry};
use crate::types::*;
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, Txid};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::ChainWatcher;
use swap_common::wallet::OnchainWallet;
use swap_common::{Result, SwapError};
use tracing::{debug, info, warn};

pub struct BeignetWallet {
    http: Arc<BeignetHttp>,
    bridge: BlockingBridge,
    network: Network,
    /// Resolved once at construction, because `receive_destination` is infallible and is called
    /// from async code with no bridge available.
    receive_spk: ScriptBuf,
    fee_rate_sat_vb: u64,
    /// Used only to recover a funding outpoint if `/send` ever stops returning the raw
    /// transaction. The provider always has a watcher, so wiring it through costs nothing.
    chain: Option<Arc<dyn ChainWatcher>>,
}

impl BeignetWallet {
    pub async fn connect(
        http: Arc<BeignetHttp>,
        network: Network,
        fee_rate_sat_vb: u64,
        chain: Option<Arc<dyn ChainWatcher>>,
    ) -> std::result::Result<Self, String> {
        let addr: AddressResponse = http
            .post("/address/new", &serde_json::json!({}), Retry::Safe)
            .await
            .map_err(|e| e.to_string())?;
        let receive_spk = parse_address(&addr.address, network)?;
        let bridge = BlockingBridge::new(Duration::from_secs(180)).map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            bridge,
            network,
            receive_spk,
            fee_rate_sat_vb,
            chain,
        })
    }

    /// A fresh, previously-unused sweep destination.
    pub async fn fresh_receive_spk(&self) -> std::result::Result<ScriptBuf, String> {
        let addr: AddressResponse = self
            .http
            .post("/address/new", &serde_json::json!({}), Retry::Safe)
            .await
            .map_err(|e| e.to_string())?;
        parse_address(&addr.address, self.network)
    }

    /// Confirmed on-chain balance, for the provider's preflight.
    pub async fn onchain_balance_sat(&self) -> std::result::Result<u64, String> {
        let balance: BalanceResponse =
            self.http.get("/balance").await.map_err(|e| e.to_string())?;
        Ok(balance.onchain)
    }
}

fn parse_address(addr: &str, network: Network) -> std::result::Result<ScriptBuf, String> {
    let parsed = Address::from_str(addr).map_err(|e| format!("parse address {addr}: {e}"))?;
    // The wrong network here would mean sweeping funds to an address on another chain.
    let checked = parsed
        .require_network(network)
        .map_err(|e| format!("address {addr} is not valid on {network:?}: {e}"))?;
    Ok(checked.script_pubkey())
}

impl OnchainWallet for BeignetWallet {
    fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint> {
        // `/send` takes an address, not a script, so the HTLC's P2WSH script has to be
        // addressable. Every script this engine builds is.
        let address = Address::from_script(htlc_spk, self.network)
            .map_err(|e| SwapError::Permanent(format!("HTLC script is not addressable: {e}")))?
            .to_string();

        let http = self.http.clone();
        let spk = htlc_spk.clone();
        let rate = self.fee_rate_sat_vb;
        let response: SendResponse = self.bridge.call(async move {
            http.post(
                "/send",
                &SendRequest {
                    address,
                    amount_sats: amount_sat,
                    sats_per_vbyte: rate,
                },
                // Never retried. beignet does not honour an idempotency key on `/send`
                // (beignet#745), so a repeat after a lost response would spend twice.
                Retry::Never,
            )
            .await
        })??;

        let txid = Txid::from_str(&response.txid)
            .map_err(|e| SwapError::Permanent(format!("beignet returned a bad txid: {e}")))?;

        // The raw transaction is the direct answer: find the output paying our script with the
        // right value. Matching on *both* is stricter than matching the script alone, and closes
        // the case where change happens to pay the same script.
        if let Some(hex_str) = response.hex.as_ref().filter(|h| !h.is_empty()) {
            let raw = hex::decode(hex_str)
                .map_err(|e| SwapError::Permanent(format!("decode funding tx: {e}")))?;
            let tx: Transaction = bitcoin::consensus::deserialize(&raw)
                .map_err(|e| SwapError::Permanent(format!("parse funding tx: {e}")))?;
            if tx.txid() != txid {
                return Err(SwapError::Permanent(
                    "the transaction beignet returned does not match the txid it reported".into(),
                ));
            }
            let vout = tx
                .output
                .iter()
                .position(|o| o.script_pubkey == spk && o.value == amount_sat)
                .ok_or_else(|| {
                    SwapError::Permanent(format!(
                        "no output in {txid} pays {amount_sat} sat to the HTLC script"
                    ))
                })? as u32;
            info!("beignet funded the HTLC at {txid}:{vout}");
            return Ok(OutPoint { txid, vout });
        }

        // Fallback for a daemon that stops returning the transaction: find it on chain. The money
        // has already moved at this point, so failing here would strand it; the outpoint is worth
        // waiting for.
        warn!("beignet returned no raw transaction for {txid}; locating the output on chain");
        let chain = self.chain.as_ref().ok_or_else(|| {
            SwapError::Permanent(
                "beignet returned no raw transaction and no chain watcher is configured, so the \
                 funding outpoint cannot be determined"
                    .into(),
            )
        })?;
        for _ in 0..30 {
            if let Ok(outputs) = chain.find_outputs(htlc_spk) {
                if let Some(u) = outputs
                    .iter()
                    .find(|u| u.outpoint.txid == txid && u.value_sat == amount_sat)
                {
                    return Ok(u.outpoint);
                }
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        Err(SwapError::transient(
            "locating the beignet funding output",
            format!("{txid} did not appear paying {amount_sat} sat within 30s"),
        ))
    }

    fn receive_destination(&self) -> ScriptBuf {
        self.receive_spk.clone()
    }

    fn spendable_balance_sat(&self) -> Result<Option<u64>> {
        let http = self.http.clone();
        let balance: BalanceResponse = self
            .bridge
            .call(async move { http.get("/balance").await })??;
        Ok(Some(balance.onchain))
    }

    fn cpfp_bump(&self, parent: OutPoint, fee_rate_sat_vb: u64) -> Result<Option<Txid>> {
        // `/tx/boost` does RBF where it can and CPFP otherwise. A claim or refund is a
        // transaction beignet did not send, so it cannot replace it; it takes the CPFP path,
        // which is exactly what is wanted here.
        let http = self.http.clone();
        let txid = parent.txid.to_string();
        let result: std::result::Result<BoostResult, _> = self.bridge.call(async move {
            // Make sure the daemon has seen the transaction paying our address before asking it
            // to bump one.
            let _: std::result::Result<serde_json::Value, _> = http
                .post("/wallet/refresh", &serde_json::json!({}), Retry::Safe)
                .await;
            http.post(
                "/tx/boost",
                &BoostRequest {
                    txid,
                    sats_per_vbyte: fee_rate_sat_vb,
                },
                Retry::Never,
            )
            .await
        })?;

        match result {
            Ok(boost) => {
                info!(
                    "beignet bumped {parent} via {} -> {}",
                    boost.boost_type.as_deref().unwrap_or("unknown"),
                    boost.txid
                );
                Ok(Txid::from_str(&boost.txid).ok())
            }
            // Both callers treat this as best-effort, so an error and a `None` are handled
            // identically. Returning `Ok(None)` with a log is the honest shape.
            Err(e) => {
                debug!("beignet could not bump {parent}: {e}");
                Ok(None)
            }
        }
    }
}
