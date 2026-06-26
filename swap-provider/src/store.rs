//! Crash-safe persistence of in-flight swaps so a restarted provider can resume driving them.
//!
//! Each non-terminal swap is written to its own JSON file under `<data_dir>/swaps/<id>.json`.
//! A record holds the minimum needed to rebuild a [`crate::reverse::ReverseSwap`] /
//! [`crate::submarine::SubmarineSwap`] and re-spawn its driver: the HTLC script, the branch
//! secret key, the funding outpoint (once known), and routing/counterparty details. The
//! Lightning **preimage is never persisted** — it is recovered live from the on-chain claim
//! (reverse) or the invoice payment (submarine).

use anyhow::{anyhow, Context, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use swap_common::htlc::{htlc_p2wsh_address, PaymentHash};
use swap_common::{NetworkSpec, SwapDirection, SwapState};
use uuid::Uuid;

/// A persisted in-flight swap. Bitcoin types are stored as hex/strings because the `bitcoin`
/// crate is built without its `serde` feature here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    pub swap_id: Uuid,
    pub direction: SwapDirection,
    /// Counterparty pubky, used to send the final `SwapStatusUpdate` after resume.
    pub peer: String,
    pub network: NetworkSpec,

    // --- HTLC / spend reconstruction ---
    pub payment_hash_hex: String,
    pub onchain_amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    /// HTLC redeem script (hex). The P2WSH scriptPubKey is derived from this + `network`.
    pub htlc_script_hex: String,
    pub timeout_height: u32,
    /// The branch secret key (refund key for reverse, claim key for submarine), 32-byte hex.
    pub secret_key_hex: String,
    /// Hold invoice (reverse) or the invoice to pay (submarine).
    pub invoice: String,
    /// Submarine only: routing-fee cap (msat) for paying the invoice.
    pub max_routing_fee_msat: u64,

    // --- progress / idempotency ---
    pub required_confirmations: u32,
    /// Set once the HTLC funding outpoint is known, so a resumed driver never re-funds.
    pub funding_txid_hex: Option<String>,
    pub funding_vout: Option<u32>,
    pub state: SwapState,
}

impl SwapRecord {
    /// Reconstruct the branch secret key.
    pub fn secret_key(&self) -> Result<SecretKey> {
        let bytes = hex::decode(&self.secret_key_hex).context("decode secret_key_hex")?;
        SecretKey::from_slice(&bytes).map_err(|e| anyhow!("parse secret key: {e}"))
    }

    /// Reconstruct the HTLC redeem script.
    pub fn htlc_script(&self) -> Result<ScriptBuf> {
        ScriptBuf::from_hex(&self.htlc_script_hex).map_err(|e| anyhow!("parse htlc script: {e}"))
    }

    /// The HTLC P2WSH scriptPubKey, derived from the redeem script + network.
    pub fn htlc_spk(&self) -> Result<ScriptBuf> {
        let script = self.htlc_script()?;
        Ok(htlc_p2wsh_address(&script, self.network.to_bitcoin_network()).script_pubkey())
    }

    /// Reconstruct the 32-byte payment hash.
    pub fn payment_hash(&self) -> Result<PaymentHash> {
        let bytes = hex::decode(&self.payment_hash_hex).context("decode payment_hash_hex")?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("payment hash must be 32 bytes"))
    }

    /// The funding outpoint, if it has been recorded.
    pub fn funding_outpoint(&self) -> Option<OutPoint> {
        let txid = Txid::from_str(self.funding_txid_hex.as_ref()?).ok()?;
        Some(OutPoint {
            txid,
            vout: self.funding_vout?,
        })
    }
}

/// Persistent store of in-flight swaps.
pub trait SwapStore: Send + Sync {
    /// Insert or overwrite a record (called on swap start and on each transition).
    fn put(&self, rec: &SwapRecord) -> Result<()>;
    /// All non-terminal records, used on startup to resume.
    fn load_active(&self) -> Result<Vec<SwapRecord>>;
    /// Drop a record once its swap reaches a terminal state.
    fn remove(&self, swap_id: Uuid) -> Result<()>;
}

/// A directory-of-JSON-files [`SwapStore`]: one `<dir>/<swap_id>.json` per swap.
pub struct JsonFileSwapStore {
    dir: PathBuf,
}

impl JsonFileSwapStore {
    /// Open (creating if needed) a store rooted at `dir`.
    pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).with_context(|| format!("create swap store dir {dir:?}"))?;
        Ok(Self { dir })
    }

    fn path_for(&self, swap_id: Uuid) -> PathBuf {
        self.dir.join(format!("{swap_id}.json"))
    }
}

impl SwapStore for JsonFileSwapStore {
    fn put(&self, rec: &SwapRecord) -> Result<()> {
        let path = self.path_for(rec.swap_id);
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(rec).context("serialize swap record")?;
        // Write to a temp file then rename, so a crash mid-write can't corrupt the record.
        fs::write(&tmp, &bytes).with_context(|| format!("write {tmp:?}"))?;
        fs::rename(&tmp, &path).with_context(|| format!("rename into {path:?}"))?;
        Ok(())
    }

    fn load_active(&self) -> Result<Vec<SwapRecord>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir).with_context(|| format!("read dir {:?}", self.dir))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("skipping unreadable swap record {path:?}: {e}");
                    continue;
                }
            };
            match serde_json::from_slice::<SwapRecord>(&bytes) {
                Ok(rec) if !rec.state.is_terminal() => out.push(rec),
                Ok(_) => {} // terminal records that weren't cleaned up; ignore
                Err(e) => tracing::warn!("skipping unparsable swap record {path:?}: {e}"),
            }
        }
        Ok(out)
    }

    fn remove(&self, swap_id: Uuid) -> Result<()> {
        let path = self.path_for(swap_id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow!("remove {path:?}: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use swap_common::htlc::{build_htlc_script, generate_preimage, payment_hash};
    use swap_common::random_keypair;

    fn temp_dir() -> PathBuf {
        // A unique, isolated directory under the system temp dir (no Math.random needed: the
        // swap_id is unique per call).
        let id = Uuid::new_v4();
        std::env::temp_dir().join(format!("pubky-swap-store-test-{id}"))
    }

    #[test]
    fn record_round_trips_through_the_store() {
        let secp = Secp256k1::new();
        let (refund_sk, _refund_pk) = random_keypair(&secp);
        let (_c_sk, claim_pk) = random_keypair(&secp);
        let (_r2, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, 800_000);
        let outpoint = OutPoint {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            vout: 1,
        };

        let rec = SwapRecord {
            swap_id: Uuid::new_v4(),
            direction: SwapDirection::Reverse,
            peer: "peer-pubky".into(),
            network: NetworkSpec::Regtest,
            payment_hash_hex: hex::encode(ph),
            onchain_amount_sat: 100_000,
            fee_rate_sat_vb: 5,
            htlc_script_hex: hex::encode(script.as_bytes()),
            timeout_height: 800_000,
            secret_key_hex: hex::encode(refund_sk.secret_bytes()),
            invoice: "lnbcrt-mock".into(),
            max_routing_fee_msat: 0,
            required_confirmations: 1,
            funding_txid_hex: Some(outpoint.txid.to_string()),
            funding_vout: Some(outpoint.vout),
            state: SwapState::LockupConfirmed,
        };

        let dir = temp_dir();
        let store = JsonFileSwapStore::new(&dir).unwrap();
        store.put(&rec).unwrap();

        let loaded = store.load_active().unwrap();
        assert_eq!(loaded.len(), 1);
        let got = &loaded[0];
        // The branch key, script, and outpoint reconstruct exactly.
        assert_eq!(
            got.secret_key().unwrap().secret_bytes(),
            refund_sk.secret_bytes()
        );
        assert_eq!(got.htlc_script().unwrap(), script);
        assert_eq!(got.funding_outpoint(), Some(outpoint));
        assert_eq!(got.payment_hash().unwrap(), ph);

        // Terminal records are not returned as active.
        let mut done = rec.clone();
        done.state = SwapState::Claimed;
        store.put(&done).unwrap();
        assert!(store.load_active().unwrap().is_empty());

        // Removal is idempotent.
        store.remove(rec.swap_id).unwrap();
        store.remove(rec.swap_id).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
