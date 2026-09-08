//! Crash-safe persistence of in-flight swaps, so a restart can resume driving them.
//!
//! Both sides need this, and for the same reason: a swap commits funds to a script that only one
//! key can move on each branch, and that key exists nowhere else. Losing it does not fail the
//! swap, it destroys the money. The provider holds the refund key for a reverse swap and the
//! claim key for a submarine one; the client holds the mirror of each.
//!
//! Each non-terminal swap is written to its own JSON file under `<data_dir>/swaps/<id>.json`,
//! holding the minimum needed to rebuild the swap and re-enter its driver: the HTLC script, the
//! branch secret key, the funding outpoint once known, and routing/counterparty details.
//!
//! The Lightning **preimage is not persisted** on the provider side: it is recovered live from
//! the on-chain claim. A reverse-swap *client* does persist it, because there it is not a secret
//! recoverable from anywhere else -- it is the client's own, generated before the swap began, and
//! without it the client cannot claim the coins it has already paid for.

use crate::htlc::{htlc_p2wsh_address, PaymentHash};
use crate::{NetworkSpec, SwapDirection, SwapState};
use anyhow::{anyhow, Context, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

/// Which side of a swap a record belongs to.
///
/// The two roles hold opposite branch keys, so a record is only meaningful alongside the role
/// that wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SwapRole {
    #[default]
    Provider,
    Client,
}

/// A persisted in-flight swap. Bitcoin types are stored as hex/strings because the `bitcoin`
/// crate is built without its `serde` feature here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    pub swap_id: Uuid,
    /// Which side wrote this record. Absent on records written before roles existed, which were
    /// all the provider's.
    #[serde(default)]
    pub role: SwapRole,
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

    // --- intent markers ---
    //
    // Each of these is written *before* the act it names. A crash in the gap then leaves a
    // marker saying "this may have happened, go and check" rather than nothing, which is the
    // difference between a resumed driver finding an existing funding and funding a second one.
    /// Set immediately before a funding transaction is broadcast, cleared once its outpoint is
    /// known. Present with no outpoint means a funding may exist that we never recorded.
    #[serde(default)]
    pub funding_intent_at_height: Option<u32>,
    /// How many funding attempts have been started, so a resume loop cannot fund repeatedly.
    #[serde(default)]
    pub funding_attempts: u32,
    /// Set immediately before an invoice payment is attempted. Present means a payment may be in
    /// flight, so a resumed driver asks the node rather than paying again.
    #[serde(default)]
    pub invoice_pay_started_at_unix: Option<u64>,
    /// The counterparty spend that revealed the preimage, if one has been seen. The preimage is
    /// never persisted; it is re-extracted from this transaction on chain.
    #[serde(default)]
    pub claim_observed_txid_hex: Option<String>,
    /// Our own claim or refund, once broadcast.
    #[serde(default)]
    pub spend_txid_hex: Option<String>,

    // --- client-side recovery ---
    /// The client's preimage, for a reverse swap.
    ///
    /// Persisted only by the client, and only in that direction, because there it is not
    /// recoverable from anywhere else: the client generates it before the swap begins, and
    /// without it the client cannot claim coins it has already paid for. The provider learns its
    /// preimage from the chain or from its own payment, so it never writes one.
    #[serde(default)]
    pub preimage_hex: Option<String>,
    /// Where swept funds go. Pinned at the start so RBF replacements and resumed drivers all pay
    /// the same place.
    #[serde(default)]
    pub dest_spk_hex: Option<String>,
    /// The total the client agreed to in the quote, so a resumed driver funds that rather than
    /// re-reading a number from the counterparty.
    #[serde(default)]
    pub quote_total_sat: u64,

    // --- diagnostics ---
    /// The most recent driver failure, for the operator.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Consecutive transient failures, bounding the retry loop.
    #[serde(default)]
    pub retry_count: u32,
    #[serde(default)]
    pub updated_at_unix: u64,
}

impl SwapRecord {
    /// Zeroed progress/diagnostic fields, so a constructor can name only the swap's own details.
    pub fn new_progress() -> Self {
        Self {
            swap_id: Uuid::nil(),
            role: SwapRole::Provider,
            direction: SwapDirection::Reverse,
            peer: String::new(),
            network: NetworkSpec::Regtest,
            payment_hash_hex: String::new(),
            onchain_amount_sat: 0,
            fee_rate_sat_vb: 0,
            htlc_script_hex: String::new(),
            timeout_height: 0,
            secret_key_hex: String::new(),
            invoice: String::new(),
            max_routing_fee_msat: 0,
            required_confirmations: 0,
            funding_txid_hex: None,
            funding_vout: None,
            state: SwapState::Created,
            funding_intent_at_height: None,
            funding_attempts: 0,
            invoice_pay_started_at_unix: None,
            claim_observed_txid_hex: None,
            spend_txid_hex: None,
            preimage_hex: None,
            dest_spk_hex: None,
            quote_total_sat: 0,
            last_error: None,
            retry_count: 0,
            updated_at_unix: 0,
        }
    }

    /// Reconstruct the preimage, when this record carries one.
    pub fn preimage(&self) -> Result<Option<[u8; 32]>> {
        let Some(hex_str) = self.preimage_hex.as_ref() else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_str).context("decode preimage_hex")?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("preimage must be 32 bytes"))?;
        Ok(Some(arr))
    }

    /// Reconstruct the pinned sweep destination, when this record carries one.
    pub fn dest_spk(&self) -> Result<Option<ScriptBuf>> {
        let Some(hex_str) = self.dest_spk_hex.as_ref() else {
            return Ok(None);
        };
        Ok(Some(
            ScriptBuf::from_hex(hex_str).map_err(|e| anyhow!("parse dest_spk: {e}"))?,
        ))
    }

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
///
/// There is deliberately no `remove`. A record is the only thing standing between a funded HTLC
/// and funds nobody is watching, so deleting one is never the right reaction to a failure --
/// and when `remove` existed, the driver called it on *every* return, including errors. One
/// momentary Electrum failure on a funded swap deleted the record, so the refund was never
/// attempted and the coins sat until someone reconstructed the key by hand.
///
/// Terminal records are written, not deleted, and cleaned up later by [`SwapStore::prune_terminal`].
pub trait SwapStore: Send + Sync {
    /// Insert or overwrite a record (called on swap start and on each transition).
    fn put(&self, rec: &SwapRecord) -> Result<()>;
    /// One record by id, if it exists.
    fn get(&self, swap_id: Uuid) -> Result<Option<SwapRecord>>;
    /// All non-terminal records, used on startup to resume.
    fn load_active(&self) -> Result<Vec<SwapRecord>>;
    /// Record a swap's terminal state. Keeps the record for audit rather than deleting it.
    fn mark_terminal(&self, rec: &SwapRecord) -> Result<()>;
    /// Delete terminal records older than `retain`, returning how many were removed. Called only
    /// by a background sweeper, never by a driver.
    fn prune_terminal(&self, retain: Duration) -> Result<usize>;
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
        // The directory holds branch secret keys, so keep it to the owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)) {
                tracing::warn!("could not restrict permissions on {dir:?}: {e}");
            }
        }
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

        // Write to a temp file, fsync it, then rename. The rename is what makes the update
        // atomic against a crash; the fsync is what makes it durable against power loss. Without
        // the fsync the rename can land while the data behind it has not, which is the one case
        // where a "crash-safe" write leaves an empty record for a funded HTLC.
        //
        // 0600 because the record carries the branch secret key: whoever holds it can move the
        // HTLC funds on the branch this swap owns.
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).with_context(|| format!("open {tmp:?}"))?;
            f.write_all(&bytes)
                .with_context(|| format!("write {tmp:?}"))?;
            f.sync_all().with_context(|| format!("fsync {tmp:?}"))?;
        }
        fs::rename(&tmp, &path).with_context(|| format!("rename into {path:?}"))?;
        // Make the rename itself durable, so the record survives power loss and not merely a
        // process crash.
        if let Ok(dir) = fs::File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn get(&self, swap_id: Uuid) -> Result<Option<SwapRecord>> {
        let path = self.path_for(swap_id);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).with_context(|| format!("parse {path:?}"))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!("read {path:?}: {e}")),
        }
    }

    fn mark_terminal(&self, rec: &SwapRecord) -> Result<()> {
        debug_assert!(rec.state.is_terminal(), "mark_terminal on a live swap");
        self.put(rec)
    }

    fn prune_terminal(&self, retain: Duration) -> Result<usize> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.dir).with_context(|| format!("read dir {:?}", self.dir))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else { continue };
            let Ok(rec) = serde_json::from_slice::<SwapRecord>(&bytes) else {
                // Unparsable records are never pruned: a record we cannot read may still be a
                // live swap, and deleting it would strand whatever it was watching.
                continue;
            };
            if !rec.state.is_terminal() {
                continue;
            }
            let age = fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok());
            if age.is_some_and(|a| a >= retain) && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{build_htlc_script, generate_preimage, payment_hash};
    use crate::random_keypair;
    use bitcoin::secp256k1::Secp256k1;

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
            ..SwapRecord::new_progress()
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

        // Fetching one by id round-trips too.
        assert_eq!(
            store.get(rec.swap_id).unwrap().unwrap().swap_id,
            rec.swap_id
        );
        assert!(store.get(Uuid::new_v4()).unwrap().is_none());

        // Terminal records are not returned as active, but are retained.
        let mut done = rec.clone();
        done.state = SwapState::Claimed;
        store.mark_terminal(&done).unwrap();
        assert!(store.load_active().unwrap().is_empty());
        assert!(store.get(rec.swap_id).unwrap().is_some());

        // A terminal record younger than the retention window is kept, not pruned.
        assert_eq!(store.prune_terminal(Duration::from_secs(3600)).unwrap(), 0);
        assert!(store.get(rec.swap_id).unwrap().is_some());

        // Past the window it is swept.
        assert_eq!(store.prune_terminal(Duration::ZERO).unwrap(), 1);
        assert!(store.get(rec.swap_id).unwrap().is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    /// A live record must never be pruned, however old it is. Pruning one would strand whatever
    /// it was watching.
    #[test]
    fn pruning_never_touches_a_live_record() {
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(&dir).unwrap();
        let mut rec = SwapRecord::new_progress();
        rec.swap_id = Uuid::new_v4();
        rec.state = SwapState::LockupConfirmed;
        store.put(&rec).unwrap();

        assert_eq!(store.prune_terminal(Duration::ZERO).unwrap(), 0);
        assert_eq!(store.load_active().unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The record carries a branch secret key, so it must not be world-readable.
    #[cfg(unix)]
    #[test]
    fn records_are_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(&dir).unwrap();
        let mut rec = SwapRecord::new_progress();
        rec.swap_id = Uuid::new_v4();
        store.put(&rec).unwrap();

        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "the store directory must be owner-only");

        let path = dir.join(format!("{}.json", rec.swap_id));
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "records hold key material");
        let _ = fs::remove_dir_all(&dir);
    }
}
