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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
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

/// Immutable terms that identify the invoice belonging to one admitted reverse swap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingHoldInvoice {
    pub amount_msat: u64,
    pub expiry_secs: u64,
    pub cltv_expiry_delta: u32,
    /// Includes the persisted swap UUID so an unrelated invoice cannot be adopted.
    pub memo: String,
}

/// A persisted in-flight swap. Bitcoin types are stored as hex/strings because the `bitcoin`
/// crate is built without its `serde` feature here.
///
/// `Debug` is written by hand and redacts the branch key and preimage. A derived one would print
/// both, and this struct is exactly the sort of thing that ends up in a `warn!` while someone is
/// debugging a stuck swap.
#[derive(Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    /// The shape this record was written in.
    ///
    /// Every optional field here is `#[serde(default)]`, which is what lets an old record load
    /// into a new build. It is also what makes a *renamed* field load silently as its default,
    /// so a record holding a funding outpoint could come back holding none. This is the version
    /// that would make that loud instead.
    #[serde(default = "current_record_version")]
    pub record_version: u16,
    pub swap_id: Uuid,
    /// A reverse invoice creation intent persisted before its Lightning RPC.
    #[serde(default)]
    pub pending_hold_invoice: Option<PendingHoldInvoice>,
    /// Durable creation identity and public response, written before acceptance is sent.
    #[serde(default)]
    pub swap_request: Option<crate::messages::SwapRequest>,
    #[serde(default)]
    pub swap_accept: Option<crate::messages::SwapAccept>,
    /// Reconstructible Taproot parameters. Absent on legacy P2WSH records.
    #[serde(default)]
    pub taproot: Option<crate::taproot::BoltzTaprootSwap>,
    /// Which side wrote this record. Absent on records written before roles existed, which were
    /// all the provider's.
    #[serde(default)]
    pub role: SwapRole,
    pub direction: SwapDirection,
    /// Counterparty pubky, used to send the final `SwapStatusUpdate` after resume.
    pub peer: String,
    /// Account that authorized a delegated session key. Absent for root-key DM peers.
    #[serde(default)]
    pub peer_account: Option<String>,
    /// Application wallet namespace that authorized the delegated key.
    #[serde(default)]
    pub peer_authorization_scope: Option<String>,
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
    /// What this side charged for the service, from the quote it accepted.
    ///
    /// Realised revenue was recorded nowhere. `QuoteFee` splits it at quote time and the quote
    /// map holds it in memory, but quotes are single-use and pruned, so by the time a swap
    /// finished there was nothing left saying what it earned. Written at accept time, when it is
    /// still known and before anything can go wrong with the swap.
    #[serde(default)]
    pub service_fee_sat: u64,
    /// What this side expected the swap to cost it on chain, from the same quote. The difference
    /// between this and the service fee is the margin; the difference between this and what was
    /// actually spent is how good the estimate was.
    #[serde(default)]
    pub onchain_fee_sat: u64,

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
    /// How many funding attempts this swap has started.
    ///
    /// Not consulted by any decision: a driver refuses to fund on the presence of the intent
    /// marker alone, whatever the chain appears to show. This counts, and a value above one is
    /// evidence that invariant was broken.
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
    /// Our own claim or refund, once broadcast. The most recent one, for the operator.
    #[serde(default)]
    pub spend_txid_hex: Option<String>,
    /// Every claim or refund we have put on the wire for this swap, oldest first.
    ///
    /// One txid is not enough. A fee bump is a *different* transaction, so a run that bumped
    /// twice and then crashed leaves two of ours that could each still confirm, and a resumed
    /// driver that recognises only the last one reads the other as the counterparty's spend.
    /// Bounded by [`MAX_TRACKED_OUR_SPENDS`]: the oldest are long since replaced.
    #[serde(default)]
    pub our_spend_txids: Vec<String>,

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
    /// The lowest height at which a reorg was seen while this swap was in flight.
    ///
    /// Persisted because a reorg is exactly the kind of thing a process does not survive to act
    /// on: the monitor noticed, the operator restarted, and the fact was gone. A resumed driver
    /// reads this and re-validates rather than trusting what it wrote down before the fork.
    #[serde(default)]
    pub reorg_seen_at_height: Option<u32>,
    /// The most recent driver failure, for the operator. Cleared as soon as the swap moves on.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Consecutive failed driver runs, setting the backoff before the next one.
    #[serde(default)]
    pub retry_count: u32,
    /// When the next driver run is due, for a swap whose last one failed.
    ///
    /// Persisted because the backoff has to survive a restart. Without it a daemon coming back up
    /// during an outage re-enters every failing driver at once, which is how a backend that is
    /// still down gets hammered by the swaps waiting on it.
    #[serde(default)]
    pub next_retry_at_unix: Option<u64>,
    #[serde(default)]
    pub updated_at_unix: u64,
    /// When this swap was first written down, as opposed to when it last changed.
    ///
    /// There was only `updated_at_unix`, which answers "is this moving" and cannot answer "when
    /// did this start" or "how long did it take" -- so a history view could sort records but not
    /// describe them. Stamped once, by the store, on the first write of a record; a record from
    /// before this field existed loads with zero, which reads as unknown rather than as 1970.
    #[serde(default)]
    pub created_at_unix: u64,
}

/// Seconds since the epoch.
///
/// Duplicated privately in the provider and the client before this; the store needs one of its own
/// because it is the only thing that can stamp a record's creation time exactly once.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl std::fmt::Debug for SwapRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwapRecord")
            .field("swap_id", &self.swap_id)
            .field("role", &self.role)
            .field("direction", &self.direction)
            .field("peer", &self.peer)
            .field("network", &self.network)
            .field("payment_hash_hex", &self.payment_hash_hex)
            .field("onchain_amount_sat", &self.onchain_amount_sat)
            .field("timeout_height", &self.timeout_height)
            .field("secret_key_hex", &"<redacted>")
            .field(
                "preimage_hex",
                &self.preimage_hex.as_ref().map(|_| "<redacted>"),
            )
            .field("state", &self.state)
            .field("funding_txid_hex", &self.funding_txid_hex)
            .field("funding_vout", &self.funding_vout)
            .field("last_error", &self.last_error)
            .finish_non_exhaustive()
    }
}

/// What a restarted driver knows about a swap that was already in flight.
///
/// Every field is something a record wrote down *before* an irreversible act, and this is the
/// whole of what a driver is allowed to conclude from a previous run. It lives beside
/// [`SwapRecord`] rather than in either binary because both sides resume, both sides can fund an
/// HTLC, and a provider and a client that disagreed about what a marker means would each be right
/// about their own half of the same bug.
///
/// [`Resume::default`] is a fresh start, and a driver given one behaves exactly as it did before
/// any of this existed: the fields only ever narrow what a resumed driver is willing to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resume {
    /// The HTLC funding outpoint, once it was known.
    pub funding: Option<OutPoint>,
    /// The tip height at which a funding broadcast was about to be attempted, still set because
    /// no outpoint was ever recorded for it. Means "a funding may exist; go and look", and it is
    /// enough on its own: a driver that sees it will never fund, however empty the chain looks.
    pub funding_intent_at_height: Option<u32>,
    /// Claim or refund transactions an earlier run put on the wire.
    pub our_spends: Vec<Txid>,
    /// The lowest height at which a reorg was seen while this swap was in flight.
    ///
    /// A recorded funding outpoint is normally taken as established, because it was: something
    /// watched it confirm. A reorg is the one event that can make it untrue after the fact, so a
    /// driver that sees this goes back to the chain instead of trusting what it wrote down.
    pub reorg_seen_at_height: Option<u32>,
}

impl Resume {
    /// Whether this is a first run rather than a resumed one.
    pub fn is_fresh(&self) -> bool {
        *self == Self::default()
    }
}

/// The record shape this build writes.
pub const RECORD_VERSION: u16 = 1;

/// A record written before versioning is version 0, and every field it lacks is one this build
/// added with a default. That is exactly the compatibility `#[serde(default)]` already provides.
fn current_record_version() -> u16 {
    0
}

/// How many of our own claim/refund txids a record keeps.
///
/// Escalation replaces a transaction rather than adding one, so only the most recent handful can
/// still be in a mempool anywhere. This is a bound on a field that would otherwise grow with the
/// length of a stuck swap, not a judgement about how many matter.
pub const MAX_TRACKED_OUR_SPENDS: usize = 16;

impl SwapRecord {
    /// Zeroed progress/diagnostic fields, so a constructor can name only the swap's own details.
    pub fn new_progress() -> Self {
        Self {
            record_version: RECORD_VERSION,
            swap_id: Uuid::nil(),
            pending_hold_invoice: None,
            swap_request: None,
            swap_accept: None,
            taproot: None,
            role: SwapRole::Provider,
            direction: SwapDirection::Reverse,
            peer: String::new(),
            peer_account: None,
            peer_authorization_scope: None,
            network: NetworkSpec::Regtest,
            payment_hash_hex: String::new(),
            onchain_amount_sat: 0,
            fee_rate_sat_vb: 0,
            htlc_script_hex: String::new(),
            timeout_height: 0,
            secret_key_hex: String::new(),
            invoice: String::new(),
            max_routing_fee_msat: 0,
            service_fee_sat: 0,
            onchain_fee_sat: 0,
            required_confirmations: 0,
            funding_txid_hex: None,
            funding_vout: None,
            state: SwapState::Created,
            funding_intent_at_height: None,
            funding_attempts: 0,
            invoice_pay_started_at_unix: None,
            claim_observed_txid_hex: None,
            spend_txid_hex: None,
            our_spend_txids: Vec::new(),
            reorg_seen_at_height: None,
            preimage_hex: None,
            dest_spk_hex: None,
            quote_total_sat: 0,
            last_error: None,
            retry_count: 0,
            next_retry_at_unix: None,
            updated_at_unix: 0,
            created_at_unix: 0,
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
        if let Some(taproot) = &self.taproot {
            return Ok(taproot
                .address(self.network.to_bitcoin_network())
                .script_pubkey());
        }
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

    /// Record a claim or refund of ours, keeping the list bounded and free of repeats.
    pub fn note_our_spend(&mut self, txid: Txid) {
        let hex = txid.to_string();
        if !self.our_spend_txids.contains(&hex) {
            self.our_spend_txids.push(hex.clone());
            if self.our_spend_txids.len() > MAX_TRACKED_OUR_SPENDS {
                self.our_spend_txids.remove(0);
            }
        }
        self.spend_txid_hex = Some(hex);
    }

    /// The claim/refund transactions this swap has broadcast, for seeding the fee-bump loop.
    ///
    /// Unparsable entries are skipped rather than failing the call: a malformed txid can only
    /// make the loop treat one of our own transactions as a stranger's, which is the behaviour
    /// without any of this, and refusing to resume over it would be worse.
    pub fn our_spends(&self) -> Vec<Txid> {
        self.our_spend_txids
            .iter()
            .chain(self.spend_txid_hex.iter())
            .filter_map(|h| Txid::from_str(h).ok())
            .collect()
    }

    /// What a driver resuming this swap must honour.
    pub fn resume(&self) -> Resume {
        Resume {
            funding: self.funding_outpoint(),
            funding_intent_at_height: self.funding_intent_at_height,
            our_spends: self.our_spends(),
            reorg_seen_at_height: self.reorg_seen_at_height,
        }
    }

    /// Note that the swap moved on, so the next failure starts a fresh backoff.
    ///
    /// Only a write that changes the state counts, so callers go through the persistence helper
    /// that checks. A driver re-entered during an outage rewrites what it already knows (the same
    /// funding output, the same paid invoice, the same claim it is about to put on the wire) before
    /// failing again at the step it is stuck on; clearing the count on those pins the swap to the
    /// first backoff delay forever and the operator alarm never fires.
    pub fn progressed(&mut self) {
        self.retry_count = 0;
        self.next_retry_at_unix = None;
        self.last_error = None;
    }

    /// Whether this side has funds committed that only an action of its own can recover.
    ///
    /// This is the line between a swap that may be given up on and one that may not. Before it,
    /// abandoning a swap costs a swap; after it, abandoning one costs the money, because the claim
    /// or refund that recovers it is unilateral and nobody else will do it.
    ///
    /// Which marker means "committed" depends on which leg this side pays. The on-chain funder
    /// (the provider in a reverse swap, the client in a submarine one) is committed from the
    /// moment it *intends* to broadcast, not from the moment it records an outpoint: the
    /// transaction may be on the wire whatever the chain currently shows. The Lightning payer is
    /// committed once a payment has been started, and recovers by claiming the HTLC on chain.
    pub fn funds_at_risk(&self) -> bool {
        let we_fund_onchain = matches!(
            (self.role, self.direction),
            (SwapRole::Provider, SwapDirection::Reverse)
                | (SwapRole::Client, SwapDirection::Submarine)
        );
        let committed = if we_fund_onchain {
            self.funding_intent_at_height.is_some() || self.funding_outpoint().is_some()
        } else {
            self.invoice_pay_started_at_unix.is_some()
        };
        // A claim or refund of ours on the wire is a commitment either way: it is the recovery
        // itself, and it is not finished until it confirms.
        committed || !self.our_spend_txids.is_empty() || self.spend_txid_hex.is_some()
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
    /// Every record, terminal or not.
    ///
    /// Terminal records are kept rather than deleted, which makes them the provider's own history
    /// of what it did: what it earned, what it refunded, and what went wrong. Nothing read them
    /// until there was a status surface to read them for.
    fn load_all(&self) -> Result<Vec<SwapRecord>>;
    /// Complete enumeration for admission and quote recovery. An omitted unreadable record
    /// could be mistaken for permission to create a second swap, so partial results are errors.
    fn load_all_checked(&self) -> Result<Vec<SwapRecord>> {
        Err(anyhow!(
            "complete swap record enumeration is not supported by this store"
        ))
    }
    /// Record a swap's terminal state. Keeps the record for audit rather than deleting it.
    fn mark_terminal(&self, rec: &SwapRecord) -> Result<()>;
    /// Delete terminal records older than `retain`, returning how many were removed. Called only
    /// by a background sweeper, never by a driver.
    fn prune_terminal(&self, retain: Duration) -> Result<usize>;

    /// Read-modify-write one record, atomically with respect to other writers.
    ///
    /// `put` takes a whole record, which is correct for the driver that owns a swap and wrong for
    /// anyone else: a caller that loaded a record, changed one field and put it back also writes
    /// back every other field as it was when it loaded. The reorg monitor does exactly that, and
    /// the fields it would revert are the funding-intent and payment-intent markers, whose only
    /// job is to stop a resumed driver funding or paying a second time.
    ///
    /// Returns `Ok(false)` when the record is gone, which is not an error: a swap can reach a
    /// terminal state and be pruned while a background task is deciding to touch it.
    fn mutate(&self, swap_id: Uuid, f: &mut dyn FnMut(&mut SwapRecord)) -> Result<bool>;
}

/// A directory-of-JSON-files [`SwapStore`]: one `<dir>/<swap_id>.json` per swap.
pub struct JsonFileSwapStore {
    dir: PathBuf,
    /// Serializes read-modify-write against other writers in this process.
    ///
    /// It does not make the store safe against a second process, which nothing here needs: one
    /// daemon owns its data directory. What it does is make [`SwapStore::mutate`] mean what it
    /// says between the driver task and the background monitors that share this store.
    write_lock: Mutex<()>,
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
        Ok(Self {
            dir,
            write_lock: Mutex::new(()),
        })
    }

    fn path_for(&self, swap_id: Uuid) -> PathBuf {
        self.dir.join(format!("{swap_id}.json"))
    }

    /// A temp path no other writer will pick.
    ///
    /// It used to be `<swap_id>.json.tmp`, which is per-swap and not per-write. Two tasks writing
    /// the same swap at once both opened that path with `truncate`, wrote different byte counts
    /// over each other, and renamed in turn; the shorter write leaves the tail of the longer one
    /// behind, and the record no longer parses. `load_active` skips a record it cannot parse, so
    /// the loss is silent, and what is lost is a swap that is in flight by definition.
    fn tmp_path_for(&self, swap_id: Uuid) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        self.dir
            .join(format!("{swap_id}.{}.{n}.tmp", std::process::id()))
    }
}

impl SwapStore for JsonFileSwapStore {
    fn mutate(&self, swap_id: Uuid, f: &mut dyn FnMut(&mut SwapRecord)) -> Result<bool> {
        // Held across the read and the write, so a concurrent `mutate` cannot read the same
        // record and write back over this one's change.
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut rec) = self.get(swap_id)? else {
            return Ok(false);
        };
        f(&mut rec);
        self.put(&rec)?;
        Ok(true)
    }

    fn put(&self, rec: &SwapRecord) -> Result<()> {
        let path = self.path_for(rec.swap_id);
        let tmp = self.tmp_path_for(rec.swap_id);

        // Stamped here rather than at each call site: `put` is the only way a record reaches the
        // disk, so this is the one place that can be sure it happens exactly once, on the write
        // that creates the file. Every later write carries the value already in the record.
        let stamped;
        let rec = if rec.created_at_unix == 0 {
            let existing = self.get(rec.swap_id).ok().flatten();
            stamped = SwapRecord {
                created_at_unix: existing
                    .map(|e| e.created_at_unix)
                    .filter(|t| *t > 0)
                    .unwrap_or_else(now_unix),
                ..rec.clone()
            };
            &stamped
        } else {
            rec
        };

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
        Ok(self
            .load_all()?
            .into_iter()
            .filter(|rec| !rec.state.is_terminal())
            .collect())
    }

    fn load_all(&self) -> Result<Vec<SwapRecord>> {
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
                Ok(rec) => out.push(rec),
                Err(e) => tracing::warn!("skipping unparsable swap record {path:?}: {e}"),
            }
        }
        Ok(out)
    }

    fn load_all_checked(&self) -> Result<Vec<SwapRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.dir).with_context(|| format!("read dir {:?}", self.dir))? {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("read swap record {path:?}"))?;
            records.push(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse swap record {path:?}"))?,
            );
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{build_htlc_script, generate_preimage, payment_hash};
    use crate::random_keypair;
    use bitcoin::secp256k1::Secp256k1;

    fn txid(n: u8) -> Txid {
        use bitcoin::hashes::Hash;
        Txid::from_byte_array([n; 32])
    }

    /// A record written before delegated sessions existed has no `peer_account`, and must still
    /// load as a plain DM peer rather than failing the whole store open.
    #[test]
    fn session_delivery_survives_restart_and_legacy_records_default_to_dm() {
        let mut record = SwapRecord::new_progress();
        record.peer_account = Some("account".into());
        let mut json = serde_json::to_value(&record).unwrap();
        assert_eq!(
            serde_json::from_value::<SwapRecord>(json.clone())
                .unwrap()
                .peer_account
                .as_deref(),
            Some("account")
        );
        json.as_object_mut().unwrap().remove("peer_account");
        assert!(serde_json::from_value::<SwapRecord>(json)
            .unwrap()
            .peer_account
            .is_none());
    }

    /// A swap that bumps its refund twice and then crashes has two transactions of its own that
    /// could each still confirm. Keeping only the newest leaves the older one looking like the
    /// counterparty's spend to the next run, which is the reading that abandons a swap we were
    /// winning.
    #[test]
    fn a_record_remembers_every_spend_it_broadcast() {
        let mut rec = SwapRecord::new_progress();
        rec.note_our_spend(txid(1));
        rec.note_our_spend(txid(2));
        rec.note_our_spend(txid(2)); // a re-broadcast of the same transaction is not a new one

        assert_eq!(rec.our_spends(), vec![txid(1), txid(2), txid(2)]);
        assert_eq!(
            rec.spend_txid_hex.as_deref(),
            Some(txid(2).to_string().as_str()),
            "the newest stays where the operator looks for it"
        );

        // Bounded: escalation replaces rather than adds, so only the recent ones can still be in
        // a mempool, and the field must not grow with the length of a stuck swap.
        for n in 0..(MAX_TRACKED_OUR_SPENDS as u8 + 5) {
            rec.note_our_spend(txid(n.wrapping_add(10)));
        }
        assert_eq!(rec.our_spend_txids.len(), MAX_TRACKED_OUR_SPENDS);
    }

    /// Which marker means "our money is committed" depends on which leg this side pays, and
    /// getting it backwards is expensive in both directions: too eager and an ordinary failed swap
    /// is retried forever; too cautious and a funded HTLC is given up on.
    #[test]
    fn committed_funds_are_recognised_from_the_marker_this_side_writes() {
        let base = |role, direction| SwapRecord {
            role,
            direction,
            ..SwapRecord::new_progress()
        };

        for (role, direction) in [
            (SwapRole::Provider, SwapDirection::Reverse),
            (SwapRole::Client, SwapDirection::Submarine),
        ] {
            // The on-chain funder. Committed from the intent, not the outpoint: the transaction
            // may be on the wire whatever the chain currently shows.
            let mut rec = base(role, direction);
            assert!(!rec.funds_at_risk(), "{role:?}/{direction:?}: nothing yet");
            rec.invoice_pay_started_at_unix = Some(1);
            assert!(
                !rec.funds_at_risk(),
                "{role:?}/{direction:?}: this side does not pay the invoice"
            );
            rec.funding_intent_at_height = Some(800_000);
            assert!(rec.funds_at_risk());

            let mut rec = base(role, direction);
            rec.funding_txid_hex = Some("11".repeat(32));
            rec.funding_vout = Some(0);
            assert!(rec.funds_at_risk());
        }

        for (role, direction) in [
            (SwapRole::Provider, SwapDirection::Submarine),
            (SwapRole::Client, SwapDirection::Reverse),
        ] {
            // The Lightning payer. The counterparty's on-chain funding is not this side's money;
            // its own payment is, and it recovers by claiming.
            let mut rec = base(role, direction);
            rec.funding_txid_hex = Some("11".repeat(32));
            rec.funding_vout = Some(0);
            assert!(
                !rec.funds_at_risk(),
                "{role:?}/{direction:?}: the counterparty funded that, not us"
            );
            rec.invoice_pay_started_at_unix = Some(1);
            assert!(rec.funds_at_risk());
        }

        // A claim or refund on the wire counts whoever wrote it: it is the recovery itself, and it
        // is not finished until it confirms.
        let mut rec = base(SwapRole::Provider, SwapDirection::Submarine);
        rec.note_our_spend(txid(3));
        assert!(rec.funds_at_risk());
    }

    /// Progress is what ends a backoff. Leaving the count and the error behind would have a swap
    /// that recovered still reported as needing an operator.
    #[test]
    fn progress_clears_the_retry_state() {
        let mut rec = SwapRecord::new_progress();
        rec.retry_count = 7;
        rec.next_retry_at_unix = Some(1);
        rec.last_error = Some("electrum: connection refused".into());

        rec.progressed();
        assert_eq!(rec.retry_count, 0);
        assert_eq!(rec.next_retry_at_unix, None);
        assert_eq!(rec.last_error, None);
    }

    fn temp_dir() -> PathBuf {
        // A unique, isolated directory under the system temp dir (no Math.random needed: the
        // swap_id is unique per call).
        let id = Uuid::new_v4();
        std::env::temp_dir().join(format!("pubky-swap-store-test-{id}"))
    }

    /// A record's creation time is stamped once, on the write that creates it.
    ///
    /// The store is the only thing that can guarantee "once": every driver writes through `put`
    /// repeatedly as a swap progresses, and a later write must not move the timestamp.
    #[test]
    fn a_record_is_stamped_with_its_creation_time_exactly_once() {
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(&dir).unwrap();

        let mut rec = SwapRecord::new_progress();
        rec.swap_id = Uuid::new_v4();
        store.put(&rec).unwrap();

        let first = store.get(rec.swap_id).unwrap().unwrap();
        assert!(
            first.created_at_unix > 0,
            "the first write stamps a creation time"
        );

        // A driver writing progress back does not carry the timestamp in its own copy.
        let mut later = rec.clone();
        later.state = SwapState::LockupConfirmed;
        store.put(&later).unwrap();

        let second = store.get(rec.swap_id).unwrap().unwrap();
        assert_eq!(
            second.created_at_unix, first.created_at_unix,
            "a later write must not move the creation time"
        );
        assert_eq!(second.state, SwapState::LockupConfirmed);

        let _ = std::fs::remove_dir_all(&dir);
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

#[cfg(test)]
mod redaction_tests {
    use super::*;

    /// A record carries the only key that can move the funds on this side's HTLC branch, and it
    /// is exactly the sort of thing that ends up in a log line while someone debugs a stuck swap.
    #[test]
    fn debug_output_does_not_contain_key_material() {
        let mut rec = SwapRecord::new_progress();
        rec.secret_key_hex = "aa".repeat(32);
        rec.preimage_hex = Some("bb".repeat(32));

        let printed = format!("{rec:?}");
        assert!(
            !printed.contains(&"aa".repeat(32)),
            "branch key leaked: {printed}"
        );
        assert!(
            !printed.contains(&"bb".repeat(32)),
            "preimage leaked: {printed}"
        );
        assert!(printed.contains("<redacted>"));
        // Everything useful for debugging is still there.
        assert!(printed.contains("swap_id"));
        assert!(printed.contains("state"));
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;

    /// An isolated store under the system temp dir, removed when the test ends.
    struct TempStore {
        dir: PathBuf,
        store: JsonFileSwapStore,
    }
    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    fn store() -> TempStore {
        let dir = std::env::temp_dir().join(format!("pubky-swap-concurrency-{}", Uuid::new_v4()));
        let store = JsonFileSwapStore::new(&dir).unwrap();
        TempStore { dir, store }
    }

    /// `put` writes a whole record, so a caller that loaded one, changed a field and put it back
    /// also writes back every other field as it was when it loaded.
    ///
    /// The reorg monitor does exactly that, on a snapshot, while the swap's own driver is writing
    /// to the same store. The fields it reverts are the funding-intent and payment-intent
    /// markers, whose only job is to stop a resumed driver funding or paying a second time. This
    /// is the read-modify-write that keeps a background writer from undoing them.
    #[test]
    fn mutate_does_not_revert_a_concurrent_writers_markers() {
        let t = store();
        let store = &t.store;
        let mut rec = SwapRecord::new_progress();
        rec.peer = "peer".into();
        store.put(&rec).unwrap();

        // The background task's snapshot, taken before the driver wrote anything.
        let stale = store.get(rec.swap_id).unwrap().unwrap();
        assert_eq!(stale.funding_intent_at_height, None);

        // The driver records that it is about to fund, and then that it did.
        let mut live = store.get(rec.swap_id).unwrap().unwrap();
        live.funding_intent_at_height = Some(800_000);
        live.funding_txid_hex = Some("aa".repeat(32));
        live.funding_vout = Some(0);
        store.put(&live).unwrap();

        // The background task marks its own field, the way the reorg monitor does.
        let marked = store
            .mutate(rec.swap_id, &mut |r| r.reorg_seen_at_height = Some(799_999))
            .unwrap();
        assert!(marked);

        let after = store.get(rec.swap_id).unwrap().unwrap();
        assert_eq!(after.reorg_seen_at_height, Some(799_999), "its own field");
        assert_eq!(
            after.funding_intent_at_height,
            Some(800_000),
            "the funding intent survived; putting the stale copy back would have erased it"
        );
        assert_eq!(after.funding_vout, Some(0));

        // Which is what a `put` of the snapshot would have done.
        store.put(&stale).unwrap();
        let clobbered = store.get(rec.swap_id).unwrap().unwrap();
        assert_eq!(
            clobbered.funding_intent_at_height, None,
            "this is the behaviour `mutate` exists to avoid"
        );
    }

    /// A record that reached a terminal state and was pruned is not an error to mutate: a
    /// background task can decide to touch a swap that finishes while it is deciding.
    #[test]
    fn mutating_a_missing_record_is_not_an_error() {
        let t = store();
        assert!(!t.store.mutate(Uuid::new_v4(), &mut |_| {}).unwrap());
    }

    /// Concurrent writers used to share one temp path per swap, so two writes of the same record
    /// opened the same file with `truncate`, wrote over each other and renamed in turn. The
    /// shorter write leaves the tail of the longer behind and the record no longer parses;
    /// `load_active` drops what it cannot parse, silently, and what it drops is by definition a
    /// swap in flight.
    #[test]
    fn concurrent_writes_of_one_record_always_leave_it_parsable() {
        let t = store();
        let store = &t.store;
        let mut rec = SwapRecord::new_progress();
        rec.peer = "peer".into();
        store.put(&rec).unwrap();
        let id = rec.swap_id;
        let store = std::sync::Arc::new(JsonFileSwapStore::new(&t.dir).unwrap());

        let mut handles = Vec::new();
        for i in 0..8 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                for n in 0..40 {
                    let mut r = SwapRecord::new_progress();
                    r.swap_id = id;
                    // Wildly different lengths, so an interleaved write leaves a tail.
                    r.last_error = Some("x".repeat(1 + (i * 40 + n) * 7));
                    store.put(&r).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        store
            .get(id)
            .expect("the record must still parse")
            .expect("and still exist");
        // And no temp files were left behind for `load_all` to trip over.
        assert!(
            store.load_all().unwrap().len() == 1,
            "exactly one record, and nothing that looks like one"
        );
    }
}
