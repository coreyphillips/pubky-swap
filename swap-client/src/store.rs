//! Client-side persistence of in-flight swaps.
//!
//! Until this existed the client kept nothing on disk. In a submarine swap that meant the refund
//! key lived only on the stack: the client generated it, funded an HTLC whose refund branch only
//! that key can spend, and held it in memory for the length of the timeout. A crash at any point
//! after `fund_htlc` returned destroyed the only key that could ever recover those coins. Not
//! "failed the swap" -- nobody could spend that output again, ever. The provider needs the
//! preimage to take the claim branch and the client no longer had the key for the refund branch.
//!
//! A reverse swap was milder but still wrong: losing the preimage and claim key meant the client
//! could not claim, and was made whole only because the provider eventually refunded and cancelled
//! the invoice. That is relying on the counterparty's correctness for your own safety.
//!
//! So the rule here is the same as on the provider side: **write before you act**. The key is on
//! disk before the funding transaction is built, and the intent to fund is on disk before it is
//! broadcast.

use anyhow::{anyhow, Context, Result};
use std::path::Path;
use swap_common::store::{JsonFileSwapStore, SwapRecord, SwapRole, SwapStore};
use swap_common::{NetworkSpec, SwapDirection, SwapState};
use uuid::Uuid;

/// Open (creating if needed) the client's swap store under `data_dir`.
pub fn open(data_dir: &str) -> Result<JsonFileSwapStore> {
    let dir = Path::new(data_dir).join("swaps");
    JsonFileSwapStore::new(&dir).with_context(|| format!("open the client swap store at {dir:?}"))
}

/// The details a client knows before it has sent anything.
pub struct NewClientSwap {
    pub swap_id: Uuid,
    pub direction: SwapDirection,
    pub peer: String,
    pub network: NetworkSpec,
    pub payment_hash: [u8; 32],
    /// The branch key only this side holds: the claim key for a reverse swap, the refund key for
    /// a submarine one.
    pub branch_key: [u8; 32],
    /// The client's preimage, for a reverse swap.
    pub preimage: Option<[u8; 32]>,
    /// The invoice this side issued (submarine) or is about to pay (reverse).
    pub invoice: String,
    pub quote_total_sat: u64,
    pub required_confirmations: u32,
    pub fee_rate_sat_vb: u64,
}

/// Write the record that must exist before the client sends a `SwapRequest`.
///
/// It is deliberately written before the request goes out rather than after the acceptance comes
/// back: the branch key is generated here, and once a counterparty knows about the swap there is
/// a path to funds moving. A record written after the acceptance would leave a window where the
/// key exists only in memory.
pub fn record_intent(store: &dyn SwapStore, swap: &NewClientSwap) -> Result<()> {
    let rec = SwapRecord {
        swap_id: swap.swap_id,
        role: SwapRole::Client,
        direction: swap.direction,
        peer: swap.peer.clone(),
        network: swap.network,
        payment_hash_hex: hex::encode(swap.payment_hash),
        secret_key_hex: hex::encode(swap.branch_key),
        preimage_hex: swap.preimage.map(hex::encode),
        invoice: swap.invoice.clone(),
        quote_total_sat: swap.quote_total_sat,
        required_confirmations: swap.required_confirmations,
        fee_rate_sat_vb: swap.fee_rate_sat_vb,
        state: SwapState::Created,
        ..SwapRecord::new_progress()
    };
    store
        .put(&rec)
        .with_context(|| format!("persist the swap {} before sending it", swap.swap_id))
}

/// Fill in what the counterparty's acceptance settled, before any funds move.
#[allow(clippy::too_many_arguments)]
pub fn record_accept(
    store: &dyn SwapStore,
    swap_id: Uuid,
    htlc_script_hex: String,
    timeout_height: u32,
    onchain_amount_sat: u64,
    dest_spk_hex: String,
) -> Result<()> {
    let mut rec = load(store, swap_id)?;
    rec.htlc_script_hex = htlc_script_hex;
    rec.timeout_height = timeout_height;
    rec.onchain_amount_sat = onchain_amount_sat;
    rec.dest_spk_hex = Some(dest_spk_hex);
    store.put(&rec).context("persist the accepted swap")
}

/// Note that a funding transaction is about to be broadcast.
///
/// This is the marker that turns an unrecoverable crash into a chain scan. Without it, a crash
/// between broadcast and recording the outpoint leaves coins in an HTLC with nothing pointing at
/// them; with it, a resumed client knows to go looking.
pub fn record_funding_intent(store: &dyn SwapStore, swap_id: Uuid, tip: u32) -> Result<()> {
    let mut rec = load(store, swap_id)?;
    rec.funding_intent_at_height = Some(tip);
    rec.funding_attempts = rec.funding_attempts.saturating_add(1);
    rec.state = SwapState::LockupPending;
    store.put(&rec).context("persist the funding intent")
}

/// Record the funding outpoint once it is known.
pub fn record_funded(
    store: &dyn SwapStore,
    swap_id: Uuid,
    outpoint: bitcoin::OutPoint,
) -> Result<()> {
    let mut rec = load(store, swap_id)?;
    rec.funding_txid_hex = Some(outpoint.txid.to_string());
    rec.funding_vout = Some(outpoint.vout);
    rec.funding_intent_at_height = None;
    rec.state = SwapState::LockupConfirmed;
    store.put(&rec).context("persist the funding outpoint")
}

/// Note a claim or refund this client is about to broadcast.
///
/// Written before the broadcast, so a later run recognises the transaction as its own instead of
/// reading it as the counterparty's spend and abandoning a swap it was winning.
pub fn record_our_spend(store: &dyn SwapStore, swap_id: Uuid, txid: bitcoin::Txid) -> Result<()> {
    let mut rec = load(store, swap_id)?;
    rec.note_our_spend(txid);
    store.put(&rec).context("persist the broadcast spend")
}

/// Record a terminal outcome, keeping the record for audit.
pub fn record_terminal(store: &dyn SwapStore, swap_id: Uuid, state: SwapState) -> Result<()> {
    let mut rec = load(store, swap_id)?;
    rec.state = state;
    store.mark_terminal(&rec).context("record the outcome")
}

fn load(store: &dyn SwapStore, swap_id: Uuid) -> Result<SwapRecord> {
    store
        .get(swap_id)?
        .ok_or_else(|| anyhow!("swap {swap_id} is not in the store"))
}

/// Records this client left in flight, worth reporting on startup.
pub fn unfinished(store: &dyn SwapStore) -> Result<Vec<SwapRecord>> {
    Ok(store
        .load_active()?
        .into_iter()
        .filter(|r| r.role == SwapRole::Client)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_common::random_secret_key;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pubky-swap-client-store-{}", Uuid::new_v4()))
    }

    fn new_swap(direction: SwapDirection) -> NewClientSwap {
        NewClientSwap {
            swap_id: Uuid::new_v4(),
            direction,
            peer: "provider".into(),
            network: NetworkSpec::Regtest,
            payment_hash: [7u8; 32],
            branch_key: random_secret_key().secret_bytes(),
            preimage: (direction == SwapDirection::Reverse).then_some([9u8; 32]),
            invoice: "lnbcrt-mock".into(),
            quote_total_sat: 100_700,
            required_confirmations: 2,
            fee_rate_sat_vb: 5,
        }
    }

    /// The key the client needs to get its own money back must be on disk before anything can
    /// possibly move funds, and must survive a restart intact.
    #[test]
    fn the_refund_key_is_recoverable_after_a_restart() {
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let swap = new_swap(SwapDirection::Submarine);
        record_intent(&store, &swap).unwrap();

        // A fresh process opening the same directory.
        let reopened = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let recovered = unfinished(&reopened).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered[0].secret_key().unwrap().secret_bytes(),
            swap.branch_key,
            "the refund key must survive; without it the HTLC output is unspendable forever"
        );
        assert_eq!(recovered[0].role, SwapRole::Client);
        assert_eq!(recovered[0].quote_total_sat, 100_700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A reverse-swap client persists its preimage too: it generated it, so nothing else in the
    /// world has a copy.
    #[test]
    fn a_reverse_client_persists_its_preimage() {
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let swap = new_swap(SwapDirection::Reverse);
        record_intent(&store, &swap).unwrap();

        let rec = &unfinished(&store).unwrap()[0];
        assert_eq!(rec.preimage().unwrap(), Some([9u8; 32]));

        // The provider's records never carry one.
        let sub = new_swap(SwapDirection::Submarine);
        record_intent(&store, &sub).unwrap();
        let subs: Vec<_> = unfinished(&store)
            .unwrap()
            .into_iter()
            .filter(|r| r.direction == SwapDirection::Submarine)
            .collect();
        assert_eq!(subs[0].preimage().unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The crash window that used to destroy funds: between broadcasting the funding and
    /// recording its outpoint. The intent marker is what makes it recoverable.
    #[test]
    fn a_funding_intent_survives_a_crash_before_the_outpoint_is_known() {
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let swap = new_swap(SwapDirection::Submarine);
        record_intent(&store, &swap).unwrap();
        record_funding_intent(&store, swap.swap_id, 800_000).unwrap();

        let rec = &unfinished(&store).unwrap()[0];
        assert_eq!(rec.funding_intent_at_height, Some(800_000));
        assert_eq!(rec.funding_attempts, 1);
        assert!(
            rec.funding_outpoint().is_none(),
            "no outpoint yet: this is exactly the crash window"
        );

        // Once the outpoint is known the marker clears.
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            vout: 1,
        };
        record_funded(&store, swap.swap_id, outpoint).unwrap();
        let rec = &unfinished(&store).unwrap()[0];
        assert!(rec.funding_intent_at_height.is_none());
        assert_eq!(rec.funding_outpoint(), Some(outpoint));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_finished_swap_leaves_the_active_set() {
        let dir = temp_dir();
        let store = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let swap = new_swap(SwapDirection::Reverse);
        record_intent(&store, &swap).unwrap();
        assert_eq!(unfinished(&store).unwrap().len(), 1);
        record_terminal(&store, swap.swap_id, SwapState::Claimed).unwrap();
        assert!(unfinished(&store).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
