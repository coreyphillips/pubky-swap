//! Driving swaps a previous run left in flight.
//!
//! Persisting the branch key stopped a crash from making coins unspendable forever. It did not
//! make them spendable *now*: the record held everything needed and nothing read it, so recovery
//! meant an operator, a hex editor and a copy of the HTLC script. Reporting the swap loudly on
//! startup, which is what this replaced, tells someone their money is at risk without doing
//! anything about it.
//!
//! What a resumed swap owes each side is not symmetric. A submarine client has its own coins in
//! an HTLC and the refund branch is the only way back, so it must be driven to a claim or a
//! refund. A reverse client has paid over Lightning against an HTLC it can claim with a preimage
//! only it holds, so it must claim before the provider's refund window opens. Both are the same
//! two functions the live path uses, handed a state rebuilt from the record instead of from a
//! negotiation.

use anyhow::{anyhow, Context, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::ScriptBuf;
use lightning_backend::LightningBackend;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::ChainWatcher;
use swap_common::store::{JsonFileSwapStore, SwapRecord};
use swap_common::wallet::OnchainWallet;
use swap_common::{SwapDirection, SwapState};
use tracing::{error, info, warn};

use crate::reverse::{execute_reverse_swap, ReverseClaim};
use crate::submarine::{execute_submarine_swap, SubmarineFunding};
use crate::{store, RecordProgress};

/// How often a resumed driver looks at the chain.
const POLL: Duration = Duration::from_secs(2);

/// Drive every swap this client left unfinished, in order, to a terminal state.
///
/// Errors on individual swaps are reported and do not stop the rest: one swap that cannot be
/// rebuilt is not a reason to leave the others unattended.
pub async fn resume_unfinished(
    store: &JsonFileSwapStore,
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    wallet: Option<Arc<dyn OnchainWallet>>,
    max_routing_fee_msat: u64,
) -> Result<()> {
    let records = store::unfinished(store)?;
    if records.is_empty() {
        return Ok(());
    }
    info!(
        "{} swap(s) from a previous run are unfinished; driving them before anything else",
        records.len()
    );

    for rec in records {
        let swap_id = rec.swap_id;
        info!(
            "Resuming swap {swap_id} ({:?} with {}): state {:?}, timeout height {}",
            rec.direction, rec.peer, rec.state, rec.timeout_height
        );
        let outcome = match rec.direction {
            SwapDirection::Submarine => {
                resume_submarine(store, &rec, ln.clone(), chain.clone(), wallet.clone()).await
            }
            SwapDirection::Reverse => {
                resume_reverse(store, &rec, ln.clone(), chain.clone(), max_routing_fee_msat).await
            }
        };
        match outcome {
            Ok(state) => {
                info!("Swap {swap_id} resumed to {state:?}");
                if let Err(e) = store::record_terminal(store, swap_id, state) {
                    warn!("could not record the outcome of {swap_id}: {e}");
                }
            }
            // Deliberately not terminal. The record holds the only key that can move this side's
            // branch, and a swap that could not be resumed today is one to try again tomorrow,
            // not one to write off.
            Err(e) => error!(
                "could not resume swap {swap_id}: {e}. Its record is kept: it holds the only key \
                 that can recover any committed funds."
            ),
        }
    }
    Ok(())
}

async fn resume_submarine(
    store: &JsonFileSwapStore,
    rec: &SwapRecord,
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    wallet: Option<Arc<dyn OnchainWallet>>,
) -> Result<SwapState> {
    let wallet = wallet.ok_or_else(|| {
        anyhow!(
            "a submarine swap needs a wallet to refund with; configure the same --wallet this \
             swap was funded from"
        )
    })?;
    let funding = submarine_funding_from_record(rec)?;
    let sink = RecordProgress {
        store,
        swap_id: rec.swap_id,
    };
    execute_submarine_swap(ln, chain, wallet, funding, POLL, &rec.resume(), &sink).await
}

async fn resume_reverse(
    store: &JsonFileSwapStore,
    rec: &SwapRecord,
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    max_routing_fee_msat: u64,
) -> Result<SwapState> {
    let claim = reverse_claim_from_record(rec)?;
    let sink = RecordProgress {
        store,
        swap_id: rec.swap_id,
    };
    // The claim is what makes the provider settle, so the confirmations required here are the
    // ones the swap agreed to, read back from the record rather than from today's flags.
    execute_reverse_swap(
        ln,
        chain,
        claim,
        max_routing_fee_msat,
        rec.required_confirmations,
        POLL,
        &rec.resume(),
        &sink,
    )
    .await
    .map(|_| SwapState::Claimed)
}

/// Rebuild the submarine state from what was written down.
fn submarine_funding_from_record(rec: &SwapRecord) -> Result<SubmarineFunding> {
    Ok(SubmarineFunding {
        htlc_script: rec.htlc_script()?,
        htlc_spk: rec.htlc_spk()?,
        onchain_amount_sat: rec.onchain_amount_sat,
        payment_hash: rec.payment_hash()?,
        refund_key: rec.secret_key()?,
        timeout_height: rec.timeout_height,
        fee_rate_sat_vb: rec.fee_rate_sat_vb,
    })
}

/// Rebuild the reverse state from what was written down.
///
/// The preimage is the one field with no other source. A reverse client generates it before the
/// swap begins and it exists nowhere else until the claim puts it on chain, which is why the
/// record carries it and why a record without one cannot be resumed.
fn reverse_claim_from_record(rec: &SwapRecord) -> Result<ReverseClaim> {
    let preimage_hex = rec
        .preimage_hex
        .as_deref()
        .ok_or_else(|| anyhow!("no preimage on the record; this swap cannot be claimed"))?;
    let preimage: [u8; 32] = hex::decode(preimage_hex)
        .context("decode the preimage")?
        .try_into()
        .map_err(|_| anyhow!("the preimage must be 32 bytes"))?;
    let dest_spk_hex = rec
        .dest_spk_hex
        .as_deref()
        .ok_or_else(|| anyhow!("no claim destination on the record"))?;
    Ok(ReverseClaim {
        htlc_script: rec.htlc_script()?,
        htlc_spk: rec.htlc_spk()?,
        onchain_amount_sat: rec.onchain_amount_sat,
        timeout_height: rec.timeout_height,
        invoice: rec.invoice.clone(),
        preimage,
        claim_key: secret_key(rec)?,
        dest_spk: ScriptBuf::from_hex(dest_spk_hex).context("decode the claim destination")?,
        fee_rate_sat_vb: rec.fee_rate_sat_vb,
    })
}

fn secret_key(rec: &SwapRecord) -> Result<SecretKey> {
    rec.secret_key()
}

/// Parse a txid the way the record wrote it, for tests and diagnostics.
#[allow(dead_code)]
fn txid(s: &str) -> Result<bitcoin::Txid> {
    bitcoin::Txid::from_str(s).context("decode a txid")
}
