//! Reverse-swap (Lightning → on-chain) provider orchestration.
//!
//! Flow driven here:
//! 1. Create a Lightning **hold invoice** for the swap's payment hash.
//! 2. Build the on-chain HTLC (claim = client's key, refund = provider's key).
//! 3. When the client pays the invoice (it becomes `Accepted`/held), **fund** the HTLC.
//! 4. Once the funding confirms, wait for the client to **claim** it on-chain, which
//!    reveals the preimage.
//! 5. Recover the preimage from the claim tx and **settle** the hold invoice — the provider
//!    gets paid over Lightning, atomically with the client receiving the on-chain coins.
//! 6. If the client never claims before the timeout, **refund** the HTLC and cancel the
//!    invoice, so both parties are made whole.
//!
//! The Lightning, chain, and wallet sides are abstracted as traits so this logic is unit-
//! tested end-to-end with mocks (see the tests below); the same code runs against a real
//! LND node + Electrum server in production.

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, OutPoint, PublicKey, ScriptBuf, Txid};
use lightning_backend::{HoldInvoiceRequest, InvoiceState, LightningBackend};
use std::time::Duration;
use swap_common::chain::{run_blocking, select_recorded_funding, ChainWatcher};
use swap_common::fee_bump::{confirm_or_bump, SpendOutcome, SpendWatchConfig};
use swap_common::htlc::{build_htlc_script, htlc_p2wsh_address, PaymentHash};
use swap_common::onchain::{
    build_refund_tx, estimate_spend_fee, extract_preimage, fee_rate_cap, spend_vsize,
    ABSOLUTE_MAX_FEE_RATE_SAT_VB, DEFAULT_MAX_FEE_BPS, REFUND_FEE_TARGET_BLOCKS,
};
use swap_common::reorg::FINALITY_DEPTH;
use swap_common::timelock::{self, TimelockParams};
use swap_common::SwapState;
use tokio::time::sleep;
use tracing::{error, info, warn};

// The funding-wallet abstraction now lives in `swap-common` so the submarine-swap client can
// reuse it; re-exported here for the provider's existing call sites.
pub use swap_common::wallet::OnchainWallet;

/// Hook for persisting a driver's progress so a restart can resume it. The provider supplies an
/// implementation that updates and persists the swap's [`crate::store::SwapRecord`]; the unit
/// `()` is a no-op used by tests.
///
/// The ordering matters more than the contents. Every method that names an *intent* is called
/// **before** the irreversible act it describes, so a crash in the gap leaves a marker saying
/// "this may have happened, go and check" rather than nothing at all. Recording only outcomes
/// leaves a window where funds have moved and no trace of it exists.
pub trait ProgressSink: Send + Sync {
    /// About to broadcast a funding transaction, at the given tip height.
    ///
    /// Fallible, unlike most of these, because this marker is the only thing standing between a
    /// crash and a second funding. Broadcasting after failing to write it is how a swap gets
    /// funded twice, so the driver stops instead.
    fn funding_intent(&self, _tip: u32) -> Result<()> {
        Ok(())
    }
    /// The HTLC funding outpoint is now known (funded by us, or observed on-chain).
    fn funded(&self, _outpoint: OutPoint) {}
    /// About to pay a Lightning invoice, which cannot be undone.
    ///
    /// Fallible for the same reason as [`funding_intent`](ProgressSink::funding_intent): without
    /// this marker a resumed driver has no reason to ask the node whether a payment is already in
    /// flight, and pays again.
    fn invoice_pay_started(&self) -> Result<()> {
        Ok(())
    }
    /// The invoice payment succeeded.
    fn invoice_paid(&self) {}
    /// A counterparty spend revealing the preimage has been seen, identified by txid. The
    /// preimage itself is never persisted; it is re-extracted from this transaction on resume.
    fn claim_observed(&self, _txid: Txid) {}
    /// We broadcast a claim or refund.
    fn spend_broadcast(&self, _txid: Txid) {}
}

impl ProgressSink for () {}

pub use swap_common::store::Resume;

/// State describing one provider-side reverse swap.
pub struct ReverseSwap {
    pub payment_hash: PaymentHash,
    /// Amount locked on-chain (what the client receives, before their claim-tx fee).
    pub onchain_amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    pub htlc_script: ScriptBuf,
    pub htlc_spk: ScriptBuf,
    pub timeout_height: u32,
    /// Provider's key for the HTLC refund branch.
    pub refund_key: SecretKey,
    /// The hold-invoice BOLT11 the client must pay.
    pub invoice: String,
    /// The timelock model this swap was created under. The driver re-checks against it before
    /// committing on-chain funds.
    pub timelock: TimelockParams,
}

/// Create the reverse swap: a hold invoice plus the on-chain HTLC the provider will fund.
#[allow(clippy::too_many_arguments)]
pub async fn init_reverse_swap(
    ln: &dyn LightningBackend,
    client_claim_pubkey: &PublicKey,
    provider_refund_key: SecretKey,
    provider_refund_pubkey: &PublicKey,
    payment_hash: PaymentHash,
    onchain_amount_sat: u64,
    provider_fee_sat: u64,
    fee_rate_sat_vb: u64,
    timeout_height: u32,
    invoice_expiry_secs: u64,
    network: Network,
    timelock: TimelockParams,
) -> Result<ReverseSwap> {
    let htlc_script = build_htlc_script(
        &payment_hash,
        client_claim_pubkey,
        provider_refund_pubkey,
        timeout_height,
    );
    let htlc_spk = htlc_p2wsh_address(&htlc_script, network).script_pubkey();

    // The client pays the on-chain amount plus the provider's fee over Lightning.
    let invoice_amount_msat = onchain_amount_sat
        .checked_add(provider_fee_sat)
        .and_then(|sat| sat.checked_mul(1000))
        .ok_or_else(|| {
            anyhow!("invoice amount overflows: {onchain_amount_sat} + {provider_fee_sat} sat")
        })?;

    // The incoming Lightning HTLC has to outlive our on-chain refund window, or a client can let
    // the LN leg expire (recovering its sats) and still claim the on-chain HTLC for free. Left
    // unset, LND applies `--bitcoin.timelockdelta`, which is 80 blocks by default and far short
    // of a 144-block on-chain timeout.
    let cltv_expiry_delta = timelock::reverse_invoice_cltv_delta(&timelock)
        .map_err(|e| anyhow!("hold invoice CLTV delta: {e}"))?;
    // Raised to whatever the client's own invoice check demands, if the configured value is
    // shorter. Left as configured, the default hour is well under the three-plus hours that check
    // needs, and every reverse swap was refused at the invoice step.
    let expiry_secs = invoice_expiry_secs.max(timelock::reverse_invoice_min_expiry_secs(
        timelock.required_confirmations,
    ));
    if expiry_secs != invoice_expiry_secs {
        tracing::debug!(
            "raising the hold invoice expiry from {invoice_expiry_secs}s to {expiry_secs}s, \
             which is the shortest a client will accept at {} confirmations",
            timelock.required_confirmations
        );
    }
    let hold = ln
        .create_hold_invoice(HoldInvoiceRequest {
            payment_hash,
            amount_msat: invoice_amount_msat,
            expiry_secs,
            cltv_expiry_delta,
            memo: "pubky-swap reverse".to_string(),
        })
        .await
        .map_err(|e| anyhow!("create hold invoice: {e}"))?;

    Ok(ReverseSwap {
        payment_hash,
        onchain_amount_sat,
        fee_rate_sat_vb,
        htlc_script,
        htlc_spk,
        timeout_height,
        refund_key: provider_refund_key,
        invoice: hold.bolt11,
        timelock,
    })
}

/// The result of trying to put the swap's coins into the HTLC.
enum FundingOutcome {
    /// The HTLC is funded, at this outpoint. Either we funded it now, or an earlier run did.
    Funded(OutPoint),
    /// Nothing was committed, and nothing will be. The hold invoice has been cancelled, so the
    /// client is whole; this carries the terminal state to report.
    Refused(SwapState),
}

/// Establish the HTLC funding outpoint without ever funding twice.
///
/// The order of the questions is the whole point. A known outpoint needs no chain call at all. An
/// unspent output paying the script is the ordinary "someone already funded this" answer. Only
/// when both are empty does history get asked, and only then because "no unspent output" means
/// two opposite things: on a fresh start nothing has been funded, and on a resume the
/// counterparty may simply have claimed already. Funding again in that second case hands them a
/// second HTLC they hold the preimage for, which is a total loss of the amount.
#[allow(clippy::too_many_arguments)]
async fn establish_funding(
    ln: &dyn LightningBackend,
    chain: &dyn ChainWatcher,
    wallet: &dyn OnchainWallet,
    swap: &ReverseSwap,
    resume: &Resume,
    required_confirmations: u32,
    poll: Duration,
    progress: &dyn ProgressSink,
) -> Result<FundingOutcome> {
    // Resumed with a known outpoint: we already funded before the restart.
    //
    // Trusting that outpoint is right except after a reorg, which is the one thing that can undo
    // a confirmation already observed. So when one has been seen, ask the chain whether the
    // output is still there at the depth the swap requires, and fall through to looking for it if
    // it is not. A funding orphaned by a reorg is usually re-mined at the same outpoint, in which
    // case this costs one lookup and changes nothing.
    if let Some(op) = resume.funding {
        let Some(fork) = resume.reorg_seen_at_height else {
            return Ok(FundingOutcome::Funded(op));
        };
        let outputs = run_blocking(|| chain.find_outputs(&swap.htlc_spk))?;
        if outputs
            .iter()
            .any(|u| u.outpoint == op && u.confirmations >= required_confirmations)
        {
            return Ok(FundingOutcome::Funded(op));
        }
        warn!(
            "Reverse swap: a reorg at height {fork} left the recorded funding {op} unconfirmed; \
             re-establishing it from the chain"
        );
        return await_recorded_funding(ln, chain, swap, poll, progress).await;
    }

    // Already funded and still unspent: adopt the existing output.
    if let Some(u) = run_blocking(|| chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat))? {
        progress.funded(u.outpoint);
        return Ok(FundingOutcome::Funded(u.outpoint));
    }

    // Nothing unspent, and a previous run recorded that it was about to broadcast a funding. From
    // here this driver will not fund, whatever it finds. The two outcomes are not comparable:
    // refusing costs a swap that fails and returns the client's money, while funding a second time
    // costs the entire on-chain amount, because the client holds the preimage for the new HTLC
    // just as much as the old one. So the answer to "I cannot see a funding I may have made" is to
    // keep looking, not to make another.
    if resume.funding_intent_at_height.is_some() {
        return await_recorded_funding(ln, chain, swap, poll, progress).await;
    }

    // About to commit funds. Verify the *realised* timelocks first.
    //
    // Asking for a CLTV delta is not the same as getting one: a node may clamp it, ignore it, or
    // apply its own default. LND's default is 80 blocks, well short of a 144-block on-chain
    // timeout, which would let a client reclaim its sats over Lightning and *then* claim the
    // on-chain HTLC for free. So read back the expiry the accepted HTLC actually carries and
    // refuse unless the Lightning leg genuinely outlives our refund window.
    //
    // Refusing costs nobody anything: the payment is still held, so cancelling returns it in
    // full.
    let status = ln
        .invoice_status(swap.payment_hash)
        .await
        .map_err(|e| anyhow!("invoice status: {e}"))?;
    let ln_expiry = match status.earliest_htlc_expiry() {
        Some(h) => h,
        None => {
            warn!("Reverse swap: invoice accepted but no HTLC is held; not funding");
            cancel_hold_invoice(ln, swap.payment_hash).await;
            return Ok(FundingOutcome::Refused(SwapState::Failed(
                "no held HTLC on an accepted invoice".into(),
            )));
        }
    };
    let tip = run_blocking(|| chain.tip_height())?;
    if let Err(violation) =
        timelock::check_reverse_before_fund(tip, swap.timeout_height, ln_expiry, &swap.timelock)
    {
        error!(
            "Reverse swap: refusing to fund the HTLC, timelock violation: {violation}. \
             Cancelling the hold invoice; the client's payment is returned in full."
        );
        cancel_hold_invoice(ln, swap.payment_hash).await;
        return Ok(FundingOutcome::Refused(SwapState::Failed(format!(
            "timelock violation: {violation}"
        ))));
    }
    info!(
        "Reverse swap: lightning HTLC expires at {ln_expiry}, on-chain refund opens at {}; \
         funding on-chain HTLC",
        swap.timeout_height
    );

    // Record the intent before broadcasting. A crash in this gap otherwise leaves a funded HTLC
    // with nothing on disk pointing at it, and this is the marker that stops a resumed driver
    // reading that as "never funded".
    //
    // Nothing has gone on the wire yet, so a marker that cannot be written costs only this swap:
    // cancel the invoice and the client is whole.
    if let Err(e) = progress.funding_intent(tip) {
        error!("Reverse swap: cannot record the funding intent ({e}); not funding");
        cancel_hold_invoice(ln, swap.payment_hash).await;
        return Ok(FundingOutcome::Refused(SwapState::Failed(format!(
            "could not record the funding intent: {e}"
        ))));
    }

    match run_blocking(|| wallet.fund_htlc(&swap.htlc_spk, swap.onchain_amount_sat)) {
        Ok(op) => {
            progress.funded(op);
            Ok(FundingOutcome::Funded(op))
        }
        // Not a failure to fund: a failure to *know whether* we funded. Both wallets can answer
        // with an error after the transaction is already on the wire (a lost gRPC response, a
        // reply we cannot decode), and treating that as a dead swap abandons a funded HTLC with
        // no refund and no cancelled invoice. The marker is written, so this is the same
        // situation a crash here would have left, and it takes the same route.
        Err(e) => {
            error!(
                "Reverse swap: the funding call failed ({e}), but it may already have been \
                 broadcast. Not funding again; watching for it to appear."
            );
            await_recorded_funding(ln, chain, swap, poll, progress).await
        }
    }
}

/// Wait for a funding this swap may already have broadcast, without ever broadcasting another.
///
/// Reached whenever a funding intent is on the record and no matching output is visible. That is
/// two situations at once, and no single observation separates them: the broadcast may never have
/// landed, or it may have landed and been spent, or this Electrum server may simply not have
/// indexed it yet. Only time distinguishes them, so this watches until either the funding appears
/// or the swap's own timeout arrives.
async fn await_recorded_funding(
    ln: &dyn LightningBackend,
    chain: &dyn ChainWatcher,
    swap: &ReverseSwap,
    poll: Duration,
    progress: &dyn ProgressSink,
) -> Result<FundingOutcome> {
    // Slower than the driver's own poll: this loop can run for the whole timeout window, and it
    // asks for a script's entire history each time. Zero stays zero so tests do not sleep.
    let watch_poll = if poll.is_zero() {
        poll
    } else {
        poll.max(Duration::from_secs(30))
    };
    loop {
        if let Some(u) =
            run_blocking(|| chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat))?
        {
            info!(
                "Reverse swap: the recorded funding is visible at {}; adopting it",
                u.outpoint
            );
            progress.funded(u.outpoint);
            return Ok(FundingOutcome::Funded(u.outpoint));
        }

        let history = run_blocking(|| chain.find_historical_outputs(&swap.htlc_spk))?;
        if let Some(op) = run_blocking(|| {
            select_recorded_funding(
                chain,
                &swap.htlc_spk,
                &swap.payment_hash,
                swap.onchain_amount_sat,
                &history,
            )
        })? {
            warn!(
                "Reverse swap: the recorded funding is on chain at {op} and has been spent; \
                 adopting it rather than funding again"
            );
            progress.funded(op);
            return Ok(FundingOutcome::Funded(op));
        }

        let tip = run_blocking(|| chain.tip_height())?;
        if tip >= swap.timeout_height {
            // A whole timeout window of looking and nothing has ever paid this script, on any
            // view of the chain this daemon has had. Nothing is locked, so returning the client's
            // payment is both safe and the only thing left to do. The record keeps its funding
            // markers, so an operator with a better view of the chain still has the outpoint to
            // go looking with.
            error!(
                "Reverse swap: a funding was recorded but never became visible before height {}. \
                 Cancelling the hold invoice. If coins were sent to the HTLC script, they are \
                 refundable with the key in this swap's record.",
                swap.timeout_height
            );
            cancel_hold_invoice(ln, swap.payment_hash).await;
            return Ok(FundingOutcome::Refused(SwapState::Expired));
        }
        sleep(watch_poll).await;
    }
}

/// Cancel the hold invoice, logging rather than failing.
///
/// Every caller is already on its way out and has something better to report than "and the cancel
/// also failed"; the invoice expires on its own regardless, which returns the payment anyway.
pub(crate) async fn cancel_hold_invoice(ln: &dyn LightningBackend, payment_hash: PaymentHash) {
    if let Err(e) = ln.cancel_hold_invoice(payment_hash).await {
        warn!("Reverse swap: failed to cancel the hold invoice: {e}");
    }
}

/// Drive a reverse swap to a terminal [`SwapState`] (`Claimed`, `Refunded`, `Expired`, or
/// `Failed`).
///
/// [`ChainWatcher`] calls are blocking, so they are wrapped in [`run_blocking`] to avoid stalling
/// the async runtime. `poll` is injected for testability.
#[allow(clippy::too_many_arguments)]
pub async fn drive_reverse_swap(
    ln: &dyn LightningBackend,
    chain: &dyn ChainWatcher,
    wallet: &dyn OnchainWallet,
    swap: &ReverseSwap,
    required_confirmations: u32,
    poll: Duration,
    // What a previous run of this swap already did, so this one does not do it again.
    // [`Resume::default`] on a fresh start.
    resume: &Resume,
    progress: &dyn ProgressSink,
) -> Result<SwapState> {
    // 1. Wait for the client to pay the hold invoice (give up at timeout — nothing locked yet).
    //
    //    "Nothing locked yet" is only true before this driver funds. A resumed one may have
    //    coins on chain already, and then every exit here is wrong: the parenthetical above was
    //    written for a fresh start and the loop was reached on both paths. `Cancelled` is the
    //    expensive one. It returns the client's payment and, in a reverse swap, the client is
    //    the party that chose the preimage: they can still claim the funded HTLC, for free,
    //    the moment they notice. Returning `Failed` here leaves nobody driving the refund that
    //    races them.
    //
    //    So a driver that may have funded skips this loop entirely and goes to the funding
    //    path, which adopts what is on chain and drives it to a claim or a refund. Whether the
    //    invoice can still be settled is decided there, with the coins accounted for.
    let may_have_funded = resume.funding.is_some() || resume.funding_intent_at_height.is_some();
    if may_have_funded {
        info!(
            "Reverse swap: resuming a swap that may already hold coins on chain, so the invoice \
             state does not decide this on its own."
        );
    } else {
        loop {
            match ln
                .invoice_state(swap.payment_hash)
                .await
                .map_err(|e| anyhow!("invoice state: {e}"))?
            {
                InvoiceState::Accepted => break,
                InvoiceState::Settled => return Ok(SwapState::Claimed),
                InvoiceState::Cancelled => {
                    return Ok(SwapState::Failed("hold invoice cancelled".into()))
                }
                InvoiceState::Open => {
                    if run_blocking(|| chain.tip_height())? >= swap.timeout_height {
                        if let Err(e) = ln.cancel_hold_invoice(swap.payment_hash).await {
                            warn!("Reverse swap: failed to cancel hold invoice on expiry: {e}");
                        }
                        return Ok(SwapState::Expired);
                    }
                }
            }
            sleep(poll).await;
        }
        info!("Reverse swap: hold invoice accepted");
    }

    // 2. Establish the HTLC funding outpoint, idempotently, so a resumed driver never
    //    double-funds. Only the branch that commits *new* funds is gated on the timelocks: once
    //    coins are already in the HTLC the money is at risk either way, and refusing there would
    //    strand it instead of driving it to a refund.
    let funding_outpoint = match establish_funding(
        ln,
        chain,
        wallet,
        swap,
        resume,
        required_confirmations,
        poll,
        progress,
    )
    .await?
    {
        FundingOutcome::Funded(op) => op,
        // Refused before committing anything. The hold invoice is already cancelled, so the
        // client's payment is returned in full.
        FundingOutcome::Refused(state) => return Ok(state),
    };
    info!("Reverse swap: HTLC funded; awaiting client claim");

    // We funded the output ourselves, so we already know its outpoint. We do NOT separately
    // wait for it to appear as an unspent UTXO: the client claims as soon as it confirms,
    // which spends the output — an unspent lookup here would race (and usually lose) that
    // claim and then loop forever. Instead we watch directly for the spend (to settle) or
    // refund at the timeout. `required_confirmations` is enforced client-side before claiming.
    let _ = required_confirmations;

    // 3. Watch for the client's claim (which reveals the preimage), and refund at the timeout.
    //
    // Settling and finishing are deliberately separate. Recovering a preimage from an
    // unconfirmed claim and settling on it is free money for us, so it is done as soon as the
    // preimage is visible. But an unconfirmed claim can still be replaced or reorged out, and if
    // we treated settling as the end of the swap we would stop watching an HTLC that is once
    // again claimable, and lose the on-chain leg without ever noticing. So the swap only finishes
    // once the claim is buried, and until then the refund path stays live.
    let dest = wallet.receive_destination();
    let refund_vsize = spend_vsize(&swap.htlc_script, &dest, false);
    let build = |rate: u64| {
        build_refund_tx(
            funding_outpoint,
            swap.onchain_amount_sat,
            &swap.htlc_script,
            dest.clone(),
            estimate_spend_fee(rate, refund_vsize),
            swap.timeout_height,
            &swap.refund_key,
        )
    };
    // The refund sweeps to our own wallet, so CPFP can pull it in when an RBF replacement is
    // rejected.
    let cpfp = |parent: Txid, rate: u64| {
        run_blocking(|| {
            wallet.cpfp_bump(
                OutPoint {
                    txid: parent,
                    vout: 0,
                },
                rate,
            )
        })
        .ok()
        .flatten()
    };
    let cap = fee_rate_cap(
        swap.onchain_amount_sat,
        refund_vsize,
        DEFAULT_MAX_FEE_BPS,
        ABSOLUTE_MAX_FEE_RATE_SAT_VB,
        swap.fee_rate_sat_vb,
    );

    let mut settled = false;
    loop {
        // Any spend of the HTLC, ours or theirs.
        if let Some(spend) = run_blocking(|| chain.find_spend(&swap.htlc_spk, &funding_outpoint))? {
            let spend_txid = spend.compute_txid();
            if let Some(preimage) = extract_preimage(&spend, &funding_outpoint, &swap.payment_hash)
            {
                if !settled {
                    // Persist that we have seen the claim before settling against it, so a
                    // crash between the two resumes from the right place.
                    progress.claim_observed(spend_txid);
                    match ln.settle_hold_invoice(preimage).await {
                        Ok(()) => {
                            info!("Reverse swap: client claimed; hold invoice settled");
                            settled = true;
                        }
                        Err(e) => {
                            // A settle that fails because it already happened is success. Any
                            // other failure is worth retrying: the preimage is public now, so
                            // there is no secret left to protect and nothing to lose by asking
                            // again on the next poll.
                            warn!("Reverse swap: settling the hold invoice failed: {e}");
                        }
                    }
                }
                if settled {
                    match run_blocking(|| chain.tx_confirmations(&swap.htlc_spk, &spend_txid))? {
                        Some(c) if c >= FINALITY_DEPTH => return Ok(SwapState::Claimed),
                        _ => {
                            // Settled but the claim is not yet buried. Keep watching: if it is
                            // replaced or reorged out, the loop falls back to refunding.
                        }
                    }
                }
            }
        }

        if run_blocking(|| chain.tip_height())? >= swap.timeout_height {
            if settled {
                // We already hold the Lightning money and the claim has not buried. Nothing
                // useful is left to do on-chain: our refund would conflict with a claim that
                // paid us. Wait for the claim to bury rather than fighting it.
                sleep(poll).await;
                continue;
            }
            warn!("Reverse swap: timeout reached without a claim; refunding the HTLC");
            let cfg = SpendWatchConfig::refund(
                REFUND_FEE_TARGET_BLOCKS,
                swap.fee_rate_sat_vb,
                cap,
                poll,
                FINALITY_DEPTH,
            )
            .with_known_ours(resume.our_spends.clone());
            match confirm_or_bump(
                chain,
                &swap.htlc_spk,
                funding_outpoint,
                &cfg,
                Some(&cpfp),
                &|txid| progress.spend_broadcast(txid),
                build,
            )
            .await
            .map_err(|e| anyhow!("refund broadcast/bump: {e}"))?
            {
                SpendOutcome::Confirmed { .. } => {
                    if let Err(e) = ln.cancel_hold_invoice(swap.payment_hash).await {
                        warn!("Reverse swap: failed to cancel hold invoice after refund: {e}");
                    }
                    return Ok(SwapState::Refunded);
                }
                // The client claimed while we were refunding. This is the case that used to
                // spin forever: our refund left the HTLC's history, so it read as "dropped" and
                // was re-broadcast against an already-spent output every two seconds, while the
                // preimage sat unclaimed in the winning transaction and the hold invoice was
                // never settled. We lost both legs. Now the outer loop settles from it instead.
                SpendOutcome::ConflictingSpend { tx } => {
                    info!(
                        "Reverse swap: the client's claim {} beat our refund; recovering the \
                         preimage from it",
                        tx.compute_txid()
                    );
                    sleep(poll).await;
                    continue;
                }
                SpendOutcome::DeadlineExceeded { last_txid, tip } => {
                    warn!(
                        "Reverse swap: refund {last_txid} still unconfirmed at height {tip}; \
                         retrying"
                    );
                    sleep(poll).await;
                    continue;
                }
            }
        }
        sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{ScriptBuf, Txid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::mock::MockChain;
    use swap_common::chain::FundingUtxo;
    use swap_common::htlc::{generate_preimage, payment_hash};
    use swap_common::onchain::build_claim_tx;
    use swap_common::random_keypair;

    const AMOUNT: u64 = 100_000;
    /// Chain tip the mocks report. The timeout sits a realistic 144 blocks above it, so the
    /// timelock checks exercise the same arithmetic production does.
    const MOCK_TIP: u32 = 700_000;
    const TIMEOUT: u32 = MOCK_TIP + 144;

    struct MockLn {
        state: Mutex<InvoiceState>,
        settled_preimage: Mutex<Option<[u8; 32]>>,
        cancelled: Mutex<bool>,
        /// The expiry height the "node" reports for the held HTLC. Scriptable so a test can
        /// reproduce a node that ignored the requested CLTV delta.
        htlc_expiry: Mutex<Option<u32>>,
        /// The delta the last `create_hold_invoice` asked for.
        requested_cltv_delta: Mutex<Option<u32>>,
    }
    impl MockLn {
        fn new(initial: InvoiceState) -> Self {
            Self {
                state: Mutex::new(initial),
                settled_preimage: Mutex::new(None),
                cancelled: Mutex::new(false),
                // Safe by default: an expiry derived from the delta the caller asked for.
                htlc_expiry: Mutex::new(None),
                requested_cltv_delta: Mutex::new(None),
            }
        }
        /// Report this exact expiry height for the held HTLC, whatever delta was requested.
        fn with_htlc_expiry(self, height: u32) -> Self {
            *self.htlc_expiry.lock().unwrap() = Some(height);
            self
        }
    }
    #[async_trait::async_trait]
    impl LightningBackend for MockLn {
        async fn node_info(&self) -> lightning_backend::Result<NodeInfo> {
            Ok(NodeInfo {
                pubkey: "mock".into(),
                alias: "mock".into(),
                synced_to_chain: true,
                chain_network: None,
            })
        }
        async fn create_hold_invoice(
            &self,
            req: lightning_backend::HoldInvoiceRequest,
        ) -> lightning_backend::Result<HoldInvoice> {
            assert_ne!(
                req.cltv_expiry_delta, 0,
                "a hold invoice must carry an explicit final CLTV delta"
            );
            *self.requested_cltv_delta.lock().unwrap() = Some(req.cltv_expiry_delta);
            Ok(HoldInvoice {
                bolt11: "lnbcrt-mock".into(),
                payment_hash: req.payment_hash,
                amount_msat: req.amount_msat,
            })
        }
        async fn create_invoice(
            &self,
            _amount_msat: u64,
            _expiry_secs: u64,
            _memo: &str,
        ) -> lightning_backend::Result<HoldInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn invoice_status(
            &self,
            _ph: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::InvoiceStatus> {
            let state = *self.state.lock().unwrap();
            let htlcs = if state == InvoiceState::Accepted {
                // Either the scripted expiry, or one derived from the delta that was asked for
                // (what an honest node does).
                let expiry = self.htlc_expiry.lock().unwrap().unwrap_or_else(|| {
                    MOCK_TIP + self.requested_cltv_delta.lock().unwrap().unwrap_or(0)
                });
                vec![lightning_backend::AcceptedHtlc {
                    amount_msat: 0,
                    expiry_height: expiry,
                }]
            } else {
                vec![]
            };
            Ok(lightning_backend::InvoiceStatus {
                state,
                amount_paid_msat: 0,
                htlcs,
            })
        }
        async fn settle_hold_invoice(&self, preimage: [u8; 32]) -> lightning_backend::Result<()> {
            *self.settled_preimage.lock().unwrap() = Some(preimage);
            *self.state.lock().unwrap() = InvoiceState::Settled;
            Ok(())
        }
        async fn cancel_hold_invoice(&self, _ph: [u8; 32]) -> lightning_backend::Result<()> {
            *self.cancelled.lock().unwrap() = true;
            Ok(())
        }
        async fn pay_invoice(
            &self,
            _bolt11: &str,
            _max_fee_msat: u64,
            _cltv_limit: Option<u32>,
        ) -> lightning_backend::Result<PaymentResult> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn payment_status(
            &self,
            _ph: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::PaymentStatus> {
            Ok(lightning_backend::PaymentStatus::Unknown)
        }
        async fn decode_invoice(&self, _bolt11: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
    }

    struct MockWallet {
        funding_outpoint: OutPoint,
        refund_spk: ScriptBuf,
    }
    impl OnchainWallet for MockWallet {
        fn fund_htlc(
            &self,
            _htlc_spk: &ScriptBuf,
            _amount_sat: u64,
        ) -> swap_common::Result<OutPoint> {
            Ok(self.funding_outpoint)
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.refund_spk.clone()
        }
    }

    /// The timelock model the tests run under: the shipped defaults with the mocks' timeout.
    fn params() -> TimelockParams {
        TimelockParams {
            htlc_timeout_blocks: TIMEOUT - MOCK_TIP,
            ..TimelockParams::default()
        }
    }

    fn dest() -> ScriptBuf {
        ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap()
    }

    fn funding_outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            vout: 0,
        }
    }

    #[tokio::test]
    async fn reverse_swap_happy_path_settles_invoice() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);

        let ln = MockLn::new(InvoiceState::Accepted); // client has paid the hold invoice
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        // The client's on-chain claim, spending the (mock) funding outpoint and revealing
        // the preimage in its witness.
        let outpoint = funding_outpoint();
        let claim_tx = build_claim_tx(
            outpoint,
            AMOUNT,
            &swap.htlc_script,
            dest(),
            1000,
            preimage,
            &claim_sk,
        )
        .unwrap();

        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            })
            .with_spend(claim_tx)
            .always_final();
        let wallet = MockWallet {
            funding_outpoint: outpoint,
            refund_spk: dest(),
        };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert_eq!(
            *ln.settled_preimage.lock().unwrap(),
            Some(preimage),
            "provider must settle the invoice with the preimage recovered from the claim"
        );
        assert!(chain.broadcasts().is_empty());
    }

    #[tokio::test]
    async fn reverse_swap_refunds_after_timeout() {
        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);

        let ln = MockLn::new(InvoiceState::Accepted);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        let outpoint = funding_outpoint();
        let chain = MockChain::new()
            .with_tip(TIMEOUT)
            .with_funding(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet {
            funding_outpoint: outpoint,
            refund_spk: dest(),
        };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Refunded);
        assert_eq!(
            chain.broadcast_count(),
            1,
            "a refund transaction must be broadcast"
        );
        assert!(
            *ln.cancelled.lock().unwrap(),
            "the hold invoice must be cancelled on refund"
        );
        assert!(ln.settled_preimage.lock().unwrap().is_none());
    }

    /// A wallet whose `fund_htlc` must never be reached: proves the provider refuses to commit
    /// on-chain funds rather than committing them and losing them.
    struct NeverFundWallet {
        refund_spk: ScriptBuf,
    }
    impl OnchainWallet for NeverFundWallet {
        fn fund_htlc(
            &self,
            _htlc_spk: &ScriptBuf,
            _amount_sat: u64,
        ) -> swap_common::Result<OutPoint> {
            panic!("the provider must not fund an HTLC whose lightning leg expires first");
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.refund_spk.clone()
        }
    }

    /// The reverse-swap theft vector.
    ///
    /// Left unset, LND applies `--bitcoin.timelockdelta` (80 blocks) to a hold invoice, while the
    /// on-chain HTLC refunds after 144. The incoming Lightning HTLC therefore dies ~64 blocks
    /// before the provider's refund branch opens: a client pays, waits for the LN HTLC to expire
    /// and return its sats, and *then* claims the on-chain HTLC for free.
    ///
    /// The provider must read back the realised expiry and refuse to fund.
    #[tokio::test]
    async fn refuses_to_fund_when_the_lightning_leg_expires_first() {
        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());

        // A node that reports an 80-block expiry whatever delta was requested.
        let ln = MockLn::new(InvoiceState::Accepted).with_htlc_expiry(MOCK_TIP + 80);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        let chain = MockChain::new().always_final().with_tip(MOCK_TIP);
        let wallet = NeverFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        match final_state {
            SwapState::Failed(reason) => assert!(
                reason.contains("timelock violation"),
                "expected a timelock refusal, got: {reason}"
            ),
            other => panic!("expected the swap to be refused, got {other:?}"),
        }
        assert!(
            *ln.cancelled.lock().unwrap(),
            "the hold invoice must be cancelled so the client's payment is returned in full"
        );
        assert!(ln.settled_preimage.lock().unwrap().is_none());
        assert!(chain.broadcasts().is_empty());
    }

    /// The hold invoice must carry an explicit final CLTV delta that outlives the on-chain
    /// timeout, rather than letting the node substitute its own default.
    #[tokio::test]
    async fn hold_invoice_carries_a_cltv_delta_that_outlives_the_onchain_timeout() {
        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());

        let ln = MockLn::new(InvoiceState::Open);
        let p = params();
        init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            p,
        )
        .await
        .unwrap();

        let delta = ln
            .requested_cltv_delta
            .lock()
            .unwrap()
            .expect("a delta must be requested");
        assert_eq!(delta, 144 + 18 + 24 + 30);
        assert!(
            delta > p.htlc_timeout_blocks + p.refund_confirm_blocks,
            "the lightning leg must outlive the on-chain refund window"
        );
    }

    /// An HTLC that is already funded must still be driven to a refund, even when the remaining
    /// window is too short to have started one. Refusing there would strand the coins.
    #[tokio::test]
    async fn an_already_funded_htlc_is_still_driven_to_refund() {
        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());

        // A node reporting an unsafe expiry: it is too late for that to matter, the coins are
        // already committed.
        let ln = MockLn::new(InvoiceState::Accepted).with_htlc_expiry(MOCK_TIP + 1);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        let outpoint = funding_outpoint();
        let chain = MockChain::new()
            .with_tip(TIMEOUT)
            .with_funding(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet {
            funding_outpoint: outpoint,
            refund_spk: dest(),
        };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();
        assert_eq!(final_state, SwapState::Refunded);
        assert_eq!(chain.broadcast_count(), 1);
    }

    /// A backend outage is not a protocol outcome, and a funded swap must outlive one.
    ///
    /// Ten transient failures used to end the swap: the driver got ten immediate re-entries and
    /// then wrote `SwapState::Failed`, which is terminal. Terminal records are filtered out of
    /// `load_active`, so no restart resumed it; the reservation was released with the task; and
    /// the provider's coins sat in an HTLC with nobody left to refund them. Ten re-entries with
    /// no delay between them is what one Electrum restart costs.
    ///
    /// This drives the real loop: the same store, the same failure accounting, the same decision
    /// `finish_driver_run` takes, through an outage that lasts well past the old budget and across
    /// a restart in the middle of it.
    #[tokio::test]
    async fn a_funded_reverse_swap_outlives_an_outage_and_still_refunds() {
        use crate::recovery::{Recovery, MAX_DRIVER_RETRIES};
        use std::sync::Arc;
        use swap_common::chain::mock::FlakyChain;
        use swap_common::store::{JsonFileSwapStore, SwapRecord, SwapStore};
        use swap_common::{NetworkSpec, SwapDirection};

        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());

        let ln = MockLn::new(InvoiceState::Accepted);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        // The state the outage begins in: our funding is on chain, past the timeout, so the only
        // thing left to do is the refund only we can make.
        let outpoint = funding_outpoint();
        let swap_id = uuid::Uuid::new_v4();
        let record = SwapRecord {
            swap_id,
            direction: SwapDirection::Reverse,
            peer: "client".into(),
            network: NetworkSpec::Regtest,
            payment_hash_hex: hex::encode(swap.payment_hash),
            onchain_amount_sat: AMOUNT,
            fee_rate_sat_vb: swap.fee_rate_sat_vb,
            htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
            timeout_height: TIMEOUT,
            secret_key_hex: hex::encode(swap.refund_key.secret_bytes()),
            invoice: swap.invoice.clone(),
            required_confirmations: 2,
            funding_txid_hex: Some(outpoint.txid.to_string()),
            funding_vout: Some(outpoint.vout),
            state: SwapState::LockupConfirmed,
            ..SwapRecord::new_progress()
        };

        let dir = std::env::temp_dir().join(format!("pubky-swap-recovery-{swap_id}"));
        let mut store: Arc<dyn SwapStore> = Arc::new(JsonFileSwapStore::new(&dir).unwrap());
        store.put(&record).unwrap();

        let chain = FlakyChain::new(
            MockChain::new()
                .with_tip(TIMEOUT)
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 3,
                })
                .always_final(),
            u32::MAX,
        );
        let wallet = MockWallet {
            funding_outpoint: outpoint,
            refund_spk: dest(),
        };

        // Long enough that the old budget would have been spent twice over.
        let outage_runs = MAX_DRIVER_RETRIES + 2;
        let mut failures = 0u32;
        let mut restarted = false;
        let final_state = loop {
            assert!(failures < 100, "the driver never got anywhere");
            // Re-read the record every time, the way a re-entered or restarted driver does.
            let rec = store
                .get(swap_id)
                .unwrap()
                .expect("the record must never leave the store");
            assert!(
                !rec.state.is_terminal(),
                "an outage made a funded swap terminal after {failures} failures"
            );
            let resumed = crate::reverse_swap_from_record(&rec, params()).unwrap();
            let resume = rec.resume();
            let progress = crate::StoreProgress {
                store: store.clone(),
                record: std::sync::Mutex::new(rec),
            };
            match drive_reverse_swap(
                &ln,
                &chain,
                &wallet,
                &resumed,
                2,
                Duration::ZERO,
                &resume,
                &progress,
            )
            .await
            {
                Ok(state) if state.is_terminal() => break state,
                Ok(_) => {}
                Err(e) => {
                    failures += 1;
                    let (rec, recovery) = progress.record_failure(&e, crate::is_transient(&e));
                    assert!(
                        matches!(recovery, Recovery::Retry(_)),
                        "failure {failures} gave up on a swap holding {AMOUNT} sat: {e}"
                    );
                    assert_eq!(rec.retry_count, failures);
                }
            }

            if failures == outage_runs && !restarted {
                restarted = true;
                // The daemon restarts mid-outage. Everything it needs to carry on has to be on
                // disk, because everything in memory has just gone.
                store = Arc::new(JsonFileSwapStore::new(&dir).unwrap());
                let active = store.load_active().unwrap();
                assert_eq!(
                    active.len(),
                    1,
                    "a funded swap that failed {failures} times must still be resumed"
                );
                assert_eq!(active[0].swap_id, swap_id);
                assert!(active[0].funds_at_risk());
                assert!(
                    crate::needs_recovery(&active[0]),
                    "and it must be reported as needing an operator"
                );
                assert!(
                    active[0].next_retry_at_unix.is_some(),
                    "the backoff must survive the restart rather than restarting from zero"
                );
                assert!(crate::resume_delay(&active[0]) <= crate::recovery::BACKOFF_MAX);
                // The backend comes back.
                chain.recover();
            }
        };

        assert_eq!(final_state, SwapState::Refunded);
        assert!(
            chain.failed_calls() >= outage_runs,
            "the outage was meant to fail at least {outage_runs} calls, it failed {}",
            chain.failed_calls()
        );
        assert_eq!(
            chain.inner().broadcast_count(),
            1,
            "the refund must actually reach the wire once the backend is back"
        );
        let done = store.get(swap_id).unwrap().unwrap();
        assert_eq!(done.retry_count, 0, "progress clears the backoff");
        assert!(done.last_error.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cancelled hold invoice is a fatal answer only while nothing is committed on chain.
    ///
    /// The provider's coins are in the HTLC and, in a reverse swap, the *client* chose the
    /// preimage: a cancel returns their Lightning payment and leaves them able to claim the
    /// on-chain contract for nothing. Returning `Failed` here marks the record terminal, so it
    /// leaves `load_active`, no restart resumes it, and the refund that races the client is never
    /// broadcast. The whole funded amount is lost on the one branch the provider holds the key
    /// for.
    ///
    /// LND cancels an accepted hold invoice as its incoming HTLC nears expiry, and the timelock
    /// model deliberately makes the Lightning leg outlive the on-chain refund, so this is the
    /// ordinary end of an unhappy swap rather than an exotic case.
    #[tokio::test]
    async fn a_cancelled_invoice_does_not_abandon_an_already_funded_htlc() {
        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());

        let ln = MockLn::new(InvoiceState::Accepted);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        // The state a restart finds: our funding is on chain and confirmed, and the node has
        // since cancelled the invoice.
        let outpoint = funding_outpoint();
        let ln = MockLn::new(InvoiceState::Cancelled);
        let chain = MockChain::new()
            .with_tip(TIMEOUT)
            .with_funding(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            })
            .always_final();
        let wallet = NeverFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume {
                funding: Some(outpoint),
                ..Default::default()
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(
            final_state,
            SwapState::Refunded,
            "a funded HTLC must be refunded, not abandoned because the invoice was cancelled"
        );
        assert_eq!(
            chain.broadcast_count(),
            1,
            "and the refund must actually reach the wire"
        );
    }

    /// The same hole reached through the intent marker rather than a recorded outpoint: a driver
    /// that crashed between broadcasting its funding and writing down where it landed.
    #[tokio::test]
    async fn a_cancelled_invoice_does_not_abandon_a_funding_we_only_intended() {
        let secp = Secp256k1::new();
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());

        let ln = MockLn::new(InvoiceState::Accepted);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        let outpoint = funding_outpoint();
        let ln = MockLn::new(InvoiceState::Cancelled);
        let chain = MockChain::new()
            .with_tip(TIMEOUT)
            .with_funding(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            })
            .always_final();
        let wallet = NeverFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume {
                funding_intent_at_height: Some(MOCK_TIP),
                ..Default::default()
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Refunded);
        assert_eq!(chain.broadcast_count(), 1);
    }

    /// A wallet that must never be asked to fund — used to prove a resumed driver does not
    /// re-fund an already-funded HTLC.
    struct PanicFundWallet {
        refund_spk: ScriptBuf,
    }
    impl OnchainWallet for PanicFundWallet {
        fn fund_htlc(
            &self,
            _htlc_spk: &ScriptBuf,
            _amount_sat: u64,
        ) -> swap_common::Result<OutPoint> {
            panic!("resumed driver must not re-fund the HTLC");
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.refund_spk.clone()
        }
    }

    /// A wallet that counts fundings instead of refusing them, for the cases where the assertion
    /// is "it was not called" rather than "it must never be called".
    struct CountingWallet {
        refund_spk: ScriptBuf,
        funded: Mutex<Vec<u64>>,
    }
    impl CountingWallet {
        fn new() -> Self {
            Self {
                refund_spk: dest(),
                funded: Mutex::new(Vec::new()),
            }
        }
        fn fund_count(&self) -> usize {
            self.funded.lock().unwrap().len()
        }
    }
    impl OnchainWallet for CountingWallet {
        fn fund_htlc(
            &self,
            _htlc_spk: &ScriptBuf,
            amount_sat: u64,
        ) -> swap_common::Result<OutPoint> {
            self.funded.lock().unwrap().push(amount_sat);
            Ok(funding_outpoint())
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.refund_spk.clone()
        }
    }

    /// A sink whose intent markers cannot be written, standing in for a full or unwritable disk.
    struct UnwritableSink;
    impl ProgressSink for UnwritableSink {
        fn funding_intent(&self, _tip: u32) -> Result<()> {
            Err(anyhow!("disk full"))
        }
    }

    /// Set up a reverse swap plus the client's claim of it, which several resume tests need.
    async fn swap_with_claim(ln: &MockLn) -> (ReverseSwap, bitcoin::Transaction, [u8; 32]) {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let swap = init_reverse_swap(
            ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();
        let claim_tx = build_claim_tx(
            funding_outpoint(),
            AMOUNT,
            &swap.htlc_script,
            dest(),
            1000,
            preimage,
            &claim_sk,
        )
        .unwrap();
        (swap, claim_tx, preimage)
    }

    /// The double-funding hole, in the shape that actually loses the money.
    ///
    /// A provider broadcasts its funding, crashes before recording the outpoint, and comes back
    /// after the client has claimed. Nothing is unspent, so the UTXO set says "never funded" and
    /// the pre-fix driver funded a second HTLC into a script whose preimage the client already
    /// holds. They claim that one too and the provider is out the whole amount, with a hold
    /// invoice it can settle only once.
    ///
    /// The intent marker is what makes this answerable, and the chain's history is what tells
    /// "the broadcast never landed" apart from "it landed and has been spent".
    #[tokio::test]
    async fn a_resumed_driver_adopts_a_funding_the_counterparty_has_already_spent() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, preimage) = swap_with_claim(&ln).await;

        // The chain as it looks after the client's claim confirmed: no unspent output paying the
        // HTLC, but a history that still records the funding.
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spent_output(funding_outpoint(), AMOUNT, claim_tx.compute_txid())
            .with_spend(claim_tx);
        let wallet = PanicFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume {
                funding: None,
                funding_intent_at_height: Some(MOCK_TIP),
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert_eq!(
            *ln.settled_preimage.lock().unwrap(),
            Some(preimage),
            "adopting the spent funding is what lets the provider settle and be paid"
        );
    }

    /// Several outputs can pay the HTLC script: the address is public from the moment it is in a
    /// `SwapAccept`. The spend builders take one input, so only one can be driven, and the one
    /// worth driving is whichever the client claimed: its spend carries the preimage, which is
    /// what settles the Lightning leg and pays for the swap. Cancelling the invoice instead, or
    /// picking by depth alone, forfeits a settle already earned.
    #[tokio::test]
    async fn several_fundings_prefer_the_one_whose_spend_reveals_the_preimage() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, _) = swap_with_claim(&ln).await;
        let other = OutPoint {
            txid: Txid::from_str(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            vout: 0,
        };

        // `other` is deeper, so depth alone would pick it. Only `funding_outpoint()` is spent by
        // a transaction carrying the preimage.
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spent_output(other, AMOUNT, claim_tx.compute_txid())
            .with_spent_output(funding_outpoint(), AMOUNT, claim_tx.compute_txid())
            .with_spend(claim_tx);
        let history = chain.find_historical_outputs(&swap.htlc_spk).unwrap();
        assert_eq!(history.len(), 2);

        let chosen = select_recorded_funding(
            &chain,
            &swap.htlc_spk,
            &swap.payment_hash,
            swap.onchain_amount_sat,
            &history,
        )
        .unwrap()
        .expect("one of the candidates must be chosen");
        assert_eq!(chosen, funding_outpoint());
    }

    /// A recorded funding outpoint is normally taken as established, and should be: something
    /// watched it confirm. A reorg is the one event that can undo that after the fact, and it
    /// used to end in a log line saying the driver would re-validate, which the driver had no way
    /// of knowing to do.
    #[tokio::test]
    async fn a_reorg_makes_a_driver_re_establish_its_funding() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, preimage) = swap_with_claim(&ln).await;

        // The funding is gone from the UTXO set, but the history still records it and the client
        // has claimed it. Without the marker the driver would drive a phantom outpoint; with it,
        // it goes back to the chain, finds the real one, and settles.
        let moved = OutPoint {
            txid: Txid::from_str(
                "7777777777777777777777777777777777777777777777777777777777777777",
            )
            .unwrap(),
            vout: 0,
        };
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spent_output(funding_outpoint(), AMOUNT, claim_tx.compute_txid())
            .with_spend(claim_tx);
        let wallet = PanicFundWallet { refund_spk: dest() };

        // Bounded: without the fix the driver watches an outpoint that does not exist and never
        // finishes, and a hang says far less than a failure.
        let final_state = tokio::time::timeout(
            Duration::from_secs(5),
            drive_reverse_swap(
                &ln,
                &chain,
                &wallet,
                &swap,
                2,
                Duration::from_millis(0),
                &Resume {
                    // The outpoint the record believes in, which the reorg invalidated.
                    funding: Some(moved),
                    funding_intent_at_height: Some(MOCK_TIP),
                    our_spends: Vec::new(),
                    reorg_seen_at_height: Some(MOCK_TIP - 2),
                },
                &(),
            ),
        )
        .await
        .expect("the driver must re-establish the funding rather than watch a phantom outpoint")
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert_eq!(
            *ln.settled_preimage.lock().unwrap(),
            Some(preimage),
            "re-establishing the funding is what lets the provider settle and be paid"
        );
    }

    /// And with no reorg on the record, a known outpoint is still taken at its word: this must
    /// not turn every resume into a chain scan.
    #[tokio::test]
    async fn without_a_reorg_a_recorded_funding_is_trusted() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, _) = swap_with_claim(&ln).await;
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spend(claim_tx);
        let wallet = PanicFundWallet { refund_spk: dest() };

        // Nothing pays the script at all, so any lookup would come back empty. The driver still
        // proceeds on its recorded outpoint.
        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume {
                funding: Some(funding_outpoint()),
                funding_intent_at_height: None,
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
    }

    /// Without an intent marker there is nothing to be careful about: a fresh swap whose HTLC is
    /// unfunded funds it, exactly as before.
    #[tokio::test]
    async fn a_fresh_swap_still_funds_its_htlc() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, _) = swap_with_claim(&ln).await;
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spend(claim_tx);
        let wallet = CountingWallet::new();

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert_eq!(wallet.fund_count(), 1);
    }

    /// A funding intent that cannot be persisted stops the funding, and returns the payment.
    ///
    /// Broadcasting anyway would put coins into an HTLC that no restart can find, and the marker
    /// is the only thing that would have pointed at them. Nothing is on the wire at that point,
    /// so the client's held payment is cancelled rather than left waiting on a swap that will
    /// never happen.
    #[tokio::test]
    async fn funding_stops_when_its_intent_cannot_be_recorded() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, _) = swap_with_claim(&ln).await;
        // The claim is scripted so that a driver which funds anyway still terminates: this test
        // is about the funding not happening, and a hang would say that far less clearly.
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spend(claim_tx);
        let wallet = CountingWallet::new();

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &UnwritableSink,
        )
        .await
        .unwrap();

        match &final_state {
            SwapState::Failed(why) => assert!(why.contains("disk full"), "got: {why}"),
            other => panic!("expected a failed swap, got {other:?}"),
        }
        assert_eq!(
            wallet.fund_count(),
            0,
            "nothing may be broadcast once the marker has failed to write"
        );
        assert!(
            *ln.cancelled.lock().unwrap(),
            "the client's held payment is returned, since nothing was ever committed"
        );
    }

    /// An empty chain is not proof that the broadcast never happened.
    ///
    /// One Electrum server that is behind, re-indexing, or simply a different server from the one
    /// the funding was broadcast through answers "nothing pays this script" for a funding that
    /// exists. Funding again on that answer is the loss this whole path exists to avoid, so the
    /// driver waits instead, and gives up only when the swap's own timeout arrives.
    #[tokio::test]
    async fn a_recorded_funding_that_never_appears_expires_rather_than_funding_again() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, _, _) = swap_with_claim(&ln).await;
        // Nothing on chain, ever, and the tip is already past the swap's timeout so the watch
        // gives up on its first pass.
        let chain = MockChain::new().always_final().with_tip(TIMEOUT);
        let wallet = CountingWallet::new();

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume {
                funding: None,
                funding_intent_at_height: Some(MOCK_TIP),
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Expired);
        assert_eq!(wallet.fund_count(), 0, "never fund on a recorded intent");
        assert!(
            *ln.cancelled.lock().unwrap(),
            "giving up returns the client's payment in full"
        );
    }

    /// A wallet whose funding call fails after the transaction is already on the wire.
    ///
    /// Both real wallets can do this: a lost gRPC response, a reply that will not decode. The
    /// money has moved and the caller cannot tell, so this must take the same route as a crash in
    /// the same place, not end the swap.
    struct LosesTheResponseWallet {
        refund_spk: ScriptBuf,
        calls: Mutex<u32>,
    }
    impl OnchainWallet for LosesTheResponseWallet {
        fn fund_htlc(
            &self,
            _htlc_spk: &ScriptBuf,
            _amount_sat: u64,
        ) -> swap_common::Result<OutPoint> {
            *self.calls.lock().unwrap() += 1;
            Err(swap_common::SwapError::Other("lost the response".into()))
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.refund_spk.clone()
        }
    }

    /// A funding whose outcome is unknown is watched for, not retried and not abandoned.
    ///
    /// Returning an error here used to end the swap: the error is not transient, so the driver
    /// marked the record terminal, `load_active` skipped it forever, and a funded HTLC was left
    /// with no refund and an open hold invoice.
    #[tokio::test]
    async fn a_funding_whose_outcome_is_unknown_is_watched_for() {
        let ln = MockLn::new(InvoiceState::Accepted);
        let (swap, claim_tx, preimage) = swap_with_claim(&ln).await;
        // The funding did land, and the client claimed it, which is what the watch will find.
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spent_output(funding_outpoint(), AMOUNT, claim_tx.compute_txid())
            .with_spend(claim_tx);
        let wallet = LosesTheResponseWallet {
            refund_spk: dest(),
            calls: Mutex::new(0),
        };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert_eq!(
            *wallet.calls.lock().unwrap(),
            1,
            "asked to fund exactly once"
        );
        assert_eq!(
            *ln.settled_preimage.lock().unwrap(),
            Some(preimage),
            "the funding it could not confirm was found and settled from"
        );
    }

    #[tokio::test]
    async fn resume_with_known_funding_does_not_refund_or_double_fund() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);

        let ln = MockLn::new(InvoiceState::Accepted);
        let swap = init_reverse_swap(
            &ln,
            &claim_pk,
            refund_sk,
            &refund_pk,
            ph,
            AMOUNT,
            1000,
            5,
            TIMEOUT,
            3600,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();

        let outpoint = funding_outpoint();
        let claim_tx = build_claim_tx(
            outpoint,
            AMOUNT,
            &swap.htlc_script,
            dest(),
            1000,
            preimage,
            &claim_sk,
        )
        .unwrap();

        // The funding UTXO is gone (already spent by the client's claim), so a fresh driver
        // would try to fund again — but on resume with a known outpoint it must not.
        let chain = MockChain::new()
            .always_final()
            .with_tip(MOCK_TIP)
            .with_spend(claim_tx);
        let wallet = PanicFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            // resumed: funding already known
            &Resume {
                funding: Some(outpoint),
                ..Default::default()
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert!(
            chain.broadcasts().is_empty(),
            "resumed claim path broadcasts nothing (no refund)"
        );
    }
}
