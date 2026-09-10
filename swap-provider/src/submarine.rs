//! Submarine-swap (on-chain → Lightning) provider orchestration.
//!
//! Mirror of the reverse swap, with the legs swapped:
//! 1. The client supplies the Lightning **invoice** they want paid; the provider decodes its
//!    payment hash and amount.
//! 2. The provider builds the on-chain HTLC (claim = provider's key, refund = client's key)
//!    and tells the client the address to fund.
//! 3. The client funds the HTLC on-chain.
//! 4. Once it confirms, the provider **pays the invoice**, learning the preimage.
//! 5. The provider **claims** the on-chain HTLC with that preimage.
//! 6. If the provider never pays/claims, the client refunds after the timeout (handled
//!    client-side).
//!
//! The provider only pays the invoice *after* the on-chain HTLC has confirmed, so a failed
//! Lightning payment costs it nothing on-chain.

use crate::reverse::{OnchainWallet, ProgressSink, Resume};
use anyhow::{anyhow, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, OutPoint, PublicKey, ScriptBuf, Txid};
use lightning_backend::{LightningBackend, PaymentStatus};
use std::time::Duration;
use swap_common::chain::{
    run_blocking, select_funding, ChainWatcher, FundingSelection, DEFAULT_MAX_OVERPAY_SAT,
};
use swap_common::fee_bump::{confirm_or_bump, SpendOutcome, SpendWatchConfig};
use swap_common::htlc::{build_htlc_script, htlc_p2wsh_address, payment_hash, PaymentHash};
use swap_common::onchain::{
    build_claim_tx, estimate_spend_fee, extract_preimage, fee_rate_cap, spend_vsize,
    ABSOLUTE_MAX_FEE_RATE_SAT_VB, CLAIM_FEE_TARGET_BLOCKS, DEFAULT_MAX_FEE_BPS,
};
use swap_common::reorg::FINALITY_DEPTH;
use swap_common::timelock::{self, TimelockParams};
use swap_common::SwapState;
use tokio::time::sleep;
use tracing::{error, info, warn};

/// State describing one provider-side submarine swap.
pub struct SubmarineSwap {
    pub payment_hash: PaymentHash,
    /// Amount the client locks on-chain (invoice amount + provider fee).
    pub onchain_amount_sat: u64,
    pub fee_rate_sat_vb: u64,
    pub htlc_script: ScriptBuf,
    pub htlc_spk: ScriptBuf,
    pub timeout_height: u32,
    /// Provider's key for the HTLC claim branch.
    pub claim_key: SecretKey,
    /// The Lightning invoice the provider must pay.
    pub invoice: String,
    /// Routing-fee cap (msat) for paying the invoice.
    pub max_routing_fee_msat: u64,
    /// The timelock model this swap runs under. Re-checked immediately before the invoice is
    /// paid, because paying is the irreversible step.
    pub timelock: TimelockParams,
}

/// Create the submarine swap: decode the client's invoice and build the on-chain HTLC the
/// client must fund.
#[allow(clippy::too_many_arguments)]
pub async fn init_submarine_swap(
    ln: &dyn LightningBackend,
    invoice: &str,
    client_refund_pubkey: &PublicKey,
    provider_claim_key: SecretKey,
    provider_claim_pubkey: &PublicKey,
    // What the quote said this swap is for. The invoice is the client's own document and its
    // amount is what actually gets locked and paid, so the two have to agree before either is
    // used for anything.
    quoted_amount_sat: u64,
    provider_fee_sat: u64,
    fee_rate_sat_vb: u64,
    max_routing_fee_msat: u64,
    tip: u32,
    timeout_height: u32,
    network: Network,
    timelock: TimelockParams,
) -> Result<SubmarineSwap> {
    let decoded = ln
        .decode_invoice(invoice)
        .await
        .map_err(|e| anyhow!("decode invoice: {e}"))?;
    let payment_hash = decoded.payment_hash;
    // An amountless invoice lets the payer choose what to send, which is not a swap. Reject it
    // rather than deriving an on-chain amount from a zero.
    if !decoded.amount_is_explicit {
        return Err(anyhow!(
            "the client's invoice carries no amount; a swap needs an amount-bearing invoice"
        ));
    }
    // A sub-satoshi remainder would be paid over Lightning but never charged on-chain.
    if decoded.amount_msat % 1000 != 0 {
        return Err(anyhow!(
            "invoice amount {} msat is not a whole number of satoshis",
            decoded.amount_msat
        ));
    }
    let invoice_amount_sat = decoded.amount_msat / 1000;
    // The quote is what was priced, rate-limited and reserved against the risk limits; the
    // invoice is what the swap actually runs on. Nothing compared them, so a peer could take a
    // quote for the 10,000 sat minimum and hand back an invoice for five million: the fee was
    // charged on the small number and the exposure was booked on it too, while the provider
    // committed to paying the large one.
    if invoice_amount_sat != quoted_amount_sat {
        return Err(anyhow!(
            "the client's invoice is for {invoice_amount_sat} sat but the quote is for \
             {quoted_amount_sat} sat"
        ));
    }
    // The outgoing Lightning HTLC has to end early enough to still claim on chain afterwards.
    // This refuses an invoice that could never fit before a payment is attempted; the `cltv_limit`
    // on the payment itself is what enforces it against the route.
    if let Err(violation) = timelock::check_submarine_invoice_cltv(
        tip,
        timeout_height,
        decoded.min_final_cltv_expiry,
        &timelock,
    ) {
        return Err(anyhow!(
            "the client's invoice demands too much final CLTV: {violation}"
        ));
    }
    let onchain_amount_sat = invoice_amount_sat
        .checked_add(provider_fee_sat)
        .ok_or_else(|| {
            anyhow!("on-chain amount overflows: {invoice_amount_sat} + {provider_fee_sat} sat")
        })?;

    // Claim branch = provider (who learns the preimage by paying the invoice); refund branch
    // = client (who reclaims on-chain if the provider doesn't pay before the timeout).
    let htlc_script = build_htlc_script(
        &payment_hash,
        provider_claim_pubkey,
        client_refund_pubkey,
        timeout_height,
    );
    let htlc_spk = htlc_p2wsh_address(&htlc_script, network).script_pubkey();

    Ok(SubmarineSwap {
        payment_hash,
        onchain_amount_sat,
        fee_rate_sat_vb,
        htlc_script,
        htlc_spk,
        timeout_height,
        claim_key: provider_claim_key,
        invoice: invoice.to_string(),
        max_routing_fee_msat,
        timelock,
    })
}

/// How many times a driver asks the node about a payment before handing control back.
///
/// Waiting in place is cheap (one call per poll); handing back re-runs the funding lookup, the
/// spend lookup and the reorg guard as well. Coming back around periodically is still worth it,
/// because those are the checks that notice a reorg underneath a payment that is taking its time.
const PAYMENT_POLL_ITERATIONS: u32 = 30;

/// Drive a submarine swap to a terminal [`SwapState`].
///
/// [`ChainWatcher`] calls are blocking, so they are wrapped in [`run_blocking`] to avoid stalling
/// the async runtime. `poll` is injected for testability.
#[allow(clippy::too_many_arguments)]
pub async fn drive_submarine_swap(
    ln: &dyn LightningBackend,
    chain: &dyn ChainWatcher,
    wallet: &dyn OnchainWallet,
    swap: &SubmarineSwap,
    required_confirmations: u32,
    poll: Duration,
    // What a previous run of this swap already did. The provider does not fund a submarine
    // swap, so only the observed funding and our own spends matter here.
    resume: &Resume,
    // True when a previous run recorded that it was about to pay the invoice. Combined with the
    // node's own answer, this is what keeps a resumed driver from paying twice.
    already_attempted_payment: bool,
    progress: &dyn ProgressSink,
) -> Result<SwapState> {
    // 1. Establish the funding outpoint. On a fresh start, wait for the client to fund the HTLC
    //    (give up at timeout — nothing at risk yet). On resume, adopt the known outpoint, and if
    //    we already claimed before the crash, finish immediately.
    let funding_outpoint = match resume.funding {
        Some(op) => {
            if let Some(spend) = run_blocking(|| chain.find_spend(&swap.htlc_spk, &op))? {
                if extract_preimage(&spend, &op, &swap.payment_hash).is_some() {
                    info!("Submarine swap: already claimed before restart");
                    return Ok(SwapState::Claimed);
                }
            }
            op
        }
        None => loop {
            // Classify what is actually paying the address rather than asking "is there an
            // output worth exactly X". The HTLC address is public from the moment it is in the
            // `SwapAccept`, so an underpayment, an overpayment, and a double payment are all
            // things that happen; a single "not funded yet" answer for all of them means waiting
            // out the whole timeout instead of saying what is wrong.
            let outputs = run_blocking(|| chain.find_outputs(&swap.htlc_spk))?;
            match select_funding(&outputs, swap.onchain_amount_sat, DEFAULT_MAX_OVERPAY_SAT) {
                FundingSelection::Exact(utxo) => {
                    if utxo.confirmations >= required_confirmations {
                        progress.funded(utxo.outpoint);
                        break utxo.outpoint;
                    }
                }
                FundingSelection::Overpaid { utxo, excess_sat } => {
                    if utxo.confirmations >= required_confirmations {
                        info!(
                            "Submarine swap: the client overpaid by {excess_sat} sat; sweeping \
                             the whole output"
                        );
                        progress.funded(utxo.outpoint);
                        break utxo.outpoint;
                    }
                }
                FundingSelection::Underpaid { got_sat } => {
                    warn!(
                        "Submarine swap: the HTLC holds {got_sat} sat but the swap is priced on \
                         {}. Not proceeding; the client refunds at the timeout.",
                        swap.onchain_amount_sat
                    );
                    return Ok(SwapState::Failed(format!(
                        "funding is short: {got_sat} of {} sat",
                        swap.onchain_amount_sat
                    )));
                }
                FundingSelection::ExcessiveOverpay { got_sat } => {
                    warn!(
                        "Submarine swap: the HTLC holds {got_sat} sat against an expected {}, \
                         far beyond tolerance. Not proceeding; the client refunds at the timeout.",
                        swap.onchain_amount_sat
                    );
                    return Ok(SwapState::Failed(format!(
                        "funding of {got_sat} sat is implausible for a {} sat swap",
                        swap.onchain_amount_sat
                    )));
                }
                FundingSelection::Multiple(utxos) => {
                    warn!(
                        "Submarine swap: {} separate outputs pay the HTLC address. The spend \
                         builders take a single input, so this is left for the client's refund.",
                        utxos.len()
                    );
                    return Ok(SwapState::Failed(
                        "several outputs pay the HTLC address".into(),
                    ));
                }
                FundingSelection::None => {}
            }
            if run_blocking(|| chain.tip_height())? >= swap.timeout_height {
                return Ok(SwapState::Expired);
            }
            sleep(poll).await;
        },
    };
    info!("Submarine swap: HTLC funding confirmed; paying the Lightning invoice");

    // Reorg guard: paying the invoice is irreversible, so re-confirm the funding is STILL buried
    // to the required depth right before paying. A reorg that dropped it below that depth (or
    // orphaned it entirely) means we must not pay — otherwise we'd pay Lightning for an HTLC that
    // no longer exists. (If it was instead spent by our own earlier claim on resume, finish.)
    //
    // This is also where the amount the claim will be signed over comes from. A BIP143 sighash
    // commits to the input's value, so signing over anything but what the output actually holds
    // produces a signature that does not validate and a claim that can never be broadcast. The
    // quoted amount is not that value: an overpaying client is explicitly accepted above, and a
    // resumed driver adopts an outpoint it has not measured. Read it from the chain, once, here.
    let funding_value_sat =
        match run_blocking(|| chain.outpoint_status(&swap.htlc_spk, &funding_outpoint))? {
            Some(utxo) if utxo.confirmations >= required_confirmations => utxo.value_sat,
            _ => {
                if run_blocking(|| chain.find_spend(&swap.htlc_spk, &funding_outpoint))?.is_some() {
                    info!("Submarine swap: funding already spent (prior claim); done");
                    return Ok(SwapState::Claimed);
                }
                warn!(
                    "Submarine swap: funding no longer confirmed at required depth (reorg?); not \
                     paying"
                );
                return Ok(SwapState::Failed(
                    "funding reorged below required confirmations before payment".into(),
                ));
            }
        };
    if funding_value_sat != swap.onchain_amount_sat {
        info!(
            "Submarine swap: the HTLC holds {funding_value_sat} sat against a quoted {}; the \
             claim is signed over what is there.",
            swap.onchain_amount_sat
        );
    }

    // Claim-window guard: paying is irreversible, but the on-chain claim that recovers the money
    // is a race against the client's refund branch. A client that funds late -- or a funding that
    // confirms slowly -- can leave only a block or two before that branch opens, and the client
    // can fee-bump its refund past our claim. Refusing to pay costs nothing: the client simply
    // refunds its own funding.
    let tip = run_blocking(|| chain.tip_height())?;
    if let Err(violation) =
        timelock::check_submarine_before_pay(tip, swap.timeout_height, &swap.timelock)
    {
        warn!(
            "Submarine swap: not paying the invoice, {violation}. The client's on-chain funding \
             is untouched and refunds to them at the timeout."
        );
        return Ok(SwapState::Failed(format!(
            "insufficient claim window: {violation}"
        )));
    }

    // 2. Pay the invoice to learn the preimage. A failure costs nothing on-chain: the client
    //    simply refunds after the timeout.
    //
    //    Ask the node first. A driver resumed after a crash cannot tell from its own state
    //    whether a payment went out, and the two possibilities want opposite actions: paying
    //    again risks paying twice, while assuming it was paid abandons an HTLC we have already
    //    bought. The node knows, so ask it.
    // A payment that is in flight, or that the node cannot account for, is waited on here rather
    // than by returning and having the whole driver re-enter. Handing back meant re-running the
    // funding lookup, the spend lookup and the reorg guard on every two-second poll, which is
    // several chain calls per swap per poll against a single Electrum server. Bounded, so the
    // driver still comes back around periodically and re-checks everything it skipped.
    let mut payment = None;
    for _ in 0..PAYMENT_POLL_ITERATIONS {
        match ln
            .payment_status(swap.payment_hash)
            .await
            .map_err(|e| anyhow!("payment status: {e}"))?
        {
            PaymentStatus::Succeeded(p) => {
                info!("Submarine swap: the invoice was already paid; proceeding to the claim");
                progress.invoice_paid();
                payment = Some(p);
                break;
            }
            PaymentStatus::InFlight => {
                // Wait it out rather than launching a second attempt. The claim-window gate above
                // bounds how long this can go on.
                info!("Submarine swap: a payment is already in flight; waiting for it to settle");
                sleep(poll).await;
            }
            PaymentStatus::Failed(reason) => {
                warn!("Submarine swap: the invoice payment failed permanently: {reason}");
                return Ok(SwapState::Failed(format!(
                    "invoice payment failed: {reason}"
                )));
            }
            PaymentStatus::Unknown => {
                if resume.funding.is_some() && already_attempted_payment {
                    // We recorded an intent to pay and the node has no record of it. Do not assume
                    // either way: keep polling. Paying again could pay twice; giving up would
                    // abandon an HTLC we may already have bought.
                    warn!(
                        "Submarine swap: a payment was started but the node has no record of it; \
                         polling rather than paying again"
                    );
                    sleep(poll).await;
                    continue;
                }

                // Bound how far out the outgoing HTLC may expire, and refuse if there is no room
                // for one at all.
                //
                // This is the half of the swap that has no on-chain guard. The payee decides when
                // to settle, any time up to that expiry, and settling is what reveals the preimage
                // this side needs to claim. Left unbounded, LND applies its own
                // `--max-cltv-expiry`, 2016 blocks by default: many times any swap's on-chain
                // timeout. A client that holds the payment until after its own refund branch
                // opens takes its coins back on chain and then settles, collecting both legs.
                let Some(cltv_limit) =
                    timelock::submarine_cltv_budget(tip, swap.timeout_height, &swap.timelock)
                else {
                    warn!(
                        "Submarine swap: no room to pay the invoice and still claim before the \
                         client's refund opens at {}; not paying",
                        swap.timeout_height
                    );
                    return Ok(SwapState::Failed(
                        "no CLTV budget left to pay the invoice safely".into(),
                    ));
                };

                // Record the intent before the irreversible call.
                progress.invoice_pay_started()?;
                match ln
                    .pay_invoice(&swap.invoice, swap.max_routing_fee_msat, Some(cltv_limit))
                    .await
                {
                    Ok(p) => {
                        progress.invoice_paid();
                        payment = Some(p);
                        break;
                    }
                    Err(e) => {
                        warn!("Submarine swap: invoice payment failed: {e}");
                        return Ok(SwapState::Failed(format!("invoice payment failed: {e}")));
                    }
                }
            }
        }
    }
    let Some(payment) = payment else {
        // Still unresolved after the in-place budget. Hand back so the driver re-enters and
        // re-checks the chain state it has not looked at while waiting.
        return Ok(SwapState::InvoicePending);
    };

    // Defensive: the preimage from the payment must match the HTLC's hashlock.
    if payment_hash(&payment.preimage) != swap.payment_hash {
        return Ok(SwapState::Failed(
            "paid invoice preimage does not match HTLC hashlock".into(),
        ));
    }

    // 3. Claim the on-chain HTLC with the preimage, keeping it confirming under fee pressure
    //    (RBF) — the claim races the client's refund timeout, so a stuck claim is bumped.
    let dest = wallet.receive_destination();
    let preimage = payment.preimage;
    let claim_vsize = spend_vsize(&swap.htlc_script, &dest, true);
    let build = |rate: u64| {
        build_claim_tx(
            funding_outpoint,
            funding_value_sat,
            &swap.htlc_script,
            dest.clone(),
            estimate_spend_fee(rate, claim_vsize),
            preimage,
            &swap.claim_key,
        )
    };
    // The claim sweeps to our wallet, so CPFP can bump it if an RBF replacement is rejected.
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
    // The claim races the client's refund branch, so it escalates as that height approaches
    // rather than on a fixed bump count. `CLAIM_ABORT_MARGIN` keeps the deadline a few blocks
    // short of the refund opening, since a claim landing in the same block as a refund is a
    // coin toss we have already paid for.
    let deadline = swap
        .timeout_height
        .saturating_sub(swap_common::timelock::CLAIM_ABORT_MARGIN);
    let cfg = SpendWatchConfig::claim(
        CLAIM_FEE_TARGET_BLOCKS,
        swap.fee_rate_sat_vb,
        fee_rate_cap(
            swap.onchain_amount_sat,
            claim_vsize,
            DEFAULT_MAX_FEE_BPS,
            ABSOLUTE_MAX_FEE_RATE_SAT_VB,
            swap.fee_rate_sat_vb,
        ),
        poll,
        FINALITY_DEPTH,
        deadline,
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
    .map_err(|e| anyhow!("claim broadcast/bump: {e}"))?
    {
        SpendOutcome::Confirmed { .. } => {
            info!("Submarine swap: invoice paid and on-chain HTLC claimed");
            Ok(SwapState::Claimed)
        }
        // We paid the invoice and the client's refund confirmed anyway: a realised loss of the
        // on-chain amount. The pre-payment claim-window check should make this unreachable, so
        // reaching it means the timelock parameters are wrong and want the operator's attention,
        // not a quiet `Failed`.
        SpendOutcome::ConflictingSpend { tx } => {
            error!(
                "Submarine swap: LOSS. The invoice was paid but the client's refund {} confirmed \
                 before our claim. Check --min-claim-window-blocks and --timeout-blocks.",
                tx.compute_txid()
            );
            Ok(SwapState::Failed(
                "the client's refund won the claim race after the invoice was paid".into(),
            ))
        }
        SpendOutcome::DeadlineExceeded { last_txid, tip } => {
            error!(
                "Submarine swap: LOSS RISK. The invoice was paid but claim {last_txid} has not \
                 confirmed by height {tip}, past its deadline. The client can now refund."
            );
            Ok(SwapState::Failed(
                "the on-chain claim did not confirm before the client's refund window".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::OnchainWallet;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{OutPoint, Txid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::mock::MockChain;
    use swap_common::chain::FundingUtxo;
    use swap_common::htlc::{generate_preimage, payment_hash};
    use swap_common::onchain::extract_preimage;
    use swap_common::random_keypair;

    const INVOICE_SAT: u64 = 100_000;
    const FEE_SAT: u64 = 1_000;
    /// Chain tip the mocks report, with the timeout a realistic 144 blocks above it.
    const MOCK_TIP: u32 = 700_000;
    const ONCHAIN_SAT: u64 = INVOICE_SAT + FEE_SAT;
    const TIMEOUT: u32 = MOCK_TIP + 144;

    // Mock LN that decodes to a fixed payment hash and (optionally) pays back a preimage.
    struct MockLn {
        payment_hash: [u8; 32],
        pay_preimage: Option<[u8; 32]>, // None => payment fails
        /// Set the moment `pay_invoice` is called, so a test can assert the irreversible
        /// step was never taken.
        paid: Mutex<bool>,
        /// What the "node" reports about the payment, so a test can model a resumed driver.
        status: Mutex<lightning_backend::PaymentStatus>,
        /// The CLTV bound the driver asked for, which is what stops a payee settling late.
        cltv_limit: Mutex<Option<u32>>,
        /// The final CLTV the decoded invoice demands.
        min_final_cltv_expiry: u32,
    }
    impl MockLn {
        fn new(payment_hash: [u8; 32], pay_preimage: Option<[u8; 32]>) -> Self {
            Self {
                payment_hash,
                pay_preimage,
                paid: Mutex::new(false),
                status: Mutex::new(lightning_backend::PaymentStatus::Unknown),
                cltv_limit: Mutex::new(None),
                min_final_cltv_expiry: 80,
            }
        }
        /// Decode to an invoice demanding this much final CLTV.
        fn with_min_final_cltv(mut self, blocks: u32) -> Self {
            self.min_final_cltv_expiry = blocks;
            self
        }
        /// Report this payment status, as a node that already knows about the payment would.
        fn with_status(self, status: lightning_backend::PaymentStatus) -> Self {
            *self.status.lock().unwrap() = status;
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
            _req: lightning_backend::HoldInvoiceRequest,
        ) -> lightning_backend::Result<HoldInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn create_invoice(
            &self,
            _amt: u64,
            _e: u64,
            _m: &str,
        ) -> lightning_backend::Result<HoldInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn invoice_status(
            &self,
            _ph: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::InvoiceStatus> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn settle_hold_invoice(&self, _p: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn cancel_hold_invoice(&self, _ph: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn pay_invoice(
            &self,
            _bolt11: &str,
            _max_fee_msat: u64,
            cltv_limit: Option<u32>,
        ) -> lightning_backend::Result<PaymentResult> {
            *self.cltv_limit.lock().unwrap() = cltv_limit;
            *self.paid.lock().unwrap() = true;
            match self.pay_preimage {
                Some(preimage) => Ok(PaymentResult {
                    preimage,
                    fee_msat: 0,
                }),
                None => Err(LightningError::PaymentFailed("no route".into())),
            }
        }
        async fn payment_status(
            &self,
            _ph: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::PaymentStatus> {
            Ok(self.status.lock().unwrap().clone())
        }
        async fn decode_invoice(&self, _bolt11: &str) -> lightning_backend::Result<DecodedInvoice> {
            Ok(DecodedInvoice {
                payment_hash: self.payment_hash,
                amount_msat: INVOICE_SAT * 1000,
                min_final_cltv_expiry: self.min_final_cltv_expiry,
                amount_is_explicit: true,
                expires_at_unix: 0,
            })
        }
    }

    struct MockWallet {
        spk: ScriptBuf,
    }
    impl OnchainWallet for MockWallet {
        fn fund_htlc(&self, _spk: &ScriptBuf, _amount_sat: u64) -> swap_common::Result<OutPoint> {
            Err(swap_common::SwapError::Other(
                "provider does not fund in a submarine swap".into(),
            ))
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.spk.clone()
        }
    }

    /// The timelock model the tests run under.
    /// The invoice a client hands over is the client's document, and the amount on it is what
    /// actually gets locked on chain and paid over Lightning. Nothing compared it to the quote,
    /// so a peer could take a quote for the minimum and hand back an invoice for a hundred times
    /// that: the fee was charged on the small number, the risk limits booked the small number,
    /// and the provider committed to the large one.
    #[tokio::test]
    async fn an_invoice_that_does_not_match_the_quote_is_refused() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_refund_sk, refund_pk) = random_keypair(&secp);
        let ln = MockLn::new([9u8; 32], None);

        let err = init_submarine_swap(
            &ln,
            "lnbcrt-mock",
            &refund_pk,
            claim_sk,
            &claim_pk,
            // Quoted for a tenth of what the invoice asks for.
            INVOICE_SAT / 10,
            FEE_SAT,
            5,
            5_000,
            MOCK_TIP,
            TIMEOUT,
            Network::Regtest,
            params(),
        )
        .await;
        let err = match err {
            Err(e) => e,
            // `SubmarineSwap` deliberately has no `Debug`: it holds the provider's claim key.
            Ok(_) => panic!("an invoice that does not match the quote must be refused"),
        };
        assert!(
            err.to_string().contains("but the quote is for"),
            "got: {err}"
        );
    }

    /// The submarine theft condition, and the mirror of the one fixed in #9.
    ///
    /// The provider pays first and claims second, so its outgoing HTLC has to end early enough
    /// to still claim on chain afterwards. An invoice demanding a final CLTV past that point
    /// lets the payee hold the payment until its own refund branch opens, take its coins back on
    /// chain, and settle afterwards: both legs, one payer.
    #[tokio::test]
    async fn an_invoice_demanding_too_much_final_cltv_is_refused() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_refund_sk, refund_pk) = random_keypair(&secp);
        // The mock decodes to a final CLTV of 80 blocks by default, which fits. Ask for one that
        // reaches past the on-chain timeout.
        let ln = MockLn::new([9u8; 32], None).with_min_final_cltv(TIMEOUT - MOCK_TIP);

        let err = init_submarine_swap(
            &ln,
            "lnbcrt-mock",
            &refund_pk,
            claim_sk,
            &claim_pk,
            INVOICE_SAT,
            FEE_SAT,
            5,
            5_000,
            MOCK_TIP,
            TIMEOUT,
            Network::Regtest,
            params(),
        )
        .await;
        let err = match err {
            Err(e) => e,
            Ok(_) => {
                panic!("an invoice whose final CLTV outlives the on-chain leg must be refused")
            }
        };
        assert!(
            err.to_string().contains("too much final CLTV"),
            "got: {err}"
        );
    }

    /// And the payment itself carries the bound, because the invoice's own demand is only the
    /// floor: the route adds its deltas on top, and nothing else stops them.
    #[tokio::test]
    async fn the_payment_is_bounded_by_the_claim_window() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn::new(ph, Some(preimage));
        let (swap, _) = make_swap(&ln).await;
        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: ONCHAIN_SAT,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();

        let limit = ln.cltv_limit.lock().unwrap().expect("a bound must be set");
        // Everything from the tip to the client's refund height, less the window needed to get a
        // claim confirmed once the preimage is known.
        assert_eq!(limit, TIMEOUT - MOCK_TIP - params().min_claim_window_blocks);
    }

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
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            vout: 0,
        }
    }

    async fn make_swap(ln: &MockLn) -> (SubmarineSwap, [u8; 32]) {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_refund_sk, refund_pk) = random_keypair(&secp);
        let swap = init_submarine_swap(
            ln,
            "lnbcrt-mock",
            &refund_pk,
            claim_sk,
            &claim_pk,
            INVOICE_SAT,
            FEE_SAT,
            5,
            5_000,
            MOCK_TIP,
            TIMEOUT,
            Network::Regtest,
            params(),
        )
        .await
        .unwrap();
        (swap, ln.payment_hash)
    }

    #[tokio::test]
    async fn submarine_swap_happy_path_pays_and_claims() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn::new(ph, Some(preimage));
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: ONCHAIN_SAT,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Claimed);
        let broadcasts = chain.broadcasts();
        assert_eq!(broadcasts.len(), 1, "one claim tx must be broadcast");
        // The broadcast claim must carry the preimage that matches the hashlock.
        assert_eq!(
            extract_preimage(&broadcasts[0], &funding_outpoint(), &ph),
            Some(preimage)
        );
    }

    /// The submarine half of the same hole. The provider has paid the Lightning invoice, so the
    /// on-chain claim is the only way that money comes back, and it is a race against the client's
    /// refund branch. Ten transient failures used to write `Failed` and stop: no claim, no
    /// fee-bump, no resume after a restart, and a client refund walking towards its timeout.
    #[tokio::test]
    async fn a_paid_submarine_swap_outlives_an_outage_and_still_claims() {
        use crate::recovery::{Recovery, MAX_DRIVER_RETRIES};
        use std::sync::Arc;
        use swap_common::chain::mock::FlakyChain;
        use swap_common::store::{JsonFileSwapStore, SwapRecord, SwapStore};
        use swap_common::{NetworkSpec, SwapDirection};

        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        // A node that has already paid: this is the state a driver comes back to.
        let ln = MockLn::new(ph, Some(preimage)).with_status(PaymentStatus::Succeeded(
            lightning_backend::PaymentResult {
                preimage,
                fee_msat: 0,
            },
        ));
        let (swap, _) = make_swap(&ln).await;

        let outpoint = funding_outpoint();
        let swap_id = uuid::Uuid::new_v4();
        let record = SwapRecord {
            swap_id,
            direction: SwapDirection::Submarine,
            peer: "client".into(),
            network: NetworkSpec::Regtest,
            payment_hash_hex: hex::encode(swap.payment_hash),
            onchain_amount_sat: ONCHAIN_SAT,
            fee_rate_sat_vb: swap.fee_rate_sat_vb,
            htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
            timeout_height: TIMEOUT,
            secret_key_hex: hex::encode(swap.claim_key.secret_bytes()),
            invoice: swap.invoice.clone(),
            max_routing_fee_msat: swap.max_routing_fee_msat,
            required_confirmations: 2,
            funding_txid_hex: Some(outpoint.txid.to_string()),
            funding_vout: Some(outpoint.vout),
            invoice_pay_started_at_unix: Some(1),
            state: SwapState::InvoicePaid,
            ..SwapRecord::new_progress()
        };

        let dir = std::env::temp_dir().join(format!("pubky-swap-recovery-{swap_id}"));
        let mut store: Arc<dyn SwapStore> = Arc::new(JsonFileSwapStore::new(&dir).unwrap());
        store.put(&record).unwrap();

        let chain = FlakyChain::new(
            MockChain::new()
                .with_tip(MOCK_TIP)
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: ONCHAIN_SAT,
                    confirmations: 3,
                })
                .always_final(),
            u32::MAX,
        );
        let wallet = MockWallet { spk: dest() };

        let outage_runs = MAX_DRIVER_RETRIES + 2;
        let mut failures = 0u32;
        let mut restarted = false;
        let state = loop {
            assert!(failures < 100, "the driver never got anywhere");
            let rec = store
                .get(swap_id)
                .unwrap()
                .expect("the record must never leave the store");
            assert!(
                !rec.state.is_terminal(),
                "an outage made a paid swap terminal after {failures} failures"
            );
            let resumed = crate::submarine_swap_from_record(&rec, params()).unwrap();
            let resume = rec.resume();
            let already_paid = rec.invoice_pay_started_at_unix.is_some();
            let progress = crate::StoreProgress {
                store: store.clone(),
                record: std::sync::Mutex::new(rec),
            };
            match drive_submarine_swap(
                &ln,
                &chain,
                &wallet,
                &resumed,
                2,
                Duration::ZERO,
                &resume,
                already_paid,
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
                        "failure {failures} gave up on a swap whose invoice is already paid: {e}"
                    );
                    assert_eq!(rec.retry_count, failures);
                }
            }

            if failures == outage_runs && !restarted {
                restarted = true;
                store = Arc::new(JsonFileSwapStore::new(&dir).unwrap());
                let active = store.load_active().unwrap();
                assert_eq!(
                    active.len(),
                    1,
                    "a swap with a paid invoice must still be resumed after {failures} failures"
                );
                assert!(active[0].funds_at_risk());
                assert!(crate::needs_recovery(&active[0]));
                assert!(active[0].next_retry_at_unix.is_some());
                chain.recover();
            }
        };

        assert_eq!(state, SwapState::Claimed);
        assert!(chain.failed_calls() >= outage_runs);
        let broadcasts = chain.inner().broadcasts();
        assert_eq!(broadcasts.len(), 1, "the claim must reach the wire");
        assert_eq!(
            extract_preimage(&broadcasts[0], &outpoint, &ph),
            Some(preimage),
            "and it must carry the preimage the payment bought"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn submarine_swap_payment_failure_does_not_claim() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn::new(ph, None); // payment fails
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: ONCHAIN_SAT,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();

        assert!(matches!(state, SwapState::Failed(_)));
        assert!(
            chain.broadcasts().is_empty(),
            "no on-chain claim when the invoice payment fails"
        );
    }

    /// A client that funds only a block or two before its own refund branch opens must not get
    /// the provider to pay.
    ///
    /// Paying the invoice is irreversible, but recovering the money means winning an on-chain
    /// race against a refund the client can fee-bump. With no window there is no race to win, so
    /// the provider refuses and the client simply refunds its own funding.
    /// A driver resumed after a crash must not pay a second time for the same swap.
    ///
    /// Its own state cannot distinguish "the payment never went out" from "it went out and we
    /// crashed before recording it", and those want opposite actions. The node knows, so the
    /// driver asks it: a payment the node already settled is adopted rather than repeated.
    #[tokio::test]
    async fn a_resumed_driver_adopts_an_already_settled_payment() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage)).with_status(
            lightning_backend::PaymentStatus::Succeeded(PaymentResult {
                preimage,
                fee_msat: 0,
            }),
        );
        let (swap, _) = make_swap(&ln).await;
        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            &Resume {
                funding: Some(funding_outpoint()),
                ..Default::default()
            },
            true, // a previous run recorded that it was about to pay
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Claimed);
        assert!(
            !*ln.paid.lock().unwrap(),
            "a settled payment must be adopted, not repeated"
        );
        assert_eq!(
            chain.broadcasts().len(),
            1,
            "the claim must still be broadcast against the HTLC we already bought"
        );
    }

    /// The other half: a payment the node has no record of, after we recorded an intent to make
    /// it. Neither paying nor giving up is safe, so the driver waits instead of guessing.
    #[tokio::test]
    async fn a_resumed_driver_with_an_unknown_payment_neither_pays_nor_abandons() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage));
        let (swap, _) = make_swap(&ln).await;
        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            &Resume {
                funding: Some(funding_outpoint()),
                ..Default::default()
            },
            true,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(
            state,
            SwapState::InvoicePending,
            "must hand back, not decide"
        );
        assert!(!*ln.paid.lock().unwrap(), "must not pay a second time");
        assert!(chain.broadcasts().is_empty());
    }

    /// A client that funds the HTLC short must not get the provider to pay the full invoice.
    ///
    /// This used to be invisible: the exact-value lookup answered "nothing here" for a short
    /// funding exactly as it did for an empty address, so the provider waited out the whole
    /// timeout without ever saying what was wrong.
    #[tokio::test]
    async fn refuses_to_pay_against_an_underfunded_htlc() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage));
        let (swap, _) = make_swap(&ln).await;
        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat - 1,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();

        match state {
            SwapState::Failed(reason) => assert!(
                reason.contains("short"),
                "expected a short-funding refusal, got: {reason}"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            !*ln.paid.lock().unwrap(),
            "must not pay against a short HTLC"
        );
    }

    /// A small overpayment is accepted and swept whole: refusing would strand the surplus.
    #[tokio::test]
    async fn a_small_overpayment_is_accepted() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage));
        let (swap, _) = make_swap(&ln).await;
        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat + 500,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();
        assert_eq!(state, SwapState::Claimed);
        assert!(*ln.paid.lock().unwrap());
    }

    /// The overpayment test above asserted the swap reached `Claimed` and stopped there, which
    /// is why this survived: the driver did claim, with a transaction nobody could broadcast.
    ///
    /// The claim is signed over the value the driver was quoted, and BIP143 commits the signature
    /// to the input's real amount. One sat of overpayment by the client, which costs them
    /// nothing, makes the provider's claim invalid, and the provider has paid the invoice by the
    /// time it finds out.
    #[tokio::test]
    async fn the_claim_is_signed_over_what_the_htlc_holds_not_what_was_quoted() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage));
        let (swap, _) = make_swap(&ln).await;
        const OVERPAY: u64 = 1;
        let funded_sat = swap.onchain_amount_sat + OVERPAY;
        let chain = MockChain::new()
            .with_tip(MOCK_TIP)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: funded_sat,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();
        assert_eq!(state, SwapState::Claimed);

        // The claim went out. Whether it could ever confirm is decided by the amount its
        // signature commits to, so that is what this checks, against real script consensus.
        let claim = chain
            .broadcasts()
            .into_iter()
            .find(|tx| {
                tx.input
                    .iter()
                    .any(|i| i.previous_output == funding_outpoint())
            })
            .expect("the driver broadcast a claim");
        let spent = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(funded_sat),
            script_pubkey: swap.htlc_spk.clone(),
        };
        let outpoint = funding_outpoint();
        claim
            .verify(|op| (*op == outpoint).then(|| spent.clone()))
            .expect("the claim must be valid against the output it actually spends");
    }

    #[tokio::test]
    async fn refuses_to_pay_when_the_claim_window_is_too_short() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage));
        let (swap, _) = make_swap(&ln).await;

        // Funding confirms with two blocks left before the client's refund branch opens.
        let chain = MockChain::new()
            .with_tip(TIMEOUT - 2)
            .with_funding(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat,
                confirmations: 3,
            })
            .always_final();
        let wallet = MockWallet { spk: dest() };

        let final_state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();

        match final_state {
            SwapState::Failed(reason) => assert!(
                reason.contains("claim window"),
                "expected a claim-window refusal, got: {reason}"
            ),
            other => panic!("expected the swap to be refused, got {other:?}"),
        }
        assert!(
            !*ln.paid.lock().unwrap(),
            "the provider must not pay an invoice it cannot then claim against"
        );
        assert!(chain.broadcasts().is_empty(), "nothing should be broadcast");
    }

    #[tokio::test]
    async fn submarine_swap_expires_without_funding() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn::new(ph, Some(preimage));
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain::new().with_tip(TIMEOUT).always_final();
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            &Resume::default(),
            false,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Expired);
        assert!(chain.broadcasts().is_empty());
    }
}
