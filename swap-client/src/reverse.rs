//! Client-side execution of a reverse swap (Lightning → on-chain).
//!
//! After negotiation, the client holds the preimage + claim key and the provider's HTLC
//! details. Execution is concurrent: the client starts paying the hold invoice (which stays
//! in-flight/held on the provider until it is settled), waits for the provider to fund the
//! on-chain HTLC, then claims it with the preimage — revealing it, which lets the provider
//! settle the invoice and complete the client's payment.

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{ScriptBuf, Txid};
use lightning_backend::{LightningBackend, PaymentStatus};
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::{
    run_blocking, select_funding, ChainWatcher, FundingSelection, FundingUtxo,
    DEFAULT_MAX_OVERPAY_SAT,
};
use swap_common::fee_bump::{confirm_or_bump, SpendOutcome, SpendWatchConfig};
use swap_common::htlc::{payment_hash, Preimage};
use swap_common::onchain::{
    build_claim_tx, estimate_spend_fee, extract_preimage, fee_rate_cap, spend_vsize,
    ABSOLUTE_MAX_FEE_RATE_SAT_VB, CLAIM_FEE_TARGET_BLOCKS, DEFAULT_MAX_FEE_BPS,
};
use swap_common::reorg::FINALITY_DEPTH;
use swap_common::store::Resume;
use swap_common::timelock::claim_start_is_safe;
use swap_common::validate::{min_reverse_lockup_sat, DEFAULT_MAX_SWAP_FEE_BPS};
use tokio::time::sleep;
use tracing::{info, warn};

/// Everything the client needs (from its own state + the provider's `SwapAccept`) to execute
/// a reverse swap.
pub struct ReverseClaim {
    /// HTLC redeem script (verify it matches what you expect before paying!).
    pub htlc_script: ScriptBuf,
    /// HTLC P2WSH scriptPubKey.
    pub htlc_spk: ScriptBuf,
    /// Amount the provider locks on-chain.
    pub onchain_amount_sat: u64,
    /// The height at which the provider's refund branch opens.
    ///
    /// The client's claim is racing this, so it needs to know it: without a deadline the claim
    /// has nothing to escalate its fee against, and no point at which pushing further is
    /// throwing money at a spend that has already lost.
    pub timeout_height: u32,
    /// The hold invoice to pay.
    pub invoice: String,
    /// The client's preimage (kept secret until the on-chain claim).
    pub preimage: Preimage,
    /// The client's HTLC claim key.
    pub claim_key: SecretKey,
    /// Where the client receives the swept on-chain funds.
    pub dest_spk: ScriptBuf,
    /// Fee rate (sat/vB) for the claim transaction.
    pub fee_rate_sat_vb: u64,
}

impl ReverseClaim {
    /// The hash the hold invoice is against, derived from the preimage this side holds.
    pub fn payment_hash(&self) -> [u8; 32] {
        payment_hash(&self.preimage)
    }
}

/// Notified as the client's reverse swap progresses, so what it did reaches disk.
pub trait ClaimSink: Send + Sync {
    /// Persist possible submission before the payment RPC. Failure must stop publication.
    fn payment_started(&self) -> Result<()> {
        Ok(())
    }

    /// A claim we are about to put on the wire, reported *before* the broadcast so a later run
    /// knows the transaction is its own rather than reading it as the provider's refund.
    fn spend_broadcast(&self, _txid: Txid) {}
}

impl ClaimSink for () {}

/// Execute the client side of a reverse swap, returning the claim txid on success.
///
/// [`ChainWatcher`] calls are blocking, so they are wrapped in [`run_blocking`] to avoid stalling
/// the async runtime. `poll` is injected for testability.
#[allow(clippy::too_many_arguments)]
pub async fn execute_reverse_swap(
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    claim: ReverseClaim,
    max_routing_fee_msat: u64,
    required_confirmations: u32,
    poll: Duration,
    // What a previous run of this swap already did. `Resume::default()` on a fresh start.
    resume: &Resume,
    progress: &dyn ClaimSink,
) -> Result<Txid> {
    // 1. Start paying the hold invoice, unless a previous run already did.
    //
    // The saved payment-start marker and a node lookup distinguish a first attempt from an
    // ambiguous prior submission. An in-flight or settled payment must not be started again. The invoice is held either way until the provider settles it, which only
    // happens after we claim on-chain and reveal the preimage.
    // A restart before funding or spending leaves a default Resume even if payment began.
    let status = ln.payment_status(claim.payment_hash()).await;
    let already_paying = match &status {
        Ok(PaymentStatus::Succeeded { .. }) => {
            info!("Client: the hold invoice was already paid by an earlier run");
            true
        }
        Ok(PaymentStatus::InFlight { .. }) => {
            info!("Client: a payment for this invoice is still in flight");
            true
        }
        Ok(PaymentStatus::NotFound) | Ok(PaymentStatus::Failed(_)) => false,
        Ok(PaymentStatus::Unknown) if resume.is_fresh() => false,
        Ok(PaymentStatus::Unknown) => {
            warn!("Client: a prior payment may exist and its status is unknown; not paying again");
            true
        }
        Err(error) => {
            warn!("Client: could not read the payment's status ({error}); not paying again");
            true
        }
    };
    if resume.restored_from_listing {
        check_restored_payment(&status, claim.onchain_amount_sat)?;
    }
    // A settled payment means the provider has the preimage. Keeping it secret past the claim
    // window protects nothing, and stopping there only leaves the provider the lockup as well, so
    // a settled swap claims and bumps whatever the window says. Every other status, including
    // one the node cannot report, keeps the window.
    let settled = matches!(status, Ok(PaymentStatus::Succeeded(_)));
    let mut known_ours = resume.our_spends.clone();

    let pay_task = if already_paying {
        None
    } else {
        progress.payment_started()?;
        let pay_ln = ln.clone();
        let invoice = claim.invoice.clone();
        Some(tokio::spawn(async move {
            // No CLTV bound: a hold invoice is meant to be held, and the client's protection is
            // the on-chain claim it is about to make rather than an early expiry.
            pay_ln
                .pay_invoice(&invoice, max_routing_fee_msat, None)
                .await
        }))
    };

    // Dropping a driver must also stop its local RPC watcher. A payment already admitted by
    // the node is recovered through payment_status on the next run.
    let _payment_abort = pay_task
        .as_ref()
        .map(|task| AbortPayment(task.abort_handle()));

    // 2. Wait for the provider to fund + confirm the on-chain HTLC.
    //
    // Classify what pays the script rather than asking for an exact value. The HTLC address is
    // public from the moment it is in the `SwapAccept`, so an underpayment, an overpayment and a
    // double payment all happen, and a single "not funded yet" answer for all of them means
    // waiting out the whole timeout with a Lightning payment held.
    let funding = loop {
        let outputs = run_blocking(|| chain.find_outputs(&claim.htlc_spk))
            .map_err(|e| anyhow!("find_outputs: {e}"))?;
        // A lockup is there but still short of its confirmations.
        let mut lockup_pending = false;
        match select_funding(&outputs, claim.onchain_amount_sat, DEFAULT_MAX_OVERPAY_SAT) {
            FundingSelection::Exact(u) | FundingSelection::Overpaid { utxo: u, .. } => {
                if u.confirmations >= required_confirmations {
                    break u;
                }
                lockup_pending = true;
            }
            FundingSelection::Underpaid { got_sat } => {
                return Err(anyhow!(
                    "the provider's HTLC holds {got_sat} sat against the {} the swap is priced \
                     on; not revealing the preimage for it",
                    claim.onchain_amount_sat
                ));
            }
            FundingSelection::ExcessiveOverpay { got_sat } => {
                return Err(anyhow!(
                    "the provider's HTLC holds {got_sat} sat against an expected {}, far beyond \
                     tolerance; not claiming it",
                    claim.onchain_amount_sat
                ));
            }
            FundingSelection::Multiple(utxos) => {
                return Err(anyhow!(
                    "{} separate outputs pay the HTLC address; the claim builder takes one input, \
                     so this is left alone",
                    utxos.len()
                ));
            }
            // The provider settles once it sees a claim in the mempool, so a settled swap's lockup
            // is usually already spent by an earlier run's claim, which the unspent set no longer
            // shows. The script's history says whether that claim is there to drive or the
            // provider's refund has taken the lockup.
            FundingSelection::None if settled => match spent_lockup(chain.as_ref(), &claim)? {
                Some(SpentLockup::Claimed { funding, claim }) => {
                    info!("Client: the payment settled and claim {claim} is on chain; driving it");
                    known_ours.push(claim);
                    break funding;
                }
                Some(SpentLockup::Refunding(u)) => {
                    if u.confirmations >= required_confirmations {
                        info!("Client: the payment settled; outbidding an unconfirmed refund");
                        break u;
                    }
                    lockup_pending = true;
                }
                Some(SpentLockup::Refunded(refund)) => {
                    return Err(anyhow!(
                        "the provider refunded the HTLC ({refund}) after the payment settled; \
                         there is nothing left to claim"
                    ));
                }
                None => {}
            },
            FundingSelection::None => {}
        }
        // The provider's refund branch opens at the timeout. Past it there is nothing left to
        // claim, and a resumed client has no `pay_task` to end this loop for it: its payment was
        // started by a previous run, so the only other exit is the chain. Without this the loop
        // polls forever and the swap never reaches its refund-or-give-up conclusion.
        //
        // A settled swap waits past the window only for a lockup that is there. One that never
        // appeared, or that a reorg took away, still ends here.
        let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip_height: {e}"))?;
        if !claim_start_is_safe(tip, claim.timeout_height) {
            if !settled {
                return Err(anyhow!(
                    "the provider's HTLC did not confirm in time: tip {tip} against a timeout at \
                     {}. The provider refunds its own funding; nothing of ours is locked on chain.",
                    claim.timeout_height
                ));
            }
            if !lockup_pending {
                return Err(anyhow!(
                    "the payment settled, but nothing pays the provider's HTLC at tip {tip}, \
                     past the claim window before its timeout at {}; there is no lockup to claim",
                    claim.timeout_height
                ));
            }
        }
        // If the payment terminated before funding appeared, there's nothing to claim.
        if pay_task.as_ref().is_some_and(|t| t.is_finished()) {
            let pay_task = pay_task.expect("just checked");
            let res = pay_task.await.map_err(|e| anyhow!("pay task join: {e}"))?;
            // Report why it ended, not the whole result: a successful `PaymentResult` carries
            // the preimage, and this string reaches the logs.
            let detail = match res {
                Ok(_) => "the payment settled".to_string(),
                Err(e) => e.to_string(),
            };
            return Err(anyhow!(
                "invoice payment ended before the HTLC was funded: {detail}"
            ));
        }
        sleep(poll).await;
    };
    // Revealing the preimage is the irreversible step: it settles the provider's hold invoice
    // whether or not our claim ever confirms. Doing it inside the provider's refund window means
    // paying for an on-chain output the provider can take back, so the window is checked here,
    // immediately before the reveal, and not only when the funding was first seen. Funding can
    // confirm at the last moment, and polling itself takes blocks.
    //
    // `claim_start_is_safe` existed for exactly this and was called from nowhere.
    //
    // A settled payment has already given the provider the preimage, so there is no reveal left
    // to gate.
    if !settled {
        let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip_height: {e}"))?;
        if !claim_start_is_safe(tip, claim.timeout_height) {
            return Err(anyhow!(
                "the provider's HTLC confirmed too close to its refund at height {} (tip {tip}) \
                 to claim safely, so the preimage stays secret. The provider refunds its own \
                 funding and the hold invoice expires unsettled.",
                claim.timeout_height
            ));
        }
    }
    info!("Client: provider HTLC funded; claiming with the preimage");

    // 3. Claim the HTLC, revealing the preimage on-chain — and keep it confirming under fee
    //    pressure (RBF), since it must land before the provider's refund timeout.
    let claim_vsize = spend_vsize(&claim.htlc_script, &claim.dest_spk, true);
    let build = |rate: u64| {
        build_claim_tx(
            funding.outpoint,
            // What the output holds, not what the swap was priced at. A BIP143 sighash commits
            // to the input's value, so an overpaying provider (accepted above) would otherwise
            // produce a signature that does not validate, and a claim that cannot be broadcast,
            // with our Lightning payment already in flight.
            funding.value_sat,
            &claim.htlc_script,
            claim.dest_spk.clone(),
            estimate_spend_fee(rate, claim_vsize),
            claim.preimage,
            &claim.claim_key,
        )
    };
    // The claim sweeps to the client's chosen address, which is not necessarily a wallet we can
    // spend from here, so RBF is the only bump mechanism: no CPFP fallback.
    //
    // It races the provider's refund branch, so the fee escalates as that height approaches.
    // Past it a claim normally gives up, but a settled one is the only way left to the lockup, so
    // it stays at the fee cap until it or the refund wins.
    let deadline = claim
        .timeout_height
        .saturating_sub(swap_common::timelock::CLAIM_ABORT_MARGIN);
    let mut cfg = SpendWatchConfig::claim(
        CLAIM_FEE_TARGET_BLOCKS,
        claim.fee_rate_sat_vb,
        fee_rate_cap(
            claim.onchain_amount_sat,
            claim_vsize,
            DEFAULT_MAX_FEE_BPS,
            ABSOLUTE_MAX_FEE_RATE_SAT_VB,
            claim.fee_rate_sat_vb,
        ),
        poll,
        FINALITY_DEPTH,
        deadline,
    )
    .with_known_ours(known_ours);
    if settled {
        cfg = cfg.bumping_past_deadline();
    }
    let txid = match confirm_or_bump(
        chain.as_ref(),
        &claim.htlc_spk,
        funding.outpoint,
        &cfg,
        None,
        &|txid| progress.spend_broadcast(txid),
        build,
    )
    .await
    .map_err(|e| anyhow!("claim broadcast/bump: {e}"))?
    {
        SpendOutcome::Confirmed { txid } => txid,
        // The provider refunded first. Pushing another claim would only burn fees against a
        // confirmed spend, and our Lightning payment fails back on its own.
        SpendOutcome::ConflictingSpend { tx } => {
            return Err(anyhow!(
                "the provider refunded the HTLC ({}) before our claim confirmed; the hold \
                 invoice will be cancelled and the payment returned",
                tx.compute_txid()
            ));
        }
        // Without a deadline to stop at, a settled claim only ends here on the driver's wall-clock
        // or iteration cap.
        SpendOutcome::DeadlineExceeded { last_txid, tip } if settled => {
            return Err(anyhow!(
                "claim {last_txid} has not confirmed by height {tip}. The payment settled, so \
                 resume this swap to keep bumping it."
            ));
        }
        SpendOutcome::DeadlineExceeded { last_txid, tip } => {
            return Err(anyhow!(
                "claim {last_txid} did not confirm by height {tip}, past the provider's refund \
                 window; not broadcasting further"
            ));
        }
    };
    info!("Client: claim broadcast {txid}; awaiting hold-invoice settlement");

    // 4. The provider sees our claim, recovers the preimage, and settles the invoice — which
    //    completes our payment.
    match pay_task {
        Some(task) => {
            let payment = task
                .await
                .map_err(|e| anyhow!("pay task join: {e}"))?
                .map_err(|e| anyhow!("invoice payment failed: {e}"))?;
            info!(
                "Client: hold invoice settled (routing fee {} msat)",
                payment.fee_msat
            );
        }
        // An earlier run started the payment, so there is no task here to wait on. The claim is
        // on chain and the preimage is public, which is what settles it; the operator's node is
        // where that shows up.
        None => info!("Client: claim confirmed; the payment started earlier will settle from it"),
    }

    Ok(txid)
}

/// Whether a swap restored from a provider's listing may go on to its claim, from what the node
/// says about its payment.
///
/// The listing named the invoice and the lockup, and nothing checked either against a quote. So
/// the invoice is never paid, and a lockup is claimed only if a quote within
/// [`DEFAULT_MAX_SWAP_FEE_BPS`] could have offered it for what the node did pay, the one figure
/// the provider did not choose. A node that cannot say what it paid leaves the preimage secret:
/// the provider cannot settle, and the payment fails back when its HTLC expires. A payment that
/// already settled is claimed whatever the lockup holds, because the provider has the preimage
/// and declining would only leave it the lockup as well.
fn check_restored_payment(
    status: &lightning_backend::Result<PaymentStatus>,
    listed_lockup_sat: u64,
) -> Result<()> {
    let paid_msat = match status {
        Ok(PaymentStatus::Succeeded(_)) => return Ok(()),
        Ok(PaymentStatus::InFlight {
            amount_msat: Some(paid_msat),
        }) => *paid_msat,
        Ok(PaymentStatus::NotFound) | Ok(PaymentStatus::Failed(_)) => {
            return Err(anyhow!(
                "this swap was restored from the provider's listing and the node has no payment \
                 for it, so there is nothing to claim. Its invoice was never checked against a \
                 quote, so it is not paid."
            ))
        }
        Ok(PaymentStatus::InFlight { amount_msat: None }) | Ok(PaymentStatus::Unknown) | Err(_) => {
            return Err(anyhow!(
                "this swap was restored from the provider's listing and the node does not say \
                 what it paid for it, so the lockup cannot be checked and the preimage stays \
                 secret. Resume it again once the node reports the payment."
            ))
        }
    };
    let min_sat = min_reverse_lockup_sat(paid_msat, DEFAULT_MAX_SWAP_FEE_BPS);
    if listed_lockup_sat < min_sat {
        return Err(anyhow!(
            "this swap was restored from the provider's listing, which locks {listed_lockup_sat} \
             sat for a payment of {paid_msat} msat. Within the default fee bound that payment \
             buys at least {min_sat} sat, so the preimage stays secret and the payment fails back \
             when its HTLC expires."
        ));
    }
    Ok(())
}

/// What took a lockup out of the unspent set.
enum SpentLockup {
    /// A claim carrying our preimage, from an earlier run or another device.
    Claimed { funding: FundingUtxo, claim: Txid },
    /// Anything else, which can only be the provider's refund: the claim branch is the one that
    /// reveals the preimage. Unconfirmed, a claim paying more can still replace it.
    Refunding(FundingUtxo),
    /// The provider's refund, confirmed.
    Refunded(Txid),
}

/// Read the HTLC script's history for a lockup that has been spent. `None` when nothing that paid
/// the script has been.
fn spent_lockup(chain: &dyn ChainWatcher, claim: &ReverseClaim) -> Result<Option<SpentLockup>> {
    let history = run_blocking(|| chain.find_historical_outputs(&claim.htlc_spk))
        .map_err(|e| anyhow!("script history: {e}"))?;
    let mut refund = None;
    for output in history.iter().filter(|o| o.spent_by.is_some()) {
        let Some(spend) = run_blocking(|| chain.find_spend(&claim.htlc_spk, &output.outpoint))
            .map_err(|e| anyhow!("find_spend: {e}"))?
        else {
            continue;
        };
        let funding = FundingUtxo {
            outpoint: output.outpoint,
            value_sat: output.value_sat,
            confirmations: output.confirmations,
        };
        let spend_txid = spend.compute_txid();
        if extract_preimage(&spend, &output.outpoint, &claim.payment_hash()).is_some() {
            return Ok(Some(SpentLockup::Claimed {
                funding,
                claim: spend_txid,
            }));
        }
        if refund.is_none() {
            let confirmations =
                run_blocking(|| chain.tx_confirmations(&claim.htlc_spk, &spend_txid))
                    .map_err(|e| anyhow!("tx_confirmations: {e}"))?;
            refund = Some(match confirmations {
                Some(c) if c > 0 => SpentLockup::Refunded(spend_txid),
                _ => SpentLockup::Refunding(funding),
            });
        }
    }
    Ok(refund)
}

struct AbortPayment(tokio::task::AbortHandle);
impl Drop for AbortPayment {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Network, OutPoint, Txid as BTxid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;

    use swap_common::chain::mock::MockChain;
    use swap_common::htlc::{
        build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash,
    };
    use swap_common::random_keypair;
    use swap_common::timelock::CLAIM_ABORT_MARGIN;

    const AMOUNT: u64 = 100_000;
    const MOCK_TIP: u32 = 700_000;
    const TIMEOUT: u32 = MOCK_TIP + 144;

    struct MockLn {
        preimage: [u8; 32],
        /// What the node says about a payment for this hash, and how many times it was asked to
        /// make one.
        status: lightning_backend::PaymentStatus,
        pay_calls: std::sync::Mutex<u32>,
        status_error: bool,
        hold_payment: bool,
        payment_started: tokio::sync::Notify,
        payment_canceled: std::sync::atomic::AtomicBool,
        submission_record: Option<(Arc<swap_common::store::JsonFileSwapStore>, uuid::Uuid)>,
    }

    impl MockLn {
        fn new(preimage: [u8; 32]) -> Self {
            Self {
                preimage,
                status: lightning_backend::PaymentStatus::Unknown,
                pay_calls: std::sync::Mutex::new(0),
                status_error: false,
                hold_payment: false,
                payment_started: tokio::sync::Notify::new(),
                payment_canceled: std::sync::atomic::AtomicBool::new(false),
                submission_record: None,
            }
        }
        fn with_status(mut self, status: lightning_backend::PaymentStatus) -> Self {
            self.status = status;
            self
        }
    }
    #[async_trait::async_trait]
    impl LightningBackend for MockLn {
        async fn node_info(&self) -> lightning_backend::Result<NodeInfo> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn create_hold_invoice(
            &self,
            _req: lightning_backend::HoldInvoiceRequest,
        ) -> lightning_backend::Result<HoldInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn create_invoice(
            &self,
            _: u64,
            _: u64,
            _: &str,
        ) -> lightning_backend::Result<HoldInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn invoice_status(
            &self,
            _: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::InvoiceStatus> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn settle_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn cancel_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn pay_invoice(
            &self,
            _: &str,
            _: u64,
            _: Option<u32>,
        ) -> lightning_backend::Result<PaymentResult> {
            if let Some((store, id)) = &self.submission_record {
                let saved = swap_common::store::SwapStore::get(&**store, *id)
                    .unwrap()
                    .unwrap();
                assert!(
                    saved.invoice_pay_started_at_unix.is_some(),
                    "submission requires a durable marker"
                );
            }
            *self.pay_calls.lock().unwrap() += 1;
            if self.hold_payment {
                let _cancellation = PaymentCanceled(&self.payment_canceled);
                self.payment_started.notify_one();
                std::future::pending::<()>().await;
            }
            // Simulate the hold invoice eventually settling.
            Ok(PaymentResult {
                preimage: self.preimage,
                fee_msat: 0,
            })
        }
        async fn payment_status(
            &self,
            _ph: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::PaymentStatus> {
            if self.status_error {
                return Err(LightningError::NotImplemented(
                    "payment lookup unavailable".into(),
                ));
            }
            Ok(self.status.clone())
        }
        async fn decode_invoice(&self, _: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
    }

    struct PaymentCanceled<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for PaymentCanceled<'_> {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Drive a swap restored from a provider's listing, whose lockup of `lockup_sat` is funded as
    /// listed and confirmed, against `ln`.
    async fn run_restored(
        ln: MockLn,
        lockup_sat: u64,
    ) -> (
        Result<Txid>,
        Arc<MockLn>,
        Arc<MockChain>,
        OutPoint,
        [u8; 32],
    ) {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_r, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, TIMEOUT);
        let htlc_spk = htlc_p2wsh_address(&script, Network::Regtest).script_pubkey();
        let outpoint = OutPoint {
            txid: BTxid::from_str(
                "5555555555555555555555555555555555555555555555555555555555555555",
            )
            .unwrap(),
            vout: 0,
        };
        let ln = Arc::new(ln);
        let mc = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: lockup_sat,
                    confirmations: 2,
                })
                .always_final(),
        );
        let claim = ReverseClaim {
            htlc_script: script,
            htlc_spk,
            onchain_amount_sat: lockup_sat,
            // Whatever the provider listed: another hash, another amount.
            invoice: "lnbcrt-listed-by-the-provider".into(),
            preimage,
            claim_key: claim_sk,
            dest_spk: ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap(),
            fee_rate_sat_vb: 5,
            timeout_height: TIMEOUT,
        };
        // What `reverse_resume` hands a restored record.
        let resume = Resume {
            invoice_pay_started_at_unix: Some(0),
            restored_from_listing: true,
            ..Resume::default()
        };
        let result = execute_reverse_swap(
            ln.clone(),
            mc.clone(),
            claim,
            10_000,
            1,
            Duration::from_millis(0),
            &resume,
            &(),
        )
        .await;
        (result, ln, mc, outpoint, ph)
    }

    /// A node reporting `status`. A restored swap never pays, so its preimage is never asked for.
    fn node(status: lightning_backend::PaymentStatus) -> MockLn {
        MockLn::new([0; 32]).with_status(status)
    }

    /// A payment in flight for `sat`, as the node reports it.
    fn in_flight(sat: u64) -> lightning_backend::PaymentStatus {
        lightning_backend::PaymentStatus::InFlight {
            amount_msat: Some(sat * 1_000),
        }
    }

    /// The most a quote for [`AMOUNT`] can charge within the default fee bound.
    const MAX_FEE: u64 = AMOUNT * DEFAULT_MAX_SWAP_FEE_BPS as u64 / 10_000;

    /// A restored swap's invoice is the provider's word, never checked against a quote. A node
    /// with no payment for it, or a failed one, is never asked to pay it, however the lockup
    /// looks, and the preimage stays secret.
    #[tokio::test]
    async fn a_restored_swap_never_pays_its_listed_invoice() {
        for status in [
            lightning_backend::PaymentStatus::NotFound,
            lightning_backend::PaymentStatus::Failed("no route".into()),
        ] {
            let (result, ln, mc, _, _) = run_restored(node(status), AMOUNT).await;
            let err = result.unwrap_err();
            assert!(err.to_string().contains("never checked"), "{err:#}");
            assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
            assert!(mc.broadcasts().is_empty());
        }
    }

    /// A restored swap whose payment the node already made is claimed as any other, without
    /// paying again, when its lockup is one a quote within the fee bound could have offered for
    /// that payment.
    #[tokio::test]
    async fn a_restored_swap_claims_a_payment_the_node_already_made() {
        for paid in [AMOUNT, AMOUNT + 700, AMOUNT + MAX_FEE] {
            let (result, ln, mc, outpoint, ph) = run_restored(node(in_flight(paid)), AMOUNT).await;
            result.unwrap();
            assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
            let broadcasts = mc.broadcasts();
            assert_eq!(broadcasts.len(), 1);
            assert!(extract_preimage(&broadcasts[0], &outpoint, &ph).is_some());
        }
    }

    /// The provider listed the lockup, so it can list and fund less than the node paid and settle
    /// the full payment once the claim reveals the preimage. A lockup smaller than any quote
    /// within the fee bound would offer for the payment is not claimed.
    #[tokio::test]
    async fn a_restored_swap_keeps_the_preimage_from_a_lockup_short_of_its_payment() {
        for lockup in [AMOUNT - 1, AMOUNT / 2] {
            let (result, ln, mc, _, _) =
                run_restored(node(in_flight(AMOUNT + MAX_FEE)), lockup).await;
            let err = result.unwrap_err();
            assert!(err.to_string().contains("stays secret"), "{err:#}");
            assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
            assert!(mc.broadcasts().is_empty());
        }
    }

    /// Without the node's own figure there is nothing to check the listed lockup against, so a
    /// restored swap waits rather than revealing the preimage.
    #[tokio::test]
    async fn a_restored_swap_waits_for_the_node_to_say_what_it_paid() {
        let mut unreadable = MockLn::new([0; 32]);
        unreadable.status_error = true;
        for ln in [
            node(lightning_backend::PaymentStatus::InFlight { amount_msat: None }),
            node(lightning_backend::PaymentStatus::Unknown),
            unreadable,
        ] {
            let (result, ln, mc, _, _) = run_restored(ln, AMOUNT).await;
            let err = result.unwrap_err();
            assert!(err.to_string().contains("does not say"), "{err:#}");
            assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
            assert!(mc.broadcasts().is_empty());
        }
    }

    /// A settled payment means the provider already has the preimage. Declining to claim would
    /// leave it the lockup as well as the payment, so the claim goes out whatever the lockup holds.
    #[tokio::test]
    async fn a_restored_swap_whose_payment_settled_is_claimed_whatever_its_lockup() {
        let settled = lightning_backend::PaymentStatus::Succeeded(PaymentResult {
            preimage: [0; 32],
            fee_msat: 0,
        });
        let (result, ln, mc, outpoint, ph) = run_restored(node(settled), AMOUNT / 2).await;
        result.unwrap();
        assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
        let broadcasts = mc.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert!(extract_preimage(&broadcasts[0], &outpoint, &ph).is_some());
    }

    #[tokio::test]
    async fn client_pays_and_claims() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_r, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, 5000);
        let htlc_spk = htlc_p2wsh_address(&script, Network::Regtest).script_pubkey();
        let outpoint = OutPoint {
            txid: BTxid::from_str(
                "3333333333333333333333333333333333333333333333333333333333333333",
            )
            .unwrap(),
            vout: 0,
        };
        let dest = ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap();

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn::new(preimage));
        let mc = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );
        let chain: Arc<dyn ChainWatcher> = mc.clone();

        let claim = ReverseClaim {
            htlc_script: script,
            htlc_spk,
            onchain_amount_sat: AMOUNT,
            invoice: "lnbcrt-mock".into(),
            preimage,
            claim_key: claim_sk,
            dest_spk: dest,
            fee_rate_sat_vb: 5,
            timeout_height: TIMEOUT,
        };

        execute_reverse_swap(
            ln,
            chain,
            claim,
            10_000,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        // A claim carrying the preimage was broadcast at the funding outpoint.
        let broadcasts = mc.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(
            extract_preimage(&broadcasts[0], &outpoint, &ph),
            Some(preimage)
        );
    }

    /// The provider funds this HTLC, so the provider chooses its value, and a small overpayment
    /// is accepted rather than refused. The claim then has to be signed over what is there: a
    /// BIP143 sighash commits to the input's amount, so signing over the quoted figure produces a
    /// transaction that cannot be broadcast, with the client's Lightning payment already in
    /// flight and the provider's refund branch counting down.
    ///
    /// One sat is enough, and it costs the provider nothing to do deliberately.
    #[tokio::test]
    async fn the_claim_is_signed_over_what_the_provider_funded() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_r, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, 5000);
        let htlc_spk = htlc_p2wsh_address(&script, Network::Regtest).script_pubkey();
        let outpoint = OutPoint {
            txid: BTxid::from_str(
                "4444444444444444444444444444444444444444444444444444444444444444",
            )
            .unwrap(),
            vout: 0,
        };
        let dest = ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap();
        const OVERPAID: u64 = AMOUNT + 1;

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn::new(preimage));
        let mc = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: OVERPAID,
                    confirmations: 2,
                })
                .always_final(),
        );
        let chain: Arc<dyn ChainWatcher> = mc.clone();

        let claim = ReverseClaim {
            htlc_script: script,
            htlc_spk: htlc_spk.clone(),
            onchain_amount_sat: AMOUNT,
            invoice: "lnbcrt-mock".into(),
            preimage,
            claim_key: claim_sk,
            dest_spk: dest,
            fee_rate_sat_vb: 5,
            timeout_height: TIMEOUT,
        };

        execute_reverse_swap(
            ln,
            chain,
            claim,
            10_000,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();

        let broadcasts = mc.broadcasts();
        assert_eq!(broadcasts.len(), 1);
        let spent = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(OVERPAID),
            script_pubkey: htlc_spk,
        };
        broadcasts[0]
            .verify(|op| (*op == outpoint).then(|| spent.clone()))
            .expect("the claim must be valid against the output it actually spends");
    }

    /// Revealing the preimage settles the provider's hold invoice whether or not the on-chain
    /// claim ever confirms, so it must not happen inside the provider's refund window. Funding
    /// can confirm at the last moment, which is exactly when this matters and exactly when the
    /// check that existed for it (`claim_start_is_safe`) was called from nowhere.
    #[tokio::test]
    async fn the_preimage_is_not_revealed_once_the_refund_window_has_opened() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_r, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, 5000);
        let htlc_spk = htlc_p2wsh_address(&script, Network::Regtest).script_pubkey();
        let outpoint = OutPoint {
            txid: BTxid::from_str(
                "5555555555555555555555555555555555555555555555555555555555555555",
            )
            .unwrap(),
            vout: 0,
        };
        let dest = ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap();

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn::new(preimage));
        // Funded and confirmed, but the tip has reached the provider's refund height.
        let mc = Arc::new(
            MockChain::new()
                .with_tip(TIMEOUT)
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );
        let chain: Arc<dyn ChainWatcher> = mc.clone();

        let claim = ReverseClaim {
            htlc_script: script,
            htlc_spk,
            onchain_amount_sat: AMOUNT,
            invoice: "lnbcrt-mock".into(),
            preimage,
            claim_key: claim_sk,
            dest_spk: dest,
            fee_rate_sat_vb: 5,
            timeout_height: TIMEOUT,
        };

        let result = execute_reverse_swap(
            ln,
            chain,
            claim,
            10_000,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await;

        assert!(
            result.is_err(),
            "claiming into the refund window must refuse"
        );
        assert_eq!(
            mc.broadcast_count(),
            0,
            "nothing may be broadcast, because broadcasting is what reveals the preimage"
        );
    }

    /// A resumed reverse client must not pay the hold invoice again.
    ///
    /// The first run's payment is held against the same hash, and a second one is a second
    /// payment: the provider settles once, on a preimage that is about to become public, and the
    /// other is left to time out through whatever route it took. The node is the only thing that
    /// knows a payment is in flight, so a resumed run asks it.
    #[tokio::test]
    async fn a_resumed_client_does_not_pay_the_invoice_twice() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_r, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, 5000);
        let htlc_spk = htlc_p2wsh_address(&script, Network::Regtest).script_pubkey();
        let outpoint = OutPoint {
            txid: BTxid::from_str(
                "3333333333333333333333333333333333333333333333333333333333333333",
            )
            .unwrap(),
            vout: 0,
        };

        let ln = Arc::new(
            MockLn::new(preimage)
                .with_status(lightning_backend::PaymentStatus::InFlight { amount_msat: None }),
        );
        let mc = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );

        let claim = ReverseClaim {
            htlc_script: script,
            htlc_spk,
            onchain_amount_sat: AMOUNT,
            invoice: "lnbcrt-mock".into(),
            preimage,
            claim_key: claim_sk,
            dest_spk: ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap(),
            fee_rate_sat_vb: 5,
            timeout_height: TIMEOUT,
        };

        execute_reverse_swap(
            ln.clone(),
            mc.clone(),
            claim,
            10_000,
            1,
            Duration::from_millis(0),
            &Resume {
                invoice_pay_started_at_unix: None,
                funding: Some(outpoint),
                funding_intent_at_height: None,
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
                restored_from_listing: false,
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(
            *ln.pay_calls.lock().unwrap(),
            0,
            "a payment already in flight must not be started again"
        );
        // And it still claimed, which is the point: the claim is what settles the held payment.
        assert_eq!(mc.broadcasts().len(), 1);
    }

    /// The client used to look for an output of exactly the right value, so a provider funding a
    /// slightly different amount looked like "not funded yet" and the client waited out the whole
    /// timeout with its Lightning payment held. Classifying says what is wrong instead.
    #[tokio::test]
    async fn an_underfunded_htlc_is_refused_rather_than_waited_out() {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (_r, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, 5000);
        let htlc_spk = htlc_p2wsh_address(&script, Network::Regtest).script_pubkey();

        let ln = Arc::new(MockLn::new(preimage));
        let mc = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint: OutPoint {
                        txid: BTxid::from_str(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                        vout: 0,
                    },
                    value_sat: AMOUNT - 1,
                    confirmations: 2,
                })
                .always_final(),
        );

        let claim = ReverseClaim {
            htlc_script: script,
            htlc_spk,
            onchain_amount_sat: AMOUNT,
            invoice: "lnbcrt-mock".into(),
            preimage,
            claim_key: claim_sk,
            dest_spk: ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap(),
            fee_rate_sat_vb: 5,
            timeout_height: TIMEOUT,
        };

        let err = execute_reverse_swap(
            ln,
            mc.clone(),
            claim,
            10_000,
            1,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .expect_err("an underfunded HTLC must be refused");

        assert!(
            err.to_string().contains("not revealing the preimage"),
            "got: {err}"
        );
        assert!(mc.broadcasts().is_empty(), "nothing was claimed");
    }

    fn recovery_claim() -> (ReverseClaim, OutPoint) {
        let secp = Secp256k1::new();
        let (claim_key, claim_public) = random_keypair(&secp);
        let (_, refund_public) = random_keypair(&secp);
        let preimage = generate_preimage();
        let script = build_htlc_script(
            &payment_hash(&preimage),
            &claim_public,
            &refund_public,
            TIMEOUT,
        );
        let claim = ReverseClaim {
            htlc_spk: htlc_p2wsh_address(&script, Network::Regtest).script_pubkey(),
            htlc_script: script,
            onchain_amount_sat: AMOUNT,
            timeout_height: TIMEOUT,
            invoice: "saved-invoice".into(),
            preimage,
            claim_key,
            dest_spk: ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap(),
            fee_rate_sat_vb: 5,
        };
        (
            claim,
            OutPoint {
                txid: BTxid::from_str(&"33".repeat(32)).unwrap(),
                vout: 0,
            },
        )
    }

    fn settled() -> PaymentStatus {
        PaymentStatus::Succeeded(PaymentResult {
            preimage: [0; 32],
            fee_msat: 0,
        })
    }

    /// The recovery claim's lockup, unspent and confirmed.
    fn confirmed_lockup(outpoint: OutPoint) -> FundingUtxo {
        FundingUtxo {
            outpoint,
            value_sat: AMOUNT,
            confirmations: 2,
        }
    }

    /// Drive a swap an earlier run started paying, with the node reporting `ln`'s status.
    async fn run_resumed(
        ln: MockLn,
        chain: MockChain,
        claim: ReverseClaim,
    ) -> (Result<Txid>, Arc<MockLn>, Arc<MockChain>) {
        let ln = Arc::new(ln);
        let chain = Arc::new(chain);
        let resume = Resume {
            invoice_pay_started_at_unix: Some(1),
            ..Resume::default()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            execute_reverse_swap(
                ln.clone(),
                chain.clone(),
                claim,
                10_000,
                1,
                Duration::ZERO,
                &resume,
                &(),
            ),
        )
        .await
        .expect("the driver must not wait forever");
        (result, ln, chain)
    }

    /// Once the payment settled, the provider has the preimage, so a lockup confirmed past the
    /// claim window, or past the timeout itself, is still claimed.
    #[tokio::test]
    async fn a_settled_payment_is_claimed_past_the_claim_window() {
        for tip in [TIMEOUT - CLAIM_ABORT_MARGIN, TIMEOUT, TIMEOUT + 10] {
            let (claim, outpoint) = recovery_claim();
            let (preimage, ph) = (claim.preimage, claim.payment_hash());
            let chain = MockChain::new()
                .with_tip(tip)
                .with_funding(confirmed_lockup(outpoint))
                .always_final();
            let ln = MockLn::new(preimage).with_status(settled());
            let (result, ln, chain) = run_resumed(ln, chain, claim).await;
            result.unwrap_or_else(|e| panic!("tip {tip}: {e:#}"));
            assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
            let broadcasts = chain.broadcasts();
            assert_eq!(broadcasts.len(), 1, "tip {tip}");
            assert_eq!(
                extract_preimage(&broadcasts[0], &outpoint, &ph),
                Some(preimage)
            );
        }
    }

    /// A settled claim past its deadline goes to the fee cap and stays there until it confirms,
    /// where an unsettled one would give up and leave the lockup to the refund.
    #[tokio::test]
    async fn a_settled_claim_is_bumped_past_its_deadline() {
        let (claim, outpoint) = recovery_claim();
        let chain = MockChain::new()
            .with_tip(TIMEOUT + 1)
            .with_funding(confirmed_lockup(outpoint))
            .with_confirmations(vec![Some(0), Some(0), Some(0), Some(FINALITY_DEPTH)]);
        let ln = MockLn::new(claim.preimage).with_status(settled());
        let (result, _, chain) = run_resumed(ln, chain, claim).await;
        let txid = result.unwrap();
        let broadcasts = chain.broadcasts();
        assert_eq!(
            broadcasts.len(),
            2,
            "the first claim and one bump to the cap"
        );
        assert!(broadcasts[1].output[0].value < broadcasts[0].output[0].value);
        assert_eq!(txid, broadcasts[1].compute_txid());
    }

    /// The provider settles on seeing a claim in the mempool, which also takes the lockup out of
    /// the unspent set. A settled swap finds that claim in the script's history and drives it
    /// rather than waiting for a lockup that will never reappear, even when this device has no
    /// record of broadcasting it.
    #[tokio::test]
    async fn a_settled_swap_drives_a_claim_already_on_chain() {
        let (claim, outpoint) = recovery_claim();
        let earlier = build_claim_tx(
            outpoint,
            AMOUNT,
            &claim.htlc_script,
            claim.dest_spk.clone(),
            1_000,
            claim.preimage,
            &claim.claim_key,
        )
        .unwrap();
        let earlier_txid = earlier.compute_txid();
        let chain = MockChain::new()
            .with_tip(TIMEOUT + 1)
            .with_spent_output(outpoint, AMOUNT, earlier_txid)
            .with_spend(earlier)
            .always_final();
        let ln = MockLn::new(claim.preimage).with_status(settled());
        let (result, _, chain) = run_resumed(ln, chain, claim).await;
        assert_eq!(result.unwrap(), earlier_txid);
        assert!(
            chain.broadcasts().is_empty(),
            "the claim on chain is adopted"
        );
    }

    /// A transaction spending `outpoint` without the preimage, as the provider's refund does.
    fn refund_of(outpoint: OutPoint) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: outpoint,
                ..Default::default()
            }],
            output: vec![],
        }
    }

    /// Past the window, a settled swap whose lockup the provider refunded, or that nothing ever
    /// paid, ends rather than polling for a lockup that is gone.
    #[tokio::test]
    async fn a_settled_swap_with_no_lockup_left_stops_waiting() {
        let (claim, outpoint) = recovery_claim();
        let refund = refund_of(outpoint);
        let refunded = MockChain::new()
            .with_tip(TIMEOUT + 1)
            .with_spent_output(outpoint, AMOUNT, refund.compute_txid())
            .with_spend(refund)
            .with_confirmations(vec![Some(1)]);
        let ln = MockLn::new(claim.preimage).with_status(settled());
        let (result, _, chain) = run_resumed(ln, refunded, claim).await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("refunded"), "{err:#}");
        assert!(chain.broadcasts().is_empty());

        let (claim, _) = recovery_claim();
        let ln = MockLn::new(claim.preimage).with_status(settled());
        let empty = MockChain::new().with_tip(TIMEOUT - CLAIM_ABORT_MARGIN);
        let (result, _, chain) = run_resumed(ln, empty, claim).await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("no lockup"), "{err:#}");
        assert!(chain.broadcasts().is_empty());
    }

    /// A refund still in the mempool has not won: a settled swap claims over it at the cap.
    #[tokio::test]
    async fn a_settled_swap_outbids_an_unconfirmed_refund() {
        let (claim, outpoint) = recovery_claim();
        let (preimage, ph) = (claim.preimage, claim.payment_hash());
        let refund = refund_of(outpoint);
        // The refund twice (seen by the wait loop, then by the claim driver), our first claim
        // displaced by it, the refund again, then our claim at the cap buried.
        let chain = MockChain::new()
            .with_tip(TIMEOUT + 1)
            .with_spent_output(outpoint, AMOUNT, refund.compute_txid())
            .with_spend(refund)
            .with_confirmations(vec![Some(0), Some(0), None, Some(0), Some(FINALITY_DEPTH)]);
        let ln = MockLn::new(preimage).with_status(settled());
        let (result, _, chain) = run_resumed(ln, chain, claim).await;
        let txid = result.unwrap();
        let broadcasts = chain.broadcasts();
        assert_eq!(broadcasts.len(), 2, "the first claim and one at the cap");
        assert!(broadcasts[1].output[0].value < broadcasts[0].output[0].value);
        assert_eq!(txid, broadcasts[1].compute_txid());
        assert_eq!(
            extract_preimage(&broadcasts[1], &outpoint, &ph),
            Some(preimage)
        );
    }

    /// Short of a settled payment the preimage is still the client's to keep, so past the window
    /// a payment in flight, one the node cannot report, or a failed lookup claims nothing.
    #[tokio::test]
    async fn an_unsettled_payment_past_the_window_keeps_the_preimage_secret() {
        for tip in [TIMEOUT - CLAIM_ABORT_MARGIN, TIMEOUT + 10] {
            for case in 0..4 {
                let (claim, outpoint) = recovery_claim();
                let mut ln = MockLn::new(claim.preimage);
                match case {
                    0 => ln.status = in_flight(AMOUNT),
                    1 => ln.status = PaymentStatus::InFlight { amount_msat: None },
                    2 => ln.status = PaymentStatus::Unknown,
                    _ => ln.status_error = true,
                }
                let chain = MockChain::new()
                    .with_tip(tip)
                    .with_funding(confirmed_lockup(outpoint))
                    .always_final();
                let (result, ln, chain) = run_resumed(ln, chain, claim).await;
                assert!(result.is_err(), "tip {tip}, case {case}");
                assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
                assert!(
                    chain.broadcasts().is_empty(),
                    "tip {tip}, case {case}: the claim would reveal the preimage"
                );
            }
        }
    }

    #[tokio::test]
    async fn default_resume_queries_existing_or_uncertain_payment_before_any_new_payment() {
        for scenario in 0..3 {
            let (claim, outpoint) = recovery_claim();
            let mut backend = MockLn::new(claim.preimage);
            match scenario {
                0 => backend.status = PaymentStatus::InFlight { amount_msat: None },
                1 => {
                    backend.status = PaymentStatus::Succeeded(PaymentResult {
                        preimage: claim.preimage,
                        fee_msat: 0,
                    })
                }
                _ => backend.status_error = true,
            }
            let ln = Arc::new(backend);
            let chain = Arc::new(
                MockChain::new()
                    .with_funding(FundingUtxo {
                        outpoint,
                        value_sat: AMOUNT,
                        confirmations: 2,
                    })
                    .always_final(),
            );
            execute_reverse_swap(
                ln.clone(),
                chain.clone(),
                claim,
                10_000,
                1,
                Duration::ZERO,
                &Resume::default(),
                &(),
            )
            .await
            .unwrap();
            assert_eq!(
                *ln.pay_calls.lock().unwrap(),
                0,
                "scenario {scenario} must not pay again"
            );
            assert_eq!(chain.broadcasts().len(), 1);
        }
    }

    #[tokio::test]
    async fn canceling_the_driver_also_drops_its_payment_rpc_watcher() {
        let (claim, _) = recovery_claim();
        let mut backend = MockLn::new(claim.preimage);
        backend.hold_payment = true;
        let ln = Arc::new(backend);
        let chain = Arc::new(MockChain::new());
        let resume = Resume::default();
        {
            let driver = execute_reverse_swap(
                ln.clone(),
                chain,
                claim,
                10_000,
                1,
                Duration::from_secs(1),
                &resume,
                &(),
            );
            tokio::pin!(driver);
            tokio::select! {
                result = &mut driver => panic!("driver unexpectedly completed: {result:?}"),
                () = ln.payment_started.notified() => {},
            }
        }
        tokio::task::yield_now().await;
        assert_eq!(*ln.pay_calls.lock().unwrap(), 1);
        assert!(ln
            .payment_canceled
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    fn payment_record(
        claim: &ReverseClaim,
    ) -> (
        std::path::PathBuf,
        Arc<swap_common::store::JsonFileSwapStore>,
        uuid::Uuid,
    ) {
        use swap_common::store::{JsonFileSwapStore, SwapRecord, SwapRole, SwapStore};
        let dir = std::env::temp_dir().join(format!("client-payment-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&dir).unwrap());
        let id = uuid::Uuid::new_v4();
        store
            .put(&SwapRecord {
                swap_id: id,
                role: SwapRole::Client,
                direction: swap_common::SwapDirection::Reverse,
                invoice: claim.invoice.clone(),
                payment_hash_hex: hex::encode(claim.payment_hash()),
                preimage_hex: Some(hex::encode(claim.preimage)),
                secret_key_hex: hex::encode(claim.claim_key.secret_bytes()),
                ..SwapRecord::new_progress()
            })
            .unwrap();
        (dir, store, id)
    }

    #[tokio::test]
    async fn payment_marker_survives_restart_and_unknown_does_not_submit_again() {
        use swap_common::store::{JsonFileSwapStore, SwapStore};
        let (claim, outpoint) = recovery_claim();
        let (dir, store, id) = payment_record(&claim);
        crate::store::record_payment_started(&*store, id).unwrap();
        drop(store);
        let store = JsonFileSwapStore::new(&dir).unwrap();
        let saved = store.get(id).unwrap().unwrap();
        assert!(saved.invoice_pay_started_at_unix.is_some());
        assert!(saved.funds_at_risk());
        assert!(!saved.resume().is_fresh());
        let ln = Arc::new(MockLn::new(claim.preimage));
        let chain = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );
        execute_reverse_swap(
            ln.clone(),
            chain.clone(),
            claim,
            10_000,
            1,
            Duration::ZERO,
            &saved.resume(),
            &crate::RecordProgress {
                store: &store,
                swap_id: id,
            },
        )
        .await
        .unwrap();
        assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
        assert_eq!(chain.broadcasts().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn authoritative_absence_or_failure_retries_a_marked_payment() {
        use swap_common::store::SwapStore;
        for status in [
            PaymentStatus::NotFound,
            PaymentStatus::Failed("previous attempt failed".into()),
        ] {
            let (claim, outpoint) = recovery_claim();
            let (dir, store, id) = payment_record(&claim);
            crate::store::record_payment_started(&*store, id).unwrap();
            let saved = store.get(id).unwrap().unwrap();
            let mut backend = MockLn::new(claim.preimage).with_status(status);
            backend.submission_record = Some((store.clone(), id));
            let ln = Arc::new(backend);
            let chain = Arc::new(
                MockChain::new()
                    .with_funding(FundingUtxo {
                        outpoint,
                        value_sat: AMOUNT,
                        confirmations: 2,
                    })
                    .always_final(),
            );
            execute_reverse_swap(
                ln.clone(),
                chain,
                claim,
                10_000,
                1,
                Duration::ZERO,
                &saved.resume(),
                &crate::RecordProgress {
                    store: &store,
                    swap_id: id,
                },
            )
            .await
            .unwrap();
            assert_eq!(*ln.pay_calls.lock().unwrap(), 1);
            assert_eq!(
                store.get(id).unwrap().unwrap().invoice_pay_started_at_unix,
                saved.invoice_pay_started_at_unix
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn initial_unknown_payment_is_marked_before_submission() {
        use swap_common::store::SwapStore;
        let (claim, outpoint) = recovery_claim();
        let (dir, store, id) = payment_record(&claim);
        let mut backend = MockLn::new(claim.preimage);
        backend.submission_record = Some((store.clone(), id));
        let ln = Arc::new(backend);
        let chain = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );
        execute_reverse_swap(
            ln.clone(),
            chain,
            claim,
            10_000,
            1,
            Duration::ZERO,
            &Resume::default(),
            &crate::RecordProgress {
                store: &store,
                swap_id: id,
            },
        )
        .await
        .unwrap();
        assert_eq!(*ln.pay_calls.lock().unwrap(), 1);
        assert!(store
            .get(id)
            .unwrap()
            .unwrap()
            .invoice_pay_started_at_unix
            .is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct FailedPaymentMarker;
    impl ClaimSink for FailedPaymentMarker {
        fn payment_started(&self) -> Result<()> {
            Err(anyhow!("payment marker could not be persisted"))
        }
    }

    #[tokio::test]
    async fn failed_payment_marker_blocks_submission() {
        let (claim, outpoint) = recovery_claim();
        let ln = Arc::new(MockLn::new(claim.preimage).with_status(PaymentStatus::NotFound));
        let chain = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );
        assert!(execute_reverse_swap(
            ln.clone(),
            chain.clone(),
            claim,
            10_000,
            1,
            Duration::ZERO,
            &Resume::default(),
            &FailedPaymentMarker
        )
        .await
        .is_err());
        assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
        assert!(chain.broadcasts().is_empty());
    }

    #[tokio::test]
    async fn legacy_progress_with_unknown_payment_is_not_treated_as_definite_absence() {
        let (claim, outpoint) = recovery_claim();
        let ln = Arc::new(MockLn::new(claim.preimage));
        let chain = Arc::new(
            MockChain::new()
                .with_funding(FundingUtxo {
                    outpoint,
                    value_sat: AMOUNT,
                    confirmations: 2,
                })
                .always_final(),
        );
        let resume = Resume {
            funding: Some(outpoint),
            ..Resume::default()
        };
        execute_reverse_swap(
            ln.clone(),
            chain,
            claim,
            10_000,
            1,
            Duration::ZERO,
            &resume,
            &(),
        )
        .await
        .unwrap();
        assert_eq!(*ln.pay_calls.lock().unwrap(), 0);
    }
}
