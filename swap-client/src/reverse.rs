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
    run_blocking, select_funding, ChainWatcher, FundingSelection, DEFAULT_MAX_OVERPAY_SAT,
};
use swap_common::fee_bump::{confirm_or_bump, SpendOutcome, SpendWatchConfig};
use swap_common::htlc::{payment_hash, Preimage};
use swap_common::onchain::{
    build_claim_tx, estimate_spend_fee, fee_rate_cap, spend_vsize, ABSOLUTE_MAX_FEE_RATE_SAT_VB,
    CLAIM_FEE_TARGET_BLOCKS, DEFAULT_MAX_FEE_BPS,
};
use swap_common::reorg::FINALITY_DEPTH;
use swap_common::store::Resume;
use swap_common::timelock::claim_start_is_safe;
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
    // Asking the node first is the whole of the resume story on this side: a payment that is
    // in flight or already settled must not be started again, and the node is the only thing
    // that knows. The invoice is held either way until the provider settles it, which only
    // happens after we claim on-chain and reveal the preimage.
    let already_paying = if resume.is_fresh() {
        false
    } else {
        match ln.payment_status(claim.payment_hash()).await {
            Ok(PaymentStatus::Succeeded { .. }) => {
                info!("Client: the hold invoice was already paid by an earlier run");
                true
            }
            Ok(PaymentStatus::InFlight) => {
                info!("Client: a payment for this invoice is still in flight");
                true
            }
            Ok(PaymentStatus::Failed(_)) | Ok(PaymentStatus::Unknown) => false,
            Err(e) => {
                // Not knowing is not a reason to pay again: the on-chain HTLC is what this run
                // is here for, and paying twice is the one mistake with no way back.
                warn!("Client: could not read the payment's status ({e}); not paying again");
                true
            }
        }
    };

    let pay_task = if already_paying {
        None
    } else {
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

    // 2. Wait for the provider to fund + confirm the on-chain HTLC.
    //
    // Classify what pays the script rather than asking for an exact value. The HTLC address is
    // public from the moment it is in the `SwapAccept`, so an underpayment, an overpayment and a
    // double payment all happen, and a single "not funded yet" answer for all of them means
    // waiting out the whole timeout with a Lightning payment held.
    let funding = loop {
        let outputs = run_blocking(|| chain.find_outputs(&claim.htlc_spk))
            .map_err(|e| anyhow!("find_outputs: {e}"))?;
        match select_funding(&outputs, claim.onchain_amount_sat, DEFAULT_MAX_OVERPAY_SAT) {
            FundingSelection::Exact(u) | FundingSelection::Overpaid { utxo: u, .. } => {
                if u.confirmations >= required_confirmations {
                    break u;
                }
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
            FundingSelection::None => {}
        }
        // The provider's refund branch opens at the timeout. Past it there is nothing left to
        // claim, and a resumed client has no `pay_task` to end this loop for it: its payment was
        // started by a previous run, so the only other exit is the chain. Without this the loop
        // polls forever and the swap never reaches its refund-or-give-up conclusion.
        let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip_height: {e}"))?;
        if !claim_start_is_safe(tip, claim.timeout_height) {
            return Err(anyhow!(
                "the provider's HTLC did not confirm in time: tip {tip} against a timeout at {}. \
                 The provider refunds its own funding; nothing of ours is locked on chain.",
                claim.timeout_height
            ));
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
    let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip_height: {e}"))?;
    if !claim_start_is_safe(tip, claim.timeout_height) {
        return Err(anyhow!(
            "the provider's HTLC confirmed too close to its refund at height {} (tip {tip}) to \
             claim safely, so the preimage stays secret. The provider refunds its own funding \
             and the hold invoice expires unsettled.",
            claim.timeout_height
        ));
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
    let deadline = claim
        .timeout_height
        .saturating_sub(swap_common::timelock::CLAIM_ABORT_MARGIN);
    let cfg = SpendWatchConfig::claim(
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
    .with_known_ours(resume.our_spends.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Network, OutPoint, Txid as BTxid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;

    use swap_common::chain::mock::MockChain;
    use swap_common::chain::FundingUtxo;
    use swap_common::htlc::{
        build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash,
    };
    use swap_common::onchain::extract_preimage;
    use swap_common::random_keypair;

    const AMOUNT: u64 = 100_000;
    const MOCK_TIP: u32 = 700_000;
    const TIMEOUT: u32 = MOCK_TIP + 144;

    struct MockLn {
        preimage: [u8; 32],
        /// What the node says about a payment for this hash, and how many times it was asked to
        /// make one.
        status: lightning_backend::PaymentStatus,
        pay_calls: std::sync::Mutex<u32>,
    }

    impl MockLn {
        fn new(preimage: [u8; 32]) -> Self {
            Self {
                preimage,
                status: lightning_backend::PaymentStatus::Unknown,
                pay_calls: std::sync::Mutex::new(0),
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
            *self.pay_calls.lock().unwrap() += 1;
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
            Ok(self.status.clone())
        }
        async fn decode_invoice(&self, _: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
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

        let ln =
            Arc::new(MockLn::new(preimage).with_status(lightning_backend::PaymentStatus::InFlight));
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
                funding: Some(outpoint),
                funding_intent_at_height: None,
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
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
}
