//! Client-side execution of a submarine swap (on-chain → Lightning).
//!
//! After negotiation, the client holds a Lightning invoice it issued (the provider will pay it),
//! an HTLC refund key, and the provider's HTLC details. Execution: fund the HTLC on-chain, then
//! wait. When the provider pays the invoice — settling it and learning the preimage — the client
//! has received its Lightning funds and the swap is done. If the provider never pays before the
//! timeout, the client refunds the HTLC on-chain.

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{OutPoint, ScriptBuf, Txid};
use lightning_backend::{InvoiceState, LightningBackend};
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::{run_blocking, select_recorded_funding, ChainWatcher};
use swap_common::fee_bump::{confirm_or_bump, SpendOutcome, SpendWatchConfig};
use swap_common::htlc::PaymentHash;
use swap_common::onchain::{
    build_refund_tx, estimate_spend_fee, extract_preimage, fee_rate_cap, spend_vsize,
    ABSOLUTE_MAX_FEE_RATE_SAT_VB, DEFAULT_MAX_FEE_BPS, REFUND_FEE_TARGET_BLOCKS,
};
use swap_common::reorg::FINALITY_DEPTH;
use swap_common::store::Resume;
use swap_common::timelock::claim_start_is_safe;
use swap_common::wallet::OnchainWallet;
use swap_common::SwapState;
use tokio::time::sleep;
use tracing::{info, warn};

/// Everything the client needs (from its own state + the provider's `SwapAccept`) to execute the
/// on-chain side of a submarine swap.
pub struct SubmarineFunding {
    /// HTLC redeem script (verify it matches what you expect before funding!).
    pub htlc_script: ScriptBuf,
    /// HTLC P2WSH scriptPubKey.
    pub htlc_spk: ScriptBuf,
    /// Amount the client locks on-chain (invoice amount + provider fee).
    pub onchain_amount_sat: u64,
    /// Payment hash of the client's invoice (the HTLC hashlock).
    pub payment_hash: PaymentHash,
    /// The client's HTLC refund key (refund branch).
    pub refund_key: SecretKey,
    /// Absolute block height at which the refund branch becomes spendable.
    pub timeout_height: u32,
    /// Fee rate (sat/vB) floor for the refund transaction.
    pub fee_rate_sat_vb: u64,
}

/// Notified as the client's swap progresses, so what it did reaches disk.
///
/// The refund key is already persisted before this executor is called; this records where the
/// coins actually landed, which is what turns a resumed client's recovery from a chain scan into
/// a lookup.
pub trait FundingSink: Send + Sync {
    /// About to broadcast a funding transaction, at the given tip height.
    ///
    /// Fallible, because this marker is the only thing standing between a crash and a second
    /// funding: broadcasting after failing to write it is how the same swap gets funded twice.
    fn funding_intent(&self, _tip: u32) -> Result<()> {
        Ok(())
    }
    fn funded(&self, _outpoint: OutPoint) {}
    /// A claim or refund we are about to put on the wire.
    ///
    /// Reported *before* the broadcast, so a later run knows the transaction is its own rather
    /// than reading it as the counterparty's spend.
    fn spend_broadcast(&self, _txid: Txid) {}
}

impl FundingSink for () {}

/// Establish the HTLC funding without ever making a second one.
///
/// The client's exposure here is the whole point of the swap: it locks its own coins, and the
/// refund branch is the only way back. Funding twice locks them twice, and only one of the two
/// outputs is the one the provider is watching, so the other has no counterparty at all and comes
/// back only at the timeout. `Ok(None)` means nothing was funded and nothing will be.
async fn establish_funding(
    chain: &dyn ChainWatcher,
    wallet: &dyn OnchainWallet,
    funding: &SubmarineFunding,
    poll: Duration,
    resume: &Resume,
    progress: &dyn FundingSink,
) -> Result<Option<OutPoint>> {
    if let Some(op) = resume.funding {
        return Ok(Some(op));
    }

    if let Some(u) =
        run_blocking(|| chain.find_funding(&funding.htlc_spk, funding.onchain_amount_sat))
            .map_err(|e| anyhow!("find funding: {e}"))?
    {
        progress.funded(u.outpoint);
        return Ok(Some(u.outpoint));
    }

    // A previous run recorded that it was about to broadcast. Whatever the chain shows now, this
    // run does not fund: an empty answer means "the broadcast never landed" and "it landed and
    // has been spent" alike, and only one of those is safe to act on.
    if resume.funding_intent_at_height.is_some() {
        return await_recorded_funding(chain, funding, poll, progress).await;
    }

    let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?;

    // Nothing has been committed yet, so there is still a decision to make: is this swap worth
    // funding at all? On the fresh path `validate_accept` answered that before we got here. A
    // resume calls straight into this function with a record rebuilt from disk and asks nothing,
    // so a client restarted after the timeout would fund an HTLC whose provider gave up long ago,
    // then immediately refund it. That is two on-chain fees and the whole amount locked and
    // unlocked, for a swap that was already dead.
    if !claim_start_is_safe(tip, funding.timeout_height) {
        return Err(anyhow!(
            "this swap's HTLC times out at height {} and the tip is {tip}, so there is no window \
             left for the provider to pay and claim. Not funding it. Nothing was committed on \
             chain.",
            funding.timeout_height
        ));
    }

    // Written before the broadcast: without it a crash in the gap leaves coins in an HTLC with
    // nothing on disk pointing at them, and the refund key alone is not enough to find them.
    progress.funding_intent(tip)?;

    match run_blocking(|| wallet.fund_htlc(&funding.htlc_spk, funding.onchain_amount_sat)) {
        Ok(op) => {
            progress.funded(op);
            Ok(Some(op))
        }
        // Not a failure to fund: a failure to know whether we funded. The wallet can answer with
        // an error after the transaction is already on the wire, and giving up there abandons
        // coins whose only way back is the refund branch.
        Err(e) => {
            warn!(
                "Submarine client: the funding call failed ({e}), but it may already have been \
                 broadcast. Not funding again; watching for it to appear."
            );
            await_recorded_funding(chain, funding, poll, progress).await
        }
    }
}

/// Wait for a funding this client may already have broadcast, without broadcasting another.
async fn await_recorded_funding(
    chain: &dyn ChainWatcher,
    funding: &SubmarineFunding,
    poll: Duration,
    progress: &dyn FundingSink,
) -> Result<Option<OutPoint>> {
    // Slower than the driver's own poll: this can run for the whole timeout window and asks for a
    // script's entire history each time. Zero stays zero so tests do not sleep.
    let watch_poll = if poll.is_zero() {
        poll
    } else {
        poll.max(Duration::from_secs(30))
    };
    loop {
        if let Some(u) =
            run_blocking(|| chain.find_funding(&funding.htlc_spk, funding.onchain_amount_sat))
                .map_err(|e| anyhow!("find funding: {e}"))?
        {
            info!(
                "Submarine client: the recorded funding is visible at {}",
                u.outpoint
            );
            progress.funded(u.outpoint);
            return Ok(Some(u.outpoint));
        }

        let history = run_blocking(|| chain.find_historical_outputs(&funding.htlc_spk))
            .map_err(|e| anyhow!("script history: {e}"))?;
        if let Some(op) = run_blocking(|| {
            select_recorded_funding(
                chain,
                &funding.htlc_spk,
                &funding.payment_hash,
                funding.onchain_amount_sat,
                &history,
            )
        })
        .map_err(|e| anyhow!("select funding: {e}"))?
        {
            warn!("Submarine client: the recorded funding is on chain at {op} and has been spent");
            progress.funded(op);
            return Ok(Some(op));
        }

        let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?;
        if tip >= funding.timeout_height {
            warn!(
                "Submarine client: a funding was recorded but never became visible before height \
                 {}. Nothing appears to be locked; the refund key stays in this swap's record.",
                funding.timeout_height
            );
            return Ok(None);
        }
        sleep(watch_poll).await;
    }
}

/// Execute the client side of a submarine swap, returning the terminal [`SwapState`]
/// (`Claimed` once the provider settles the invoice, or `Refunded` on timeout).
pub async fn execute_submarine_swap(
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    wallet: Arc<dyn OnchainWallet>,
    funding: SubmarineFunding,
    poll: Duration,
    // What a previous run of this swap already did. `Resume::default()` on a fresh start.
    resume: &Resume,
    progress: &dyn FundingSink,
) -> Result<SwapState> {
    // 1. Establish the HTLC funding, without ever making a second one.
    //
    // The refund key for this output is already on disk: the caller writes it before the swap is
    // ever mentioned to the provider, because it is the only key that can move these coins on the
    // refund branch and it exists nowhere else.
    let Some(outpoint) = establish_funding(
        chain.as_ref(),
        wallet.as_ref(),
        &funding,
        poll,
        resume,
        progress,
    )
    .await?
    else {
        return Ok(SwapState::Expired);
    };
    info!("Submarine client: HTLC funded at {outpoint}; awaiting Lightning settlement");

    // 2. Wait for the provider to pay (settling our invoice) or refund at the timeout.
    loop {
        if matches!(
            ln.invoice_state(funding.payment_hash)
                .await
                .map_err(|e| anyhow!("invoice state: {e}"))?,
            InvoiceState::Settled
        ) {
            info!("Submarine client: invoice settled — Lightning funds received");
            return Ok(SwapState::Claimed);
        }

        if run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?
            >= funding.timeout_height
        {
            // If the provider already claimed the HTLC, the preimage is public and our invoice
            // will settle — don't refund (the refund would just lose to their claim).
            //
            // A spend is not by itself a claim. Our own refund spends this same outpoint, and it
            // sits in the mempool for as long as it takes to confirm; a resumed run, or the next
            // turn of this loop, would read it back and conclude the provider had won. That
            // returns `Claimed` for a swap nobody claimed, stops driving the refund before it is
            // confirmed, and leaves the fee escalation that gets it mined unstarted.
            //
            // Only a spend that reveals the preimage is the provider's claim. Nothing else can
            // produce one: that is the whole point of the hashlock branch.
            if let Some(spend) = run_blocking(|| chain.find_spend(&funding.htlc_spk, &outpoint))
                .map_err(|e| anyhow!("find spend: {e}"))?
            {
                if extract_preimage(&spend, &outpoint, &funding.payment_hash).is_some() {
                    info!(
                        "Submarine client: HTLC already claimed by provider; awaiting settlement"
                    );
                    return Ok(SwapState::Claimed);
                }
                info!(
                    "Submarine client: the HTLC is spent by a transaction that reveals no \
                     preimage, so it is our own refund. Continuing to drive it."
                );
            }

            warn!("Submarine client: timeout reached without settlement; refunding HTLC");
            let dest = wallet.receive_destination();
            let refund_vsize = spend_vsize(&funding.htlc_script, &dest, false);
            let build = |rate: u64| {
                build_refund_tx(
                    outpoint,
                    funding.onchain_amount_sat,
                    &funding.htlc_script,
                    dest.clone(),
                    estimate_spend_fee(rate, refund_vsize),
                    funding.timeout_height,
                    &funding.refund_key,
                )
            };
            // The refund sweeps to our wallet, so CPFP can bump it if RBF is rejected.
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
            // No deadline on a refund: this is our own money, so there is no point at which
            // giving up is better than continuing.
            let cfg = SpendWatchConfig::refund(
                REFUND_FEE_TARGET_BLOCKS,
                funding.fee_rate_sat_vb,
                fee_rate_cap(
                    funding.onchain_amount_sat,
                    refund_vsize,
                    DEFAULT_MAX_FEE_BPS,
                    ABSOLUTE_MAX_FEE_RATE_SAT_VB,
                    funding.fee_rate_sat_vb,
                ),
                poll,
                FINALITY_DEPTH,
            )
            .with_known_ours(resume.our_spends.clone());
            match confirm_or_bump(
                chain.as_ref(),
                &funding.htlc_spk,
                outpoint,
                &cfg,
                Some(&cpfp),
                &|txid| progress.spend_broadcast(txid),
                build,
            )
            .await
            .map_err(|e| anyhow!("refund broadcast/bump: {e}"))?
            {
                SpendOutcome::Confirmed { .. } => return Ok(SwapState::Refunded),
                // A spend that is not one we recognise. Whether it is the provider claiming or
                // our own earlier refund is decided by the witness, not by whether we happen to
                // have the txid on file: a crash between broadcasting a refund and persisting its
                // txid leaves `known_ours` empty for a transaction that is very much ours, and
                // reading that as the provider's claim ends the swap as `Claimed` with our own
                // coins still unconfirmed in an unfinished refund nobody is bumping any more.
                //
                // Only the hashlock branch can produce a preimage. That is the test.
                SpendOutcome::ConflictingSpend { tx } => {
                    let txid = tx.compute_txid();
                    if extract_preimage(&tx, &outpoint, &funding.payment_hash).is_some() {
                        // The provider claimed while we were refunding. The preimage is public
                        // now, so our invoice settles and we are paid over Lightning: this is the
                        // swap succeeding, not failing.
                        info!(
                            "Submarine client: the provider claimed the HTLC ({txid}) as we \
                             refunded; awaiting Lightning settlement"
                        );
                        return Ok(SwapState::Claimed);
                    }
                    info!(
                        "Submarine client: the HTLC is spent by {txid}, which reveals no \
                         preimage, so it is a refund of ours from an earlier run. Adopting it."
                    );
                    progress.spend_broadcast(txid);
                    return Ok(SwapState::Refunded);
                }
                SpendOutcome::DeadlineExceeded { last_txid, tip } => {
                    warn!(
                        "Submarine client: refund {last_txid} still unconfirmed at height {tip}; \
                         retrying"
                    );
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
    use bitcoin::{OutPoint, Txid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;

    use swap_common::chain::mock::MockChain;

    use swap_common::htlc::{
        build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash,
    };
    use swap_common::random_keypair;

    const AMOUNT: u64 = 100_000;
    const TIMEOUT: u32 = 5000;

    struct MockLn {
        state: InvoiceState,
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
            Ok(lightning_backend::InvoiceStatus {
                state: self.state,
                amount_paid_msat: 0,
                htlcs: Vec::new(),
            })
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
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn payment_status(
            &self,
            _ph: [u8; 32],
        ) -> lightning_backend::Result<lightning_backend::PaymentStatus> {
            Ok(lightning_backend::PaymentStatus::Unknown)
        }
        async fn decode_invoice(&self, _: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
    }

    struct MockWallet {
        outpoint: OutPoint,
        dest: ScriptBuf,
    }
    impl OnchainWallet for MockWallet {
        fn fund_htlc(&self, _: &ScriptBuf, _: u64) -> swap_common::Result<OutPoint> {
            Ok(self.outpoint)
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.dest.clone()
        }
    }

    fn dest() -> ScriptBuf {
        ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap()
    }

    fn funding(refund_key: SecretKey, script: ScriptBuf, ph: [u8; 32]) -> SubmarineFunding {
        let htlc_spk = htlc_p2wsh_address(&script, bitcoin::Network::Regtest).script_pubkey();
        SubmarineFunding {
            htlc_script: script,
            htlc_spk,
            onchain_amount_sat: AMOUNT,
            payment_hash: ph,
            refund_key,
            timeout_height: TIMEOUT,
            fee_rate_sat_vb: 5,
        }
    }

    fn outpoint() -> OutPoint {
        OutPoint {
            txid: Txid::from_str(
                "4444444444444444444444444444444444444444444444444444444444444444",
            )
            .unwrap(),
            vout: 0,
        }
    }

    /// A wallet that refuses to fund, for the cases where funding at all is the bug.
    struct PanicFundWallet {
        dest: ScriptBuf,
    }
    impl OnchainWallet for PanicFundWallet {
        fn fund_htlc(&self, _: &ScriptBuf, _: u64) -> swap_common::Result<OutPoint> {
            panic!("a resumed client must not fund a second HTLC");
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.dest.clone()
        }
    }

    struct CountingWallet {
        dest: ScriptBuf,
        funded: std::sync::Mutex<u32>,
    }
    impl OnchainWallet for CountingWallet {
        fn fund_htlc(&self, _: &ScriptBuf, _: u64) -> swap_common::Result<OutPoint> {
            *self.funded.lock().unwrap() += 1;
            Ok(outpoint())
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.dest.clone()
        }
    }

    /// A resume must not fund a swap that is already over.
    ///
    /// On the fresh path `validate_accept` answers "is this worth funding" before anything is
    /// committed. The resume path calls straight in with a record rebuilt from disk and asks
    /// nothing, so a client restarted after the timeout funded an HTLC whose provider gave up
    /// long ago and then immediately refunded it: two on-chain fees and the whole amount locked
    /// and unlocked, on a swap that was dead before the funding was broadcast.
    #[tokio::test]
    async fn a_resumed_client_does_not_fund_a_swap_whose_window_has_closed() {
        let secp = Secp256k1::new();
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, TIMEOUT);
        let f = funding(refund_sk, script, ph);

        // Restarted well past the timeout, with nothing funded and no marker: the state a client
        // that died before broadcasting comes back in.
        let chain = MockChain::new().always_final().with_tip(TIMEOUT + 50);
        let ln = MockLn {
            state: InvoiceState::Open,
        };
        let wallet = PanicFundWallet { dest: dest() };

        let result = execute_submarine_swap(
            Arc::new(ln),
            Arc::new(chain),
            Arc::new(wallet),
            f,
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await;

        // `PanicFundWallet` panics if funding is attempted, so reaching here at all is the
        // assertion; the error says so out loud.
        assert!(
            result.is_err(),
            "a swap whose window has closed must be refused, not funded and refunded"
        );
    }

    /// Our own refund spends the same outpoint the provider's claim would, and it sits in the
    /// mempool for as long as it takes to confirm. Reading any spend as the provider's claim
    /// returns `Claimed` for a swap nobody claimed, and stops driving the refund before it is
    /// mined: the fee escalation that gets it in never starts, and the client's own coins are the
    /// ones left in the HTLC.
    ///
    /// Only a spend revealing the preimage is the provider's claim.
    #[tokio::test]
    async fn our_own_unconfirmed_refund_is_not_mistaken_for_the_providers_claim() {
        let secp = Secp256k1::new();
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, TIMEOUT);
        let f = funding(refund_sk, script.clone(), ph);

        // Past the timeout, funded, and already spent by a refund we broadcast: a refund witness
        // carries no preimage, which is the whole distinction.
        let our_refund = swap_common::onchain::build_refund_tx(
            outpoint(),
            AMOUNT,
            &script,
            dest(),
            500,
            TIMEOUT,
            &refund_sk,
        )
        .unwrap();
        assert!(
            swap_common::onchain::extract_preimage(&our_refund, &outpoint(), &ph).is_none(),
            "a refund reveals no preimage; that is what this test rests on"
        );

        let chain = MockChain::new()
            .always_final()
            .with_tip(TIMEOUT + 1)
            .with_funding(swap_common::chain::FundingUtxo {
                outpoint: outpoint(),
                value_sat: AMOUNT,
                confirmations: 3,
            })
            .with_spend(our_refund);
        let ln = MockLn {
            state: InvoiceState::Open,
        };
        let wallet = PanicFundWallet { dest: dest() };

        let state = execute_submarine_swap(
            Arc::new(ln),
            Arc::new(chain),
            Arc::new(wallet),
            f,
            Duration::from_millis(0),
            &Resume {
                funding: Some(outpoint()),
                ..Default::default()
            },
            &(),
        )
        .await
        .unwrap();

        assert_ne!(
            state,
            SwapState::Claimed,
            "our own refund must not be read as the provider claiming; the swap refunded"
        );
    }

    /// The client's version of the double-funding hole, and the more expensive one: these are the
    /// client's own coins, and a second HTLC has no counterparty watching it at all, so it comes
    /// back only at the timeout and only if the refund key survives.
    ///
    /// A crash between broadcast and recording the outpoint, then a provider that claims, leaves
    /// an empty UTXO set. That reads as "never funded" and used to fund again.
    #[tokio::test]
    async fn a_resumed_client_does_not_fund_a_second_htlc() {
        let secp = Secp256k1::new();
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, TIMEOUT);
        let f = funding(refund_sk, script, ph);

        // The provider claimed, so nothing is unspent and the invoice has settled.
        let chain = MockChain::new()
            .always_final()
            .with_tip(TIMEOUT - 10)
            .with_spent_output(
                outpoint(),
                AMOUNT,
                Txid::from_str("5555555555555555555555555555555555555555555555555555555555555555")
                    .unwrap(),
            );
        let ln = MockLn {
            state: InvoiceState::Settled,
        };
        let wallet = PanicFundWallet { dest: dest() };

        let state = execute_submarine_swap(
            Arc::new(ln),
            Arc::new(chain),
            Arc::new(wallet),
            f,
            Duration::from_millis(0),
            &Resume {
                funding: None,
                funding_intent_at_height: Some(TIMEOUT - 100),
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Claimed);
    }

    /// And when nothing ever appears, it still does not fund: the swap simply never happened, and
    /// an empty chain view is not proof of that either way.
    #[tokio::test]
    async fn a_recorded_client_funding_that_never_appears_is_not_funded_again() {
        let secp = Secp256k1::new();
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let (_claim_sk, claim_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, TIMEOUT);
        let f = funding(refund_sk, script, ph);

        // Past the timeout with nothing on chain, so the watch gives up on its first pass.
        let chain = MockChain::new().always_final().with_tip(TIMEOUT);
        let ln = MockLn {
            state: InvoiceState::Open,
        };
        let wallet = CountingWallet {
            dest: dest(),
            funded: std::sync::Mutex::new(0),
        };
        let wallet = Arc::new(wallet);

        let state = execute_submarine_swap(
            Arc::new(ln),
            Arc::new(chain),
            wallet.clone(),
            f,
            Duration::from_millis(0),
            &Resume {
                funding: None,
                funding_intent_at_height: Some(TIMEOUT - 100),
                our_spends: Vec::new(),
                reorg_seen_at_height: None,
            },
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Expired);
        assert_eq!(*wallet.funded.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn submarine_client_succeeds_when_invoice_settles() {
        let secp = Secp256k1::new();
        let (_p_sk, provider_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());
        let script = build_htlc_script(&ph, &provider_pk, &refund_pk, TIMEOUT);

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn {
            state: InvoiceState::Settled,
        });
        let chain: Arc<dyn ChainWatcher> = Arc::new(MockChain::new().with_tip(100).always_final());
        let wallet: Arc<dyn OnchainWallet> = Arc::new(MockWallet {
            outpoint: outpoint(),
            dest: dest(),
        });

        let state = execute_submarine_swap(
            ln,
            chain,
            wallet,
            funding(refund_sk, script, ph),
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();
        assert_eq!(state, SwapState::Claimed);
    }

    #[tokio::test]
    async fn submarine_client_refunds_after_timeout() {
        let secp = Secp256k1::new();
        let (_p_sk, provider_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());
        let script = build_htlc_script(&ph, &provider_pk, &refund_pk, TIMEOUT);

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn {
            state: InvoiceState::Open, // never settles
        });
        // The tip advances while the swap runs: funding happens with the window open, and the
        // timeout arrives afterwards. Starting at the timeout would mean funding into a window
        // that had already closed, which is a thing the client now refuses to do.
        let chain_mock = Arc::new(
            MockChain::new()
                .with_tips(vec![TIMEOUT - 100, TIMEOUT])
                .always_final(),
        );
        let chain: Arc<dyn ChainWatcher> = chain_mock.clone();
        let wallet: Arc<dyn OnchainWallet> = Arc::new(MockWallet {
            outpoint: outpoint(),
            dest: dest(),
        });

        let state = execute_submarine_swap(
            ln,
            chain,
            wallet,
            funding(refund_sk, script, ph),
            Duration::from_millis(0),
            &Resume::default(),
            &(),
        )
        .await
        .unwrap();
        assert_eq!(state, SwapState::Refunded);
        assert_eq!(
            chain_mock.broadcasts().len(),
            1,
            "a refund tx must be broadcast"
        );
    }

    /// TEMPORARY probe: a resumed client whose OWN refund is the only spend of the HTLC.
    #[tokio::test]
    async fn probe_resumed_client_reads_its_own_refund() {
        use bitcoin::absolute::LockTime;
        use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};
        let secp = Secp256k1::new();
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let (_c_sk, claim_pk) = random_keypair(&secp);
        let ph = payment_hash(&generate_preimage());
        let script = build_htlc_script(&ph, &claim_pk, &refund_pk, TIMEOUT);

        // Our own refund: spends the HTLC outpoint, no preimage in the witness.
        let our_refund = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::from_height(TIMEOUT).unwrap(),
            input: vec![TxIn {
                previous_output: outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(AMOUNT - 500),
                script_pubkey: dest(),
            }],
        };
        let our_txid = our_refund.compute_txid();

        let chain = Arc::new(
            MockChain::new()
                .with_tip(TIMEOUT + 1)
                .always_final()
                .with_spend(our_refund),
        );
        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn {
            state: InvoiceState::Open, // the provider never paid
        });
        let wallet: Arc<dyn OnchainWallet> = Arc::new(MockWallet {
            outpoint: outpoint(),
            dest: dest(),
        });

        let state = execute_submarine_swap(
            ln,
            chain.clone(),
            wallet,
            funding(refund_sk, script, ph),
            Duration::from_millis(0),
            &Resume {
                funding: Some(outpoint()),
                funding_intent_at_height: None,
                our_spends: vec![our_txid],
                reorg_seen_at_height: None,
            },
            &(),
        )
        .await
        .unwrap();
        println!(
            "PROBE RESULT: {state:?}, broadcasts={}",
            chain.broadcast_count()
        );
        assert_eq!(
            state,
            SwapState::Refunded,
            "PROBE: our own refund was read as the provider's claim"
        );
    }
}
