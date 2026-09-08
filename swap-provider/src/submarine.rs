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

use crate::reverse::{OnchainWallet, ProgressSink};
use anyhow::{anyhow, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Network, OutPoint, PublicKey, ScriptBuf, Txid};
use lightning_backend::{LightningBackend, PaymentStatus};
use std::time::Duration;
use swap_common::chain::{run_blocking, ChainWatcher};
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
    provider_fee_sat: u64,
    fee_rate_sat_vb: u64,
    max_routing_fee_msat: u64,
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
    // If resuming after a restart and the HTLC funding was already observed, its outpoint.
    // `None` on a fresh start.
    resume_funding: Option<OutPoint>,
    // True when a previous run recorded that it was about to pay the invoice. Combined with the
    // node's own answer, this is what keeps a resumed driver from paying twice.
    already_attempted_payment: bool,
    progress: &dyn ProgressSink,
) -> Result<SwapState> {
    // 1. Establish the funding outpoint. On a fresh start, wait for the client to fund the HTLC
    //    (give up at timeout — nothing at risk yet). On resume, adopt the known outpoint, and if
    //    we already claimed before the crash, finish immediately.
    let funding_outpoint = match resume_funding {
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
            if let Some(utxo) =
                run_blocking(|| chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat))?
            {
                if utxo.confirmations >= required_confirmations {
                    progress.funded(utxo.outpoint);
                    break utxo.outpoint;
                }
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
    match run_blocking(|| chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat))? {
        Some(utxo) if utxo.confirmations >= required_confirmations => {}
        _ => {
            if run_blocking(|| chain.find_spend(&swap.htlc_spk, &funding_outpoint))?.is_some() {
                info!("Submarine swap: funding already spent (prior claim); done");
                return Ok(SwapState::Claimed);
            }
            warn!("Submarine swap: funding no longer confirmed at required depth (reorg?); not paying");
            return Ok(SwapState::Failed(
                "funding reorged below required confirmations before payment".into(),
            ));
        }
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
    let payment = match ln
        .payment_status(swap.payment_hash)
        .await
        .map_err(|e| anyhow!("payment status: {e}"))?
    {
        PaymentStatus::Succeeded(p) => {
            info!("Submarine swap: the invoice was already paid; proceeding to the claim");
            progress.invoice_paid();
            p
        }
        PaymentStatus::InFlight => {
            // Wait it out rather than launching a second attempt. The claim-window gate above
            // bounds how long this can go on.
            info!("Submarine swap: a payment is already in flight; waiting for it to settle");
            sleep(poll).await;
            return Ok(SwapState::InvoicePending);
        }
        PaymentStatus::Failed(reason) => {
            warn!("Submarine swap: the invoice payment failed permanently: {reason}");
            return Ok(SwapState::Failed(format!(
                "invoice payment failed: {reason}"
            )));
        }
        PaymentStatus::Unknown => {
            if resume_funding.is_some() && already_attempted_payment {
                // We recorded an intent to pay and the node has no record of it. Do not assume
                // either way: keep polling. Paying again could pay twice; giving up would
                // abandon an HTLC we may already have bought.
                warn!(
                    "Submarine swap: a payment was started but the node has no record of it; \
                     polling rather than paying again"
                );
                sleep(poll).await;
                return Ok(SwapState::InvoicePending);
            }
            // Record the intent before the irreversible call.
            progress.invoice_pay_started();
            match ln
                .pay_invoice(&swap.invoice, swap.max_routing_fee_msat)
                .await
            {
                Ok(p) => {
                    progress.invoice_paid();
                    p
                }
                Err(e) => {
                    warn!("Submarine swap: invoice payment failed: {e}");
                    return Ok(SwapState::Failed(format!("invoice payment failed: {e}")));
                }
            }
        }
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
            swap.onchain_amount_sat,
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
    );
    match confirm_or_bump(
        chain,
        &swap.htlc_spk,
        funding_outpoint,
        &cfg,
        Some(&cpfp),
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
                tx.txid()
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
    use bitcoin::{OutPoint, Transaction, Txid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::{ChainWatcher, FundingUtxo};
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
    }
    impl MockLn {
        fn new(payment_hash: [u8; 32], pay_preimage: Option<[u8; 32]>) -> Self {
            Self {
                payment_hash,
                pay_preimage,
                paid: Mutex::new(false),
                status: Mutex::new(lightning_backend::PaymentStatus::Unknown),
            }
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
        ) -> lightning_backend::Result<PaymentResult> {
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
                min_final_cltv_expiry: 80,
                amount_is_explicit: true,
            })
        }
    }

    struct MockChain {
        tip: u32,
        funding: Option<FundingUtxo>,
        broadcasts: Mutex<Vec<Transaction>>,
    }
    impl ChainWatcher for MockChain {
        fn tip_height(&self) -> swap_common::Result<u32> {
            Ok(self.tip)
        }
        fn find_funding(
            &self,
            _spk: &bitcoin::Script,
            _amount: u64,
        ) -> swap_common::Result<Option<FundingUtxo>> {
            Ok(self.funding.clone())
        }
        fn find_spend(
            &self,
            _spk: &bitcoin::Script,
            _o: &OutPoint,
        ) -> swap_common::Result<Option<Transaction>> {
            Ok(None)
        }
        fn broadcast(&self, tx: &Transaction) -> swap_common::Result<Txid> {
            self.broadcasts.lock().unwrap().push(tx.clone());
            Ok(tx.txid())
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
            FEE_SAT,
            5,
            5_000,
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

        let chain = MockChain {
            tip: MOCK_TIP,
            funding: Some(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: ONCHAIN_SAT,
                confirmations: 3,
            }),
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            None,
            false,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Claimed);
        let broadcasts = chain.broadcasts.lock().unwrap();
        assert_eq!(broadcasts.len(), 1, "one claim tx must be broadcast");
        // The broadcast claim must carry the preimage that matches the hashlock.
        assert_eq!(
            extract_preimage(&broadcasts[0], &funding_outpoint(), &ph),
            Some(preimage)
        );
    }

    #[tokio::test]
    async fn submarine_swap_payment_failure_does_not_claim() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn::new(ph, None); // payment fails
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain {
            tip: MOCK_TIP,
            funding: Some(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: ONCHAIN_SAT,
                confirmations: 3,
            }),
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            None,
            false,
            &(),
        )
        .await
        .unwrap();

        assert!(matches!(state, SwapState::Failed(_)));
        assert!(
            chain.broadcasts.lock().unwrap().is_empty(),
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
        let chain = MockChain {
            tip: MOCK_TIP,
            funding: Some(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat,
                confirmations: 3,
            }),
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            Some(funding_outpoint()),
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
            chain.broadcasts.lock().unwrap().len(),
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
        let chain = MockChain {
            tip: MOCK_TIP,
            funding: Some(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat,
                confirmations: 3,
            }),
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            Some(funding_outpoint()),
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
        assert!(chain.broadcasts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn refuses_to_pay_when_the_claim_window_is_too_short() {
        let preimage = generate_preimage();
        let ln = MockLn::new(payment_hash(&preimage), Some(preimage));
        let (swap, _) = make_swap(&ln).await;

        // Funding confirms with two blocks left before the client's refund branch opens.
        let chain = MockChain {
            tip: TIMEOUT - 2,
            funding: Some(FundingUtxo {
                outpoint: funding_outpoint(),
                value_sat: swap.onchain_amount_sat,
                confirmations: 3,
            }),
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = MockWallet { spk: dest() };

        let final_state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            1,
            Duration::from_millis(0),
            None,
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
        assert!(
            chain.broadcasts.lock().unwrap().is_empty(),
            "nothing should be broadcast"
        );
    }

    #[tokio::test]
    async fn submarine_swap_expires_without_funding() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn::new(ph, Some(preimage));
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain {
            tip: TIMEOUT, // reached the timeout with no funding
            funding: None,
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = MockWallet { spk: dest() };

        let state = drive_submarine_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            None,
            false,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Expired);
        assert!(chain.broadcasts.lock().unwrap().is_empty());
    }
}
