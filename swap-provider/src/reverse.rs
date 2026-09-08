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
use swap_common::chain::{run_blocking, ChainWatcher};
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
pub trait ProgressSink: Send + Sync {
    /// The HTLC funding outpoint is now known (funded by us, or observed on-chain).
    fn funded(&self, _outpoint: OutPoint) {}
}

impl ProgressSink for () {}

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
    let hold = ln
        .create_hold_invoice(HoldInvoiceRequest {
            payment_hash,
            amount_msat: invoice_amount_msat,
            expiry_secs: invoice_expiry_secs,
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
    // If resuming after a restart and the HTLC was already funded, its outpoint — so we never
    // re-fund. `None` on a fresh start.
    resume_funding: Option<OutPoint>,
    progress: &dyn ProgressSink,
) -> Result<SwapState> {
    // 1. Wait for the client to pay the hold invoice (give up at timeout — nothing locked yet).
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

    // 2. Establish the HTLC funding outpoint, idempotently, so a resumed driver never
    //    double-funds. Only the branch that commits *new* funds is gated on the timelocks: once
    //    coins are already in the HTLC the money is at risk either way, and refusing there would
    //    strand it instead of driving it to a refund.
    let funding_outpoint = match resume_funding {
        // Resumed with a known outpoint: we already funded before the restart.
        Some(op) => op,
        None => match run_blocking(|| chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat))?
        {
            // Already funded (and still unspent) - adopt the existing output.
            Some(u) => {
                progress.funded(u.outpoint);
                u.outpoint
            }
            None => {
                // About to commit funds. Verify the *realised* timelocks first.
                //
                // Asking for a CLTV delta is not the same as getting one: a node may clamp it,
                // ignore it, or apply its own default. LND's default is 80 blocks, well short of
                // a 144-block on-chain timeout, which would let a client reclaim its sats over
                // Lightning and *then* claim the on-chain HTLC for free. So read back the expiry
                // the accepted HTLC actually carries and refuse unless the Lightning leg
                // genuinely outlives our refund window.
                //
                // Refusing costs nobody anything: the payment is still held, so cancelling
                // returns it in full.
                let status = ln
                    .invoice_status(swap.payment_hash)
                    .await
                    .map_err(|e| anyhow!("invoice status: {e}"))?;
                let ln_expiry = match status.earliest_htlc_expiry() {
                    Some(h) => h,
                    None => {
                        warn!("Reverse swap: invoice accepted but no HTLC is held; not funding");
                        if let Err(e) = ln.cancel_hold_invoice(swap.payment_hash).await {
                            warn!("Reverse swap: failed to cancel hold invoice: {e}");
                        }
                        return Ok(SwapState::Failed(
                            "no held HTLC on an accepted invoice".into(),
                        ));
                    }
                };
                let tip = run_blocking(|| chain.tip_height())?;
                if let Err(violation) = timelock::check_reverse_before_fund(
                    tip,
                    swap.timeout_height,
                    ln_expiry,
                    &swap.timelock,
                ) {
                    error!(
                        "Reverse swap: refusing to fund the HTLC, timelock violation: \
                         {violation}. Cancelling the hold invoice; the client's payment is \
                         returned in full."
                    );
                    if let Err(e) = ln.cancel_hold_invoice(swap.payment_hash).await {
                        warn!(
                            "Reverse swap: failed to cancel hold invoice after refusing to \
                             fund: {e}"
                        );
                    }
                    return Ok(SwapState::Failed(format!(
                        "timelock violation: {violation}"
                    )));
                }
                info!(
                    "Reverse swap: lightning HTLC expires at {ln_expiry}, on-chain refund opens \
                     at {}; funding on-chain HTLC",
                    swap.timeout_height
                );
                let op =
                    run_blocking(|| wallet.fund_htlc(&swap.htlc_spk, swap.onchain_amount_sat))?;
                progress.funded(op);
                op
            }
        },
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
            let spend_txid = spend.txid();
            if let Some(preimage) = extract_preimage(&spend, &funding_outpoint, &swap.payment_hash)
            {
                if !settled {
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
                        tx.txid()
                    );
                    continue;
                }
                SpendOutcome::DeadlineExceeded { last_txid, tip } => {
                    warn!(
                        "Reverse swap: refund {last_txid} still unconfirmed at height {tip}; \
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
    use bitcoin::{ScriptBuf, Transaction, Txid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::{ChainWatcher, FundingUtxo};
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
        ) -> lightning_backend::Result<PaymentResult> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn decode_invoice(&self, _bolt11: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
    }

    struct MockChain {
        tip: u32,
        funding: Option<FundingUtxo>,
        spend: Option<Transaction>,
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
            _outpoint: &OutPoint,
        ) -> swap_common::Result<Option<Transaction>> {
            Ok(self.spend.clone())
        }
        fn broadcast(&self, tx: &Transaction) -> swap_common::Result<Txid> {
            self.broadcasts.lock().unwrap().push(tx.clone());
            Ok(tx.txid())
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

        let chain = MockChain {
            tip: MOCK_TIP, // below timeout
            funding: Some(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            }),
            spend: Some(claim_tx),
            broadcasts: Mutex::new(Vec::new()),
        };
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
            None,
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
        assert!(chain.broadcasts.lock().unwrap().is_empty());
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
        let chain = MockChain {
            tip: TIMEOUT, // at/after timeout, and the client never claimed
            funding: Some(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            }),
            spend: None,
            broadcasts: Mutex::new(Vec::new()),
        };
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
            None,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Refunded);
        assert_eq!(
            chain.broadcasts.lock().unwrap().len(),
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

        let chain = MockChain {
            tip: MOCK_TIP,
            funding: None,
            spend: None,
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = NeverFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            None,
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
        assert!(chain.broadcasts.lock().unwrap().is_empty());
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
        let chain = MockChain {
            tip: TIMEOUT,
            funding: Some(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 3,
            }),
            spend: None,
            broadcasts: Mutex::new(Vec::new()),
        };
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
            None,
            &(),
        )
        .await
        .unwrap();
        assert_eq!(final_state, SwapState::Refunded);
        assert_eq!(chain.broadcasts.lock().unwrap().len(), 1);
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
        let chain = MockChain {
            tip: MOCK_TIP,
            funding: None,
            spend: Some(claim_tx),
            broadcasts: Mutex::new(Vec::new()),
        };
        let wallet = PanicFundWallet { refund_spk: dest() };

        let final_state = drive_reverse_swap(
            &ln,
            &chain,
            &wallet,
            &swap,
            2,
            Duration::from_millis(0),
            Some(outpoint), // resumed: funding already known
            &(),
        )
        .await
        .unwrap();

        assert_eq!(final_state, SwapState::Claimed);
        assert!(
            chain.broadcasts.lock().unwrap().is_empty(),
            "resumed claim path broadcasts nothing (no refund)"
        );
    }
}
