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
use bitcoin::{Network, OutPoint, PublicKey, ScriptBuf};
use lightning_backend::{InvoiceState, LightningBackend};
use std::time::Duration;
use swap_common::chain::ChainWatcher;
use swap_common::fee_bump::{confirm_or_bump, MAX_FEE_BUMPS};
use swap_common::htlc::{build_htlc_script, htlc_p2wsh_address, PaymentHash};
use swap_common::onchain::{
    build_refund_tx, estimate_spend_fee, extract_preimage, REFUND_FEE_TARGET_BLOCKS,
};
use swap_common::reorg::FINALITY_DEPTH;
use swap_common::SwapState;
use tokio::time::sleep;
use tracing::{info, warn};

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
) -> Result<ReverseSwap> {
    let htlc_script = build_htlc_script(
        &payment_hash,
        client_claim_pubkey,
        provider_refund_pubkey,
        timeout_height,
    );
    let htlc_spk = htlc_p2wsh_address(&htlc_script, network).script_pubkey();

    // The client pays the on-chain amount plus the provider's fee over Lightning.
    let invoice_amount_msat = (onchain_amount_sat + provider_fee_sat) * 1000;
    let hold = ln
        .create_hold_invoice(
            payment_hash,
            invoice_amount_msat,
            invoice_expiry_secs,
            "pubky-swap reverse",
        )
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
    })
}

/// Drive a reverse swap to a terminal [`SwapState`] (`Claimed`, `Refunded`, `Expired`, or
/// `Failed`).
///
/// NOTE: [`ChainWatcher`] calls are blocking; a production caller should run this on a
/// blocking-friendly task. `poll` is injected for testability.
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
                if chain.tip_height()? >= swap.timeout_height {
                    if let Err(e) = ln.cancel_hold_invoice(swap.payment_hash).await {
                        warn!("Reverse swap: failed to cancel hold invoice on expiry: {e}");
                    }
                    return Ok(SwapState::Expired);
                }
            }
        }
        sleep(poll).await;
    }
    info!("Reverse swap: hold invoice accepted; funding on-chain HTLC");

    // 2. Fund the on-chain HTLC — idempotently, so a resumed driver never double-funds.
    let funding_outpoint = match resume_funding {
        // Resumed with a known outpoint: we already funded before the restart.
        Some(op) => op,
        None => match chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat)? {
            // Already funded (and still unspent) — adopt the existing output.
            Some(u) => {
                progress.funded(u.outpoint);
                u.outpoint
            }
            None => {
                let op = wallet.fund_htlc(&swap.htlc_spk, swap.onchain_amount_sat)?;
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

    // 3. Wait for the client to claim (revealing the preimage), else refund at timeout.
    loop {
        if let Some(spend) = chain.find_spend(&swap.htlc_spk, &funding_outpoint)? {
            if let Some(preimage) = extract_preimage(&spend, &funding_outpoint, &swap.payment_hash)
            {
                ln.settle_hold_invoice(preimage)
                    .await
                    .map_err(|e| anyhow!("settle invoice: {e}"))?;
                info!("Reverse swap: client claimed; hold invoice settled");
                return Ok(SwapState::Claimed);
            }
        }
        if chain.tip_height()? >= swap.timeout_height {
            warn!("Reverse swap: timeout reached without claim; refunding HTLC");
            // Broadcast the refund and keep it confirming under fee pressure (RBF): the initial
            // fee uses a live estimate clamped to the floor, and is bumped if it doesn't confirm.
            let dest = wallet.receive_destination();
            let build = |rate: u64| {
                build_refund_tx(
                    funding_outpoint,
                    swap.onchain_amount_sat,
                    &swap.htlc_script,
                    dest.clone(),
                    estimate_spend_fee(rate, false),
                    swap.timeout_height,
                    &swap.refund_key,
                )
            };
            confirm_or_bump(
                chain,
                &swap.htlc_spk,
                REFUND_FEE_TARGET_BLOCKS,
                swap.fee_rate_sat_vb,
                poll,
                MAX_FEE_BUMPS,
                FINALITY_DEPTH,
                build,
            )
            .await
            .map_err(|e| anyhow!("refund broadcast/bump: {e}"))?;
            if let Err(e) = ln.cancel_hold_invoice(swap.payment_hash).await {
                warn!("Reverse swap: failed to cancel hold invoice after refund: {e}");
            }
            return Ok(SwapState::Refunded);
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
    const TIMEOUT: u32 = 800_000;

    struct MockLn {
        state: Mutex<InvoiceState>,
        settled_preimage: Mutex<Option<[u8; 32]>>,
        cancelled: Mutex<bool>,
    }
    impl MockLn {
        fn new(initial: InvoiceState) -> Self {
            Self {
                state: Mutex::new(initial),
                settled_preimage: Mutex::new(None),
                cancelled: Mutex::new(false),
            }
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
            payment_hash: [u8; 32],
            amount_msat: u64,
            _expiry_secs: u64,
            _memo: &str,
        ) -> lightning_backend::Result<HoldInvoice> {
            Ok(HoldInvoice {
                bolt11: "lnbcrt-mock".into(),
                payment_hash,
                amount_msat,
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
        async fn invoice_state(&self, _ph: [u8; 32]) -> lightning_backend::Result<InvoiceState> {
            Ok(*self.state.lock().unwrap())
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
            tip: 700_000, // below timeout
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
            tip: 700_000,
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
