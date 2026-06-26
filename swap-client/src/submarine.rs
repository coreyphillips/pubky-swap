//! Client-side execution of a submarine swap (on-chain → Lightning).
//!
//! After negotiation, the client holds a Lightning invoice it issued (the provider will pay it),
//! an HTLC refund key, and the provider's HTLC details. Execution: fund the HTLC on-chain, then
//! wait. When the provider pays the invoice — settling it and learning the preimage — the client
//! has received its Lightning funds and the swap is done. If the provider never pays before the
//! timeout, the client refunds the HTLC on-chain.

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::SecretKey;
use bitcoin::ScriptBuf;
use lightning_backend::{InvoiceState, LightningBackend};
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::ChainWatcher;
use swap_common::fee_bump::{confirm_or_bump, MAX_FEE_BUMPS};
use swap_common::htlc::PaymentHash;
use swap_common::onchain::{build_refund_tx, estimate_spend_fee, REFUND_FEE_TARGET_BLOCKS};
use swap_common::reorg::FINALITY_DEPTH;
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

/// Execute the client side of a submarine swap, returning the terminal [`SwapState`]
/// (`Claimed` once the provider settles the invoice, or `Refunded` on timeout).
pub async fn execute_submarine_swap(
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    wallet: Arc<dyn OnchainWallet>,
    funding: SubmarineFunding,
    poll: Duration,
) -> Result<SwapState> {
    // 1. Fund the HTLC on-chain.
    let outpoint = wallet
        .fund_htlc(&funding.htlc_spk, funding.onchain_amount_sat)
        .map_err(|e| anyhow!("fund HTLC: {e}"))?;
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

        if chain.tip_height().map_err(|e| anyhow!("tip height: {e}"))? >= funding.timeout_height {
            // If the provider already claimed the HTLC, the preimage is public and our invoice
            // will settle — don't refund (the refund would just lose to their claim).
            if chain
                .find_spend(&funding.htlc_spk, &outpoint)
                .map_err(|e| anyhow!("find spend: {e}"))?
                .is_some()
            {
                info!("Submarine client: HTLC already claimed by provider; awaiting settlement");
                return Ok(SwapState::Claimed);
            }

            warn!("Submarine client: timeout reached without settlement; refunding HTLC");
            let dest = wallet.receive_destination();
            let build = |rate: u64| {
                build_refund_tx(
                    outpoint,
                    funding.onchain_amount_sat,
                    &funding.htlc_script,
                    dest.clone(),
                    estimate_spend_fee(rate, false),
                    funding.timeout_height,
                    &funding.refund_key,
                )
            };
            confirm_or_bump(
                chain.as_ref(),
                &funding.htlc_spk,
                REFUND_FEE_TARGET_BLOCKS,
                funding.fee_rate_sat_vb,
                poll,
                MAX_FEE_BUMPS,
                FINALITY_DEPTH,
                build,
            )
            .await
            .map_err(|e| anyhow!("refund broadcast/bump: {e}"))?;
            return Ok(SwapState::Refunded);
        }
        sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{OutPoint, Transaction, Txid};
    use lightning_backend::{DecodedInvoice, HoldInvoice, LightningError, NodeInfo, PaymentResult};
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::{ChainWatcher, FundingUtxo};
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
            _: [u8; 32],
            _: u64,
            _: u64,
            _: &str,
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
        async fn invoice_state(&self, _: [u8; 32]) -> lightning_backend::Result<InvoiceState> {
            Ok(self.state)
        }
        async fn settle_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn cancel_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn pay_invoice(&self, _: &str, _: u64) -> lightning_backend::Result<PaymentResult> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn decode_invoice(&self, _: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
    }

    struct MockChain {
        tip: u32,
        spend: Option<Transaction>,
        broadcasts: Mutex<Vec<Transaction>>,
    }
    impl ChainWatcher for MockChain {
        fn tip_height(&self) -> swap_common::Result<u32> {
            Ok(self.tip)
        }
        fn find_funding(
            &self,
            _: &bitcoin::Script,
            _: u64,
        ) -> swap_common::Result<Option<FundingUtxo>> {
            Ok(None)
        }
        fn find_spend(
            &self,
            _: &bitcoin::Script,
            _: &OutPoint,
        ) -> swap_common::Result<Option<Transaction>> {
            Ok(self.spend.clone())
        }
        fn broadcast(&self, tx: &Transaction) -> swap_common::Result<Txid> {
            self.broadcasts.lock().unwrap().push(tx.clone());
            Ok(tx.txid())
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
        let chain: Arc<dyn ChainWatcher> = Arc::new(MockChain {
            tip: 100,
            spend: None,
            broadcasts: Mutex::new(Vec::new()),
        });
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
        let chain_mock = Arc::new(MockChain {
            tip: TIMEOUT, // at timeout, HTLC unspent
            spend: None,
            broadcasts: Mutex::new(Vec::new()),
        });
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
        )
        .await
        .unwrap();
        assert_eq!(state, SwapState::Refunded);
        assert_eq!(
            chain_mock.broadcasts.lock().unwrap().len(),
            1,
            "a refund tx must be broadcast"
        );
    }
}
