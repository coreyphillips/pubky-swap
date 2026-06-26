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
use lightning_backend::LightningBackend;
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::ChainWatcher;
use swap_common::fee_bump::{confirm_or_bump, MAX_FEE_BUMPS};
use swap_common::htlc::Preimage;
use swap_common::onchain::{build_claim_tx, estimate_spend_fee, CLAIM_FEE_TARGET_BLOCKS};
use swap_common::reorg::FINALITY_DEPTH;
use tokio::time::sleep;
use tracing::info;

/// Everything the client needs (from its own state + the provider's `SwapAccept`) to execute
/// a reverse swap.
pub struct ReverseClaim {
    /// HTLC redeem script (verify it matches what you expect before paying!).
    pub htlc_script: ScriptBuf,
    /// HTLC P2WSH scriptPubKey.
    pub htlc_spk: ScriptBuf,
    /// Amount the provider locks on-chain.
    pub onchain_amount_sat: u64,
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

/// Execute the client side of a reverse swap, returning the claim txid on success.
///
/// NOTE: [`ChainWatcher`] calls are blocking; a production caller should run this on a
/// blocking-friendly task. `poll` is injected for testability.
pub async fn execute_reverse_swap(
    ln: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    claim: ReverseClaim,
    max_routing_fee_msat: u64,
    required_confirmations: u32,
    poll: Duration,
) -> Result<Txid> {
    // 1. Start paying the hold invoice. It stays in-flight (held) until the provider settles
    //    it — which only happens after we claim on-chain and reveal the preimage.
    let pay_ln = ln.clone();
    let invoice = claim.invoice.clone();
    let pay_task =
        tokio::spawn(async move { pay_ln.pay_invoice(&invoice, max_routing_fee_msat).await });

    // 2. Wait for the provider to fund + confirm the on-chain HTLC.
    let funding = loop {
        let found = chain
            .find_funding(&claim.htlc_spk, claim.onchain_amount_sat)
            .map_err(|e| anyhow!("find_funding: {e}"))?;
        if let Some(u) = found {
            if u.confirmations >= required_confirmations {
                break u;
            }
        }
        // If the payment terminated before funding appeared, there's nothing to claim.
        if pay_task.is_finished() {
            let res = pay_task.await.map_err(|e| anyhow!("pay task join: {e}"))?;
            return Err(anyhow!(
                "invoice payment ended before the HTLC was funded: {res:?}"
            ));
        }
        sleep(poll).await;
    };
    info!("Client: provider HTLC funded; claiming with the preimage");

    // 3. Claim the HTLC, revealing the preimage on-chain — and keep it confirming under fee
    //    pressure (RBF), since it must land before the provider's refund timeout.
    let build = |rate: u64| {
        build_claim_tx(
            funding.outpoint,
            claim.onchain_amount_sat,
            &claim.htlc_script,
            claim.dest_spk.clone(),
            estimate_spend_fee(rate, true),
            claim.preimage,
            &claim.claim_key,
        )
    };
    let txid = confirm_or_bump(
        chain.as_ref(),
        &claim.htlc_spk,
        CLAIM_FEE_TARGET_BLOCKS,
        claim.fee_rate_sat_vb,
        poll,
        MAX_FEE_BUMPS,
        FINALITY_DEPTH,
        build,
    )
    .await
    .map_err(|e| anyhow!("claim broadcast/bump: {e}"))?;
    info!("Client: claim broadcast {txid}; awaiting hold-invoice settlement");

    // 4. The provider sees our claim, recovers the preimage, and settles the invoice — which
    //    completes our payment.
    let payment = pay_task
        .await
        .map_err(|e| anyhow!("pay task join: {e}"))?
        .map_err(|e| anyhow!("invoice payment failed: {e}"))?;
    info!(
        "Client: hold invoice settled (routing fee {} msat)",
        payment.fee_msat
    );

    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Network, OutPoint, Transaction, Txid as BTxid};
    use lightning_backend::{
        DecodedInvoice, HoldInvoice, InvoiceState, LightningError, NodeInfo, PaymentResult,
    };
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::{ChainWatcher, FundingUtxo};
    use swap_common::htlc::{
        build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash,
    };
    use swap_common::onchain::extract_preimage;
    use swap_common::random_keypair;

    const AMOUNT: u64 = 100_000;

    struct MockLn {
        preimage: [u8; 32],
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
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn settle_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn cancel_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn pay_invoice(&self, _: &str, _: u64) -> lightning_backend::Result<PaymentResult> {
            // Simulate the hold invoice eventually settling.
            Ok(PaymentResult {
                preimage: self.preimage,
                fee_msat: 0,
            })
        }
        async fn decode_invoice(&self, _: &str) -> lightning_backend::Result<DecodedInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
    }

    struct MockChain {
        funding: Option<FundingUtxo>,
        broadcasts: Mutex<Vec<Transaction>>,
    }
    impl ChainWatcher for MockChain {
        fn tip_height(&self) -> swap_common::Result<u32> {
            Ok(1000)
        }
        fn find_funding(
            &self,
            _: &bitcoin::Script,
            _: u64,
        ) -> swap_common::Result<Option<FundingUtxo>> {
            Ok(self.funding.clone())
        }
        fn find_spend(
            &self,
            _: &bitcoin::Script,
            _: &OutPoint,
        ) -> swap_common::Result<Option<Transaction>> {
            Ok(None)
        }
        fn broadcast(&self, tx: &Transaction) -> swap_common::Result<BTxid> {
            self.broadcasts.lock().unwrap().push(tx.clone());
            Ok(tx.txid())
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

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn { preimage });
        let mc = Arc::new(MockChain {
            funding: Some(FundingUtxo {
                outpoint,
                value_sat: AMOUNT,
                confirmations: 2,
            }),
            broadcasts: Mutex::new(Vec::new()),
        });
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
        };

        execute_reverse_swap(ln, chain, claim, 10_000, 1, Duration::from_millis(0))
            .await
            .unwrap();

        // A claim carrying the preimage was broadcast at the funding outpoint.
        let broadcasts = mc.broadcasts.lock().unwrap();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(
            extract_preimage(&broadcasts[0], &outpoint, &ph),
            Some(preimage)
        );
    }
}
