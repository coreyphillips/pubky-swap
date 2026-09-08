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
use swap_common::chain::{run_blocking, ChainWatcher};
use swap_common::fee_bump::{confirm_or_bump, SpendOutcome, SpendWatchConfig};
use swap_common::htlc::Preimage;
use swap_common::onchain::{
    build_claim_tx, estimate_spend_fee, fee_rate_cap, spend_vsize, ABSOLUTE_MAX_FEE_RATE_SAT_VB,
    CLAIM_FEE_TARGET_BLOCKS, DEFAULT_MAX_FEE_BPS,
};
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

/// Execute the client side of a reverse swap, returning the claim txid on success.
///
/// [`ChainWatcher`] calls are blocking, so they are wrapped in [`run_blocking`] to avoid stalling
/// the async runtime. `poll` is injected for testability.
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
        let found = run_blocking(|| chain.find_funding(&claim.htlc_spk, claim.onchain_amount_sat))
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
    let claim_vsize = spend_vsize(&claim.htlc_script, &claim.dest_spk, true);
    let build = |rate: u64| {
        build_claim_tx(
            funding.outpoint,
            claim.onchain_amount_sat,
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
    );
    let txid = match confirm_or_bump(
        chain.as_ref(),
        &claim.htlc_spk,
        funding.outpoint,
        &cfg,
        None,
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
                tx.txid()
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
        async fn pay_invoice(&self, _: &str, _: u64) -> lightning_backend::Result<PaymentResult> {
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
            Ok(lightning_backend::PaymentStatus::Unknown)
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

        let ln: Arc<dyn LightningBackend> = Arc::new(MockLn { preimage });
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

        execute_reverse_swap(ln, chain, claim, 10_000, 1, Duration::from_millis(0))
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
}
