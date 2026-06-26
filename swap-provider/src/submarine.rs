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
use bitcoin::{Network, OutPoint, PublicKey, ScriptBuf};
use lightning_backend::LightningBackend;
use std::time::Duration;
use swap_common::chain::ChainWatcher;
use swap_common::htlc::{build_htlc_script, htlc_p2wsh_address, payment_hash, PaymentHash};
use swap_common::onchain::{
    build_claim_tx, estimate_spend_fee, extract_preimage, resolve_fee_rate, CLAIM_FEE_TARGET_BLOCKS,
};
use swap_common::SwapState;
use tokio::time::sleep;
use tracing::{info, warn};

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
) -> Result<SubmarineSwap> {
    let decoded = ln
        .decode_invoice(invoice)
        .await
        .map_err(|e| anyhow!("decode invoice: {e}"))?;
    let payment_hash = decoded.payment_hash;
    let invoice_amount_sat = decoded.amount_msat / 1000;
    let onchain_amount_sat = invoice_amount_sat + provider_fee_sat;

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
    })
}

/// Drive a submarine swap to a terminal [`SwapState`].
///
/// NOTE: [`ChainWatcher`] calls are blocking; a production caller should run this on a
/// blocking-friendly task. `poll` is injected for testability.
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
    progress: &dyn ProgressSink,
) -> Result<SwapState> {
    // 1. Establish the funding outpoint. On a fresh start, wait for the client to fund the HTLC
    //    (give up at timeout — nothing at risk yet). On resume, adopt the known outpoint, and if
    //    we already claimed before the crash, finish immediately.
    let funding_outpoint = match resume_funding {
        Some(op) => {
            if let Some(spend) = chain.find_spend(&swap.htlc_spk, &op)? {
                if extract_preimage(&spend, &op, &swap.payment_hash).is_some() {
                    info!("Submarine swap: already claimed before restart");
                    return Ok(SwapState::Claimed);
                }
            }
            op
        }
        None => loop {
            if let Some(utxo) = chain.find_funding(&swap.htlc_spk, swap.onchain_amount_sat)? {
                if utxo.confirmations >= required_confirmations {
                    progress.funded(utxo.outpoint);
                    break utxo.outpoint;
                }
            }
            if chain.tip_height()? >= swap.timeout_height {
                return Ok(SwapState::Expired);
            }
            sleep(poll).await;
        },
    };
    info!("Submarine swap: HTLC funding confirmed; paying the Lightning invoice");

    // 2. Pay the invoice to learn the preimage. A failure costs nothing on-chain — the
    //    client simply refunds after the timeout.
    let payment = match ln
        .pay_invoice(&swap.invoice, swap.max_routing_fee_msat)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            warn!("Submarine swap: invoice payment failed: {e}");
            return Ok(SwapState::Failed(format!("invoice payment failed: {e}")));
        }
    };

    // Defensive: the preimage from the payment must match the HTLC's hashlock.
    if payment_hash(&payment.preimage) != swap.payment_hash {
        return Ok(SwapState::Failed(
            "paid invoice preimage does not match HTLC hashlock".into(),
        ));
    }

    // 3. Claim the on-chain HTLC with the preimage. Prefer a live fee estimate (the claim
    //    races the client's refund timeout); never go below the configured floor.
    let est = chain
        .estimate_fee_rate(CLAIM_FEE_TARGET_BLOCKS)
        .unwrap_or(None);
    let fee = estimate_spend_fee(resolve_fee_rate(est, swap.fee_rate_sat_vb), true);
    let claim_tx = build_claim_tx(
        funding_outpoint,
        swap.onchain_amount_sat,
        &swap.htlc_script,
        wallet.receive_destination(),
        fee,
        payment.preimage,
        &swap.claim_key,
    )
    .map_err(|e| anyhow!("build claim: {e}"))?;
    chain.broadcast(&claim_tx)?;
    info!("Submarine swap: invoice paid and on-chain HTLC claimed");
    Ok(SwapState::Claimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reverse::OnchainWallet;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{OutPoint, Transaction, Txid};
    use lightning_backend::{
        DecodedInvoice, HoldInvoice, InvoiceState, LightningError, NodeInfo, PaymentResult,
    };
    use std::str::FromStr;
    use std::sync::Mutex;
    use swap_common::chain::{ChainWatcher, FundingUtxo};
    use swap_common::htlc::{generate_preimage, payment_hash};
    use swap_common::onchain::extract_preimage;
    use swap_common::random_keypair;

    const INVOICE_SAT: u64 = 100_000;
    const FEE_SAT: u64 = 1_000;
    const ONCHAIN_SAT: u64 = INVOICE_SAT + FEE_SAT;
    const TIMEOUT: u32 = 800_000;

    // Mock LN that decodes to a fixed payment hash and (optionally) pays back a preimage.
    struct MockLn {
        payment_hash: [u8; 32],
        pay_preimage: Option<[u8; 32]>, // None => payment fails
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
            _ph: [u8; 32],
            _amt: u64,
            _e: u64,
            _m: &str,
        ) -> lightning_backend::Result<HoldInvoice> {
            Err(LightningError::NotImplemented("mock".into()))
        }
        async fn invoice_state(&self, _ph: [u8; 32]) -> lightning_backend::Result<InvoiceState> {
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
            match self.pay_preimage {
                Some(preimage) => Ok(PaymentResult {
                    preimage,
                    fee_msat: 0,
                }),
                None => Err(LightningError::PaymentFailed("no route".into())),
            }
        }
        async fn decode_invoice(&self, _bolt11: &str) -> lightning_backend::Result<DecodedInvoice> {
            Ok(DecodedInvoice {
                payment_hash: self.payment_hash,
                amount_msat: INVOICE_SAT * 1000,
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
        fn fund_htlc(&self, _spk: &ScriptBuf, _amount_sat: u64) -> Result<OutPoint> {
            Err(anyhow!("provider does not fund in a submarine swap"))
        }
        fn receive_destination(&self) -> ScriptBuf {
            self.spk.clone()
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
        )
        .await
        .unwrap();
        (swap, ln.payment_hash)
    }

    #[tokio::test]
    async fn submarine_swap_happy_path_pays_and_claims() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn {
            payment_hash: ph,
            pay_preimage: Some(preimage),
        };
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain {
            tip: 700_000,
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
        let ln = MockLn {
            payment_hash: ph,
            pay_preimage: None, // payment fails
        };
        let (swap, _) = make_swap(&ln).await;

        let chain = MockChain {
            tip: 700_000,
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

    #[tokio::test]
    async fn submarine_swap_expires_without_funding() {
        let preimage = generate_preimage();
        let ph = payment_hash(&preimage);
        let ln = MockLn {
            payment_hash: ph,
            pay_preimage: Some(preimage),
        };
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
            &(),
        )
        .await
        .unwrap();

        assert_eq!(state, SwapState::Expired);
        assert!(chain.broadcasts.lock().unwrap().is_empty());
    }
}
