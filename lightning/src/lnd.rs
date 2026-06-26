//! Real LND backend over gRPC (feature `lnd`).
//!
//! Uses `fedimint-tonic-lnd` (generated LND protos over tonic). Hold invoices come from
//! `invoicesrpc`; payments and node info from `lnrpc`. Requires `protoc` at build time.

use crate::{
    DecodedInvoice, HoldInvoice, InvoiceState, LightningBackend, LightningError, LndConfig,
    NodeInfo, PaymentResult, Result,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

use fedimint_tonic_lnd::invoicesrpc::{AddHoldInvoiceRequest, CancelInvoiceMsg, SettleInvoiceMsg};
use fedimint_tonic_lnd::lnrpc::{GetInfoRequest, PayReqString, PaymentHash};
use fedimint_tonic_lnd::routerrpc::SendPaymentRequest;

/// LND node backend.
///
/// The aggregate client exposes `lightning()` / `invoices()` / `router()` as `&mut`
/// accessors, so it is guarded by a mutex; the underlying tonic channel is cheap to share.
pub struct LndBackend {
    client: Mutex<fedimint_tonic_lnd::Client>,
}

impl LndBackend {
    /// Connect to an LND node using its gRPC URL, TLS cert, and macaroon.
    pub async fn connect(config: LndConfig) -> Result<Self> {
        // rustls 0.23 (pulled in by the gRPC stack) needs a process-wide CryptoProvider.
        // Install the ring provider once; ignore the error if one is already set.
        use std::sync::Once;
        static CRYPTO_INIT: Once = Once::new();
        CRYPTO_INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let client = fedimint_tonic_lnd::connect(
            config.address.clone(),
            config.tls_cert_path.clone(),
            config.macaroon_path.clone(),
        )
        .await
        .map_err(|e| LightningError::Backend(format!("LND connect: {e}")))?;
        Ok(Self {
            client: Mutex::new(client),
        })
    }
}

fn to_32(bytes: &[u8], what: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| LightningError::Backend(format!("{what} is not 32 bytes")))
}

#[async_trait]
impl LightningBackend for LndBackend {
    async fn node_info(&self) -> Result<NodeInfo> {
        let mut client = self.client.lock().await;
        let resp = client
            .lightning()
            .get_info(GetInfoRequest {})
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        Ok(NodeInfo {
            pubkey: resp.identity_pubkey,
            alias: resp.alias,
            synced_to_chain: resp.synced_to_chain,
        })
    }

    async fn create_hold_invoice(
        &self,
        payment_hash: [u8; 32],
        amount_msat: u64,
        expiry_secs: u64,
        memo: &str,
    ) -> Result<HoldInvoice> {
        let mut client = self.client.lock().await;
        let resp = client
            .invoices()
            .add_hold_invoice(AddHoldInvoiceRequest {
                memo: memo.to_string(),
                hash: payment_hash.to_vec(),
                value_msat: amount_msat as i64,
                expiry: expiry_secs as i64,
                ..Default::default()
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        Ok(HoldInvoice {
            bolt11: resp.payment_request,
            payment_hash,
            amount_msat,
        })
    }

    async fn invoice_state(&self, payment_hash: [u8; 32]) -> Result<InvoiceState> {
        let mut client = self.client.lock().await;
        let resp = client
            .lightning()
            .lookup_invoice(PaymentHash {
                r_hash: payment_hash.to_vec(),
                ..Default::default()
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        // lnrpc.Invoice.InvoiceState: OPEN=0, SETTLED=1, CANCELED=2, ACCEPTED=3
        Ok(match resp.state {
            0 => InvoiceState::Open,
            1 => InvoiceState::Settled,
            2 => InvoiceState::Cancelled,
            3 => InvoiceState::Accepted,
            other => {
                return Err(LightningError::Backend(format!(
                    "unknown invoice state {other}"
                )))
            }
        })
    }

    async fn settle_hold_invoice(&self, preimage: [u8; 32]) -> Result<()> {
        let mut client = self.client.lock().await;
        client
            .invoices()
            .settle_invoice(SettleInvoiceMsg {
                preimage: preimage.to_vec(),
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?;
        Ok(())
    }

    async fn cancel_hold_invoice(&self, payment_hash: [u8; 32]) -> Result<()> {
        let mut client = self.client.lock().await;
        client
            .invoices()
            .cancel_invoice(CancelInvoiceMsg {
                payment_hash: payment_hash.to_vec(),
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?;
        Ok(())
    }

    async fn pay_invoice(&self, bolt11: &str, max_fee_msat: u64) -> Result<PaymentResult> {
        let mut client = self.client.lock().await;
        // routerrpc.SendPaymentV2 streams payment updates until a terminal status.
        let mut stream = client
            .router()
            .send_payment_v2(SendPaymentRequest {
                payment_request: bolt11.to_string(),
                // Generous: a reverse-swap hold invoice stays in-flight until the on-chain
                // claim reveals the preimage and the provider settles.
                timeout_seconds: 300,
                fee_limit_msat: max_fee_msat as i64,
                ..Default::default()
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();

        loop {
            let update = stream
                .message()
                .await
                .map_err(|s| LightningError::Backend(s.to_string()))?;
            let payment = match update {
                Some(p) => p,
                None => return Err(LightningError::PaymentFailed("payment stream ended".into())),
            };
            // lnrpc.Payment.PaymentStatus: UNKNOWN=0, IN_FLIGHT=1, SUCCEEDED=2, FAILED=3
            match payment.status {
                2 => {
                    let preimage_bytes = hex::decode(&payment.payment_preimage)
                        .map_err(|e| LightningError::Backend(format!("decode preimage: {e}")))?;
                    let preimage = to_32(&preimage_bytes, "preimage")?;
                    return Ok(PaymentResult {
                        preimage,
                        fee_msat: payment.fee_msat as u64,
                    });
                }
                3 => {
                    return Err(LightningError::PaymentFailed(format!(
                        "payment failed (reason {})",
                        payment.failure_reason
                    )))
                }
                _ => continue, // UNKNOWN / IN_FLIGHT: keep waiting for a terminal update
            }
        }
    }

    async fn decode_invoice(&self, bolt11: &str) -> Result<DecodedInvoice> {
        let mut client = self.client.lock().await;
        let resp = client
            .lightning()
            .decode_pay_req(PayReqString {
                pay_req: bolt11.to_string(),
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        let hash_bytes = hex::decode(&resp.payment_hash)
            .map_err(|e| LightningError::Backend(format!("decode payment_hash: {e}")))?;
        let payment_hash = to_32(&hash_bytes, "payment_hash")?;
        Ok(DecodedInvoice {
            payment_hash,
            amount_msat: resp.num_msat as u64,
        })
    }
}
