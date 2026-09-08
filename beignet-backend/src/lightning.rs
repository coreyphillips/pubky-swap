//! [`LightningBackend`] over beignet's HTTP daemon.

use crate::error::BeignetError;
use crate::http::{BeignetHttp, Retry};
use crate::types::*;
use async_trait::async_trait;
use lightning_backend::{
    AcceptedHtlc, DecodedInvoice, HoldInvoice, HoldInvoiceRequest, InvoiceState, InvoiceStatus,
    LightningBackend, LightningError, NodeInfo, PaymentResult, PaymentStatus, Result,
};
use std::sync::Arc;
use tracing::{info, warn};

pub struct BeignetLightningBackend {
    http: Arc<BeignetHttp>,
}

impl BeignetLightningBackend {
    pub fn new(http: Arc<BeignetHttp>) -> Self {
        Self { http }
    }

    async fn held(&self, payment_hash: &str) -> Result<Option<HoldInvoiceInfo>> {
        let all: Vec<HoldInvoiceInfo> = self.http.get("/invoices/held").await.map_err(conv)?;
        Ok(all.into_iter().find(|h| h.payment_hash == payment_hash))
    }
}

fn conv(e: BeignetError) -> LightningError {
    e.into()
}

fn to_32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| LightningError::Backend(format!("decode {what}: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| LightningError::Backend(format!("{what} is not 32 bytes")))
}

#[async_trait]
impl LightningBackend for BeignetLightningBackend {
    async fn node_info(&self) -> Result<NodeInfo> {
        let info: NodeInfoResponse = self.http.get("/info").await.map_err(conv)?;
        // `/health` is auth-exempt and cheap; a daemon that cannot reach Electrum is not synced,
        // whatever `/info` says about its height.
        let health: std::result::Result<HealthResponse, _> = self.http.get("/health").await;
        let synced = match &health {
            Ok(h) => h.status.as_deref() != Some("syncing") && h.electrum_connected.unwrap_or(true),
            Err(e) => {
                warn!("beignet health check failed: {e}");
                false
            }
        };
        Ok(NodeInfo {
            pubkey: info.node_id,
            alias: info.alias.unwrap_or_default(),
            synced_to_chain: synced,
            // beignet reports mainnet/testnet/signet/regtest, the same strings the network guard
            // already understands.
            chain_network: Some(info.network),
        })
    }

    async fn create_hold_invoice(&self, req: HoldInvoiceRequest) -> Result<HoldInvoice> {
        if req.cltv_expiry_delta == 0 {
            return Err(LightningError::Backend(
                "refusing to create a hold invoice with a zero final CLTV delta".into(),
            ));
        }
        let hash_hex = hex::encode(req.payment_hash);

        // Reuse an invoice we already created for this hash. Creating one is not idempotent
        // upstream, so a lost response would otherwise mint a second invoice for the same swap.
        let bolt11 = match self.held(&hash_hex).await? {
            Some(existing) if existing.state == "OPEN" || existing.state == "ACCEPTED" => {
                match existing.bolt11 {
                    Some(b) => {
                        info!("reusing the existing hold invoice for {hash_hex}");
                        b
                    }
                    None => return Err(LightningError::Backend(
                        "beignet reports a held invoice for this hash but will not give us its \
                         bolt11; cannot proceed safely"
                            .into(),
                    )),
                }
            }
            _ => {
                let created: InvoiceInfo = self
                    .http
                    .post(
                        "/invoice/create-hold",
                        &CreateHoldInvoiceRequest {
                            payment_hash: hash_hex.clone(),
                            amount_msat: Msat(req.amount_msat),
                            description: req.memo.clone(),
                            expiry: req.expiry_secs,
                            min_final_cltv_expiry: Some(req.cltv_expiry_delta),
                        },
                        Retry::Safe,
                    )
                    .await
                    .map_err(conv)?;
                created.bolt11
            }
        };

        // Verify what we actually got rather than trusting what we asked for.
        //
        // beignet cannot set a hold invoice's final CLTV yet (beignet#744), so the delta above is
        // very likely ignored. Decoding is what turns that from a silent, fund-losing
        // misconfiguration into a refusal: a reverse swap is only safe while the Lightning leg
        // outlives the on-chain one.
        let decoded = self.decode_invoice(&bolt11).await?;
        if decoded.payment_hash != req.payment_hash {
            return Err(LightningError::Backend(
                "the hold invoice beignet returned is locked to a different payment hash".into(),
            ));
        }
        if decoded.amount_msat != req.amount_msat {
            return Err(LightningError::Backend(format!(
                "the hold invoice is for {} msat, not the {} msat we asked for",
                decoded.amount_msat, req.amount_msat
            )));
        }
        if decoded.min_final_cltv_expiry < req.cltv_expiry_delta {
            // Leave nothing behind: an invoice we will not use should not sit accepting payments.
            if let Err(e) = self.cancel_hold_invoice(req.payment_hash).await {
                warn!("could not cancel the unusable hold invoice: {e}");
            }
            return Err(LightningError::Backend(format!(
                "beignet issued a hold invoice with a {}-block final CLTV, but this swap needs \
                 at least {}. The Lightning leg would expire before the on-chain refund, which \
                 lets the payer take both legs. See beignet#744; until it lands, this backend \
                 cannot serve reverse swaps.",
                decoded.min_final_cltv_expiry, req.cltv_expiry_delta
            )));
        }

        Ok(HoldInvoice {
            bolt11,
            payment_hash: req.payment_hash,
            amount_msat: req.amount_msat,
        })
    }

    async fn create_invoice(
        &self,
        amount_msat: u64,
        expiry_secs: u64,
        memo: &str,
    ) -> Result<HoldInvoice> {
        if !amount_msat.is_multiple_of(1000) {
            return Err(LightningError::Backend(format!(
                "beignet issues invoices in whole satoshis; {amount_msat} msat is not one"
            )));
        }
        let created: InvoiceInfo = self
            .http
            .post(
                "/invoice/create",
                &CreateInvoiceRequest {
                    amount_sats: amount_msat / 1000,
                    description: memo.to_string(),
                    expiry_secs,
                    min_final_cltv_expiry: None,
                },
                Retry::Safe,
            )
            .await
            .map_err(conv)?;
        Ok(HoldInvoice {
            payment_hash: to_32(&created.payment_hash, "payment hash")?,
            bolt11: created.bolt11,
            amount_msat,
        })
    }

    async fn invoice_status(&self, payment_hash: [u8; 32]) -> Result<InvoiceStatus> {
        let hash_hex = hex::encode(payment_hash);

        // Two sources, because they hold different things. A hold invoice we created appears in
        // `/invoices/held`; a plain invoice the submarine client issued never does, and is only
        // visible as an incoming payment.
        if let Some(held) = self.held(&hash_hex).await? {
            let state = match held.state.as_str() {
                "OPEN" => InvoiceState::Open,
                "ACCEPTED" => InvoiceState::Accepted,
                "SETTLED" => InvoiceState::Settled,
                "CANCELLED" | "CANCELED" => InvoiceState::Cancelled,
                other => {
                    return Err(LightningError::Backend(format!(
                        "unknown hold invoice state {other}"
                    )))
                }
            };
            let amount_paid_msat = held.held_amount_msat.unwrap_or_default().0;
            // beignet does not report per-HTLC expiry heights, so there is nothing to hand the
            // timelock check. Reporting an empty list is the honest answer: the caller refuses to
            // fund rather than proceeding on an assumption. This is the same gap as beignet#744.
            return Ok(InvoiceStatus {
                state,
                amount_paid_msat,
                htlcs: Vec::<AcceptedHtlc>::new(),
            });
        }

        let payment: std::result::Result<PaymentInfo, _> = self
            .http
            .get(&format!("/payment?paymentHash={hash_hex}"))
            .await;
        match payment {
            Ok(p) => Ok(InvoiceStatus {
                state: match p.status.as_str() {
                    "COMPLETED" => InvoiceState::Settled,
                    "PENDING" => InvoiceState::Open,
                    _ => InvoiceState::Cancelled,
                },
                amount_paid_msat: 0,
                htlcs: Vec::new(),
            }),
            Err(e) if e.code() == Some("NOT_FOUND") => Err(LightningError::InvoiceNotFound),
            Err(e) => Err(conv(e)),
        }
    }

    async fn settle_hold_invoice(&self, preimage: [u8; 32]) -> Result<()> {
        let body = serde_json::json!({ "preimage": hex::encode(preimage) });
        match self
            .http
            .post::<_, serde_json::Value>("/invoice/settle-hold", &body, Retry::Safe)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.code() == Some("NOT_FOUND") => {
                // A settle that fails because it already happened is success. This is the retried
                // call after a lost response, and failing it would fail a completed swap.
                let hash = hex::encode(swap_common::htlc::payment_hash(&preimage));
                match self.held(&hash).await? {
                    Some(h) if h.state == "SETTLED" => Ok(()),
                    _ => Err(conv(e)),
                }
            }
            Err(e) => Err(conv(e)),
        }
    }

    async fn cancel_hold_invoice(&self, payment_hash: [u8; 32]) -> Result<()> {
        let body = serde_json::json!({ "paymentHash": hex::encode(payment_hash) });
        match self
            .http
            .post::<_, serde_json::Value>("/invoice/cancel-hold", &body, Retry::Safe)
            .await
        {
            Ok(_) => Ok(()),
            // Already gone is the outcome we wanted.
            Err(e) if e.code() == Some("NOT_FOUND") => Ok(()),
            Err(e) => Err(conv(e)),
        }
    }

    async fn pay_invoice(&self, bolt11: &str, max_fee_msat: u64) -> Result<PaymentResult> {
        let decoded = self.decode_invoice(bolt11).await?;
        if !decoded.amount_is_explicit {
            return Err(LightningError::PaymentFailed(
                "the invoice carries no amount; paying it would let the payee choose".into(),
            ));
        }
        let request = PayInvoiceRequest {
            bolt11: bolt11.to_string(),
            timeout_ms: 300_000,
            // Round up: a sub-satoshi budget rounded down becomes zero, which forbids all
            // routing fees and fails every multi-hop payment. The overspend is under a satoshi.
            max_fee_sats: max_fee_msat.div_ceil(1000),
        };

        let payment: PaymentInfo = match self
            .http
            .post_slow("/invoice/pay", &request, Retry::Never)
            .await
        {
            Ok(p) => p,
            Err(e) if e.is_transient() => {
                // The payment may well be in flight. Reporting failure here would make the
                // caller abandon a swap it has possibly already paid for, so ask the node.
                warn!("beignet payment call failed transiently ({e}); checking its status");
                return match self.payment_status(decoded.payment_hash).await? {
                    PaymentStatus::Succeeded(result) => Ok(result),
                    other => Err(LightningError::PaymentFailed(format!(
                        "the payment call failed ({e}) and the node reports {other:?}"
                    ))),
                };
            }
            Err(e) => return Err(conv(e)),
        };
        payment_result(&payment, self).await
    }

    async fn payment_status(&self, payment_hash: [u8; 32]) -> Result<PaymentStatus> {
        let hash_hex = hex::encode(payment_hash);
        let payment: PaymentInfo = match self
            .http
            .get(&format!("/payment?paymentHash={hash_hex}"))
            .await
        {
            Ok(p) => p,
            Err(e) if e.code() == Some("NOT_FOUND") => return Ok(PaymentStatus::Unknown),
            Err(e) => return Err(conv(e)),
        };
        Ok(match payment.status.as_str() {
            "COMPLETED" => PaymentStatus::Succeeded(payment_result(&payment, self).await?),
            "PENDING" => PaymentStatus::InFlight,
            "FAILED" => PaymentStatus::Failed(
                payment
                    .failure_reason
                    .unwrap_or_else(|| "no reason given".into()),
            ),
            _ => PaymentStatus::Unknown,
        })
    }

    async fn decode_invoice(&self, bolt11: &str) -> Result<DecodedInvoice> {
        let body = serde_json::json!({ "bolt11": bolt11 });
        let decoded: DecodedInvoiceResponse = self
            .http
            .post("/invoice/decode", &body, Retry::Safe)
            .await
            .map_err(conv)?;
        let amount_sats = decoded.amount_sats.unwrap_or(0);
        Ok(DecodedInvoice {
            payment_hash: to_32(&decoded.payment_hash, "payment hash")?,
            amount_msat: amount_sats.saturating_mul(1000),
            min_final_cltv_expiry: decoded.min_final_cltv_expiry.unwrap_or(0),
            amount_is_explicit: amount_sats > 0,
        })
    }
}

/// Turn a settled payment into a result, recovering the preimage from the proof route when the
/// payment record does not carry it.
async fn payment_result(
    payment: &PaymentInfo,
    backend: &BeignetLightningBackend,
) -> Result<PaymentResult> {
    if payment.status != "COMPLETED" {
        return Err(LightningError::PaymentFailed(
            payment
                .failure_reason
                .clone()
                .unwrap_or_else(|| format!("payment status {}", payment.status)),
        ));
    }
    let preimage_hex = match &payment.preimage {
        Some(p) if !p.is_empty() => p.clone(),
        _ => {
            let proof: PaymentProof = backend
                .http
                .get(&format!(
                    "/payment/proof?paymentHash={}",
                    payment.payment_hash
                ))
                .await
                .map_err(conv)?;
            proof.preimage
        }
    };
    Ok(PaymentResult {
        preimage: to_32(&preimage_hex, "preimage")?,
        // beignet reports fees in whole satoshis.
        fee_msat: payment.fee_sats.unwrap_or(0).saturating_mul(1000),
    })
}
