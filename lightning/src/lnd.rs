//! Real LND backend over gRPC (feature `lnd`).
//!
//! Uses `fedimint-tonic-lnd` (generated LND protos over tonic). Hold invoices come from
//! `invoicesrpc`; payments and node info from `lnrpc`. Requires `protoc` at build time.

use crate::{
    AcceptedHtlc, DecodedInvoice, HoldInvoice, HoldInvoiceRequest, InvoiceState, InvoiceStatus,
    LightningBackend, LightningError, LndConfig, NodeInfo, PaymentResult, PaymentStatus, Result,
};
use async_trait::async_trait;
use tokio::sync::Mutex;

use fedimint_tonic_lnd::invoicesrpc::{AddHoldInvoiceRequest, CancelInvoiceMsg, SettleInvoiceMsg};
use fedimint_tonic_lnd::lnrpc::{GetInfoRequest, NewAddressRequest, PayReqString, PaymentHash};
use fedimint_tonic_lnd::routerrpc::{SendPaymentRequest, TrackPaymentRequest};
use fedimint_tonic_lnd::signrpc::TxOut;
use fedimint_tonic_lnd::walletrpc::SendOutputsRequest;

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

    /// A fresh on-chain receive address (P2WPKH) from LND's wallet. Returned as a string; the
    /// caller parses it for the node's network.
    pub async fn new_address(&self) -> Result<String> {
        let mut client = self.client.lock().await;
        let resp = client
            .lightning()
            .new_address(NewAddressRequest {
                r#type: 0, // WITNESS_PUBKEY_HASH
                account: String::new(),
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        Ok(resp.address)
    }

    /// LND's own fee estimate for `conf_target` blocks, in sat per 1000 weight units.
    ///
    /// `None` when the node cannot say (regtest, or an unsynced fee estimator), which callers
    /// treat as "use the configured floor" rather than as zero.
    pub async fn estimate_fee_sat_per_kw(&self, conf_target: i32) -> Result<Option<i64>> {
        use fedimint_tonic_lnd::walletrpc::EstimateFeeRequest;
        let mut client = self.client.lock().await;
        let resp = client
            .wallet()
            .estimate_fee(EstimateFeeRequest { conf_target })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        Ok((resp.sat_per_kw > 0).then_some(resp.sat_per_kw))
    }

    /// Bump an unconfirmed transaction's fee, using CPFP when the output is ours.
    ///
    /// `walletrpc.BumpFee` is what makes CPFP available to an `--wallet lnd` provider at all: the
    /// claim and refund transactions are built and signed by the swap engine, not by LND, so LND
    /// cannot replace them. It can spend their output at a high fee and pull them in.
    pub async fn bump_fee(&self, txid: &str, vout: u32, sat_per_vbyte: u64) -> Result<()> {
        use fedimint_tonic_lnd::lnrpc::OutPoint as LndOutPoint;
        use fedimint_tonic_lnd::walletrpc::BumpFeeRequest;
        let mut client = self.client.lock().await;
        client
            .wallet()
            .bump_fee(BumpFeeRequest {
                outpoint: Some(LndOutPoint {
                    txid_str: txid.to_string(),
                    output_index: vout,
                    ..Default::default()
                }),
                sat_per_vbyte,
                ..Default::default()
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?;
        Ok(())
    }

    /// Send `amount_sat` to `pk_script` from LND's on-chain wallet at `sat_per_kw`, returning the
    /// raw funding transaction (the caller locates the funding output). Requires a macaroon with
    /// on-chain write permission.
    pub async fn send_outputs(
        &self,
        pk_script: Vec<u8>,
        amount_sat: i64,
        sat_per_kw: i64,
    ) -> Result<Vec<u8>> {
        let mut client = self.client.lock().await;
        let resp = client
            .wallet()
            .send_outputs(SendOutputsRequest {
                sat_per_kw,
                outputs: vec![TxOut {
                    value: amount_sat,
                    pk_script,
                }],
                label: "pubky-swap htlc funding".to_string(),
                min_confs: 1,
                spend_unconfirmed: false,
                coin_selection_strategy: 0,
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        Ok(resp.raw_tx)
    }
}

/// Narrow a `u64` to the `i64` LND's protobufs use, refusing rather than wrapping into a
/// negative value that the node would interpret as something else entirely.
fn to_i64(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| LightningError::Backend(format!("{what} {value} does not fit in i64")))
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
            // LND reports each active chain's network ("mainnet"/"testnet"/"regtest"/...).
            chain_network: resp.chains.first().map(|c| c.network.clone()),
        })
    }

    async fn create_hold_invoice(&self, req: HoldInvoiceRequest) -> Result<HoldInvoice> {
        // A zero delta makes LND substitute `--bitcoin.timelockdelta` (80 by default), which is
        // shorter than any sensible on-chain timeout. Refusing here keeps the failure at swap
        // setup rather than after a client's payment is already held.
        if req.cltv_expiry_delta == 0 {
            return Err(LightningError::Backend(
                "refusing to create a hold invoice with a zero final CLTV delta: LND would                  substitute its own default, which is shorter than the on-chain timeout"
                    .into(),
            ));
        }
        let mut client = self.client.lock().await;
        let resp = client
            .invoices()
            .add_hold_invoice(AddHoldInvoiceRequest {
                memo: req.memo.clone(),
                hash: req.payment_hash.to_vec(),
                value_msat: to_i64(req.amount_msat, "invoice amount_msat")?,
                expiry: to_i64(req.expiry_secs, "invoice expiry_secs")?,
                cltv_expiry: u64::from(req.cltv_expiry_delta),
                ..Default::default()
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        Ok(HoldInvoice {
            bolt11: resp.payment_request,
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
        let mut client = self.client.lock().await;
        let resp = client
            .lightning()
            .add_invoice(fedimint_tonic_lnd::lnrpc::Invoice {
                memo: memo.to_string(),
                value_msat: to_i64(amount_msat, "invoice amount_msat")?,
                expiry: to_i64(expiry_secs, "invoice expiry_secs")?,
                ..Default::default()
            })
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
            .into_inner();
        // LND returns the node-generated payment hash in `r_hash`.
        let payment_hash = to_32(&resp.r_hash, "invoice r_hash")?;
        Ok(HoldInvoice {
            bolt11: resp.payment_request,
            payment_hash,
            amount_msat,
        })
    }

    async fn invoice_status(&self, payment_hash: [u8; 32]) -> Result<InvoiceStatus> {
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
        let state = match resp.state {
            0 => InvoiceState::Open,
            1 => InvoiceState::Settled,
            2 => InvoiceState::Cancelled,
            3 => InvoiceState::Accepted,
            other => {
                return Err(LightningError::Backend(format!(
                    "unknown invoice state {other}"
                )))
            }
        };
        // Only HTLCs still held count. lnrpc.InvoiceHTLC.InvoiceHTLCState: ACCEPTED=0,
        // SETTLED=1, CANCELED=2 — a settled or cancelled HTLC no longer bounds our deadline.
        let htlcs = resp
            .htlcs
            .iter()
            .filter(|h| h.state == 0)
            .map(|h| AcceptedHtlc {
                amount_msat: h.amt_msat,
                // `expiry_height` is a signed field. A value we cannot read becomes 0,
                // which fails the timelock check closed rather than open.
                expiry_height: u32::try_from(h.expiry_height).unwrap_or(0),
            })
            .collect();
        Ok(InvoiceStatus {
            state,
            amount_paid_msat: u64::try_from(resp.amt_paid_msat).unwrap_or(0),
            htlcs,
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
                fee_limit_msat: to_i64(max_fee_msat, "max_fee_msat")?,
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
                        // A negative fee is nonsense; clamping to 0 keeps it from becoming a
                        // near-u64::MAX value that would poison any accounting downstream.
                        fee_msat: u64::try_from(payment.fee_msat).unwrap_or(0),
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

    async fn payment_status(&self, payment_hash: [u8; 32]) -> Result<PaymentStatus> {
        let mut client = self.client.lock().await;
        let mut stream = match client
            .router()
            .track_payment_v2(TrackPaymentRequest {
                payment_hash: payment_hash.to_vec(),
                no_inflight_updates: true,
            })
            .await
        {
            Ok(s) => s.into_inner(),
            // LND answers NotFound when it has never seen the hash.
            Err(s) if s.code() == fedimint_tonic_lnd::tonic::Code::NotFound => {
                return Ok(PaymentStatus::Unknown)
            }
            Err(s) => return Err(LightningError::Backend(s.to_string())),
        };
        let payment = match stream
            .message()
            .await
            .map_err(|s| LightningError::Backend(s.to_string()))?
        {
            Some(p) => p,
            None => return Ok(PaymentStatus::Unknown),
        };
        // lnrpc.Payment.PaymentStatus: UNKNOWN=0, IN_FLIGHT=1, SUCCEEDED=2, FAILED=3
        Ok(match payment.status {
            2 => {
                let bytes = hex::decode(&payment.payment_preimage)
                    .map_err(|e| LightningError::Backend(format!("decode preimage: {e}")))?;
                PaymentStatus::Succeeded(PaymentResult {
                    preimage: to_32(&bytes, "preimage")?,
                    fee_msat: u64::try_from(payment.fee_msat).unwrap_or(0),
                })
            }
            3 => PaymentStatus::Failed(format!("reason {}", payment.failure_reason)),
            1 => PaymentStatus::InFlight,
            _ => PaymentStatus::Unknown,
        })
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
        // `num_msat` is a signed field. A negative value cast with `as u64` becomes an enormous
        // amount, which downstream would treat as a colossal swap; reject it instead.
        let amount_msat = u64::try_from(resp.num_msat).map_err(|_| {
            LightningError::Backend(format!(
                "invoice reports a negative amount {}",
                resp.num_msat
            ))
        })?;
        let min_final_cltv_expiry = u32::try_from(resp.cltv_expiry).map_err(|_| {
            LightningError::Backend(format!(
                "invoice reports an out-of-range final CLTV expiry {}",
                resp.cltv_expiry
            ))
        })?;
        Ok(DecodedInvoice {
            payment_hash,
            amount_msat,
            min_final_cltv_expiry,
            // LND reports 0 for an amountless invoice, where the payer chooses the amount.
            amount_is_explicit: resp.num_msat > 0,
        })
    }
}
