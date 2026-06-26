//! Lightning node backend abstraction.
//!
//! Swaps need three Lightning capabilities:
//! - **Hold invoices** (reverse swaps): accept an incoming payment but defer settlement
//!   until we hold the preimage, so settlement is atomic with the on-chain claim.
//! - **Pay + extract preimage** (submarine swaps): pay the client's invoice and learn the
//!   preimage, which we then use to claim the client's on-chain HTLC.
//! - **Invoice state lookup**: drive the swap state machine off LN events.
//!
//! [`LndBackend`] is a stub today; the real implementation (tonic gRPC to LND's
//! `invoicesrpc` + `routerrpc`) is the roadmap's "LND backend" milestone. Core Lightning
//! can be added later as another [`LightningBackend`] impl without touching swap logic.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LightningError {
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("invoice not found")]
    InvoiceNotFound,
    #[error("payment failed: {0}")]
    PaymentFailed(String),
}

pub type Result<T> = std::result::Result<T, LightningError>;

/// Basic node identity / health.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub pubkey: String,
    pub alias: String,
    pub synced_to_chain: bool,
}

/// A created hold invoice (reverse swaps).
#[derive(Debug, Clone)]
pub struct HoldInvoice {
    pub bolt11: String,
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
}

/// Lifecycle of an invoice, as needed to drive a swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvoiceState {
    /// Created, not yet paid.
    Open,
    /// Payment received and held (hold invoice), awaiting preimage to settle.
    Accepted,
    /// Settled (preimage revealed).
    Settled,
    /// Cancelled / expired.
    Cancelled,
}

/// Result of paying a BOLT11 invoice.
#[derive(Debug, Clone)]
pub struct PaymentResult {
    /// The preimage learned from a successful payment — the atomic link to the on-chain leg.
    pub preimage: [u8; 32],
    pub fee_msat: u64,
}

/// Decoded essentials of a BOLT11 invoice.
#[derive(Debug, Clone)]
pub struct DecodedInvoice {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
}

#[async_trait]
pub trait LightningBackend: Send + Sync {
    /// Node identity / sync status.
    async fn node_info(&self) -> Result<NodeInfo>;

    /// Create a hold invoice locked to `payment_hash`. The incoming payment will be
    /// accepted but not settled until [`settle_hold_invoice`](LightningBackend::settle_hold_invoice).
    async fn create_hold_invoice(
        &self,
        payment_hash: [u8; 32],
        amount_msat: u64,
        expiry_secs: u64,
        memo: &str,
    ) -> Result<HoldInvoice>;

    /// Current state of an invoice identified by its payment hash.
    async fn invoice_state(&self, payment_hash: [u8; 32]) -> Result<InvoiceState>;

    /// Settle a held invoice by revealing the preimage (`sha256(preimage) == payment_hash`).
    async fn settle_hold_invoice(&self, preimage: [u8; 32]) -> Result<()>;

    /// Cancel an unsettled (hold) invoice.
    async fn cancel_hold_invoice(&self, payment_hash: [u8; 32]) -> Result<()>;

    /// Pay a BOLT11 invoice, returning the preimage on success.
    async fn pay_invoice(&self, bolt11: &str, max_fee_msat: u64) -> Result<PaymentResult>;

    /// Decode a BOLT11 invoice's payment hash and amount.
    async fn decode_invoice(&self, bolt11: &str) -> Result<DecodedInvoice>;
}

/// Connection configuration for an LND node (gRPC).
#[derive(Debug, Clone)]
pub struct LndConfig {
    /// Full gRPC URL of the LND node, e.g. `https://127.0.0.1:10009`.
    pub address: String,
    /// Path to LND's TLS certificate (`tls.cert`).
    pub tls_cert_path: String,
    /// Path to a macaroon with invoice + router permissions (e.g. `admin.macaroon`).
    pub macaroon_path: String,
}

/// A backend that implements no operations — used when no Lightning node is configured, or
/// when the `lnd` feature is disabled. Every call returns [`LightningError::NotImplemented`].
#[derive(Default)]
pub struct StubBackend;

impl StubBackend {
    pub fn new() -> Self {
        Self
    }
}

const STUB: &str =
    "no Lightning backend configured (build with --features lnd and provide LND credentials)";

#[async_trait]
impl LightningBackend for StubBackend {
    async fn node_info(&self) -> Result<NodeInfo> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn create_hold_invoice(
        &self,
        _payment_hash: [u8; 32],
        _amount_msat: u64,
        _expiry_secs: u64,
        _memo: &str,
    ) -> Result<HoldInvoice> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn invoice_state(&self, _payment_hash: [u8; 32]) -> Result<InvoiceState> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn settle_hold_invoice(&self, _preimage: [u8; 32]) -> Result<()> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn cancel_hold_invoice(&self, _payment_hash: [u8; 32]) -> Result<()> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn pay_invoice(&self, _bolt11: &str, _max_fee_msat: u64) -> Result<PaymentResult> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn decode_invoice(&self, _bolt11: &str) -> Result<DecodedInvoice> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
}

#[cfg(feature = "lnd")]
mod lnd;
#[cfg(feature = "lnd")]
pub use lnd::LndBackend;
