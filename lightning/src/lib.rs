//! Lightning node backend abstraction.
//!
//! Swaps need three Lightning capabilities:
//! - **Hold invoices** (reverse swaps): accept an incoming payment but defer settlement
//!   until we hold the preimage, so settlement is atomic with the on-chain claim.
//! - **Pay + extract preimage** (submarine swaps): pay the client's invoice and learn the
//!   preimage, which we then use to claim the client's on-chain HTLC.
//! - **Invoice state lookup**: drive the swap state machine off LN events.
//!
//! [`LndBackend`] (behind the `lnd` feature) implements this over tonic gRPC to LND's
//! `invoicesrpc` + `routerrpc`. A no-op [`StubBackend`] is used when no node is configured.
//! Core Lightning can be added later as another [`LightningBackend`] impl without touching
//! swap logic.

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
    /// The chain network the node reports it is on (`"mainnet"`/`"testnet"`/`"signet"`/
    /// `"regtest"`), used to guard against a network mismatch. `None` if the backend doesn't
    /// report one.
    pub chain_network: Option<String>,
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

/// What a node knows about an outbound payment.
///
/// This is the ground truth a resumed driver needs. Without it, "did I already pay this?" can
/// only be answered from our own persisted intent, which cannot distinguish "the payment was
/// never sent" from "it was sent and we crashed before recording it" -- and those want opposite
/// actions.
#[derive(Debug, Clone)]
pub enum PaymentStatus {
    /// The node has no record of this payment hash.
    Unknown,
    /// An attempt is in flight.
    InFlight,
    /// Settled, with the preimage.
    Succeeded(PaymentResult),
    /// Permanently failed, so paying again is safe.
    Failed(String),
}

/// Result of paying a BOLT11 invoice.
///
/// `Debug` is written by hand and redacts the preimage. The derived one printed it, and the
/// client formatted this whole struct into an error message, so a routine failure wrote the
/// secret linking both legs of a swap into the logs. Redacting it here makes that impossible to
/// reintroduce by accident at any call site.
#[derive(Clone)]
pub struct PaymentResult {
    /// The preimage learned from a successful payment: the atomic link to the on-chain leg.
    pub preimage: [u8; 32],
    pub fee_msat: u64,
}

impl std::fmt::Debug for PaymentResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentResult")
            .field("preimage", &"<redacted>")
            .field("fee_msat", &self.fee_msat)
            .finish()
    }
}

/// Decoded essentials of a BOLT11 invoice.
#[derive(Debug, Clone)]
pub struct DecodedInvoice {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    /// The invoice's `min_final_cltv_expiry` in blocks: how much timelock the payer must leave
    /// on the final hop. A swap's safety depends on this outliving the on-chain leg, so it is
    /// part of the decoded surface rather than something callers have to assume.
    pub min_final_cltv_expiry: u32,
    /// Whether the invoice carried an explicit amount. A zero-amount invoice is not a
    /// zero-value one; it means the payer chooses, which a swap must refuse.
    pub amount_is_explicit: bool,
    /// Unix seconds at which the invoice expires, or `0` when the backend does not say.
    ///
    /// A swap has to outlive its own Lightning leg: an invoice that expires before the on-chain
    /// side can complete leaves a client that has committed coins with nothing to settle against.
    /// The check for that existed and was fed a hard-coded zero, which is the value that means
    /// "unknown" and so disabled it.
    pub expires_at_unix: u64,
}

/// Everything needed to create a hold invoice for a reverse swap.
///
/// Grouped into a struct because the CLTV delta is not optional detail: it is the field that
/// keeps the Lightning leg alive past the on-chain refund height, and a positional argument list
/// makes it too easy to add a call site that forgets it.
#[derive(Debug, Clone)]
pub struct HoldInvoiceRequest {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub expiry_secs: u64,
    /// Minimum final CLTV expiry **delta**, in blocks, that the payer must extend.
    ///
    /// Must be non-zero. Left at zero, LND substitutes `--bitcoin.timelockdelta` (80 by
    /// default), which is far short of a 144-block on-chain timeout: the incoming HTLC would
    /// expire first, letting the payer reclaim its sats over Lightning and *then* claim the
    /// on-chain HTLC for free. See [`swap_common::timelock`] for the arithmetic.
    pub cltv_expiry_delta: u32,
    pub memo: String,
}

/// One incoming HTLC held against an invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedHtlc {
    pub amount_msat: u64,
    /// The block height at which this HTLC expires, as the node reports it.
    ///
    /// This is the **realised** value, not the delta that was requested. Verifying it is the
    /// point: a node that ignored, clamped, or defaulted the requested delta would otherwise
    /// leave the swap in exactly the unsafe configuration the delta exists to prevent.
    pub expiry_height: u32,
}

/// An invoice's state together with the HTLCs currently held against it.
#[derive(Debug, Clone)]
pub struct InvoiceStatus {
    pub state: InvoiceState,
    pub amount_paid_msat: u64,
    pub htlcs: Vec<AcceptedHtlc>,
}

impl InvoiceStatus {
    /// The earliest expiry among the held HTLCs: the height by which the whole payment must be
    /// resolved. `None` when nothing is held.
    pub fn earliest_htlc_expiry(&self) -> Option<u32> {
        self.htlcs.iter().map(|h| h.expiry_height).min()
    }
}

#[async_trait]
pub trait LightningBackend: Send + Sync {
    /// Node identity / sync status.
    async fn node_info(&self) -> Result<NodeInfo>;

    /// Create a hold invoice locked to `req.payment_hash`. The incoming payment will be
    /// accepted but not settled until [`settle_hold_invoice`](LightningBackend::settle_hold_invoice).
    ///
    /// Implementations must apply `req.cltv_expiry_delta` and must reject a zero delta rather
    /// than silently falling back to a node default.
    async fn create_hold_invoice(&self, req: HoldInvoiceRequest) -> Result<HoldInvoice>;

    /// Create a normal (auto-settling) invoice — the node generates the preimage and settles on
    /// payment. Used by the submarine-swap client: the provider pays this invoice (learning the
    /// preimage) and the client receives the Lightning funds. Returns the BOLT11 and its
    /// node-generated payment hash.
    async fn create_invoice(
        &self,
        amount_msat: u64,
        expiry_secs: u64,
        memo: &str,
    ) -> Result<HoldInvoice>;

    /// Full status of an invoice: its state plus the HTLCs currently held against it, with
    /// their realised expiry heights.
    async fn invoice_status(&self, payment_hash: [u8; 32]) -> Result<InvoiceStatus>;

    /// Current state of an invoice identified by its payment hash.
    ///
    /// A projection of [`invoice_status`](LightningBackend::invoice_status); it carries no
    /// safety-relevant information on its own, which is why the timelock checks read the full
    /// status instead.
    async fn invoice_state(&self, payment_hash: [u8; 32]) -> Result<InvoiceState> {
        Ok(self.invoice_status(payment_hash).await?.state)
    }

    /// Settle a held invoice by revealing the preimage (`sha256(preimage) == payment_hash`).
    async fn settle_hold_invoice(&self, preimage: [u8; 32]) -> Result<()>;

    /// Cancel an unsettled (hold) invoice.
    async fn cancel_hold_invoice(&self, payment_hash: [u8; 32]) -> Result<()>;

    /// Pay a BOLT11 invoice, returning the preimage on success.
    async fn pay_invoice(&self, bolt11: &str, max_fee_msat: u64) -> Result<PaymentResult>;

    /// What the node knows about an outbound payment for `payment_hash`.
    ///
    /// Consulted before paying, so a resumed driver never pays twice for one swap. Backends that
    /// cannot answer should return [`PaymentStatus::Unknown`], which callers treat as "do not
    /// assume it is safe to pay again".
    async fn payment_status(&self, payment_hash: [u8; 32]) -> Result<PaymentStatus>;

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
    async fn create_hold_invoice(&self, _req: HoldInvoiceRequest) -> Result<HoldInvoice> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn create_invoice(
        &self,
        _amount_msat: u64,
        _expiry_secs: u64,
        _memo: &str,
    ) -> Result<HoldInvoice> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn invoice_status(&self, _payment_hash: [u8; 32]) -> Result<InvoiceStatus> {
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
    async fn payment_status(&self, _payment_hash: [u8; 32]) -> Result<PaymentStatus> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
    async fn decode_invoice(&self, _bolt11: &str) -> Result<DecodedInvoice> {
        Err(LightningError::NotImplemented(STUB.into()))
    }
}

/// Finding an existing node's credentials on disk. Needs no `lnd` feature: it only looks at
/// the filesystem, so `doctor` can report on it in any build.
pub mod discover;

#[cfg(feature = "lnd")]
mod lnd;
#[cfg(feature = "lnd")]
pub use lnd::LndBackend;

#[cfg(feature = "lnd")]
mod lnd_wallet;
#[cfg(feature = "lnd")]
pub use lnd_wallet::LndWallet;

#[cfg(test)]
mod redaction_tests {
    use super::PaymentResult;

    /// The preimage links both legs of a swap. It used to be printed by the derived `Debug`, and
    /// the client formatted this whole struct into an error message, so a routine failure wrote
    /// the secret into the logs.
    #[test]
    fn payment_result_debug_does_not_contain_the_preimage() {
        let result = PaymentResult {
            preimage: [0xab; 32],
            fee_msat: 1_234,
        };
        let printed = format!("{result:?}");
        assert!(!printed.contains("ab"), "preimage leaked: {printed}");
        assert!(!printed.contains("171"), "preimage bytes leaked: {printed}");
        assert!(printed.contains("<redacted>"));
        // The useful part survives.
        assert!(printed.contains("1234"));
    }
}
