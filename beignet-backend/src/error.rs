//! Errors from the beignet daemon, and how they map onto the swap engine's own.

use lightning_backend::LightningError;
use swap_common::SwapError;

/// A typed error the daemon returned in its response envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeignetApiError {
    pub http_status: u16,
    pub code: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BeignetError {
    /// The request never got an answer: connection refused, timed out, TLS failed.
    #[error("beignet transport: {0}")]
    Transport(String),
    /// An answer arrived that we could not read. Never silently defaulted: a response we cannot
    /// parse is a response we cannot act on.
    #[error("beignet decode: {0}")]
    Decode(String),
    /// The daemon said no, with a reason.
    #[error("beignet [{}] {} (HTTP {})", .0.code, .0.message, .0.http_status)]
    Api(BeignetApiError),
    /// Our own configuration is wrong.
    #[error("beignet config: {0}")]
    Config(String),
}

impl BeignetError {
    /// Whether retrying could plausibly succeed.
    ///
    /// Transport failures and the daemon's own "busy" answers are retryable. A typed refusal is
    /// not: repeating a request the daemon has already declined only delays finding that out.
    pub fn is_transient(&self) -> bool {
        match self {
            BeignetError::Transport(_) => true,
            BeignetError::Api(e) => matches!(e.http_status, 429 | 502 | 503 | 504),
            BeignetError::Decode(_) | BeignetError::Config(_) => false,
        }
    }

    pub fn code(&self) -> Option<&str> {
        match self {
            BeignetError::Api(e) => Some(&e.code),
            _ => None,
        }
    }
}

/// Map a beignet error onto the Lightning backend's error type.
///
/// The daemon's own code is kept in the message, prefixed, so an operator reading a log line can
/// look it up in beignet's documentation rather than guessing what we turned it into.
impl From<BeignetError> for LightningError {
    fn from(e: BeignetError) -> Self {
        let Some(code) = e.code() else {
            return LightningError::Backend(e.to_string());
        };
        let detail = e.to_string();
        match code {
            "NOT_FOUND" => LightningError::InvoiceNotFound,
            "PAYMENT_FAILED"
            | "PAYMENT_TIMEOUT"
            | "NO_ROUTE"
            | "INVOICE_EXPIRED"
            | "INSUFFICIENT_BALANCE"
            | "DUPLICATE_PAYMENT"
            | "SPENDING_LIMIT_EXCEEDED"
            | "SERVICE_DRAINING" => LightningError::PaymentFailed(detail),
            "UNAUTHORIZED" | "FORBIDDEN" | "MNEMONIC_REQUIRES_AUTH" => {
                LightningError::Backend(format!("beignet rejected our credentials: {detail}"))
            }
            _ => LightningError::Backend(detail),
        }
    }
}

/// Map a beignet error onto the swap engine's error type, preserving whether it is worth
/// retrying. That classification is what keeps a driver from discarding a swap record over a
/// momentary daemon restart.
impl From<BeignetError> for SwapError {
    fn from(e: BeignetError) -> Self {
        if e.is_transient() {
            SwapError::Transient(e.to_string())
        } else {
            SwapError::Permanent(e.to_string())
        }
    }
}
