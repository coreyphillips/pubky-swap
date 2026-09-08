use thiserror::Error;

#[derive(Error, Debug)]
pub enum SwapError {
    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    #[error("amount {amount} outside offer range [{min}, {max}]")]
    AmountOutOfRange { amount: u64, min: u64, max: u64 },

    #[error("unsupported swap direction for this offer")]
    UnsupportedDirection,

    #[error("invalid public key: {0}")]
    InvalidPubkey(String),

    #[error("invalid preimage/hash: {0}")]
    InvalidPreimage(String),

    #[error("htlc script error: {0}")]
    Htlc(String),

    #[error("quote expired or unknown: {0}")]
    QuoteExpired(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A condition that may resolve on its own: the chain backend is unreachable, an RPC timed
    /// out, a wallet is mid-sync.
    ///
    /// The distinction is not cosmetic. A driver that treats every failure as terminal will
    /// discard a swap record on a momentary Electrum blip, and a funded HTLC with no record is a
    /// refund that never happens. Callers must retry a transient failure and must not drop state
    /// over one.
    #[error("transient: {0}")]
    Transient(String),

    /// A condition that will not resolve by retrying: a protocol violation, a broken invariant, a
    /// permanent Lightning failure.
    #[error("permanent: {0}")]
    Permanent(String),

    #[error("other: {0}")]
    Other(String),
}

impl SwapError {
    /// Whether retrying could plausibly succeed.
    ///
    /// `Other` is deliberately treated as **not** transient: an unclassified error should not
    /// silently buy itself an unbounded retry loop. Classify it explicitly to get one.
    pub fn is_transient(&self) -> bool {
        matches!(self, SwapError::Transient(_))
    }

    /// Wrap a backend failure as transient.
    pub fn transient(what: &str, e: impl std::fmt::Display) -> Self {
        SwapError::Transient(format!("{what}: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, SwapError>;
