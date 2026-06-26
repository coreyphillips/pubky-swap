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

    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SwapError>;
