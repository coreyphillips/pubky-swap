//! Shared types for the pubky-swap marketplace.
//!
//! - [`messages`] — the wire protocol (offers, quotes, swap requests, status updates).
//! - [`swap`] — direction, network, and the lifecycle [`swap::SwapState`] machine.
//! - [`htlc`] — P2WSH HTLC script construction and preimage helpers.
//! - [`onchain`] — build & sign HTLC claim/refund transactions.
//! - [`fee_bump`] — replace-by-fee bumping for claim/refund spends.
//! - [`chain`] — chain observation (`ChainWatcher`; Electrum impl behind feature `electrum`).
//! - [`keys`] — key helpers.

pub mod chain;
pub mod error;
pub mod fee_bump;
pub mod htlc;
pub mod keys;
pub mod messages;
pub mod onchain;
pub mod swap;
pub mod wallet;

pub use error::{Result, SwapError};
pub use keys::{random_keypair, random_secret_key};
pub use messages::*;
pub use swap::{NetworkSpec, SwapDirection, SwapState};
