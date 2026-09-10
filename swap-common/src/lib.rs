//! Shared types for the pubky-swap marketplace.
//!
//! - [`messages`] — the wire protocol (offers, quotes, swap requests, status updates).
//! - [`swap`] — direction, network, and the lifecycle [`swap::SwapState`] machine.
//! - [`htlc`] — P2WSH HTLC script construction and preimage helpers.
//! - [`taproot`]: Boltz-compatible Bitcoin Taproot contracts and script-path spends.
//! - [`onchain`] — build & sign HTLC claim/refund transactions.
//! - [`fee_bump`] — replace-by-fee bumping for claim/refund spends.
//! - [`chain`] — chain observation (`ChainWatcher`; Electrum impl behind feature `electrum`).
//! - [`timelock`] — cross-leg timelock invariants (the ordering that makes a swap atomic).
//! - [`validate`] — client-side checks on a provider's quote, acceptance, and invoice.
//! - [`store`] — crash-safe persistence of in-flight swaps, shared by both sides.
//! - [`keys`] — key helpers.

pub mod chain;
pub mod error;
pub mod fee_bump;
pub mod htlc;
pub mod keys;
pub mod messages;
pub mod onchain;
pub mod reorg;
pub mod store;
pub mod swap;
pub mod taproot;
pub mod timelock;
pub mod validate;
pub mod wallet;

pub use error::{Result, SwapError};
pub use keys::{random_keypair, random_secret_key};
pub use messages::*;
pub use swap::{NetworkSpec, SwapDirection, SwapState};
