//! A [beignet] daemon as a swap backend: both the Lightning side and the on-chain wallet.
//!
//! beignet runs a self-custodial Bitcoin and Lightning node behind a small authenticated HTTP
//! API, which turns out to cover everything a swap needs: hold invoices with caller-supplied
//! payment hashes, settle and cancel, paying an invoice and getting the preimage back, sending an
//! exact amount on chain, and fee-bumping an unconfirmed transaction. That makes it an
//! alternative to LND for an operator who would rather not run one.
//!
//! What it does **not** replace is chain observation. beignet reaches Bitcoin through Electrum
//! and exposes no raw chain API, so the swap engine keeps its own `ChainWatcher` pointed at the
//! same Electrum server. The split is natural: beignet holds keys and moves money, the watcher
//! reads the chain.
//!
//! # One gap worth knowing about
//!
//! `POST /invoice/create-hold` cannot set the invoice's final CLTV expiry, while the sibling
//! `POST /invoice/create` can. A reverse swap depends on the Lightning leg outliving the on-chain
//! one, so until that is fixed upstream ([beignet#744]) this crate creates the invoice, decodes
//! it, and refuses to proceed when the realised delta is too short. [`capability`] also probes
//! for the field at startup so a provider stops advertising reverse swaps rather than discovering
//! the problem with a counterparty's payment already held.
//!
//! [beignet]: https://github.com/coreyphillips/beignet
//! [beignet#744]: https://github.com/coreyphillips/beignet/issues/744

pub mod blocking;
pub mod capability;
pub mod error;
pub mod http;
pub mod lightning;
pub mod types;
pub mod wallet;

pub use capability::Preflight;
pub use error::{BeignetApiError, BeignetError};
pub use http::{ApiToken, BeignetConfig, BeignetHttp};
pub use lightning::BeignetLightningBackend;
pub use wallet::BeignetWallet;
