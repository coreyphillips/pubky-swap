//! The BDK funding wallet now lives in `swap-common` (so the submarine-swap client can reuse it).
//! Re-exported here for the provider's existing call sites and integration tests.

pub use swap_common::wallet::BdkWallet;
