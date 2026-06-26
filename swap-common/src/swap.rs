//! Core swap vocabulary: direction, network, and the lifecycle state machine.

use serde::{Deserialize, Serialize};

/// Direction of a swap, from the *client's* point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwapDirection {
    /// On-chain → Lightning. The client locks on-chain BTC in an HTLC; the provider pays
    /// the client's Lightning invoice and then claims the on-chain HTLC with the preimage.
    Submarine,
    /// Lightning → on-chain. The client pays a Lightning hold invoice; the provider locks
    /// on-chain BTC in an HTLC; the client claims it with the preimage, which lets the
    /// provider settle the hold invoice.
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkSpec {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl NetworkSpec {
    pub fn to_bitcoin_network(self) -> bitcoin::Network {
        match self {
            NetworkSpec::Bitcoin => bitcoin::Network::Bitcoin,
            NetworkSpec::Testnet => bitcoin::Network::Testnet,
            NetworkSpec::Signet => bitcoin::Network::Signet,
            NetworkSpec::Regtest => bitcoin::Network::Regtest,
        }
    }

    pub fn from_bitcoin_network(n: bitcoin::Network) -> Self {
        match n {
            bitcoin::Network::Bitcoin => NetworkSpec::Bitcoin,
            bitcoin::Network::Testnet => NetworkSpec::Testnet,
            bitcoin::Network::Signet => NetworkSpec::Signet,
            _ => NetworkSpec::Regtest,
        }
    }
}

/// Lifecycle state of a single swap, covering the meaningful transitions a swap moves
/// through: created → lockup → invoice → claim/refund.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum SwapState {
    /// Swap negotiated; waiting for the funding party to lock funds.
    Created,
    /// The funding HTLC / hold-invoice payment is in the mempool / in flight.
    LockupPending,
    /// The funding HTLC has the required confirmations (or the hold invoice is accepted).
    LockupConfirmed,
    /// Lightning leg in progress (paying the invoice, or awaiting hold-invoice payment).
    InvoicePending,
    /// Lightning leg succeeded; preimage is now known to at least one party.
    InvoicePaid,
    /// A claim transaction has been built/broadcast and is awaiting confirmation.
    ClaimPending,
    /// Swap completed successfully.
    Claimed,
    /// Funds were refunded via the timelock path (swap did not complete).
    Refunded,
    /// The swap expired before completing.
    Expired,
    /// The swap failed; `detail` carries the reason.
    Failed(String),
}

impl SwapState {
    /// Whether this is a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SwapState::Claimed | SwapState::Refunded | SwapState::Expired | SwapState::Failed(_)
        )
    }
}
