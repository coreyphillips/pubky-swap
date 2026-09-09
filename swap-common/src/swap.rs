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

impl SwapDirection {
    /// The one spelling of a direction: what the CLI accepts, what serde writes, and what any
    /// human-readable output should print.
    ///
    /// It exists so that nothing reaches for `{:?}`. Debug renders `Reverse`, which was the only
    /// capitalised spelling anywhere in the system, so anything parsing it had to know to
    /// case-fold, and anything comparing it against a configured value silently did not match.
    pub fn as_str(self) -> &'static str {
        match self {
            SwapDirection::Submarine => "submarine",
            SwapDirection::Reverse => "reverse",
        }
    }
}

impl std::fmt::Display for SwapDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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

    /// The wire spec for a `bitcoin::Network`, or an error for one this protocol cannot name.
    ///
    /// Fallible because `bitcoin::Network` is `#[non_exhaustive]`: it gains variants, and the
    /// catch-all this used to have mapped every future one to `Regtest`. A record carrying the
    /// wrong network derives addresses on the wrong chain, and the whole point of writing the
    /// network down is that a resumed driver can rebuild the HTLC exactly.
    pub fn from_bitcoin_network(n: bitcoin::Network) -> crate::error::Result<Self> {
        Ok(match n {
            bitcoin::Network::Bitcoin => NetworkSpec::Bitcoin,
            bitcoin::Network::Testnet => NetworkSpec::Testnet,
            bitcoin::Network::Signet => NetworkSpec::Signet,
            bitcoin::Network::Regtest => NetworkSpec::Regtest,
            other => {
                return Err(crate::error::SwapError::Permanent(format!(
                    "this build has no wire name for the {other} network"
                )))
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `bitcoin::Network` is `#[non_exhaustive]`, so it gains variants: 0.32 has four and the
    /// next release adds more. The mapping used to end in a catch-all that answered `Regtest` for
    /// anything it did not recognise, which would put a record on the wrong chain and derive its
    /// HTLC address there. Writing the network down is only worth doing if it is right.
    #[test]
    fn every_network_this_protocol_names_round_trips() {
        for (spec, network) in [
            (NetworkSpec::Bitcoin, bitcoin::Network::Bitcoin),
            (NetworkSpec::Testnet, bitcoin::Network::Testnet),
            (NetworkSpec::Signet, bitcoin::Network::Signet),
            (NetworkSpec::Regtest, bitcoin::Network::Regtest),
        ] {
            assert_eq!(spec.to_bitcoin_network(), network);
            assert_eq!(NetworkSpec::from_bitcoin_network(network).unwrap(), spec);
        }
    }
}

#[cfg(test)]
mod direction_tests {
    use super::*;

    /// One spelling, everywhere.
    ///
    /// `as_str` has to match what the CLI parses and what serde writes, or a value printed for a
    /// human cannot be pasted back in as a flag.
    #[test]
    fn a_direction_prints_the_way_it_is_parsed() {
        assert_eq!(SwapDirection::Submarine.as_str(), "submarine");
        assert_eq!(SwapDirection::Reverse.as_str(), "reverse");
        assert_eq!(SwapDirection::Reverse.to_string(), "reverse");
        for d in [SwapDirection::Submarine, SwapDirection::Reverse] {
            let wire = serde_json::to_string(&d).unwrap();
            assert_eq!(wire, format!("\"{}\"", d.as_str()), "serde and as_str must agree");
        }
    }
}

