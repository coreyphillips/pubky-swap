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

    /// The Paykit leg status a provider record in this state reports, from the owner's point of
    /// view. The table and its caveats are in `docs/CLIENT_ADAPTERS.md`.
    ///
    /// `funding_known` is whether the record has a funding outpoint (`funding_txid_hex`), which
    /// decides whether a failure stranded funds. `needs_recovery` is the provider record's flag
    /// for a funded swap its driver cannot progress. It is the only source of `needs_attention`,
    /// and it never overrides a terminal status: a leg the owner already has is not reopened by
    /// the provider's own trouble. A snapshot does not carry it, so a caller without the record
    /// passes `false`.
    ///
    /// The status covers the whole route. A split into Lightning and chain legs can wrap this.
    /// `replaced` is never produced: nothing in a swap consumes the owner's input for another
    /// operation.
    pub fn leg_status(
        &self,
        direction: SwapDirection,
        funding_known: bool,
        needs_recovery: bool,
    ) -> LegStatus {
        let status = match self {
            SwapState::Created => LegStatus::Pending,
            // The provider sets this only for its own reverse funding. In a submarine swap it
            // could only be the owner's funding, still unresolved.
            SwapState::LockupPending => match direction {
                SwapDirection::Reverse => LegStatus::InTransit,
                SwapDirection::Submarine => LegStatus::Pending,
            },
            // The provider sets `LockupConfirmed` when a reverse funding is broadcast, not at
            // depth, so it says nothing about what the owner can safely claim.
            SwapState::LockupConfirmed | SwapState::InvoicePending => LegStatus::InTransit,
            // A paid invoice is the submarine owner's delivery, with the preimage as evidence.
            // The reverse owner's delivery is its own claim, which may not have confirmed yet.
            SwapState::InvoicePaid | SwapState::ClaimPending => match direction {
                SwapDirection::Reverse => LegStatus::InTransit,
                SwapDirection::Submarine => LegStatus::Delivered,
            },
            SwapState::Claimed => LegStatus::Delivered,
            SwapState::Refunded => LegStatus::Refunded,
            SwapState::Expired => LegStatus::Failed,
            SwapState::Failed(_) if funding_known => LegStatus::DeliveryFailed,
            SwapState::Failed(_) => LegStatus::Failed,
        };
        if needs_recovery && !status.is_terminal() {
            LegStatus::NeedsAttention
        } else {
            status
        }
    }
}

/// Per-leg status vocabulary of the Paykit Intents draft (§5.5), which a Paykit solver sends in
/// `paykit.intent_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegStatus {
    /// Source step signed or submitted; outcome unresolved.
    Pending,
    /// Source step failed or proved unexecuted.
    Failed,
    /// Another operation consumed the nonce or input.
    Replaced,
    /// Source executed; delivery unresolved.
    InTransit,
    /// Retryable delivery problem or missing evidence.
    NeedsAttention,
    /// Delivery permanently stopped. Does not imply a refund.
    DeliveryFailed,
    /// Source-chain evidence shows funds returned.
    Refunded,
    /// Delivery evidence accepted under the route's trust label.
    Delivered,
}

impl LegStatus {
    /// Whether automation is finished with this leg.
    ///
    /// `delivery_failed` counts: the draft allows a later `refunded` once refund evidence is
    /// verified, but nothing retries it.
    pub fn is_terminal(self) -> bool {
        match self {
            LegStatus::Pending | LegStatus::InTransit | LegStatus::NeedsAttention => false,
            LegStatus::Failed
            | LegStatus::Replaced
            | LegStatus::DeliveryFailed
            | LegStatus::Refunded
            | LegStatus::Delivered => true,
        }
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
            assert_eq!(
                wire,
                format!("\"{}\"", d.as_str()),
                "serde and as_str must agree"
            );
        }
    }
}

#[cfg(test)]
mod leg_status_tests {
    use super::*;
    use LegStatus::*;
    use SwapDirection::{Reverse, Submarine};

    fn all_states() -> [SwapState; 10] {
        [
            SwapState::Created,
            SwapState::LockupPending,
            SwapState::LockupConfirmed,
            SwapState::InvoicePending,
            SwapState::InvoicePaid,
            SwapState::ClaimPending,
            SwapState::Claimed,
            SwapState::Refunded,
            SwapState::Expired,
            SwapState::Failed("the peer never paid".into()),
        ]
    }

    /// The table in `docs/CLIENT_ADAPTERS.md`, row for row.
    #[test]
    fn every_state_maps_to_the_documented_leg_status() {
        // (state, reverse, submarine), whatever is known about funding.
        let rows = [
            (SwapState::Created, Pending, Pending),
            (SwapState::LockupPending, InTransit, Pending),
            (SwapState::LockupConfirmed, InTransit, InTransit),
            (SwapState::InvoicePending, InTransit, InTransit),
            (SwapState::InvoicePaid, InTransit, Delivered),
            (SwapState::ClaimPending, InTransit, Delivered),
            (SwapState::Claimed, Delivered, Delivered),
            (SwapState::Refunded, Refunded, Refunded),
            (SwapState::Expired, Failed, Failed),
        ];
        for (state, reverse, submarine) in rows {
            for funding_known in [false, true] {
                assert_eq!(
                    state.leg_status(Reverse, funding_known, false),
                    reverse,
                    "{state:?} reverse, funding known: {funding_known}"
                );
                assert_eq!(
                    state.leg_status(Submarine, funding_known, false),
                    submarine,
                    "{state:?} submarine, funding known: {funding_known}"
                );
            }
        }

        let failed = SwapState::Failed("the peer never paid".into());
        for direction in [Reverse, Submarine] {
            assert_eq!(failed.leg_status(direction, false, false), Failed);
            assert_eq!(failed.leg_status(direction, true, false), DeliveryFailed);
        }
    }

    /// A finished swap never reports a leg still in progress. The converse holds except where the
    /// owner's leg finishes before the swap does: a submarine owner is paid once its invoice is.
    #[test]
    fn terminal_states_report_terminal_leg_statuses() {
        for state in all_states() {
            for direction in [Reverse, Submarine] {
                for funding_known in [false, true] {
                    let leg = state.leg_status(direction, funding_known, false);
                    let owner_paid_early = direction == Submarine
                        && matches!(state, SwapState::InvoicePaid | SwapState::ClaimPending);
                    assert_eq!(
                        leg.is_terminal(),
                        state.is_terminal() || owner_paid_early,
                        "{state:?} {direction}, funding known: {funding_known} gave {leg:?}"
                    );
                }
            }
        }
    }

    /// The provider sets `LockupConfirmed` when a reverse funding is broadcast, not at depth, and
    /// it never sets `ClaimPending`, so that state has to read like the one it would follow.
    #[test]
    fn lockup_confirmed_is_never_delivered_and_claim_pending_reads_as_invoice_paid() {
        for direction in [Reverse, Submarine] {
            for funding_known in [false, true] {
                for needs_recovery in [false, true] {
                    let leg = |state: SwapState| {
                        state.leg_status(direction, funding_known, needs_recovery)
                    };
                    let case = format!(
                        "{direction}, funding known: {funding_known}, \
                         needs recovery: {needs_recovery}"
                    );
                    assert_ne!(leg(SwapState::LockupConfirmed), Delivered, "{case}");
                    assert_eq!(
                        leg(SwapState::ClaimPending),
                        leg(SwapState::InvoicePaid),
                        "{case}"
                    );
                }
            }
        }
    }

    /// `needs_attention` comes only from the record's recovery flag, and only for a leg still in
    /// progress. `replaced` never comes at all.
    #[test]
    fn needs_attention_comes_only_from_the_recovery_flag() {
        for state in all_states() {
            for direction in [Reverse, Submarine] {
                for funding_known in [false, true] {
                    let plain = state.leg_status(direction, funding_known, false);
                    let flagged = state.leg_status(direction, funding_known, true);
                    assert_ne!(plain, NeedsAttention);
                    assert_ne!(plain, Replaced);
                    let expected = if plain.is_terminal() {
                        plain
                    } else {
                        NeedsAttention
                    };
                    assert_eq!(
                        flagged, expected,
                        "{state:?} {direction}, funding known: {funding_known}"
                    );
                }
            }
        }
    }

    /// These are wire words in `paykit.intent_status`, so they must match the draft exactly.
    #[test]
    fn leg_statuses_serialize_as_the_draft_spells_them() {
        for (status, word) in [
            (Pending, "pending"),
            (Failed, "failed"),
            (Replaced, "replaced"),
            (InTransit, "in_transit"),
            (NeedsAttention, "needs_attention"),
            (DeliveryFailed, "delivery_failed"),
            (Refunded, "refunded"),
            (Delivered, "delivered"),
        ] {
            let wire = serde_json::to_string(&status).unwrap();
            assert_eq!(wire, format!("\"{word}\""));
            assert_eq!(serde_json::from_str::<LegStatus>(&wire).unwrap(), status);
        }
    }
}
