//! Wire messages for the pubky-swap marketplace, exchanged as encrypted Pubky DMs.
//!
//! Flow (happy path):
//! ```text
//! Provider --Offer-->            (published to followers / on request)
//! Client   --QuoteRequest-->     Provider
//! Client   <--Quote--            Provider
//! Client   --SwapRequest-->      Provider
//! Client   <--SwapAccept--       Provider   (HTLC address / hold invoice)
//! ... funding, lockup, claim ...
//! both     <--SwapStatusUpdate--> both
//! ```

use crate::swap::{NetworkSpec, SwapDirection, SwapState};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Top-level wire envelope exchanged over the Pubky transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SwapMessage {
    /// Provider → anyone: advertises swap capabilities + rates.
    Offer(SwapOffer),
    /// Client requests the current executable offer.
    OfferRequest(OfferRequest),
    /// Client → provider: request a concrete quote against an offer.
    QuoteRequest(QuoteRequest),
    /// Provider → client: a firm, time-limited quote.
    Quote(Quote),
    /// Client → provider: commit to a swap based on a quote.
    SwapRequest(SwapRequest),
    /// Provider → client: details the client needs to proceed (HTLC address, invoice…).
    SwapAccept(SwapAccept),
    /// Either party → counterparty: lifecycle transition.
    SwapStatusUpdate(SwapStatusUpdate),
    /// Client queries its persisted swap or recovers a lost acceptance.
    SwapStatusRequest(SwapStatusRequest),
    /// Provider returns public recovery data to the authenticated swap owner.
    SwapStatusSnapshot(SwapStatusSnapshot),
    /// Either party → counterparty: cooperative signature material.
    /// Reserved for phase-2 Taproot cooperative (key-path) spends.
    CoopSignature(CoopSignature),
    /// Either party → counterparty: abort/reject with a reason.
    Reject(Reject),
}

impl SwapMessage {
    /// Group transport resources by the operation that controls their retention.
    ///
    /// Creation requests and acceptances share the quote scope. Read-only traffic uses an
    /// ephemeral scope so expiring a quote or status reply cannot complete a creation. Transport
    /// resource identity and application idempotency remain separate from this grouping.
    pub fn delivery_scope(&self) -> String {
        match self {
            Self::SwapRequest(request) => format!("quote:{}", request.quote_id),
            Self::SwapAccept(accept) => format!("quote:{}", accept.quote_id),
            Self::SwapStatusUpdate(update) => format!("swap:{}", update.swap_id),
            Self::CoopSignature(signature) => format!("swap:{}", signature.swap_id),
            Self::Offer(offer) => ephemeral("offer", offer.request_id.unwrap_or(offer.offer_id)),
            Self::OfferRequest(request) => {
                ephemeral("offer-request", request.request_id.unwrap_or_default())
            }
            Self::QuoteRequest(request) => ephemeral(
                "quote-request",
                request.request_id.unwrap_or(request.offer_id),
            ),
            Self::Quote(quote) => ephemeral("quote", quote.request_id.unwrap_or(quote.quote_id)),
            Self::SwapStatusRequest(request) => ephemeral(
                "status-request",
                request
                    .request_id
                    .or(request.swap_id)
                    .or(request.quote_id)
                    .unwrap_or_default(),
            ),
            Self::SwapStatusSnapshot(snapshot) => ephemeral(
                "status-snapshot",
                snapshot.request_id.unwrap_or(snapshot.accept.swap_id),
            ),
            Self::Reject(rejection) => ephemeral(
                "reject",
                rejection
                    .request_id
                    .or(rejection.quote_id)
                    .or(rejection.swap_id)
                    .unwrap_or_default(),
            ),
        }
    }
}

fn ephemeral(kind: &str, id: Uuid) -> String {
    format!("ephemeral:{kind}:{id}")
}

/// The wire protocol this build speaks.
///
/// Bumped when a change would make one side act on a message the other meant differently. Adding
/// an optional field is not that: `#[serde(default)]` already carries those, and the codebase has
/// used it that way from the start. What it is for is the change that cannot be expressed as an
/// absent field, and `CoopSignature`'s deliberately opaque payload is the one already on the
/// roadmap.
pub const PROTOCOL_VERSION: u16 = 1;

/// Versions this build can complete a swap against.
///
/// Version 0 is every build before versioning existed, which sends no version at all and is
/// otherwise wire-compatible with this one. Treating an absent field as 0 rather than as an error
/// is what lets that keep working.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u16 = 0;

/// Whether a counterparty's protocol version is one this build can complete a swap against.
pub fn protocol_version_supported(version: u16) -> bool {
    (MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version)
}

/// A provider's advertised swap capabilities and rates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOffer {
    /// Correlates a direct offer response. Absent for broadcasts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    pub offer_id: Uuid,
    pub provider_pkarr: String,
    pub network: NetworkSpec,
    pub directions: Vec<SwapDirection>,
    pub min_amount_sat: u64,
    pub max_amount_sat: u64,
    /// Flat fee component.
    pub base_fee_sat: u64,
    /// Proportional fee, in parts-per-million of the swap amount.
    pub fee_ppm: u64,
    /// On-chain confirmations required before a lockup is treated as final.
    pub required_confirmations: u32,
    /// HTLC timelock, in blocks measured from the lockup.
    pub htlc_timeout_blocks: u32,
    /// Provider's Lightning node id (informational / routing hint).
    pub lightning_node_id: Option<String>,
    /// Unix seconds after which the offer is stale.
    pub valid_until_unix: u64,
    /// Seconds the provider takes to fund its leg once the owner's funding is final. Advisory,
    /// like `valid_until_unix`; the quote carries the binding figure. Absent means 0: undeclared.
    #[serde(default)]
    pub fund_within_secs: u64,
    /// What the provider expects to spend on chain to run one swap of this kind, at the fee rate
    /// it is currently seeing.
    ///
    /// The provider pays a transaction fee on every swap: the funding transaction for a reverse
    /// swap, the claim for a submarine one, plus a share of the refund sweeps that unhappy paths
    /// require. Quoting only a service fee means quoting below cost, so this is priced in and
    /// shown separately rather than buried.
    #[serde(default)]
    pub onchain_fee_sat: u64,
    /// The sat/vB the figure above was priced at, so a client can see the fee environment the
    /// quote assumes.
    #[serde(default)]
    pub fee_rate_sat_vb: u64,
    /// The wire protocol this provider speaks. Absent means 0: a build from before versioning.
    ///
    /// Compatibility was inferred from which fields happened to be present, and there is even a
    /// comment in `validate` acknowledging it ("a v0 provider sends neither part, which is why
    /// this only binds when at least one is present"). That works for exactly one change and then
    /// stops: two absent-field conventions layered on each other cannot be told apart.
    #[serde(default)]
    pub protocol_version: u16,
    /// Optional capabilities this provider has, for changes that are additive rather than
    /// breaking. Unknown entries are ignored, which is the point.
    #[serde(default)]
    pub features: Vec<String>,
}

/// A quoted fee, split so the client can see what it is paying for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuoteFee {
    /// What the provider charges for the service.
    pub service_fee_sat: u64,
    /// What the provider expects to spend on chain running the swap.
    pub onchain_fee_sat: u64,
    /// The two together, which is what the client actually pays.
    pub total_fee_sat: u64,
}

/// How many times the on-chain cost a swap must be worth before it is worth doing.
///
/// Below this the fee dominates the trade and both sides are better off not bothering, so the
/// advertised minimum rises with the fee environment instead of staying at a number chosen when
/// fees were low.
pub const MIN_AMOUNT_FEE_MULTIPLE: u64 = 10;

impl SwapOffer {
    /// Fee the provider charges for a swap of `amount_sat`, itemised.
    ///
    /// The on-chain component is what makes this honest. With the shipped defaults (500 sat base,
    /// 2000 ppm) a 100k sat swap earned 700 sat, while the funding transaction alone costs around
    /// 770 sat at the 5 sat/vB mainnet floor: every mainnet swap ran at a loss, and the unhappy
    /// path added a refund sweep on top.
    pub fn quote_fee(&self, amount_sat: u64) -> QuoteFee {
        let proportional = (u128::from(amount_sat) * u128::from(self.fee_ppm) / 1_000_000) as u64;
        let service_fee_sat = self.base_fee_sat.saturating_add(proportional);
        QuoteFee {
            service_fee_sat,
            onchain_fee_sat: self.onchain_fee_sat,
            total_fee_sat: service_fee_sat.saturating_add(self.onchain_fee_sat),
        }
    }

    pub fn supports(&self, dir: SwapDirection) -> bool {
        self.directions.contains(&dir)
    }

    /// The smallest swap worth doing at the current fee environment.
    ///
    /// A configured minimum from a quiet mempool becomes uneconomic in a busy one, so the
    /// effective floor tracks the on-chain cost.
    pub fn effective_min_amount_sat(&self) -> u64 {
        self.min_amount_sat
            .max(self.onchain_fee_sat.saturating_mul(MIN_AMOUNT_FEE_MULTIPLE))
    }

    pub fn accepts_amount(&self, amount_sat: u64) -> bool {
        amount_sat >= self.effective_min_amount_sat() && amount_sat <= self.max_amount_sat
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRequest {
    /// Correlates concurrent quote requests and delayed responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    pub offer_id: Uuid,
    /// The sender's own pubky, as the sender states it.
    ///
    /// Not authoritative and never authorization: the transport's authenticated sender is the
    /// identity a provider quotes and bills. A provider checks the two agree and refuses the
    /// request if they do not, rather than believing this field over the sender it came from.
    pub client_pkarr: String,
    pub direction: SwapDirection,
    pub amount_sat: u64,
    /// The wire protocol this client speaks. Absent means 0: a build from before versioning.
    ///
    /// This is the first message a client sends, so it is where a mismatch costs least: nothing
    /// has been quoted, nothing reserved, and no key generated.
    #[serde(default)]
    pub protocol_version: u16,
    /// Optional capabilities this client has. Unknown entries are ignored.
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    pub quote_id: Uuid,
    pub offer_id: Uuid,
    pub direction: SwapDirection,
    pub amount_sat: u64,
    /// The whole fee: service plus the provider's expected on-chain cost.
    pub fee_sat: u64,
    /// The service half of `fee_sat`.
    #[serde(default)]
    pub service_fee_sat: u64,
    /// The on-chain half of `fee_sat`: what the provider expects to spend in miner fees.
    #[serde(default)]
    pub onchain_fee_sat: u64,
    /// The sat/vB the on-chain component was priced at.
    #[serde(default)]
    pub fee_rate_sat_vb: u64,
    /// What the client ultimately pays (amount + fee for submarine; LN invoice amount for
    /// reverse). Kept explicit so the client can sanity-check before committing.
    pub total_sat: u64,
    pub htlc_timeout_blocks: u32,
    pub required_confirmations: u32,
    pub valid_until_unix: u64,
    /// Seconds, for this quote's direction, between the owner's funding becoming final and the
    /// provider funding its own leg. Absent means 0: undeclared.
    ///
    /// Final means the hold invoice accepted for a reverse swap, and the lockup at
    /// `required_confirmations` for a submarine one. Declared, not enforced.
    #[serde(default)]
    pub fund_within_secs: u64,
    /// The wire protocol this provider speaks. Absent means 0.
    ///
    /// Also on `SwapOffer`, and the check belongs on both: an offer is what a client will read
    /// once discovery exists, and a quote is what it reads today.
    #[serde(default)]
    pub protocol_version: u16,
}

impl Quote {
    /// Whether the quote has expired at `now_unix`. A `valid_until_unix` of 0 means "no expiry".
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.valid_until_unix != 0 && now_unix >= self.valid_until_unix
    }
}

/// On-chain contract selected by the client. Old requests retain the P2WSH contract.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapScript {
    #[default]
    P2wsh,
    /// Boltz-compatible Taproot tree with unilateral script-path spends.
    TaprootBoltz,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapRequest {
    #[serde(default)]
    pub script_type: SwapScript,
    pub quote_id: Uuid,
    /// The sender's own pubky, as the sender states it. Non-authoritative, exactly as on
    /// [`QuoteRequest`]; a quote is redeemable only by the authenticated pubky it was issued to.
    pub client_pkarr: String,
    pub direction: SwapDirection,
    /// SHA256 payment hash (hex). Reverse: generated by the client. Submarine: taken from
    /// the client's Lightning invoice.
    pub payment_hash_hex: String,
    /// Client's claim pubkey (hex, 33-byte compressed). Reverse: claim branch of the
    /// provider's on-chain HTLC.
    pub client_claim_pubkey_hex: Option<String>,
    /// Client's refund pubkey (hex). Submarine: refund branch of the client's own HTLC.
    pub client_refund_pubkey_hex: Option<String>,
    /// Submarine only: the Lightning invoice the provider must pay.
    pub invoice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapAccept {
    #[serde(default)]
    pub script_type: SwapScript,
    /// Present for Taproot contracts. The legacy redeem script is empty in this case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_tree: Option<crate::taproot::BoltzSwapTree>,
    pub quote_id: Uuid,
    pub swap_id: Uuid,
    pub direction: SwapDirection,
    /// HTLC redeem script (hex), so both parties can independently verify it.
    pub htlc_script_hex: String,
    /// Contract address the funding party must pay into.
    pub htlc_address: String,
    /// Exact amount to lock on-chain.
    pub onchain_amount_sat: u64,
    /// Absolute block height at which the HTLC refund branch becomes spendable.
    pub timeout_block_height: u32,
    /// Provider's pubkey in the HTLC (hex).
    pub provider_pubkey_hex: String,
    /// Reverse only: the Lightning hold invoice the client must pay.
    pub invoice: Option<String>,
}

/// Request a provider's current offer without committing to a quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferRequest {
    #[serde(default)]
    pub request_id: Option<Uuid>,
}

/// Exactly one of swap_id and quote_id must be present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapStatusRequest {
    #[serde(default)]
    pub request_id: Option<Uuid>,
    pub swap_id: Option<Uuid>,
    pub quote_id: Option<Uuid>,
}

/// Public recovery information. This never contains a branch secret or a preimage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapStatusSnapshot {
    #[serde(default)]
    pub request_id: Option<Uuid>,
    pub accept: SwapAccept,
    pub network: NetworkSpec,
    pub state: SwapState,
    pub funding_txid_hex: Option<String>,
    pub funding_vout: Option<u32>,
    pub spend_txid_hex: Option<String>,
    /// Reverse only: the owner's claim of the HTLC, as the provider saw it.
    #[serde(default)]
    pub claim_observed_txid_hex: Option<String>,
    pub required_confirmations: u32,
    pub updated_at_unix: u64,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapStatusUpdate {
    pub swap_id: Uuid,
    pub state: SwapState,
    /// Optional txid / preimage / invoice reference for this transition.
    pub reference: Option<String>,
}

/// Cooperative signature material (phase-2 Taproot key-path spends). The encoding is
/// intentionally opaque until that work lands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoopSignature {
    pub swap_id: Uuid,
    pub data_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reject {
    /// A [`RejectCode`] as its string. Kept a string on the wire so a code added later still
    /// parses on an older client; read it through [`Reject::code`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    pub swap_id: Option<Uuid>,
    pub quote_id: Option<Uuid>,
    /// For a person. Its wording is not part of the protocol.
    pub reason: String,
}

impl Reject {
    /// The refusal's code. `None` when the provider sent none, which every provider from before
    /// the vocabulary does, or sent one this build does not know.
    pub fn code(&self) -> Option<RejectCode> {
        self.code.as_deref()?.parse().ok()
    }
}

/// Why a provider refused a request, so a client can act on it without parsing `reason`.
///
/// Closed: a provider sends nothing outside this set. The first three predate it and keep their
/// strings. The next eight are the Paykit Intents draft's refusal reasons. The last four are local
/// cases the draft has no word for, which an adapter reports as its generic decline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectCode {
    /// A status lookup found no swap this sender owns.
    NotFound,
    /// The swap is admitted but not yet ready to describe, or another request is admitting it.
    Pending,
    /// The provider's access policy refuses this sender.
    AccessDenied,
    /// The provider does not offer this direction, or cannot execute swaps at all.
    UnsupportedRoute,
    /// Below the offer's effective minimum, which `reason` states.
    AmountBelowMinimum,
    /// Above the offer's maximum, which `reason` states.
    AmountAboveMaximum,
    /// The provider's capacity, exposure limits or wallet cannot take this swap now.
    LiquidityUnavailable,
    /// This sender has started too many swaps recently.
    RateLimited,
    /// The provider has not priced its offer yet.
    PricingUnavailable,
    /// The quote is unknown to the provider or has expired.
    QuoteExpired,
    /// The submarine invoice cannot be paid on the quoted terms.
    InvalidDestination,
    /// The request is malformed or contradicts itself or an earlier one.
    InvalidRequest,
    /// The sender's protocol version is outside what the provider speaks.
    UnsupportedProtocol,
    /// The request names an offer that is no longer current.
    OfferStale,
    /// The provider failed for a reason of its own.
    InternalError,
}

impl RejectCode {
    pub const ALL: [Self; 15] = [
        Self::NotFound,
        Self::Pending,
        Self::AccessDenied,
        Self::UnsupportedRoute,
        Self::AmountBelowMinimum,
        Self::AmountAboveMaximum,
        Self::LiquidityUnavailable,
        Self::RateLimited,
        Self::PricingUnavailable,
        Self::QuoteExpired,
        Self::InvalidDestination,
        Self::InvalidRequest,
        Self::UnsupportedProtocol,
        Self::OfferStale,
        Self::InternalError,
    ];

    /// The string sent in [`Reject::code`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Pending => "pending",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedRoute => "unsupported_route",
            Self::AmountBelowMinimum => "amount_below_minimum",
            Self::AmountAboveMaximum => "amount_above_maximum",
            Self::LiquidityUnavailable => "liquidity_unavailable",
            Self::RateLimited => "rate_limited",
            Self::PricingUnavailable => "pricing_unavailable",
            Self::QuoteExpired => "quote_expired",
            Self::InvalidDestination => "invalid_destination",
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::OfferStale => "offer_stale",
            Self::InternalError => "internal_error",
        }
    }
}

impl std::fmt::Display for RejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A string that is not a [`RejectCode`] this build knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRejectCode;

impl std::fmt::Display for UnknownRejectCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown reject code")
    }
}

impl std::error::Error for UnknownRejectCode {}

impl std::str::FromStr for RejectCode {
    type Err = UnknownRejectCode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == value)
            .ok_or(UnknownRejectCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> SwapOffer {
        SwapOffer {
            request_id: None,
            offer_id: Uuid::nil(),
            provider_pkarr: "provider".to_string(),
            network: NetworkSpec::Regtest,
            directions: vec![SwapDirection::Submarine, SwapDirection::Reverse],
            min_amount_sat: 10_000,
            max_amount_sat: 1_000_000,
            base_fee_sat: 500,
            fee_ppm: 2_000, // 0.2%
            required_confirmations: 1,
            htlc_timeout_blocks: 144,
            lightning_node_id: None,
            valid_until_unix: 0,
            fund_within_secs: 300,
            onchain_fee_sat: 0,
            fee_rate_sat_vb: 0,
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        }
    }

    /// Compatibility used to be inferred from which fields were present, which works for exactly
    /// one change: two absent-field conventions layered on each other cannot be told apart. A
    /// counterparty from before versioning sends no version at all, and reads as 0.
    #[test]
    fn a_message_without_a_version_reads_as_the_one_before_versioning() {
        let json = serde_json::json!({
            "offer_id": "00000000-0000-0000-0000-000000000000",
            "client_pkarr": "client",
            "direction": "submarine",
            "amount_sat": 50_000
        });
        let req: QuoteRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.protocol_version, 0);
        assert!(req.features.is_empty());
        assert!(
            protocol_version_supported(req.protocol_version),
            "a build from before versioning is still one we can swap with"
        );
    }

    #[test]
    fn a_version_from_the_future_is_not_supported() {
        assert!(protocol_version_supported(PROTOCOL_VERSION));
        assert!(protocol_version_supported(MIN_SUPPORTED_PROTOCOL_VERSION));
        assert!(
            !protocol_version_supported(PROTOCOL_VERSION + 1),
            "a counterparty speaking something newer may mean any field differently"
        );
    }

    #[test]
    fn quote_fee_is_itemised_service_plus_onchain_cost() {
        let mut offer = sample_offer();
        // 500 base + 0.2% of 1_000_000 = 500 + 2000 = 2500 of service fee.
        let fee = offer.quote_fee(1_000_000);
        assert_eq!(fee.service_fee_sat, 2_500);
        assert_eq!(fee.onchain_fee_sat, 0);
        assert_eq!(fee.total_fee_sat, 2_500);

        // The provider's own on-chain cost is added on top and shown separately, rather than
        // being absorbed into a service fee that does not cover it.
        offer.onchain_fee_sat = 1_400;
        let fee = offer.quote_fee(1_000_000);
        assert_eq!(fee.service_fee_sat, 2_500);
        assert_eq!(fee.onchain_fee_sat, 1_400);
        assert_eq!(fee.total_fee_sat, 3_900);

        assert!(offer.supports(SwapDirection::Reverse));
    }

    #[test]
    fn the_minimum_rises_with_the_on_chain_cost() {
        let mut offer = sample_offer();
        assert!(offer.accepts_amount(10_000));
        assert!(!offer.accepts_amount(9_999));

        // In a busy mempool a 10k sat swap would be mostly fee, so the floor rises with it.
        offer.onchain_fee_sat = 2_000;
        assert_eq!(offer.effective_min_amount_sat(), 20_000);
        assert!(!offer.accepts_amount(10_000));
        assert!(offer.accepts_amount(20_000));
    }

    fn sample_quote() -> Quote {
        Quote {
            request_id: None,
            quote_id: Uuid::nil(),
            offer_id: Uuid::nil(),
            direction: SwapDirection::Reverse,
            amount_sat: 50_000,
            fee_sat: 500,
            service_fee_sat: 500,
            onchain_fee_sat: 0,
            fee_rate_sat_vb: 5,
            total_sat: 50_500,
            htlc_timeout_blocks: 144,
            required_confirmations: 1,
            valid_until_unix: 1_000,
            fund_within_secs: 300,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    /// A provider from before the field existed declares nothing, which reads as 0 rather than
    /// failing to parse.
    #[test]
    fn fund_within_reads_as_undeclared_when_absent_and_round_trips() {
        let mut offer = serde_json::to_value(sample_offer()).unwrap();
        offer.as_object_mut().unwrap().remove("fund_within_secs");
        let offer: SwapOffer = serde_json::from_value(offer).unwrap();
        assert_eq!(offer.fund_within_secs, 0);

        let mut quote = serde_json::to_value(sample_quote()).unwrap();
        quote.as_object_mut().unwrap().remove("fund_within_secs");
        let quote: Quote = serde_json::from_value(quote).unwrap();
        assert_eq!(quote.fund_within_secs, 0);

        let json = serde_json::to_string(&SwapMessage::Offer(sample_offer())).unwrap();
        let SwapMessage::Offer(offer) = serde_json::from_str(&json).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(offer.fund_within_secs, 300);
        let json = serde_json::to_string(&SwapMessage::Quote(sample_quote())).unwrap();
        let SwapMessage::Quote(quote) = serde_json::from_str(&json).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(quote.fund_within_secs, 300);
    }

    #[test]
    fn quote_expiry() {
        let mut q = sample_quote();
        assert!(!q.is_expired(999));
        assert!(q.is_expired(1_000));
        assert!(q.is_expired(1_001));
        // 0 means no expiry.
        q.valid_until_unix = 0;
        assert!(!q.is_expired(u64::MAX));
    }

    #[test]
    fn swap_message_roundtrips() {
        let msg = SwapMessage::Offer(sample_offer());
        let json = serde_json::to_string(&msg).unwrap();
        let back: SwapMessage = serde_json::from_str(&json).unwrap();
        match back {
            SwapMessage::Offer(o) => assert_eq!(o.base_fee_sat, 500),
            _ => panic!("wrong variant"),
        }
    }

    fn accepted_swap() -> SwapAccept {
        SwapAccept {
            script_type: Default::default(),
            swap_tree: None,
            quote_id: Uuid::new_v4(),
            swap_id: Uuid::new_v4(),
            direction: SwapDirection::Reverse,
            htlc_script_hex: String::new(),
            htlc_address: String::new(),
            onchain_amount_sat: 100_000,
            timeout_block_height: 1000,
            provider_pubkey_hex: String::new(),
            invoice: None,
        }
    }

    #[test]
    fn creation_messages_share_retention_without_using_read_only_reply_scopes() {
        let accept = accepted_swap();
        let request = SwapRequest {
            script_type: Default::default(),
            quote_id: accept.quote_id,
            client_pkarr: "client".into(),
            direction: SwapDirection::Reverse,
            payment_hash_hex: "00".repeat(32),
            client_claim_pubkey_hex: None,
            client_refund_pubkey_hex: None,
            invoice: None,
        };
        let creation = SwapMessage::SwapAccept(accept.clone()).delivery_scope();
        assert_eq!(creation, SwapMessage::SwapRequest(request).delivery_scope());
        let status = SwapMessage::SwapStatusSnapshot(SwapStatusSnapshot {
            request_id: Some(Uuid::new_v4()),
            accept: accept.clone(),
            network: NetworkSpec::Regtest,
            state: SwapState::Created,
            funding_txid_hex: None,
            funding_vout: None,
            spend_txid_hex: None,
            claim_observed_txid_hex: None,
            required_confirmations: 1,
            updated_at_unix: 1,
            observed_at_unix: 1,
        });
        assert!(status
            .delivery_scope()
            .starts_with("ephemeral:status-snapshot:"));
        assert_ne!(creation, status.delivery_scope());
        let query = SwapMessage::SwapStatusRequest(SwapStatusRequest {
            request_id: None,
            swap_id: None,
            quote_id: Some(accept.quote_id),
        });
        assert_ne!(creation, query.delivery_scope());
    }

    #[test]
    fn status_snapshot_from_an_older_provider_has_no_claim_txid() {
        let snapshot = SwapStatusSnapshot {
            request_id: None,
            accept: accepted_swap(),
            network: NetworkSpec::Regtest,
            state: SwapState::Claimed,
            funding_txid_hex: Some("aa".repeat(32)),
            funding_vout: Some(0),
            spend_txid_hex: None,
            claim_observed_txid_hex: Some("cc".repeat(32)),
            required_confirmations: 1,
            updated_at_unix: 1,
            observed_at_unix: 1,
        };
        let mut json = serde_json::to_value(&snapshot).unwrap();
        json.as_object_mut()
            .unwrap()
            .remove("claim_observed_txid_hex");
        let older: SwapStatusSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(older.claim_observed_txid_hex, None);
        assert_eq!(older.funding_txid_hex, snapshot.funding_txid_hex);
    }

    #[test]
    fn lifecycle_retention_isolated_by_swap_identity() {
        let first = accepted_swap();
        let second = accepted_swap();
        let status = |swap_id| {
            SwapMessage::SwapStatusUpdate(SwapStatusUpdate {
                swap_id,
                state: SwapState::Claimed,
                reference: None,
            })
            .delivery_scope()
        };
        assert_ne!(status(first.swap_id), status(second.swap_id));
        assert_ne!(
            status(first.swap_id),
            SwapMessage::SwapAccept(first.clone()).delivery_scope()
        );
        assert_eq!(
            status(first.swap_id),
            SwapMessage::CoopSignature(CoopSignature {
                swap_id: first.swap_id,
                data_hex: String::new(),
            })
            .delivery_scope()
        );
    }

    #[test]
    fn every_reject_code_round_trips_as_its_snake_case_string() {
        for code in RejectCode::ALL {
            let text = code.as_str();
            assert!(text.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
            assert_eq!(serde_json::to_value(code).unwrap(), text);
            assert_eq!(
                serde_json::from_value::<RejectCode>(text.into()).unwrap(),
                code
            );
            assert_eq!(text.parse::<RejectCode>(), Ok(code));
            let reject = Reject {
                code: Some(text.into()),
                request_id: None,
                swap_id: None,
                quote_id: None,
                reason: String::new(),
            };
            assert_eq!(reject.code(), Some(code));
        }
        // Clients already match on these, so they must not change.
        assert_eq!(RejectCode::NotFound.as_str(), "not_found");
        assert_eq!(RejectCode::Pending.as_str(), "pending");
        assert_eq!(RejectCode::AccessDenied.as_str(), "access_denied");
    }

    /// A code from a newer provider, or from none at all, reads as absent rather than failing
    /// the whole message.
    #[test]
    fn an_unknown_or_absent_reject_code_reads_as_none() {
        let json = serde_json::json!({
            "type": "Reject",
            "code": "bogus",
            "swap_id": null,
            "quote_id": null,
            "reason": "from the future"
        });
        let SwapMessage::Reject(reject) = serde_json::from_value(json.clone()).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(reject.code.as_deref(), Some("bogus"));
        assert_eq!(reject.code(), None);

        let mut older = json;
        older.as_object_mut().unwrap().remove("code");
        let SwapMessage::Reject(reject) = serde_json::from_value(older).unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(reject.code(), None);
    }

    #[test]
    fn rejection_does_not_complete_a_creation_or_lifecycle_scope() {
        let accept = accepted_swap();
        let rejection = SwapMessage::Reject(Reject {
            code: None,
            request_id: None,
            swap_id: Some(accept.swap_id),
            quote_id: Some(accept.quote_id),
            reason: "retry status".into(),
        });
        assert!(rejection.delivery_scope().starts_with("ephemeral:reject:"));
        assert_ne!(
            rejection.delivery_scope(),
            SwapMessage::SwapAccept(accept).delivery_scope()
        );
        let encoded = serde_json::to_vec(&rejection).unwrap();
        let restored: SwapMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(rejection.delivery_scope(), restored.delivery_scope());
    }
}
