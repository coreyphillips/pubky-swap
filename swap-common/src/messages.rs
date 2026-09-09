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
    /// Either party → counterparty: cooperative signature material.
    /// Reserved for phase-2 Taproot cooperative (key-path) spends.
    CoopSignature(CoopSignature),
    /// Either party → counterparty: abort/reject with a reason.
    Reject(Reject),
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
    pub offer_id: Uuid,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRequest {
    pub quote_id: Uuid,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapAccept {
    pub quote_id: Uuid,
    pub swap_id: Uuid,
    pub direction: SwapDirection,
    /// HTLC redeem script (hex), so both parties can independently verify it.
    pub htlc_script_hex: String,
    /// P2WSH address the funding party must pay into.
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
    pub swap_id: Option<Uuid>,
    pub quote_id: Option<Uuid>,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> SwapOffer {
        SwapOffer {
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

    #[test]
    fn quote_expiry() {
        let mut q = Quote {
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
            protocol_version: PROTOCOL_VERSION,
        };
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
}
