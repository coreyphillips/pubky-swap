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
//! Client   --SwapStatusRequest--> Provider   (one swap, by id)
//! Client   --SwapListRequest-->   Provider   (every swap it owns; `swap-list-v1`)
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
    /// Client asks for every swap it owns at this provider, paged. Needs `swap-list-v1`.
    SwapListRequest(SwapListRequest),
    /// Provider returns one page of the sender's own swaps.
    SwapList(SwapList),
    /// Owner → provider, after `SwapAccept`: a wake gateway grant for this one swap. Needs
    /// `swap-wake-v1`.
    SwapWakeCapability(SwapWakeCapability),
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
            Self::SwapListRequest(request) => {
                ephemeral("list-request", request.request_id.unwrap_or_default())
            }
            Self::SwapList(list) => ephemeral("list", list.request_id.unwrap_or_default()),
            Self::SwapWakeCapability(offer) => {
                ephemeral("wake-capability", offer.request_id.unwrap_or(offer.swap_id))
            }
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

/// The largest plaintext a Paykit Event Message carries (paykit-rs `PUBKY_NOISE_MSG_LEN`).
///
/// Not a limit on any pubky-swap carrier: encrypted DMs and iroh streams take far larger messages.
/// It binds an adapter that re-encodes these messages over Paykit Encrypted Links, and the test
/// `negotiation_messages_fit_a_paykit_event_message` measures which ones fit.
pub const PAYKIT_EVENT_MAX_BYTES: usize = 1_000;

/// The offer feature of a provider that answers [`SwapListRequest`] and keeps
/// [`SwapRequest::owner_ref`].
pub const SWAP_LIST_FEATURE: &str = "swap-list-v1";

/// The offer feature of a provider that answers the `paykit-cap.*` kinds for `swap/1` on iroh
/// `direct/1` (see [`crate::paykit_cap`]). A client that asks for signed quotes and contracts
/// checks for it first: a provider without it drops those kinds unanswered.
pub const PAYKIT_CAP_FEATURE: &str = "paykit-cap-v1";

/// The feature of a side that sends, or wants, the claimable hint.
///
/// A provider advertising it, sent a [`QuoteRequest`] that lists it, tells the owner of a reverse
/// swap when its lockup reaches the quote's `required_confirmations`: one [`SwapStatusUpdate`] in
/// `lockup_confirmed` whose reference is the funding outpoint (`txid:vout`), and
/// [`SwapStatusSnapshot::claimable`] from then on. Only DM owners get the update; session owners
/// read the snapshot. Neither authorizes a claim: the owner checks the lockup on its own chain
/// view before revealing the preimage.
pub const CLAIMABLE_HINT_FEATURE: &str = "claimable-hint-v1";

/// The offer feature of a provider that accepts a [`SwapWakeCapability`] and wakes the owner
/// through it when the claimable hint fires. Advertised only with [`CLAIMABLE_HINT_FEATURE`] and a
/// non-empty gateway allowlist.
pub const SWAP_WAKE_FEATURE: &str = "swap-wake-v1";

/// The wake gateway peer topic a swap grant covers.
pub const SWAP_WAKE_TOPIC: &str = "swap.claimable";

/// The longest wake grant token a provider keeps.
pub const WAKE_TOKEN_MAX_LEN: usize = 256;

/// Snapshots on a [`SwapList`] page when the request names no limit.
pub const SWAP_LIST_DEFAULT_PAGE: u32 = 10;

/// The most snapshots one [`SwapList`] page carries, whatever the request asks for.
///
/// Sized so a page of the largest snapshots stays well inside one iroh reply (64 KiB) and one
/// DM payload. `a_full_page_of_the_largest_snapshots_fits_an_iroh_reply` measures it.
pub const SWAP_LIST_MAX_PAGE: u32 = 16;

/// The longest [`SwapRequest::owner_ref`] a provider keeps.
pub const OWNER_REF_MAX_LEN: usize = 128;

/// Whether an `owner_ref` is one a provider keeps: at most [`OWNER_REF_MAX_LEN`] bytes, all
/// printable ASCII. It reaches logs and listings verbatim, so nothing else is accepted.
pub fn owner_ref_is_valid(owner_ref: &str) -> bool {
    owner_ref.len() <= OWNER_REF_MAX_LEN
        && owner_ref.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// An opaque reference the owner chooses, kept verbatim by the provider and echoed in every
    /// [`SwapStatusSnapshot`] and listing.
    ///
    /// A wallet that derives its swap keys from a seed puts the key index here, so a restore from
    /// the seed alone can rebuild them from the provider's listing instead of scanning. At most
    /// [`OWNER_REF_MAX_LEN`] printable ASCII characters, never interpreted. Providers from before
    /// `swap-list-v1` ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
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
    ///
    /// This and `htlc_address` follow from the other fields, so a receiver accepts an acceptance
    /// without them and derives both (see [`crate::validate::verify_contract`]). They are still
    /// always sent, because a receiver from before that cannot read one without them.
    #[serde(default)]
    pub htlc_script_hex: String,
    /// Contract address the funding party must pay into.
    #[serde(default)]
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
    /// When the provider first wrote the swap down. 0 from a provider before `swap-list-v1`,
    /// or for a record older than the field.
    #[serde(default)]
    pub created_at_unix: u64,
    /// The swap's payment hash (hex), so a wallet can match a listed swap against the keys it
    /// can derive without decoding the contract or the invoice. Empty from an older provider.
    #[serde(default)]
    pub payment_hash_hex: String,
    /// What the owner put in [`SwapRequest::owner_ref`], if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    /// The reverse lockup has reached `required_confirmations`, as the provider saw it. Set only
    /// for owners that asked for [`CLAIMABLE_HINT_FEATURE`]. A hint, never an authorization.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub claimable: bool,
}

/// Ask for the swaps the authenticated sender owns at this provider, newest first.
///
/// Answered only by providers advertising [`SWAP_LIST_FEATURE`]. An older provider cannot parse
/// the kind and never replies, so a client checks the offer before asking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwapListRequest {
    #[serde(default)]
    pub request_id: Option<Uuid>,
    /// The `next_cursor` of the previous page. Absent starts from the newest swap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Snapshots wanted on this page. Absent or 0 means [`SWAP_LIST_DEFAULT_PAGE`]; anything
    /// above [`SWAP_LIST_MAX_PAGE`] is clamped to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Only swaps that have not reached a terminal state.
    #[serde(default)]
    pub active_only: bool,
}

/// One page of the sender's own swaps.
///
/// Pages go by creation time, newest first, so a swap changing state never moves between them.
/// A swap created while paging sorts before the first page and shows up in the next listing.
/// Each snapshot's `request_id` is empty; the page carries the correlation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwapList {
    #[serde(default)]
    pub request_id: Option<Uuid>,
    #[serde(default)]
    pub snapshots: Vec<SwapStatusSnapshot>,
    /// Present when more swaps follow. Opaque: pass it back as `cursor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapStatusUpdate {
    pub swap_id: Uuid,
    pub state: SwapState,
    /// Optional txid / preimage / invoice reference for this transition.
    pub reference: Option<String>,
}

/// A wake gateway grant the owner issued for one swap, in the shape the gateway's anti-spam
/// notes propose for Paykit.
///
/// The token is a bearer secret, so `Debug` redacts it and a provider never logs it, echoes it or
/// keeps it past the swap.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeCapability {
    pub v: u16,
    /// The gateway's base URL. A provider calls only gateways on its own allowlist.
    pub gateway: String,
    pub topics: Vec<String>,
    /// The `wkg_` grant token.
    pub token: String,
    /// Unix seconds after which the grant is dead.
    pub expires_at: u64,
}

impl std::fmt::Debug for WakeCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeCapability")
            .field("v", &self.v)
            .field("gateway", &self.gateway)
            .field("topics", &self.topics)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Owner → provider: wake me through this grant when the swap becomes claimable.
///
/// Sent once, after `SwapAccept`, and only to a provider advertising [`SWAP_WAKE_FEATURE`]: an
/// older provider cannot parse the kind. Accepted with the swap's [`SwapStatusSnapshot`],
/// refused with a [`Reject`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapWakeCapability {
    #[serde(default)]
    pub request_id: Option<Uuid>,
    pub swap_id: Uuid,
    pub capability: WakeCapability,
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
    /// The RFQ's `atomicity_min` is a class `hash` does not meet (Capabilities §12.1).
    AtomicityUnsupported,
    /// The provider failed for a reason of its own.
    InternalError,
}

impl RejectCode {
    pub const ALL: [Self; 16] = [
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
        Self::AtomicityUnsupported,
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
            Self::AtomicityUnsupported => "atomicity_unsupported",
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
            owner_ref: None,
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
            created_at_unix: 1,
            payment_hash_hex: "00".repeat(32),
            owner_ref: None,
            claimable: false,
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
            created_at_unix: 1,
            payment_hash_hex: "00".repeat(32),
            owner_ref: Some("index:7".into()),
            claimable: false,
        };
        let mut json = serde_json::to_value(&snapshot).unwrap();
        let fields = json.as_object_mut().unwrap();
        fields.remove("claim_observed_txid_hex");
        // The `swap-list-v1` additions are just as optional.
        fields.remove("created_at_unix");
        fields.remove("payment_hash_hex");
        fields.remove("owner_ref");
        let older: SwapStatusSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(older.claim_observed_txid_hex, None);
        assert_eq!(older.funding_txid_hex, snapshot.funding_txid_hex);
        assert_eq!(older.created_at_unix, 0);
        assert!(older.payment_hash_hex.is_empty());
        assert_eq!(older.owner_ref, None);
    }

    /// #105: a request from before `owner_ref` loads with none, and one that carries it keeps
    /// it through the wire, while the provider's bound on it keeps logs and listings clean.
    #[test]
    fn an_owner_ref_is_optional_on_the_wire_and_bounded_at_the_provider() {
        let mut json = serde_json::json!({
            "quote_id": Uuid::new_v4(), "client_pkarr": "c", "direction": "reverse",
            "payment_hash_hex": "00".repeat(32), "client_claim_pubkey_hex": null,
            "client_refund_pubkey_hex": null, "invoice": null,
        });
        let older: SwapRequest = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(older.owner_ref, None);
        assert!(!serde_json::to_string(&older).unwrap().contains("owner_ref"));
        json["owner_ref"] = "index:42".into();
        let newer: SwapRequest = serde_json::from_value(json).unwrap();
        assert_eq!(newer.owner_ref.as_deref(), Some("index:42"));

        assert!(owner_ref_is_valid(""));
        assert!(owner_ref_is_valid("index:42 slot/7"));
        assert!(owner_ref_is_valid(&"a".repeat(OWNER_REF_MAX_LEN)));
        assert!(!owner_ref_is_valid(&"a".repeat(OWNER_REF_MAX_LEN + 1)));
        assert!(!owner_ref_is_valid("line\nbreak"));
        assert!(!owner_ref_is_valid("tab\t"));
        assert!(!owner_ref_is_valid("caf\u{e9}"));
    }

    #[test]
    fn list_messages_use_their_own_ephemeral_scopes() {
        let request_id = Some(Uuid::new_v4());
        let request = SwapMessage::SwapListRequest(SwapListRequest {
            request_id,
            ..Default::default()
        });
        let page = SwapMessage::SwapList(SwapList {
            request_id,
            ..Default::default()
        });
        assert!(request
            .delivery_scope()
            .starts_with("ephemeral:list-request:"));
        assert!(page.delivery_scope().starts_with("ephemeral:list:"));
        assert_ne!(request.delivery_scope(), page.delivery_scope());
        assert_ne!(
            page.delivery_scope(),
            SwapMessage::OfferRequest(OfferRequest { request_id }).delivery_scope()
        );
    }

    /// #105: the page cap exists for the carriers, so it is measured against the smallest one.
    /// Every field is at its longest: a Taproot tree, a bech32m address, a long hold invoice,
    /// every txid known, and an `owner_ref` at its limit.
    #[test]
    fn a_full_page_of_the_largest_snapshots_fits_an_iroh_reply() {
        // `pubky_transport::p2p::MAX_RPC_BYTES`, which this crate cannot name.
        const IROH_REPLY_MAX_BYTES: usize = 64 * 1024;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (_, client) = crate::random_keypair(&secp);
        let (_, provider) = crate::random_keypair(&secp);
        let contract = crate::taproot::BoltzTaprootSwap::new(
            SwapDirection::Reverse,
            &[0xab; 32],
            &client,
            &provider,
            499_999_999,
        )
        .unwrap();
        let largest = SwapStatusSnapshot {
            request_id: None,
            accept: SwapAccept {
                script_type: SwapScript::TaprootBoltz,
                swap_tree: Some(contract.swap_tree()),
                quote_id: Uuid::new_v4(),
                swap_id: Uuid::new_v4(),
                direction: SwapDirection::Reverse,
                htlc_script_hex: String::new(),
                htlc_address: contract.address(bitcoin::Network::Bitcoin).to_string(),
                onchain_amount_sat: u64::MAX,
                timeout_block_height: 499_999_999,
                provider_pubkey_hex: hex::encode(provider.to_bytes()),
                // A mainnet hold invoice with several route hints.
                invoice: Some("l".repeat(1_024)),
            },
            network: NetworkSpec::Bitcoin,
            state: SwapState::Failed("x".repeat(200)),
            funding_txid_hex: Some("aa".repeat(32)),
            funding_vout: Some(u32::MAX),
            spend_txid_hex: Some("bb".repeat(32)),
            claim_observed_txid_hex: Some("cc".repeat(32)),
            required_confirmations: u32::MAX,
            updated_at_unix: u64::MAX,
            observed_at_unix: u64::MAX,
            created_at_unix: u64::MAX,
            payment_hash_hex: "ab".repeat(32),
            owner_ref: Some("r".repeat(OWNER_REF_MAX_LEN)),
            claimable: true,
        };
        let page = SwapMessage::SwapList(SwapList {
            request_id: Some(Uuid::new_v4()),
            snapshots: vec![largest; SWAP_LIST_MAX_PAGE as usize],
            next_cursor: Some("c".repeat(80)),
        });
        let len = wire_len(page);
        println!("a full page of the largest snapshots: {len} bytes");
        assert!(
            len <= IROH_REPLY_MAX_BYTES * 3 / 4,
            "{len} bytes leaves too little of the {IROH_REPLY_MAX_BYTES}-byte iroh reply"
        );
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

    fn wire_len(message: SwapMessage) -> usize {
        serde_json::to_vec(&message).unwrap().len()
    }

    /// Which messages fit a Paykit Event Message, with each field at its longest on mainnet.
    ///
    /// Numbers are at their maximum, ids are hyphenated uuids, keys are 66 hex characters and the
    /// contract address is bech32m. Run with `--nocapture` to see the sizes.
    #[test]
    fn negotiation_messages_fit_a_paykit_event_message() {
        let max = u64::MAX;
        let id = Some(Uuid::new_v4());
        let pubky = format!("pubky://{}", "y".repeat(52));
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (_, client) = crate::random_keypair(&secp);
        let (_, provider) = crate::random_keypair(&secp);
        let key_hex = |key: &bitcoin::PublicKey| hex::encode(key.to_bytes());
        // Every capability a provider advertises today.
        let features: Vec<String> = [
            "boltz-taproot-v1",
            "swap-status-v1",
            SWAP_LIST_FEATURE,
            CLAIMABLE_HINT_FEATURE,
            SWAP_WAKE_FEATURE,
            "dm-retention-v1",
            "session-rpc-v1",
            "direct-rpc-v1",
            PAYKIT_CAP_FEATURE,
        ]
        .map(String::from)
        .to_vec();
        // The longest text the provider words itself: a reverse start refused for wallet balance.
        // A reason or failure detail that quotes a backend error has no bound, so an adapter has
        // to truncate those.
        let reason = format!(
            "swap start failed: insufficient on-chain balance: {max} sat available ({max} sat of \
             it promised to swaps not yet funded), {max} sat needed for a {max} sat swap plus fees \
             and the {max} sat reserve"
        );
        let code = RejectCode::ALL
            .into_iter()
            .map(RejectCode::as_str)
            .max_by_key(|code| code.len())
            .unwrap();
        // The highest height a timelock can name, so the leaf scripts push the most bytes.
        let timeout = 499_999_999;

        let mut measured: Vec<(String, usize)> = vec![
            (
                "SwapOffer".into(),
                wire_len(SwapMessage::Offer(SwapOffer {
                    request_id: id,
                    offer_id: Uuid::new_v4(),
                    provider_pkarr: pubky.clone(),
                    network: NetworkSpec::Bitcoin,
                    directions: vec![SwapDirection::Submarine, SwapDirection::Reverse],
                    min_amount_sat: max,
                    max_amount_sat: max,
                    base_fee_sat: max,
                    fee_ppm: max,
                    required_confirmations: u32::MAX,
                    htlc_timeout_blocks: u32::MAX,
                    lightning_node_id: Some(key_hex(&provider)),
                    valid_until_unix: max,
                    fund_within_secs: max,
                    onchain_fee_sat: max,
                    fee_rate_sat_vb: max,
                    protocol_version: u16::MAX,
                    features: features.clone(),
                })),
            ),
            (
                "QuoteRequest".into(),
                wire_len(SwapMessage::QuoteRequest(QuoteRequest {
                    request_id: id,
                    offer_id: Uuid::new_v4(),
                    client_pkarr: pubky.clone(),
                    direction: SwapDirection::Submarine,
                    amount_sat: max,
                    protocol_version: u16::MAX,
                    features,
                })),
            ),
            (
                "Quote".into(),
                wire_len(SwapMessage::Quote(Quote {
                    request_id: id,
                    quote_id: Uuid::new_v4(),
                    offer_id: Uuid::new_v4(),
                    direction: SwapDirection::Submarine,
                    amount_sat: max,
                    fee_sat: max,
                    service_fee_sat: max,
                    onchain_fee_sat: max,
                    fee_rate_sat_vb: max,
                    total_sat: max,
                    htlc_timeout_blocks: u32::MAX,
                    required_confirmations: u32::MAX,
                    valid_until_unix: max,
                    fund_within_secs: max,
                    protocol_version: u16::MAX,
                })),
            ),
            (
                "Reject".into(),
                wire_len(SwapMessage::Reject(Reject {
                    code: Some(code.into()),
                    request_id: id,
                    swap_id: Some(Uuid::new_v4()),
                    quote_id: Some(Uuid::new_v4()),
                    reason: reason.clone(),
                })),
            ),
            (
                "SwapStatusUpdate".into(),
                wire_len(SwapMessage::SwapStatusUpdate(SwapStatusUpdate {
                    swap_id: Uuid::new_v4(),
                    state: SwapState::Failed(reason),
                    reference: Some("ab".repeat(32)),
                })),
            ),
            (
                "SwapRequest without invoice".into(),
                wire_len(SwapMessage::SwapRequest(SwapRequest {
                    script_type: SwapScript::TaprootBoltz,
                    quote_id: Uuid::new_v4(),
                    client_pkarr: pubky,
                    direction: SwapDirection::Submarine,
                    payment_hash_hex: "ab".repeat(32),
                    client_claim_pubkey_hex: Some(key_hex(&client)),
                    client_refund_pubkey_hex: Some(key_hex(&client)),
                    invoice: None,
                    owner_ref: Some("r".repeat(OWNER_REF_MAX_LEN)),
                })),
            ),
        ];
        let mut compact_reverse = None;
        for direction in [SwapDirection::Reverse, SwapDirection::Submarine] {
            let (claim, refund) = match direction {
                SwapDirection::Reverse => (&client, &provider),
                SwapDirection::Submarine => (&provider, &client),
            };
            let contract = crate::taproot::BoltzTaprootSwap::new(
                direction,
                &[0xab; 32],
                claim,
                refund,
                timeout,
            )
            .unwrap();
            let accept = SwapAccept {
                script_type: SwapScript::TaprootBoltz,
                swap_tree: Some(contract.swap_tree()),
                quote_id: Uuid::new_v4(),
                swap_id: Uuid::new_v4(),
                direction,
                htlc_script_hex: String::new(),
                htlc_address: contract.address(bitcoin::Network::Bitcoin).to_string(),
                onchain_amount_sat: max,
                timeout_block_height: timeout,
                provider_pubkey_hex: key_hex(&provider),
                invoice: None,
            };
            let name = format!("Taproot {direction} SwapAccept without invoice");
            measured.push((name, wire_len(SwapMessage::SwapAccept(accept.clone()))));
            if direction == SwapDirection::Reverse {
                compact_reverse = Some(accept);
            }
        }

        for (name, len) in &measured {
            println!("{name}: {len} bytes");
        }
        // Where a reverse hold invoice rides is the adapter's question, so this is measured only.
        let compact = SwapAccept {
            swap_tree: None,
            htlc_address: String::new(),
            invoice: Some("l".repeat(400)),
            ..compact_reverse.unwrap()
        };
        println!(
            "compact Taproot reverse SwapAccept with a 400-character invoice: {} bytes",
            wire_len(SwapMessage::SwapAccept(compact))
        );
        for (name, len) in measured {
            assert!(
                len <= PAYKIT_EVENT_MAX_BYTES,
                "{name} is {len} bytes, over the {PAYKIT_EVENT_MAX_BYTES}-byte Paykit cap"
            );
        }
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
