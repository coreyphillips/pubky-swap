//! The `swap/1` wire as Paykit Capabilities §8.1, §10 and §13.1 define it.
//!
//! Every message is a closed object: the §8.1 envelope, a `body` with exactly the members §13.1
//! lists, and the members its kind adds beside the body. Amounts are integer strings and times
//! are integer Unix seconds, because `terms_hash` covers the JCS form of the RFQ and the quote and
//! two implementations agree on it only with the same names and encodings.
//!
//! A message with `version` takes this wire. Anything else is the older wire in the parent
//! module, which the provider still answers until every client has moved.

use super::{jcs, CapError, CapSigner, InvoiceBlob};
use crate::messages::{Reject, SwapAccept, SwapMessage, SwapScript};
use crate::SwapDirection;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

pub const VERSION: u8 = 1;
pub const PROFILE: &str = "swap/1";
/// The provider's App ID in every envelope it sends.
pub const PROVIDER_APP_ID: &str = "pubky-swap";
/// The only atomicity class `swap/1` offers. It is the strongest class (§11), so it meets every
/// `atomicity_min` a reader knows.
pub const ATOMICITY: &str = "hash";
/// The classes of §11, strongest first. An `atomicity_min` outside them is refused.
pub const ATOMICITY_CLASSES: [&str; 7] = [
    "hash",
    "point",
    "escrow",
    "attested",
    "credit_bounded",
    "provider_trusted",
    "fiat_attested",
];
/// §13.1 caps `owner_ref` so a reverse commit fits an Encrypted Link message. The native wire
/// keeps [`crate::messages::OWNER_REF_MAX_LEN`].
pub const OWNER_REF_MAX_LEN: usize = 63;

pub const TERMS_DOMAIN: &[u8] = b"paykit-cap/terms/v1\0";
pub const COMMIT_DOMAIN: &[u8] = b"paykit-cap/commit/v1\0";
pub const CONTRACT_DOMAIN: &[u8] = b"paykit-cap/contract/v1\0";

/// Whether a carrier message speaks this wire rather than the older `{kind, body}` one.
pub fn is_v1(message: &Value) -> bool {
    message.get("version").is_some()
}

/// A base-unit amount, sent as an integer string (§8.1). A JSON number is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sat(pub u64);

impl Serialize for Sat {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Sat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        // One canonical form per value, so the hashed bytes are the ones the sender meant.
        let canonical = !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text == "0" || !text.starts_with('0'));
        match text.parse() {
            Ok(value) if canonical => Ok(Sat(value)),
            _ => Err(serde::de::Error::custom(format!("not an amount: {text:?}"))),
        }
    }
}

/// The §8.1 envelope members every message carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub app_id: String,
    pub profile: String,
    pub flow_id: Uuid,
    pub key_generation: u64,
}

impl Envelope {
    pub fn new(app_id: &str, flow_id: Uuid, key_generation: u64) -> Self {
        Self {
            version: VERSION,
            app_id: app_id.into(),
            profile: PROFILE.into(),
            flow_id,
            key_generation,
        }
    }

    /// The version and profile this provider speaks. Anything else is `unsupported_protocol`.
    pub fn supported(&self) -> bool {
        self.version == VERSION && self.profile == PROFILE
    }
}

/// `paykit-cap.rfq` body (§13.1): exactly these members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RfqBody {
    /// Nil asks for whatever offer is current.
    pub offer_id: Uuid,
    pub dir: SwapDirection,
    pub from: String,
    pub to: String,
    pub amount_sat: Sat,
}

/// The RFQ without its envelope, as the terms hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RfqTerms {
    pub body: RfqBody,
    pub atomicity_min: String,
    pub respond_by: u64,
    pub valid_until: u64,
}

/// `paykit-cap.quote` body (§13.1). `fee_sat` is not sent: it is the two fees summed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteBody {
    pub quote_id: Uuid,
    pub offer_id: Uuid,
    pub dir: SwapDirection,
    pub amount_sat: Sat,
    pub service_fee_sat: Sat,
    pub onchain_fee_sat: Sat,
    pub total_sat: Sat,
    pub htlc_timeout_blocks: u32,
    pub required_confirmations: u32,
    pub fund_within_secs: u64,
    pub lock_profiles: Vec<SwapScript>,
}

/// The quote without its envelope, `rfq_event_id` and `sig`, as the terms hold it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteTerms {
    pub body: QuoteBody,
    pub atomicity: String,
    pub valid_until: u64,
}

/// The closed terms object of §10.1, which `terms_hash` covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub owner: String,
    pub owner_key_generation: u64,
    pub provider: String,
    pub provider_key_generation: u64,
    pub profile: String,
    pub flow_id: Uuid,
    pub rfq: RfqTerms,
    pub quote: QuoteTerms,
}

impl Terms {
    pub fn hash(&self) -> Result<[u8; 32], CapError> {
        domain_hash(
            TERMS_DOMAIN,
            &serde_json::to_value(self).map_err(canonical)?,
        )
    }
}

/// A commit's `quote`: the terms and the provider's `sig` over their hash (§10.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTerms {
    pub terms: Terms,
    pub sig: String,
}

/// `paykit-cap.commit` body (§13.1). It names the quote through `terms_hash`, so it carries no
/// quote id or direction of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitBody {
    pub lock_profile: SwapScript,
    pub payment_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice: Option<String>,
    /// At most [`OWNER_REF_MAX_LEN`] characters, covered by `commit_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
}

impl CommitBody {
    /// Whether `owner_ref` is one this profile carries: printable ASCII within the §13.1 cap.
    pub fn owner_ref_is_valid(&self) -> bool {
        self.owner_ref.as_deref().is_none_or(|owner_ref| {
            owner_ref.len() <= OWNER_REF_MAX_LEN && crate::messages::owner_ref_is_valid(owner_ref)
        })
    }
}

/// `paykit-cap.contract` body (§13.1). The hold invoice travels sealed beside it, bound by
/// `invoice_blob`, the blob's SHA-256. The script, tree and address are #119's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractBody {
    pub swap_id: Uuid,
    pub lock_profile: SwapScript,
    pub onchain_amount_sat: Sat,
    pub timeout_block_height: u32,
    pub provider_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice_blob: Option<String>,
}

/// What the owner needs to fund that #119 will have it derive instead. Unsigned, and checked by
/// the client against its own derivation before funding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lock {
    pub htlc_address: String,
    pub htlc_script_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_tree: Option<crate::taproot::BoltzSwapTree>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfq {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    pub body: RfqBody,
    pub atomicity_min: String,
    pub respond_by: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    pub rfq_event_id: Uuid,
    pub body: QuoteBody,
    pub atomicity: String,
    pub valid_until: u64,
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    pub quote_event_id: Uuid,
    pub terms_hash: String,
    pub body: CommitBody,
    /// Outside `commit_hash`: `terms_hash` already binds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<SignedTerms>,
    /// The owner's signature over `commit_hash`. Optional on `direct/1` until v0.2, where the
    /// connection authenticates the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    pub commit_event_id: Uuid,
    pub commit_hash: String,
    pub body: ContractBody,
    pub sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice_blob: Option<InvoiceBlob>,
    pub lock: Lock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRequest {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    pub body: StatusRequestBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusBody {
    pub swap_id: Uuid,
    /// A §12.2 leg status, or `pending` while a commit is still being admitted.
    pub state: String,
    /// `SwapState`'s own name, so a client that tracks it loses nothing.
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_event_id: Option<Uuid>,
    /// Always 0: §13.1 makes one swap one leg.
    pub leg: u32,
    pub body: StatusBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalBody {
    pub code: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    #[serde(flatten)]
    pub envelope: Envelope,
    pub event_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfq_event_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_event_id: Option<Uuid>,
    pub body: RefusalBody,
}

/// One message of this wire. `kind` names the variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Message {
    #[serde(rename = "paykit-cap.rfq")]
    Rfq(Rfq),
    #[serde(rename = "paykit-cap.quote")]
    Quote(Quote),
    #[serde(rename = "paykit-cap.commit")]
    Commit(Box<Commit>),
    #[serde(rename = "paykit-cap.contract")]
    Contract(Box<Contract>),
    #[serde(rename = "paykit-cap.status")]
    Status(Status),
    #[serde(rename = "paykit-cap.status_request")]
    StatusRequest(StatusRequest),
    #[serde(rename = "paykit-cap.refusal")]
    Refusal(Refusal),
}

impl Message {
    /// Read a message as a closed object. serde cannot refuse unknown members beside a flattened
    /// envelope, so the parsed message must serialize back to exactly what arrived.
    pub fn parse(value: Value) -> Result<Self, CapError> {
        let message: Self = serde_json::from_value(value.clone())
            .map_err(|e| CapError::Canonical(e.to_string()))?;
        if serde_json::to_value(&message).map_err(canonical)? != value {
            return Err(CapError::Unexpected("members this kind does not define"));
        }
        Ok(message)
    }

    pub fn envelope(&self) -> &Envelope {
        match self {
            Self::Rfq(m) => &m.envelope,
            Self::Quote(m) => &m.envelope,
            Self::Commit(m) => &m.envelope,
            Self::Contract(m) => &m.envelope,
            Self::Status(m) => &m.envelope,
            Self::StatusRequest(m) => &m.envelope,
            Self::Refusal(m) => &m.envelope,
        }
    }

    pub fn event_id(&self) -> Uuid {
        match self {
            Self::Rfq(m) => m.event_id,
            Self::Quote(m) => m.event_id,
            Self::Commit(m) => m.event_id,
            Self::Contract(m) => m.event_id,
            Self::Status(m) => m.event_id,
            Self::StatusRequest(m) => m.event_id,
            Self::Refusal(m) => m.event_id,
        }
    }
}

fn canonical(error: serde_json::Error) -> CapError {
    CapError::Canonical(error.to_string())
}

fn domain_hash(domain: &[u8], value: &Value) -> Result<[u8; 32], CapError> {
    let mut preimage = domain.to_vec();
    preimage.extend(jcs(value)?);
    Ok(sha256::Hash::hash(&preimage).to_byte_array())
}

/// SHA-256 over `paykit-cap/commit/v1 || 0x00 || JCS({terms_hash, body})` (§10.2).
pub fn commit_hash(terms_hash_hex: &str, body: &CommitBody) -> Result<[u8; 32], CapError> {
    let value = serde_json::json!({ "terms_hash": terms_hash_hex, "body": body });
    domain_hash(COMMIT_DOMAIN, &value)
}

/// SHA-256 over `paykit-cap/contract/v1 || 0x00 || JCS({commit_hash, body})` (§10.2).
pub fn contract_hash(commit_hash_hex: &str, body: &ContractBody) -> Result<[u8; 32], CapError> {
    let value = serde_json::json!({ "commit_hash": commit_hash_hex, "body": body });
    domain_hash(CONTRACT_DOMAIN, &value)
}

/// An Ed25519 signature over `hash`, as unpadded base64url (§5).
pub fn sign(signer: &dyn CapSigner, hash: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(signer.sign(hash))
}

/// Check a base64url `sig` over `hash` by `key`, the signer's key for the generation the object
/// names. There is no `signer` member: the generation and its delegation say whose key it is.
pub fn verify(key: &[u8; 32], hash: &[u8; 32], sig: &str) -> Result<(), CapError> {
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(sig)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(CapError::BadSignature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| CapError::BadSignature)?;
    key.verify_strict(hash, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| CapError::BadSignature)
}

/// The quote message's members the terms cover.
pub fn quote_terms(quote: &Quote) -> QuoteTerms {
    QuoteTerms {
        body: quote.body.clone(),
        atomicity: quote.atomicity.clone(),
        valid_until: quote.valid_until,
    }
}

/// The RFQ message's members the terms cover.
pub fn rfq_terms(rfq: &Rfq) -> RfqTerms {
    RfqTerms {
        body: rfq.body.clone(),
        atomicity_min: rfq.atomicity_min.clone(),
        respond_by: rfq.respond_by,
        valid_until: rfq.valid_until,
    }
}

/// The terms a quote answering `rfq` from `owner` carries, between the two generations the
/// envelopes name.
pub fn terms(owner: &str, rfq: &Rfq, provider: &str, quote: &Quote) -> Terms {
    Terms {
        owner: owner.into(),
        owner_key_generation: rfq.envelope.key_generation,
        provider: provider.into(),
        provider_key_generation: quote.envelope.key_generation,
        profile: rfq.envelope.profile.clone(),
        flow_id: rfq.envelope.flow_id,
        rfq: rfq_terms(rfq),
        quote: quote_terms(quote),
    }
}

impl SignedTerms {
    /// Check the terms against the commit carrying them, and the provider's `sig` with
    /// `provider_key`, its key for `terms.provider_key_generation`. Expiry is the caller's.
    pub fn check(&self, commit: &Commit, provider_key: &[u8; 32]) -> Result<(), CapError> {
        let hash = self.terms.hash()?;
        if hex::encode(hash) != commit.terms_hash {
            return Err(CapError::HashMismatch("terms_hash"));
        }
        if self.terms.profile != commit.envelope.profile
            || self.terms.flow_id != commit.envelope.flow_id
        {
            return Err(CapError::Unexpected("terms for another profile or flow"));
        }
        if self.terms.owner_key_generation != commit.envelope.key_generation {
            return Err(CapError::Unexpected("terms for another key generation"));
        }
        verify(provider_key, &hash, &self.sig)
    }
}

impl Commit {
    pub fn commit_hash(&self) -> Result<[u8; 32], CapError> {
        commit_hash(&self.terms_hash, &self.body)
    }

    /// The owner signs `commit_hash` with its capability signing key for this generation.
    pub fn sign(&mut self, owner: &dyn CapSigner) -> Result<(), CapError> {
        self.sig = Some(sign(owner, &self.commit_hash()?));
        Ok(())
    }

    /// Check the owner's `sig` with `owner_key`, its key for the envelope's generation.
    pub fn verify_owner(&self, owner_key: &[u8; 32]) -> Result<(), CapError> {
        let sig = self.sig.as_deref().ok_or(CapError::BadSignature)?;
        verify(owner_key, &self.commit_hash()?, sig)
    }
}

/// The contract body for `accept`, and the sealed invoice it binds.
pub fn contract_body(
    accept: &SwapAccept,
    invoice_blob: Option<&InvoiceBlob>,
) -> Result<ContractBody, CapError> {
    Ok(ContractBody {
        swap_id: accept.swap_id,
        lock_profile: accept.script_type,
        onchain_amount_sat: Sat(accept.onchain_amount_sat),
        timeout_block_height: accept.timeout_block_height,
        provider_pubkey: accept.provider_pubkey_hex.clone(),
        invoice_blob: invoice_blob.map(InvoiceBlob::hash).transpose()?,
    })
}

impl Contract {
    /// Recompute `contract_hash` and check the provider's `sig` with `provider_key`.
    pub fn verify(&self, provider_key: &[u8; 32]) -> Result<[u8; 32], CapError> {
        let hash = contract_hash(&self.commit_hash, &self.body)?;
        verify(provider_key, &hash, &self.sig)?;
        Ok(hash)
    }

    /// The engine's acceptance for a commit on `terms`, after the blob checks out.
    pub fn open(&self, terms: &Terms) -> Result<SwapAccept, CapError> {
        let invoice = match (&self.body.invoice_blob, &self.invoice_blob) {
            (None, None) => None,
            (Some(hash), Some(blob)) if blob.hash()? == *hash => Some(blob.open()?),
            _ => return Err(CapError::HashMismatch("invoice_blob")),
        };
        Ok(SwapAccept {
            script_type: self.body.lock_profile,
            swap_tree: self.lock.swap_tree.clone(),
            quote_id: terms.quote.body.quote_id,
            swap_id: self.body.swap_id,
            direction: terms.quote.body.dir,
            htlc_script_hex: self.lock.htlc_script_hex.clone(),
            htlc_address: self.lock.htlc_address.clone(),
            onchain_amount_sat: self.body.onchain_amount_sat.0,
            timeout_block_height: self.body.timeout_block_height,
            provider_pubkey_hex: self.body.provider_pubkey.clone(),
            invoice,
        })
    }
}

/// The lock details #119 will leave out.
pub fn lock(accept: &SwapAccept) -> Lock {
    Lock {
        htlc_address: accept.htlc_address.clone(),
        htlc_script_hex: accept.htlc_script_hex.clone(),
        swap_tree: accept.swap_tree.clone(),
    }
}

/// Whether `atomicity_min` is a class `hash` meets. `hash` is the strongest, so that is every
/// class §11 names, and an unknown one is refused.
pub fn atomicity_met(atomicity_min: &str) -> bool {
    ATOMICITY_CLASSES.contains(&atomicity_min)
}

/// The on-chain identifier's network segment for `network`, as the descriptor publishes it.
pub fn is_edge(offer: &crate::messages::SwapOffer, body: &RfqBody) -> bool {
    use crate::cap_descriptor::{onchain_rail, LIGHTNING_IDENTIFIER, ONCHAIN_FORMATS};
    if !offer.supports(body.dir) {
        return false;
    }
    let (lightning, onchain) = match body.dir {
        SwapDirection::Reverse => (&body.from, &body.to),
        SwapDirection::Submarine => (&body.to, &body.from),
    };
    let rail = onchain_rail(offer.network);
    lightning == LIGHTNING_IDENTIFIER
        && ONCHAIN_FORMATS
            .iter()
            .any(|format| *onchain == format!("btc-{rail}-{format}"))
}

#[cfg(test)]
mod tests;

/// The App ID the client puts in its envelopes.
pub const CLIENT_APP_ID: &str = "pubky-swap-client";

/// The on-chain format a reverse RFQ asks to receive and a submarine one pays from. The provider
/// takes any format on its rail.
const CLIENT_ONCHAIN_FORMAT: &str = "p2wpkh";

/// Client-side translation for this wire: [`SwapMessage`] requests into kinds, and replies back
/// after their signatures and hashes check out. Offers, listings, wake grants and status queries
/// stay native [`SwapMessage`]s, which a `paykit-cap.status` cannot stand in for.
#[derive(Debug)]
pub struct Client {
    owner: String,
    provider: String,
    /// The owner's generation in every envelope. 0 is a root key with no delegation, whose
    /// commits go unsigned.
    key_generation: u64,
    /// The provider's signing key by generation: the key the client dialed at 0, and any
    /// capability signing key whose delegation the caller checked.
    provider_keys: Vec<(u64, [u8; 32])>,
    /// The offer's network, which names the edges an RFQ asks for.
    network: Option<crate::swap::NetworkSpec>,
    /// The offer's on-chain fee rate, which the profile's quote does not carry.
    fee_rate_sat_vb: u64,
    /// Each RFQ sent, by request id, so a retry is the same event.
    rfqs: std::collections::HashMap<Uuid, Rfq>,
    /// Each quote taken: its terms and the quote message, by quote id.
    quotes: std::collections::HashMap<Uuid, (Terms, Quote)>,
    /// The commit sent for each quote, so a replay is the same event.
    commits: std::collections::HashMap<Uuid, Commit>,
}

impl Client {
    pub fn new(owner: String, provider: String, provider_root_key: Option<[u8; 32]>) -> Self {
        Self {
            owner,
            provider,
            key_generation: 0,
            provider_keys: provider_root_key.map(|key| (0, key)).into_iter().collect(),
            network: None,
            fee_rate_sat_vb: 0,
            rfqs: Default::default(),
            quotes: Default::default(),
            commits: Default::default(),
        }
    }

    /// Note the offer, whose network an RFQ's edges name.
    pub fn observe(&mut self, reply: &SwapMessage) {
        if let SwapMessage::Offer(offer) = reply {
            self.network = Some(offer.network);
            self.fee_rate_sat_vb = offer.fee_rate_sat_vb;
        }
    }

    /// Accept `key` as the provider's for `generation`, once its delegation has been checked.
    pub fn allow_key(&mut self, generation: u64, key: [u8; 32]) {
        self.provider_keys.retain(|(g, _)| *g != generation);
        self.provider_keys.push((generation, key));
    }

    /// The provider generation a reply is signed under, when this client has no key for it.
    pub fn missing_key(&self, reply: &Message) -> Option<u64> {
        let generation = match reply {
            Message::Quote(_) | Message::Contract(_) => reply.envelope().key_generation,
            _ => return None,
        };
        self.key(generation).is_err().then_some(generation)
    }

    fn key(&self, generation: u64) -> Result<[u8; 32], CapError> {
        self.provider_keys
            .iter()
            .find(|(g, _)| *g == generation)
            .map(|(_, key)| *key)
            .ok_or(CapError::UnexpectedSigner)
    }

    fn envelope(&self, flow_id: Uuid) -> Envelope {
        Envelope::new(CLIENT_APP_ID, flow_id, self.key_generation)
    }

    /// The kind to send for `request`. `None` means send it as a plain [`SwapMessage`].
    pub fn request(&mut self, request: &SwapMessage) -> Option<Message> {
        match request {
            SwapMessage::QuoteRequest(request) => {
                if let Some(sent) = request.request_id.and_then(|id| self.rfqs.get(&id)) {
                    return Some(Message::Rfq(sent.clone()));
                }
                let rail = crate::cap_descriptor::onchain_rail(self.network?);
                let onchain = format!("btc-{rail}-{CLIENT_ONCHAIN_FORMAT}");
                let lightning = crate::cap_descriptor::LIGHTNING_IDENTIFIER.to_string();
                let (from, to) = match request.direction {
                    SwapDirection::Reverse => (lightning, onchain),
                    SwapDirection::Submarine => (onchain, lightning),
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let rfq = Rfq {
                    envelope: self.envelope(Uuid::new_v4()),
                    event_id: request.request_id.unwrap_or_else(Uuid::new_v4),
                    body: RfqBody {
                        offer_id: request.offer_id,
                        dir: request.direction,
                        from,
                        to,
                        amount_sat: Sat(request.amount_sat),
                    },
                    atomicity_min: ATOMICITY.into(),
                    respond_by: now + 60,
                    valid_until: now + 300,
                };
                if let Some(id) = request.request_id {
                    self.rfqs.insert(id, rfq.clone());
                }
                Some(Message::Rfq(rfq))
            }
            SwapMessage::SwapRequest(request) => {
                let body = commit_body(request);
                if let Some(sent) = self.commits.get(&request.quote_id) {
                    if sent.body == body {
                        return Some(Message::Commit(Box::new(sent.clone())));
                    }
                }
                let (terms, quote) = self.quotes.get(&request.quote_id)?;
                let commit = Commit {
                    envelope: self.envelope(terms.flow_id),
                    event_id: Uuid::new_v4(),
                    quote_event_id: quote.event_id,
                    terms_hash: hex::encode(terms.hash().ok()?),
                    body,
                    quote: Some(SignedTerms {
                        terms: terms.clone(),
                        sig: quote.sig.clone(),
                    }),
                    sig: None,
                };
                self.commits.insert(request.quote_id, commit.clone());
                Some(Message::Commit(Box::new(commit)))
            }
            _ => None,
        }
    }

    /// Check `reply` against `request` and `sent`, the kind sent for it, and translate it.
    pub fn reply(
        &mut self,
        request: &SwapMessage,
        sent: &Message,
        reply: Message,
    ) -> Result<SwapMessage, CapError> {
        if reply.envelope().profile != PROFILE || reply.envelope().version != VERSION {
            return Err(CapError::Unexpected("a reply under another profile"));
        }
        match (request, sent, reply) {
            (_, _, Message::Refusal(refusal)) => Ok(SwapMessage::Reject(Reject {
                code: Some(refusal.body.code),
                request_id: request_id(request),
                swap_id: None,
                quote_id: match request {
                    SwapMessage::SwapRequest(request) => Some(request.quote_id),
                    _ => None,
                },
                reason: refusal.body.reason,
            })),
            (SwapMessage::QuoteRequest(request), Message::Rfq(rfq), Message::Quote(quote)) => {
                if quote.rfq_event_id != rfq.event_id
                    || quote.envelope.flow_id != rfq.envelope.flow_id
                {
                    return Err(CapError::Unexpected("a quote for another rfq"));
                }
                let body = &quote.body;
                if body.dir != rfq.body.dir
                    || body.amount_sat != rfq.body.amount_sat
                    || (!rfq.body.offer_id.is_nil() && body.offer_id != rfq.body.offer_id)
                {
                    return Err(CapError::Unexpected("a quote on other terms than asked"));
                }
                let terms = terms(&self.owner, rfq, &self.provider, &quote);
                verify(
                    &self.key(quote.envelope.key_generation)?,
                    &terms.hash()?,
                    &quote.sig,
                )?;
                let native = crate::messages::Quote {
                    request_id: request.request_id,
                    quote_id: body.quote_id,
                    offer_id: body.offer_id,
                    direction: body.dir,
                    amount_sat: body.amount_sat.0,
                    fee_sat: body.service_fee_sat.0 + body.onchain_fee_sat.0,
                    service_fee_sat: body.service_fee_sat.0,
                    onchain_fee_sat: body.onchain_fee_sat.0,
                    fee_rate_sat_vb: self.fee_rate_sat_vb,
                    total_sat: body.total_sat.0,
                    htlc_timeout_blocks: body.htlc_timeout_blocks,
                    required_confirmations: body.required_confirmations,
                    valid_until_unix: quote.valid_until,
                    fund_within_secs: body.fund_within_secs,
                    protocol_version: crate::messages::PROTOCOL_VERSION,
                };
                self.quotes.insert(body.quote_id, (terms, quote));
                Ok(SwapMessage::Quote(native))
            }
            (SwapMessage::SwapRequest(request), Message::Commit(commit), Message::Contract(c)) => {
                Ok(SwapMessage::SwapAccept(self.opened(
                    request.quote_id,
                    commit,
                    &c,
                )?))
            }
            (SwapMessage::SwapRequest(request), Message::Commit(commit), Message::Status(s))
                if s.commit_event_id == Some(commit.event_id) =>
            {
                Ok(SwapMessage::Reject(Reject {
                    code: Some(crate::messages::RejectCode::Pending.as_str().into()),
                    request_id: None,
                    swap_id: Some(s.body.swap_id),
                    quote_id: Some(request.quote_id),
                    reason: "the swap is still being admitted".into(),
                }))
            }
            _ => Err(CapError::Unexpected("kind")),
        }
    }

    /// The commit sent for `quote_id`. A creation whose contract was lost sends it again, and the
    /// provider answers the same event with the contract it signed first.
    pub fn sent_commit(&self, quote_id: Uuid) -> Option<Commit> {
        self.commits.get(&quote_id).cloned()
    }

    /// The swap a contract for the commit sent for `quote_id` accepts, once it checks out.
    pub fn recovered(&self, quote_id: Uuid, reply: &Message) -> Result<SwapAccept, CapError> {
        let commit = self
            .commits
            .get(&quote_id)
            .ok_or(CapError::Unexpected("no commit was sent for this quote"))?;
        match reply {
            Message::Contract(c)
                if c.envelope.profile == PROFILE && c.envelope.version == VERSION =>
            {
                self.opened(quote_id, commit, c)
            }
            _ => Err(CapError::Unexpected("kind")),
        }
    }

    fn opened(
        &self,
        quote_id: Uuid,
        commit: &Commit,
        c: &Contract,
    ) -> Result<SwapAccept, CapError> {
        if c.commit_event_id != commit.event_id
            || c.commit_hash != hex::encode(commit.commit_hash()?)
        {
            return Err(CapError::HashMismatch("commit_hash"));
        }
        if c.envelope.flow_id != commit.envelope.flow_id {
            return Err(CapError::Unexpected("a contract for another flow"));
        }
        c.verify(&self.key(c.envelope.key_generation)?)?;
        let (terms, _) = self
            .quotes
            .get(&quote_id)
            .ok_or(CapError::Unexpected("contract for an unsigned quote"))?;
        let accept = c.open(terms)?;
        if accept.quote_id != quote_id {
            return Err(CapError::Unexpected("contract for another quote"));
        }
        Ok(accept)
    }
}

fn commit_body(request: &crate::messages::SwapRequest) -> CommitBody {
    CommitBody {
        lock_profile: request.script_type,
        payment_hash: request.payment_hash_hex.clone(),
        claim_pubkey: request.client_claim_pubkey_hex.clone(),
        refund_pubkey: request.client_refund_pubkey_hex.clone(),
        invoice: request.invoice.clone(),
        owner_ref: request.owner_ref.clone(),
    }
}

fn request_id(request: &SwapMessage) -> Option<Uuid> {
    match request {
        SwapMessage::QuoteRequest(request) => request.request_id,
        _ => None,
    }
}
