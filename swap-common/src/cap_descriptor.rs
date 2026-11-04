//! The provider's public `swap/1` Capability Descriptor (Paykit Capabilities §6 and §13.1).
//!
//! Built from the current [`SwapOffer`], so a wallet reading a provider's homeserver learns its
//! directions, bounds and indicative fees without asking for an offer. It binds nothing: only a
//! signed quote does.

use crate::messages::{SwapOffer, PAYKIT_CAP_FEATURE};
use crate::paykit_cap::{jcs, CapError, CapSigner};
use crate::swap::{NetworkSpec, SwapDirection};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DESCRIPTOR_KIND: &str = "paykit-cap.descriptor";
pub const DESCRIPTOR_VERSION: u8 = 1;
/// Signed as `domain || 0x00 || JCS(descriptor without sig)` (§5).
pub const DESCRIPTOR_DOMAIN: &[u8] = b"paykit-cap/descriptor/v1\0";
/// The App ID every pubky-swap descriptor names; it has to be in the owner's App Registry.
pub const DESCRIPTOR_APP_ID: &str = "pubky-swap";
/// One file per App ID, outside `/pub/paykit/v0/` so payment resolution never lists it.
pub const DESCRIPTOR_PATH: &str = "/pub/paykit/ext/capabilities/v1/apps/pubky-swap.json";
/// The most a descriptor file may hold (§6.2).
pub const DESCRIPTOR_MAX_BYTES: usize = 65_536;
/// The most edges one profile entry may carry (§6.2).
pub const DESCRIPTOR_MAX_EDGES: usize = 64;
pub const SWAP_PROFILE: &str = "swap/1";
/// The offer feature of a provider that can lock a Boltz-compatible Taproot contract.
pub const BOLTZ_TAPROOT_FEATURE: &str = "boltz-taproot-v1";
/// The iroh ALPN a newcomer dials, and the RFQ carrier for the `paykit-cap.*` kinds.
pub const DIRECT_ALPN: &str = "pubky-swap/direct/1";
/// The offer feature of a provider that listens on [`DIRECT_ALPN`].
pub const DIRECT_RPC_FEATURE: &str = "direct-rpc-v1";

/// The Lightning side of every edge. A BOLT 11 invoice names its own network, and
/// `terms.network` names it for the whole entry, so this identifier is the same on every network.
pub const LIGHTNING_IDENTIFIER: &str = "btc-lightning-bolt11";

/// Every on-chain output type a swap can pay or be funded from. A reverse claim pays whatever
/// address the owner gives it, and a submarine lockup can be funded from any wallet, so each edge
/// is listed once per type: identifiers are compared byte for byte and cannot be wildcards.
pub const ONCHAIN_FORMATS: [&str; 5] = ["p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2tr"];

/// The rail segment of an on-chain identifier. Test networks name their own rail
/// (`btc-regtest-p2wpkh`, `btc-signet-p2tr`), so a test descriptor can never be read as mainnet
/// liquidity, the rule `swap/1` settled on pubky/paykit-rs#229.
pub fn onchain_rail(network: NetworkSpec) -> &'static str {
    match network {
        NetworkSpec::Bitcoin => "bitcoin",
        NetworkSpec::Testnet => "testnet",
        NetworkSpec::Signet => "signet",
        NetworkSpec::Regtest => "regtest",
    }
}

/// Whether `identifier` is a Payment Endpoint Identifier: three non-empty segments of lowercase
/// ASCII letters and digits, joined by `-`.
pub fn is_endpoint_identifier(identifier: &str) -> bool {
    let segments: Vec<&str> = identifier.split('-').collect();
    segments.len() == 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// A signed descriptor file. Closed: an unknown member makes it unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub kind: String,
    /// The provider's identity, bare z-base-32.
    pub owner: String,
    pub app_id: String,
    pub key_generation: u64,
    /// Rises on every rewrite. Readers drop one lower than the highest they have seen.
    pub seq: u64,
    pub created_at: u64,
    pub valid_until: u64,
    pub profiles: Vec<SwapProfile>,
    pub contact: Contact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// The `swap/1` entry. The only profile this app publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapProfile {
    pub profile: String,
    pub role: String,
    pub edges: Vec<Edge>,
    pub terms: SwapTerms,
}

/// One direction between two exact identifiers. Amounts are base-unit integer strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub dir: SwapDirection,
    /// [`SwapOffer::effective_min_amount_sat`], which the provider enforces.
    pub min: String,
    pub max: String,
    pub unit: String,
    pub fee: EdgeFee,
    pub atomicity: String,
    pub lock_profiles: Vec<String>,
    pub sides: Vec<String>,
    pub fund_within_secs: u64,
}

/// `base + floor(amount × ppm / 1,000,000) + onchain`, which is [`SwapOffer::quote_fee`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeFee {
    pub base: String,
    pub ppm: String,
    pub onchain: String,
}

impl EdgeFee {
    /// The indicative fee for `amount_sat`, as §6.2 defines it.
    pub fn indicative_sat(&self, amount_sat: u64) -> Option<u64> {
        let base: u64 = self.base.parse().ok()?;
        let ppm: u64 = self.ppm.parse().ok()?;
        let onchain: u64 = self.onchain.parse().ok()?;
        let proportional = (u128::from(amount_sat) * u128::from(ppm) / 1_000_000) as u64;
        Some(base.saturating_add(proportional).saturating_add(onchain))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapTerms {
    /// Valid until `valid_until`; an RFQ may also name the nil id to take whatever is current.
    pub offer_id: Uuid,
    pub network: NetworkSpec,
    pub htlc_timeout_blocks: u32,
    pub required_confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub rfq: Vec<String>,
    pub intro: Vec<Intro>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intro {
    #[serde(rename = "type")]
    pub kind: String,
    pub alpn: String,
}

/// Who publishes, and which rewrite this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    pub owner: String,
    pub key_generation: u64,
    pub seq: u64,
    pub created_at: u64,
}

/// The lock profiles an offer can lock: `taproot_boltz` only behind its feature, `p2wsh` always.
pub fn lock_profiles(offer: &SwapOffer) -> Vec<String> {
    let mut profiles = Vec::new();
    if offer.features.iter().any(|f| f == BOLTZ_TAPROOT_FEATURE) {
        profiles.push("taproot_boltz".to_string());
    }
    profiles.push("p2wsh".to_string());
    profiles
}

/// The unsigned descriptor for `offer`. It lapses with the offer, whose id it names.
pub fn build(offer: &SwapOffer, publication: &Publication) -> Descriptor {
    let rail = onchain_rail(offer.network);
    let fee = EdgeFee {
        base: offer.base_fee_sat.to_string(),
        ppm: offer.fee_ppm.to_string(),
        onchain: offer.onchain_fee_sat.to_string(),
    };
    let edge = |from: String, to: String, dir: SwapDirection| Edge {
        from,
        to,
        dir,
        min: offer.effective_min_amount_sat().to_string(),
        max: offer.max_amount_sat.to_string(),
        unit: "sat".into(),
        fee: fee.clone(),
        atomicity: "hash".into(),
        lock_profiles: lock_profiles(offer),
        // `swap/1` v1 is `exact_out` only (§13.1).
        sides: vec!["exact_out".into()],
        fund_within_secs: offer.fund_within_secs,
    };
    let mut edges = Vec::new();
    for dir in [SwapDirection::Reverse, SwapDirection::Submarine] {
        if !offer.supports(dir) {
            continue;
        }
        for format in ONCHAIN_FORMATS {
            let onchain = format!("btc-{rail}-{format}");
            edges.push(match dir {
                SwapDirection::Reverse => edge(LIGHTNING_IDENTIFIER.into(), onchain, dir),
                SwapDirection::Submarine => edge(onchain, LIGHTNING_IDENTIFIER.into(), dir),
            });
        }
    }
    let has = |feature: &str| offer.features.iter().any(|f| f == feature);
    // A provider without the iroh rendezvous does not listen on `direct/1` at all, and one
    // without `paykit-cap-v1` drops the kinds there unanswered.
    let rfq = if has(PAYKIT_CAP_FEATURE) && has(DIRECT_RPC_FEATURE) {
        vec![format!("iroh:{DIRECT_ALPN}")]
    } else {
        Vec::new()
    };
    let intro = if has(DIRECT_RPC_FEATURE) {
        vec![Intro {
            kind: "iroh".into(),
            alpn: DIRECT_ALPN.into(),
        }]
    } else {
        Vec::new()
    };
    Descriptor {
        version: DESCRIPTOR_VERSION,
        kind: DESCRIPTOR_KIND.into(),
        owner: publication.owner.clone(),
        app_id: DESCRIPTOR_APP_ID.into(),
        key_generation: publication.key_generation,
        seq: publication.seq,
        created_at: publication.created_at,
        valid_until: offer.valid_until_unix,
        profiles: vec![SwapProfile {
            profile: SWAP_PROFILE.into(),
            role: "provider".into(),
            edges,
            terms: SwapTerms {
                offer_id: offer.offer_id,
                network: offer.network,
                htlc_timeout_blocks: offer.htlc_timeout_blocks,
                required_confirmations: offer.required_confirmations,
            },
        }],
        contact: Contact { rfq, intro },
        sig: None,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DescriptorError {
    #[error(transparent)]
    Cap(#[from] CapError),
    #[error("descriptor is {0} bytes, over the {DESCRIPTOR_MAX_BYTES}-byte limit")]
    TooLarge(usize),
    #[error("descriptor carries {0} edges, over the {DESCRIPTOR_MAX_EDGES}-edge limit")]
    TooManyEdges(usize),
    #[error("descriptor expired at {0}")]
    Expired(u64),
    #[error("{0} is not a Payment Endpoint Identifier")]
    Identifier(String),
    #[error("descriptor is not signed")]
    Unsigned,
}

impl Descriptor {
    /// What the signature covers: the domain, then the JCS form without `sig`.
    pub fn signing_input(&self) -> Result<Vec<u8>, CapError> {
        let unsigned = Self {
            sig: None,
            ..self.clone()
        };
        let mut input = DESCRIPTOR_DOMAIN.to_vec();
        input.extend(jcs(&unsigned)?);
        Ok(input)
    }

    /// Sign with `signer` and return the file's bytes, refusing one a reader would reject.
    pub fn sign(mut self, signer: &dyn CapSigner) -> Result<(Self, Vec<u8>), DescriptorError> {
        self.check_shape()?;
        let input = self.signing_input()?;
        self.sig = Some(URL_SAFE_NO_PAD.encode(signer.sign(&input)));
        let bytes = jcs(&self)?;
        if bytes.len() > DESCRIPTOR_MAX_BYTES {
            return Err(DescriptorError::TooLarge(bytes.len()));
        }
        Ok((self, bytes))
    }

    /// Check `sig` against `signer_hex`, the key the owner authorized.
    pub fn verify(&self, signer_hex: &str) -> Result<(), DescriptorError> {
        let sig = self.sig.as_deref().ok_or(DescriptorError::Unsigned)?;
        let signature = URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| CapError::BadSignature)?;
        let key: [u8; 32] = hex::decode(signer_hex)
            .ok()
            .and_then(|key| key.try_into().ok())
            .ok_or(CapError::BadSignature)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| CapError::BadSignature)?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| CapError::BadSignature)?;
        key.verify_strict(
            &self.signing_input()?,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| DescriptorError::Cap(CapError::BadSignature))
    }

    /// Whether a reader would still use it at `now`.
    pub fn is_current(&self, now: u64) -> bool {
        now < self.valid_until
    }

    fn check_shape(&self) -> Result<(), DescriptorError> {
        for profile in &self.profiles {
            if profile.edges.len() > DESCRIPTOR_MAX_EDGES {
                return Err(DescriptorError::TooManyEdges(profile.edges.len()));
            }
            for id in profile.edges.iter().flat_map(|e| [&e.from, &e.to]) {
                if !is_endpoint_identifier(id) {
                    return Err(DescriptorError::Identifier(id.clone()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{SwapOffer, PROTOCOL_VERSION};
    use crate::paykit_cap::Ed25519Signer;

    fn offer(features: &[&str]) -> SwapOffer {
        SwapOffer {
            request_id: None,
            offer_id: Uuid::from_u128(0x9a1f3c2e_7b4d_4e8a_9c1f_3d2b6a4e7c11),
            provider_pkarr: "provider".into(),
            network: NetworkSpec::Bitcoin,
            directions: vec![SwapDirection::Submarine, SwapDirection::Reverse],
            min_amount_sat: 10_000,
            max_amount_sat: 5_000_000,
            base_fee_sat: 100,
            fee_ppm: 2_500,
            required_confirmations: 2,
            htlc_timeout_blocks: 144,
            lightning_node_id: None,
            valid_until_unix: 1_793_000_300,
            fund_within_secs: 120,
            // Ten times this is above the configured minimum, so the effective one moves.
            onchain_fee_sat: 3_100,
            fee_rate_sat_vb: 10,
            protocol_version: PROTOCOL_VERSION,
            features: features.iter().map(|f| f.to_string()).collect(),
        }
    }

    fn publication(seq: u64) -> Publication {
        Publication {
            owner: "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo".into(),
            key_generation: 1,
            seq,
            created_at: 1_793_000_000,
        }
    }

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_secret(&[3; 32])
    }

    #[test]
    fn every_field_comes_from_the_offer() {
        let offer = offer(&[
            BOLTZ_TAPROOT_FEATURE,
            DIRECT_RPC_FEATURE,
            PAYKIT_CAP_FEATURE,
        ]);
        let descriptor = build(&offer, &publication(7));
        assert_eq!(descriptor.version, 1);
        assert_eq!(descriptor.kind, "paykit-cap.descriptor");
        assert_eq!(descriptor.app_id, "pubky-swap");
        assert_eq!(descriptor.owner, publication(7).owner);
        assert_eq!(descriptor.key_generation, 1);
        assert_eq!(descriptor.seq, 7);
        assert_eq!(descriptor.created_at, 1_793_000_000);
        assert_eq!(descriptor.valid_until, offer.valid_until_unix);

        let [profile] = descriptor.profiles.as_slice() else {
            panic!("one profile entry");
        };
        assert_eq!(profile.profile, "swap/1");
        assert_eq!(profile.role, "provider");
        assert_eq!(
            profile.terms,
            SwapTerms {
                offer_id: offer.offer_id,
                network: NetworkSpec::Bitcoin,
                htlc_timeout_blocks: 144,
                required_confirmations: 2,
            }
        );
        // The configured 10,000 is raised to ten times the on-chain cost.
        assert_eq!(offer.effective_min_amount_sat(), 31_000);
        assert_eq!(profile.edges.len(), 2 * ONCHAIN_FORMATS.len());
        for edge in &profile.edges {
            assert_eq!(edge.min, offer.effective_min_amount_sat().to_string());
            assert_eq!(edge.max, "5000000");
            assert_eq!(edge.unit, "sat");
            assert_eq!(edge.atomicity, "hash");
            assert_eq!(edge.sides, ["exact_out"]);
            assert_eq!(edge.fund_within_secs, 120);
            assert_eq!(edge.lock_profiles, ["taproot_boltz", "p2wsh"]);
            for amount in [31_000, 250_000, 1_234_567, 5_000_000] {
                assert_eq!(
                    edge.fee.indicative_sat(amount),
                    Some(offer.quote_fee(amount).total_fee_sat),
                    "{amount}"
                );
            }
            let (lightning, onchain) = match edge.dir {
                SwapDirection::Reverse => (&edge.from, &edge.to),
                SwapDirection::Submarine => (&edge.to, &edge.from),
            };
            assert_eq!(lightning, "btc-lightning-bolt11");
            assert!(onchain.starts_with("btc-bitcoin-"), "{onchain}");
            assert!(is_endpoint_identifier(onchain), "{onchain}");
        }
        for dir in [SwapDirection::Reverse, SwapDirection::Submarine] {
            let mut covered: Vec<&str> = profile
                .edges
                .iter()
                .filter(|e| e.dir == dir)
                .map(|e| match dir {
                    SwapDirection::Reverse => e.to.as_str(),
                    SwapDirection::Submarine => e.from.as_str(),
                })
                .collect();
            covered.sort();
            assert_eq!(
                covered,
                [
                    "btc-bitcoin-p2pkh",
                    "btc-bitcoin-p2sh",
                    "btc-bitcoin-p2tr",
                    "btc-bitcoin-p2wpkh",
                    "btc-bitcoin-p2wsh"
                ]
            );
        }
        assert_eq!(descriptor.contact.rfq, ["iroh:pubky-swap/direct/1"]);
        assert_eq!(
            descriptor.contact.intro,
            [Intro {
                kind: "iroh".into(),
                alpn: "pubky-swap/direct/1".into(),
            }]
        );
    }

    #[test]
    fn an_offer_without_taproot_never_advertises_it() {
        for features in [&[][..], &["swap-status-v1", "boltz-taproot-v2"][..]] {
            let descriptor = build(&offer(features), &publication(1));
            let (_, bytes) = descriptor.sign(&signer()).unwrap();
            assert!(!String::from_utf8(bytes).unwrap().contains("taproot_boltz"));
        }
    }

    #[test]
    fn only_offered_directions_get_edges() {
        let mut reverse_only = offer(&[DIRECT_RPC_FEATURE]);
        reverse_only.directions = vec![SwapDirection::Reverse];
        let descriptor = build(&reverse_only, &publication(1));
        assert!(descriptor.profiles[0]
            .edges
            .iter()
            .all(|e| e.dir == SwapDirection::Reverse && e.from == LIGHTNING_IDENTIFIER));
        // No `paykit-cap-v1`, so no RFQ carrier is named; the doorbell still is.
        assert!(descriptor.contact.rfq.is_empty());
        assert_eq!(descriptor.contact.intro.len(), 1);
    }

    #[test]
    fn a_provider_not_on_direct_1_names_no_contact_there() {
        let descriptor = build(&offer(&[PAYKIT_CAP_FEATURE]), &publication(1));
        assert!(descriptor.contact.rfq.is_empty());
        assert!(descriptor.contact.intro.is_empty());
    }

    #[test]
    fn test_networks_name_their_own_rail() {
        for (network, rail) in [
            (NetworkSpec::Regtest, "btc-regtest-"),
            (NetworkSpec::Signet, "btc-signet-"),
            (NetworkSpec::Testnet, "btc-testnet-"),
        ] {
            let mut test_offer = offer(&[]);
            test_offer.network = network;
            let descriptor = build(&test_offer, &publication(1));
            assert_eq!(descriptor.profiles[0].terms.network, network);
            for edge in &descriptor.profiles[0].edges {
                let onchain = if edge.dir == SwapDirection::Reverse {
                    &edge.to
                } else {
                    &edge.from
                };
                assert!(onchain.starts_with(rail), "{onchain}");
                assert!(!onchain.contains("bitcoin"), "{onchain}");
            }
        }
    }

    #[test]
    fn identifiers_follow_the_grammar() {
        assert!(is_endpoint_identifier("btc-regtest-p2wpkh"));
        assert!(!is_endpoint_identifier("btc-bitcoin-*"));
        assert!(!is_endpoint_identifier("btc-Bitcoin-p2tr"));
        assert!(!is_endpoint_identifier("btc--p2tr"));
        assert!(!is_endpoint_identifier("btc-lightning-bolt11-x"));
    }

    #[test]
    fn the_signature_covers_everything_but_itself() {
        let signer = signer();
        let (signed, bytes) = build(&offer(&[BOLTZ_TAPROOT_FEATURE]), &publication(4))
            .sign(&signer)
            .unwrap();
        signed.verify(&signer.public_key_hex()).unwrap();
        let read: Descriptor = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(read, signed);
        read.verify(&signer.public_key_hex()).unwrap();

        let mut tampered = read.clone();
        tampered.profiles[0].edges[0].min = "1".into();
        assert!(tampered.verify(&signer.public_key_hex()).is_err());
        let other = Ed25519Signer::from_secret(&[4; 32]);
        assert!(read.verify(&other.public_key_hex()).is_err());

        // A closed envelope: an extra member does not parse.
        let mut extra: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        extra["reputation"] = serde_json::json!({});
        assert!(serde_json::from_value::<Descriptor>(extra).is_err());
    }

    #[test]
    fn the_largest_descriptor_fits_the_file_limit() {
        let mut big = offer(&[
            BOLTZ_TAPROOT_FEATURE,
            DIRECT_RPC_FEATURE,
            PAYKIT_CAP_FEATURE,
        ]);
        big.max_amount_sat = u64::MAX >> 11;
        big.base_fee_sat = u64::MAX >> 11;
        big.fee_ppm = 1_000_000;
        big.onchain_fee_sat = u64::MAX >> 11;
        big.fund_within_secs = u64::MAX >> 11;
        big.htlc_timeout_blocks = u32::MAX;
        big.required_confirmations = u32::MAX;
        big.valid_until_unix = u64::MAX >> 11;
        let mut publication = publication(u64::MAX >> 11);
        publication.created_at = u64::MAX >> 11;
        publication.key_generation = u64::MAX >> 11;
        let (signed, bytes) = build(&big, &publication).sign(&signer()).unwrap();
        assert!(bytes.len() < DESCRIPTOR_MAX_BYTES, "{}", bytes.len());
        assert!(signed.profiles[0].edges.len() <= DESCRIPTOR_MAX_EDGES);
    }

    #[test]
    fn a_wildcard_identifier_is_refused_before_signing() {
        let mut descriptor = build(&offer(&[]), &publication(1));
        descriptor.profiles[0].edges[0].to = "btc-bitcoin-*".into();
        assert_eq!(
            descriptor.sign(&signer()).unwrap_err(),
            DescriptorError::Identifier("btc-bitcoin-*".into())
        );
    }

    #[test]
    fn a_descriptor_lapses_at_valid_until() {
        let descriptor = build(&offer(&[]), &publication(1));
        assert!(descriptor.is_current(descriptor.valid_until - 1));
        assert!(!descriptor.is_current(descriptor.valid_until));
    }
}
