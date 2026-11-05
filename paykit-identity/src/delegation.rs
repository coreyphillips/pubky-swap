//! The capability signing key and the routing key's delegation to it (Paykit Capabilities §5).
//!
//! Every app of an identity derives the same capability signing key from `K_g`, and the routing
//! key signs one delegation naming it per key generation. The delegation holds no timestamp and
//! Ed25519 is deterministic, so every app of the identity writes byte-identical bytes.
//!
//! Encodings follow §5 as pinned in `55e0bc2`: `owner` is bare z-base-32 (`PublicKey::z32()`,
//! never its `pubky`-prefixed `Display` form) and base64url is RFC 4648 §5 without padding. A
//! reader refuses any other form rather than normalizing it, because the signature covers the
//! exact bytes.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use paykit_lib::PaykitNoiseKeyAuthorization;
use pubky::errors::RequestError;
use pubky::{PublicKey, PublicStorage, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{GenerationKeys, RoutingSigner};

/// Where every app of the identity publishes the delegation, under the existing session.
pub const SIGNING_KEY_PATH: &str = "/pub/paykit/ext/capabilities/v1/signing-key.json";

/// The domain string the routing key signs the delegation under. `0x00` follows it.
pub const SUBKEY_DOMAIN: &[u8] = b"paykit-cap/subkey/v1";

/// The Paykit KDF v1 context the capability signing key's seed is derived under.
pub const CAP_SIGNING_CONTEXT: &str = "paykit/cap-signing";

const KIND: &str = "paykit-cap.signing_key";
const VERSION: u64 = 1;
/// Far above the roughly 260 bytes a delegation takes, and small enough to read whole.
const MAX_BYTES: usize = 4096;
/// The largest integer JCS writes the same way in every implementation.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The capability signing key's Ed25519 seed for the Paykit identity secret `K_g`.
pub fn derive_cap_signing_secret(paykit_identity_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(CAP_SIGNING_CONTEXT, paykit_identity_secret)
}

/// The file as written. Fields are declared in JCS order (sorted by name), and every value is an
/// ASCII string or a safe integer, so `serde_json` writes the canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    key_generation: u64,
    kind: String,
    owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
    signing_key: String,
    version: u64,
}

impl Wire {
    /// What the routing key signs: the domain, `0x00`, then the JCS form without `sig`.
    fn signing_input(&self) -> Result<Vec<u8>> {
        let unsigned = Self {
            sig: None,
            ..self.clone()
        };
        let mut input = SUBKEY_DOMAIN.to_vec();
        input.push(0);
        input.extend(serde_json::to_vec(&unsigned).context("encode the delegation")?);
        Ok(input)
    }
}

/// A delegation from `owner`'s routing key at `key_generation` to a capability signing key.
///
/// Built by [`SigningKeyDelegation::sign`] or checked by [`SigningKeyDelegation::verify`], so a
/// value of this type always carries a valid routing key signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyDelegation {
    wire: Wire,
    signing_key: [u8; 32],
}

impl SigningKeyDelegation {
    /// Sign the delegation for the generation `current` authorizes, with that generation's
    /// routing key. Fails if `current` is not this identity's derived key, so an app holding an
    /// older generation cannot write over a newer delegation.
    pub fn sign(identity_secret: &[u8; 32], current: &PaykitNoiseKeyAuthorization) -> Result<Self> {
        let signer = RoutingSigner::new(identity_secret, current)?;
        let keys = GenerationKeys::derive(identity_secret, current.key_generation())?;
        let signing_key = keys.cap_signing_public_key();
        let mut wire = Wire {
            key_generation: current.key_generation(),
            kind: KIND.into(),
            owner: current.owner().z32(),
            sig: None,
            signing_key: URL_SAFE_NO_PAD.encode(signing_key),
            version: VERSION,
        };
        if wire.key_generation > MAX_SAFE_INTEGER {
            bail!(
                "key generation {} is too large to sign",
                wire.key_generation
            );
        }
        let signature = signer.sign(current, &wire.signing_input()?)?;
        wire.sig = Some(URL_SAFE_NO_PAD.encode(signature));
        Ok(Self { wire, signing_key })
    }

    /// Check `bytes` as the delegation `authorization` roots: the same owner and generation, and
    /// a valid signature by its routing key. A delegation for any other generation is refused.
    pub fn verify(bytes: &[u8], authorization: &PaykitNoiseKeyAuthorization) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            bail!("the delegation is {} bytes, over {MAX_BYTES}", bytes.len());
        }
        let wire: Wire = serde_json::from_slice(bytes).context("read the delegation")?;
        if wire.version != VERSION || wire.kind != KIND {
            bail!("not a version {VERSION} {KIND} delegation");
        }
        if wire.owner != authorization.owner().z32() {
            bail!("the delegation's owner is not this identity in bare z-base-32");
        }
        if wire.key_generation != authorization.key_generation() {
            bail!(
                "the delegation is for generation {}, the authorization for generation {}",
                wire.key_generation,
                authorization.key_generation()
            );
        }
        let signing_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&wire.signing_key)
            .ok()
            .and_then(|key| key.try_into().ok())
            .ok_or_else(|| anyhow!("the delegation's signing_key is not a 32-byte key"))?;
        ed25519_dalek::VerifyingKey::from_bytes(&signing_key)
            .map_err(|_| anyhow!("the delegation's signing_key is not an Ed25519 key"))?;
        let signature: [u8; 64] = wire
            .sig
            .as_deref()
            .and_then(|sig| URL_SAFE_NO_PAD.decode(sig).ok())
            .and_then(|sig| sig.try_into().ok())
            .ok_or_else(|| anyhow!("the delegation's sig is missing or malformed"))?;
        let routing_key =
            ed25519_dalek::VerifyingKey::from_bytes(authorization.noise_public_key().as_bytes())
                .map_err(|_| anyhow!("the authorized routing key is not an Ed25519 key"))?;
        routing_key
            .verify_strict(
                &wire.signing_input()?,
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .map_err(|_| anyhow!("the delegation is not signed by the authorized routing key"))?;
        Ok(Self { wire, signing_key })
    }

    /// The file's bytes, in JCS form.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.wire).expect("strings and integers always encode")
    }

    pub fn key_generation(&self) -> u64 {
        self.wire.key_generation
    }

    /// The delegated capability signing key.
    pub fn signing_key(&self) -> [u8; 32] {
        self.signing_key
    }

    /// The delegated capability signing key as hex, the form `paykit-cap` signatures name.
    pub fn signing_key_hex(&self) -> String {
        hex::encode(self.signing_key)
    }
}

/// Read `owner`'s published delegation bytes. A missing file is `None`.
pub async fn fetch_delegation(
    storage: &PublicStorage,
    owner: &PublicKey,
) -> Result<Option<Vec<u8>>> {
    let response = match storage.get(format!("{owner}{SIGNING_KEY_PATH}")).await {
        Ok(response) => response,
        Err(pubky::Error::Request(RequestError::Server { status, .. }))
            if status == StatusCode::NOT_FOUND || status == StatusCode::GONE =>
        {
            return Ok(None)
        }
        Err(e) => return Err(e).context("read the capability signing key delegation"),
    };
    let bytes = response
        .bytes()
        .await
        .context("read the capability signing key delegation")?;
    if bytes.len() > MAX_BYTES {
        bail!("the delegation is {} bytes, over {MAX_BYTES}", bytes.len());
    }
    Ok(Some(bytes.to_vec()))
}

/// Follow §5 from `owner`'s published records to its capability signing key.
///
/// Verifies the Noise Key Authorization through paykit-rs, then the delegation against it.
/// `None` when either record is unpublished. An error when a published record does not verify,
/// including a delegation left at an older generation than the authorization.
pub async fn resolve_signing_key(
    storage: &PublicStorage,
    owner: &PublicKey,
) -> Result<Option<SigningKeyDelegation>> {
    let Some(authorization) = paykit_lib::get_paykit_noise_key_authorization(storage, owner)
        .await
        .map_err(|e| anyhow!("read the Noise Key Authorization: {e}"))?
    else {
        return Ok(None);
    };
    let Some(bytes) = fetch_delegation(storage, owner).await? else {
        return Ok(None);
    };
    SigningKeyDelegation::verify(&bytes, &authorization).map(Some)
}

/// [`resolve_signing_key`] over the public Pubky network, for a pubky with or without its prefix.
pub async fn resolve_published_signing_key(owner: &str) -> Result<Option<SigningKeyDelegation>> {
    let owner = PublicKey::try_from(owner).map_err(|e| anyhow!("not a pubky: {e}"))?;
    let storage = PublicStorage::new().context("build a Pubky client")?;
    resolve_signing_key(&storage, &owner).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky::Keypair;

    const SECRET: [u8; 32] = [7; 32];

    fn authorization(secret: &[u8; 32], generation: u64) -> PaykitNoiseKeyAuthorization {
        let keys = GenerationKeys::derive(secret, generation).unwrap();
        PaykitNoiseKeyAuthorization::sign(
            &Keypair::from_secret(secret),
            &keys.noise_secret,
            generation,
        )
        .unwrap()
    }

    fn rewrite(bytes: &[u8], edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        edit(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn each_generation_derives_its_own_cap_signing_key() {
        let one = GenerationKeys::derive(&SECRET, 1).unwrap();
        let again = GenerationKeys::derive(&SECRET, 1).unwrap();
        let two = GenerationKeys::derive(&SECRET, 2).unwrap();
        assert_eq!(one.cap_signing_public_key(), again.cap_signing_public_key());
        assert_ne!(one.cap_signing_public_key(), two.cap_signing_public_key());
        // Neither the routing key nor the identity key.
        assert_ne!(&one.cap_signing_public_key(), one.routing_key().as_bytes());
        assert_ne!(
            &one.cap_signing_public_key(),
            Keypair::from_secret(&SECRET).public_key().as_bytes()
        );
    }

    /// A shared test vector: every app of the identity must write exactly these bytes.
    #[test]
    fn the_delegation_bytes_match_the_golden_vector() {
        let delegation = SigningKeyDelegation::sign(&SECRET, &authorization(&SECRET, 1)).unwrap();
        let bytes = String::from_utf8(delegation.to_bytes()).unwrap();
        assert_eq!(bytes, GOLDEN_DELEGATION);
        // JCS form: what swap-common's canonical encoder writes for the same object.
        let value: serde_json::Value = serde_json::from_str(&bytes).unwrap();
        assert_eq!(
            swap_common::paykit_cap::jcs(&value).unwrap(),
            bytes.as_bytes()
        );
        // Signing again writes the same bytes, so concurrent writers never conflict.
        let again = SigningKeyDelegation::sign(&SECRET, &authorization(&SECRET, 1)).unwrap();
        assert_eq!(again.to_bytes(), delegation.to_bytes());
    }

    /// Pubky secret `[7; 32]`, generation 1. Recomputed independently from Paykit KDF v1 and §5
    /// with Python's `blake3` and `pynacl`, which reproduce this byte for byte.
    const GOLDEN_DELEGATION: &str = concat!(
        r#"{"key_generation":1,"kind":"paykit-cap.signing_key","#,
        r#""owner":"7jfgaa9nutjyixzikb7tgmsf9gkwq7iqz498zr1nd5ig1fng4esy","#,
        r#""sig":"Sj9Xps4rjkmNrqYv4EU8OuD7gyN4LGNb1SyAbjv0p9PEEg7HekF6unysSnkPRXDn_k9XOBHmll3-Xdo2xkrtAQ","#,
        r#""signing_key":"7TrkHFnQPW67doNM4TipjT9CmZygnHHbriRjgBb4Ry8","version":1}"#
    );

    #[test]
    fn a_delegation_verifies_under_its_authorization() {
        let current = authorization(&SECRET, 1);
        let delegation = SigningKeyDelegation::sign(&SECRET, &current).unwrap();
        let verified = SigningKeyDelegation::verify(&delegation.to_bytes(), &current).unwrap();
        assert_eq!(verified, delegation);
        assert_eq!(verified.key_generation(), 1);
        assert_eq!(
            verified.signing_key(),
            GenerationKeys::derive(&SECRET, 1)
                .unwrap()
                .cap_signing_public_key()
        );
    }

    #[test]
    fn an_owner_or_key_in_another_encoding_is_refused() {
        let current = authorization(&SECRET, 1);
        let keys = GenerationKeys::derive(&SECRET, 1).unwrap();
        let mut wire = Wire {
            key_generation: 1,
            kind: KIND.into(),
            owner: current.owner().to_string(),
            sig: None,
            signing_key: URL_SAFE_NO_PAD.encode(keys.cap_signing_public_key()),
            version: VERSION,
        };
        assert!(wire.owner.starts_with("pubky"));
        let signer = RoutingSigner::new(&SECRET, &current).unwrap();
        let signed = |wire: &mut Wire| {
            wire.sig = None;
            let signature = signer
                .sign(&current, &wire.signing_input().unwrap())
                .unwrap();
            wire.sig = Some(URL_SAFE_NO_PAD.encode(signature));
            serde_json::to_vec(&*wire).unwrap()
        };
        // Correctly signed over the prefixed form, and still refused.
        let err = SigningKeyDelegation::verify(&signed(&mut wire), &current).unwrap_err();
        assert!(err.to_string().contains("bare z-base-32"), "{err}");
        wire.owner = format!("pk:{}", current.owner().z32());
        assert!(SigningKeyDelegation::verify(&signed(&mut wire), &current).is_err());
        wire.owner = current.owner().z32().to_uppercase();
        assert!(SigningKeyDelegation::verify(&signed(&mut wire), &current).is_err());

        // A padded signing key is refused, and so is a padded signature.
        wire.owner = current.owner().z32();
        assert!(SigningKeyDelegation::verify(&signed(&mut wire), &current).is_ok());
        wire.signing_key = format!("{}=", wire.signing_key);
        assert!(SigningKeyDelegation::verify(&signed(&mut wire), &current).is_err());
        wire.signing_key = URL_SAFE_NO_PAD.encode(keys.cap_signing_public_key());
        let mut padded: serde_json::Value = serde_json::from_slice(&signed(&mut wire)).unwrap();
        let sig = format!("{}==", padded["sig"].as_str().unwrap());
        padded["sig"] = sig.into();
        let bytes = serde_json::to_vec(&padded).unwrap();
        assert!(SigningKeyDelegation::verify(&bytes, &current).is_err());
    }

    #[test]
    fn a_delegation_for_another_generation_is_refused() {
        let first = authorization(&SECRET, 1);
        let second = authorization(&SECRET, 2);
        let old = SigningKeyDelegation::sign(&SECRET, &first).unwrap();
        let error = SigningKeyDelegation::verify(&old.to_bytes(), &second).unwrap_err();
        assert!(error.to_string().contains("generation 1"), "{error}");
        // Relabelling the old delegation as the new generation breaks its signature.
        let relabelled = rewrite(&old.to_bytes(), |v| v["key_generation"] = 2.into());
        assert!(SigningKeyDelegation::verify(&relabelled, &second).is_err());
        assert!(SigningKeyDelegation::verify(&relabelled, &first).is_err());
    }

    #[test]
    fn a_delegation_for_another_identity_is_refused() {
        let mine = SigningKeyDelegation::sign(&SECRET, &authorization(&SECRET, 1)).unwrap();
        let theirs = authorization(&[8; 32], 1);
        assert!(SigningKeyDelegation::verify(&mine.to_bytes(), &theirs).is_err());
        // Nor can a delegation name an identity whose routing key did not sign it.
        let renamed = rewrite(&mine.to_bytes(), |v| {
            v["owner"] = theirs.owner().z32().into()
        });
        assert!(SigningKeyDelegation::verify(&renamed, &theirs).is_err());
    }

    #[test]
    fn a_tampered_or_unknown_delegation_is_refused() {
        let current = authorization(&SECRET, 1);
        let bytes = SigningKeyDelegation::sign(&SECRET, &current)
            .unwrap()
            .to_bytes();
        let other_key = URL_SAFE_NO_PAD.encode(Keypair::random().public_key().as_bytes());
        let cases = [
            rewrite(&bytes, |v| v["signing_key"] = other_key.clone().into()),
            rewrite(&bytes, |v| v["extra"] = 1.into()),
            rewrite(&bytes, |v| v["version"] = 2.into()),
            rewrite(&bytes, |v| v["kind"] = "paykit-cap.descriptor".into()),
            rewrite(&bytes, |v| {
                v.as_object_mut().unwrap().remove("sig");
            }),
            rewrite(&bytes, |v| {
                let sig = v["sig"].as_str().unwrap().to_string();
                v["sig"] = format!("{sig}==").into();
            }),
        ];
        for case in cases {
            assert!(
                SigningKeyDelegation::verify(&case, &current).is_err(),
                "{}",
                String::from_utf8_lossy(&case)
            );
        }
        assert!(SigningKeyDelegation::verify(&vec![b' '; MAX_BYTES + 1], &current).is_err());
    }

    /// A reader following §5 verifies a descriptor through the Noise Key Authorization, the
    /// routing key's delegation and the capability signing key, and drops one the identity key
    /// signed, which is what pubky-swap published before this delegation existed.
    #[test]
    fn a_descriptor_verifies_through_the_whole_chain() {
        use swap_common::cap_descriptor::{build, Publication};
        use swap_common::messages::SwapOffer;
        use swap_common::paykit_cap::Ed25519Signer;
        use swap_common::{NetworkSpec, SwapDirection, PROTOCOL_VERSION};

        let current = authorization(&SECRET, 1);
        let keys = GenerationKeys::derive(&SECRET, 1).unwrap();
        let offer = SwapOffer {
            request_id: None,
            offer_id: uuid::Uuid::nil(),
            provider_pkarr: current.owner().z32(),
            network: NetworkSpec::Regtest,
            directions: vec![SwapDirection::Reverse, SwapDirection::Submarine],
            min_amount_sat: 10_000,
            max_amount_sat: 1_000_000,
            base_fee_sat: 500,
            fee_ppm: 2_000,
            required_confirmations: 2,
            htlc_timeout_blocks: 144,
            lightning_node_id: None,
            valid_until_unix: 1_793_000_300,
            fund_within_secs: 300,
            onchain_fee_sat: 300,
            fee_rate_sat_vb: 2,
            protocol_version: PROTOCOL_VERSION,
            features: vec![],
        };
        let publication = Publication {
            owner: current.owner().z32(),
            key_generation: current.key_generation(),
            seq: 1_793_000_000,
            created_at: 1_793_000_000,
        };
        let cap_signer = Ed25519Signer::from_secret(&keys.cap_signing_secret());
        let (descriptor, _) = build(&offer, &publication).sign(&cap_signer).unwrap();

        // §5: verify the authorization (paykit-rs did, on deserializing it), require the
        // object's generation, verify the delegation against it, then the object.
        let published = SigningKeyDelegation::sign(&SECRET, &current)
            .unwrap()
            .to_bytes();
        let delegation = SigningKeyDelegation::verify(&published, &current).unwrap();
        assert_eq!(descriptor.key_generation, delegation.key_generation());
        descriptor.verify(&delegation.signing_key_hex()).unwrap();

        let identity_signer = Ed25519Signer::from_secret(&SECRET);
        let (by_identity, _) = build(&offer, &publication).sign(&identity_signer).unwrap();
        assert!(by_identity.verify(&delegation.signing_key_hex()).is_err());
        // Nor does the routing key itself sign descriptors.
        let routing_signer = Ed25519Signer::from_secret(&keys.noise_secret);
        let (by_routing, _) = build(&offer, &publication).sign(&routing_signer).unwrap();
        assert!(by_routing.verify(&delegation.signing_key_hex()).is_err());
    }

    #[test]
    fn a_signer_only_delegates_for_its_own_authorization() {
        let foreign =
            PaykitNoiseKeyAuthorization::sign(&Keypair::from_secret(&SECRET), &[9; 32], 1).unwrap();
        assert!(SigningKeyDelegation::sign(&SECRET, &foreign).is_err());
        assert!(SigningKeyDelegation::sign(&[8; 32], &authorization(&SECRET, 1)).is_err());
    }
}
