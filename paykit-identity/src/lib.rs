//! The provider as a Paykit peer.
//!
//! Paykit Capabilities §5 roots every signature in the identity-signed Noise Key Authorization at
//! `/pub/paykit-authority/v0/current-key.json`, and §6.2 needs the descriptor's `app_id` in the
//! owner's App Registry. This crate derives the keys for one generation, publishes both records
//! and checks them. Every derivation, record and signature check is paykit-rs's own code, except
//! the capability signing key and its delegation (§5), which paykit-rs does not define yet.

mod delegation;

pub use delegation::{
    derive_cap_signing_secret, fetch_delegation, resolve_published_signing_key,
    resolve_signing_key, SigningKeyDelegation, CAP_SIGNING_CONTEXT, SIGNING_KEY_PATH,
    SUBKEY_DOMAIN,
};

use anyhow::{anyhow, bail, Context, Result};
use paykit_lib::{
    content_revision, get_paykit_app_registry, get_paykit_noise_key_authorization,
    parse_paykit_app_registry_json, PaykitApp, PaykitAppCapabilities, PaykitAppId,
    PaykitAppRegistry, PaykitNoiseKeyAuthorization, PAYKIT_APP_REGISTRY_PATH,
    PAYKIT_NOISE_KEY_AUTHORIZATION_PATH,
};
use paykit_sdk::PubkyLocalSecretKey;
use pubky::{Keypair, PubkySession, PublicKey, PublicStorage};

pub use paykit_lib::INITIAL_PAYKIT_KEY_GENERATION;

/// The `app_id` swap descriptors name.
pub const APP_ID: &str = "pubky-swap";
const APP_DISPLAY_NAME: &str = "pubky-swap provider";

/// The Pubky capabilities the setup session needs, and no more.
pub const AUTHORIZER_CAPABILITIES: &str = paykit_sdk::PAYKIT_AUTHORIZER_SESSION_CAPABILITIES;

/// Keys for one Paykit key generation, under Paykit KDF v1.
pub struct GenerationKeys {
    generation: u64,
    noise_secret: [u8; 32],
    routing_key: PublicKey,
    cap_signing_secret: [u8; 32],
}

impl GenerationKeys {
    /// Derive `K_g` from the Pubky identity secret, then the Noise key, the routing key and the
    /// capability signing key from it.
    pub fn derive(identity_secret: &[u8; 32], generation: u64) -> Result<Self> {
        let k_g = PubkyLocalSecretKey::from(*identity_secret)
            .derive_paykit_identity_secret_key(generation)
            .map_err(|e| anyhow!("derive Paykit key generation {generation}: {e}"))?;
        Ok(Self {
            generation,
            noise_secret: paykit_lib::derive_paykit_noise_secret_key(k_g.as_bytes()),
            routing_key: paykit_lib::derive_paykit_noise_public_key(k_g.as_bytes()),
            cap_signing_secret: derive_cap_signing_secret(k_g.as_bytes()),
        })
    }

    /// The capability signing key's Ed25519 seed (§5). Secret: it signs as the identity.
    pub fn cap_signing_secret(&self) -> [u8; 32] {
        self.cap_signing_secret
    }

    /// The capability signing key's public key, which the delegation names.
    pub fn cap_signing_public_key(&self) -> [u8; 32] {
        *Keypair::from_secret(&self.cap_signing_secret)
            .public_key()
            .as_bytes()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The Ed25519 key peers route to and verify signatures against.
    pub fn routing_key(&self) -> &PublicKey {
        &self.routing_key
    }

    /// Whether `authorization` approves exactly these keys.
    pub fn matches(&self, authorization: &PaykitNoiseKeyAuthorization) -> bool {
        authorization.key_generation() == self.generation
            && authorization.noise_public_key() == &self.routing_key
            && authorization.noise_static_public_key()
                == &paykit_lib::pubky_noise::derive_static_public_key(&self.noise_secret)
    }
}

/// What one record went through during [`setup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Unchanged,
    Created,
    Updated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupReport {
    pub generation: u64,
    pub routing_key: String,
    pub registry: Change,
    pub authorization: Change,
    /// The capability signing key delegation at `signing-key.json` (Capabilities §5).
    pub delegation: Change,
}

/// Publish the App Registry entry, the Noise Key Authorization and the capability signing key
/// delegation for `generation`.
///
/// Rerunning with the published generation writes nothing. Rotation is the next generation: the
/// registry advances first and the authorization second, the order paykit-sdk rotates in, so a
/// reader never sees an authorization the registry does not advertise yet. paykit-rs refuses a
/// lower generation, a skipped one, or a different key at the same one. The delegation comes
/// last, because a reader verifies it against the authorization.
pub async fn setup(
    session: &PubkySession,
    identity: &Keypair,
    generation: u64,
) -> Result<SetupReport> {
    let owner = identity.public_key();
    if session.info().public_key() != &owner {
        bail!("the setup session belongs to another identity");
    }
    let keys = GenerationKeys::derive(&identity.secret_key(), generation)?;
    let published = read_authorization(session, &owner).await?;
    if let Some(current) = &published {
        if generation < current.key_generation() {
            bail!(
                "generation {generation} is older than the published generation {}",
                current.key_generation()
            );
        }
        if generation > current.key_generation().saturating_add(1) {
            bail!(
                "generation {generation} skips ahead of the published generation {}: rotate one \
                 generation at a time",
                current.key_generation()
            );
        }
        if generation == current.key_generation() && !keys.matches(current) {
            bail!(
                "the published authorization at generation {generation} approves a key this \
                 identity does not derive; rotate to generation {}",
                generation.saturating_add(1)
            );
        }
    }

    let registry = publish_registry(session, &keys).await?;
    let (authorization, current) = match published {
        Some(current) if keys.matches(&current) => (Change::Unchanged, current),
        previous => {
            let record =
                PaykitNoiseKeyAuthorization::sign(identity, &keys.noise_secret, generation)
                    .map_err(|e| anyhow!("sign the Noise Key Authorization: {e}"))?;
            paykit_lib::publish_paykit_noise_key_authorization(session, &record)
                .await
                .map_err(|e| anyhow!("publish the Noise Key Authorization: {e}"))?;
            let change = if previous.is_some() {
                Change::Updated
            } else {
                Change::Created
            };
            (change, record)
        }
    };
    let delegation = publish_delegation(session, &identity.secret_key(), &current).await?;
    Ok(SetupReport {
        generation,
        routing_key: keys.routing_key.z32(),
        registry,
        authorization,
        delegation,
    })
}

/// Write the delegation `current` roots, unless the published file already has these bytes.
///
/// Every app of the identity writes the same bytes for one generation, so an equal file is left
/// alone and a different one (absent, older generation, or corrupt) is replaced.
async fn publish_delegation(
    session: &PubkySession,
    identity_secret: &[u8; 32],
    current: &PaykitNoiseKeyAuthorization,
) -> Result<Change> {
    let bytes = SigningKeyDelegation::sign(identity_secret, current)?.to_bytes();
    let previous = read(session, SIGNING_KEY_PATH).await?;
    if previous.as_deref() == Some(bytes.as_slice()) {
        return Ok(Change::Unchanged);
    }
    session
        .storage()
        .put(SIGNING_KEY_PATH, bytes)
        .await
        .with_context(|| format!("write {SIGNING_KEY_PATH}"))?;
    Ok(if previous.is_some() {
        Change::Updated
    } else {
        Change::Created
    })
}

/// Sign in to the identity's homeserver and run [`setup`].
///
/// With no generation it keeps the published one, or starts at the first. Rotating means passing
/// the published generation plus one.
pub async fn sign_in_and_setup(
    identity_secret: &[u8; 32],
    generation: Option<u64>,
) -> Result<SetupReport> {
    let identity = Keypair::from_secret(identity_secret);
    let pubky = pubky::Pubky::new().context("build a Pubky client")?;
    let generation = match generation {
        Some(generation) => generation,
        None => get_paykit_noise_key_authorization(&pubky.public_storage(), &identity.public_key())
            .await
            .map_err(|e| anyhow!("read the Noise Key Authorization: {e}"))?
            .map_or(INITIAL_PAYKIT_KEY_GENERATION, |current| {
                current.key_generation()
            }),
    };
    let session = pubky
        .signer(identity.clone())
        .signin(pubky::ClientId::new(APP_ID).map_err(|e| anyhow!("{e}"))?)
        .await
        .context("sign in to the homeserver")?;
    setup(&session, &identity, generation).await
}

/// Writes this app's Capability Descriptor file under a signed-in session.
///
/// It signs in only once the identity's Paykit records are published and match what it derives,
/// because a reader drops a descriptor whose `app_id` the App Registry does not list (§6.2).
pub struct DescriptorWriter {
    session: PubkySession,
    generation: u64,
}

impl DescriptorWriter {
    pub async fn sign_in(identity_secret: &[u8; 32]) -> Result<Self> {
        let inspection = inspect_published(identity_secret).await?;
        let generation = match inspection.generation {
            Some(generation) if inspection.is_healthy() => generation,
            _ => bail!(
                "the Paykit identity is not set up ({inspection:?}); run swap-provider \
                 --paykit-setup"
            ),
        };
        let identity = Keypair::from_secret(identity_secret);
        let session = pubky::Pubky::new()
            .context("build a Pubky client")?
            .signer(identity)
            .signin(pubky::ClientId::new(APP_ID).map_err(|e| anyhow!("{e}"))?)
            .await
            .context("sign in to the homeserver")?;
        Ok(Self {
            session,
            generation,
        })
    }

    /// A writer for `generation` on a session the caller has already signed in. Unlike
    /// [`DescriptorWriter::sign_in`] it does not check the published records first, but
    /// [`DescriptorWriter::ensure_delegation`] still checks the generation before each write.
    pub fn with_session(session: PubkySession, generation: u64) -> Self {
        Self {
            session,
            generation,
        }
    }

    /// The key generation the published authorization was at when this writer signed in.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Publish the capability signing key delegation for this writer's generation, if the file
    /// does not hold it already, and return that generation's keys to sign with.
    ///
    /// The authorization is read again first and must still be at this generation, so a writer
    /// whose generation has since been rotated away never writes over the newer delegation.
    /// Called again later, it also repairs a delegation another app overwrote with an older
    /// generation, or removed (Capabilities §5, "Writing the delegation").
    pub async fn ensure_delegation(
        &self,
        identity_secret: &[u8; 32],
    ) -> Result<(Change, GenerationKeys)> {
        let owner = Keypair::from_secret(identity_secret).public_key();
        let current = read_authorization(&self.session, &owner)
            .await?
            .ok_or_else(|| anyhow!("the Noise Key Authorization is no longer published"))?;
        if current.key_generation() != self.generation {
            bail!(
                "the published generation moved from {} to {}; sign in again",
                self.generation,
                current.key_generation()
            );
        }
        let change = publish_delegation(&self.session, identity_secret, &current).await?;
        Ok((
            change,
            GenerationKeys::derive(identity_secret, self.generation)?,
        ))
    }

    pub async fn put(&self, path: &str, bytes: Vec<u8>) -> Result<()> {
        self.session
            .storage()
            .put(path, bytes)
            .await
            .with_context(|| format!("write {path}"))?;
        Ok(())
    }
}

/// [`inspect`] over the public Pubky network.
pub async fn inspect_published(identity_secret: &[u8; 32]) -> Result<Inspection> {
    let storage = PublicStorage::new().context("build a Pubky client")?;
    inspect(&storage, identity_secret).await
}

/// The registry carrying `pubky-swap` and the Noise key for `keys`' generation.
///
/// Other apps' entries and defaults are kept: the registry is identity-wide.
async fn publish_registry(session: &PubkySession, keys: &GenerationKeys) -> Result<Change> {
    let app_id = PaykitAppId::new(APP_ID).map_err(|e| anyhow!("{e}"))?;
    // Swap descriptors and terms ride Capabilities kinds, not payment lists, requests or
    // receipts, so the entry claims none of those.
    let app = PaykitApp::new(
        APP_DISPLAY_NAME,
        PaykitAppCapabilities {
            private_payments: false,
            payment_requests: false,
            receipts: false,
            outgoing_payments: false,
        },
    )
    .map_err(|e| anyhow!("{e}"))?;

    let Some(body) = read(session, PAYKIT_APP_REGISTRY_PATH).await? else {
        let mut registry = PaykitAppRegistry::new(None);
        registry
            .set_noise_public_key(keys.routing_key.clone(), keys.generation)
            .map_err(|e| anyhow!("{e}"))?;
        registry
            .register_app(app_id, app)
            .map_err(|e| anyhow!("{e}"))?;
        paykit_lib::create_paykit_app_registry(session, &registry)
            .await
            .map_err(|e| anyhow!("create the App Registry: {e}"))?;
        return Ok(Change::Created);
    };
    let text = std::str::from_utf8(&body).context("the App Registry is not UTF-8")?;
    let mut registry =
        parse_paykit_app_registry_json(text).map_err(|e| anyhow!("read the App Registry: {e}"))?;
    let before = registry.clone();

    match registry.noise_public_key().cloned() {
        None => registry.set_noise_public_key(keys.routing_key.clone(), keys.generation),
        Some(key) if key == keys.routing_key && registry.key_generation() == keys.generation => {
            Ok(())
        }
        Some(_) if registry.key_generation().checked_add(1) == Some(keys.generation) => {
            registry.rotate_noise_public_key(keys.routing_key.clone(), keys.generation)
        }
        Some(_) => {
            bail!(
                "the App Registry advertises generation {} with another key; it cannot move to \
                 generation {}",
                registry.key_generation(),
                keys.generation
            )
        }
    }
    .map_err(|e| anyhow!("{e}"))?;
    if registry.apps().get(&app_id) != Some(&app) {
        registry
            .register_app(app_id, app)
            .map_err(|e| anyhow!("{e}"))?;
    }
    if registry == before {
        return Ok(Change::Unchanged);
    }
    paykit_lib::update_paykit_app_registry(session, &registry, &content_revision(&body))
        .await
        .map_err(|e| anyhow!("update the App Registry: {e}"))?;
    Ok(Change::Updated)
}

async fn read_authorization(
    session: &PubkySession,
    owner: &PublicKey,
) -> Result<Option<PaykitNoiseKeyAuthorization>> {
    let Some(body) = read(session, PAYKIT_NOISE_KEY_AUTHORIZATION_PATH).await? else {
        return Ok(None);
    };
    // Deserializing verifies the identity signature.
    let record: PaykitNoiseKeyAuthorization = serde_json::from_slice(&body)
        .context("the published Noise Key Authorization does not verify")?;
    if record.owner() != owner {
        bail!("the published Noise Key Authorization belongs to another identity");
    }
    Ok(Some(record))
}

async fn read(session: &PubkySession, path: &str) -> Result<Option<Vec<u8>>> {
    let storage = session.storage();
    if !storage
        .exists(path)
        .await
        .with_context(|| format!("check {path}"))?
    {
        return Ok(None);
    }
    let response = storage
        .get(path)
        .await
        .with_context(|| format!("read {path}"))?;
    Ok(Some(
        response
            .bytes()
            .await
            .with_context(|| format!("read {path}"))?
            .to_vec(),
    ))
}

/// What a peer sees of this identity, checked against what the identity derives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// Generation of the published, signature-verified authorization. `None` when unpublished.
    pub generation: Option<u64>,
    /// Whether the published routing key is the one this identity derives at that generation.
    pub routing_key_matches: bool,
    /// Whether the App Registry lists `pubky-swap`.
    pub app_registered: bool,
    /// Whether the App Registry advertises the authorized key and generation.
    pub registry_matches: bool,
    /// The published capability signing key delegation, against the authorization.
    pub delegation: DelegationState,
}

/// The capability signing key delegation as a reader following §5 finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationState {
    /// No delegation is published, or there is no authorization to check one against.
    Missing,
    /// It verifies under the published authorization and names the key this identity derives.
    Current,
    /// Published but unusable, and why: another generation, another key, or a bad signature.
    /// Readers drop everything the capability signing key signs until it is rewritten.
    Invalid(String),
}

impl Inspection {
    /// Whether the App Registry and the authorization are in place, which a descriptor needs.
    /// The delegation is not part of it: whoever writes a descriptor writes the delegation first.
    pub fn is_healthy(&self) -> bool {
        self.generation.is_some()
            && self.routing_key_matches
            && self.app_registered
            && self.registry_matches
    }
}

/// Read the records the way any peer does, unauthenticated, and compare them with the
/// derivation at the published generation.
pub async fn inspect(storage: &PublicStorage, identity_secret: &[u8; 32]) -> Result<Inspection> {
    let owner = Keypair::from_secret(identity_secret).public_key();
    let authorization = get_paykit_noise_key_authorization(storage, &owner)
        .await
        .map_err(|e| anyhow!("read the Noise Key Authorization: {e}"))?;
    let registry = get_paykit_app_registry(storage, &owner)
        .await
        .map_err(|e| anyhow!("read the App Registry: {e}"))?;
    let app_registered = registry
        .as_ref()
        .is_some_and(|r| PaykitAppId::new(APP_ID).is_ok_and(|id| r.apps().contains_key(&id)));
    let Some(authorization) = authorization else {
        return Ok(Inspection {
            generation: None,
            routing_key_matches: false,
            app_registered,
            registry_matches: false,
            delegation: DelegationState::Missing,
        });
    };
    let generation = authorization.key_generation();
    let keys = GenerationKeys::derive(identity_secret, generation)?;
    let registry_matches = registry.as_ref().is_some_and(|r| {
        r.key_generation() == generation
            && r.noise_public_key() == Some(authorization.noise_public_key())
    });
    let delegation = match fetch_delegation(storage, &owner).await? {
        None => DelegationState::Missing,
        Some(bytes) => match SigningKeyDelegation::verify(&bytes, &authorization) {
            Ok(d) if d.signing_key() == keys.cap_signing_public_key() => DelegationState::Current,
            Ok(_) => DelegationState::Invalid(
                "it names a key this identity does not derive at this generation".into(),
            ),
            Err(e) => DelegationState::Invalid(format!("{e:#}")),
        },
    };
    Ok(Inspection {
        generation: Some(generation),
        routing_key_matches: keys.matches(&authorization),
        app_registered,
        registry_matches,
        delegation,
    })
}

/// Signs with the routing key of one generation, and only while that generation is current.
///
/// After a rotation the old signer refuses, so nothing the provider publishes can carry a key
/// peers have stopped trusting. Whatever it signed has to be signed again by the new one.
pub struct RoutingSigner {
    owner: PublicKey,
    generation: u64,
    keypair: Keypair,
}

impl RoutingSigner {
    /// A signer for the generation `current` authorizes. Fails if this identity did not derive it.
    pub fn new(identity_secret: &[u8; 32], current: &PaykitNoiseKeyAuthorization) -> Result<Self> {
        let owner = Keypair::from_secret(identity_secret).public_key();
        if current.owner() != &owner {
            bail!("the authorization belongs to another identity");
        }
        let keys = GenerationKeys::derive(identity_secret, current.key_generation())?;
        if !keys.matches(current) {
            bail!(
                "the authorization at generation {} is not for this identity's derived key",
                keys.generation
            );
        }
        Ok(Self {
            owner,
            generation: keys.generation,
            keypair: Keypair::from_secret(&keys.noise_secret),
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn routing_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Sign `message` if `current`, the latest verified authorization, is still this generation.
    pub fn sign(&self, current: &PaykitNoiseKeyAuthorization, message: &[u8]) -> Result<[u8; 64]> {
        if current.owner() != &self.owner {
            bail!("the authorization belongs to another identity");
        }
        if current.key_generation() != self.generation {
            bail!(
                "generation {} has been replaced by generation {}; sign with the current one",
                self.generation,
                current.key_generation()
            );
        }
        Ok(self.keypair.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7; 32];

    fn authorization(generation: u64) -> PaykitNoiseKeyAuthorization {
        let keys = GenerationKeys::derive(&SECRET, generation).unwrap();
        PaykitNoiseKeyAuthorization::sign(
            &Keypair::from_secret(&SECRET),
            &keys.noise_secret,
            generation,
        )
        .unwrap()
    }

    #[test]
    fn each_generation_derives_its_own_routing_key() {
        let one = GenerationKeys::derive(&SECRET, 1).unwrap();
        let again = GenerationKeys::derive(&SECRET, 1).unwrap();
        let two = GenerationKeys::derive(&SECRET, 2).unwrap();
        assert_eq!(one.routing_key(), again.routing_key());
        assert_ne!(one.routing_key(), two.routing_key());
        // The routing key is not the identity key.
        assert_ne!(
            one.routing_key(),
            &Keypair::from_secret(&SECRET).public_key()
        );
        assert!(GenerationKeys::derive(&SECRET, 0).is_err());
    }

    #[test]
    fn the_derived_keys_match_only_their_own_authorization() {
        let one = GenerationKeys::derive(&SECRET, 1).unwrap();
        assert!(one.matches(&authorization(1)));
        assert!(!one.matches(&authorization(2)));
        let foreign =
            PaykitNoiseKeyAuthorization::sign(&Keypair::from_secret(&SECRET), &[9; 32], 1).unwrap();
        assert!(!one.matches(&foreign));
    }

    #[test]
    fn the_signed_authorization_verifies_through_paykit() {
        let json = serde_json::to_vec(&authorization(1)).unwrap();
        let parsed: PaykitNoiseKeyAuthorization = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, authorization(1));
        let mut tampered: serde_json::Value = serde_json::from_slice(&json).unwrap();
        tampered["key_generation"] = 2.into();
        assert!(serde_json::from_value::<PaykitNoiseKeyAuthorization>(tampered).is_err());
    }

    #[test]
    fn the_old_generation_stops_signing_after_rotation() {
        let first = authorization(1);
        let second = authorization(2);
        second.validate_against(&first).unwrap();

        let old = RoutingSigner::new(&SECRET, &first).unwrap();
        let signature = old.sign(&first, b"descriptor").unwrap();
        first
            .noise_public_key()
            .verify(b"descriptor", &signature.into())
            .unwrap();
        assert!(old.sign(&second, b"descriptor").is_err());

        let new = RoutingSigner::new(&SECRET, &second).unwrap();
        assert_eq!(new.generation(), 2);
        assert_eq!(&new.routing_key(), second.noise_public_key());
        let signature = new.sign(&second, b"descriptor").unwrap();
        second
            .noise_public_key()
            .verify(b"descriptor", &signature.into())
            .unwrap();
        assert!(first
            .noise_public_key()
            .verify(b"descriptor", &signature.into())
            .is_err());
    }

    #[test]
    fn a_signer_refuses_an_authorization_it_did_not_derive() {
        let foreign =
            PaykitNoiseKeyAuthorization::sign(&Keypair::from_secret(&SECRET), &[9; 32], 1).unwrap();
        assert!(RoutingSigner::new(&SECRET, &foreign).is_err());
        let other = PaykitNoiseKeyAuthorization::sign(&Keypair::from_secret(&[8; 32]), &[9; 32], 1)
            .unwrap();
        assert!(RoutingSigner::new(&SECRET, &other).is_err());
    }
}
