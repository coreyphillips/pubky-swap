//! Setup, rerun and rotation against a local pubky 0.16 homeserver, read back by paykit-rs, and
//! the capability signing key delegation a reader follows from there (Capabilities §5).
//!
//! Needs Docker for Postgres, or `TEST_PUBKY_CONNECTION_STRING`. Run with
//! `cargo test --manifest-path paykit-identity/homeserver-test/Cargo.toml`.

use paykit_identity::{
    inspect, resolve_signing_key, setup, Change, DelegationState, GenerationKeys, RoutingSigner,
    APP_ID, SIGNING_KEY_PATH,
};
use paykit_lib::{
    get_paykit_app_registry, get_paykit_noise_key_authorization, PaykitAppId,
    PaykitNoiseKeyAuthorization, PAYKIT_APP_REGISTRY_PATH, PAYKIT_NOISE_KEY_AUTHORIZATION_PATH,
};
use pubky::{ClientId, Keypair, PublicKey, PublicStorage};
use pubky_testnet::{docker_postgres::DockerPostgres, EphemeralTestnet};

async fn testnet() -> EphemeralTestnet {
    let builder = if std::env::var_os("TEST_PUBKY_CONNECTION_STRING").is_some() {
        EphemeralTestnet::builder()
    } else {
        let postgres = DockerPostgres::shared()
            .await
            .connection_string()
            .expect("Docker Postgres connection string");
        EphemeralTestnet::builder().postgres(postgres)
    };
    builder.build().await.expect("testnet")
}

async fn raw(storage: &PublicStorage, owner: &PublicKey, path: &str) -> Vec<u8> {
    storage
        .get(format!("{owner}{path}"))
        .await
        .expect("record is published")
        .bytes()
        .await
        .expect("record body")
        .to_vec()
}

async fn authorization(storage: &PublicStorage, owner: &PublicKey) -> PaykitNoiseKeyAuthorization {
    get_paykit_noise_key_authorization(storage, owner)
        .await
        .expect("paykit-rs verifies the authorization")
        .expect("authorization is published")
}

#[tokio::test]
async fn setup_is_idempotent_rotates_and_is_checked_by_a_paykit_reader() {
    let testnet = testnet().await;
    let sdk = testnet.sdk().unwrap();
    let identity = Keypair::random();
    let owner = identity.public_key();
    let secret = identity.secret_key();
    let signer = sdk.signer(identity.clone());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let session = signer
        .signin(ClientId::new("pubky-swap.test").unwrap())
        .await
        .unwrap();
    let storage = sdk.public_storage();

    // First run publishes both records.
    let first = setup(&session, &identity, 1).await.unwrap();
    assert_eq!(first.registry, Change::Created);
    assert_eq!(first.authorization, Change::Created);

    // A paykit-rs reader verifies the authorization and finds the app.
    let keys = GenerationKeys::derive(&secret, 1).unwrap();
    let published = authorization(&storage, &owner).await;
    assert_eq!(published.key_generation(), 1);
    assert_eq!(published.noise_public_key(), keys.routing_key());
    let registry = get_paykit_app_registry(&storage, &owner)
        .await
        .unwrap()
        .expect("registry is published");
    assert!(registry
        .apps()
        .contains_key(&PaykitAppId::new(APP_ID).unwrap()));
    assert_eq!(registry.noise_public_key(), Some(keys.routing_key()));
    assert_eq!(registry.key_generation(), 1);
    let healthy = inspect(&storage, &secret).await.unwrap();
    assert_eq!(healthy.generation, Some(1));
    assert!(healthy.is_healthy(), "{healthy:?}");

    // Rerunning changes nothing, byte for byte.
    let before = (
        raw(&storage, &owner, PAYKIT_APP_REGISTRY_PATH).await,
        raw(&storage, &owner, PAYKIT_NOISE_KEY_AUTHORIZATION_PATH).await,
    );
    let again = setup(&session, &identity, 1).await.unwrap();
    assert_eq!(again.registry, Change::Unchanged);
    assert_eq!(again.authorization, Change::Unchanged);
    let after = (
        raw(&storage, &owner, PAYKIT_APP_REGISTRY_PATH).await,
        raw(&storage, &owner, PAYKIT_NOISE_KEY_AUTHORIZATION_PATH).await,
    );
    assert_eq!(before, after);

    // Skipping a generation is refused before anything is written.
    assert!(setup(&session, &identity, 3).await.is_err());

    // Rotation: the next generation re-signs, and the old signer refuses from then on.
    let old_signer = RoutingSigner::new(&secret, &published).unwrap();
    old_signer.sign(&published, b"descriptor").unwrap();
    let rotated = setup(&session, &identity, 2).await.unwrap();
    assert_eq!(rotated.registry, Change::Updated);
    assert_eq!(rotated.authorization, Change::Updated);
    let current = authorization(&storage, &owner).await;
    assert_eq!(current.key_generation(), 2);
    current.validate_against(&published).unwrap();
    assert!(old_signer.sign(&current, b"descriptor").is_err());
    let new_signer = RoutingSigner::new(&secret, &current).unwrap();
    let signature = new_signer.sign(&current, b"descriptor").unwrap();
    current
        .noise_public_key()
        .verify(b"descriptor", &signature.into())
        .expect("the signature verifies under the authorized routing key");
    assert_eq!(
        inspect(&storage, &secret).await.unwrap().generation,
        Some(2)
    );
    // Going back is refused.
    assert!(setup(&session, &identity, 1).await.is_err());

    // An authorization for a key this identity does not derive fails the check.
    let foreign = PaykitNoiseKeyAuthorization::sign(&identity, &[9; 32], 3).unwrap();
    paykit_lib::publish_paykit_noise_key_authorization(&session, &foreign)
        .await
        .unwrap();
    let mismatch = inspect(&storage, &secret).await.unwrap();
    assert_eq!(mismatch.generation, Some(3));
    assert!(!mismatch.routing_key_matches);
    assert!(!mismatch.is_healthy());
    assert!(RoutingSigner::new(&secret, &foreign).is_err());
    assert!(setup(&session, &identity, 3).await.is_err());
}

#[tokio::test]
async fn setup_publishes_a_delegation_a_reader_follows_to_the_signing_key() {
    let testnet = testnet().await;
    let sdk = testnet.sdk().unwrap();
    let identity = Keypair::random();
    let owner = identity.public_key();
    let secret = identity.secret_key();
    let signer = sdk.signer(identity.clone());
    signer
        .signup(&testnet.homeserver_app().public_key(), None)
        .await
        .unwrap();
    let session = signer
        .signin(ClientId::new("pubky-swap.test").unwrap())
        .await
        .unwrap();
    let storage = sdk.public_storage();
    assert!(resolve_signing_key(&storage, &owner)
        .await
        .unwrap()
        .is_none());

    // Setup publishes the delegation, and a reader follows it to the derived key.
    let first = setup(&session, &identity, 1).await.unwrap();
    assert_eq!(first.delegation, Change::Created);
    let resolved = resolve_signing_key(&storage, &owner)
        .await
        .unwrap()
        .expect("the delegation is published");
    assert_eq!(resolved.key_generation(), 1);
    let one = GenerationKeys::derive(&secret, 1).unwrap();
    assert_eq!(resolved.signing_key(), one.cap_signing_public_key());
    // The file holds exactly the bytes any app of the identity writes.
    let first_bytes = raw(&storage, &owner, SIGNING_KEY_PATH).await;
    assert_eq!(first_bytes, resolved.to_bytes());
    let inspected = inspect(&storage, &secret).await.unwrap();
    assert_eq!(inspected.delegation, DelegationState::Current);

    // Rerunning leaves it alone.
    let again = setup(&session, &identity, 1).await.unwrap();
    assert_eq!(again.delegation, Change::Unchanged);
    assert_eq!(raw(&storage, &owner, SIGNING_KEY_PATH).await, first_bytes);

    // Rotation rewrites it for the new generation's key, signed by the new routing key.
    let rotated = setup(&session, &identity, 2).await.unwrap();
    assert_eq!(rotated.delegation, Change::Updated);
    let second = resolve_signing_key(&storage, &owner)
        .await
        .unwrap()
        .expect("the delegation is published");
    assert_eq!(second.key_generation(), 2);
    let two = GenerationKeys::derive(&secret, 2).unwrap();
    assert_eq!(second.signing_key(), two.cap_signing_public_key());
    assert_ne!(second.signing_key(), resolved.signing_key());

    // A delegation left at the old generation is refused, and the doctor says why.
    session
        .storage()
        .put(SIGNING_KEY_PATH, first_bytes.clone())
        .await
        .unwrap();
    assert!(resolve_signing_key(&storage, &owner).await.is_err());
    match inspect(&storage, &secret).await.unwrap().delegation {
        DelegationState::Invalid(why) => assert!(why.contains("generation 1"), "{why}"),
        other => panic!("expected an invalid delegation, got {other:?}"),
    }
    // Setup puts it right.
    let repaired = setup(&session, &identity, 2).await.unwrap();
    assert_eq!(repaired.delegation, Change::Updated);
    assert_eq!(
        resolve_signing_key(&storage, &owner)
            .await
            .unwrap()
            .expect("the delegation is published")
            .key_generation(),
        2
    );
}
