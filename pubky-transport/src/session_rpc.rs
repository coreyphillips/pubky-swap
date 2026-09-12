//! Scoped Pubky sessions authorize a separate key for encrypted swap requests.
//!
//! The session bearer token is used only with its own homeserver. Providers read a
//! short-lived public authorization and authenticate the transport key over QUIC.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pubky_session::{PubkySession, PublicStorage};
use serde::{Deserialize, Serialize};

use crate::{canonical_pubky, Result, TransportError};

const AUTHORIZATION_LIFETIME: u64 = 600;
const MAX_AUTHORIZATION_BYTES: usize = 4096;

/// Encrypted request envelope. It contains no account or session secret.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub owner: String,
    pub scope: String,
    pub message: serde_json::Value,
}

/// Public authorization for one transport key and one provider.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwapAuthorization {
    pub version: u8,
    pub owner: String,
    pub transport_key: String,
    pub provider: String,
    pub expires_at: u64,
}

/// Session access stays on the customer's device and is never sent to the provider.
pub struct SessionClient {
    session: PubkySession,
    owner: String,
    scope: String,
    provider: String,
    transport_key: String,
}

impl SessionClient {
    /// Import a scoped session and verify the expected account and write scope.
    pub async fn connect(
        token: &str,
        owner: &str,
        scope: &str,
        provider: &str,
        transport_key: &str,
    ) -> Result<Self> {
        authorization_path(scope, transport_key)?;
        let owner = canonical_pubky(owner)?;
        let provider = canonical_pubky(provider)?;
        let session = PubkySession::import_grant_secret(token, None)
            .await
            .map_err(|_| session_error("could not validate Pubky session with its homeserver"))?;
        if session.info().public_key().z32() != owner {
            return Err(session_error(
                "Pubky session belongs to a different account",
            ));
        }
        let permitted = session
            .info()
            .capabilities()
            .iter()
            .any(|capability| capability_covers(capability, scope));
        if !permitted {
            return Err(session_error(
                "Pubky session cannot authorize swaps in this application scope",
            ));
        }
        Ok(Self {
            session,
            owner,
            scope: scope.into(),
            provider,
            transport_key: canonical_pubky(transport_key)?,
        })
    }

    /// Renew authorization immediately before each request, proving the session is still usable.
    pub async fn authorize(&self) -> Result<()> {
        let authorization = SwapAuthorization {
            version: 1,
            owner: self.owner.clone(),
            provider: self.provider.clone(),
            transport_key: self.transport_key.clone(),
            expires_at: now_unix()?.saturating_add(AUTHORIZATION_LIFETIME),
        };
        let path = authorization_path(&self.scope, &self.transport_key)?;
        let bytes = serde_json::to_vec(&authorization)?;
        self.session.storage().put(path, bytes).await.map_err(|_| {
            session_error("could not renew swap authorization with the account homeserver")
        })?;
        Ok(())
    }
}

/// Verify a fresh authorization through the account's Pubky-resolved homeserver.
pub async fn verify_request(
    request: &SessionRequest,
    remote_key: &str,
    provider: &str,
) -> Result<String> {
    let owner = canonical_pubky(&request.owner)?;
    if owner != request.owner {
        return Err(session_error("noncanonical swap account"));
    }
    let path = authorization_path(&request.scope, remote_key)?;
    let storage = PublicStorage::new().map_err(|_| session_error("Pubky resolver unavailable"))?;
    let address = format!("{owner}{path}");
    let fetch = async {
        let mut response = storage
            .get(address)
            .await
            .map_err(|_| session_error("swap authorization unavailable"))?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| session_error("invalid authorization response"))?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_AUTHORIZATION_BYTES {
                return Err(session_error("swap authorization is too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let authorization: SwapAuthorization = serde_json::from_slice(&bytes)?;
        validate_authorization(&authorization, &owner, remote_key, provider, now_unix()?)?;
        Ok(owner)
    };
    tokio::time::timeout(Duration::from_secs(15), fetch)
        .await
        .map_err(|_| session_error("swap authorization lookup timed out"))?
}

/// Derive an application transport key without reusing the wallet or account key.
pub fn derive_transport_secret(
    wallet_secret: &[u8; 32],
    owner: &str,
    provider: &str,
    scope: &str,
) -> Result<[u8; 32]> {
    let owner = canonical_pubky(owner)?;
    let provider = canonical_pubky(provider)?;
    authorization_path(scope, &owner)?;
    let context = format!("pubky-swap/session-transport/1/{owner}/{provider}/{scope}");
    Ok(*blake3::keyed_hash(wallet_secret, context.as_bytes()).as_bytes())
}

/// Public resource path, confined to an application's wallet namespace.
pub fn authorization_path(scope: &str, transport_key: &str) -> Result<String> {
    let segments: Vec<_> = scope.split('/').collect();
    let valid_segment = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value != "."
            && value != ".."
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
            })
    };
    if segments.len() != 6
        || !segments[0].is_empty()
        || segments[1] != "pub"
        || !valid_segment(segments[2])
        || !valid_segment(segments[3])
        || segments[4] != "wallet"
        || !segments[5].is_empty()
    {
        return Err(session_error("invalid swap authorization scope"));
    }
    let key = canonical_pubky(transport_key)?;
    Ok(format!("{scope}swap-authorizations/{key}.json"))
}

fn capability_covers(capability: &pubky_session::Capability, scope: &str) -> bool {
    let path = capability.scope().as_str();
    (path == scope || (path.ends_with('/') && scope.starts_with(path)))
        && capability
            .to_string()
            .rsplit(':')
            .next()
            .is_some_and(|actions| actions.contains('w'))
}

/// Read an account hint from a locally stored grant, without contacting its homeserver.
/// This is only for selecting local recovery state. It does not authorize requests;
/// `SessionClient::connect` validates the credential with the homeserver first.
pub fn session_account_hint(token: &str) -> Result<String> {
    let mut fields = token.splitn(4, ':');
    if fields.next() != Some("pubky-grant-credential-v1") {
        return Err(session_error("unsupported Pubky grant credential"));
    }
    let homeserver = fields
        .next()
        .ok_or_else(|| session_error("invalid Pubky grant"))?;
    canonical_pubky(homeserver)?;
    let secret = fields
        .next()
        .ok_or_else(|| session_error("invalid Pubky grant"))?;
    if secret.is_empty() {
        return Err(session_error("invalid Pubky grant"));
    }
    let grant = fields
        .next()
        .ok_or_else(|| session_error("invalid Pubky grant"))?;
    let claims = pubky_session::GrantClaims::decode(grant)
        .map_err(|_| session_error("invalid Pubky grant"))?;
    canonical_pubky(&claims.iss.z32())
}

fn validate_authorization(
    auth: &SwapAuthorization,
    owner: &str,
    key: &str,
    provider: &str,
    now: u64,
) -> Result<()> {
    if auth.version != 1
        || auth.owner != owner
        || auth.transport_key != key
        || auth.provider != provider
        || auth.expires_at <= now
        || auth.expires_at > now.saturating_add(AUTHORIZATION_LIFETIME + 60)
    {
        return Err(session_error(
            "swap authorization does not match this request",
        ));
    }
    Ok(())
}

fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| session_error("system clock is invalid"))
}

pub(crate) fn session_error(message: &str) -> TransportError {
    TransportError::Iroh(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_from_secret;

    #[test]
    fn grant_account_hint_uses_issuer_and_allows_offline_recovery_after_expiry() {
        use pubky_session::{ClientId, GrantClaims, GrantId, Keypair, GRANT_JWS_TYP};
        let owner = Keypair::from_secret(&[1; 32]);
        let homeserver = Keypair::from_secret(&[2; 32]).public_key().z32();
        let claims = GrantClaims {
            iss: owner.public_key(),
            client_id: ClientId::new("bitkit.to").unwrap(),
            caps: vec![pubky_session::Capability::read_write("/pub/bitkit.to/").unwrap()],
            cnf: Keypair::from_secret(&[0; 32]).public_key(),
            jti: GrantId::parse("fixture").unwrap(),
            iat: 0,
            exp: 1,
        };
        let grant = claims.sign(&owner, GRANT_JWS_TYP);
        let token = format!("pubky-grant-credential-v1:{homeserver}:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:{grant}");
        assert_eq!(
            session_account_hint(&token).unwrap(),
            owner.public_key().z32()
        );
        for invalid in [
            "",
            "owner:cookie",
            "pubky-grant-credential-v1:missing",
            "pubky-grant-credential-v2:unsupported",
        ] {
            assert!(session_account_hint(invalid).is_err());
        }
    }

    #[test]
    fn session_requires_write_access_to_the_exact_app_scope() {
        use pubky_session::Capability;
        let scope = "/pub/bitkit.to/bitkit/wallet/";
        assert!(capability_covers(
            &Capability::read_write(scope).unwrap(),
            scope
        ));
        assert!(!capability_covers(&Capability::read(scope).unwrap(), scope));
        assert!(!capability_covers(
            &Capability::read_write("/pub/other/bitkit/wallet/").unwrap(),
            scope
        ));
        assert!(!capability_covers(
            &Capability::read_write("/pub/bitkit.to/bitkit/wallet").unwrap(),
            scope
        ));
    }

    #[test]
    fn authorization_rejects_wrong_owner_provider_key_and_expiry() {
        let owner = identity_from_secret(&[1; 32]);
        let key = identity_from_secret(&[2; 32]);
        let provider = identity_from_secret(&[3; 32]);
        let mut auth = SwapAuthorization {
            version: 1,
            owner: owner.clone(),
            transport_key: key.clone(),
            provider: provider.clone(),
            expires_at: 1100,
        };
        assert!(validate_authorization(&auth, &owner, &key, &provider, 1000).is_ok());
        for (account, transport, service) in [
            (&key, &key, &provider),
            (&owner, &owner, &provider),
            (&owner, &key, &owner),
        ] {
            assert!(validate_authorization(&auth, account, transport, service, 1000).is_err());
        }
        assert!(validate_authorization(&auth, &owner, &key, &provider, 1100).is_err());
        auth.expires_at = 2000;
        assert!(validate_authorization(&auth, &owner, &key, &provider, 1000).is_err());
    }

    #[test]
    fn scope_cannot_escape_application_wallet() {
        let key = identity_from_secret(&[2; 32]);
        assert!(authorization_path("/pub/bitkit.to/bitkit/wallet/", &key).is_ok());
        for scope in [
            "/pub/",
            "/pub/../bitkit/wallet/",
            "/pub/bitkit.to/../wallet/",
            "/pub/bitkit.to/bitkit/wallet/../",
            "/pub/bitkit.to/bitkit/server/",
            "https://example.org/",
        ] {
            assert!(authorization_path(scope, &key).is_err(), "{scope}");
        }
    }

    #[test]
    fn transport_keys_are_stable_and_account_and_provider_scoped() {
        let owner = identity_from_secret(&[1; 32]);
        let provider = identity_from_secret(&[2; 32]);
        let secret =
            derive_transport_secret(&[3; 32], &owner, &provider, "/pub/bitkit.to/bitkit/wallet/")
                .unwrap();
        assert_eq!(
            secret,
            derive_transport_secret(&[3; 32], &owner, &provider, "/pub/bitkit.to/bitkit/wallet/")
                .unwrap()
        );
        assert_ne!(secret, [3; 32]);
        assert_ne!(
            secret,
            derive_transport_secret(&[3; 32], &provider, &owner, "/pub/bitkit.to/bitkit/wallet/")
                .unwrap()
        );
        assert_ne!(
            secret,
            derive_transport_secret(&[4; 32], &owner, &provider, "/pub/bitkit.to/bitkit/wallet/")
                .unwrap()
        );
    }
}
