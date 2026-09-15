//! Scoped Pubky sessions authorize a separate key for encrypted swap requests.
//!
//! The session bearer token is used only with its own homeserver. Providers read a
//! short-lived public authorization and authenticate the transport key over QUIC.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use pubky_session::{pkarr, Method, PubkyHttpClient, PubkySession};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::debug;

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

/// Upper bound on one lookup, including time spent waiting for a lookup slot.
const AUTHORIZATION_LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);
/// Matches the session request queue in `p2p`, so a full queue cannot fan out
/// into more homeserver lookups than that.
const MAX_CONCURRENT_LOOKUPS: usize = 16;
/// The Pubky client keeps a resolver entry for every account it has looked up and
/// never evicts them. Owners arrive before they are authorized, so the client is
/// replaced once it has seen this many.
const MAX_OWNERS_PER_CLIENT: usize = 1024;
/// Transport choices, matching Pubky's own client.
const ROUTE_TTL: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

type ClientFactory = dyn Fn() -> pkarr::ClientBuilder + Send + Sync;

/// Provider-side authorization checks over one long-lived Pubky HTTP client.
///
/// Sharing the client keeps its connection pool and resolver cache warm across
/// requests. Authorization decisions are never cached: every request fetches the
/// current record and validates it, so removal and expiry take effect at once.
///
/// `PublicStorage::get` reads the whole body of an error response before it
/// returns, so no size limit could apply to it. Lookups send their own request
/// instead, choosing between the homeserver's direct and ICANN endpoints the way
/// that API does, which needs a resolver of our own.
#[derive(Clone)]
pub struct AuthorizationVerifier {
    factory: Arc<ClientFactory>,
    client: Arc<Mutex<SharedClient>>,
    provider: String,
    lookups: Arc<Semaphore>,
    timeout: Duration,
    max_owners: usize,
}

struct SharedClient {
    http: PubkyHttpClient,
    pkarr: pkarr::Client,
    generation: u64,
    /// Owners this client has seen, with the route last chosen for each.
    owners: HashMap<String, Option<(Instant, Route)>>,
}

/// How to reach an owner's homeserver.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Direct,
    Icann { domain: String, port: Option<u16> },
}

struct Lookup {
    http: PubkyHttpClient,
    pkarr: pkarr::Client,
    generation: u64,
    route: Option<Route>,
}

/// Where one lookup spent its time. Resolution and connection setup happen inside
/// the HTTP client, so they are reported together with the response headers.
#[derive(Debug, Clone, Copy)]
struct LookupTiming {
    queued: Duration,
    response: Duration,
    body: Duration,
}

impl AuthorizationVerifier {
    /// Build a verifier with a default mainline Pubky client.
    pub fn new(provider: &str) -> Result<Self> {
        Self::with_client_factory(pkarr::ClientBuilder::default, provider)
    }

    /// Build a verifier whose clients resolve through `factory`'s configuration,
    /// which is asked for again whenever the current client is replaced.
    pub fn with_client_factory(
        factory: impl Fn() -> pkarr::ClientBuilder + Send + Sync + 'static,
        provider: &str,
    ) -> Result<Self> {
        let provider = canonical_pubky(provider)?;
        let factory: Arc<ClientFactory> = Arc::new(factory);
        let client = build_client(factory.as_ref(), 0)?;
        Ok(Self {
            factory,
            client: Arc::new(Mutex::new(client)),
            provider,
            lookups: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            timeout: AUTHORIZATION_LOOKUP_TIMEOUT,
            max_owners: MAX_OWNERS_PER_CLIENT,
        })
    }

    /// The shared client, replaced first if `owner` would take it past its owner
    /// limit. Lookups already running keep the old client until they finish.
    fn client_for(&self, owner: &str) -> Result<Lookup> {
        let mut client = self.client.lock().unwrap_or_else(PoisonError::into_inner);
        if !client.owners.contains_key(owner) {
            if client.owners.len() >= self.max_owners {
                *client = build_client(self.factory.as_ref(), client.generation + 1)?;
            }
            client.owners.insert(owner.to_string(), None);
        }
        let route = client.owners[owner]
            .as_ref()
            .filter(|(chosen, _)| chosen.elapsed() < ROUTE_TTL)
            .map(|(_, route)| route.clone());
        Ok(Lookup {
            http: client.http.clone(),
            pkarr: client.pkarr.clone(),
            generation: client.generation,
            route,
        })
    }

    /// Kept only while the client that chose the route is still the shared one,
    /// so replaced clients cannot grow the new client's owner map.
    fn remember_route(&self, owner: &str, generation: u64, route: Route) {
        let mut client = self.client.lock().unwrap_or_else(PoisonError::into_inner);
        if client.generation != generation {
            return;
        }
        if let Some(entry) = client.owners.get_mut(owner) {
            *entry = Some((Instant::now(), route));
        }
    }

    /// Send the lookup and read at most `MAX_AUTHORIZATION_BYTES` of the body,
    /// whatever its status. Also returns how long the response headers took,
    /// including resolution.
    async fn fetch(&self, owner: &str, path: &str) -> Result<(Vec<u8>, Duration)> {
        let started = Instant::now();
        let lookup = self.client_for(owner)?;
        let route = match lookup.route {
            Some(route) => route,
            None => {
                let route = resolve_route(&lookup.pkarr, &format!("_pubky.{owner}")).await;
                self.remember_route(owner, lookup.generation, route.clone());
                route
            }
        };
        let request = match &route {
            Route::Direct => lookup
                .http
                .request(Method::GET, &format!("https://_pubky.{owner}{path}")),
            Route::Icann { domain, port } => {
                let authority =
                    port.map_or_else(|| domain.clone(), |port| format!("{domain}:{port}"));
                lookup
                    .http
                    .request(Method::GET, &format!("https://{authority}{path}"))
                    .header("pubky-host", owner)
            }
        };
        let mut response = request
            .send()
            .await
            .map_err(|_| session_error("swap authorization unavailable"))?;
        let response_at = started.elapsed();
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
        if !response.status().is_success() {
            return Err(session_error("swap authorization unavailable"));
        }
        Ok((bytes, response_at))
    }

    /// Verify a fresh authorization through the account's Pubky-resolved homeserver.
    pub async fn verify(&self, request: &SessionRequest, remote_key: &str) -> Result<String> {
        let (owner, timing) = self.verify_timed(request, remote_key).await?;
        debug!(
            queued = ?timing.queued,
            response = ?timing.response,
            body = ?timing.body,
            "verified swap authorization"
        );
        Ok(owner)
    }

    async fn verify_timed(
        &self,
        request: &SessionRequest,
        remote_key: &str,
    ) -> Result<(String, LookupTiming)> {
        let owner = canonical_pubky(&request.owner)?;
        if owner != request.owner {
            return Err(session_error("noncanonical swap account"));
        }
        let path = authorization_path(&request.scope, remote_key)?;
        let lookup = async {
            let started = Instant::now();
            let _permit = self
                .lookups
                .acquire()
                .await
                .map_err(|_| session_error("swap authorization unavailable"))?;
            let queued = started.elapsed();
            let (bytes, response) = self.fetch(&owner, &path).await?;
            let timing = LookupTiming {
                queued,
                response,
                body: started.elapsed() - queued - response,
            };
            let authorization: SwapAuthorization = serde_json::from_slice(&bytes)?;
            validate_authorization(
                &authorization,
                &owner,
                remote_key,
                &self.provider,
                now_unix()?,
            )?;
            Ok((owner, timing))
        };
        tokio::time::timeout(self.timeout, lookup)
            .await
            .map_err(|_| session_error("swap authorization lookup timed out"))?
    }
}

fn build_client(factory: &ClientFactory, generation: u64) -> Result<SharedClient> {
    let started = Instant::now();
    let config = factory();
    let pkarr = config
        .clone()
        .build()
        .map_err(|_| session_error("Pubky resolver unavailable"))?;
    let mut builder = PubkyHttpClient::builder();
    builder.pkarr(|pkarr| {
        *pkarr = config;
        pkarr
    });
    let http = builder
        .build()
        .map_err(|_| session_error("Pubky resolver unavailable"))?;
    debug!(elapsed = ?started.elapsed(), "built Pubky authorization client");
    Ok(SharedClient {
        http,
        pkarr,
        generation,
        owners: HashMap::new(),
    })
}

/// Pubky's transport choice: the direct endpoint unless the homeserver publishes
/// only an ICANN domain, or also publishes one and the direct endpoint is unreachable.
async fn resolve_route(pkarr: &pkarr::Client, qname: &str) -> Route {
    let endpoints = pkarr.resolve_https_endpoints(qname);
    futures::pin_mut!(endpoints);
    let mut direct: Option<Vec<SocketAddr>> = None;
    let mut icann = None;
    while let Some(endpoint) = endpoints.next().await {
        match endpoint.domain() {
            Some(domain) => {
                icann.get_or_insert_with(|| (domain.to_string(), endpoint.port()));
            }
            None => direct
                .get_or_insert_with(Vec::new)
                .extend(endpoint.to_socket_addrs()),
        }
    }
    let Some((domain, port)) = icann else {
        return Route::Direct;
    };
    if let Some(addrs) = direct {
        for addr in addrs {
            if let Ok(Ok(_)) = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await {
                return Route::Direct;
            }
        }
    }
    Route::Icann { domain, port }
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

    mod lookup_fixture {
        //! A local DHT and a minimal homeserver reached through the real Pubky client:
        //! pkarr resolution, raw-public-key TLS and HTTP/1.1 keep-alive.

        use super::*;
        use pubky_session::pkarr::dns::rdata::SVCB;
        use pubky_session::pkarr::{Client as PkarrClient, Keypair, SignedPacket};
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        const SCOPE: &str = "/pub/bitkit.to/bitkit/wallet/";

        enum Reply {
            Body(Vec<u8>),
            Error(Vec<u8>),
            Stall,
        }

        #[derive(Default)]
        struct Counters {
            accepted: AtomicUsize,
            open: AtomicUsize,
            requests: AtomicUsize,
            in_flight: AtomicUsize,
            peak_in_flight: AtomicUsize,
        }

        /// Counts a connection as open until its task finishes or is aborted.
        struct OpenConnection(Arc<Counters>);

        impl Drop for OpenConnection {
            fn drop(&mut self) {
                self.0.open.fetch_sub(1, Ordering::SeqCst);
            }
        }

        struct Homeserver {
            dht: mainline::Testnet,
            owner: String,
            transport_key: String,
            provider: String,
            files: Arc<Mutex<HashMap<String, Reply>>>,
            counters: Arc<Counters>,
            server: tokio::task::JoinHandle<()>,
        }

        impl Homeserver {
            async fn start() -> Self {
                let dht = mainline::Testnet::builder(3).build().unwrap();
                let homeserver = Keypair::random();
                let owner = Keypair::random();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();

                let pkarr = pkarr_client(&dht);
                let root = ".".try_into().unwrap();
                let mut endpoint = SVCB::new(1, ".".try_into().unwrap());
                endpoint.set_port(port);
                endpoint.set_ipv4hint(&[Ipv4Addr::LOCALHOST.to_bits()]);
                let packet = SignedPacket::builder()
                    .https(root, endpoint, 3600)
                    .address(
                        ".".try_into().unwrap(),
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        3600,
                    )
                    .sign(&homeserver)
                    .unwrap();
                pkarr.publish(&packet).await.unwrap();
                let homeserver_name = homeserver.public_key().to_z32();
                let packet = SignedPacket::builder()
                    .https(
                        "_pubky".try_into().unwrap(),
                        SVCB::new(0, homeserver_name.as_str().try_into().unwrap()),
                        3600,
                    )
                    .sign(&owner)
                    .unwrap();
                pkarr.publish(&packet).await.unwrap();

                let files = Arc::new(Mutex::new(HashMap::new()));
                let counters = Arc::new(Counters::default());
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
                    homeserver.to_rpk_rustls_server_config(),
                ));
                let server =
                    tokio::spawn(serve(listener, acceptor, files.clone(), counters.clone()));
                Self {
                    dht,
                    owner: owner.public_key().to_z32(),
                    transport_key: identity_from_secret(&[21; 32]),
                    provider: identity_from_secret(&[22; 32]),
                    files,
                    counters,
                    server,
                }
            }

            fn verifier(&self) -> AuthorizationVerifier {
                let bootstrap = self.dht.bootstrap.clone();
                AuthorizationVerifier::with_client_factory(
                    move || {
                        let mut pkarr = pkarr_builder(&bootstrap);
                        pkarr.request_timeout(Duration::from_millis(100));
                        pkarr
                    },
                    &self.provider,
                )
                .unwrap()
            }

            fn request(&self) -> SessionRequest {
                SessionRequest {
                    owner: self.owner.clone(),
                    scope: SCOPE.into(),
                    message: serde_json::json!({}),
                }
            }

            fn path(&self) -> String {
                authorization_path(SCOPE, &self.transport_key).unwrap()
            }

            fn authorize(&self, provider: &str, expires_at: u64) {
                let authorization = SwapAuthorization {
                    version: 1,
                    owner: self.owner.clone(),
                    transport_key: self.transport_key.clone(),
                    provider: provider.into(),
                    expires_at,
                };
                self.reply(Reply::Body(serde_json::to_vec(&authorization).unwrap()));
            }

            fn reply(&self, reply: Reply) {
                self.files.lock().unwrap().insert(self.path(), reply);
            }

            fn remove(&self) {
                self.files.lock().unwrap().remove(&self.path());
            }

            fn requests(&self) -> usize {
                self.counters.requests.load(Ordering::SeqCst)
            }
        }

        fn pkarr_builder(bootstrap: &[String]) -> pkarr::ClientBuilder {
            let mut builder = PkarrClient::builder();
            builder
                .no_default_network()
                .no_relays()
                .bootstrap(bootstrap)
                .dht_report_policy(pubky_session::pkarr::dht::ReportPolicy::testnet());
            builder
        }

        fn pkarr_client(dht: &mainline::Testnet) -> PkarrClient {
            pkarr_builder(&dht.bootstrap).build().unwrap()
        }

        async fn serve(
            listener: TcpListener,
            acceptor: tokio_rustls::TlsAcceptor,
            files: Arc<Mutex<HashMap<String, Reply>>>,
            counters: Arc<Counters>,
        ) {
            // Connection tasks live in the set, so aborting the server closes them too.
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                counters.accepted.fetch_add(1, Ordering::SeqCst);
                counters.open.fetch_add(1, Ordering::SeqCst);
                let open = OpenConnection(counters.clone());
                let (acceptor, files, counters) =
                    (acceptor.clone(), files.clone(), counters.clone());
                connections.spawn(async move {
                    let _open = open;
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let _ = serve_connection(stream, &files, &counters).await;
                    }
                });
            }
        }

        async fn serve_connection(
            stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            files: &Mutex<HashMap<String, Reply>>,
            counters: &Counters,
        ) -> std::io::Result<()> {
            let mut stream = BufReader::new(stream);
            loop {
                let mut request_line = String::new();
                if stream.read_line(&mut request_line).await? == 0 {
                    return Ok(());
                }
                loop {
                    let mut header = String::new();
                    if stream.read_line(&mut header).await? == 0 {
                        return Ok(());
                    }
                    if header == "\r\n" {
                        break;
                    }
                }
                counters.requests.fetch_add(1, Ordering::SeqCst);
                let in_flight = counters.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                counters
                    .peak_in_flight
                    .fetch_max(in_flight, Ordering::SeqCst);
                // Long enough for concurrent lookups to overlap at the server.
                tokio::time::sleep(Duration::from_millis(10)).await;
                counters.in_flight.fetch_sub(1, Ordering::SeqCst);
                let path = request_line.split(' ').nth(1).unwrap_or_default();
                let reply = match files.lock().unwrap().get(path) {
                    Some(Reply::Body(body)) => Some(Some(("200 OK", body.clone()))),
                    Some(Reply::Error(body)) => {
                        Some(Some(("500 Internal Server Error", body.clone())))
                    }
                    Some(Reply::Stall) => Some(None),
                    None => None,
                };
                let (status, body) = match reply {
                    Some(Some(reply)) => reply,
                    Some(None) => {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return Ok(());
                    }
                    None => {
                        stream
                            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                            .await?;
                        continue;
                    }
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(&body).await?;
                stream.flush().await?;
            }
        }

        impl Drop for Homeserver {
            fn drop(&mut self) {
                self.server.abort();
            }
        }

        async fn wait_for(condition: impl Fn() -> bool) -> bool {
            for _ in 0..100 {
                if condition() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            false
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn repeated_lookups_reuse_one_connection_and_fetch_every_time() {
            let homeserver = Homeserver::start().await;
            let expires = now_unix().unwrap() + AUTHORIZATION_LIFETIME;
            homeserver.authorize(&homeserver.provider, expires);
            let request = homeserver.request();

            let verifier = homeserver.verifier();
            let (owner, cold) = verifier
                .verify_timed(&request, &homeserver.transport_key)
                .await
                .unwrap();
            assert_eq!(owner, homeserver.owner);
            let mut warm = Vec::new();
            for _ in 0..5 {
                let (_, timing) = verifier
                    .verify_timed(&request, &homeserver.transport_key)
                    .await
                    .unwrap();
                warm.push(timing);
            }
            // Every decision came from a fresh fetch, over the one pooled connection.
            assert_eq!(homeserver.requests(), 6);
            assert_eq!(homeserver.counters.accepted.load(Ordering::SeqCst), 1);

            // A second client is what every request used to pay for.
            let (_, fresh_client) = homeserver
                .verifier()
                .verify_timed(&request, &homeserver.transport_key)
                .await
                .unwrap();
            assert_eq!(homeserver.counters.accepted.load(Ordering::SeqCst), 2);
            eprintln!("cold lookup: {cold:?}");
            eprintln!("warm lookups: {warm:?}");
            eprintln!("second client, first lookup: {fresh_client:?}");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn concurrent_lookups_share_the_client_and_stay_bounded() {
            let homeserver = Homeserver::start().await;
            let expires = now_unix().unwrap() + AUTHORIZATION_LIFETIME;
            homeserver.authorize(&homeserver.provider, expires);
            let verifier = homeserver.verifier();
            let request = Arc::new(homeserver.request());
            let lookups: Vec<_> = (0..MAX_CONCURRENT_LOOKUPS * 2)
                .map(|_| {
                    let (verifier, request) = (verifier.clone(), request.clone());
                    let key = homeserver.transport_key.clone();
                    tokio::spawn(async move { verifier.verify(&request, &key).await })
                })
                .collect();
            for lookup in lookups {
                assert_eq!(lookup.await.unwrap().unwrap(), homeserver.owner);
            }
            assert_eq!(homeserver.requests(), MAX_CONCURRENT_LOOKUPS * 2);
            let peak = homeserver.counters.peak_in_flight.load(Ordering::SeqCst);
            assert!(peak > 1 && peak <= MAX_CONCURRENT_LOOKUPS, "{peak}");
            // The pool may race a few extra connections, so this is recorded rather than bounded.
            eprintln!(
                "connections for {} concurrent lookups: {}",
                MAX_CONCURRENT_LOOKUPS * 2,
                homeserver.counters.accepted.load(Ordering::SeqCst)
            );
            assert_eq!(Arc::strong_count(&verifier.lookups), 1);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn every_request_sees_the_current_authorization() {
            let homeserver = Homeserver::start().await;
            let verifier = homeserver.verifier();
            let request = homeserver.request();
            let key = homeserver.transport_key.clone();
            let now = now_unix().unwrap();
            let valid = now + AUTHORIZATION_LIFETIME;

            homeserver.authorize(&homeserver.provider, valid);
            assert!(verifier.verify(&request, &key).await.is_ok());

            homeserver.remove();
            assert!(verifier.verify(&request, &key).await.is_err());

            homeserver.authorize(&homeserver.provider, valid);
            assert!(verifier.verify(&request, &key).await.is_ok());

            homeserver.authorize(&homeserver.owner, valid);
            assert!(verifier.verify(&request, &key).await.is_err());

            homeserver.authorize(&homeserver.provider, now);
            assert!(verifier.verify(&request, &key).await.is_err());

            homeserver.authorize(&homeserver.provider, valid);
            let other_key = identity_from_secret(&[23; 32]);
            assert!(verifier.verify(&request, &other_key).await.is_err());
            let mut other_owner = homeserver.request();
            other_owner.owner = homeserver.provider.clone();
            assert!(verifier.verify(&other_owner, &key).await.is_err());
            let mut noncanonical = homeserver.request();
            noncanonical.owner = format!("pubky{}", homeserver.owner);
            assert!(verifier.verify(&noncanonical, &key).await.is_err());

            assert!(verifier.verify(&request, &key).await.is_ok());
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn oversized_slow_and_unavailable_homeservers_are_rejected() {
            let homeserver = Homeserver::start().await;
            let mut verifier = homeserver.verifier();
            let request = homeserver.request();
            let key = homeserver.transport_key.clone();

            homeserver.reply(Reply::Body(vec![b' '; MAX_AUTHORIZATION_BYTES + 1]));
            let error = verifier.verify(&request, &key).await.unwrap_err();
            assert!(error.to_string().contains("too large"), "{error}");

            // Error bodies are held to the same limit.
            homeserver.reply(Reply::Error(vec![b' '; MAX_AUTHORIZATION_BYTES + 1]));
            let error = verifier.verify(&request, &key).await.unwrap_err();
            assert!(error.to_string().contains("too large"), "{error}");
            homeserver.reply(Reply::Error(b"{}".to_vec()));
            let error = verifier.verify(&request, &key).await.unwrap_err();
            assert!(error.to_string().contains("unavailable"), "{error}");

            verifier.timeout = Duration::from_millis(500);
            homeserver.reply(Reply::Stall);
            let error = verifier.verify(&request, &key).await.unwrap_err();
            assert!(error.to_string().contains("timed out"), "{error}");

            // Waiting for a lookup slot counts against the same deadline.
            homeserver.authorize(&homeserver.provider, now_unix().unwrap() + 60);
            let slots = verifier
                .lookups
                .clone()
                .acquire_many_owned(MAX_CONCURRENT_LOOKUPS as u32)
                .await
                .unwrap();
            let error = verifier.verify(&request, &key).await.unwrap_err();
            assert!(error.to_string().contains("timed out"), "{error}");
            drop(slots);
            verifier.timeout = AUTHORIZATION_LOOKUP_TIMEOUT;
            assert!(verifier.verify(&request, &key).await.is_ok());

            homeserver.server.abort();
            assert!(wait_for(|| homeserver.counters.open.load(Ordering::SeqCst) == 0).await);
            let error = verifier.verify(&request, &key).await.unwrap_err();
            assert!(error.to_string().contains("unavailable"), "{error}");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn icann_domain_is_used_only_when_the_direct_endpoint_is_unreachable() {
            let dht = mainline::Testnet::builder(3).build().unwrap();
            let pkarr = pkarr_client(&dht);
            let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let closed_port = closed.local_addr().unwrap().port();
            drop(closed);

            let mut routes = Vec::new();
            for direct_port in [
                None,
                Some(open.local_addr().unwrap().port()),
                Some(closed_port),
            ] {
                let homeserver = Keypair::random();
                let mut builder = SignedPacket::builder();
                if let Some(port) = direct_port {
                    let mut direct = SVCB::new(1, ".".try_into().unwrap());
                    direct.set_port(port);
                    builder = builder
                        .https(".".try_into().unwrap(), direct, 3600)
                        .address(
                            ".".try_into().unwrap(),
                            IpAddr::V4(Ipv4Addr::LOCALHOST),
                            3600,
                        );
                }
                let mut icann = SVCB::new(2, "homeserver.example".try_into().unwrap());
                icann.set_port(8443);
                let packet = builder
                    .https(".".try_into().unwrap(), icann, 3600)
                    .sign(&homeserver)
                    .unwrap();
                pkarr.publish(&packet).await.unwrap();
                let owner = Keypair::random();
                let name = homeserver.public_key().to_z32();
                let packet = SignedPacket::builder()
                    .https(
                        "_pubky".try_into().unwrap(),
                        SVCB::new(0, name.as_str().try_into().unwrap()),
                        3600,
                    )
                    .sign(&owner)
                    .unwrap();
                pkarr.publish(&packet).await.unwrap();
                let qname = format!("_pubky.{}", owner.public_key().to_z32());
                routes.push(resolve_route(&pkarr, &qname).await);
            }
            let icann = Route::Icann {
                domain: "homeserver.example".into(),
                port: Some(8443),
            };
            assert_eq!(routes, [icann.clone(), Route::Direct, icann]);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn client_is_replaced_after_too_many_owners() {
            let homeserver = Homeserver::start().await;
            homeserver.authorize(&homeserver.provider, now_unix().unwrap() + 60);
            let mut verifier = homeserver.verifier();
            verifier.max_owners = 2;
            let request = homeserver.request();
            let key = homeserver.transport_key.clone();
            let strangers: Vec<_> = (30..33)
                .map(|seed| identity_from_secret(&[seed; 32]))
                .collect();

            verifier.verify(&request, &key).await.unwrap();
            let mut stranger = homeserver.request();
            stranger.owner = strangers[0].clone();
            assert!(verifier.verify(&stranger, &key).await.is_err());
            // Known owners do not count again.
            verifier.verify(&request, &key).await.unwrap();
            assert_eq!(homeserver.counters.accepted.load(Ordering::SeqCst), 1);

            for owner in &strangers[1..] {
                stranger.owner = owner.clone();
                assert!(verifier.verify(&stranger, &key).await.is_err());
            }
            let owners = verifier.client.lock().unwrap().owners.len();
            assert!(owners <= 2, "{owners}");
            // The replacement client still verifies, over a new connection.
            verifier.verify(&request, &key).await.unwrap();
            assert_eq!(homeserver.counters.accepted.load(Ordering::SeqCst), 2);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn an_open_connection_does_not_extend_authorization() {
            use crate::p2p::fixture::Provider;
            let homeserver = Homeserver::start().await;
            let verifier = homeserver.verifier();
            let Provider {
                endpoint,
                mut requests,
            } = Provider::start([22; 32], Default::default()).await;
            let client = Provider::client_for(&endpoint, [21; 32]).await;
            tokio::spawn(async move {
                while let Some(rpc) = requests.recv().await {
                    if verifier.verify(&rpc.request, &rpc.remote_key).await.is_ok() {
                        let _ = rpc.reply.send(b"authorized".to_vec());
                    }
                }
            });
            let request = homeserver.request();
            let now = now_unix().unwrap();
            let valid = now + AUTHORIZATION_LIFETIME;

            homeserver.authorize(&homeserver.provider, valid);
            assert_eq!(client.request(&request).await.unwrap(), b"authorized");
            homeserver.remove();
            assert!(client.request(&request).await.is_err());
            homeserver.authorize(&homeserver.provider, now);
            assert!(client.request(&request).await.is_err());
            homeserver.authorize(&homeserver.provider, valid);
            assert_eq!(client.request(&request).await.unwrap(), b"authorized");
            // Every decision above was made over the same connection.
            assert_eq!(client.connections_established(), 1);
            client.close().await;
            endpoint.close().await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn dropping_the_verifier_closes_its_connections() {
            let homeserver = Homeserver::start().await;
            homeserver.authorize(&homeserver.provider, now_unix().unwrap() + 60);
            let verifier = homeserver.verifier();
            let request = homeserver.request();
            verifier
                .verify(&request, &homeserver.transport_key)
                .await
                .unwrap();
            let clone = verifier.clone();
            drop(verifier);
            assert_eq!(homeserver.counters.open.load(Ordering::SeqCst), 1);
            drop(clone);
            assert!(wait_for(|| homeserver.counters.open.load(Ordering::SeqCst) == 0).await);
        }
    }
}
