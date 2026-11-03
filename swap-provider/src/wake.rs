//! Waking a reverse swap's owner through the wake gateway grant it issued for that swap.
//!
//! The owner creates a grant for its own identity on [`SWAP_WAKE_TOPIC`] and hands the provider
//! the token in a [`SwapWakeCapability`]. When the swap becomes claimable the provider sends one
//! peer wake with it (`POST /v1/peer/wakes`). The gateway turns that into a silent background
//! push, bound by the owner's quota, and never learns who sent it.
//!
//! The token is a bearer secret. It is never logged or echoed, and is dropped when the wake is
//! sent or the swap ends. It is kept in an owner-only file of its own, so a grant survives a
//! restart. Not in the swap record: the driver rewrites that from its own copy, and would drop a
//! grant written beside it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use swap_common::messages::{WakeCapability, SWAP_WAKE_TOPIC, WAKE_TOKEN_MAX_LEN};
use tracing::warn;
use uuid::Uuid;

/// How long one peer wake may take before it is abandoned. The swap never waits on it.
const WAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The capability version this build understands.
const CAPABILITY_VERSION: u16 = 1;

/// The gateways this provider may call, and the capabilities owners have handed it.
pub(crate) struct Waker {
    allowlist: Vec<String>,
    held: Mutex<HashMap<Uuid, WakeCapability>>,
    file: Option<PathBuf>,
    http: reqwest::Client,
}

/// Why a capability was refused. The wording reaches the owner, so it never quotes the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Version,
    Gateway,
    Topic,
    Token,
    Expired,
    AlreadyHeld,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refused::Version => "unsupported wake capability version",
            Refused::Gateway => "wake gateway is not on this provider's allowlist",
            Refused::Topic => "wake capability does not cover the swap topic",
            Refused::Token => "wake capability token is malformed",
            Refused::Expired => "wake capability has expired",
            Refused::AlreadyHeld => "this swap already has a wake capability",
        })
    }
}

/// What became of one peer wake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WakeOutcome {
    /// 202: the gateway took it, whatever became of the push.
    Accepted,
    /// 403: the grant is revoked, expired or unknown.
    GrantInvalid,
    /// 429: the owner's quota is spent. Skipped, not retried.
    RateLimited,
    /// Anything else, or no answer in time.
    Failed(String),
}

/// Whether a configured allowlist names any gateway this provider would call.
pub(crate) fn allowlist_usable(allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|url| normalized(url).starts_with("https://"))
}

/// Replace `path` with `bytes`, readable by this user only from the moment the file exists.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// A gateway URL in the one form the allowlist compares: no trailing slash.
fn normalized(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

impl Waker {
    /// `allowlist` holds gateway base URLs. Only `https` ones are kept, so an owner can never make
    /// this provider send a token in the clear.
    pub(crate) fn new(allowlist: &[String]) -> Self {
        Self::build(allowlist, false)
    }

    /// A waker that also calls plain `http` gateways, for a test gateway on loopback.
    #[cfg(test)]
    pub(crate) fn allowing_http(allowlist: &[String]) -> Self {
        Self::build(allowlist, true)
    }

    fn build(allowlist: &[String], allow_http: bool) -> Self {
        let allowlist = allowlist
            .iter()
            .map(|url| normalized(url).to_owned())
            .filter(|url| url.starts_with("https://") || (allow_http && url.starts_with("http://")))
            .collect();
        // No redirects: an allowlisted gateway must not be able to send the token elsewhere.
        let http = reqwest::Client::builder()
            .timeout(WAKE_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            allowlist,
            held: Mutex::new(HashMap::new()),
            file: None,
            http,
        }
    }

    /// Keep held capabilities in `path`, and take back the ones a previous run held.
    pub(crate) fn persisted_at(mut self, path: PathBuf) -> Self {
        let held = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                warn!("ignoring unreadable wake grants in {}", path.display());
                HashMap::new()
            }),
            Err(_) => HashMap::new(),
        };
        self.held = Mutex::new(held);
        self.file = Some(path);
        self
    }

    /// Best effort: a grant that fails to save still wakes, unless the process restarts first.
    fn save(&self, held: &HashMap<Uuid, WakeCapability>) {
        let Some(path) = &self.file else {
            return;
        };
        let written = serde_json::to_vec(held)
            .map_err(std::io::Error::from)
            .and_then(|bytes| write_owner_only(path, &bytes));
        if let Err(e) = written {
            warn!("could not save wake grants to {}: {e}", path.display());
        }
    }

    /// Whether this provider can wake anyone at all, which is what `swap-wake-v1` advertises.
    pub(crate) fn enabled(&self) -> bool {
        !self.allowlist.is_empty()
    }

    fn held(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, WakeCapability>> {
        self.held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Check a capability against the allowlist and the clock, without keeping it.
    pub(crate) fn check(&self, capability: &WakeCapability, now_unix: u64) -> Result<(), Refused> {
        if capability.v != CAPABILITY_VERSION {
            return Err(Refused::Version);
        }
        if !self
            .allowlist
            .iter()
            .any(|allowed| allowed == normalized(&capability.gateway))
        {
            return Err(Refused::Gateway);
        }
        if !capability
            .topics
            .iter()
            .any(|topic| topic == SWAP_WAKE_TOPIC)
        {
            return Err(Refused::Topic);
        }
        let token = &capability.token;
        if !token.starts_with("wkg_")
            || token.len() > WAKE_TOKEN_MAX_LEN
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Refused::Token);
        }
        if capability.expires_at <= now_unix {
            return Err(Refused::Expired);
        }
        Ok(())
    }

    /// Keep one capability for `swap_id`. The same one again is accepted, so a resend after a lost
    /// reply is not refused; a different one is.
    pub(crate) fn hold(
        &self,
        swap_id: Uuid,
        capability: WakeCapability,
        now_unix: u64,
    ) -> Result<(), Refused> {
        self.check(&capability, now_unix)?;
        let mut held = self.held();
        match held.get(&swap_id) {
            Some(existing) if *existing == capability => Ok(()),
            Some(_) => Err(Refused::AlreadyHeld),
            None => {
                held.insert(swap_id, capability);
                self.save(&held);
                Ok(())
            }
        }
    }

    /// Hand over the capability for `swap_id`, leaving none behind.
    pub(crate) fn take(&self, swap_id: Uuid) -> Option<WakeCapability> {
        let mut held = self.held();
        let taken = held.remove(&swap_id);
        if taken.is_some() {
            self.save(&held);
        }
        taken
    }

    /// Forget the capability for a swap that has ended.
    pub(crate) fn forget(&self, swap_id: Uuid) {
        self.take(swap_id);
    }

    #[cfg(test)]
    pub(crate) fn holds(&self, swap_id: Uuid) -> bool {
        self.held().contains_key(&swap_id)
    }

    /// Send one peer wake. The allowlist is checked again, in case it changed since the
    /// capability was taken in.
    pub(crate) async fn wake(&self, capability: &WakeCapability, now_unix: u64) -> WakeOutcome {
        if let Err(refused) = self.check(capability, now_unix) {
            return WakeOutcome::Failed(refused.to_string());
        }
        let url = format!("{}/v1/peer/wakes", normalized(&capability.gateway));
        let sent = self
            .http
            .post(url)
            .bearer_auth(&capability.token)
            .json(&serde_json::json!({ "topic": SWAP_WAKE_TOPIC }))
            .send()
            .await;
        match sent {
            Ok(response) => match response.status().as_u16() {
                202 => WakeOutcome::Accepted,
                403 => WakeOutcome::GrantInvalid,
                429 => WakeOutcome::RateLimited,
                status => WakeOutcome::Failed(format!("gateway answered {status}")),
            },
            // Without the URL: it is the gateway's, but nothing about this request belongs in a
            // log line beyond the kind of failure.
            Err(error) => WakeOutcome::Failed(if error.is_timeout() {
                "gateway timed out".into()
            } else if error.is_connect() {
                "gateway unreachable".into()
            } else {
                "gateway request failed".into()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: &str = "https://wake.example";

    fn capability() -> WakeCapability {
        WakeCapability {
            v: 1,
            gateway: format!("{GATEWAY}/"),
            topics: vec![SWAP_WAKE_TOPIC.into()],
            token: format!("wkg_{}_{}", "a".repeat(32), "B-c_".repeat(10)),
            expires_at: 2_000,
        }
    }

    #[test]
    fn only_an_allowlisted_https_gateway_is_accepted() {
        let waker = Waker::new(&[GATEWAY.into(), "http://plain.example".into()]);
        assert_eq!(waker.check(&capability(), 1_000), Ok(()));
        let elsewhere = WakeCapability {
            gateway: "https://attacker.example".into(),
            ..capability()
        };
        assert_eq!(waker.check(&elsewhere, 1_000), Err(Refused::Gateway));
        let plain = WakeCapability {
            gateway: "http://plain.example".into(),
            ..capability()
        };
        assert_eq!(waker.check(&plain, 1_000), Err(Refused::Gateway));
        assert!(!Waker::new(&[]).enabled());
        assert!(!Waker::new(&["http://plain.example".into()]).enabled());
    }

    #[test]
    fn a_capability_must_cover_the_swap_topic_and_be_live() {
        let waker = Waker::new(&[GATEWAY.into()]);
        let sync_only = WakeCapability {
            topics: vec!["paykit.sync".into()],
            ..capability()
        };
        assert_eq!(waker.check(&sync_only, 1_000), Err(Refused::Topic));
        assert_eq!(waker.check(&capability(), 2_000), Err(Refused::Expired));
        let v2 = WakeCapability {
            v: 2,
            ..capability()
        };
        assert_eq!(waker.check(&v2, 1_000), Err(Refused::Version));
        for token in [
            "wkp_abc",
            "wkg_has space",
            &format!("wkg_{}", "a".repeat(300)),
        ] {
            let bad = WakeCapability {
                token: token.into(),
                ..capability()
            };
            assert_eq!(waker.check(&bad, 1_000), Err(Refused::Token), "{token}");
        }
    }

    #[test]
    fn one_capability_per_swap_and_a_resend_is_not_refused() {
        let waker = Waker::new(&[GATEWAY.into()]);
        let swap_id = Uuid::new_v4();
        assert_eq!(waker.hold(swap_id, capability(), 1_000), Ok(()));
        assert_eq!(waker.hold(swap_id, capability(), 1_000), Ok(()));
        let other = WakeCapability {
            token: "wkg_other".into(),
            ..capability()
        };
        assert_eq!(waker.hold(swap_id, other, 1_000), Err(Refused::AlreadyHeld));
        assert!(waker.take(swap_id).is_some());
        assert!(waker.take(swap_id).is_none());
    }

    #[test]
    fn a_held_capability_survives_a_restart_until_taken() {
        let dir = std::env::temp_dir().join(format!("wake-grants-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wake-grants.json");
        let restart = || Waker::new(&[GATEWAY.into()]).persisted_at(path.clone());
        let swap_id = Uuid::new_v4();
        restart().hold(swap_id, capability(), 1_000).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(restart().take(swap_id), Some(capability()));
        assert!(!restart().holds(swap_id));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A gateway on loopback that answers every request with `status` and keeps what it was sent.
    async fn gateway(status: u16) -> (String, std::sync::Arc<Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    request.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&request);
                    if n == 0 || (text.contains("\r\n\r\n") && text.ends_with('}')) {
                        break;
                    }
                }
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&request).into_owned());
                let reply = format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\n\r\n");
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        (url, seen)
    }

    #[tokio::test]
    async fn one_wake_is_one_request_and_each_answer_maps() {
        for (status, outcome) in [
            (202, WakeOutcome::Accepted),
            (403, WakeOutcome::GrantInvalid),
            (429, WakeOutcome::RateLimited),
            (500, WakeOutcome::Failed("gateway answered 500".into())),
        ] {
            let (url, seen) = gateway(status).await;
            let waker = Waker::allowing_http(std::slice::from_ref(&url));
            let capability = WakeCapability {
                gateway: url,
                ..capability()
            };
            let swap_id = Uuid::new_v4();
            waker.hold(swap_id, capability, 1_000).unwrap();
            assert!(waker.holds(swap_id));
            let taken = waker.take(swap_id).unwrap();
            assert_eq!(waker.wake(&taken, 1_000).await, outcome);
            let seen = seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 1, "{seen:?}");
            let request = seen[0].to_ascii_lowercase();
            assert!(request.starts_with("post /v1/peer/wakes "), "{request}");
            assert!(request.contains(&format!(
                "authorization: bearer {}",
                taken.token.to_ascii_lowercase()
            )));
            assert!(
                request.ends_with(&format!("{{\"topic\":\"{SWAP_WAKE_TOPIC}\"}}")),
                "{request}"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_gateway_fails_without_the_token_in_the_reason() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let waker = Waker::allowing_http(std::slice::from_ref(&url));
        let capability = WakeCapability {
            gateway: url,
            ..capability()
        };
        let WakeOutcome::Failed(reason) = waker.wake(&capability, 1_000).await else {
            panic!("expected a failure");
        };
        assert!(!reason.contains("wkg_"), "{reason}");
    }

    #[test]
    fn neither_debug_nor_a_refusal_shows_the_token() {
        let capability = capability();
        let debug = format!("{capability:?}");
        assert!(!debug.contains(&capability.token), "{debug}");
        let waker = Waker::new(&[GATEWAY.into()]);
        for refused in [
            Refused::Version,
            Refused::Gateway,
            Refused::Topic,
            Refused::Token,
            Refused::Expired,
            Refused::AlreadyHeld,
        ] {
            assert!(!refused.to_string().contains("wkg_"));
        }
        let _ = waker;
    }

    /// The one wake this provider sends, against a real gateway: the dev stack of
    /// synonymdev/wake, with a grant a simulated phone created for `swap.claimable`. The phone
    /// then holds exactly one `swap.claimable` push. Run it with:
    ///
    /// ```text
    /// # in a wake checkout
    /// docker compose -f docker/compose.yml --profile dev up -d --build --wait
    /// cargo build -q -p wake-cli
    /// ./target/debug/wake sim init --state target/phone.json --force --platform apns \
    ///   --ln-secret "$(printf '33%.0s' {1..32})" --pk-seed "$(printf '44%.0s' {1..32})"
    /// ./target/debug/wake sim register --state target/phone.json \
    ///   --gateway http://127.0.0.1:9010 --topics swap.claimable
    /// TOKEN=$(./target/debug/wake sim grant create --state target/phone.json \
    ///   --topics swap.claimable | jq -r .token)
    /// # in pubky-swap
    /// WAKE_GATEWAY_URL=http://127.0.0.1:9010 WAKE_GRANT_TOKEN=$TOKEN cargo test -p swap-provider \
    ///   --lib wake::tests::a_live_gateway_takes_the_claim_wake -- --ignored
    /// # back in wake: one swap.claimable push, then tear down
    /// ./target/debug/wake sim inbox --state target/phone.json --fake http://127.0.0.1:9100
    /// docker compose -f docker/compose.yml --profile dev down -v
    /// ```
    #[tokio::test]
    #[ignore = "needs a running wake gateway and a swap.claimable grant token"]
    async fn a_live_gateway_takes_the_claim_wake() {
        let gateway = std::env::var("WAKE_GATEWAY_URL").expect("WAKE_GATEWAY_URL");
        let token = std::env::var("WAKE_GRANT_TOKEN").expect("WAKE_GRANT_TOKEN");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let waker = Waker::allowing_http(std::slice::from_ref(&gateway));
        let swap_id = Uuid::new_v4();
        let capability = WakeCapability {
            v: 1,
            gateway,
            topics: vec![SWAP_WAKE_TOPIC.into()],
            token,
            expires_at: now + 3600,
        };
        waker.hold(swap_id, capability, now).unwrap();
        let taken = waker.take(swap_id).unwrap();
        assert_eq!(waker.wake(&taken, now).await, WakeOutcome::Accepted);
    }
}
