//! The HTTP layer: auth, the response envelope, retries, and timeouts.

use crate::error::{BeignetApiError, BeignetError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;
use tracing::debug;

/// A bearer credential.
///
/// A newtype whose `Debug` redacts, so the token cannot reach a log line or an `anyhow` chain by
/// being formatted along with the config that holds it.
#[derive(Clone)]
pub struct ApiToken(String);

impl ApiToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiToken(<redacted>)")
    }
}

/// How to reach a beignet daemon.
#[derive(Debug, Clone)]
pub struct BeignetConfig {
    /// Base URL, e.g. `http://127.0.0.1:2112`.
    pub url: String,
    /// Bearer token. beignet exempts only `/health`, `/readiness`, `/openapi.json` and (unless
    /// configured otherwise) `/metrics` from auth, so everything this crate does needs one.
    pub token: Option<ApiToken>,
    /// Optional `/v1` prefix, which beignet accepts and strips.
    pub api_prefix: String,
    /// PEM root certificate, when the daemon was started with `--tls-cert`.
    pub tls_cert_pem: Option<Vec<u8>>,
    /// Timeout for ordinary calls.
    pub timeout: Duration,
    /// Timeout for paying an invoice, which legitimately takes minutes.
    pub pay_timeout: Duration,
    /// Attempts for a request we have decided is safe to repeat.
    pub attempts: u32,
}

impl BeignetConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: None,
            api_prefix: String::new(),
            tls_cert_pem: None,
            timeout: Duration::from_secs(15),
            // Beignet's own default payment timeout is 60s and callers may raise it; leave room
            // above whatever it uses so a client-side timeout never fires first and leaves us
            // guessing whether a payment went out.
            pay_timeout: Duration::from_secs(310),
            attempts: 3,
        }
    }

    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.map(ApiToken::new);
        self
    }
}

/// Fetch a route that answers with a bare document rather than the usual envelope.
///
/// There is exactly one: `GET /openapi.json` returns the specification itself, since it is meant
/// to be readable by tools that know nothing about this API's conventions. Putting it through
/// the envelope decoder fails, and the caller that reads it is the startup capability probe,
/// whose failure mode is answering "no" to every question.
#[derive(serde::Deserialize)]
struct Envelope<T> {
    ok: bool,
    result: Option<T>,
    error: Option<EnvelopeError>,
}

#[derive(serde::Deserialize)]
struct EnvelopeError {
    code: Option<String>,
    message: Option<String>,
}

/// Whether a request may be repeated after an ambiguous failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Safe to repeat: reading, or a write whose effect is the same twice.
    Safe,
    /// Never repeat. `POST /send` is the case that matters: a lost response is
    /// indistinguishable from a lost request, and repeating it would spend the money twice.
    ///
    /// beignet honours `X-Idempotency-Key` on `/send` since 0.15.0, which would make a retry
    /// safe against a daemon new enough. This stays as it is anyway, because the callers no
    /// longer need it: a funding whose outcome is unknown is now watched for on chain rather
    /// than attempted again, which is correct whatever the daemon in front of us supports.
    Never,
}

pub struct BeignetHttp {
    client: reqwest::Client,
    config: BeignetConfig,
}

impl BeignetHttp {
    pub fn new(config: BeignetConfig) -> Result<Self, BeignetError> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(token) = &config.token {
            // Installed as a default header so no call site can forget it.
            let mut value =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose()))
                    .map_err(|e| BeignetError::Config(format!("api token: {e}")))?;
            value.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(5))
            .timeout(config.timeout);

        #[cfg(feature = "tls")]
        if let Some(pem) = &config.tls_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| BeignetError::Config(format!("tls certificate: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        let client = builder
            .build()
            .map_err(|e| BeignetError::Config(format!("http client: {e}")))?;
        Ok(Self { client, config })
    }

    pub fn config(&self) -> &BeignetConfig {
        &self.config
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}{}{}",
            self.config.url.trim_end_matches('/'),
            self.config.api_prefix,
            path
        )
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, BeignetError> {
        self.send(reqwest::Method::GET, path, None::<&()>, Retry::Safe, None)
            .await
    }

    /// Fetch a route that answers with a bare document rather than the usual envelope.
    ///
    /// See the note above `Envelope`: `GET /openapi.json` is the only one, and reading it through
    /// the envelope decoder fails on every real daemon.
    pub async fn get_unenveloped<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, BeignetError> {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .await
            .map_err(|e| BeignetError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| BeignetError::Transport(format!("reading the body: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(BeignetError::Api(BeignetApiError {
                http_status: status,
                code: "HTTP_ERROR".into(),
                message: text.chars().take(200).collect::<String>(),
            }));
        }
        serde_json::from_str(&text).map_err(|e| {
            BeignetError::Decode(format!(
                "HTTP {status} body did not parse ({e}): {}",
                text.chars().take(200).collect::<String>()
            ))
        })
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        retry: Retry,
    ) -> Result<T, BeignetError> {
        self.send(reqwest::Method::POST, path, Some(body), retry, None)
            .await
    }

    /// A POST with its own timeout, for calls that legitimately take minutes.
    pub async fn post_slow<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        retry: Retry,
    ) -> Result<T, BeignetError> {
        self.send(
            reqwest::Method::POST,
            path,
            Some(body),
            retry,
            Some(self.config.pay_timeout),
        )
        .await
    }

    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
        retry: Retry,
        timeout: Option<Duration>,
    ) -> Result<T, BeignetError> {
        let attempts = match retry {
            Retry::Safe => self.config.attempts.max(1),
            Retry::Never => 1,
        };
        let mut backoff = Duration::from_millis(200);
        let mut last: Option<BeignetError> = None;

        for attempt in 1..=attempts {
            let mut req = self.client.request(method.clone(), self.url(path));
            if let Some(b) = body {
                req = req.json(b);
            }
            if let Some(t) = timeout {
                req = req.timeout(t);
            }
            match self.execute(req).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if !e.is_transient() || attempt == attempts {
                        return Err(e);
                    }
                    debug!("beignet {method} {path} failed (attempt {attempt}): {e}");
                    last = Some(e);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(2));
                }
            }
        }
        Err(last.unwrap_or_else(|| BeignetError::Transport("no attempts made".into())))
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        req: reqwest::RequestBuilder,
    ) -> Result<T, BeignetError> {
        let resp = req
            .send()
            .await
            .map_err(|e| BeignetError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| BeignetError::Transport(format!("reading the body: {e}")))?;

        let envelope: Envelope<T> = serde_json::from_str(&text).map_err(|e| {
            BeignetError::Decode(format!(
                "HTTP {status} body was not a beignet envelope ({e}): {}",
                text.chars().take(200).collect::<String>()
            ))
        })?;

        if !envelope.ok {
            let err = envelope.error.unwrap_or(EnvelopeError {
                code: None,
                message: None,
            });
            return Err(BeignetError::Api(BeignetApiError {
                http_status: status,
                code: err.code.unwrap_or_else(|| "UNKNOWN".into()),
                message: err.message.unwrap_or_else(|| "no message".into()),
            }));
        }
        envelope.result.ok_or_else(|| {
            BeignetError::Decode("the daemon reported success with no result".into())
        })
    }
}
