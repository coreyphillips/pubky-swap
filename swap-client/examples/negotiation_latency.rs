//! Compare request latency to one provider over Pubky DMs and over cold and warm iroh.
//!
//! ```text
//! cargo run -p swap-client --features iroh --example negotiation_latency -- <provider> [samples]
//! ```
//!
//! The identity comes from the client configuration, e.g. `PUBKY_SWAP_RECOVERY_FILE` and
//! `PUBKY_SWAP_PASSPHRASE`. Every sample is an `OfferRequest`, which a provider answers without
//! side effects. Homeserver counts are this client's own requests; a provider answering over
//! iroh makes none for these, while one serving DMs polls its homeserver continuously.

#[cfg(feature = "iroh")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use std::time::{Duration, Instant};
    use swap_client::negotiate::{DmChannel, IrohChannel, Negotiator, Unavailable};
    use swap_client::ClientConfig;

    #[derive(Default)]
    struct Samples {
        latencies: Vec<Duration>,
        errors: usize,
    }

    impl Samples {
        fn record<T>(&mut self, started: Instant, result: anyhow::Result<T>) {
            match result {
                Ok(_) => self.latencies.push(started.elapsed()),
                Err(e) => {
                    eprintln!("request failed: {e}");
                    self.errors += 1;
                }
            }
        }

        fn report(mut self, label: &str, homeserver_requests: u64) {
            let total = self.latencies.len() + self.errors;
            self.latencies.sort();
            let at = |q: f64| {
                self.latencies
                    .get(((self.latencies.len().max(1) - 1) as f64 * q).round() as usize)
                    .map_or("n/a".to_string(), |d| format!("{d:?}"))
            };
            println!(
                "{label}: p50 {} p95 {} errors {}/{total} homeserver requests {homeserver_requests}",
                at(0.5),
                at(0.95),
                self.errors,
            );
        }
    }

    let mut args = std::env::args().skip(1);
    let provider = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: negotiation_latency <provider> [samples]"))?;
    let samples: usize = args.next().map(|s| s.parse()).transpose()?.unwrap_or(20);
    let path = swap_config::paths::resolve_config_path(None);
    let config: ClientConfig =
        swap_config::load(Some(&path), "PUBKY_SWAP_", &serde_json::json!({}))?;
    let identity = config.identity()?;
    let secret = pubky_transport::identity::secret_from_recovery(
        identity.method,
        &identity.value,
        &identity.passphrase,
    )?;

    // DMs: the first request also signs in, skips the conversation history and rings the doorbell.
    let dm = DmChannel::new(
        pubky_transport::Transport::unsigned(secret)?,
        &provider,
        false,
        Some(secret),
    );
    let negotiator = Negotiator::<Unavailable, _>::new(None, Some(dm));
    let mut first = Samples::default();
    let started = Instant::now();
    first.record(started, negotiator.offer().await);
    let transport = negotiator.fallback().unwrap().transport();
    first.report("dm, first request", transport.homeserver_requests());
    let before = transport.homeserver_requests();
    let mut warm = Samples::default();
    for _ in 0..samples {
        let started = Instant::now();
        warm.record(started, negotiator.offer().await);
    }
    warm.report("dm", transport.homeserver_requests() - before);

    let mut cold = Samples::default();
    let mut connections = 0;
    for _ in 0..samples {
        let started = Instant::now();
        let channel = IrohChannel::new(secret, &provider).await?;
        let negotiator = Negotiator::<_, Unavailable>::new(Some(channel), None);
        cold.record(started, negotiator.offer().await);
        let channel = negotiator.preferred().unwrap();
        connections += channel.connections_established();
        channel.close().await;
    }
    cold.report(&format!("iroh cold, {connections} connections"), 0);

    let channel = IrohChannel::new(secret, &provider).await?;
    let negotiator = Negotiator::<_, Unavailable>::new(Some(channel), None);
    negotiator.offer().await?;
    let mut warm = Samples::default();
    for _ in 0..samples {
        let started = Instant::now();
        warm.record(started, negotiator.offer().await);
    }
    let channel = negotiator.preferred().unwrap();
    let label = format!(
        "iroh warm, {} connections",
        channel.connections_established()
    );
    warm.report(&label, 0);
    channel.close().await;
    Ok(())
}

#[cfg(not(feature = "iroh"))]
fn main() {
    eprintln!("build with --features iroh");
}
