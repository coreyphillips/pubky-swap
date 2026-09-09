use clap::Parser;
use serde::Serialize;
use swap_provider::{parse_directions, run, ProviderConfig};

/// pubky-swap provider daemon.
///
/// Settings come from four places, most specific last: built-in defaults, a TOML config file,
/// the environment, and these flags. A flag you do not pass leaves the lower layers alone, which
/// is what makes the file and the environment usable at all: `--network` having a default value
/// would otherwise overwrite whatever the file said on every start.
///
/// Every flag has an environment variable, named by upper-casing it and prefixing `PUBKY_SWAP_`:
/// `--lnd-address` is `PUBKY_SWAP_LND_ADDRESS`. Secrets have no flag, only the environment or a
/// file, because an argv value is readable by anything that can see the process table.
#[derive(Parser, Debug)]
#[command(name = "swap-provider", version, about)]
struct Cli {
    /// Pubky recovery file path. Mutually exclusive with a configured recovery phrase.
    recovery_file: Option<String>,

    /// TOML configuration file. Defaults to $PUBKY_SWAP_CONFIG, then $PUBKY_SWAP_DATA_DIR/
    /// config.toml, then ~/.config/pubky-swap/config.toml, then ./pubky-swap.toml.
    #[arg(long)]
    config: Option<String>,

    /// Report on everything the daemon needs, say what to do about anything missing, and exit.
    #[arg(long)]
    doctor: bool,

    /// Print the resolved configuration, with secrets redacted, and exit.
    #[arg(long)]
    show_config: bool,

    /// Network: bitcoin, testnet, signet, regtest.
    #[arg(long)]
    network: Option<String>,

    /// Comma-separated swap directions to support: submarine,reverse.
    #[arg(long)]
    directions: Option<String>,

    #[arg(long)]
    min_amount: Option<u64>,
    #[arg(long)]
    max_amount: Option<u64>,
    #[arg(long)]
    base_fee: Option<u64>,
    #[arg(long)]
    fee_ppm: Option<u64>,
    #[arg(long)]
    confirmations: Option<u32>,
    /// Blocks from a swap being accepted to its on-chain HTLC refund branch opening.
    #[arg(long)]
    timeout_blocks: Option<u32>,

    /// Minimum blocks that must remain before the on-chain timeout for the provider to take an
    /// irreversible step (paying a submarine invoice, or committing funds to a reverse HTLC).
    #[arg(long)]
    min_claim_window_blocks: Option<u32>,

    /// Push the offer to discovered followers on startup.
    #[arg(long)]
    broadcast_offer: bool,

    #[arg(long)]
    lnd_address: Option<String>,
    #[arg(long)]
    lnd_cert: Option<String>,
    #[arg(long)]
    lnd_macaroon: Option<String>,

    /// SOCKS5 proxy for Electrum, e.g. 127.0.0.1:9050. Required to reach a .onion server.
    #[arg(long)]
    electrum_socks5: Option<String>,

    /// Per-call Electrum socket timeout, in seconds.
    #[arg(long)]
    electrum_timeout_secs: Option<u8>,

    /// Lightning backend: `lnd` (gRPC to your own node) or `beignet` (HTTP to a beignet daemon).
    #[arg(long)]
    lightning: Option<String>,

    /// Base URL of a beignet daemon.
    #[arg(long)]
    beignet_url: Option<String>,

    /// PEM root certificate for the beignet daemon, if it was started with --tls-cert.
    #[arg(long)]
    beignet_tls_cert: Option<String>,

    /// API prefix for the beignet daemon, e.g. /v1.
    #[arg(long)]
    beignet_api_prefix: Option<String>,

    /// Electrum server URL for the chain watcher / funding wallet (e.g. tcp://127.0.0.1:60001).
    #[arg(long)]
    electrum_url: Option<String>,
    /// Fee rate (sat/vB) for claim/refund transactions.
    #[arg(long)]
    onchain_fee_rate: Option<u64>,
    /// Hold-invoice expiry in seconds.
    #[arg(long)]
    invoice_expiry: Option<u64>,
    /// Routing-fee cap (msat) when paying invoices.
    #[arg(long)]
    max_routing_fee_msat: Option<u64>,

    /// Swaps this provider will drive at once.
    #[arg(long)]
    max_concurrent_swaps: Option<usize>,

    /// Swaps one counterparty may have in flight at once. Low by design: a counterparty that
    /// pays a hold invoice and never claims costs you two on-chain fees and a timeout of locked
    /// capital, at no cost to itself.
    #[arg(long)]
    max_concurrent_per_peer: Option<usize>,

    /// Most this provider will have committed on chain across all live swaps.
    #[arg(long)]
    max_total_exposure_sat: Option<u64>,

    /// Most this provider will have committed to any one counterparty.
    #[arg(long)]
    max_exposure_per_peer_sat: Option<u64>,

    /// On-chain balance kept back, so committing to a swap never leaves the wallet unable to pay
    /// for a refund it may owe.
    #[arg(long)]
    min_onchain_reserve_sat: Option<u64>,

    /// New swaps one counterparty may start per hour.
    #[arg(long)]
    max_new_swaps_per_peer_per_hour: Option<u32>,

    /// Permit unsafe mainnet parameters (low confirmations / fee floor). Required to run on
    /// mainnet with regtest-grade settings; intended for testing only.
    #[arg(long)]
    allow_unsafe: bool,

    /// How long an issued quote stays valid, in seconds.
    #[arg(long)]
    quote_ttl: Option<u64>,

    /// Directory for persisted in-flight swap state (so a restart can resume swaps).
    #[arg(long)]
    data_dir: Option<String>,

    /// On-chain funding wallet: `lnd` (your LND node's own wallet, no separate seed),
    /// `beignet` (a beignet daemon's wallet), or `bdk` (a separate BIP84 wallet from a
    /// configured mnemonic).
    #[arg(long)]
    wallet: Option<String>,

    /// Seconds of inactivity before an unpinned peer (a client that never completed a swap) is
    /// evicted from the poll set and unfollowed. 0 disables idle reaping. Peers are evicted
    /// immediately on swap completion regardless of this value.
    #[arg(long)]
    peer_idle_ttl: Option<u64>,

    /// Accept iroh P2P rendezvous connections (the "doorbell") so clients that know our pubky can
    /// reach us without a pre-existing follow. Requires a build with `--features iroh`.
    #[arg(long)]
    rendezvous_iroh: bool,

    /// Serve a read-only status API here, e.g. 127.0.0.1:9737. Off unless set.
    ///
    /// Read-only by design: it exists so a dashboard or a health check can see what the daemon is
    /// doing without parsing its logs. The bearer token it requires is written to
    /// <data-dir>/status.token at 0600.
    #[arg(long)]
    status_addr: Option<String>,
}

/// What the operator typed, in the shape the config layers merge.
///
/// Every field is `Option` and skipped when absent, which is the whole mechanism: a flag that was
/// not passed contributes nothing, rather than contributing a default that silently outranks the
/// config file it was supposed to sit above.
#[derive(Serialize, Default)]
struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    directions: Option<Vec<swap_common::SwapDirection>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_amount_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_amount_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_fee_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_ppm: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_confirmations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    htlc_timeout_blocks: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_claim_window_blocks: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    broadcast_offer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lightning_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnd_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnd_cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnd_macaroon_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beignet_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beignet_tls_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beignet_api_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    electrum_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    electrum_socks5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    electrum_timeout_secs: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_fee_rate_sat_vb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invoice_expiry_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_routing_fee_msat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_concurrent_swaps: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_concurrent_per_peer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_total_exposure_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_exposure_per_peer_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_onchain_reserve_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_new_swaps_per_peer_per_hour: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_unsafe: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_idle_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendezvous_iroh: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_addr: Option<String>,
}

/// A boolean flag contributes only when it is set.
///
/// clap gives `false` for a flag nobody passed, and `false` is a value: written into the top
/// layer it would turn off whatever the config file had turned on.
fn flag(set: bool) -> Option<bool> {
    set.then_some(true)
}

impl Cli {
    fn overrides(&self) -> anyhow::Result<Overrides> {
        Ok(Overrides {
            recovery_file: self.recovery_file.clone(),
            network: self.network.clone(),
            directions: self
                .directions
                .as_deref()
                .map(parse_directions)
                .transpose()?,
            min_amount_sat: self.min_amount,
            max_amount_sat: self.max_amount,
            base_fee_sat: self.base_fee,
            fee_ppm: self.fee_ppm,
            required_confirmations: self.confirmations,
            htlc_timeout_blocks: self.timeout_blocks,
            min_claim_window_blocks: self.min_claim_window_blocks,
            broadcast_offer: flag(self.broadcast_offer),
            lightning_backend: self.lightning.clone(),
            lnd_address: self.lnd_address.clone(),
            lnd_cert_path: self.lnd_cert.clone(),
            lnd_macaroon_path: self.lnd_macaroon.clone(),
            beignet_url: self.beignet_url.clone(),
            beignet_tls_cert: self.beignet_tls_cert.clone(),
            beignet_api_prefix: self.beignet_api_prefix.clone(),
            electrum_url: self.electrum_url.clone(),
            electrum_socks5: self.electrum_socks5.clone(),
            electrum_timeout_secs: self.electrum_timeout_secs,
            onchain_fee_rate_sat_vb: self.onchain_fee_rate,
            invoice_expiry_secs: self.invoice_expiry,
            max_routing_fee_msat: self.max_routing_fee_msat,
            max_concurrent_swaps: self.max_concurrent_swaps,
            max_concurrent_per_peer: self.max_concurrent_per_peer,
            max_total_exposure_sat: self.max_total_exposure_sat,
            max_exposure_per_peer_sat: self.max_exposure_per_peer_sat,
            min_onchain_reserve_sat: self.min_onchain_reserve_sat,
            max_new_swaps_per_peer_per_hour: self.max_new_swaps_per_peer_per_hour,
            allow_unsafe: flag(self.allow_unsafe),
            quote_ttl_secs: self.quote_ttl,
            data_dir: self.data_dir.clone(),
            wallet_backend: self.wallet.clone(),
            peer_idle_ttl_secs: self.peer_idle_ttl,
            rendezvous_iroh: flag(self.rendezvous_iroh),
            status_addr: self.status_addr.clone(),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let path = swap_config::paths::resolve_config_path(cli.config.as_deref());
    let config: ProviderConfig = swap_config::load(Some(&path), "PUBKY_SWAP_", &cli.overrides()?)?;

    if cli.show_config {
        print!("{}", swap_config::to_redacted_toml(&config)?);
        return Ok(());
    }

    if cli.doctor {
        let report = swap_provider::preflight::diagnose(&config).await;
        print!("{}", report.render());
        // A non-zero exit is what makes this usable from a health check or a container's
        // readiness probe, rather than something a person has to read.
        if !report.is_capable() {
            std::process::exit(1);
        }
        return Ok(());
    }

    run(config).await
}
