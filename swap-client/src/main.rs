use clap::Parser;
use serde::Serialize;
use swap_client::{run, ClientConfig};
use swap_common::SwapDirection;

/// pubky-swap client.
///
/// Settings come from four places, most specific last: built-in defaults, a TOML config file, the
/// environment, and these flags. A flag you do not pass leaves the lower layers alone.
///
/// Every flag has an environment variable, named by upper-casing it and prefixing `PUBKY_SWAP_`:
/// `--electrum-url` is `PUBKY_SWAP_ELECTRUM_URL`. Secrets have no flag, only the environment or a
/// file, because an argv value is readable by anything that can see the process table.
#[derive(Parser, Debug)]
#[command(name = "swap-client", version, about)]
struct Cli {
    /// Provider's pubky. Not needed with --resume-only.
    provider: Option<String>,

    /// Pubky recovery file path. Mutually exclusive with a configured recovery phrase.
    recovery_file: Option<String>,

    /// TOML configuration file. Defaults to $PUBKY_SWAP_CONFIG, then $PUBKY_SWAP_DATA_DIR/
    /// config.toml, then ~/.config/pubky-swap/config.toml, then ./pubky-swap.toml.
    #[arg(long)]
    config: Option<String>,

    /// Print the resolved configuration, with secrets redacted, and exit.
    #[arg(long)]
    show_config: bool,

    /// Network: bitcoin, testnet, signet, regtest.
    #[arg(long)]
    network: Option<String>,

    /// Swap direction: reverse (LN to on-chain) or submarine (on-chain to LN).
    #[arg(long)]
    direction: Option<String>,

    /// Amount in satoshis. Not needed with --resume-only.
    #[arg(long)]
    amount: Option<u64>,

    /// LND gRPC endpoint used to pay the hold invoice (reverse-swap execution).
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

    /// Electrum server URL for watching/claiming the HTLC.
    #[arg(long)]
    electrum_url: Option<String>,

    /// Address to receive the swept on-chain funds (reverse swaps).
    #[arg(long)]
    claim_address: Option<String>,

    /// On-chain wallet: `lnd`, `beignet`, or `bdk` (a BIP84 wallet from a configured mnemonic).
    #[arg(long)]
    wallet: Option<String>,

    /// Fee rate (sat/vB) floor for claim/refund transactions.
    #[arg(long)]
    onchain_fee_rate: Option<u64>,

    /// Routing-fee cap (msat) when paying the hold invoice.
    #[arg(long)]
    max_routing_fee_msat: Option<u64>,

    /// Confirmations this client requires before acting, whatever the provider quotes.
    #[arg(long)]
    min_confirmations: Option<u32>,

    /// Most this client will pay in total fees, in basis points of the swap amount.
    #[arg(long)]
    max_fee_bps: Option<u16>,

    /// Hard ceiling on anything this client will lock on-chain or pay over Lightning.
    #[arg(long)]
    max_total_sat: Option<u64>,

    /// Directory for persisted in-flight swap state.
    #[arg(long)]
    data_dir: Option<String>,

    /// Only check the provider (request a quote and print its rates), then exit without swapping.
    #[arg(long)]
    quote_only: bool,

    /// Ring the provider's iroh P2P rendezvous (doorbell) before negotiating. Requires `iroh`.
    #[arg(long)]
    rendezvous_iroh: bool,

    /// Drive any swaps a previous run left in flight, then exit without starting a new one.
    ///
    /// This is the recovery path. A swap that was interrupted still has money in it: the client's
    /// own coins in a submarine swap's HTLC, or a Lightning payment held against a reverse swap's
    /// HTLC that only this client can claim. Neither needs the provider to be reachable.
    #[arg(long)]
    resume_only: bool,
}

/// What the operator typed, in the shape the config layers merge. Absent fields contribute
/// nothing, which is what lets the file and the environment mean anything.
#[derive(Serialize, Default)]
struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_pkarr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<SwapDirection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lightning_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beignet_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beignet_tls_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    beignet_api_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnd_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnd_cert_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lnd_macaroon_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    electrum_socks5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    electrum_timeout_secs: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    electrum_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_fee_rate_sat_vb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_routing_fee_msat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_confirmations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_fee_bps: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_total_sat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendezvous_iroh: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_only: Option<bool>,
}

/// A boolean flag contributes only when it is set: clap reports `false` for one nobody passed,
/// and writing that into the top layer would turn off what the config file turned on.
fn flag(set: bool) -> Option<bool> {
    set.then_some(true)
}

fn parse_direction(s: &str) -> anyhow::Result<SwapDirection> {
    match s.to_lowercase().as_str() {
        "submarine" => Ok(SwapDirection::Submarine),
        "reverse" => Ok(SwapDirection::Reverse),
        other => Err(anyhow::anyhow!("unknown direction: {other}")),
    }
}

impl Cli {
    fn overrides(&self) -> anyhow::Result<Overrides> {
        Ok(Overrides {
            provider_pkarr: self.provider.clone(),
            recovery_file: self.recovery_file.clone(),
            network: self.network.clone(),
            direction: self.direction.as_deref().map(parse_direction).transpose()?,
            amount_sat: self.amount,
            lightning_backend: self.lightning.clone(),
            beignet_url: self.beignet_url.clone(),
            beignet_tls_cert: self.beignet_tls_cert.clone(),
            beignet_api_prefix: self.beignet_api_prefix.clone(),
            lnd_address: self.lnd_address.clone(),
            lnd_cert_path: self.lnd_cert.clone(),
            lnd_macaroon_path: self.lnd_macaroon.clone(),
            electrum_socks5: self.electrum_socks5.clone(),
            electrum_timeout_secs: self.electrum_timeout_secs,
            electrum_url: self.electrum_url.clone(),
            claim_address: self.claim_address.clone(),
            wallet_backend: self.wallet.clone(),
            onchain_fee_rate_sat_vb: self.onchain_fee_rate,
            max_routing_fee_msat: self.max_routing_fee_msat,
            min_confirmations: self.min_confirmations,
            max_fee_bps: self.max_fee_bps,
            max_total_sat: self.max_total_sat,
            data_dir: self.data_dir.clone(),
            quote_only: flag(self.quote_only),
            rendezvous_iroh: flag(self.rendezvous_iroh),
            resume_only: flag(self.resume_only),
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
    let config: ClientConfig = swap_config::load(Some(&path), "PUBKY_SWAP_", &cli.overrides()?)?;

    if cli.show_config {
        print!("{}", swap_config::to_redacted_toml(&config)?);
        return Ok(());
    }

    // A resume needs nothing from the provider: everything a swap needs to finish is already on
    // disk, which is the point of writing it there.
    if !config.resume_only && (config.provider_pkarr.is_empty() || config.amount_sat == 0) {
        return Err(anyhow::anyhow!(
            "a swap needs a provider pubky and an amount; pass --resume-only to finish swaps a \
             previous run left in flight instead"
        ));
    }

    run(config).await
}
