use clap::Parser;
use swap_provider::{parse_directions, run, ProviderConfig};

/// pubky-swap provider daemon.
#[derive(Parser, Debug)]
#[command(name = "swap-provider", version, about)]
struct Cli {
    /// Pubky recovery file path (mutually exclusive with --recovery-phrase).
    recovery_file: Option<String>,

    /// Pubky recovery phrase (instead of a recovery file).
    #[arg(long)]
    recovery_phrase: Option<String>,

    /// Passphrase for the Pubky identity.
    #[arg(long, default_value = "")]
    pass: String,

    /// Network: bitcoin, testnet, signet, regtest.
    #[arg(long, default_value = "regtest")]
    network: String,

    /// Comma-separated swap directions to support: submarine,reverse.
    #[arg(long, default_value = "submarine,reverse")]
    directions: String,

    #[arg(long, default_value_t = 10_000)]
    min_amount: u64,
    #[arg(long, default_value_t = 1_000_000)]
    max_amount: u64,
    #[arg(long, default_value_t = 500)]
    base_fee: u64,
    #[arg(long, default_value_t = 2_000)]
    fee_ppm: u64,
    #[arg(long, default_value_t = 1)]
    confirmations: u32,
    #[arg(long, default_value_t = 144)]
    timeout_blocks: u32,

    /// Push the offer to discovered followers on startup.
    #[arg(long)]
    broadcast_offer: bool,

    #[arg(long, default_value = "https://127.0.0.1:10009")]
    lnd_address: String,
    #[arg(long, default_value = "")]
    lnd_cert: String,
    #[arg(long, default_value = "")]
    lnd_macaroon: String,

    /// Electrum server URL for the chain watcher / funding wallet (e.g. tcp://127.0.0.1:60001).
    #[arg(long, default_value = "")]
    electrum_url: String,
    /// BIP39 mnemonic for the on-chain funding wallet.
    #[arg(long, default_value = "")]
    wallet_mnemonic: String,
    /// Fee rate (sat/vB) for claim/refund transactions.
    #[arg(long, default_value_t = 2)]
    onchain_fee_rate: u64,
    /// Hold-invoice expiry in seconds.
    #[arg(long, default_value_t = 3600)]
    invoice_expiry: u64,
    /// Routing-fee cap (msat) when paying invoices.
    #[arg(long, default_value_t = 10_000)]
    max_routing_fee_msat: u64,

    /// Permit unsafe mainnet parameters (low confirmations / fee floor). Required to run on
    /// mainnet with regtest-grade settings; intended for testing only.
    #[arg(long)]
    allow_unsafe: bool,

    /// How long an issued quote stays valid, in seconds.
    #[arg(long, default_value_t = 300)]
    quote_ttl: u64,

    /// Directory for persisted in-flight swap state (so a restart can resume swaps).
    #[arg(long, default_value = "./pubky-swap-data")]
    data_dir: String,

    /// On-chain funding wallet: `lnd` (fund from your LND node's own wallet — no separate seed) or
    /// `bdk` (a separate BIP84 wallet from --wallet-mnemonic).
    #[arg(long, default_value = "bdk")]
    wallet: String,
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

    let (recovery_method, recovery_value) = match (&cli.recovery_file, &cli.recovery_phrase) {
        (Some(file), None) => ("file".to_string(), file.clone()),
        (None, Some(phrase)) => ("phrase".to_string(), phrase.clone()),
        _ => {
            return Err(anyhow::anyhow!(
                "provide exactly one of <recovery_file> or --recovery-phrase"
            ))
        }
    };

    let config = ProviderConfig {
        recovery_method,
        recovery_value,
        passphrase: cli.pass,
        network: cli.network,
        min_amount_sat: cli.min_amount,
        max_amount_sat: cli.max_amount,
        base_fee_sat: cli.base_fee,
        fee_ppm: cli.fee_ppm,
        required_confirmations: cli.confirmations,
        htlc_timeout_blocks: cli.timeout_blocks,
        directions: parse_directions(&cli.directions)?,
        broadcast_offer: cli.broadcast_offer,
        lnd_address: cli.lnd_address,
        lnd_cert_path: cli.lnd_cert,
        lnd_macaroon_path: cli.lnd_macaroon,
        electrum_url: cli.electrum_url,
        wallet_mnemonic: cli.wallet_mnemonic,
        onchain_fee_rate_sat_vb: cli.onchain_fee_rate,
        invoice_expiry_secs: cli.invoice_expiry,
        max_routing_fee_msat: cli.max_routing_fee_msat,
        allow_unsafe: cli.allow_unsafe,
        quote_ttl_secs: cli.quote_ttl,
        data_dir: cli.data_dir,
        wallet_backend: cli.wallet,
    };

    run(config).await
}
