use clap::Parser;
use swap_client::{run, ClientConfig};
use swap_common::SwapDirection;

/// pubky-swap client.
#[derive(Parser, Debug)]
#[command(name = "swap-client", version, about)]
struct Cli {
    /// Provider's pubky.
    provider: String,

    /// Pubky recovery file path (mutually exclusive with --recovery-phrase).
    recovery_file: Option<String>,

    /// Pubky recovery phrase (instead of a recovery file).
    #[arg(long)]
    recovery_phrase: Option<String>,

    #[arg(long, default_value = "")]
    pass: String,

    #[arg(long, default_value = "regtest")]
    network: String,

    /// Swap direction: submarine (on-chain→LN) or reverse (LN→on-chain).
    #[arg(long, default_value = "reverse")]
    direction: String,

    /// Amount in satoshis.
    #[arg(long)]
    amount: u64,

    /// LND gRPC endpoint used to pay the hold invoice (reverse-swap execution).
    #[arg(long, default_value = "https://127.0.0.1:10009")]
    lnd_address: String,
    #[arg(long, default_value = "")]
    lnd_cert: String,
    #[arg(long, default_value = "")]
    lnd_macaroon: String,

    /// Electrum server URL for watching/claiming the on-chain HTLC.
    #[arg(long, default_value = "")]
    electrum_url: String,
    /// Address that receives the swept on-chain funds (reverse-swap claim destination).
    #[arg(long, default_value = "")]
    claim_address: String,
    /// BIP39 mnemonic for the on-chain funding wallet (submarine swaps fund the HTLC).
    #[arg(long, default_value = "")]
    wallet_mnemonic: String,
    /// On-chain wallet: `lnd` (fund/claim via your own LND node — no seed or claim address) or
    /// `bdk` (a separate BIP84 wallet from --wallet-mnemonic, with --claim-address for reverse).
    #[arg(long, default_value = "bdk")]
    wallet: String,
    /// Fee rate (sat/vB) for the claim transaction.
    #[arg(long, default_value_t = 2)]
    onchain_fee_rate: u64,
    /// Routing-fee cap (msat) when paying the hold invoice.
    #[arg(long, default_value_t = 10_000)]
    max_routing_fee_msat: u64,
    /// Confirmations to require before acting on a provider's funding, whatever it quotes.
    /// 0 uses the network default (2 on mainnet, 1 elsewhere). Raising it is safer; lowering it
    /// below the default lets a provider get you to reveal a preimage against a funding it can
    /// still replace.
    #[arg(long, default_value_t = 0)]
    min_confirmations: u32,

    /// Most to pay in total fees, in basis points of the swap amount (500 = 5%).
    #[arg(long, default_value_t = 500)]
    max_fee_bps: u16,

    /// Hard ceiling on what this client will lock on-chain or pay over Lightning, in satoshis.
    /// 0 means no ceiling beyond the amount you asked to swap.
    #[arg(long, default_value_t = 0)]
    max_total_sat: u64,

    /// Only check the provider (request a quote and print its rates), then exit without swapping.
    #[arg(long)]
    quote_only: bool,

    /// Ring the provider's iroh P2P rendezvous (doorbell) before negotiating, so a provider that
    /// isn't already following us starts polling us. Requires a build with `--features iroh`.
    #[arg(long)]
    rendezvous_iroh: bool,
}

fn parse_direction(s: &str) -> anyhow::Result<SwapDirection> {
    match s.to_lowercase().as_str() {
        "submarine" => Ok(SwapDirection::Submarine),
        "reverse" => Ok(SwapDirection::Reverse),
        other => Err(anyhow::anyhow!("unknown direction: {other}")),
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

    let (recovery_method, recovery_value) = match (&cli.recovery_file, &cli.recovery_phrase) {
        (Some(file), None) => ("file".to_string(), file.clone()),
        (None, Some(phrase)) => ("phrase".to_string(), phrase.clone()),
        _ => {
            return Err(anyhow::anyhow!(
                "provide exactly one of <recovery_file> or --recovery-phrase"
            ))
        }
    };

    let config = ClientConfig {
        recovery_method,
        recovery_value,
        passphrase: cli.pass,
        network: cli.network,
        provider_pkarr: cli.provider,
        direction: parse_direction(&cli.direction)?,
        amount_sat: cli.amount,
        lnd_address: cli.lnd_address,
        lnd_cert_path: cli.lnd_cert,
        lnd_macaroon_path: cli.lnd_macaroon,
        electrum_url: cli.electrum_url,
        claim_address: cli.claim_address,
        wallet_mnemonic: cli.wallet_mnemonic,
        wallet_backend: cli.wallet,
        onchain_fee_rate_sat_vb: cli.onchain_fee_rate,
        max_routing_fee_msat: cli.max_routing_fee_msat,
        quote_only: cli.quote_only,
        min_confirmations: cli.min_confirmations,
        max_fee_bps: cli.max_fee_bps,
        max_total_sat: cli.max_total_sat,
        rendezvous_iroh: cli.rendezvous_iroh,
    };

    run(config).await
}
