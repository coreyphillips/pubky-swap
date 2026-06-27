//! Provider daemon library.
//!
//! Negotiation (offer → quote → swap-accept) is always available. When the provider is
//! fully configured — a real LND backend (`lnd`), an Electrum chain watcher (`chain`), and a
//! BDK funding wallet (`bdk-wallet`) — it also **executes** swaps: on a `SwapRequest` it
//! creates the HTLC (and, for reverse, a hold invoice), replies with a `SwapAccept`, and
//! spawns a per-swap task that drives it to completion (see [`reverse`] / [`submarine`]),
//! sending the client a final `SwapStatusUpdate`. Without those pieces it stays
//! negotiation-only and rejects `SwapRequest`s.

pub mod reverse;
pub mod store;
pub mod submarine;
#[cfg(feature = "bdk-wallet")]
pub mod wallet;

use anyhow::{anyhow, Context, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, OutPoint, PublicKey};
#[cfg(feature = "lnd")]
use lightning_backend::LndBackend;
use lightning_backend::{LightningBackend, LndConfig, StubBackend};
use pubky_transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use swap_common::chain::{run_blocking, ChainWatcher};
use swap_common::htlc::{htlc_p2wsh_address, PaymentHash};
use swap_common::{messages::*, NetworkSpec, SwapDirection, SwapState};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::reverse::{
    drive_reverse_swap, init_reverse_swap, OnchainWallet, ProgressSink, ReverseSwap,
};
use crate::store::{JsonFileSwapStore, SwapRecord, SwapStore};
use crate::submarine::{drive_submarine_swap, init_submarine_swap, SubmarineSwap};

/// Provider configuration (typically populated from the CLI).
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// "phrase" or "file".
    pub recovery_method: String,
    pub recovery_value: String,
    pub passphrase: String,
    pub network: String,
    pub min_amount_sat: u64,
    pub max_amount_sat: u64,
    pub base_fee_sat: u64,
    pub fee_ppm: u64,
    pub required_confirmations: u32,
    pub htlc_timeout_blocks: u32,
    pub directions: Vec<SwapDirection>,
    /// Push the offer to all discovered followers on startup.
    pub broadcast_offer: bool,
    pub lnd_address: String,
    pub lnd_cert_path: String,
    pub lnd_macaroon_path: String,
    /// Electrum server URL for the chain watcher (e.g. `tcp://127.0.0.1:60001`).
    pub electrum_url: String,
    /// BIP39 mnemonic for the on-chain funding wallet.
    pub wallet_mnemonic: String,
    /// Fee rate (sat/vB) for claim/refund transactions.
    pub onchain_fee_rate_sat_vb: u64,
    /// Hold-invoice expiry (seconds).
    pub invoice_expiry_secs: u64,
    /// Routing-fee cap (msat) when paying invoices (submarine swaps).
    pub max_routing_fee_msat: u64,
    /// Explicitly permit unsafe mainnet parameters (low confirmations / fee floor). Off by
    /// default so a misconfigured mainnet provider refuses to start.
    pub allow_unsafe: bool,
    /// How long an issued quote stays valid, in seconds. After this it is rejected and pruned.
    pub quote_ttl_secs: u64,
    /// Directory for persisted in-flight swap state (so a restart can resume them).
    pub data_dir: String,
    /// On-chain funding wallet backend: `"lnd"` (fund from LND's own wallet, no seed) or `"bdk"`
    /// (a separate BIP84 wallet from `wallet_mnemonic`).
    pub wallet_backend: String,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            recovery_method: "phrase".to_string(),
            recovery_value: String::new(),
            passphrase: String::new(),
            network: "regtest".to_string(),
            min_amount_sat: 10_000,
            max_amount_sat: 1_000_000,
            base_fee_sat: 500,
            fee_ppm: 2_000,
            required_confirmations: 1,
            htlc_timeout_blocks: 144,
            directions: vec![SwapDirection::Submarine, SwapDirection::Reverse],
            broadcast_offer: false,
            lnd_address: "https://127.0.0.1:10009".to_string(),
            lnd_cert_path: String::new(),
            lnd_macaroon_path: String::new(),
            electrum_url: String::new(),
            wallet_mnemonic: String::new(),
            onchain_fee_rate_sat_vb: 2,
            invoice_expiry_secs: 3600,
            max_routing_fee_msat: 10_000,
            allow_unsafe: false,
            quote_ttl_secs: 300,
            data_dir: "./pubky-swap-data".to_string(),
            wallet_backend: "bdk".to_string(),
        }
    }
}

/// Current Unix time in seconds (saturating at 0 if the clock is before the epoch).
fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Upper bound on retained quotes, so a flood of `QuoteRequest`s cannot grow the map without
/// limit even before they expire.
const MAX_TRACKED_QUOTES: usize = 10_000;

/// Drop expired quotes from the map.
fn prune_quotes(quotes: &mut HashMap<Uuid, IssuedQuote>, now: u64) {
    quotes.retain(|_, q| q.expires_at_unix == 0 || now < q.expires_at_unix);
}

/// Remove and return a still-valid quote (single-use, so a quote can't be replayed). Also prunes
/// any other expired quotes while the map is locked.
async fn take_valid_quote(ctx: &ExecCtx, quote_id: Uuid) -> Result<IssuedQuote> {
    let now = now_unix();
    let mut quotes = ctx.quotes.lock().await;
    prune_quotes(&mut quotes, now);
    let q = quotes
        .remove(&quote_id)
        .ok_or_else(|| anyhow!("unknown or expired quote"))?;
    if q.expires_at_unix != 0 && now >= q.expires_at_unix {
        return Err(anyhow!("quote expired"));
    }
    Ok(q)
}

/// Minimum HTLC funding confirmations the provider will accept on mainnet without `allow_unsafe`.
const MIN_MAINNET_CONFIRMATIONS: u32 = 2;
/// Minimum on-chain fee floor (sat/vB) the provider will accept on mainnet without `allow_unsafe`.
/// The dynamic estimator (see `onchain::resolve_fee_rate`) can raise the effective rate above
/// this; the floor only guards the fallback used when estimation is unavailable.
const MIN_MAINNET_FEE_FLOOR_SAT_VB: u64 = 5;

/// Reject obviously-unsafe parameters on mainnet unless the operator opts in via `allow_unsafe`.
/// A no-op on non-mainnet networks.
fn validate_mainnet_safety(c: &ProviderConfig, network: Network) -> Result<()> {
    if network != Network::Bitcoin || c.allow_unsafe {
        return Ok(());
    }
    if c.required_confirmations < MIN_MAINNET_CONFIRMATIONS {
        return Err(anyhow!(
            "unsafe mainnet config: required_confirmations={} (< {}); raise it or pass --allow-unsafe",
            c.required_confirmations,
            MIN_MAINNET_CONFIRMATIONS
        ));
    }
    if c.onchain_fee_rate_sat_vb < MIN_MAINNET_FEE_FLOOR_SAT_VB {
        return Err(anyhow!(
            "unsafe mainnet config: onchain_fee_rate_sat_vb={} (< {} sat/vB floor); raise it or pass --allow-unsafe",
            c.onchain_fee_rate_sat_vb,
            MIN_MAINNET_FEE_FLOOR_SAT_VB
        ));
    }
    Ok(())
}

/// Map LND's reported chain network string to a [`Network`]. Returns `None` for networks with no
/// `bitcoin::Network` equivalent (e.g. `"simnet"`).
fn lnd_network_to_bitcoin(s: &str) -> Option<Network> {
    Some(match s {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return None,
    })
}

pub fn parse_network(s: &str) -> Result<Network> {
    Ok(match s {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(anyhow!("unknown network: {other}")),
    })
}

/// Parse a comma-separated `submarine,reverse` list.
pub fn parse_directions(s: &str) -> Result<Vec<SwapDirection>> {
    s.split(',')
        .map(|d| match d.trim().to_lowercase().as_str() {
            "submarine" => Ok(SwapDirection::Submarine),
            "reverse" => Ok(SwapDirection::Reverse),
            other => Err(anyhow!("unknown direction: {other}")),
        })
        .collect()
}

/// A quote the provider has issued, retained so a later `SwapRequest` can be priced/validated.
#[derive(Debug, Clone)]
struct IssuedQuote {
    direction: SwapDirection,
    amount_sat: u64,
    fee_sat: u64,
    /// Unix seconds after which this quote is no longer honoured (0 = never).
    expires_at_unix: u64,
}

/// Shared execution context handed to message handlers and spawned driver tasks.
#[derive(Clone)]
struct ExecCtx {
    transport: Arc<Transport>,
    ln: Arc<dyn LightningBackend>,
    chain: Option<Arc<dyn ChainWatcher>>,
    wallet: Option<Arc<dyn OnchainWallet>>,
    network: Network,
    required_confirmations: u32,
    htlc_timeout_blocks: u32,
    onchain_fee_rate_sat_vb: u64,
    invoice_expiry_secs: u64,
    max_routing_fee_msat: u64,
    quote_ttl_secs: u64,
    quotes: Arc<Mutex<HashMap<Uuid, IssuedQuote>>>,
    store: Arc<dyn SwapStore>,
    /// True when the provider can execute swaps (real LN + chain + wallet present).
    capable: bool,
}

/// A [`ProgressSink`] that records driver progress into the persistent [`SwapStore`], so a
/// restart can resume the swap.
struct StoreProgress {
    store: Arc<dyn SwapStore>,
    record: std::sync::Mutex<SwapRecord>,
}

impl ProgressSink for StoreProgress {
    fn funded(&self, outpoint: OutPoint) {
        let mut rec = match self.record.lock() {
            Ok(r) => r,
            Err(_) => return,
        };
        rec.funding_txid_hex = Some(outpoint.txid.to_string());
        rec.funding_vout = Some(outpoint.vout);
        rec.state = SwapState::LockupConfirmed;
        if let Err(e) = self.store.put(&rec) {
            warn!("failed to persist funding for swap {}: {e}", rec.swap_id);
        }
    }
}

/// Run the provider daemon.
pub async fn run(config: ProviderConfig) -> Result<()> {
    let network = parse_network(&config.network)?;
    // Refuse to start with unsafe mainnet parameters (guards programmatic callers too).
    validate_mainnet_safety(&config, network)?;

    let transport = match config.recovery_method.as_str() {
        "file" => Transport::from_recovery_file(&config.recovery_value, &config.passphrase).await?,
        "phrase" => {
            Transport::from_recovery_phrase(&config.recovery_value, Some(&config.passphrase))
                .await?
        }
        other => return Err(anyhow!("unknown recovery method: {other}")),
    };
    let provider_pkarr = transport.public_key_string();
    info!("Provider pubky: {provider_pkarr}");

    // Lightning backend (real with `--features lnd`, else a stub).
    let ln = make_backend(&config).await;
    let ln_ready = match ln.node_info().await {
        Ok(info) => {
            info!(
                "Connected to LND node {} (alias {})",
                info.pubkey, info.alias
            );
            // Guard against a network mismatch (e.g. a regtest config pointed at mainnet LND).
            match info.chain_network.as_deref() {
                Some(reported) => match lnd_network_to_bitcoin(reported) {
                    Some(lnd_net) if lnd_net != network => {
                        return Err(anyhow!(
                            "network mismatch: provider configured for {network:?} but LND is on \
                             {lnd_net:?} ({reported}); aborting"
                        ));
                    }
                    Some(_) => {}
                    None => warn!(
                        "LND reported unrecognized network '{reported}'; skipping network guard"
                    ),
                },
                None => warn!("LND did not report a chain network; skipping network guard"),
            }
            true
        }
        Err(e) => {
            warn!("Lightning backend not ready: {e}");
            false
        }
    };

    let chain = build_chain(&config);
    let wallet = build_wallet(&config).await;

    let capable = ln_ready && chain.is_some() && wallet.is_some();
    if capable {
        info!("Provider is execution-capable (LND + chain watcher + funding wallet present)");
    } else {
        warn!(
            "Provider is negotiation-only (LND ready: {ln_ready}, chain: {}, wallet: {}); \
             SwapRequests will be rejected. Build with --features full and configure \
             --electrum-url / --wallet-mnemonic to enable execution.",
            chain.is_some(),
            wallet.is_some()
        );
    }

    let store: Arc<dyn SwapStore> = Arc::new(
        JsonFileSwapStore::new(format!("{}/swaps", config.data_dir)).context("open swap store")?,
    );

    let transport = Arc::new(transport);
    let ctx = ExecCtx {
        transport: transport.clone(),
        ln,
        chain,
        wallet,
        network,
        required_confirmations: config.required_confirmations,
        htlc_timeout_blocks: config.htlc_timeout_blocks,
        onchain_fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
        invoice_expiry_secs: config.invoice_expiry_secs,
        max_routing_fee_msat: config.max_routing_fee_msat,
        quote_ttl_secs: config.quote_ttl_secs,
        quotes: Arc::new(Mutex::new(HashMap::new())),
        store,
        capable,
    };

    // Resume any swaps that were in flight when we last shut down / crashed.
    resume_swaps(&ctx);
    // Watch for chain reorganizations affecting in-flight swaps.
    spawn_reorg_monitor(&ctx);

    let offer = build_offer(&config, &provider_pkarr, network);
    info!(
        "Advertising offer {} ({}..{} sat, dirs: {:?})",
        offer.offer_id, offer.min_amount_sat, offer.max_amount_sat, offer.directions
    );

    if let Err(e) = transport.discover_peers().await {
        warn!("peer discovery failed: {e}");
    }
    if config.broadcast_offer {
        for peer in transport.get_known_peers() {
            if let Err(e) = transport
                .send(&peer, &SwapMessage::Offer(offer.clone()))
                .await
            {
                debug!("failed to send offer to {peer}: {e}");
            }
        }
    }

    info!("Provider running; waiting for quote/swap requests...");
    loop {
        let messages = transport
            .receive_all::<SwapMessage>()
            .await
            .unwrap_or_default();
        for (sender, msg) in messages {
            if let Err(e) = handle_message(&ctx, &offer, &sender, msg).await {
                warn!("error handling message from {sender}: {e}");
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// Construct the Lightning backend. Real LND with the `lnd` feature (and a successful
/// connection), otherwise a stub.
async fn make_backend(config: &ProviderConfig) -> Arc<dyn LightningBackend> {
    let lnd_config = LndConfig {
        address: config.lnd_address.clone(),
        tls_cert_path: config.lnd_cert_path.clone(),
        macaroon_path: config.lnd_macaroon_path.clone(),
    };
    #[cfg(feature = "lnd")]
    {
        match LndBackend::connect(lnd_config).await {
            Ok(b) => return Arc::new(b),
            Err(e) => warn!("LND connect failed ({e}); falling back to stub backend"),
        }
    }
    #[cfg(not(feature = "lnd"))]
    {
        let _ = lnd_config;
    }
    Arc::new(StubBackend::new())
}

#[cfg(feature = "chain")]
fn build_chain(config: &ProviderConfig) -> Option<Arc<dyn ChainWatcher>> {
    if config.electrum_url.is_empty() {
        return None;
    }
    match swap_common::chain::ElectrumWatcher::new(&config.electrum_url) {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("chain watcher unavailable: {e}");
            None
        }
    }
}
#[cfg(not(feature = "chain"))]
fn build_chain(_config: &ProviderConfig) -> Option<Arc<dyn ChainWatcher>> {
    None
}

/// Build the on-chain funding wallet. `wallet_backend = "lnd"` funds from LND's own on-chain
/// balance (no separate seed); anything else uses the BDK wallet from `--wallet-mnemonic`.
async fn build_wallet(config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    if config.wallet_backend == "lnd" {
        build_lnd_wallet(config).await
    } else {
        build_bdk_wallet(config)
    }
}

#[cfg(feature = "lnd")]
async fn build_lnd_wallet(config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    let lnd_config = LndConfig {
        address: config.lnd_address.clone(),
        tls_cert_path: config.lnd_cert_path.clone(),
        macaroon_path: config.lnd_macaroon_path.clone(),
    };
    match lightning_backend::LndWallet::connect(lnd_config, config.onchain_fee_rate_sat_vb).await {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("LND on-chain wallet unavailable: {e}");
            None
        }
    }
}
#[cfg(not(feature = "lnd"))]
async fn build_lnd_wallet(_config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    warn!("wallet-backend 'lnd' requires the `lnd` feature");
    None
}

#[cfg(feature = "bdk-wallet")]
fn build_bdk_wallet(config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    if config.wallet_mnemonic.is_empty() || config.electrum_url.is_empty() {
        return None;
    }
    let network = parse_network(&config.network).ok()?;
    match crate::wallet::BdkWallet::from_mnemonic(
        &config.wallet_mnemonic,
        network,
        &config.electrum_url,
        config.onchain_fee_rate_sat_vb as f32,
    ) {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("funding wallet unavailable: {e}");
            None
        }
    }
}
#[cfg(not(feature = "bdk-wallet"))]
fn build_bdk_wallet(_config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    None
}

fn build_offer(config: &ProviderConfig, provider_pkarr: &str, network: Network) -> SwapOffer {
    SwapOffer {
        offer_id: Uuid::new_v4(),
        provider_pkarr: provider_pkarr.to_string(),
        network: NetworkSpec::from_bitcoin_network(network),
        directions: config.directions.clone(),
        min_amount_sat: config.min_amount_sat,
        max_amount_sat: config.max_amount_sat,
        base_fee_sat: config.base_fee_sat,
        fee_ppm: config.fee_ppm,
        required_confirmations: config.required_confirmations,
        htlc_timeout_blocks: config.htlc_timeout_blocks,
        lightning_node_id: None,
        // Advisory: clients should always request a fresh Quote (which carries the firm,
        // enforced expiry) before committing.
        valid_until_unix: now_unix().saturating_add(config.quote_ttl_secs),
    }
}

async fn handle_message(
    ctx: &ExecCtx,
    offer: &SwapOffer,
    sender: &str,
    msg: SwapMessage,
) -> Result<()> {
    match msg {
        SwapMessage::QuoteRequest(req) => {
            if req.offer_id != Uuid::nil() && req.offer_id != offer.offer_id {
                return Ok(());
            }
            if !offer.supports(req.direction) {
                return reject(&ctx.transport, sender, None, None, "unsupported direction").await;
            }
            if !offer.accepts_amount(req.amount_sat) {
                return reject(&ctx.transport, sender, None, None, "amount out of range").await;
            }
            let fee = offer.quote_fee(req.amount_sat);
            let now = now_unix();
            let expires_at_unix = now.saturating_add(ctx.quote_ttl_secs);
            let quote = Quote {
                quote_id: Uuid::new_v4(),
                offer_id: offer.offer_id,
                direction: req.direction,
                amount_sat: req.amount_sat,
                fee_sat: fee,
                total_sat: req.amount_sat.saturating_add(fee),
                htlc_timeout_blocks: offer.htlc_timeout_blocks,
                required_confirmations: offer.required_confirmations,
                valid_until_unix: expires_at_unix,
            };
            {
                let mut quotes = ctx.quotes.lock().await;
                prune_quotes(&mut quotes, now);
                // Bound memory under a quote flood: drop the request if we're already at capacity.
                if quotes.len() >= MAX_TRACKED_QUOTES {
                    warn!(
                        "quote cache full ({MAX_TRACKED_QUOTES}); dropping request from {sender}"
                    );
                    return reject(&ctx.transport, sender, None, None, "provider busy").await;
                }
                quotes.insert(
                    quote.quote_id,
                    IssuedQuote {
                        direction: req.direction,
                        amount_sat: req.amount_sat,
                        fee_sat: fee,
                        expires_at_unix,
                    },
                );
            }
            info!("Sending quote {} to {sender}", quote.quote_id);
            ctx.transport
                .send(sender, &SwapMessage::Quote(quote))
                .await?;
        }

        SwapMessage::SwapRequest(req) => {
            if !ctx.capable {
                return reject(
                    &ctx.transport,
                    sender,
                    None,
                    Some(req.quote_id),
                    "provider is not configured for swap execution",
                )
                .await;
            }
            let direction = req.direction;
            let quote_id = req.quote_id;
            let result = match direction {
                SwapDirection::Reverse => start_reverse(ctx, sender, req).await,
                SwapDirection::Submarine => start_submarine(ctx, sender, req).await,
            };
            if let Err(e) = result {
                warn!("failed to start {direction:?} swap: {e}");
                reject(
                    &ctx.transport,
                    sender,
                    None,
                    Some(quote_id),
                    &format!("swap start failed: {e}"),
                )
                .await?;
            }
        }

        other => debug!("ignoring message variant: {}", variant_name(&other)),
    }
    Ok(())
}

/// Start a reverse swap: create the hold invoice + HTLC, reply with `SwapAccept`, and spawn
/// the driver.
async fn start_reverse(ctx: &ExecCtx, sender: &str, req: SwapRequest) -> Result<()> {
    let chain = ctx
        .chain
        .clone()
        .ok_or_else(|| anyhow!("no chain watcher"))?;
    let quote = take_valid_quote(ctx, req.quote_id).await?;
    if quote.direction != SwapDirection::Reverse {
        return Err(anyhow!("quote {} is not for a reverse swap", req.quote_id));
    }

    let claim_pk = parse_pubkey(
        req.client_claim_pubkey_hex
            .as_deref()
            .ok_or_else(|| anyhow!("reverse swap requires client_claim_pubkey"))?,
    )?;
    let payment_hash = parse_hash32(&req.payment_hash_hex)?;

    let secp = Secp256k1::new();
    let (refund_sk, refund_pk) = swap_common::random_keypair(&secp);
    let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?;
    let timeout_height = tip + ctx.htlc_timeout_blocks;

    let swap = init_reverse_swap(
        ctx.ln.as_ref(),
        &claim_pk,
        refund_sk,
        &refund_pk,
        payment_hash,
        quote.amount_sat,
        quote.fee_sat,
        ctx.onchain_fee_rate_sat_vb,
        timeout_height,
        ctx.invoice_expiry_secs,
        ctx.network,
    )
    .await?;

    let swap_id = Uuid::new_v4();
    let accept = SwapAccept {
        quote_id: req.quote_id,
        swap_id,
        direction: SwapDirection::Reverse,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        htlc_address: htlc_p2wsh_address(&swap.htlc_script, ctx.network).to_string(),
        onchain_amount_sat: swap.onchain_amount_sat,
        timeout_block_height: swap.timeout_height,
        provider_pubkey_hex: hex::encode(refund_pk.to_bytes()),
        invoice: Some(swap.invoice.clone()),
    };
    ctx.transport
        .send(sender, &SwapMessage::SwapAccept(accept))
        .await?;
    info!("Reverse swap {swap_id} started (timeout height {timeout_height})");

    let record = SwapRecord {
        swap_id,
        direction: SwapDirection::Reverse,
        peer: sender.to_string(),
        network: NetworkSpec::from_bitcoin_network(ctx.network),
        payment_hash_hex: hex::encode(swap.payment_hash),
        onchain_amount_sat: swap.onchain_amount_sat,
        fee_rate_sat_vb: swap.fee_rate_sat_vb,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        timeout_height: swap.timeout_height,
        secret_key_hex: hex::encode(swap.refund_key.secret_bytes()),
        invoice: swap.invoice.clone(),
        max_routing_fee_msat: 0,
        required_confirmations: ctx.required_confirmations,
        funding_txid_hex: None,
        funding_vout: None,
        state: SwapState::Created,
    };
    if let Err(e) = ctx.store.put(&record) {
        warn!("failed to persist reverse swap {swap_id}: {e}");
    }
    spawn_reverse_driver(ctx, swap, record);
    Ok(())
}

/// Spawn the per-swap reverse driver task (shared by fresh starts and restart-resume), persisting
/// progress and cleaning up the store + sending a final status on completion.
fn spawn_reverse_driver(ctx: &ExecCtx, swap: ReverseSwap, record: SwapRecord) {
    let chain = match ctx.chain.clone() {
        Some(c) => c,
        None => return,
    };
    let wallet = match ctx.wallet.clone() {
        Some(w) => w,
        None => return,
    };
    let resume_funding = record.funding_outpoint();
    let peer = record.peer.clone();
    let swap_id = record.swap_id;
    let required_confirmations = record.required_confirmations;
    let progress = Arc::new(StoreProgress {
        store: ctx.store.clone(),
        record: std::sync::Mutex::new(record),
    });
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let result = drive_reverse_swap(
            ctx2.ln.as_ref(),
            chain.as_ref(),
            wallet.as_ref(),
            &swap,
            required_confirmations,
            Duration::from_secs(2),
            resume_funding,
            progress.as_ref(),
        )
        .await;
        if let Err(e) = ctx2.store.remove(swap_id) {
            warn!("failed to remove swap {swap_id} from store: {e}");
        }
        send_final_status(&ctx2.transport, &peer, swap_id, result).await;
    });
}

/// Start a submarine swap: build the HTLC the client funds, reply with `SwapAccept`, and
/// spawn the driver.
async fn start_submarine(ctx: &ExecCtx, sender: &str, req: SwapRequest) -> Result<()> {
    let chain = ctx
        .chain
        .clone()
        .ok_or_else(|| anyhow!("no chain watcher"))?;
    let quote = take_valid_quote(ctx, req.quote_id).await?;
    if quote.direction != SwapDirection::Submarine {
        return Err(anyhow!(
            "quote {} is not for a submarine swap",
            req.quote_id
        ));
    }

    let invoice = req
        .invoice
        .clone()
        .ok_or_else(|| anyhow!("submarine swap requires an invoice"))?;
    let client_refund_pk = parse_pubkey(
        req.client_refund_pubkey_hex
            .as_deref()
            .ok_or_else(|| anyhow!("submarine swap requires client_refund_pubkey"))?,
    )?;

    let secp = Secp256k1::new();
    let (claim_sk, claim_pk) = swap_common::random_keypair(&secp);
    let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?;
    let timeout_height = tip + ctx.htlc_timeout_blocks;

    let swap = init_submarine_swap(
        ctx.ln.as_ref(),
        &invoice,
        &client_refund_pk,
        claim_sk,
        &claim_pk,
        quote.fee_sat,
        ctx.onchain_fee_rate_sat_vb,
        ctx.max_routing_fee_msat,
        timeout_height,
        ctx.network,
    )
    .await?;

    let swap_id = Uuid::new_v4();
    let accept = SwapAccept {
        quote_id: req.quote_id,
        swap_id,
        direction: SwapDirection::Submarine,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        htlc_address: htlc_p2wsh_address(&swap.htlc_script, ctx.network).to_string(),
        onchain_amount_sat: swap.onchain_amount_sat,
        timeout_block_height: swap.timeout_height,
        provider_pubkey_hex: hex::encode(claim_pk.to_bytes()),
        invoice: None,
    };
    ctx.transport
        .send(sender, &SwapMessage::SwapAccept(accept))
        .await?;
    info!(
        "Submarine swap {swap_id} started (fund {} to the HTLC)",
        swap.onchain_amount_sat
    );

    let record = SwapRecord {
        swap_id,
        direction: SwapDirection::Submarine,
        peer: sender.to_string(),
        network: NetworkSpec::from_bitcoin_network(ctx.network),
        payment_hash_hex: hex::encode(swap.payment_hash),
        onchain_amount_sat: swap.onchain_amount_sat,
        fee_rate_sat_vb: swap.fee_rate_sat_vb,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        timeout_height: swap.timeout_height,
        secret_key_hex: hex::encode(swap.claim_key.secret_bytes()),
        invoice: swap.invoice.clone(),
        max_routing_fee_msat: swap.max_routing_fee_msat,
        required_confirmations: ctx.required_confirmations,
        funding_txid_hex: None,
        funding_vout: None,
        state: SwapState::Created,
    };
    if let Err(e) = ctx.store.put(&record) {
        warn!("failed to persist submarine swap {swap_id}: {e}");
    }
    spawn_submarine_driver(ctx, swap, record);
    Ok(())
}

/// Spawn the per-swap submarine driver task (shared by fresh starts and restart-resume).
fn spawn_submarine_driver(ctx: &ExecCtx, swap: SubmarineSwap, record: SwapRecord) {
    let chain = match ctx.chain.clone() {
        Some(c) => c,
        None => return,
    };
    let wallet = match ctx.wallet.clone() {
        Some(w) => w,
        None => return,
    };
    let resume_funding = record.funding_outpoint();
    let peer = record.peer.clone();
    let swap_id = record.swap_id;
    let required_confirmations = record.required_confirmations;
    let progress = Arc::new(StoreProgress {
        store: ctx.store.clone(),
        record: std::sync::Mutex::new(record),
    });
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let result = drive_submarine_swap(
            ctx2.ln.as_ref(),
            chain.as_ref(),
            wallet.as_ref(),
            &swap,
            required_confirmations,
            Duration::from_secs(2),
            resume_funding,
            progress.as_ref(),
        )
        .await;
        if let Err(e) = ctx2.store.remove(swap_id) {
            warn!("failed to remove swap {swap_id} from store: {e}");
        }
        send_final_status(&ctx2.transport, &peer, swap_id, result).await;
    });
}

/// Reconstruct a [`ReverseSwap`] from a persisted record (resume path).
fn reverse_swap_from_record(rec: &SwapRecord) -> Result<ReverseSwap> {
    Ok(ReverseSwap {
        payment_hash: rec.payment_hash()?,
        onchain_amount_sat: rec.onchain_amount_sat,
        fee_rate_sat_vb: rec.fee_rate_sat_vb,
        htlc_script: rec.htlc_script()?,
        htlc_spk: rec.htlc_spk()?,
        timeout_height: rec.timeout_height,
        refund_key: rec.secret_key()?,
        invoice: rec.invoice.clone(),
    })
}

/// Reconstruct a [`SubmarineSwap`] from a persisted record (resume path).
fn submarine_swap_from_record(rec: &SwapRecord) -> Result<SubmarineSwap> {
    Ok(SubmarineSwap {
        payment_hash: rec.payment_hash()?,
        onchain_amount_sat: rec.onchain_amount_sat,
        fee_rate_sat_vb: rec.fee_rate_sat_vb,
        htlc_script: rec.htlc_script()?,
        htlc_spk: rec.htlc_spk()?,
        timeout_height: rec.timeout_height,
        claim_key: rec.secret_key()?,
        invoice: rec.invoice.clone(),
        max_routing_fee_msat: rec.max_routing_fee_msat,
    })
}

/// Spawn a background task that watches for chain reorganizations and re-validates the funding of
/// in-flight swaps. The per-swap drivers already self-heal (the submarine driver re-confirms the
/// funding depth before paying; `confirm_or_bump` re-broadcasts a reorged-out claim/refund and
/// only treats a spend as final once it is buried), so this primarily surfaces reorgs to the
/// operator and flags any funding that may have been orphaned.
fn spawn_reorg_monitor(ctx: &ExecCtx) {
    let chain = match ctx.chain.clone() {
        Some(c) => c,
        None => return,
    };
    let store = ctx.store.clone();
    tokio::spawn(async move {
        let mut monitor = swap_common::reorg::ReorgMonitor::new(100);
        loop {
            match run_blocking(|| monitor.observe(chain.as_ref())) {
                Ok(Some(fork)) => {
                    warn!("chain reorg detected at height {fork}; re-validating in-flight swaps");
                    if let Ok(records) = store.load_active() {
                        for rec in records {
                            let (Some(op), Ok(spk)) = (rec.funding_outpoint(), rec.htlc_spk())
                            else {
                                continue;
                            };
                            let still_funded = matches!(
                                run_blocking(|| chain.find_funding(&spk, rec.onchain_amount_sat)),
                                Ok(Some(ref u)) if u.outpoint == op
                            );
                            if !still_funded {
                                warn!(
                                    "swap {}: recorded funding {op} not found at required depth \
                                     after the reorg; its driver will re-validate before acting",
                                    rec.swap_id
                                );
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => debug!("reorg monitor: {e}"),
            }
            sleep(Duration::from_secs(30)).await;
        }
    });
}

/// On startup, re-spawn drivers for any swaps that were in flight at the last shutdown/crash.
fn resume_swaps(ctx: &ExecCtx) {
    let records = match ctx.store.load_active() {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to load persisted swaps: {e}");
            return;
        }
    };
    if records.is_empty() {
        return;
    }
    if !ctx.capable {
        warn!(
            "{} persisted swap(s) found, but the provider is negotiation-only and cannot resume \
             them; configure --features full with an Electrum URL + funding wallet",
            records.len()
        );
        return;
    }
    info!("Resuming {} persisted swap(s)", records.len());
    for rec in records {
        let swap_id = rec.swap_id;
        match rec.direction {
            SwapDirection::Reverse => match reverse_swap_from_record(&rec) {
                Ok(swap) => spawn_reverse_driver(ctx, swap, rec),
                Err(e) => warn!("cannot resume reverse swap {swap_id}: {e}"),
            },
            SwapDirection::Submarine => match submarine_swap_from_record(&rec) {
                Ok(swap) => spawn_submarine_driver(ctx, swap, rec),
                Err(e) => warn!("cannot resume submarine swap {swap_id}: {e}"),
            },
        }
    }
}

async fn send_final_status(
    transport: &Transport,
    peer: &str,
    swap_id: Uuid,
    result: Result<SwapState>,
) {
    let state = result.unwrap_or_else(|e| SwapState::Failed(e.to_string()));
    info!("Swap {swap_id} finished: {state:?}");
    let update = SwapStatusUpdate {
        swap_id,
        state,
        reference: None,
    };
    if let Err(e) = transport
        .send(peer, &SwapMessage::SwapStatusUpdate(update))
        .await
    {
        warn!("failed to send final status for swap {swap_id}: {e}");
    }
}

async fn reject(
    transport: &Transport,
    sender: &str,
    swap_id: Option<Uuid>,
    quote_id: Option<Uuid>,
    reason: &str,
) -> Result<()> {
    transport
        .send(
            sender,
            &SwapMessage::Reject(Reject {
                swap_id,
                quote_id,
                reason: reason.to_string(),
            }),
        )
        .await?;
    Ok(())
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str).context("decode pubkey hex")?;
    PublicKey::from_slice(&bytes).context("parse public key")
}

fn parse_hash32(hex_str: &str) -> Result<PaymentHash> {
    let bytes = hex::decode(hex_str).context("decode hash hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("payment hash must be 32 bytes"))?;
    Ok(arr)
}

fn variant_name(msg: &SwapMessage) -> &'static str {
    match msg {
        SwapMessage::Offer(_) => "Offer",
        SwapMessage::QuoteRequest(_) => "QuoteRequest",
        SwapMessage::Quote(_) => "Quote",
        SwapMessage::SwapRequest(_) => "SwapRequest",
        SwapMessage::SwapAccept(_) => "SwapAccept",
        SwapMessage::SwapStatusUpdate(_) => "SwapStatusUpdate",
        SwapMessage::CoopSignature(_) => "CoopSignature",
        SwapMessage::Reject(_) => "Reject",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(confs: u32, fee_floor: u64, allow_unsafe: bool) -> ProviderConfig {
        ProviderConfig {
            required_confirmations: confs,
            onchain_fee_rate_sat_vb: fee_floor,
            allow_unsafe,
            ..Default::default()
        }
    }

    #[test]
    fn mainnet_safety_allows_safe_and_non_mainnet() {
        // Regtest defaults (1 conf, 2 sat/vB) are fine off-mainnet.
        assert!(validate_mainnet_safety(&cfg(1, 2, false), Network::Regtest).is_ok());
        // Safe mainnet values pass.
        assert!(validate_mainnet_safety(&cfg(2, 5, false), Network::Bitcoin).is_ok());
    }

    #[test]
    fn mainnet_safety_rejects_unsafe_unless_overridden() {
        // Too few confirmations on mainnet.
        assert!(validate_mainnet_safety(&cfg(1, 10, false), Network::Bitcoin).is_err());
        // Fee floor too low on mainnet.
        assert!(validate_mainnet_safety(&cfg(3, 2, false), Network::Bitcoin).is_err());
        // The override permits both.
        assert!(validate_mainnet_safety(&cfg(1, 2, true), Network::Bitcoin).is_ok());
    }

    #[test]
    fn lnd_network_mapping() {
        assert_eq!(lnd_network_to_bitcoin("mainnet"), Some(Network::Bitcoin));
        assert_eq!(lnd_network_to_bitcoin("regtest"), Some(Network::Regtest));
        assert_eq!(lnd_network_to_bitcoin("signet"), Some(Network::Signet));
        assert_eq!(lnd_network_to_bitcoin("simnet"), None);
    }
}
