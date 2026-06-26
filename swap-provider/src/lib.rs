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
pub mod submarine;
#[cfg(feature = "bdk-wallet")]
pub mod wallet;

use anyhow::{anyhow, Context, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, PublicKey};
#[cfg(feature = "lnd")]
use lightning_backend::LndBackend;
use lightning_backend::{LightningBackend, LndConfig, StubBackend};
use pubky_transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use swap_common::chain::ChainWatcher;
use swap_common::htlc::{htlc_p2wsh_address, PaymentHash};
use swap_common::{messages::*, NetworkSpec, SwapDirection, SwapState};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::reverse::{drive_reverse_swap, init_reverse_swap, OnchainWallet};
use crate::submarine::{drive_submarine_swap, init_submarine_swap};

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
        }
    }
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
    quotes: Arc<Mutex<HashMap<Uuid, IssuedQuote>>>,
    /// True when the provider can execute swaps (real LN + chain + wallet present).
    capable: bool,
}

/// Run the provider daemon.
pub async fn run(config: ProviderConfig) -> Result<()> {
    let network = parse_network(&config.network)?;

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
            true
        }
        Err(e) => {
            warn!("Lightning backend not ready: {e}");
            false
        }
    };

    let chain = build_chain(&config);
    let wallet = build_wallet(&config);

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
        quotes: Arc::new(Mutex::new(HashMap::new())),
        capable,
    };

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

#[cfg(feature = "bdk-wallet")]
fn build_wallet(config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
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
fn build_wallet(_config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
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
        valid_until_unix: 0,
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
            let quote = Quote {
                quote_id: Uuid::new_v4(),
                offer_id: offer.offer_id,
                direction: req.direction,
                amount_sat: req.amount_sat,
                fee_sat: fee,
                total_sat: req.amount_sat.saturating_add(fee),
                htlc_timeout_blocks: offer.htlc_timeout_blocks,
                required_confirmations: offer.required_confirmations,
                valid_until_unix: 0,
            };
            ctx.quotes.lock().await.insert(
                quote.quote_id,
                IssuedQuote {
                    direction: req.direction,
                    amount_sat: req.amount_sat,
                    fee_sat: fee,
                },
            );
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
    let quote = ctx
        .quotes
        .lock()
        .await
        .get(&req.quote_id)
        .cloned()
        .ok_or_else(|| anyhow!("unknown or expired quote"))?;
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
    let tip = chain.tip_height().map_err(|e| anyhow!("tip height: {e}"))?;
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

    let ctx2 = ctx.clone();
    let sender = sender.to_string();
    tokio::spawn(async move {
        let ln = ctx2.ln.clone();
        let wallet = match ctx2.wallet.clone() {
            Some(w) => w,
            None => return,
        };
        let result = drive_reverse_swap(
            ln.as_ref(),
            chain.as_ref(),
            wallet.as_ref(),
            &swap,
            ctx2.required_confirmations,
            Duration::from_secs(2),
        )
        .await;
        send_final_status(&ctx2.transport, &sender, swap_id, result).await;
    });
    Ok(())
}

/// Start a submarine swap: build the HTLC the client funds, reply with `SwapAccept`, and
/// spawn the driver.
async fn start_submarine(ctx: &ExecCtx, sender: &str, req: SwapRequest) -> Result<()> {
    let chain = ctx
        .chain
        .clone()
        .ok_or_else(|| anyhow!("no chain watcher"))?;
    let quote = ctx
        .quotes
        .lock()
        .await
        .get(&req.quote_id)
        .cloned()
        .ok_or_else(|| anyhow!("unknown or expired quote"))?;
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
    let tip = chain.tip_height().map_err(|e| anyhow!("tip height: {e}"))?;
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

    let ctx2 = ctx.clone();
    let sender = sender.to_string();
    tokio::spawn(async move {
        let ln = ctx2.ln.clone();
        let wallet = match ctx2.wallet.clone() {
            Some(w) => w,
            None => return,
        };
        let result = drive_submarine_swap(
            ln.as_ref(),
            chain.as_ref(),
            wallet.as_ref(),
            &swap,
            ctx2.required_confirmations,
            Duration::from_secs(2),
        )
        .await;
        send_final_status(&ctx2.transport, &sender, swap_id, result).await;
    });
    Ok(())
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
