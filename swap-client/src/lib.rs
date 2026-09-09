//! Client library: negotiate a swap with a provider over the Pubky transport, and execute
//! the on-chain/Lightning side.
//!
//! Negotiation (request a quote → commit → receive the provider's HTLC details) is in this
//! module's [`run`]. Reverse-swap *execution* (pay the hold invoice, watch the HTLC, claim
//! with the preimage) lives in [`reverse`].

pub mod resume;
pub mod reverse;
pub mod store;
pub mod submarine;

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network, PublicKey, ScriptBuf};
use lightning_backend::{LightningBackend, LndConfig};
use pubky_transport::Transport;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use swap_common::chain::ChainWatcher;
use swap_common::htlc::{build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash};
use swap_common::store::{JsonFileSwapStore, Resume};
use swap_common::timelock::TimelockParams;
use swap_common::validate::{self, ClientPolicy, DecodedHoldInvoice};
use swap_common::wallet::OnchainWallet;
use swap_common::{messages::*, SwapDirection, SwapState};
use tokio::time::sleep;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::reverse::{execute_reverse_swap, ReverseClaim};
use crate::submarine::{execute_submarine_swap, SubmarineFunding};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub recovery_method: String,
    pub recovery_value: String,
    pub passphrase: String,
    pub network: String,
    pub provider_pkarr: String,
    pub direction: SwapDirection,
    pub amount_sat: u64,
    /// Lightning backend: `"lnd"` or `"beignet"`.
    pub lightning_backend: String,
    /// Base URL of a beignet daemon.
    pub beignet_url: String,
    /// Bearer token for that daemon.
    pub beignet_token: String,
    /// PEM root certificate, when the daemon was started with `--tls-cert`.
    pub beignet_tls_cert: String,
    /// Optional `/v1` API prefix.
    pub beignet_api_prefix: String,
    /// LND gRPC endpoint used to pay the hold invoice (reverse-swap execution).
    pub lnd_address: String,
    pub lnd_cert_path: String,
    pub lnd_macaroon_path: String,
    /// SOCKS5 proxy for Electrum, e.g. `127.0.0.1:9050`. Required to reach a `.onion` server.
    pub electrum_socks5: String,
    /// Per-call Electrum socket timeout, in seconds.
    pub electrum_timeout_secs: u8,
    /// Electrum server URL for watching/claiming the on-chain HTLC.
    pub electrum_url: String,
    /// Address that receives the swept on-chain funds (reverse-swap claim destination).
    pub claim_address: String,
    /// BIP39 mnemonic for the on-chain funding wallet (submarine swaps fund the HTLC).
    pub wallet_mnemonic: String,
    /// On-chain wallet backend: `"lnd"` (fund/claim via the node's own LND wallet — no seed or
    /// claim address needed) or `"bdk"` (a separate BIP84 wallet from `wallet_mnemonic`).
    pub wallet_backend: String,
    /// Fee rate (sat/vB) for the claim transaction.
    pub onchain_fee_rate_sat_vb: u64,
    /// Routing-fee cap (msat) when paying the hold invoice.
    pub max_routing_fee_msat: u64,
    /// Only request a quote (to check a provider's availability/rates) and exit without swapping.
    pub quote_only: bool,
    /// Ring the provider's iroh P2P rendezvous (doorbell) before negotiating, so a provider that
    /// isn't already following us starts polling us for the swap DM. Requires the `iroh` feature.
    pub rendezvous_iroh: bool,
    /// Confirmations this client requires before acting, whatever the provider quotes. `0` means
    /// "use the network default" (2 on mainnet, 1 elsewhere).
    ///
    /// This is the floor that stops a provider quoting zero confirmations to get us to reveal a
    /// preimage against a funding it can still replace.
    pub min_confirmations: u32,
    /// Most this client will pay in total fees, in basis points of the swap amount.
    pub max_fee_bps: u16,
    /// Hard ceiling on anything this client will lock on-chain or pay over Lightning. `0` means
    /// no ceiling beyond the amount it asked to swap.
    pub max_total_sat: u64,
    /// Directory for persisted in-flight swap state.
    ///
    /// A submarine swap's refund key is generated here and exists nowhere else. Losing it does
    /// not fail the swap, it makes the on-chain output unspendable by anyone, forever.
    pub data_dir: String,
    /// Drive any swaps left in flight by a previous run, then exit without starting a new one.
    pub resume_only: bool,
}

/// Whether this client has the backends a swap needs to execute.
fn execution_ready(config: &ClientConfig) -> bool {
    !config.electrum_url.is_empty() && wallet_is_configured(config)
}

/// Whether the configured wallet backend can both fund an HTLC and supply a sweep destination
/// on its own, with no `--claim-address` and no separate seed.
fn wallet_is_self_sufficient(config: &ClientConfig) -> bool {
    matches!(config.wallet_backend.as_str(), "lnd" | "beignet")
}

/// Whether a wallet is configured at all.
fn wallet_is_configured(config: &ClientConfig) -> bool {
    wallet_is_self_sufficient(config) || !config.wallet_mnemonic.is_empty()
}

/// The policy this client holds providers to.
fn client_policy(config: &ClientConfig, network: Network) -> ClientPolicy {
    let mut policy = ClientPolicy::for_network(network, TimelockParams::default());
    if config.min_confirmations > 0 {
        policy.min_required_confirmations = config.min_confirmations;
    }
    if config.max_fee_bps > 0 {
        policy.max_fee_bps = config.max_fee_bps;
    }
    if config.max_total_sat > 0 {
        policy.max_total_sat = config.max_total_sat;
    }
    policy
}

/// Records what a swap did, so a later run of this client knows it.
///
/// One type for both directions: the markers mean the same thing on each, and two of these that
/// drifted apart would each be right about their own half of the same bug.
pub(crate) struct RecordProgress<'a> {
    pub(crate) store: &'a JsonFileSwapStore,
    pub(crate) swap_id: Uuid,
}

impl crate::submarine::FundingSink for RecordProgress<'_> {
    fn funding_intent(&self, tip: u32) -> Result<()> {
        store::record_funding_intent(self.store, self.swap_id, tip)
    }
    fn funded(&self, outpoint: bitcoin::OutPoint) {
        if let Err(e) = store::record_funded(self.store, self.swap_id, outpoint) {
            // Loud, because a funding whose outpoint never reached disk is exactly the case a
            // resumed client has to go hunting for.
            error!("FAILED TO PERSIST the funding outpoint {outpoint}: {e}");
        }
    }
    fn spend_broadcast(&self, txid: bitcoin::Txid) {
        if let Err(e) = store::record_our_spend(self.store, self.swap_id, txid) {
            error!("FAILED TO PERSIST our own spend {txid}: {e}");
        }
    }
}

impl crate::reverse::ClaimSink for RecordProgress<'_> {
    fn spend_broadcast(&self, txid: bitcoin::Txid) {
        if let Err(e) = store::record_our_spend(self.store, self.swap_id, txid) {
            error!("FAILED TO PERSIST our own claim {txid}: {e}");
        }
    }
}

/// Drive swaps this client left in flight, before starting anything new.
///
/// A record here is not an inconvenience, it is money: each one holds the only key that can move
/// the funds on this side's branch of an HTLC. This used to print them and move on, which tells
/// an operator their coins are at risk without doing anything about it.
///
/// Resuming needs the execution backends, so a client that has none can only report. That is the
/// honest limit rather than a lesser version of the same thing: without a chain watcher there is
/// no way to see the HTLC, and without a wallet no way to refund one.
async fn resume_unfinished_swaps(
    store: &JsonFileSwapStore,
    config: &ClientConfig,
    network: Network,
) {
    let records = match store::unfinished(store) {
        Ok(r) if r.is_empty() => return,
        Ok(r) => r,
        Err(e) => {
            warn!("could not read persisted swaps: {e}");
            return;
        }
    };

    if !execution_ready(config) {
        warn!(
            "{} swap(s) from a previous run are unfinished and this client has no execution \
             backends configured, so they cannot be driven. Their branch keys are in the data \
             directory and are the only way to recover any committed funds; do not delete them.",
            records.len()
        );
        for rec in &records {
            warn!(
                "  swap {} ({:?}) with {}: state {:?}, timeout height {}, funding {}",
                rec.swap_id,
                rec.direction,
                rec.peer,
                rec.state,
                rec.timeout_height,
                rec.funding_outpoint()
                    .map(|o| o.to_string())
                    .unwrap_or_else(|| "none recorded".into()),
            );
        }
        return;
    }

    let ln = match make_backend(config).await {
        Ok(ln) => ln,
        Err(e) => {
            warn!("cannot resume unfinished swaps without a Lightning backend: {e}");
            return;
        }
    };
    let chain = match build_chain(config) {
        Ok(c) => c,
        Err(e) => {
            warn!("cannot resume unfinished swaps without a chain watcher: {e}");
            return;
        }
    };
    // Only a submarine swap needs a wallet, so a missing one is not fatal here: the resume driver
    // says so per swap rather than refusing to look at the reverse ones.
    let wallet = build_wallet(config, network).await.ok();

    if let Err(e) =
        resume::resume_unfinished(store, ln, chain, wallet, config.max_routing_fee_msat).await
    {
        warn!("could not resume unfinished swaps: {e}");
    }
}

/// Seconds since the Unix epoch, for quote and invoice expiry checks.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

pub async fn run(config: ClientConfig) -> Result<()> {
    let network = parse_network(&config.network)?;

    let transport = match config.recovery_method.as_str() {
        "file" => Transport::from_recovery_file(&config.recovery_value, &config.passphrase).await?,
        "phrase" => {
            Transport::from_recovery_phrase(&config.recovery_value, Some(&config.passphrase))
                .await?
        }
        other => return Err(anyhow!("unknown recovery method: {other}")),
    };
    let client_pkarr = transport.public_key_string();
    info!("Client pubky: {client_pkarr}");

    let store = store::open(&config.data_dir)?;
    // Before anything new: a swap left in flight has money in it, and starting a second one while
    // the first is unattended is how a client ends up with two.
    resume_unfinished_swaps(&store, &config, network).await;
    if config.resume_only {
        info!("--resume-only: not starting a new swap");
        return Ok(());
    }
    transport.add_known_peer(config.provider_pkarr.clone());

    // Optionally ring the provider's iroh doorbell so a provider that isn't already following us
    // starts polling us for the swap DM below.
    maybe_ring_provider(&config).await;

    // For reverse swaps the client owns the preimage and the on-chain claim key.
    let secp = Secp256k1::new();
    let (claim_sk, claim_pk) = swap_common::random_keypair(&secp);
    let preimage = generate_preimage();
    let ph = payment_hash(&preimage);

    // 1) Request a quote (offer_id nil = the provider's current offer; a real client would
    //    first discover the Offer via the follow graph).
    let qreq = QuoteRequest {
        offer_id: Uuid::nil(),
        client_pkarr: client_pkarr.clone(),
        direction: config.direction,
        amount_sat: config.amount_sat,
        protocol_version: swap_common::messages::PROTOCOL_VERSION,
        features: Vec::new(),
    };
    transport
        .send(
            &config.provider_pkarr,
            &SwapMessage::QuoteRequest(qreq.clone()),
        )
        .await?;
    info!(
        "Requested {:?} quote for {} sat",
        config.direction, config.amount_sat
    );

    // 2) Await the quote.
    let quote = await_message(&transport, &config.provider_pkarr, 30, |m| match m {
        SwapMessage::Quote(q) => Some(q),
        _ => None,
    })
    .await?;
    info!(
        "Quote {}: amount {} sat, fee {} sat, total {} sat, timeout {} blocks",
        quote.quote_id, quote.amount_sat, quote.fee_sat, quote.total_sat, quote.htlc_timeout_blocks
    );

    // Check the quote against what we asked for and against our own policy, before it is used to
    // derive anything. In particular this is where a provider quoting zero confirmations is
    // refused: acting on a mempool-only funding would let it read our preimage and then replace
    // the funding transaction out from under us.
    let policy = client_policy(&config, network);
    if let Err(e) = validate::validate_quote(&quote, &qreq, now_unix(), &policy) {
        return Err(anyhow!("refusing the provider's quote: {e}"));
    }
    // Never act on fewer confirmations than our own floor, whatever the quote said.
    let required_confirmations = policy.effective_confirmations(quote.required_confirmations);

    // A receiving a quote confirms the peer is a live provider that serves this direction. In
    // quote-only mode, print a machine-readable line and stop (no funds move).
    if config.quote_only {
        println!(
            "QUOTE provider={} direction={:?} amount_sat={} fee_sat={} total_sat={} timeout_blocks={} confirmations={}",
            config.provider_pkarr,
            config.direction,
            quote.amount_sat,
            quote.fee_sat,
            quote.total_sat,
            quote.htlc_timeout_blocks,
            required_confirmations
        );
        return Ok(());
    }

    if config.direction == SwapDirection::Submarine {
        return run_submarine(
            &config,
            &transport,
            network,
            &quote,
            &client_pkarr,
            &policy,
            &store,
        )
        .await;
    }

    // Persist the preimage and claim key before committing to the swap.
    //
    // Unlike the provider, a reverse-swap client cannot recover its preimage from anywhere: it
    // generated it, and nothing else has a copy. Losing it after paying the hold invoice means
    // paying for coins it can no longer claim, and being made whole only if the provider
    // correctly refunds and cancels. Relying on a counterparty's correctness for your own safety
    // is not a design, so it goes on disk first.
    let client_swap_id = Uuid::new_v4();
    store::record_intent(
        &store,
        &store::NewClientSwap {
            swap_id: client_swap_id,
            direction: SwapDirection::Reverse,
            peer: config.provider_pkarr.clone(),
            network: swap_common::NetworkSpec::from_bitcoin_network(network)?,
            payment_hash: ph,
            branch_key: claim_sk.secret_bytes(),
            preimage: Some(preimage),
            invoice: String::new(),
            quote_total_sat: quote.total_sat,
            required_confirmations,
            fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
        },
    )?;

    // 3) Commit to the swap (reverse).
    let sreq = SwapRequest {
        quote_id: quote.quote_id,
        client_pkarr: client_pkarr.clone(),
        direction: config.direction,
        payment_hash_hex: hex::encode(ph),
        client_claim_pubkey_hex: Some(hex::encode(claim_pk.to_bytes())),
        client_refund_pubkey_hex: None,
        invoice: None,
    };
    transport
        .send(&config.provider_pkarr, &SwapMessage::SwapRequest(sreq))
        .await?;
    info!("Sent swap request for quote {}", quote.quote_id);

    // 4) Await the provider's HTLC details.
    let accept = await_message(&transport, &config.provider_pkarr, 30, |m| match m {
        SwapMessage::SwapAccept(a) => Some(a),
        _ => None,
    })
    .await?;
    info!("Provider locked HTLC at {}", accept.htlc_address);

    // 5a) Check the numbers the provider chose against the quote we agreed to. The script check
    //     below binds the payment hash, both pubkeys, and the timeout height, but it cannot bind
    //     *value*: a well-formed script can pay out far less than was quoted. Amounts are checked
    //     here, and the height-relative checks run once we have a chain tip (5c).
    let chain_for_checks = build_chain(&config).ok();
    let tip = chain_for_checks
        .as_ref()
        .and_then(|c| swap_common::chain::run_blocking(|| c.tip_height()).ok());
    if let Err(e) = validate::validate_accept(&accept, &quote, tip, &policy) {
        return Err(anyhow!("refusing the provider's swap acceptance: {e}"));
    }

    // 5b) Independently verify the HTLC the provider built actually pays OUR claim key under OUR
    //    payment hash before we pay anything. Rebuild the expected redeem script and compare.
    let provider_refund_pk = parse_pubkey(&accept.provider_pubkey_hex)?;
    let expected_script = build_htlc_script(
        &ph,
        &claim_pk,
        &provider_refund_pk,
        accept.timeout_block_height,
    );
    if hex::encode(expected_script.as_bytes()) != accept.htlc_script_hex {
        return Err(anyhow!(
            "provider HTLC script does not match the expected reverse-swap script; aborting"
        ));
    }
    let htlc_address = htlc_p2wsh_address(&expected_script, network);
    if htlc_address.to_string() != accept.htlc_address {
        return Err(anyhow!(
            "provider HTLC address {} does not match the verified script; aborting",
            accept.htlc_address
        ));
    }
    info!("Verified HTLC script and address match our claim key and payment hash");

    // 6) Execute, if the client is configured to (own LND + Electrum + a claim destination — either
    //    an explicit --claim-address or `--wallet lnd`, which sweeps into LND's own wallet).
    let self_sufficient = wallet_is_self_sufficient(&config);
    if config.electrum_url.is_empty() || (config.claim_address.is_empty() && !self_sufficient) {
        warn!(
            "Reverse swap negotiated and HTLC verified, but execution config is missing. To pay \
             the hold invoice and claim on-chain, rebuild with --features full and pass \
             --lnd-address/--lnd-cert/--lnd-macaroon, --electrum-url, and --claim-address (or \
             --wallet lnd to sweep into LND)."
        );
        return Ok(());
    }

    let invoice = accept
        .invoice
        .clone()
        .ok_or_else(|| anyhow!("provider did not include a hold invoice"))?;
    let dest_spk = if self_sufficient {
        build_wallet(&config, network).await?.receive_destination()
    } else {
        parse_address_spk(&config.claim_address, network)?
    };
    let ln = make_backend(&config).await?;
    let chain = build_chain(&config)?;

    // 5c) The hold invoice is the client's entire exposure in a reverse swap, and until now it
    //     was paid unread. Decode it and bind every field to the quote: our payment hash, the
    //     exact amount we agreed, and an expiry that outlives the on-chain leg.
    let decoded = ln
        .decode_invoice(&invoice)
        .await
        .map_err(|e| anyhow!("decode the provider's hold invoice: {e}"))?;
    if let Err(e) = validate::validate_hold_invoice(
        &DecodedHoldInvoice {
            payment_hash: decoded.payment_hash,
            amount_msat: decoded.amount_msat,
            amount_is_explicit: decoded.amount_is_explicit,
            expires_at_unix: decoded.expires_at_unix,
        },
        &quote,
        &ph,
        now_unix(),
        &policy,
    ) {
        return Err(anyhow!("refusing the provider's hold invoice: {e}"));
    }
    info!(
        "Verified the hold invoice pays {} sat against our payment hash",
        decoded.amount_msat / 1000
    );

    store::record_accept(
        &store,
        client_swap_id,
        hex::encode(expected_script.as_bytes()),
        accept.timeout_block_height,
        quote.amount_sat,
        hex::encode(dest_spk.as_bytes()),
    )?;

    let claim = ReverseClaim {
        htlc_script: expected_script,
        htlc_spk: htlc_address.script_pubkey(),
        // Checked equal to `quote.amount_sat` above; use our own number regardless.
        onchain_amount_sat: quote.amount_sat,
        timeout_height: accept.timeout_block_height,
        invoice,
        preimage,
        claim_key: claim_sk,
        dest_spk,
        fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
    };
    info!("Paying the hold invoice and waiting to claim the on-chain HTLC...");
    let sink = RecordProgress {
        store: &store,
        swap_id: client_swap_id,
    };
    let txid = execute_reverse_swap(
        ln,
        chain,
        claim,
        config.max_routing_fee_msat,
        required_confirmations,
        Duration::from_secs(2),
        &Resume::default(),
        &sink,
    )
    .await;
    match &txid {
        Ok(id) => {
            info!("Reverse swap complete; claim broadcast as {id}");
            if let Err(e) = store::record_terminal(&store, client_swap_id, SwapState::Claimed) {
                warn!("could not record the swap outcome: {e}");
            }
        }
        Err(e) => {
            // The record stays active on purpose. It holds the preimage and claim key, which are
            // the only way to recover anything if the HTLC is still claimable.
            warn!("Reverse swap did not complete: {e}. The swap record is retained.");
        }
    }
    txid?;

    Ok(())
}

/// Execute a submarine swap (on-chain → Lightning): issue an invoice the provider pays, fund the
/// HTLC the provider claims, and refund on-chain if the provider never pays.
async fn run_submarine(
    config: &ClientConfig,
    transport: &Transport,
    network: Network,
    quote: &Quote,
    client_pkarr: &str,
    policy: &ClientPolicy,
    store: &JsonFileSwapStore,
) -> Result<()> {
    // Execution needs our own LN node (to issue + watch the invoice), Electrum, and a funding
    // wallet (LND's own with `--wallet lnd`, or a BDK wallet from `--wallet-mnemonic`).
    if config.electrum_url.is_empty() || !wallet_is_configured(config) {
        warn!(
            "Submarine swap quoted, but execution config is missing. To run it, rebuild with \
             --features full and pass --lnd-address/--lnd-cert/--lnd-macaroon, --electrum-url, \
             and --wallet lnd (or --wallet-mnemonic)."
        );
        return Ok(());
    }

    let ln = make_backend(config).await?;
    // Issue the invoice the provider will pay — the amount we want to receive over Lightning.
    let invoice = ln
        .create_invoice(
            quote.amount_sat.saturating_mul(1000),
            3600,
            "pubky-swap submarine",
        )
        .await
        .map_err(|e| anyhow!("create invoice: {e}"))?;
    let ph = invoice.payment_hash;

    // Our HTLC refund key (refund branch of the HTLC the provider claims).
    let secp = Secp256k1::new();
    let (refund_sk, refund_pk) = swap_common::random_keypair(&secp);

    // Persist the key before telling anyone the swap exists.
    //
    // This key is the only thing that can ever move the funds on the refund branch of the HTLC
    // we are about to fund. It is generated here and exists nowhere else in the world. Writing it
    // after the counterparty replies would leave a window in which a crash loses it, and losing
    // it does not fail the swap: it makes the output unspendable by anyone, forever.
    let client_swap_id = Uuid::new_v4();
    store::record_intent(
        store,
        &store::NewClientSwap {
            swap_id: client_swap_id,
            direction: SwapDirection::Submarine,
            peer: config.provider_pkarr.clone(),
            network: swap_common::NetworkSpec::from_bitcoin_network(network)?,
            payment_hash: ph,
            branch_key: refund_sk.secret_bytes(),
            preimage: None,
            invoice: invoice.bolt11.clone(),
            quote_total_sat: quote.total_sat,
            required_confirmations: policy.effective_confirmations(quote.required_confirmations),
            fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
        },
    )?;

    // 3) Commit to the swap, carrying our invoice + refund pubkey.
    let sreq = SwapRequest {
        quote_id: quote.quote_id,
        client_pkarr: client_pkarr.to_string(),
        direction: SwapDirection::Submarine,
        payment_hash_hex: hex::encode(ph),
        client_claim_pubkey_hex: None,
        client_refund_pubkey_hex: Some(hex::encode(refund_pk.to_bytes())),
        invoice: Some(invoice.bolt11.clone()),
    };
    transport
        .send(&config.provider_pkarr, &SwapMessage::SwapRequest(sreq))
        .await?;
    info!("Sent submarine swap request for quote {}", quote.quote_id);

    // 4) Await the provider's HTLC details.
    let accept = await_message(transport, &config.provider_pkarr, 30, |m| match m {
        SwapMessage::SwapAccept(a) => Some(a),
        _ => None,
    })
    .await?;

    // 5a) Check the numbers against the quote before anything is funded. This is the direction
    //     where the client locks the coins, so an inflated `onchain_amount_sat` is a direct
    //     transfer of the client's money: a provider could quote 100k sat and then ask for 10M.
    //     The script check below cannot see it, because the script would be perfectly valid.
    let chain = build_chain(config)?;
    let tip = swap_common::chain::run_blocking(|| chain.tip_height())
        .map_err(|e| anyhow!("tip height: {e}"))?;
    if let Err(e) = validate::validate_accept(&accept, quote, Some(tip), policy) {
        return Err(anyhow!("refusing the provider's swap acceptance: {e}"));
    }

    // 5b) Verify the HTLC pays the provider's claim key under OUR payment hash and is refundable
    //    by OUR key, before funding anything.
    let provider_claim_pk = parse_pubkey(&accept.provider_pubkey_hex)?;
    let expected_script = build_htlc_script(
        &ph,
        &provider_claim_pk,
        &refund_pk,
        accept.timeout_block_height,
    );
    if hex::encode(expected_script.as_bytes()) != accept.htlc_script_hex {
        return Err(anyhow!(
            "provider HTLC script does not match the expected submarine-swap script; aborting"
        ));
    }
    let htlc_address = htlc_p2wsh_address(&expected_script, network);
    if htlc_address.to_string() != accept.htlc_address {
        return Err(anyhow!(
            "provider HTLC address {} does not match the verified script; aborting",
            accept.htlc_address
        ));
    }
    info!(
        "Verified submarine HTLC; funding {} sat on-chain",
        quote.total_sat
    );

    // 6) Fund the HTLC and wait for settlement (or refund at timeout).
    let wallet = build_wallet(config, network).await?;
    let dest_spk = wallet.receive_destination();
    store::record_accept(
        store,
        client_swap_id,
        hex::encode(expected_script.as_bytes()),
        accept.timeout_block_height,
        quote.total_sat,
        hex::encode(dest_spk.as_bytes()),
    )?;
    let _ = tip;
    let funding = SubmarineFunding {
        htlc_script: expected_script,
        htlc_spk: htlc_address.script_pubkey(),
        // Checked equal to `accept.onchain_amount_sat` above. Funding our own number rather than
        // the provider's echo means a provider-supplied amount can never reach the wallet.
        onchain_amount_sat: quote.total_sat,
        payment_hash: ph,
        refund_key: refund_sk,
        timeout_height: accept.timeout_block_height,
        fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
    };
    let sink = RecordProgress {
        store,
        swap_id: client_swap_id,
    };
    let state = execute_submarine_swap(
        ln,
        chain,
        wallet,
        funding,
        Duration::from_secs(2),
        &Resume::default(),
        &sink,
    )
    .await?;
    info!("Submarine swap finished: {state:?}");
    if let Err(e) = store::record_terminal(store, client_swap_id, state.clone()) {
        warn!("could not record the swap outcome: {e}");
    }
    Ok(())
}

/// Ring the provider's iroh rendezvous (doorbell) so it starts polling us, when enabled and built
/// with the `iroh` feature. Best-effort: a failure just falls back to relying on the provider
/// already following us.
#[cfg(feature = "iroh")]
async fn maybe_ring_provider(config: &ClientConfig) {
    if !config.rendezvous_iroh {
        return;
    }
    let secret = match pubky_transport::identity::secret_from_recovery(
        &config.recovery_method,
        &config.recovery_value,
        &config.passphrase,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("iroh rendezvous disabled: {e}");
            return;
        }
    };
    match pubky_transport::p2p::ring_provider(secret, &config.provider_pkarr).await {
        Ok(()) => info!("Rang provider iroh doorbell; it should start polling us"),
        Err(e) => warn!("iroh rendezvous ring failed ({e}); relying on the provider following us"),
    }
}

#[cfg(not(feature = "iroh"))]
async fn maybe_ring_provider(config: &ClientConfig) {
    if config.rendezvous_iroh {
        warn!("--rendezvous-iroh set but this build lacks the `iroh` feature; ignoring");
    }
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("decode pubkey hex: {e}"))?;
    PublicKey::from_slice(&bytes).map_err(|e| anyhow!("parse public key: {e}"))
}

/// Build the on-chain wallet used to fund submarine HTLCs and/or receive reverse-swap sweeps:
/// `--wallet lnd` (the node's own LND wallet, no seed) or a BDK wallet from `--wallet-mnemonic`.
async fn build_wallet(config: &ClientConfig, network: Network) -> Result<Arc<dyn OnchainWallet>> {
    if config.wallet_backend == "beignet" {
        #[cfg(feature = "beignet")]
        {
            let chain = build_chain(config).ok();
            let wallet = beignet_backend::BeignetWallet::connect(
                beignet_http(config)?,
                network,
                config.onchain_fee_rate_sat_vb,
                chain,
            )
            .await
            .map_err(|e| anyhow!("beignet wallet: {e}"))?;
            return Ok(Arc::new(wallet));
        }
        #[cfg(not(feature = "beignet"))]
        return Err(anyhow!(
            "--wallet beignet requires a build with --features beignet"
        ));
    }
    if config.wallet_backend == "lnd" {
        #[cfg(feature = "lnd")]
        {
            let lnd_config = LndConfig {
                address: config.lnd_address.clone(),
                tls_cert_path: config.lnd_cert_path.clone(),
                macaroon_path: config.lnd_macaroon_path.clone(),
            };
            let wallet =
                lightning_backend::LndWallet::connect(lnd_config, config.onchain_fee_rate_sat_vb)
                    .await
                    .map_err(|e| anyhow!("LND on-chain wallet: {e}"))?;
            return Ok(Arc::new(wallet));
        }
        #[cfg(not(feature = "lnd"))]
        return Err(anyhow!("--wallet lnd requires the `lnd` feature"));
    }
    let _ = network;
    #[cfg(feature = "bdk-wallet")]
    {
        let wallet = swap_common::wallet::BdkWallet::from_mnemonic(
            &config.wallet_mnemonic,
            network,
            &config.electrum_url,
            config.onchain_fee_rate_sat_vb,
            &std::path::Path::new(&config.data_dir).join("wallet"),
        )
        .map_err(|e| anyhow!("funding wallet: {e}"))?;
        Ok(Arc::new(wallet))
    }
    #[cfg(not(feature = "bdk-wallet"))]
    Err(anyhow!(
        "no on-chain wallet available; use --wallet lnd, or rebuild with --features full for --wallet-mnemonic"
    ))
}

fn parse_address_spk(addr: &str, network: Network) -> Result<ScriptBuf> {
    let address = Address::from_str(addr)
        .map_err(|e| anyhow!("claim address: {e}"))?
        .require_network(network)
        .map_err(|e| anyhow!("claim address is not on {network:?}: {e}"))?;
    Ok(address.script_pubkey())
}

/// A shared HTTP client for the configured beignet daemon.
#[cfg(feature = "beignet")]
fn beignet_http(config: &ClientConfig) -> Result<Arc<beignet_backend::BeignetHttp>> {
    let mut cfg = beignet_backend::BeignetConfig::new(&config.beignet_url);
    let token = std::env::var("BEIGNET_API_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .or_else(|| (!config.beignet_token.is_empty()).then(|| config.beignet_token.clone()));
    cfg = cfg.with_token(token);
    cfg.api_prefix = config.beignet_api_prefix.clone();
    if !config.beignet_tls_cert.is_empty() {
        cfg.tls_cert_pem = Some(
            std::fs::read(&config.beignet_tls_cert)
                .map_err(|e| anyhow!("read {}: {e}", config.beignet_tls_cert))?,
        );
    }
    Ok(Arc::new(
        beignet_backend::BeignetHttp::new(cfg).map_err(|e| anyhow!("{e}"))?,
    ))
}

/// Refuse to run against a node on a different chain from the one configured.
///
/// The provider has had this guard since it existed; the client had none, and it is the side that
/// funds a submarine HTLC and pays a hold invoice. A client told `--network bitcoin` while its
/// node is on testnet does not fail cleanly: it prices, funds and pays against a chain nobody
/// else in the swap is looking at.
async fn check_network_agreement(ln: &dyn LightningBackend, network: Network) -> Result<()> {
    let info = match ln.node_info().await {
        Ok(info) => info,
        // Not reachable yet is a different problem, and the paths that need the node report it
        // themselves. Refusing here would turn a quote-only run into a failure.
        Err(e) => {
            warn!("Lightning backend not reachable for the network check: {e}");
            return Ok(());
        }
    };
    match info.chain_network.as_deref() {
        Some(reported) => match lnd_network_to_bitcoin(reported) {
            Some(node_net) if node_net != network => Err(anyhow!(
                "network mismatch: this client is configured for {network:?} but its Lightning \
                 node is on {node_net:?} ({reported}); aborting"
            )),
            Some(_) => Ok(()),
            None => {
                warn!("the Lightning node reported an unrecognized network '{reported}'");
                Ok(())
            }
        },
        None => {
            warn!("the Lightning node did not report a chain network; skipping the network check");
            Ok(())
        }
    }
}

/// Map the network names a Lightning node reports onto `bitcoin::Network`.
fn lnd_network_to_bitcoin(name: &str) -> Option<Network> {
    match name {
        "mainnet" | "bitcoin" => Some(Network::Bitcoin),
        "testnet" | "testnet3" => Some(Network::Testnet),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// Build the Lightning backend and refuse it if it is on the wrong chain.
///
/// The check is here rather than at each call site so no path can acquire a backend without it.
async fn make_backend(config: &ClientConfig) -> Result<Arc<dyn LightningBackend>> {
    let backend = build_backend(config).await?;
    check_network_agreement(backend.as_ref(), parse_network(&config.network)?).await?;
    Ok(backend)
}

/// A beignet daemon over HTTP, or the node's own LND over gRPC.
async fn build_backend(config: &ClientConfig) -> Result<Arc<dyn LightningBackend>> {
    if config.lightning_backend == "beignet" {
        #[cfg(feature = "beignet")]
        {
            // Ask the daemon what it is before using it. The provider has done this since the
            // backend was added; the client skipped it, and a beignet on the wrong chain is the
            // same hazard here as an LND on the wrong chain.
            let http = beignet_http(config)?;
            let network = parse_network(&config.network)?;
            let preflight = beignet_backend::capability::probe(&http)
                .await
                .map_err(|e| anyhow!("beignet preflight: {e}"))?;
            // The same check the provider makes, and fatal for the same reason: a daemon on
            // another chain would have this client funding contracts on one and settling on
            // another.
            preflight.report(network).map_err(|e| anyhow!("{e}"))?;
            info!(
                "Connected to beignet node {} on {:?}",
                preflight.node_id, network
            );
            return Ok(Arc::new(beignet_backend::BeignetLightningBackend::new(
                http,
            )));
        }
        #[cfg(not(feature = "beignet"))]
        return Err(anyhow!(
            "--lightning beignet requires a build with --features beignet"
        ));
    }

    let lnd_config = LndConfig {
        address: config.lnd_address.clone(),
        tls_cert_path: config.lnd_cert_path.clone(),
        macaroon_path: config.lnd_macaroon_path.clone(),
    };
    #[cfg(feature = "lnd")]
    {
        let backend = lightning_backend::LndBackend::connect(lnd_config)
            .await
            .map_err(|e| anyhow!("LND connect failed: {e}"))?;
        Ok(Arc::new(backend))
    }
    #[cfg(not(feature = "lnd"))]
    {
        let _ = lnd_config;
        Err(anyhow!(
            "client built without the `lnd` feature; rebuild with --features full to pay the hold invoice"
        ))
    }
}

/// Build the Electrum chain watcher used to watch/claim the HTLC. Requires the `chain` feature.
#[cfg(feature = "chain")]
fn build_chain(config: &ClientConfig) -> Result<Arc<dyn ChainWatcher>> {
    let mut electrum = swap_common::chain::ElectrumConfig::new(&config.electrum_url);
    electrum.timeout_secs = config.electrum_timeout_secs;
    if !config.electrum_socks5.is_empty() {
        electrum.socks5 = Some(config.electrum_socks5.clone());
    }
    let watcher = swap_common::chain::ElectrumWatcher::connect(electrum)
        .map_err(|e| anyhow!("electrum connect: {e}"))?;
    Ok(Arc::new(watcher))
}

#[cfg(not(feature = "chain"))]
fn build_chain(_config: &ClientConfig) -> Result<Arc<dyn ChainWatcher>> {
    Err(anyhow!(
        "client built without the `chain` feature; rebuild with --features full to watch/claim the HTLC"
    ))
}

/// Poll the provider for messages until `extract` yields a value or we time out. A
/// [`SwapMessage::Reject`] aborts with its reason.
async fn await_message<F, T>(
    transport: &Transport,
    provider: &str,
    timeout_secs: u64,
    mut extract: F,
) -> Result<T>
where
    F: FnMut(SwapMessage) -> Option<T>,
{
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            return Err(anyhow!("timed out waiting for provider response"));
        }
        let msgs = transport
            .receive_from::<SwapMessage>(provider)
            .await
            .unwrap_or_default();
        for m in msgs {
            if let SwapMessage::Reject(r) = &m {
                return Err(anyhow!("provider rejected: {}", r.reason));
            }
            if let Some(t) = extract(m) {
                return Ok(t);
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
}
