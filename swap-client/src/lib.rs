//! Client library: negotiate a swap with a provider over the Pubky transport, and execute
//! the on-chain/Lightning side.
//!
//! Negotiation (request a quote → commit → receive the provider's HTLC details) is in this
//! module's [`run`]. Reverse-swap *execution* (pay the hold invoice, watch the HTLC, claim
//! with the preimage) lives in [`reverse`].

pub mod reverse;

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
use swap_common::{messages::*, SwapDirection};
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

use crate::reverse::{execute_reverse_swap, ReverseClaim};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub recovery_method: String,
    pub recovery_value: String,
    pub passphrase: String,
    pub network: String,
    pub provider_pkarr: String,
    pub direction: SwapDirection,
    pub amount_sat: u64,
    /// LND gRPC endpoint used to pay the hold invoice (reverse-swap execution).
    pub lnd_address: String,
    pub lnd_cert_path: String,
    pub lnd_macaroon_path: String,
    /// Electrum server URL for watching/claiming the on-chain HTLC.
    pub electrum_url: String,
    /// Address that receives the swept on-chain funds (reverse-swap claim destination).
    pub claim_address: String,
    /// Fee rate (sat/vB) for the claim transaction.
    pub onchain_fee_rate_sat_vb: u64,
    /// Routing-fee cap (msat) when paying the hold invoice.
    pub max_routing_fee_msat: u64,
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
    transport.add_known_peer(config.provider_pkarr.clone());

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
    };
    transport
        .send(&config.provider_pkarr, &SwapMessage::QuoteRequest(qreq))
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

    if config.direction == SwapDirection::Submarine {
        warn!("Submarine client execution needs your own LN node to issue an invoice — TODO (LND/client-node milestone). Negotiation stops here for the scaffold.");
        return Ok(());
    }

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

    // 5) Independently verify the HTLC the provider built actually pays OUR claim key under OUR
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

    // 6) Execute, if the client is configured to (own LND + Electrum + a claim address).
    if config.electrum_url.is_empty() || config.claim_address.is_empty() {
        warn!(
            "Reverse swap negotiated and HTLC verified, but execution config is missing. To pay \
             the hold invoice and claim on-chain, rebuild with --features full and pass \
             --lnd-address/--lnd-cert/--lnd-macaroon, --electrum-url, and --claim-address."
        );
        return Ok(());
    }

    let invoice = accept
        .invoice
        .clone()
        .ok_or_else(|| anyhow!("provider did not include a hold invoice"))?;
    let dest_spk = parse_address_spk(&config.claim_address, network)?;
    let ln = make_backend(&config).await?;
    let chain = build_chain(&config)?;

    let claim = ReverseClaim {
        htlc_script: expected_script,
        htlc_spk: htlc_address.script_pubkey(),
        onchain_amount_sat: accept.onchain_amount_sat,
        invoice,
        preimage,
        claim_key: claim_sk,
        dest_spk,
        fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
    };
    info!("Paying the hold invoice and waiting to claim the on-chain HTLC...");
    let txid = execute_reverse_swap(
        ln,
        chain,
        claim,
        config.max_routing_fee_msat,
        quote.required_confirmations,
        Duration::from_secs(2),
    )
    .await?;
    info!("Reverse swap complete; claim broadcast as {txid}");

    Ok(())
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow!("decode pubkey hex: {e}"))?;
    PublicKey::from_slice(&bytes).map_err(|e| anyhow!("parse public key: {e}"))
}

fn parse_address_spk(addr: &str, network: Network) -> Result<ScriptBuf> {
    let address = Address::from_str(addr)
        .map_err(|e| anyhow!("claim address: {e}"))?
        .require_network(network)
        .map_err(|e| anyhow!("claim address is not on {network:?}: {e}"))?;
    Ok(address.script_pubkey())
}

/// Build the Lightning backend used to pay the hold invoice. Requires the `lnd` feature.
async fn make_backend(config: &ClientConfig) -> Result<Arc<dyn LightningBackend>> {
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
    let watcher = swap_common::chain::ElectrumWatcher::new(&config.electrum_url)
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
