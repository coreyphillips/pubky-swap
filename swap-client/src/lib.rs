//! Client library: negotiate a swap with a provider over the Pubky transport, and execute
//! the on-chain/Lightning side.
//!
//! Negotiation (request a quote → commit → receive the provider's HTLC details) is in this
//! module's [`run`]. Reverse-swap *execution* (pay the hold invoice, watch the HTLC, claim
//! with the preimage) lives in [`reverse`].

pub mod reverse;

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use pubky_transport::Transport;
use std::time::{Duration, Instant};
use swap_common::htlc::{generate_preimage, payment_hash};
use swap_common::{messages::*, SwapDirection};
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub recovery_method: String,
    pub recovery_value: String,
    pub passphrase: String,
    pub network: String,
    pub provider_pkarr: String,
    pub direction: SwapDirection,
    pub amount_sat: u64,
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
    let _network = parse_network(&config.network)?;

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
    info!("HTLC redeem script: {}", accept.htlc_script_hex);
    warn!(
        "Next steps are TODO: pay the hold invoice, wait for the on-chain HTLC to confirm, \
         then claim it with the preimage (keep it secret until then)."
    );
    // The preimage and claim key are retained for the (future) claim step.
    let _ = (preimage, claim_sk);

    Ok(())
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
