//! What this beignet daemon can actually do, checked at startup.
//!
//! The point is to fail at boot rather than mid-swap. A network mismatch, a daemon that cannot
//! reach Electrum, or a missing capability all become much more expensive to discover once a
//! counterparty's payment is being held.

use crate::error::BeignetError;
use crate::http::BeignetHttp;
use crate::types::*;
use bitcoin::Network;
use tracing::{info, warn};

/// What the daemon reported.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub node_id: String,
    pub network: Option<Network>,
    /// The raw string, kept for the message when it does not map to a known network.
    pub network_str: String,
    pub healthy: bool,
    pub onchain_balance_sat: u64,
    /// Whether `POST /invoice/create-hold` accepts a final CLTV expiry.
    ///
    /// Without it a reverse swap cannot be made safe, so a provider drops that direction from its
    /// offer rather than advertising something it cannot honour (beignet#744).
    pub hold_invoice_supports_final_cltv: bool,
    /// Whether beignet's own reverse-swap provider role is switched on.
    pub swaps_role_enabled: bool,
    /// A combined daily spend limit, if the operator set one.
    pub daily_spend_limit_sat: Option<u64>,
    pub daily_spend_remaining_sat: Option<u64>,
}

fn parse_network(s: &str) -> Option<Network> {
    Some(match s {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return None,
    })
}

/// Ask the daemon what it is and what it can do.
pub async fn probe(http: &BeignetHttp) -> Result<Preflight, BeignetError> {
    let info: NodeInfoResponse = http.get("/info").await?;
    let health: Result<HealthResponse, _> = http.get("/health").await;
    let healthy = match &health {
        Ok(h) => h.status.as_deref() != Some("syncing") && h.electrum_connected.unwrap_or(true),
        Err(e) => {
            warn!("beignet /health failed: {e}");
            false
        }
    };
    let onchain_balance_sat = http
        .get::<BalanceResponse>("/balance")
        .await
        .map(|b| b.onchain)
        .unwrap_or(0);

    // beignet's own swap role and spend limit are readonly-scope, so this costs nothing.
    let swaps_role_enabled = http
        .get::<SwapsStatus>("/swaps/status")
        .await
        .map(|s| s.enabled)
        .unwrap_or(false);
    let spend = http.get::<SpendLimit>("/spend-limit").await.ok();

    Ok(Preflight {
        node_id: info.node_id,
        network: parse_network(&info.network),
        network_str: info.network,
        healthy,
        onchain_balance_sat,
        hold_invoice_supports_final_cltv: hold_invoice_cltv_supported(http).await,
        swaps_role_enabled,
        daily_spend_limit_sat: spend.as_ref().and_then(|s| s.limit_sats),
        daily_spend_remaining_sat: spend.and_then(|s| s.remaining_sats),
    })
}

/// Read the daemon's own OpenAPI document to see whether create-hold takes a CLTV parameter.
///
/// Asking the daemon what it supports beats pinning a version: an operator can be running
/// anything, and this answers for the daemon actually in front of us.
async fn hold_invoice_cltv_supported(http: &BeignetHttp) -> bool {
    let spec: serde_json::Value = match http.get("/openapi.json").await {
        Ok(v) => v,
        Err(e) => {
            warn!("could not read beignet's OpenAPI document ({e}); assuming the hold-invoice CLTV parameter is absent");
            return false;
        }
    };
    let body = spec
        .pointer("/paths/~1invoice~1create-hold/post/requestBody/content/application~1json/schema/properties");
    match body {
        Some(props) => props.get("minFinalCltvExpiry").is_some(),
        None => false,
    }
}

impl Preflight {
    /// Whether this daemon can safely serve reverse swaps.
    pub fn can_serve_reverse_swaps(&self) -> bool {
        self.hold_invoice_supports_final_cltv
    }

    /// Report what was found, at the right severity.
    pub fn report(&self, configured_network: Network) -> Result<(), String> {
        // A wrong network is never a warning: it would mean funding contracts on one chain while
        // settling on another.
        match self.network {
            Some(n) if n != configured_network => {
                return Err(format!(
                    "network mismatch: we are configured for {configured_network:?} but beignet \
                     is on {} ({:?})",
                    self.network_str, n
                ));
            }
            Some(_) => {}
            None => warn!(
                "beignet reports an unrecognized network '{}'; the network guard cannot check it",
                self.network_str
            ),
        }

        info!(
            "beignet node {} on {}, {} sat on chain",
            self.node_id, self.network_str, self.onchain_balance_sat
        );

        if !self.healthy {
            warn!(
                "beignet is not reporting healthy (still syncing, or Electrum unreachable); swaps \
                 will be refused until it is"
            );
        }

        if !self.hold_invoice_supports_final_cltv {
            warn!(
                "this beignet cannot set a hold invoice's final CLTV expiry, so reverse swaps \
                 cannot be made safe against it and will not be advertised. See beignet#744."
            );
        }

        if self.swaps_role_enabled {
            return Err(format!(
                "beignet's own reverse-swap provider role (BEIGNET_SWAPS) is enabled on node {}. \
                 It funds on-chain contracts from the same wallet and creates hold invoices on \
                 the same node, so the two roles compete for the same coins and neither one's \
                 exposure limit can see the other's. Set BEIGNET_SWAPS=false, or run pubky-swap \
                 against a different node.",
                self.node_id
            ));
        }

        if let Some(limit) = self.daily_spend_limit_sat {
            warn!(
                "beignet has a combined daily spend limit of {limit} sat ({} remaining). HTLC \
                 fundings count against it, and once it is exhausted they fail permanently \
                 rather than transiently.",
                self.daily_spend_remaining_sat
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "unknown".into())
            );
        }
        Ok(())
    }
}
