//! The shapes beignet sends and expects.
//!
//! Amounts arrive in two forms: satoshis as JSON numbers, and millisatoshis as decimal strings
//! (they exceed what JSON numbers represent exactly). Both are modelled explicitly rather than
//! being coerced, so a value we cannot read is an error rather than a silent zero.

use serde::{Deserialize, Serialize};

/// A millisatoshi value, which beignet sends as a decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Msat(pub u64);

impl<'de> Deserialize<'de> for Msat {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Str(String),
            Num(u64),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(Msat(n)),
            Raw::Str(s) => s.parse().map(Msat).map_err(D::Error::custom),
        }
    }
}

impl Serialize for Msat {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Sent as a string, which is what the daemon parses with `BigInt`.
        s.serialize_str(&self.0.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfoResponse {
    pub node_id: String,
    #[serde(default)]
    pub alias: Option<String>,
    pub network: String,
    #[serde(default)]
    pub block_height: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub electrum_connected: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateHoldInvoiceRequest {
    pub payment_hash: String,
    pub amount_msat: Msat,
    pub description: String,
    pub expiry: u64,
    /// Not accepted by the daemon yet (beignet#744). Sent anyway: a daemon that ignores an
    /// unknown field costs nothing, and the moment it is supported this starts working without a
    /// release here. The realised value is verified by decoding the invoice either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_final_cltv_expiry: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInvoiceRequest {
    pub amount_sats: u64,
    pub description: String,
    pub expiry_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_final_cltv_expiry: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvoiceInfo {
    pub bolt11: String,
    pub payment_hash: String,
    #[serde(default)]
    pub amount_sats: Option<u64>,
}

/// One hold invoice as `GET /invoices/held` reports it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HoldInvoiceInfo {
    pub payment_hash: String,
    #[serde(default)]
    pub bolt11: Option<String>,
    /// `OPEN` | `ACCEPTED` | `SETTLED` | `CANCELLED`.
    pub state: String,
    #[serde(default)]
    pub held_amount_msat: Option<Msat>,
    #[serde(default)]
    pub htlc_count: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedInvoiceResponse {
    pub payment_hash: String,
    #[serde(default)]
    pub amount_sats: Option<u64>,
    #[serde(default)]
    pub min_final_cltv_expiry: Option<u32>,
    #[serde(default)]
    pub expiry: Option<u64>,
    #[serde(default)]
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayInvoiceRequest {
    pub bolt11: String,
    pub timeout_ms: u64,
    pub max_fee_sats: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInfo {
    pub payment_hash: String,
    /// `COMPLETED` | `PENDING` | `FAILED`.
    pub status: String,
    #[serde(default)]
    pub preimage: Option<String>,
    #[serde(default)]
    pub fee_sats: Option<u64>,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentProof {
    pub preimage: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub address: String,
    pub amount_sats: u64,
    pub sats_per_vbyte: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResponse {
    pub txid: String,
    /// The raw transaction. beignet builds unbroadcast to obtain this, then broadcasts, so it is
    /// normally present; the wallet has a chain-based fallback for a daemon that stops sending it.
    #[serde(default)]
    pub hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressResponse {
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoostRequest {
    pub txid: String,
    pub sats_per_vbyte: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoostResult {
    pub txid: String,
    #[serde(default)]
    pub boost_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub onchain: u64,
    #[serde(default)]
    pub lightning: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapsStatus {
    pub enabled: bool,
    #[serde(default)]
    pub exposed_sat: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendLimit {
    #[serde(default)]
    pub limit_sats: Option<u64>,
    #[serde(default)]
    pub remaining_sats: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Millisatoshi values exceed what a JSON number holds exactly, so beignet sends them as
    /// strings. Accepting both shapes means a daemon that changes its mind about which does not
    /// silently deserialize to zero.
    #[test]
    fn msat_reads_both_strings_and_numbers() {
        let from_string: Msat = serde_json::from_str("\"1000000\"").unwrap();
        assert_eq!(from_string, Msat(1_000_000));
        let from_number: Msat = serde_json::from_str("1000000").unwrap();
        assert_eq!(from_number, Msat(1_000_000));
        // And a value that is neither is an error, not a default.
        assert!(serde_json::from_str::<Msat>("\"not a number\"").is_err());
        // Sent as a string, which is what the daemon's BigInt parse expects.
        assert_eq!(serde_json::to_string(&Msat(21)).unwrap(), "\"21\"");
    }
}
