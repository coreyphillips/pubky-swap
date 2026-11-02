//! Paykit Capabilities `swap/1`: the `paykit-cap.*` kinds, their hash chain and signatures.
//!
//! The engine speaks only [`SwapMessage`]. A carrier that speaks these kinds translates at its
//! edge, and the provider signs three hashes so a third party can check what was agreed:
//!
//! - `terms_hash` over the RFQ constraints and the quote, signed in the quote;
//! - `commit_hash` over `terms_hash` and the commit body;
//! - `contract_hash` over `commit_hash` and the contract body, signed in the contract.
//!
//! Each hash is SHA-256 over a domain prefix followed by the RFC 8785 (JCS) form of a two-member
//! object. The reverse hold invoice is not in the contract. It travels in an encrypted blob whose
//! hash the contract signs, so the signed bytes stay small enough for an Encrypted Link and are
//! the same on every carrier.

use crate::messages::*;
use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// The prefix every kind here carries.
pub const KIND_PREFIX: &str = "paykit-cap.";
pub const TERMS_DOMAIN: &[u8] = b"paykit-cap/swap/1/terms_hash\0";
pub const COMMIT_DOMAIN: &[u8] = b"paykit-cap/swap/1/commit_hash\0";
pub const CONTRACT_DOMAIN: &[u8] = b"paykit-cap/swap/1/contract_hash\0";
const BLOB_KEY_DOMAIN: &[u8] = b"paykit-cap/swap/1/invoice_blob_key\0";

/// The `state` a commit gets while another request is still admitting the same swap. Not a
/// decline: the owner asks again.
pub const STATE_PENDING: &str = "pending";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapError {
    #[error("value cannot be canonicalized: {0}")]
    Canonical(String),
    #[error("{0} does not match what was signed")]
    HashMismatch(&'static str),
    #[error("signature does not verify")]
    BadSignature,
    #[error("signed by an unexpected key")]
    UnexpectedSigner,
    #[error("invoice blob does not decrypt")]
    Blob,
    #[error("reply does not answer the request: {0}")]
    Unexpected(&'static str),
    /// A status reply for a committed swap came back unsigned. Sending this commit again gets
    /// the contract signed and stored, so the next status query carries it.
    #[error("status without the signed contract")]
    MissingContract(Box<Commit>),
}

/// Whether a carrier message is one of these kinds rather than a plain [`SwapMessage`].
pub fn is_cap_message(message: &Value) -> bool {
    message
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.starts_with(KIND_PREFIX))
}

/// One `paykit-cap.*` message. `kind` names the variant and `body` carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body")]
pub enum CapMessage {
    #[serde(rename = "paykit-cap.rfq")]
    Rfq(Rfq),
    #[serde(rename = "paykit-cap.quote")]
    Quote(SignedQuote),
    #[serde(rename = "paykit-cap.commit")]
    Commit(Commit),
    #[serde(rename = "paykit-cap.contract")]
    Contract(ContractReply),
    #[serde(rename = "paykit-cap.status")]
    Status(Box<Status>),
    #[serde(rename = "paykit-cap.status_request")]
    StatusRequest(SwapStatusRequest),
    #[serde(rename = "paykit-cap.refusal")]
    Refusal(Refusal),
}

/// A request for a quote. There is no `client_pkarr`: the carrier's authenticated sender is the
/// only owner a provider recognises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfq {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    #[serde(flatten)]
    pub constraints: RfqConstraints,
    #[serde(default)]
    pub protocol_version: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// The part of an RFQ that `terms_hash` covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RfqConstraints {
    /// Nil asks for whatever offer is current.
    pub offer_id: Uuid,
    pub direction: crate::SwapDirection,
    pub amount_sat: u64,
}

/// A quote and the provider's signature over its `terms_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedQuote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    /// Never carries a `request_id`, which is correlation and not terms.
    pub quote: Quote,
    pub terms_hash: String,
    pub signer: String,
    pub signature: String,
}

/// The owner's commitment to a quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub terms_hash: String,
    pub commit: CommitBody,
}

/// What `commit_hash` covers: a [`SwapRequest`] without its sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitBody {
    #[serde(default)]
    pub script_type: SwapScript,
    pub quote_id: Uuid,
    pub direction: crate::SwapDirection,
    pub payment_hash_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_claim_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_refund_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
}

impl CommitBody {
    pub fn from_request(request: &SwapRequest) -> Self {
        Self {
            script_type: request.script_type,
            quote_id: request.quote_id,
            direction: request.direction,
            payment_hash_hex: request.payment_hash_hex.clone(),
            client_claim_pubkey_hex: request.client_claim_pubkey_hex.clone(),
            client_refund_pubkey_hex: request.client_refund_pubkey_hex.clone(),
            invoice: request.invoice.clone(),
            owner_ref: request.owner_ref.clone(),
        }
    }

    /// The engine's request, owned by the carrier's authenticated sender.
    pub fn into_request(self, sender: &str) -> SwapRequest {
        SwapRequest {
            script_type: self.script_type,
            quote_id: self.quote_id,
            client_pkarr: sender.to_string(),
            direction: self.direction,
            payment_hash_hex: self.payment_hash_hex,
            client_claim_pubkey_hex: self.client_claim_pubkey_hex,
            client_refund_pubkey_hex: self.client_refund_pubkey_hex,
            invoice: self.invoice,
            owner_ref: self.owner_ref,
        }
    }
}

/// What `contract_hash` covers: the acceptance without its invoice, and the invoice blob's hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractBody {
    /// `invoice` is always empty here.
    pub accept: SwapAccept,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice_blob_hash: Option<String>,
}

/// The signed part of a contract, which a third party verifies on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedContract {
    pub commit_hash: String,
    pub contract: ContractBody,
    pub contract_hash: String,
    pub signer: String,
    pub signature: String,
}

impl SignedContract {
    /// Recompute `contract_hash` from what it covers and check the signature over it.
    pub fn verify(&self) -> Result<(), CapError> {
        let hash = contract_hash(&self.commit_hash, &self.contract)?;
        if hex::encode(hash) != self.contract_hash {
            return Err(CapError::HashMismatch("contract_hash"));
        }
        verify(&self.signer, &hash, &self.signature)
    }
}

/// The hold invoice, sealed under a per-swap key. Over `direct/1` the key travels beside it; an
/// Encrypted Link carries the key in the link message and the blob wherever it is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceBlob {
    pub key: String,
    pub ciphertext: String,
}

impl InvoiceBlob {
    pub fn hash(&self) -> Result<String, CapError> {
        let bytes = hex::decode(&self.ciphertext).map_err(|_| CapError::Blob)?;
        Ok(hex::encode(sha256::Hash::hash(&bytes).to_byte_array()))
    }

    pub fn open(&self) -> Result<String, CapError> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        let key: [u8; 32] = hex::decode(&self.key)
            .ok()
            .and_then(|key| key.try_into().ok())
            .ok_or(CapError::Blob)?;
        let ciphertext = hex::decode(&self.ciphertext).map_err(|_| CapError::Blob)?;
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key.into());
        let plain = cipher
            .decrypt(&[0u8; 12].into(), ciphertext.as_slice())
            .map_err(|_| CapError::Blob)?;
        String::from_utf8(plain).map_err(|_| CapError::Blob)
    }

    /// Seal `invoice` under `key`. Each key seals one invoice, so the nonce is fixed.
    pub fn seal(key: [u8; 32], invoice: &str) -> Self {
        use chacha20poly1305::aead::{Aead, KeyInit};
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher
            .encrypt(&[0u8; 12].into(), invoice.as_bytes())
            .expect("sealing a short invoice cannot fail");
        Self {
            key: hex::encode(key),
            ciphertext: hex::encode(ciphertext),
        }
    }
}

/// A contract as sent: the signed part and, for a reverse swap, the invoice blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractReply {
    pub signed: SignedContract,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invoice_blob: Option<InvoiceBlob>,
}

impl ContractReply {
    /// Check the signature and the blob, and rebuild the engine's acceptance.
    pub fn open(&self) -> Result<SwapAccept, CapError> {
        self.signed.verify()?;
        let mut accept = self.signed.contract.accept.clone();
        match (&self.signed.contract.invoice_blob_hash, &self.invoice_blob) {
            (None, None) => {}
            (Some(hash), Some(blob)) if blob.hash()? == *hash => {
                accept.invoice = Some(blob.open()?);
            }
            _ => return Err(CapError::HashMismatch("invoice_blob_hash")),
        }
        Ok(accept)
    }
}

/// A lifecycle state, the reply to `status_request`, or `pending` for a commit still admitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<Uuid>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// With a stored contract, the snapshot's invoice is left out: the blob carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SwapStatusSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<ContractReply>,
}

/// A refusal, coded as [`RejectCode`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub code: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap_id: Option<Uuid>,
}

impl From<Reject> for Refusal {
    fn from(reject: Reject) -> Self {
        Self {
            code: reject
                .code
                .unwrap_or_else(|| RejectCode::InternalError.as_str().into()),
            reason: reject.reason,
            request_id: reject.request_id,
            quote_id: reject.quote_id,
            swap_id: reject.swap_id,
        }
    }
}

impl From<Refusal> for Reject {
    fn from(refusal: Refusal) -> Self {
        Self {
            code: Some(refusal.code),
            request_id: refusal.request_id,
            swap_id: refusal.swap_id,
            quote_id: refusal.quote_id,
            reason: refusal.reason,
        }
    }
}

/// Signs the hashes. Which key, the routing key or a delegated subkey, is the implementor's.
pub trait CapSigner: Send + Sync {
    /// The Ed25519 public key a verifier checks, as hex.
    fn public_key_hex(&self) -> String;
    fn sign(&self, message: &[u8]) -> [u8; 64];
}

/// An Ed25519 key held in memory.
pub struct Ed25519Signer(ed25519_dalek::SigningKey);

impl Ed25519Signer {
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(secret))
    }
}

impl CapSigner for Ed25519Signer {
    fn public_key_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.0.sign(message).to_bytes()
    }
}

/// Check an Ed25519 signature over a 32-byte hash.
pub fn verify(signer_hex: &str, hash: &[u8; 32], signature_hex: &str) -> Result<(), CapError> {
    let key: [u8; 32] = hex::decode(signer_hex)
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or(CapError::BadSignature)?;
    let signature: [u8; 64] = hex::decode(signature_hex)
        .ok()
        .and_then(|signature| signature.try_into().ok())
        .ok_or(CapError::BadSignature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| CapError::BadSignature)?;
    key.verify_strict(hash, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| CapError::BadSignature)
}

/// RFC 8785 for the values these messages hold: object members sorted, no whitespace, and
/// integers only. A float or an integer past 2^53 is refused rather than encoded differently
/// from another implementation.
pub fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>, CapError> {
    let value = serde_json::to_value(value).map_err(|e| CapError::Canonical(e.to_string()))?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), CapError> {
    const MAX_SAFE: u64 = (1 << 53) - 1;
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            out.extend(serde_json::to_vec(value).map_err(|e| CapError::Canonical(e.to_string()))?)
        }
        Value::Number(number) => match (number.as_u64(), number.as_i64()) {
            (Some(n), _) if n <= MAX_SAFE => out.extend(n.to_string().bytes()),
            (None, Some(n)) if n.unsigned_abs() <= MAX_SAFE => out.extend(n.to_string().bytes()),
            _ => return Err(CapError::Canonical(format!("number {number}"))),
        },
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            // JCS orders by UTF-16 code units. Every key here is ASCII, where that is byte order.
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(&Value::String(key.clone()), out)?;
                out.push(b':');
                write_canonical(&members[key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn domain_hash(domain: &[u8], value: &Value) -> Result<[u8; 32], CapError> {
    let mut preimage = domain.to_vec();
    preimage.extend(jcs(value)?);
    Ok(sha256::Hash::hash(&preimage).to_byte_array())
}

/// The quote as `terms_hash` covers it: without its correlation id.
fn quote_terms(quote: &Quote) -> Quote {
    Quote {
        request_id: None,
        ..quote.clone()
    }
}

pub fn terms_hash(rfq: &RfqConstraints, quote: &Quote) -> Result<[u8; 32], CapError> {
    let value = serde_json::json!({ "rfq": rfq, "quote": quote_terms(quote) });
    domain_hash(TERMS_DOMAIN, &value)
}

pub fn commit_hash(terms_hash_hex: &str, commit: &CommitBody) -> Result<[u8; 32], CapError> {
    let value = serde_json::json!({ "terms_hash": terms_hash_hex, "commit": commit });
    domain_hash(COMMIT_DOMAIN, &value)
}

pub fn contract_hash(commit_hash_hex: &str, contract: &ContractBody) -> Result<[u8; 32], CapError> {
    let value = serde_json::json!({ "commit_hash": commit_hash_hex, "contract": contract });
    domain_hash(CONTRACT_DOMAIN, &value)
}

/// Sign a quote answering `rfq`.
pub fn sign_quote(
    signer: &dyn CapSigner,
    rfq: &RfqConstraints,
    quote: &Quote,
) -> Result<SignedQuote, CapError> {
    let hash = terms_hash(rfq, quote)?;
    Ok(SignedQuote {
        request_id: quote.request_id,
        quote: quote_terms(quote),
        terms_hash: hex::encode(hash),
        signer: signer.public_key_hex(),
        signature: hex::encode(signer.sign(&hash)),
    })
}

impl SignedQuote {
    /// Check the quote answers `rfq` and the signature over its `terms_hash`.
    pub fn verify(&self, rfq: &RfqConstraints) -> Result<(), CapError> {
        let hash = terms_hash(rfq, &self.quote)?;
        if hex::encode(hash) != self.terms_hash {
            return Err(CapError::HashMismatch("terms_hash"));
        }
        verify(&self.signer, &hash, &self.signature)
    }

    /// The engine's quote, with its correlation id restored.
    pub fn to_quote(&self) -> Quote {
        Quote {
            request_id: self.request_id,
            ..self.quote.clone()
        }
    }
}

/// Sign a contract for `accept`. The same inputs give the same bytes: Ed25519 signatures are
/// deterministic and the blob key is derived from a signature, so a contract signed again after
/// a crash matches the one first sent.
pub fn sign_contract(
    signer: &dyn CapSigner,
    terms_hash_hex: &str,
    commit: &CommitBody,
    accept: &SwapAccept,
) -> Result<ContractReply, CapError> {
    let commit_hash = hex::encode(commit_hash(terms_hash_hex, commit)?);
    let invoice_blob = accept.invoice.as_deref().map(|invoice| {
        let mut message = BLOB_KEY_DOMAIN.to_vec();
        message.extend(accept.swap_id.as_bytes());
        let key = sha256::Hash::hash(&signer.sign(&message)).to_byte_array();
        InvoiceBlob::seal(key, invoice)
    });
    let contract = ContractBody {
        accept: SwapAccept {
            invoice: None,
            ..accept.clone()
        },
        invoice_blob_hash: invoice_blob.as_ref().map(InvoiceBlob::hash).transpose()?,
    };
    let hash = contract_hash(&commit_hash, &contract)?;
    Ok(ContractReply {
        signed: SignedContract {
            commit_hash,
            contract,
            contract_hash: hex::encode(hash),
            signer: signer.public_key_hex(),
            signature: hex::encode(signer.sign(&hash)),
        },
        invoice_blob,
    })
}

/// Client-side translation: [`SwapMessage`] requests into these kinds, and replies back after
/// their signatures and hashes check out.
#[derive(Debug, Default)]
pub struct CapClient {
    /// The provider's key as hex. Replies signed by any other key are refused.
    expected_signer: Option<String>,
    /// Signed terms by quote id, which a commit names.
    terms: HashMap<Uuid, String>,
    /// Each commit sent and its `commit_hash`, by quote id. A status reply for that quote must
    /// carry a contract signed over it.
    commits: HashMap<Uuid, (String, Commit)>,
    /// The quote id of each swap a contract was opened for, so a status query by swap id is
    /// checked against the commit without trusting the quote id the reply names.
    swaps: HashMap<Uuid, Uuid>,
}

impl CapClient {
    pub fn new(expected_signer: Option<[u8; 32]>) -> Self {
        Self {
            expected_signer: expected_signer.map(hex::encode),
            terms: HashMap::new(),
            commits: HashMap::new(),
            swaps: HashMap::new(),
        }
    }

    /// The kind to send for `request`. `None` means send it as a plain [`SwapMessage`]: an offer
    /// or list request, or a commit whose signed quote this client never saw.
    pub fn request(&mut self, request: &SwapMessage) -> Option<CapMessage> {
        match request {
            SwapMessage::QuoteRequest(request) => Some(CapMessage::Rfq(Rfq {
                request_id: request.request_id,
                constraints: constraints(request),
                protocol_version: request.protocol_version,
                features: request.features.clone(),
            })),
            SwapMessage::SwapRequest(request) => {
                let commit = Commit {
                    terms_hash: self.terms.get(&request.quote_id)?.clone(),
                    commit: CommitBody::from_request(request),
                };
                let hash = commit_hash(&commit.terms_hash, &commit.commit).ok()?;
                self.commits
                    .insert(request.quote_id, (hex::encode(hash), commit.clone()));
                Some(CapMessage::Commit(commit))
            }
            SwapMessage::SwapStatusRequest(request) => {
                Some(CapMessage::StatusRequest(request.clone()))
            }
            _ => None,
        }
    }

    fn check_signer(&self, signer: &str) -> Result<(), CapError> {
        match &self.expected_signer {
            Some(expected) if expected != signer => Err(CapError::UnexpectedSigner),
            _ => Ok(()),
        }
    }

    /// Check `reply` against `request` and translate it for the engine.
    pub fn reply(
        &mut self,
        request: &SwapMessage,
        reply: CapMessage,
    ) -> Result<SwapMessage, CapError> {
        match (request, reply) {
            (_, CapMessage::Refusal(refusal)) => Ok(SwapMessage::Reject(refusal.into())),
            (SwapMessage::QuoteRequest(request), CapMessage::Quote(signed)) => {
                self.check_signer(&signed.signer)?;
                signed.verify(&constraints(request))?;
                self.terms
                    .insert(signed.quote.quote_id, signed.terms_hash.clone());
                Ok(SwapMessage::Quote(signed.to_quote()))
            }
            (SwapMessage::SwapRequest(request), CapMessage::Contract(contract)) => {
                self.check_signer(&contract.signed.signer)?;
                let terms_hash = self
                    .terms
                    .get(&request.quote_id)
                    .ok_or(CapError::Unexpected("contract for an unsigned quote"))?;
                let expected = commit_hash(terms_hash, &CommitBody::from_request(request))?;
                if hex::encode(expected) != contract.signed.commit_hash {
                    return Err(CapError::HashMismatch("commit_hash"));
                }
                let accept = contract.open()?;
                if accept.quote_id != request.quote_id {
                    return Err(CapError::Unexpected("contract for another quote"));
                }
                self.swaps.insert(accept.swap_id, accept.quote_id);
                Ok(SwapMessage::SwapAccept(accept))
            }
            (SwapMessage::SwapRequest(request), CapMessage::Status(status))
                if status.state == STATE_PENDING && status.snapshot.is_none() =>
            {
                Ok(SwapMessage::Reject(Reject {
                    code: Some(RejectCode::Pending.as_str().into()),
                    request_id: None,
                    swap_id: status.swap_id,
                    quote_id: Some(request.quote_id),
                    reason: "the swap is still being admitted".into(),
                }))
            }
            (SwapMessage::SwapStatusRequest(request), CapMessage::Status(status)) => {
                let Status {
                    snapshot, contract, ..
                } = *status;
                let mut snapshot = snapshot.ok_or(CapError::Unexpected("status without a swap"))?;
                // A swap this client committed to here is recovered only with the contract
                // signed over that commit. The quote comes from what was asked where it can,
                // since a reply naming another quote would otherwise skip the check.
                let quote_id = request
                    .quote_id
                    .or_else(|| request.swap_id.and_then(|id| self.swaps.get(&id).copied()))
                    .unwrap_or(snapshot.accept.quote_id);
                match (&contract, self.commits.get(&quote_id)) {
                    (None, Some((_, commit))) => {
                        return Err(CapError::MissingContract(Box::new(commit.clone())))
                    }
                    (Some(contract), Some((hash, _))) if contract.signed.commit_hash != *hash => {
                        return Err(CapError::HashMismatch("commit_hash"))
                    }
                    _ => {}
                }
                if let Some(contract) = contract {
                    self.check_signer(&contract.signed.signer)?;
                    let accept = contract.open()?;
                    let unsigned = SwapAccept {
                        invoice: None,
                        ..snapshot.accept.clone()
                    };
                    if unsigned != contract.signed.contract.accept {
                        return Err(CapError::HashMismatch("contract"));
                    }
                    snapshot.accept = accept;
                }
                Ok(SwapMessage::SwapStatusSnapshot(snapshot))
            }
            _ => Err(CapError::Unexpected("kind")),
        }
    }
}

fn constraints(request: &QuoteRequest) -> RfqConstraints {
    RfqConstraints {
        offer_id: request.offer_id,
        direction: request.direction,
        amount_sat: request.amount_sat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkSpec, SwapDirection, SwapState};

    fn uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_secret(&[7; 32])
    }

    fn rfq() -> RfqConstraints {
        RfqConstraints {
            offer_id: uuid(1),
            direction: SwapDirection::Reverse,
            amount_sat: 100_000,
        }
    }

    fn quote() -> Quote {
        Quote {
            request_id: Some(uuid(9)),
            quote_id: uuid(2),
            offer_id: uuid(1),
            direction: SwapDirection::Reverse,
            amount_sat: 100_000,
            fee_sat: 1_470,
            service_fee_sat: 700,
            onchain_fee_sat: 770,
            fee_rate_sat_vb: 5,
            total_sat: 101_470,
            htlc_timeout_blocks: 144,
            required_confirmations: 1,
            valid_until_unix: 1_800_000_000,
            fund_within_secs: 300,
            protocol_version: PROTOCOL_VERSION,
        }
    }

    fn commit() -> CommitBody {
        CommitBody {
            script_type: SwapScript::TaprootBoltz,
            quote_id: uuid(2),
            direction: SwapDirection::Reverse,
            payment_hash_hex: "11".repeat(32),
            client_claim_pubkey_hex: Some(format!("02{}", "22".repeat(32))),
            client_refund_pubkey_hex: None,
            invoice: None,
            owner_ref: Some("index:7".into()),
        }
    }

    fn accept() -> SwapAccept {
        SwapAccept {
            script_type: SwapScript::TaprootBoltz,
            swap_tree: None,
            quote_id: uuid(2),
            swap_id: uuid(3),
            direction: SwapDirection::Reverse,
            htlc_script_hex: String::new(),
            htlc_address: "bcrt1pexample".into(),
            onchain_amount_sat: 100_000,
            timeout_block_height: 800_144,
            provider_pubkey_hex: format!("03{}", "33".repeat(32)),
            invoice: Some("lnbcrt1hold".into()),
        }
    }

    /// Fixed inputs, fixed hashes. Another implementation that gets these bytes speaks the same
    /// profile; a change here is a wire change.
    #[test]
    fn golden_vectors() {
        let terms = sign_quote(&signer(), &rfq(), &quote()).unwrap();
        let contract = sign_contract(&signer(), &terms.terms_hash, &commit(), &accept()).unwrap();
        let actual = [
            terms.terms_hash.as_str(),
            contract.signed.commit_hash.as_str(),
            contract.signed.contract_hash.as_str(),
            terms.signer.as_str(),
        ];
        assert_eq!(actual, GOLDEN, "{actual:#?}");
        assert_eq!(
            hex::encode(commit_hash(&terms.terms_hash, &commit()).unwrap()),
            GOLDEN[1]
        );
    }

    /// `terms_hash`, `commit_hash`, `contract_hash`, and the signer for secret `[7; 32]`.
    const GOLDEN: [&str; 4] = [
        "766a45ca9f2aafb59085836d2f8c77153b26eef5461d5c55d18e3ecb495759f6",
        "a4c7b47b6a9f1e6e2d8bcab2d4046ca0365904972294a032cf5e85898246397f",
        "e09ffac51ae04cfa914e435282a976cfeb6a82ea5444a102034f4543be6a7a37",
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    ];

    #[test]
    fn jcs_sorts_members_and_refuses_floats() {
        let value = serde_json::json!({ "b": [2, {"z": null, "a": true}], "a": "é\n" });
        assert_eq!(
            String::from_utf8(jcs(&value).unwrap()).unwrap(),
            r#"{"a":"é\n","b":[2,{"a":true,"z":null}]}"#
        );
        assert!(jcs(&serde_json::json!({ "x": 1.5 })).is_err());
        assert!(jcs(&serde_json::json!({ "x": 1u64 << 53 })).is_err());
    }

    /// Both signed messages survive the wire, and a changed byte anywhere breaks them.
    #[test]
    fn signed_messages_round_trip_and_a_changed_byte_breaks_them() {
        let quote_message = CapMessage::Quote(sign_quote(&signer(), &rfq(), &quote()).unwrap());
        let bytes = serde_json::to_vec(&quote_message).unwrap();
        let CapMessage::Quote(parsed) = serde_json::from_slice(&bytes).unwrap() else {
            panic!("kind changed in transit");
        };
        parsed.verify(&rfq()).unwrap();
        assert_eq!(parsed.to_quote().request_id, quote().request_id);

        let mut changed = parsed.clone();
        changed.quote.fee_sat -= 1;
        assert_eq!(
            changed.verify(&rfq()),
            Err(CapError::HashMismatch("terms_hash"))
        );
        let mut other_rfq = rfq();
        other_rfq.amount_sat += 1;
        assert!(parsed.verify(&other_rfq).is_err());

        let contract = sign_contract(&signer(), &parsed.terms_hash, &commit(), &accept()).unwrap();
        let bytes = serde_json::to_vec(&CapMessage::Contract(contract.clone())).unwrap();
        let CapMessage::Contract(parsed) = serde_json::from_slice(&bytes).unwrap() else {
            panic!("kind changed in transit");
        };
        assert_eq!(parsed, contract);
        assert_eq!(parsed.open().unwrap(), accept());

        // Every byte of the signature, and of each hash it covers, matters.
        for index in 0..parsed.signed.signature.len() {
            let mut tampered = parsed.signed.clone();
            let mut chars: Vec<char> = tampered.signature.chars().collect();
            chars[index] = if chars[index] == '0' { '1' } else { '0' };
            tampered.signature = chars.into_iter().collect();
            assert!(tampered.verify().is_err(), "signature byte {index}");
        }
        let mut tampered = parsed.signed.clone();
        tampered.contract.accept.onchain_amount_sat += 1;
        assert!(tampered.verify().is_err());
        let mut tampered = parsed.signed.clone();
        tampered.commit_hash.replace_range(0..1, "f");
        assert!(tampered.verify().is_err());

        // The blob is bound too: another invoice under the same signature is refused.
        let mut swapped = parsed.clone();
        swapped.invoice_blob = Some(InvoiceBlob::seal([1; 32], "lnbcrt1other"));
        assert!(swapped.open().is_err());
    }

    /// Signing the same contract again, as a provider does after a crash, gives the same bytes.
    #[test]
    fn a_contract_signed_twice_is_the_same_bytes() {
        let terms = hex::encode(terms_hash(&rfq(), &quote()).unwrap());
        let first = sign_contract(&signer(), &terms, &commit(), &accept()).unwrap();
        let second = sign_contract(&signer(), &terms, &commit(), &accept()).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }

    /// The client turns a full exchange into engine messages, and refuses a quote signed by a
    /// key other than the provider it dialed.
    #[test]
    fn the_client_checks_every_signed_reply() {
        let provider = signer();
        let key: [u8; 32] = hex::decode(provider.public_key_hex())
            .unwrap()
            .try_into()
            .unwrap();
        let mut client = CapClient::new(Some(key));
        let quote_request = SwapMessage::QuoteRequest(QuoteRequest {
            request_id: quote().request_id,
            offer_id: rfq().offer_id,
            client_pkarr: "ignored".into(),
            direction: rfq().direction,
            amount_sat: rfq().amount_sat,
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        });
        let Some(CapMessage::Rfq(sent)) = client.request(&quote_request) else {
            panic!("a quote request goes as an rfq");
        };
        assert_eq!(sent.constraints, rfq());

        let stranger = Ed25519Signer::from_secret(&[8; 32]);
        let forged = CapMessage::Quote(sign_quote(&stranger, &rfq(), &quote()).unwrap());
        assert!(client.reply(&quote_request, forged).is_err());

        let signed = sign_quote(&provider, &rfq(), &quote()).unwrap();
        let reply = client
            .reply(&quote_request, CapMessage::Quote(signed.clone()))
            .unwrap();
        assert!(matches!(reply, SwapMessage::Quote(q) if q.quote_id == quote().quote_id));

        let swap_request = SwapMessage::SwapRequest(commit().into_request("owner"));
        let Some(CapMessage::Commit(sent)) = client.request(&swap_request) else {
            panic!("a commit follows a signed quote");
        };
        assert_eq!(sent.terms_hash, signed.terms_hash);
        let contract = sign_contract(&provider, &signed.terms_hash, &commit(), &accept()).unwrap();
        let reply = client
            .reply(&swap_request, CapMessage::Contract(contract.clone()))
            .unwrap();
        assert!(matches!(reply, SwapMessage::SwapAccept(a) if a == accept()));

        // A contract over another commit does not answer this one.
        let mut other = commit();
        other.owner_ref = None;
        let wrong = sign_contract(&provider, &signed.terms_hash, &other, &accept()).unwrap();
        assert!(client
            .reply(&swap_request, CapMessage::Contract(wrong.clone()))
            .is_err());

        // Pending is not a decline: the engine sees the code it already retries on.
        let pending = CapMessage::Status(Box::new(Status {
            request_id: None,
            swap_id: None,
            quote_id: Some(uuid(2)),
            state: STATE_PENDING.into(),
            reference: None,
            snapshot: None,
            contract: None,
        }));
        let reply = client.reply(&swap_request, pending).unwrap();
        assert!(matches!(reply, SwapMessage::Reject(r) if r.code() == Some(RejectCode::Pending)));

        // A status reply carries the stored contract, and the invoice comes back from its blob.
        let status_request = SwapMessage::SwapStatusRequest(SwapStatusRequest {
            request_id: None,
            swap_id: Some(uuid(3)),
            quote_id: None,
        });
        let snapshot = SwapStatusSnapshot {
            request_id: None,
            accept: SwapAccept {
                invoice: None,
                ..accept()
            },
            network: NetworkSpec::Regtest,
            state: SwapState::Created,
            funding_txid_hex: None,
            funding_vout: None,
            spend_txid_hex: None,
            claim_observed_txid_hex: None,
            required_confirmations: 1,
            updated_at_unix: 1,
            observed_at_unix: 1,
            created_at_unix: 1,
            payment_hash_hex: "11".repeat(32),
            owner_ref: None,
            claimable: false,
        };
        let status = |contract| {
            CapMessage::Status(Box::new(Status {
                request_id: None,
                swap_id: Some(uuid(3)),
                quote_id: Some(uuid(2)),
                state: "created".into(),
                reference: None,
                snapshot: Some(snapshot.clone()),
                contract,
            }))
        };
        let reply = client
            .reply(&status_request, status(Some(contract)))
            .unwrap();
        assert!(matches!(reply, SwapMessage::SwapStatusSnapshot(s) if s.accept == accept()));

        // Recovering the committed swap needs the contract signed over that commit. Without one,
        // the client gets the commit to send again.
        assert!(client.reply(&status_request, status(Some(wrong))).is_err());
        assert_eq!(
            client.reply(&status_request, status(None)).unwrap_err(),
            CapError::MissingContract(Box::new(sent.clone()))
        );
        // A reply naming another quote is still checked against the swap's commit.
        let mut moved = snapshot.clone();
        moved.accept.quote_id = uuid(4);
        let moved = CapMessage::Status(Box::new(Status {
            request_id: None,
            swap_id: Some(uuid(3)),
            quote_id: Some(uuid(4)),
            state: "created".into(),
            reference: None,
            snapshot: Some(moved),
            contract: None,
        }));
        assert!(client.reply(&status_request, moved).is_err());
    }

    /// Paykit Event Messages carry at most 1,000 bytes. A signed contract is left out: with the
    /// P2WSH script or Taproot tree the provider always sends, it does not fit yet.
    #[test]
    fn rfq_quote_and_commit_fit_a_paykit_event_message() {
        let rfq_message = CapMessage::Rfq(Rfq {
            request_id: Some(uuid(9)),
            constraints: rfq(),
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        });
        let quote_message = CapMessage::Quote(sign_quote(&signer(), &rfq(), &quote()).unwrap());
        let commit_message = CapMessage::Commit(Commit {
            terms_hash: "00".repeat(32),
            commit: commit(),
        });
        for message in [rfq_message, quote_message, commit_message] {
            let size = serde_json::to_vec(&message).unwrap().len();
            assert!(size <= PAYKIT_EVENT_MAX_BYTES, "{size} bytes: {message:?}");
        }
    }
}
