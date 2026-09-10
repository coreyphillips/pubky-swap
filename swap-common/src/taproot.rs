//! Bitcoin Taproot HTLCs compatible with Boltz's two-leaf swap profile.
//!
//! BIP327 aggregates the provider key first and client key second, without sorting.
//! Both parties retain unilateral script-path recovery. This module implements
//! script-path signing only; it never accepts or persists MuSig2 signing nonces.

use crate::htlc::{payment_hash, PaymentHash, Preimage};
use crate::onchain::SpendPath;
use crate::{Result, SwapDirection, SwapError};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::opcodes::all as op;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    transaction, Address, Amount, Network, OutPoint, PublicKey, Script, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

/// The script and leaf version exposed by Boltz API v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoltzTapLeaf {
    /// Tapscript version, 192 for Bitcoin.
    pub version: u8,
    /// Hex-encoded script bytes.
    pub output: String,
}

/// Bitcoin's two-leaf Boltz swap tree, with hex-encoded scripts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoltzSwapTree {
    /// The preimage and receiver signature path.
    pub claim_leaf: BoltzTapLeaf,
    /// The absolute timeout and funder signature path.
    pub refund_leaf: BoltzTapLeaf,
}

/// A validated swap contract. Persistence stores public construction parameters
/// and rebuilds all scripts and commitments through the validating constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TaprootParameters", into = "TaprootParameters")]
pub struct BoltzTaprootSwap {
    parameters: TaprootParameters,
    claim_key: XOnlyPublicKey,
    refund_key: XOnlyPublicKey,
    claim_script: ScriptBuf,
    refund_script: ScriptBuf,
    spend_info: TaprootSpendInfo,
    claim_control_block: Vec<u8>,
    refund_control_block: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaprootParameters {
    direction: SwapDirection,
    payment_hash: PaymentHash,
    claim_public_key: String,
    refund_public_key: String,
    timeout: u32,
}

impl BoltzTaprootSwap {
    /// Construct the exact Bitcoin submarine or reverse profile used by Boltz.
    /// Keys must be compressed and distinct, and timeout must be a block height.
    pub fn new(
        direction: SwapDirection,
        payment_hash: &PaymentHash,
        claim: &PublicKey,
        refund: &PublicKey,
        timeout: u32,
    ) -> Result<Self> {
        validate_parameters(claim, refund, timeout)?;
        let claim_key = claim.inner.x_only_public_key().0;
        let refund_key = refund.inner.x_only_public_key().0;
        let claim_script = build_claim_script(direction, payment_hash, claim_key);
        let refund_script = build_refund_script(refund_key, timeout);
        let internal_key = aggregate_internal_key(direction, claim, refund)?;
        let spend_info = build_spend_info(internal_key, &claim_script, &refund_script)?;
        let claim_control_block = control_block(&spend_info, &claim_script)?;
        let refund_control_block = control_block(&spend_info, &refund_script)?;
        Ok(Self {
            parameters: TaprootParameters {
                direction,
                payment_hash: *payment_hash,
                claim_public_key: claim.to_string(),
                refund_public_key: refund.to_string(),
                timeout,
            },
            claim_key,
            refund_key,
            claim_script,
            refund_script,
            spend_info,
            claim_control_block,
            refund_control_block,
        })
    }

    /// The P2TR address committing to the aggregate key and both script paths.
    pub fn address(&self, network: Network) -> Address {
        Address::p2tr_tweaked(self.spend_info.output_key(), network)
    }

    /// The funding output script, independent of the address network encoding.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    /// Public tree data for a client to independently reconstruct the contract.
    pub fn swap_tree(&self) -> BoltzSwapTree {
        BoltzSwapTree {
            claim_leaf: serialized_leaf(&self.claim_script),
            refund_leaf: serialized_leaf(&self.refund_script),
        }
    }

    /// The exact claim leaf script committed by the address.
    pub fn claim_script(&self) -> &ScriptBuf {
        &self.claim_script
    }

    /// The exact refund leaf script committed by the address.
    pub fn refund_script(&self) -> &ScriptBuf {
        &self.refund_script
    }

    /// The BIP341 Merkle proof and internal key for the claim path.
    pub fn claim_control_block(&self) -> Vec<u8> {
        self.claim_control_block.clone()
    }

    /// The BIP341 Merkle proof and internal key for the refund path.
    pub fn refund_control_block(&self) -> Vec<u8> {
        self.refund_control_block.clone()
    }

    /// The exact virtual size of this single-input, single-output script spend.
    /// Default Schnorr signatures have a fixed 64-byte size. Building the witness
    /// also accounts for CompactSize boundaries in arbitrary destination scripts.
    pub fn spend_vsize(&self, destination: &Script, is_claim: bool) -> u64 {
        let path = if is_claim {
            SpendPath::Claim { preimage: [0; 32] }
        } else {
            SpendPath::Refund
        };
        let mut tx = unsigned_spend(
            OutPoint::null(),
            0,
            destination.to_owned(),
            self.lock_time(&path),
        );
        tx.input[0].witness = self.witness(&path, &[0; 64]);
        tx.vsize() as u64
    }

    /// Claim using the receiver's key and preimage. The caller must obtain the
    /// actual funding value from its chain watcher before signing.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_tx(
        &self,
        outpoint: OutPoint,
        value_sat: u64,
        destination: ScriptBuf,
        fee_sat: u64,
        preimage: Preimage,
        key: &SecretKey,
    ) -> Result<Transaction> {
        if payment_hash(&preimage) != self.parameters.payment_hash {
            return Err(SwapError::InvalidPreimage(
                "Taproot claim preimage does not match".into(),
            ));
        }
        self.spend_tx(SpendRequest {
            outpoint,
            value_sat,
            destination,
            fee_sat,
            path: SpendPath::Claim { preimage },
            key,
        })
    }

    /// Refund using the funder's key. The transaction has the contract's absolute
    /// block-height locktime and a non-final sequence, and must mature before relay.
    pub fn refund_tx(
        &self,
        outpoint: OutPoint,
        value_sat: u64,
        destination: ScriptBuf,
        fee_sat: u64,
        key: &SecretKey,
    ) -> Result<Transaction> {
        self.spend_tx(SpendRequest {
            outpoint,
            value_sat,
            destination,
            fee_sat,
            path: SpendPath::Refund,
            key,
        })
    }

    fn spend_tx(&self, request: SpendRequest<'_>) -> Result<Transaction> {
        let keypair = Keypair::from_secret_key(&Secp256k1::new(), request.key);
        self.validate_signing_key(&request.path, keypair.x_only_public_key().0)?;
        let output_value = spend_output_value(&request)?;
        let mut tx = unsigned_spend(
            request.outpoint,
            output_value,
            request.destination,
            self.lock_time(&request.path),
        );
        let prevout = TxOut {
            value: Amount::from_sat(request.value_sat),
            script_pubkey: self.script_pubkey(),
        };
        let signature = self.sign_spend(&tx, &prevout, &request.path, &keypair)?;
        tx.input[0].witness = self.witness(&request.path, &signature);
        Ok(tx)
    }

    fn sign_spend(
        &self,
        tx: &Transaction,
        prevout: &TxOut,
        path: &SpendPath,
        key: &Keypair,
    ) -> Result<[u8; 64]> {
        let prevouts = [prevout.clone()];
        let leaf = TapLeafHash::from_script(self.leaf_script(path), LeafVersion::TapScript);
        let sighash = SighashCache::new(tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                leaf,
                TapSighashType::Default,
            )
            .map_err(|error| SwapError::Htlc(format!("Taproot sighash: {error}")))?;
        let message = Message::from_digest(sighash.to_byte_array());
        Ok(Secp256k1::new()
            .sign_schnorr_no_aux_rand(&message, key)
            .serialize())
    }

    fn validate_signing_key(&self, path: &SpendPath, actual: XOnlyPublicKey) -> Result<()> {
        let expected = match path {
            SpendPath::Claim { .. } => self.claim_key,
            SpendPath::Refund => self.refund_key,
        };
        if actual != expected {
            return Err(SwapError::InvalidPubkey(
                "key does not own the Taproot script path".into(),
            ));
        }
        Ok(())
    }

    fn leaf_script(&self, path: &SpendPath) -> &Script {
        match path {
            SpendPath::Claim { .. } => &self.claim_script,
            SpendPath::Refund => &self.refund_script,
        }
    }

    fn lock_time(&self, path: &SpendPath) -> LockTime {
        match path {
            SpendPath::Claim { .. } => LockTime::ZERO,
            SpendPath::Refund => LockTime::from_consensus(self.parameters.timeout),
        }
    }

    fn witness(&self, path: &SpendPath, signature: &[u8; 64]) -> Witness {
        let mut witness = Witness::new();
        witness.push(signature);
        let control = match path {
            SpendPath::Claim { preimage } => {
                witness.push(preimage);
                &self.claim_control_block
            }
            SpendPath::Refund => &self.refund_control_block,
        };
        witness.push(self.leaf_script(path));
        witness.push(control);
        witness
    }
}

impl TryFrom<TaprootParameters> for BoltzTaprootSwap {
    type Error = SwapError;

    fn try_from(value: TaprootParameters) -> Result<Self> {
        let claim = value
            .claim_public_key
            .parse()
            .map_err(|error| SwapError::InvalidPubkey(format!("{error}")))?;
        let refund = value
            .refund_public_key
            .parse()
            .map_err(|error| SwapError::InvalidPubkey(format!("{error}")))?;
        Self::new(
            value.direction,
            &value.payment_hash,
            &claim,
            &refund,
            value.timeout,
        )
    }
}

impl From<BoltzTaprootSwap> for TaprootParameters {
    fn from(value: BoltzTaprootSwap) -> Self {
        value.parameters
    }
}

fn validate_parameters(claim: &PublicKey, refund: &PublicKey, timeout: u32) -> Result<()> {
    if !claim.compressed
        || !refund.compressed
        || claim.inner.x_only_public_key().0 == refund.inner.x_only_public_key().0
    {
        return Err(SwapError::InvalidPubkey(
            "Taproot requires distinct compressed public keys".into(),
        ));
    }
    if timeout == 0 || LockTime::from_height(timeout).is_err() {
        return Err(SwapError::Htlc(
            "Taproot timeout must be a nonzero block height".into(),
        ));
    }
    Ok(())
}

fn aggregate_internal_key(
    direction: SwapDirection,
    claim: &PublicKey,
    refund: &PublicKey,
) -> Result<XOnlyPublicKey> {
    let keys = match direction {
        SwapDirection::Submarine => [claim, refund],
        SwapDirection::Reverse => [refund, claim],
    };
    let points = keys.map(|key| musig2::secp256k1::PublicKey::from_slice(&key.inner.serialize()));
    let [first, second] = points;
    let decode_error = |error| SwapError::InvalidPubkey(format!("MuSig2 public key: {error}"));
    let context =
        musig2::KeyAggContext::new([first.map_err(decode_error)?, second.map_err(decode_error)?])
            .map_err(|error| SwapError::Htlc(format!("MuSig2 key aggregation: {error}")))?;
    let aggregate: musig2::secp256k1::PublicKey = context.aggregated_pubkey();
    XOnlyPublicKey::from_slice(&aggregate.x_only_public_key().0.serialize())
        .map_err(|error| SwapError::InvalidPubkey(format!("MuSig2 internal key: {error}")))
}

fn build_claim_script(
    direction: SwapDirection,
    payment_hash: &PaymentHash,
    key: XOnlyPublicKey,
) -> ScriptBuf {
    let builder = match direction {
        SwapDirection::Submarine => Builder::new(),
        SwapDirection::Reverse => Builder::new()
            .push_opcode(op::OP_SIZE)
            .push_int(32)
            .push_opcode(op::OP_EQUALVERIFY),
    };
    builder
        .push_opcode(op::OP_HASH160)
        .push_slice(ripemd160::Hash::hash(payment_hash).to_byte_array())
        .push_opcode(op::OP_EQUALVERIFY)
        .push_x_only_key(&key)
        .push_opcode(op::OP_CHECKSIG)
        .into_script()
}

fn build_refund_script(key: XOnlyPublicKey, timeout: u32) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&key)
        .push_opcode(op::OP_CHECKSIGVERIFY)
        .push_int(i64::from(timeout))
        .push_opcode(op::OP_CLTV)
        .into_script()
}

fn build_spend_info(
    key: XOnlyPublicKey,
    claim: &Script,
    refund: &Script,
) -> Result<TaprootSpendInfo> {
    let error = |error| SwapError::Htlc(format!("Taproot tree: {error}"));
    TaprootBuilder::new()
        .add_leaf(1, claim.to_owned())
        .map_err(error)?
        .add_leaf(1, refund.to_owned())
        .map_err(error)?
        .finalize(&Secp256k1::new(), key)
        .map_err(|_| SwapError::Htlc("incomplete Taproot tree".into()))
}

fn control_block(info: &TaprootSpendInfo, script: &ScriptBuf) -> Result<Vec<u8>> {
    info.control_block(&(script.clone(), LeafVersion::TapScript))
        .map(|control| control.serialize())
        .ok_or_else(|| SwapError::Htlc("Taproot leaf missing from commitment".into()))
}

fn serialized_leaf(script: &Script) -> BoltzTapLeaf {
    BoltzTapLeaf {
        version: LeafVersion::TapScript.to_consensus(),
        output: hex::encode(script.as_bytes()),
    }
}

struct SpendRequest<'a> {
    outpoint: OutPoint,
    value_sat: u64,
    destination: ScriptBuf,
    fee_sat: u64,
    path: SpendPath,
    key: &'a SecretKey,
}

fn spend_output_value(request: &SpendRequest<'_>) -> Result<u64> {
    if request.value_sat > Amount::MAX_MONEY.to_sat() || request.fee_sat == 0 {
        return Err(SwapError::InvalidAmount(
            "invalid Taproot funding value or zero fee".into(),
        ));
    }
    let value = request
        .value_sat
        .checked_sub(request.fee_sat)
        .ok_or_else(|| {
            SwapError::InvalidAmount("Taproot spend fee exceeds funding value".into())
        })?;
    let dust = request.destination.minimal_non_dust().to_sat().max(546);
    if value < dust {
        return Err(SwapError::InvalidAmount(format!(
            "Taproot spend output is below dust ({dust} sat)"
        )));
    }
    Ok(value)
}

fn unsigned_spend(
    outpoint: OutPoint,
    value_sat: u64,
    destination: ScriptBuf,
    lock_time: LockTime,
) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: destination,
        }],
    }
}

#[cfg(test)]
mod tests;
