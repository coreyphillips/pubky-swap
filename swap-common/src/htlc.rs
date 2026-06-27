//! P2WSH HTLC scripts and preimage helpers (MVP).
//!
//! Both swap directions are made atomic by a single 32-byte preimage whose SHA256 is the
//! payment hash shared with the Lightning invoice. Whoever needs to move funds must reveal
//! the preimage on one leg, which the counterparty then replays on the other leg.
//!
//! Phase 2 (see ROADMAP.md) replaces this P2WSH form with Taproot (cooperative MuSig2
//! key-path spend + this script as the script-path fallback).

use bitcoin::blockdata::opcodes::all as op;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Address, Network, PublicKey, ScriptBuf};

/// A 32-byte swap preimage.
pub type Preimage = [u8; 32];
/// SHA256(preimage); the payment hash shared with the Lightning invoice.
pub type PaymentHash = [u8; 32];

/// Generate a fresh random 32-byte preimage.
pub fn generate_preimage() -> Preimage {
    use rand::RngCore;
    let mut p = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut p);
    p
}

/// Compute SHA256(preimage) — the payment hash linking the on-chain HTLC to the LN invoice.
pub fn payment_hash(preimage: &Preimage) -> PaymentHash {
    sha256::Hash::hash(preimage).to_byte_array()
}

/// Build a standard cross-chain HTLC redeem script:
///
/// ```text
/// OP_IF
///     OP_SHA256 <payment_hash> OP_EQUALVERIFY
///     <claim_pubkey> OP_CHECKSIG
/// OP_ELSE
///     <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP
///     <refund_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// - **Claim path** (IF): the receiver spends with `<sig> <preimage> OP_TRUE`.
/// - **Refund path** (ELSE): the funder reclaims with `<sig> OP_FALSE`, but only once the
///   transaction's locktime reaches `timeout` (an absolute block height).
pub fn build_htlc_script(
    payment_hash: &PaymentHash,
    claim_pubkey: &PublicKey,
    refund_pubkey: &PublicKey,
    timeout: u32,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(op::OP_IF)
        .push_opcode(op::OP_SHA256)
        .push_slice(*payment_hash)
        .push_opcode(op::OP_EQUALVERIFY)
        .push_key(claim_pubkey)
        .push_opcode(op::OP_CHECKSIG)
        .push_opcode(op::OP_ELSE)
        .push_int(i64::from(timeout))
        .push_opcode(op::OP_CLTV)
        .push_opcode(op::OP_DROP)
        .push_key(refund_pubkey)
        .push_opcode(op::OP_CHECKSIG)
        .push_opcode(op::OP_ENDIF)
        .into_script()
}

/// The P2WSH address committing to an HTLC redeem script (its scriptPubKey is
/// `address.script_pubkey()`).
pub fn htlc_p2wsh_address(redeem_script: &ScriptBuf, network: Network) -> Address {
    Address::p2wsh(redeem_script, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::new(sk.public_key(&secp))
    }

    #[test]
    fn payment_hash_is_deterministic_sha256() {
        let p = [7u8; 32];
        assert_eq!(payment_hash(&p), payment_hash(&p));
        assert_eq!(payment_hash(&p).len(), 32);
    }

    #[test]
    fn generate_preimage_is_random() {
        assert_ne!(generate_preimage(), generate_preimage());
    }

    #[test]
    fn htlc_script_and_address_build() {
        let claim = test_pubkey(1);
        let refund = test_pubkey(2);
        let ph = payment_hash(&generate_preimage());
        let script = build_htlc_script(&ph, &claim, &refund, 800_000);

        assert!(!script.is_empty());
        let bytes = script.as_bytes();
        // Refund branch must carry the CLTV opcode.
        assert!(bytes.contains(&op::OP_CLTV.to_u8()));

        let addr = htlc_p2wsh_address(&script, Network::Regtest);
        assert!(addr.to_string().starts_with("bcrt1"));
    }
}
