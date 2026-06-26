//! On-chain HTLC spend construction and signing.
//!
//! Given a confirmed HTLC P2WSH output (built by [`crate::htlc`]), this produces the two
//! ways to spend it:
//! - **Claim** (IF branch): the receiver provides the preimage. Witness:
//!   `[sig, preimage, 0x01, witnessScript]`.
//! - **Refund** (ELSE branch): the funder reclaims after the timeout. Witness:
//!   `[sig, <empty>, witnessScript]`, with `nLockTime = timeout` and a non-final sequence so
//!   `OP_CHECKLOCKTIMEVERIFY` is enforced.
//!
//! Signing uses the BIP143 segwit-v0 sighash over the HTLC witness script.
//!
//! Fee handling here is a simple absolute-fee deduction with a coarse size estimate;
//! RBF/CPFP fee-bumping under congestion is a later hardening step (see ROADMAP.md).

use crate::error::{Result, SwapError};
use crate::htlc::{PaymentHash, Preimage};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{ecdsa, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

const DUST_THRESHOLD: u64 = 546;

/// Which branch of the HTLC to spend.
#[derive(Debug, Clone)]
pub enum SpendPath {
    /// Claim with the preimage (IF branch).
    Claim { preimage: Preimage },
    /// Refund after the timeout (ELSE branch).
    Refund,
}

/// Coarse vsize estimate for a 1-in/1-out P2WSH HTLC spend, used for fee deduction.
/// Claim witnesses are larger (they carry the 32-byte preimage).
pub fn estimate_spend_vsize(is_claim: bool) -> u64 {
    if is_claim {
        150
    } else {
        140
    }
}

/// Absolute fee for an HTLC spend at `fee_rate_sat_vb`.
pub fn estimate_spend_fee(fee_rate_sat_vb: u64, is_claim: bool) -> u64 {
    estimate_spend_vsize(is_claim) * fee_rate_sat_vb
}

/// Fee-estimation confirmation target (blocks) for a provider's submarine **claim**. The claim
/// races the client's refund timeout, so it targets fewer blocks (more aggressive) than a refund.
pub const CLAIM_FEE_TARGET_BLOCKS: u16 = 3;
/// Fee-estimation confirmation target (blocks) for a **refund**.
pub const REFUND_FEE_TARGET_BLOCKS: u16 = 6;

/// Convert Electrum `blockchain.estimatefee` output (BTC per kB) to sat/vB, rounding up.
/// Returns `None` when the server reports no estimate (`<= 0` or non-finite — e.g. the `-1.0`
/// sentinel on regtest). Never returns below 1 sat/vB.
pub fn btc_per_kvb_to_sat_per_vb(btc_per_kvb: f64) -> Option<u64> {
    if !btc_per_kvb.is_finite() || btc_per_kvb <= 0.0 {
        return None;
    }
    // 1e8 sat/BTC / 1000 vB/kB = 1e5 sat·kB per BTC·vB.
    Some(((btc_per_kvb * 100_000.0).ceil() as u64).max(1))
}

/// Resolve the sat/vB fee rate to use for an HTLC spend. The configured `floor_sat_vb` is both a
/// fallback (when `estimate` is `None`) and a minimum: a live estimate can raise the rate but
/// never lower it below the operator's configured floor.
pub fn resolve_fee_rate(estimate: Option<u64>, floor_sat_vb: u64) -> u64 {
    estimate.unwrap_or(floor_sat_vb).max(floor_sat_vb)
}

/// Build and sign a transaction spending an HTLC P2WSH output.
///
/// - `htlc_outpoint` / `htlc_value_sat`: the funding output being spent.
/// - `redeem_script`: the HTLC witness script (from [`crate::htlc::build_htlc_script`]).
/// - `dest_spk`: destination scriptPubKey for the swept funds.
/// - `fee_sat`: absolute fee to deduct (`output = htlc_value_sat - fee_sat`).
/// - `timeout`: the HTLC's absolute timeout height (sets `nLockTime` for the refund path).
/// - `signing_key`: the key for the chosen branch (the claim key for `Claim`, the refund
///   key for `Refund`).
#[allow(clippy::too_many_arguments)]
pub fn build_htlc_spend(
    htlc_outpoint: OutPoint,
    htlc_value_sat: u64,
    redeem_script: &ScriptBuf,
    dest_spk: ScriptBuf,
    fee_sat: u64,
    timeout: u32,
    path: SpendPath,
    signing_key: &SecretKey,
) -> Result<Transaction> {
    if fee_sat >= htlc_value_sat {
        return Err(SwapError::Other(format!(
            "fee {fee_sat} >= htlc value {htlc_value_sat}"
        )));
    }
    let out_value = htlc_value_sat - fee_sat;
    if out_value < DUST_THRESHOLD {
        return Err(SwapError::Other(format!(
            "swept output {out_value} below dust threshold"
        )));
    }

    let is_claim = matches!(path, SpendPath::Claim { .. });

    // The refund branch must satisfy OP_CHECKLOCKTIMEVERIFY: nLockTime >= timeout and a
    // non-final sequence. The claim branch has no timelock constraint.
    let lock_time = if is_claim {
        LockTime::ZERO
    } else {
        LockTime::from_height(timeout).map_err(|e| SwapError::Other(format!("locktime: {e}")))?
    };
    let sequence = if is_claim {
        Sequence::MAX
    } else {
        Sequence::ENABLE_LOCKTIME_NO_RBF // 0xFFFFFFFE: non-final, so CLTV is enforced
    };

    let mut tx = Transaction {
        version: 2,
        lock_time,
        input: vec![TxIn {
            previous_output: htlc_outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: out_value,
            script_pubkey: dest_spk,
        }],
    };

    // BIP143 sighash over the HTLC witness script.
    let sighash = SighashCache::new(&tx)
        .segwit_signature_hash(0, redeem_script, htlc_value_sat, EcdsaSighashType::All)
        .map_err(|e| SwapError::Htlc(format!("sighash: {e}")))?;
    let secp = Secp256k1::new();
    let msg =
        Message::from_slice(sighash.as_ref()).map_err(|e| SwapError::Htlc(format!("msg: {e}")))?;
    let ecdsa_sig = ecdsa::Signature {
        sig: secp.sign_ecdsa(&msg, signing_key),
        hash_ty: EcdsaSighashType::All,
    };
    let sig_bytes = ecdsa_sig.serialize();

    // Assemble the witness for the chosen branch.
    let mut witness = Witness::new();
    witness.push(&sig_bytes[..]);
    match path {
        SpendPath::Claim { preimage } => {
            witness.push(preimage); // <preimage>
            witness.push([1u8]); // OP_TRUE selector → IF branch
        }
        SpendPath::Refund => {
            witness.push(Vec::<u8>::new()); // empty = OP_FALSE selector → ELSE branch
        }
    }
    witness.push(redeem_script.as_bytes()); // witnessScript last
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Build and sign a claim transaction (spend via the preimage branch).
#[allow(clippy::too_many_arguments)]
pub fn build_claim_tx(
    htlc_outpoint: OutPoint,
    htlc_value_sat: u64,
    redeem_script: &ScriptBuf,
    dest_spk: ScriptBuf,
    fee_sat: u64,
    preimage: Preimage,
    claim_key: &SecretKey,
) -> Result<Transaction> {
    build_htlc_spend(
        htlc_outpoint,
        htlc_value_sat,
        redeem_script,
        dest_spk,
        fee_sat,
        0,
        SpendPath::Claim { preimage },
        claim_key,
    )
}

/// Build and sign a refund transaction (spend via the timeout branch). The resulting tx is
/// only valid once the chain height reaches `timeout`.
#[allow(clippy::too_many_arguments)]
pub fn build_refund_tx(
    htlc_outpoint: OutPoint,
    htlc_value_sat: u64,
    redeem_script: &ScriptBuf,
    dest_spk: ScriptBuf,
    fee_sat: u64,
    timeout: u32,
    refund_key: &SecretKey,
) -> Result<Transaction> {
    build_htlc_spend(
        htlc_outpoint,
        htlc_value_sat,
        redeem_script,
        dest_spk,
        fee_sat,
        timeout,
        SpendPath::Refund,
        refund_key,
    )
}

/// Scan `tx` for the input that spends `htlc_outpoint` and recover the preimage from its
/// witness — i.e. a 32-byte element whose SHA256 equals `payment_hash`. This is how the
/// provider learns the preimage from the client's on-chain claim, in order to settle the
/// Lightning hold invoice (the atomic link between the two legs).
pub fn extract_preimage(
    tx: &Transaction,
    htlc_outpoint: &OutPoint,
    payment_hash: &PaymentHash,
) -> Option<Preimage> {
    for input in &tx.input {
        if input.previous_output != *htlc_outpoint {
            continue;
        }
        for element in input.witness.iter() {
            if element.len() == 32 && sha256::Hash::hash(element).to_byte_array() == *payment_hash {
                let mut preimage = [0u8; 32];
                preimage.copy_from_slice(element);
                return Some(preimage);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htlc::{build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash};
    use crate::keys::random_keypair;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Network, ScriptBuf, TxOut};

    const TIMEOUT: u32 = 1000;
    const VALUE: u64 = 100_000;

    struct Setup {
        redeem: ScriptBuf,
        outpoint: OutPoint,
        spent: TxOut,
        claim_sk: SecretKey,
        refund_sk: SecretKey,
        preimage: [u8; 32],
    }

    fn setup() -> Setup {
        let secp = Secp256k1::new();
        let (claim_sk, claim_pk) = random_keypair(&secp);
        let (refund_sk, refund_pk) = random_keypair(&secp);
        let preimage = generate_preimage();
        let redeem = build_htlc_script(&payment_hash(&preimage), &claim_pk, &refund_pk, TIMEOUT);
        let htlc_spk = htlc_p2wsh_address(&redeem, Network::Regtest).script_pubkey();

        // Synthetic funding tx paying the HTLC; its inputs are irrelevant to verifying the spend.
        let funding = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: VALUE,
                script_pubkey: htlc_spk.clone(),
            }],
        };
        let outpoint = OutPoint {
            txid: funding.txid(),
            vout: 0,
        };
        Setup {
            redeem,
            outpoint,
            spent: funding.output[0].clone(),
            claim_sk,
            refund_sk,
            preimage,
        }
    }

    fn dest() -> ScriptBuf {
        ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap()
    }

    /// Verify a spend against the funded output using libbitcoinconsensus (VERIFY_ALL).
    fn verify(
        tx: &Transaction,
        outpoint: OutPoint,
        spent: &TxOut,
    ) -> std::result::Result<(), String> {
        let spent = spent.clone();
        tx.verify(|op| {
            if *op == outpoint {
                Some(spent.clone())
            } else {
                None
            }
        })
        .map_err(|e| format!("{e:?}"))
    }

    #[test]
    fn claim_tx_is_consensus_valid() {
        let s = setup();
        let tx = build_claim_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            s.preimage,
            &s.claim_sk,
        )
        .unwrap();
        verify(&tx, s.outpoint, &s.spent).expect("claim must be consensus-valid");
    }

    #[test]
    fn refund_tx_is_consensus_valid_at_timeout() {
        let s = setup();
        let tx = build_refund_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            TIMEOUT,
            &s.refund_sk,
        )
        .unwrap();
        assert_eq!(tx.lock_time, LockTime::from_height(TIMEOUT).unwrap());
        verify(&tx, s.outpoint, &s.spent).expect("refund must be consensus-valid at timeout");
    }

    #[test]
    fn claim_with_wrong_preimage_is_rejected() {
        let s = setup();
        let wrong = generate_preimage();
        let tx = build_claim_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            wrong,
            &s.claim_sk,
        )
        .unwrap();
        assert!(
            verify(&tx, s.outpoint, &s.spent).is_err(),
            "claim with a wrong preimage must fail"
        );
    }

    #[test]
    fn refund_signed_by_wrong_key_is_rejected() {
        let s = setup();
        // Sign the refund branch with the CLAIM key — CHECKSIG against refund_pubkey must fail.
        let tx = build_refund_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            TIMEOUT,
            &s.claim_sk,
        )
        .unwrap();
        assert!(
            verify(&tx, s.outpoint, &s.spent).is_err(),
            "refund signed by the wrong key must fail"
        );
    }

    #[test]
    fn preimage_is_extractable_from_claim_tx() {
        let s = setup();
        let tx = build_claim_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            s.preimage,
            &s.claim_sk,
        )
        .unwrap();
        let recovered = extract_preimage(&tx, &s.outpoint, &payment_hash(&s.preimage));
        assert_eq!(recovered, Some(s.preimage));
        // A refund spend reveals no preimage.
        let refund = build_refund_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            TIMEOUT,
            &s.refund_sk,
        )
        .unwrap();
        assert_eq!(
            extract_preimage(&refund, &s.outpoint, &payment_hash(&s.preimage)),
            None
        );
    }

    #[test]
    fn btc_per_kvb_conversion() {
        // 0.0001 BTC/kB = 10 sat/vB.
        assert_eq!(btc_per_kvb_to_sat_per_vb(0.0001), Some(10));
        // 0.00001 BTC/kB = 1 sat/vB.
        assert_eq!(btc_per_kvb_to_sat_per_vb(0.00001), Some(1));
        // A tiny positive rate still rounds up to the 1 sat/vB floor.
        assert_eq!(btc_per_kvb_to_sat_per_vb(1e-12), Some(1));
        // The regtest "no estimate" sentinel and non-positive/NaN values yield None.
        assert_eq!(btc_per_kvb_to_sat_per_vb(-1.0), None);
        assert_eq!(btc_per_kvb_to_sat_per_vb(0.0), None);
        assert_eq!(btc_per_kvb_to_sat_per_vb(f64::NAN), None);
    }

    #[test]
    fn resolve_fee_rate_uses_floor_as_fallback_and_minimum() {
        // No estimate → the configured floor.
        assert_eq!(resolve_fee_rate(None, 5), 5);
        // An estimate below the floor is clamped up to the floor.
        assert_eq!(resolve_fee_rate(Some(3), 5), 5);
        // An estimate above the floor is used.
        assert_eq!(resolve_fee_rate(Some(50), 5), 50);
    }

    #[test]
    fn fee_exceeding_value_is_rejected() {
        let s = setup();
        assert!(build_claim_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            VALUE,
            s.preimage,
            &s.claim_sk
        )
        .is_err());
    }
}
