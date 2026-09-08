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
//! Fees are an absolute deduction from a coarse size estimate. Both branches are built
//! RBF-signalling (BIP125), and [`crate::fee_bump`] re-broadcasts at a higher fee if a spend
//! doesn't confirm in time.

use crate::error::{Result, SwapError};
use crate::htlc::{PaymentHash, Preimage};
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{ecdsa, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

const DUST_THRESHOLD: u64 = 546;

/// Which branch of the HTLC to spend.
#[derive(Debug, Clone)]
pub enum SpendPath {
    /// Claim with the preimage (IF branch).
    Claim { preimage: Preimage },
    /// Refund after the timeout (ELSE branch).
    Refund,
}

/// The vsize of a 1-in/1-out P2WSH HTLC spend, computed rather than guessed.
///
/// A fixed number cannot be right for both branches or for every destination: the claim witness
/// carries a 32-byte preimage the refund does not, and a P2TR output is twelve bytes wider than a
/// P2WPKH one. Getting it wrong makes the effective fee rate drift from the target, which matters
/// most exactly when it must not -- a claim racing a refund window.
///
/// This assembles the same transaction `build_htlc_spend` will, with a maximum-length signature,
/// and asks the `bitcoin` crate for its weight. A unit test asserts it is never below what the
/// real transaction measures.
pub fn spend_vsize(redeem_script: &Script, dest_spk: &Script, is_claim: bool) -> u64 {
    // Non-witness bytes: version(4) + input count(1) + outpoint(36) + scriptSig len(1) +
    // sequence(4) + output count(1) + value(8) + spk len(1) + spk + locktime(4).
    let base = 4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + dest_spk.len() as u64 + 4;

    // Witness bytes: item count, then each item length-prefixed. A DER signature plus sighash
    // byte is at most 72; using the maximum keeps the estimate conservative.
    let script_len = redeem_script.len() as u64;
    let mut witness = 1 // item count
        + 1 + 72 // signature
        + varint_len(script_len) + script_len; // witness script
    witness += if is_claim {
        1 + 32 // preimage
        + 1 + 1 // OP_TRUE branch selector
    } else {
        1 // empty element, the OP_FALSE branch selector
    };

    // Weight = base * 4 + witness, plus the 2-byte segwit marker and flag.
    let weight = base * 4 + witness + 2;
    weight.div_ceil(4)
}

fn varint_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Absolute fee for an HTLC spend at `fee_rate_sat_vb`, saturating rather than overflowing on a
/// nonsense rate.
pub fn estimate_spend_fee(fee_rate_sat_vb: u64, vsize: u64) -> u64 {
    vsize.saturating_mul(fee_rate_sat_vb)
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

/// Resolve the sat/vB fee rate to use for an HTLC spend.
///
/// The configured `floor_sat_vb` is both a fallback (when `estimate` is `None`) and a minimum: a
/// live estimate can raise the rate but never lower it below the operator's configured floor.
/// `cap_sat_vb` bounds it from above, because an Electrum server reporting a nonsense estimate
/// would otherwise set the very first broadcast's fee.
///
/// The cap never pushes the rate below the floor: for a sweep, paying an uneconomic fee still
/// beats losing the whole output.
pub fn resolve_fee_rate(estimate: Option<u64>, floor_sat_vb: u64, cap_sat_vb: u64) -> u64 {
    estimate
        .unwrap_or(floor_sat_vb)
        .max(floor_sat_vb)
        .min(cap_sat_vb.max(floor_sat_vb))
}

/// Absolute ceiling on the fee rate (sat/vB) any HTLC spend will escalate to.
pub const ABSOLUTE_MAX_FEE_RATE_SAT_VB: u64 = 1_000;

/// Share of an HTLC's value, in basis points, that may be spent on the fee to sweep it.
///
/// An absolute rate cap alone does not protect a small swap: at 1000 sat/vB a ~150 vB claim costs
/// 150,000 sat, which is fifteen times the default minimum swap size. The cap has to scale with
/// what is being swept.
pub const DEFAULT_MAX_FEE_BPS: u16 = 2_000; // 20%

/// The fee-rate ceiling for sweeping `htlc_value_sat` with a `vsize`-byte transaction.
///
/// Never returns below `floor`: an uneconomic sweep is still better than an unspendable output,
/// and the caller's dust check will refuse the truly impossible cases.
pub fn fee_rate_cap(
    htlc_value_sat: u64,
    vsize: u64,
    max_fee_bps: u16,
    absolute_cap_sat_vb: u64,
    floor_sat_vb: u64,
) -> u64 {
    let max_fee = (u128::from(htlc_value_sat) * u128::from(max_fee_bps) / 10_000) as u64;
    (max_fee / vsize.max(1))
        .min(absolute_cap_sat_vb)
        .max(floor_sat_vb)
}

/// Confirmation target to price a spend at, given how many blocks remain before its deadline.
///
/// Fewer blocks left means a tighter target, which means a higher estimate. A spend with a
/// hundred blocks of room does not need to outbid the next block; one with three does.
fn target_for_remaining(remaining: u32) -> u16 {
    match remaining {
        0..=3 => 1,
        4..=9 => 2,
        10..=19 => 3,
        20..=49 => 6,
        _ => 12,
    }
}

/// The next fee rate for a spend, given the tip and its deadline.
///
/// Escalation is driven by the deadline rather than by a bump counter. A fixed number of +25%
/// bumps tops out wherever it happens to top out -- from a 2 sat/vB floor, ten bumps reach only
/// about 37 sat/vB -- and then stops escalating entirely no matter how close the deadline gets.
/// Here the target tightens as the deadline approaches, and inside the final few blocks the rate
/// ratchets toward the cap, because at that point a fee saved is the whole output lost.
///
/// The result is always strictly above `previous` when it changes at all, satisfying BIP125's
/// requirement that a replacement pay more.
pub fn deadline_fee_rate(
    tip: u32,
    deadline_height: Option<u32>,
    previous: u64,
    estimate_for: &dyn Fn(u16) -> Option<u64>,
    floor_sat_vb: u64,
    cap_sat_vb: u64,
) -> u64 {
    let cap = cap_sat_vb.max(floor_sat_vb);
    // BIP125 needs a strictly higher fee; ~25% is a comfortable margin over the incremental
    // relay minimum for transactions of this size.
    let min_bump = previous
        .saturating_add(previous / 4)
        .saturating_add(1)
        .max(floor_sat_vb);

    let remaining = match deadline_height {
        Some(deadline) => deadline.saturating_sub(tip),
        // No deadline: escalate gently on the estimate alone.
        None => u32::MAX,
    };

    // Inside the last few blocks there is nothing left to optimise: go to the ceiling.
    if remaining <= 2 {
        return cap;
    }

    let target = target_for_remaining(remaining);
    let estimated = estimate_for(target).unwrap_or(0);
    estimated.max(min_bump).min(cap)
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
    // Both branches opt into BIP125 replace-by-fee (sequence 0xFFFFFFFD) so a stuck claim/refund
    // can be re-broadcast at a higher fee. 0xFFFFFFFD is also non-final, so the refund's absolute
    // timelock (OP_CHECKLOCKTIMEVERIFY) is still enforced; the claim's nLockTime is 0, which is
    // trivially satisfied regardless of sequence.
    let sequence = Sequence::ENABLE_RBF_NO_LOCKTIME; // 0xFFFFFFFD

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
    fn resolve_fee_rate_clamps_at_both_ends() {
        // No estimate: the configured floor.
        assert_eq!(resolve_fee_rate(None, 5, 1_000), 5);
        // An estimate below the floor is clamped up to it.
        assert_eq!(resolve_fee_rate(Some(3), 5, 1_000), 5);
        // An estimate above the floor is used.
        assert_eq!(resolve_fee_rate(Some(50), 5, 1_000), 50);
        // A nonsense estimate is clamped to the cap rather than setting the very first
        // broadcast's fee. This path used to be uncapped while only the bump path was capped, so
        // a bad Electrum answer went straight through into an unchecked multiply.
        assert_eq!(resolve_fee_rate(Some(u64::MAX), 5, 1_000), 1_000);
        // The cap never pushes below the floor: an uneconomic sweep still beats losing the
        // output entirely.
        assert_eq!(resolve_fee_rate(Some(50), 20, 3), 20);
    }

    #[test]
    fn fee_rate_cap_scales_with_the_output_being_swept() {
        // A 10k sat swap: 20% of 10_000 over ~150 vB is about 13 sat/vB, nowhere near the
        // absolute 1000 sat/vB ceiling. An absolute-only cap would have permitted a 150_000 sat
        // fee on a 10_000 sat output, which is fifteen times the whole swap.
        let small = fee_rate_cap(10_000, 150, DEFAULT_MAX_FEE_BPS, 1_000, 1);
        assert_eq!(small, 13);
        assert!(small * 150 <= 10_000 / 5);

        // A large swap is bounded by the absolute ceiling instead.
        assert_eq!(
            fee_rate_cap(10_000_000, 150, DEFAULT_MAX_FEE_BPS, 1_000, 1),
            1_000
        );

        // Never below the floor, even for a tiny output.
        assert_eq!(fee_rate_cap(1_000, 150, DEFAULT_MAX_FEE_BPS, 1_000, 5), 5);
    }

    #[test]
    fn deadline_fee_rate_escalates_as_the_deadline_approaches() {
        let none = |_t: u16| None;
        let tip = 800_000;

        // Far from the deadline: a modest bump above the previous rate.
        let far = deadline_fee_rate(tip, Some(tip + 100), 8, &none, 5, 1_000);
        assert!(far > 8, "a replacement must pay strictly more (BIP125)");
        assert!(
            far < 20,
            "no need to sprint with 100 blocks left, got {far}"
        );

        // Inside the last couple of blocks: go to the ceiling, because a fee saved there costs
        // the whole output.
        assert_eq!(
            deadline_fee_rate(tip, Some(tip + 2), 8, &none, 5, 1_000),
            1_000
        );
        assert_eq!(deadline_fee_rate(tip, Some(tip), 8, &none, 5, 1_000), 1_000);

        // The cap is always respected.
        let huge = |_t: u16| Some(u64::MAX);
        assert_eq!(
            deadline_fee_rate(tip, Some(tip + 100), 8, &huge, 5, 1_000),
            1_000
        );

        // With no deadline the rate still climbs, on the estimate and the minimum bump.
        assert!(deadline_fee_rate(tip, None, 8, &none, 5, 1_000) > 8);
    }

    #[test]
    fn deadline_fee_rate_is_strictly_increasing_up_to_the_cap() {
        // BIP125 requires each replacement to pay more, so repeated bumps must never plateau
        // below the cap. A fixed ten bumps at +25% from a 2 sat/vB floor tops out around
        // 37 sat/vB and then stops escalating no matter how close the deadline gets; the
        // deadline-driven loop reaches the ceiling instead.
        let none = |_t: u16| None;
        let tip = 800_000;
        let mut rate = 2u64;
        let mut steps = 0;
        loop {
            let next = deadline_fee_rate(tip, Some(tip + 50), rate, &none, 2, 1_000);
            if next == rate {
                break;
            }
            assert!(next > rate, "{next} must exceed {rate}");
            rate = next;
            steps += 1;
            assert!(steps < 200, "escalation should reach the cap promptly");
        }
        assert_eq!(
            rate, 1_000,
            "escalation must reach the cap, not stall below it"
        );
    }

    #[test]
    fn estimate_spend_fee_saturates_rather_than_overflowing() {
        assert_eq!(estimate_spend_fee(u64::MAX, 150), u64::MAX);
        assert_eq!(estimate_spend_fee(10, 150), 1_500);
    }

    /// The vsize estimate has to cover the real transaction, or the effective fee rate drifts
    /// below the target exactly when it must not: a claim racing a refund window.
    #[test]
    fn spend_vsize_covers_the_real_transaction() {
        let s = setup();
        let p2wsh = ScriptBuf::from_hex(
            "0020abababababababababababababababababababababababababababababababab",
        )
        .unwrap();
        let p2tr = ScriptBuf::from_hex(
            "5120abababababababababababababababababababababababababababababababab",
        )
        .unwrap();
        for (is_claim, dest_spk) in [
            (true, dest()),
            (false, dest()),
            (true, p2wsh.clone()),
            (false, p2wsh),
            (true, p2tr.clone()),
            (false, p2tr),
        ] {
            let estimated = spend_vsize(&s.redeem, &dest_spk, is_claim);
            let tx = if is_claim {
                build_claim_tx(
                    s.outpoint,
                    VALUE,
                    &s.redeem,
                    dest_spk.clone(),
                    1000,
                    s.preimage,
                    &s.claim_sk,
                )
            } else {
                build_refund_tx(
                    s.outpoint,
                    VALUE,
                    &s.redeem,
                    dest_spk.clone(),
                    1000,
                    TIMEOUT,
                    &s.refund_sk,
                )
            }
            .unwrap();
            let actual = tx.vsize() as u64;
            assert!(
                estimated >= actual,
                "estimate {estimated} must cover the real {actual} vB \
                 (claim={is_claim}, dest={} bytes)",
                dest_spk.len()
            );
            assert!(
                estimated <= actual + 5,
                "estimate {estimated} is more than 5 vB above the real {actual}"
            );
        }
    }

    #[test]
    fn claim_and_refund_signal_rbf() {
        let s = setup();
        let claim = build_claim_tx(
            s.outpoint,
            VALUE,
            &s.redeem,
            dest(),
            1000,
            s.preimage,
            &s.claim_sk,
        )
        .unwrap();
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
        // BIP125 opt-in: sequence must be <= 0xFFFFFFFD on both branches.
        assert!(claim.input[0].sequence.is_rbf());
        assert!(refund.input[0].sequence.is_rbf());
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
