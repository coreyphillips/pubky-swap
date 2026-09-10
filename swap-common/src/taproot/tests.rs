use super::*;
use bitcoin::consensus::serialize;
use bitcoin::Txid;

const VALUE: u64 = 100_000;
const TIMEOUT: u32 = 250;
const PREIMAGE: Preimage = [3; 32];
const DIRECTIONS: [SwapDirection; 2] = [SwapDirection::Submarine, SwapDirection::Reverse];

fn secret(scalar: u8) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    SecretKey::from_slice(&bytes).unwrap()
}

fn public(scalar: u8) -> PublicKey {
    PublicKey::new(secret(scalar).public_key(&Secp256k1::new()))
}

fn contract(direction: SwapDirection) -> BoltzTaprootSwap {
    let (claim, refund) = match direction {
        SwapDirection::Submarine => (public(1), public(2)),
        SwapDirection::Reverse => (public(2), public(1)),
    };
    BoltzTaprootSwap::new(
        direction,
        &payment_hash(&PREIMAGE),
        &claim,
        &refund,
        TIMEOUT,
    )
    .unwrap()
}

fn claim_secret(direction: SwapDirection) -> SecretKey {
    secret(match direction {
        SwapDirection::Submarine => 1,
        SwapDirection::Reverse => 2,
    })
}

fn refund_secret(direction: SwapDirection) -> SecretKey {
    secret(match direction {
        SwapDirection::Submarine => 2,
        SwapDirection::Reverse => 1,
    })
}

fn outpoint() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([7; 32]),
        vout: 0,
    }
}

fn destination() -> ScriptBuf {
    ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap()
}

fn prevout(swap: &BoltzTaprootSwap, value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: swap.script_pubkey(),
    }
}

fn verify(tx: &Transaction, spent: &TxOut) -> std::result::Result<(), bitcoinconsensus::Error> {
    let outputs = [bitcoinconsensus::Utxo {
        script_pubkey: spent.script_pubkey.as_bytes().as_ptr(),
        script_pubkey_len: spent.script_pubkey.len() as u32,
        value: spent.value.to_sat() as i64,
    }];
    bitcoinconsensus::verify_with_flags(
        spent.script_pubkey.as_bytes(),
        spent.value.to_sat(),
        &serialize(tx),
        Some(&outputs),
        0,
        bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT,
    )
}

fn claim(swap: &BoltzTaprootSwap, direction: SwapDirection) -> Transaction {
    swap.claim_tx(
        outpoint(),
        VALUE,
        destination(),
        1000,
        PREIMAGE,
        &claim_secret(direction),
    )
    .unwrap()
}

fn refund(swap: &BoltzTaprootSwap, direction: SwapDirection) -> Transaction {
    swap.refund_tx(
        outpoint(),
        VALUE,
        destination(),
        1000,
        &refund_secret(direction),
    )
    .unwrap()
}

fn replace_witness_element(tx: &mut Transaction, index: usize, value: Vec<u8>) {
    let mut elements = tx.input[0].witness.to_vec();
    elements[index] = value;
    tx.input[0].witness = Witness::from_slice(&elements);
}

fn resign(swap: &BoltzTaprootSwap, tx: &mut Transaction, path: SpendPath, key: SecretKey) {
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &key);
    let signature = swap
        .sign_spend(tx, &prevout(swap, VALUE), &path, &keypair)
        .unwrap();
    tx.input[0].witness = swap.witness(&path, &signature);
}

#[test]
fn contracts_match_official_boltz_core_5_0_0_vectors() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("boltz-vectors.json")).unwrap();
    assert_eq!(fixture["version"], "5.0.0");
    for direction in DIRECTIONS {
        let expected = &fixture["cases"][direction.as_str()];
        let swap = contract(direction);
        assert_eq!(
            serde_json::to_value(swap.swap_tree()).unwrap(),
            expected["swapTree"]
        );
        assert_eq!(
            swap.spend_info.internal_key().to_string(),
            expected["internalKey"]
        );
        assert_eq!(
            swap.spend_info.merkle_root().unwrap().to_string(),
            expected["merkleRoot"]
        );
        assert_eq!(
            swap.spend_info.output_key().to_string(),
            expected["outputKey"]
        );
        assert_eq!(
            swap.address(Network::Regtest).to_string(),
            expected["address"]
        );
        assert_eq!(
            hex::encode(swap.claim_control_block()),
            expected["claimControlBlock"]
        );
        assert_eq!(
            hex::encode(swap.refund_control_block()),
            expected["refundControlBlock"]
        );
    }
}

#[test]
fn claims_and_refunds_pass_taproot_consensus() {
    for direction in DIRECTIONS {
        let swap = contract(direction);
        let claim = claim(&swap, direction);
        let refund = refund(&swap, direction);
        verify(&claim, &prevout(&swap, VALUE)).unwrap();
        verify(&refund, &prevout(&swap, VALUE)).unwrap();
        assert_eq!(claim.lock_time, LockTime::ZERO);
        assert_eq!(refund.lock_time.to_consensus_u32(), TIMEOUT);
        assert!(refund.input[0].sequence.is_rbf());
        assert_eq!(
            crate::onchain::extract_preimage(&claim, &outpoint(), &payment_hash(&PREIMAGE)),
            Some(PREIMAGE)
        );
    }
}

#[test]
fn consensus_handles_odd_and_even_key_parities() {
    let mut key_parities = std::collections::HashSet::new();
    let mut output_parities = std::collections::HashSet::new();
    for direction in DIRECTIONS {
        for scalar in 1..9 {
            let swap = BoltzTaprootSwap::new(
                direction,
                &payment_hash(&PREIMAGE),
                &public(scalar),
                &public(9),
                TIMEOUT,
            )
            .unwrap();
            key_parities.insert(public(scalar).inner.serialize()[0]);
            output_parities.insert(swap.claim_control_block()[0]);
            let claim = swap
                .claim_tx(
                    outpoint(),
                    VALUE,
                    destination(),
                    1000,
                    PREIMAGE,
                    &secret(scalar),
                )
                .unwrap();
            let refund = swap
                .refund_tx(outpoint(), VALUE, destination(), 1000, &secret(9))
                .unwrap();
            verify(&claim, &prevout(&swap, VALUE)).unwrap();
            verify(&refund, &prevout(&swap, VALUE)).unwrap();
        }
    }
    assert_eq!(key_parities.len(), 2);
    assert_eq!(output_parities.len(), 2);
}

#[test]
fn reverse_leaf_enforces_boltz_preimage_length_rule() {
    let short_preimage = [3; 31];
    let hash = bitcoin::hashes::sha256::Hash::hash(&short_preimage).to_byte_array();
    for direction in DIRECTIONS {
        let swap =
            BoltzTaprootSwap::new(direction, &hash, &public(1), &public(2), TIMEOUT).unwrap();
        let mut tx = unsigned_spend(outpoint(), VALUE - 1000, destination(), LockTime::ZERO);
        resign(
            &swap,
            &mut tx,
            SpendPath::Claim { preimage: PREIMAGE },
            secret(1),
        );
        replace_witness_element(&mut tx, 1, short_preimage.to_vec());
        assert_eq!(
            verify(&tx, &prevout(&swap, VALUE)).is_ok(),
            direction == SwapDirection::Submarine
        );
    }
}

#[test]
fn consensus_rejects_invalid_preimage_and_missing_witness() {
    for direction in DIRECTIONS {
        let swap = contract(direction);
        let mut tx = claim(&swap, direction);
        replace_witness_element(&mut tx, 1, vec![4; 32]);
        assert!(verify(&tx, &prevout(&swap, VALUE)).is_err());
        tx.input[0].witness = Witness::new();
        assert!(verify(&tx, &prevout(&swap, VALUE)).is_err());
        assert!(swap
            .claim_tx(
                outpoint(),
                VALUE,
                destination(),
                1000,
                [4; 32],
                &claim_secret(direction)
            )
            .is_err());
    }
}

#[test]
fn consensus_rejects_wrong_signing_key_for_each_path() {
    for direction in DIRECTIONS {
        let swap = contract(direction);
        for path in [SpendPath::Claim { preimage: PREIMAGE }, SpendPath::Refund] {
            let mut tx = match path {
                SpendPath::Claim { .. } => claim(&swap, direction),
                SpendPath::Refund => refund(&swap, direction),
            };
            resign(&swap, &mut tx, path, secret(8));
            assert!(verify(&tx, &prevout(&swap, VALUE)).is_err());
        }
        assert!(swap
            .claim_tx(outpoint(), VALUE, destination(), 1000, PREIMAGE, &secret(8))
            .is_err());
        assert!(swap
            .refund_tx(outpoint(), VALUE, destination(), 1000, &secret(8))
            .is_err());
    }
}

#[test]
fn consensus_commits_to_actual_funding_amount() {
    for direction in DIRECTIONS {
        let swap = contract(direction);
        for tx in [claim(&swap, direction), refund(&swap, direction)] {
            assert!(verify(&tx, &prevout(&swap, VALUE + 1)).is_err());
            assert!(verify(&tx, &prevout(&swap, VALUE - 1)).is_err());
        }
    }
}

#[test]
fn consensus_enforces_refund_locktime_type_height_and_sequence() {
    for direction in DIRECTIONS {
        let swap = contract(direction);
        for locktime in [TIMEOUT - 1, 500_000_000] {
            let mut tx = refund(&swap, direction);
            tx.lock_time = LockTime::from_consensus(locktime);
            resign(&swap, &mut tx, SpendPath::Refund, refund_secret(direction));
            assert!(verify(&tx, &prevout(&swap, VALUE)).is_err());
        }
        let mut tx = refund(&swap, direction);
        tx.input[0].sequence = Sequence::MAX;
        resign(&swap, &mut tx, SpendPath::Refund, refund_secret(direction));
        assert!(verify(&tx, &prevout(&swap, VALUE)).is_err());
        tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
        tx.lock_time = LockTime::from_consensus(TIMEOUT + 1);
        resign(&swap, &mut tx, SpendPath::Refund, refund_secret(direction));
        verify(&tx, &prevout(&swap, VALUE)).unwrap();
    }
}

#[test]
fn consensus_rejects_tampered_control_blocks() {
    for direction in DIRECTIONS {
        let swap = contract(direction);
        for original in [claim(&swap, direction), refund(&swap, direction)] {
            let index = original.input[0].witness.len() - 1;
            for offset in [0, 1, 33] {
                let mut tx = original.clone();
                let mut control = tx.input[0].witness.to_vec()[index].clone();
                control[offset] ^= 1;
                replace_witness_element(&mut tx, index, control);
                assert!(verify(&tx, &prevout(&swap, VALUE)).is_err());
            }
        }
    }
}

#[test]
fn spend_size_matches_signed_transactions_for_varied_destinations() {
    let destinations = [
        destination(),
        contract(SwapDirection::Reverse).script_pubkey(),
        ScriptBuf::from_bytes(vec![0x51; 253]),
    ];
    for direction in DIRECTIONS {
        let swap = contract(direction);
        for destination in &destinations {
            let claim_size = swap.spend_vsize(destination, true);
            let refund_size = swap.spend_vsize(destination, false);
            let claim = swap
                .claim_tx(
                    outpoint(),
                    VALUE,
                    destination.clone(),
                    claim_size * 7,
                    PREIMAGE,
                    &claim_secret(direction),
                )
                .unwrap();
            let refund = swap
                .refund_tx(
                    outpoint(),
                    VALUE,
                    destination.clone(),
                    refund_size * 7,
                    &refund_secret(direction),
                )
                .unwrap();
            assert_eq!(claim_size, claim.vsize() as u64);
            assert_eq!(refund_size, refund.vsize() as u64);
            assert!(VALUE - claim.output[0].value.to_sat() >= claim.vsize() as u64 * 7);
            assert!(VALUE - refund.output[0].value.to_sat() >= refund.vsize() as u64 * 7);
        }
    }
}

#[test]
fn spend_rejects_dust_zero_fee_and_amount_overflow() {
    let swap = contract(SwapDirection::Submarine);
    for (value, fee) in [
        (VALUE, 0),
        (VALUE, VALUE),
        (VALUE, VALUE + 1),
        (1000, 455),
        (u64::MAX, 1000),
    ] {
        assert!(swap
            .claim_tx(outpoint(), value, destination(), fee, PREIMAGE, &secret(1))
            .is_err());
        assert!(swap
            .refund_tx(outpoint(), value, destination(), fee, &secret(2))
            .is_err());
    }
}

#[test]
fn construction_and_deserialization_validate_contract_parameters() {
    let swap = contract(SwapDirection::Submarine);
    let encoded = serde_json::to_value(&swap).unwrap();
    assert_eq!(
        serde_json::from_value::<BoltzTaprootSwap>(encoded.clone()).unwrap(),
        swap
    );
    for timeout in [0, 500_000_000, u32::MAX] {
        let mut bad = encoded.clone();
        bad["timeout"] = timeout.into();
        assert!(serde_json::from_value::<BoltzTaprootSwap>(bad).is_err());
    }
    let mut bad = encoded;
    bad["claim_public_key"] = "invalid".into();
    assert!(serde_json::from_value::<BoltzTaprootSwap>(bad).is_err());
    assert!(BoltzTaprootSwap::new(
        SwapDirection::Submarine,
        &payment_hash(&PREIMAGE),
        &public(1),
        &public(1),
        TIMEOUT
    )
    .is_err());
    let mut uncompressed = public(1);
    uncompressed.compressed = false;
    assert!(BoltzTaprootSwap::new(
        SwapDirection::Submarine,
        &payment_hash(&PREIMAGE),
        &uncompressed,
        &public(2),
        TIMEOUT
    )
    .is_err());
}
