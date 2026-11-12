use super::*;
use crate::paykit_cap::Ed25519Signer;

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn provider() -> Ed25519Signer {
    Ed25519Signer::from_secret(&[7; 32])
}

fn owner() -> Ed25519Signer {
    Ed25519Signer::from_secret(&[5; 32])
}

fn key(signer: &Ed25519Signer) -> [u8; 32] {
    hex::decode(signer.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap()
}

const OWNER: &str = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
const PROVIDER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn rfq() -> Rfq {
    Rfq {
        envelope: Envelope::new("bitkit", uuid(4), 1),
        event_id: uuid(5),
        body: RfqBody {
            offer_id: uuid(1),
            dir: SwapDirection::Reverse,
            from: "btc-lightning-bolt11".into(),
            to: "btc-bitcoin-p2tr".into(),
            amount_sat: Sat(250_000),
        },
        atomicity_min: "hash".into(),
        respond_by: 1_792_482_660,
        valid_until: 1_792_483_200,
    }
}

fn quote() -> Quote {
    let mut quote = Quote {
        envelope: Envelope::new(PROVIDER_APP_ID, uuid(4), 2),
        event_id: uuid(6),
        rfq_event_id: uuid(5),
        body: QuoteBody {
            quote_id: uuid(2),
            offer_id: uuid(1),
            dir: SwapDirection::Reverse,
            amount_sat: Sat(250_000),
            service_fee_sat: Sat(725),
            onchain_fee_sat: Sat(310),
            total_sat: Sat(251_035),
            htlc_timeout_blocks: 144,
            required_confirmations: 2,
            fund_within_secs: 300,
            lock_profiles: vec![SwapScript::TaprootBoltz],
        },
        atomicity: ATOMICITY.into(),
        valid_until: 1_792_482_960,
        sig: String::new(),
    };
    quote.sig = sign(
        &provider(),
        &terms(OWNER, &rfq(), PROVIDER, &quote).hash().unwrap(),
    );
    quote
}

fn commit() -> Commit {
    let terms = terms(OWNER, &rfq(), PROVIDER, &quote());
    let mut commit = Commit {
        envelope: Envelope::new("bitkit", uuid(4), 1),
        event_id: uuid(7),
        quote_event_id: uuid(6),
        terms_hash: hex::encode(terms.hash().unwrap()),
        body: CommitBody {
            lock_profile: SwapScript::TaprootBoltz,
            payment_hash: "11".repeat(32),
            claim_pubkey: Some(format!("02{}", "22".repeat(32))),
            refund_pubkey: None,
            invoice: None,
            owner_ref: Some(format!("bitkit-swap-v4:{}", "A".repeat(43))),
        },
        quote: Some(SignedTerms {
            terms,
            sig: quote().sig,
        }),
        sig: None,
    };
    commit.sign(&owner()).unwrap();
    commit
}

fn accept() -> SwapAccept {
    SwapAccept {
        script_type: SwapScript::TaprootBoltz,
        swap_tree: None,
        quote_id: uuid(2),
        swap_id: uuid(3),
        direction: SwapDirection::Reverse,
        htlc_script_hex: String::new(),
        htlc_address: "bc1pexample".into(),
        onchain_amount_sat: 250_000,
        timeout_block_height: 800_144,
        provider_pubkey_hex: format!("03{}", "33".repeat(32)),
        invoice: Some("lnbc1hold".into()),
    }
}

fn contract() -> Contract {
    let blob = InvoiceBlob::seal([9; 32], "lnbc1hold");
    let commit = commit();
    let commit_hash = hex::encode(commit.commit_hash().unwrap());
    let body = contract_body(&accept(), Some(&blob)).unwrap();
    let sig = sign(&provider(), &contract_hash(&commit_hash, &body).unwrap());
    Contract {
        envelope: Envelope::new(PROVIDER_APP_ID, uuid(4), 2),
        event_id: uuid(8),
        commit_event_id: commit.event_id,
        commit_hash,
        body,
        sig,
        invoice_blob: Some(blob),
        lock: lock(&accept()),
    }
}

/// Fixed inputs, fixed hashes, recomputed outside Rust in `docs/CLIENT_ADAPTERS.md`. A change
/// here is a wire change.
#[test]
fn golden_vectors() {
    let terms = terms(OWNER, &rfq(), PROVIDER, &quote());
    let commit = commit();
    let contract = contract();
    let actual = [
        String::from_utf8(jcs(&terms).unwrap()).unwrap(),
        hex::encode(terms.hash().unwrap()),
        hex::encode(commit.commit_hash().unwrap()),
        hex::encode(contract.verify(&key(&provider())).unwrap()),
        quote().sig,
        commit.sig.clone().unwrap(),
    ];
    assert_eq!(actual, GOLDEN, "{actual:#?}");
}

/// The JCS terms, `terms_hash`, `commit_hash`, `contract_hash`, the quote's `sig` by secret
/// `[7; 32]` and the commit's `sig` by secret `[5; 32]`.
const GOLDEN: [&str; 6] = [
    r#"{"flow_id":"04040404-0404-0404-0404-040404040404","owner":"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy","owner_key_generation":1,"profile":"swap/1","provider":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","provider_key_generation":2,"quote":{"atomicity":"hash","body":{"amount_sat":"250000","dir":"reverse","fund_within_secs":300,"htlc_timeout_blocks":144,"lock_profiles":["taproot_boltz"],"offer_id":"01010101-0101-0101-0101-010101010101","onchain_fee_sat":"310","quote_id":"02020202-0202-0202-0202-020202020202","required_confirmations":2,"service_fee_sat":"725","total_sat":"251035"},"valid_until":1792482960},"rfq":{"atomicity_min":"hash","body":{"amount_sat":"250000","dir":"reverse","from":"btc-lightning-bolt11","offer_id":"01010101-0101-0101-0101-010101010101","to":"btc-bitcoin-p2tr"},"respond_by":1792482660,"valid_until":1792483200}}"#,
    "4c32d3578f045773722fed947b2eb96a24f8fc121849ef7f0693360296a3d09a",
    "15d9bbd6897899436832098511a005b09416382fb0f738243f50f2811d0b3ed8",
    "69bd1e0b884e7b899dcf545d7ddb03a3b4493111ba30a4e474a2a55c27719b0a",
    "88lM3ZBiyGdRaTgJJRc7Acl3-95rJRewG6VxBbvwsyDmEo71emSJ4FWh5XssLGLI6Y_K6yYu448hIRwh1eyHBg",
    "6ytH3iV_uRDey-a6GQlFnK8knILJxljX6Jc8Y0gjQP74VEGG9p6-SyrWN8IqHMdFSGyhsoR3LgMbGTMTmim2Dw",
];

/// A message survives the wire as the same closed object, and anything else is refused.
#[test]
fn messages_are_closed_and_amounts_are_strings() {
    for message in [
        Message::Rfq(rfq()),
        Message::Quote(quote()),
        Message::Commit(Box::new(commit())),
        Message::Contract(Box::new(contract())),
        Message::Status(Status {
            envelope: Envelope::new(PROVIDER_APP_ID, uuid(4), 2),
            event_id: uuid(10),
            commit_event_id: Some(uuid(6)),
            leg: 0,
            body: StatusBody {
                swap_id: uuid(8),
                state: "in_transit".into(),
                detail: "lockup_confirmed".into(),
                reference: None,
            },
        }),
    ] {
        let value = serde_json::to_value(&message).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["profile"], PROFILE);
        assert_eq!(Message::parse(value.clone()).unwrap(), message);

        let mut extra = value.clone();
        extra["request_id"] = serde_json::json!(uuid(9));
        assert!(Message::parse(extra).is_err(), "unknown envelope member");
        let mut extra = value;
        extra["body"]["direction"] = serde_json::json!("reverse");
        assert!(Message::parse(extra).is_err(), "unknown body member");
    }
    let mut value = serde_json::to_value(Message::Rfq(rfq())).unwrap();
    assert_eq!(value["body"]["amount_sat"], "250000");
    value["body"]["amount_sat"] = serde_json::json!(250_000);
    assert!(Message::parse(value.clone()).is_err(), "integer amount");
    for bad in ["", "01", "-1", "1.0", " 1", "18446744073709551616"] {
        value["body"]["amount_sat"] = serde_json::json!(bad);
        assert!(Message::parse(value.clone()).is_err(), "{bad:?}");
    }
}

/// The terms bind both identities and generations, the profile and the flow, so a quote or a
/// contract under any other is refused.
#[test]
fn signatures_are_bound_to_profile_flow_and_generation() {
    let provider_key = key(&provider());
    let commit = commit();
    let signed = commit.quote.clone().unwrap();
    signed.check(&commit, &provider_key).unwrap();
    commit.verify_owner(&key(&owner())).unwrap();

    let mut other = signed.clone();
    other.terms.profile = "swap/2".into();
    assert_eq!(
        other.check(&commit, &provider_key),
        Err(CapError::HashMismatch("terms_hash"))
    );
    for change in [
        |t: &mut Terms| t.flow_id = Uuid::from_bytes([1; 16]),
        |t: &mut Terms| t.provider_key_generation += 1,
        |t: &mut Terms| t.owner_key_generation += 1,
        |t: &mut Terms| t.owner = PROVIDER.into(),
    ] {
        let mut other = signed.clone();
        change(&mut other.terms);
        assert!(other.check(&commit, &provider_key).is_err());
    }
    // Same terms, but the commit's envelope names another flow or generation.
    let mut moved = commit.clone();
    moved.envelope.flow_id = uuid(9);
    assert!(signed.check(&moved, &provider_key).is_err());
    let mut moved = commit.clone();
    moved.envelope.key_generation = 2;
    assert!(signed.check(&moved, &provider_key).is_err());
    // The key of another generation does not verify.
    let rotated = key(&Ed25519Signer::from_secret(&[8; 32]));
    assert_eq!(signed.check(&commit, &rotated), Err(CapError::BadSignature));

    // The owner's signature covers the body, `owner_ref` included.
    let mut changed = commit.clone();
    changed.body.owner_ref = Some("other".into());
    assert!(changed.verify_owner(&key(&owner())).is_err());
    assert!(commit.verify_owner(&provider_key).is_err());

    let contract = contract();
    contract.verify(&provider_key).unwrap();
    assert_eq!(contract.open(&signed.terms).unwrap(), accept());
    let mut tampered = contract.clone();
    tampered.body.onchain_amount_sat = Sat(250_001);
    assert!(tampered.verify(&provider_key).is_err());
    assert!(contract.verify(&rotated).is_err());
    let mut swapped = contract.clone();
    swapped.invoice_blob = Some(InvoiceBlob::seal([1; 32], "lnbc1other"));
    assert!(swapped.open(&signed.terms).is_err());
}

#[test]
fn owner_ref_is_capped_at_63_characters() {
    let mut body = commit().body;
    body.owner_ref = Some("r".repeat(OWNER_REF_MAX_LEN));
    assert!(body.owner_ref_is_valid());
    body.owner_ref = Some("r".repeat(OWNER_REF_MAX_LEN + 1));
    assert!(!body.owner_ref_is_valid());
    body.owner_ref = None;
    assert!(body.owner_ref_is_valid());
}

#[test]
fn atomicity_and_edges() {
    assert!(atomicity_met("hash"));
    assert!(atomicity_met("provider_trusted"));
    assert!(!atomicity_met("quantum"));

    let offer = crate::messages::SwapOffer {
        request_id: None,
        offer_id: Uuid::nil(),
        provider_pkarr: PROVIDER.into(),
        network: crate::NetworkSpec::Bitcoin,
        directions: vec![SwapDirection::Reverse],
        min_amount_sat: 10_000,
        max_amount_sat: 1_000_000,
        base_fee_sat: 500,
        fee_ppm: 2_000,
        required_confirmations: 2,
        htlc_timeout_blocks: 144,
        lightning_node_id: None,
        valid_until_unix: 0,
        fund_within_secs: 300,
        onchain_fee_sat: 0,
        fee_rate_sat_vb: 0,
        protocol_version: crate::messages::PROTOCOL_VERSION,
        features: Vec::new(),
    };
    let mut body = rfq().body;
    assert!(is_edge(&offer, &body));
    body.to = "btc-regtest-p2tr".into();
    assert!(!is_edge(&offer, &body));
    body.to = "btc-lightning-bolt11".into();
    assert!(!is_edge(&offer, &body));
    let body = RfqBody {
        dir: SwapDirection::Submarine,
        from: "btc-bitcoin-p2wpkh".into(),
        to: "btc-lightning-bolt11".into(),
        ..rfq().body
    };
    assert!(
        !is_edge(&offer, &body),
        "the offer does not take submarine swaps"
    );
}
