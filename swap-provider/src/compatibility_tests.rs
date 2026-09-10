use super::*;
use bitcoin::ScriptBuf;
use lightning_backend::{
    DecodedInvoice, HoldInvoice, HoldInvoiceRequest, InvoiceStatus, LightningError, NodeInfo,
    PaymentResult, PaymentStatus,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use swap_common::htlc::{build_htlc_script, payment_hash};
use swap_common::taproot::BoltzTaprootSwap;

struct IntentLightning {
    store: Arc<JsonFileSwapStore>,
    swap_id: Uuid,
    created: std::sync::Mutex<Option<(HoldInvoiceRequest, HoldInvoice)>>,
    fail_after_create: AtomicBool,
    fail_lookup: AtomicBool,
    create_calls: AtomicUsize,
}

impl IntentLightning {
    fn new(store: Arc<JsonFileSwapStore>, swap_id: Uuid) -> Self {
        Self {
            store,
            swap_id,
            created: std::sync::Mutex::new(None),
            fail_after_create: AtomicBool::new(false),
            fail_lookup: AtomicBool::new(false),
            create_calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl LightningBackend for IntentLightning {
    async fn create_hold_invoice(
        &self,
        request: HoldInvoiceRequest,
    ) -> lightning_backend::Result<HoldInvoice> {
        // The external side effect must never precede its durable owner and request identity.
        let persisted = self.store.get(self.swap_id).unwrap().unwrap();
        assert!(persisted.pending_hold_invoice.is_some());
        assert!(persisted.swap_request.is_some());
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        let mut created = self.created.lock().unwrap();
        if created.is_some() {
            return Err(LightningError::Backend("duplicate payment hash".into()));
        }
        let invoice = HoldInvoice {
            bolt11: "hold-invoice".into(),
            payment_hash: request.payment_hash,
            amount_msat: request.amount_msat,
        };
        *created = Some((request, invoice.clone()));
        if self.fail_after_create.swap(false, Ordering::SeqCst) {
            return Err(LightningError::Backend(
                "response lost after invoice creation".into(),
            ));
        }
        Ok(invoice)
    }

    async fn lookup_hold_invoice(
        &self,
        request: &HoldInvoiceRequest,
    ) -> lightning_backend::Result<Option<HoldInvoice>> {
        if self.fail_lookup.load(Ordering::SeqCst) {
            return Err(LightningError::Backend("node unreachable".into()));
        }
        match self.created.lock().unwrap().as_ref() {
            Some((original, invoice)) if original == request => Ok(Some(invoice.clone())),
            Some(_) => Err(LightningError::Backend("invoice intent mismatch".into())),
            None => Ok(None),
        }
    }

    async fn node_info(&self) -> lightning_backend::Result<NodeInfo> {
        unreachable!()
    }
    async fn create_invoice(
        &self,
        _: u64,
        _: u64,
        _: &str,
    ) -> lightning_backend::Result<HoldInvoice> {
        unreachable!()
    }
    async fn invoice_status(&self, _: [u8; 32]) -> lightning_backend::Result<InvoiceStatus> {
        unreachable!()
    }
    async fn settle_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
        unreachable!()
    }
    async fn cancel_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
        unreachable!()
    }
    async fn pay_invoice(
        &self,
        _: &str,
        _: u64,
        _: Option<u32>,
    ) -> lightning_backend::Result<PaymentResult> {
        unreachable!()
    }
    async fn payment_status(&self, _: [u8; 32]) -> lightning_backend::Result<PaymentStatus> {
        unreachable!()
    }
    async fn decode_invoice(&self, _: &str) -> lightning_backend::Result<DecodedInvoice> {
        unreachable!()
    }
}

fn invoice_intent() -> SwapRecord {
    let mut record = accepted_record(SwapDirection::Reverse, SwapScript::TaprootBoltz);
    let terms = reverse_invoice_request(
        record.payment_hash().unwrap(),
        record.onchain_amount_sat,
        0,
        3600,
        TimelockParams::default(),
    )
    .unwrap();
    record.pending_hold_invoice = Some(store::PendingHoldInvoice {
        amount_msat: terms.amount_msat,
        expiry_secs: terms.expiry_secs,
        cltv_expiry_delta: terms.cltv_expiry_delta,
        memo: format!("pubky-swap reverse {}", record.swap_id),
    });
    record.invoice.clear();
    record.swap_accept.as_mut().unwrap().invoice = None;
    record
}

#[tokio::test]
async fn invoice_creation_recovers_after_a_lost_rpc_response_without_a_second_invoice() {
    let directory = std::env::temp_dir().join(format!("swap-invoice-intent-{}", Uuid::new_v4()));
    let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
    let record = invoice_intent();
    let ln = IntentLightning::new(store.clone(), record.swap_id);
    // No RPC is allowed unless its complete intent is already durable.
    assert!(
        complete_invoice_intent(&ln, store.as_ref(), record.swap_id, false)
            .await
            .is_err()
    );
    assert_eq!(ln.create_calls.load(Ordering::SeqCst), 0);
    store.put(&record).unwrap();
    ln.fail_after_create.store(true, Ordering::SeqCst);
    assert!(
        complete_invoice_intent(&ln, store.as_ref(), record.swap_id, false)
            .await
            .is_err()
    );
    assert_eq!(ln.create_calls.load(Ordering::SeqCst), 1);
    assert!(store
        .get(record.swap_id)
        .unwrap()
        .unwrap()
        .pending_hold_invoice
        .is_some());
    let request = SwapStatusRequest {
        request_id: Some(Uuid::new_v4()),
        swap_id: Some(record.swap_id),
        quote_id: None,
    };
    let pending = status_snapshot(store.as_ref(), "owner", &request).unwrap_err();
    assert!(matches!(
        pending.downcast_ref::<SwapLookupError>(),
        Some(SwapLookupError::Pending)
    ));
    assert!(
        ensure_reverse_hash_available(store.as_ref(), &record.payment_hash().unwrap()).is_err()
    );
    assert!(reverse_swap_from_record(&record, TimelockParams::default()).is_err());

    let restarted = JsonFileSwapStore::new(&directory).unwrap();
    let completed = complete_invoice_intent(&ln, &restarted, record.swap_id, true)
        .await
        .unwrap();
    assert_eq!(ln.create_calls.load(Ordering::SeqCst), 1);
    assert!(completed.pending_hold_invoice.is_none());
    assert_eq!(
        completed.swap_accept.as_ref().unwrap().invoice.as_deref(),
        Some("hold-invoice")
    );
    assert!(reverse_swap_from_record(&completed, TimelockParams::default()).is_ok());
    assert_eq!(
        replay_record(&restarted, "owner", record.swap_request.as_ref().unwrap())
            .unwrap()
            .unwrap()
            .swap_accept,
        completed.swap_accept
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn invoice_recovery_requires_definite_absence_before_creating() {
    let directory =
        std::env::temp_dir().join(format!("swap-invoice-before-rpc-{}", Uuid::new_v4()));
    let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
    let record = invoice_intent();
    store.put(&record).unwrap();
    let ln = IntentLightning::new(store.clone(), record.swap_id);
    ln.fail_lookup.store(true, Ordering::SeqCst);
    assert!(
        complete_invoice_intent(&ln, store.as_ref(), record.swap_id, true)
            .await
            .is_err()
    );
    assert_eq!(ln.create_calls.load(Ordering::SeqCst), 0);
    ln.fail_lookup.store(false, Ordering::SeqCst);
    complete_invoice_intent(&ln, store.as_ref(), record.swap_id, true)
        .await
        .unwrap();
    assert_eq!(ln.create_calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn an_unreadable_record_is_never_reported_as_a_missing_quote() {
    let directory = std::env::temp_dir().join(format!("swap-corrupt-record-{}", Uuid::new_v4()));
    let store = JsonFileSwapStore::new(&directory).unwrap();
    std::fs::write(directory.join("damaged.json"), "interrupted write").unwrap();
    let record = accepted_record(SwapDirection::Reverse, SwapScript::TaprootBoltz);
    let request = record.swap_request.as_ref().unwrap();
    let query = SwapStatusRequest {
        request_id: None,
        swap_id: None,
        quote_id: Some(request.quote_id),
    };
    let error = status_snapshot(&store, "owner", &query).unwrap_err();
    assert!(error.downcast_ref::<SwapLookupError>().is_none());
    assert!(replay_record(&store, "owner", request).is_err());
    assert!(ensure_reverse_hash_available(&store, &record.payment_hash().unwrap()).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn pending_retries_obey_exposure_limits_without_counting_as_new_hourly_starts() {
    let limits = risk::RiskLimits {
        max_concurrent_swaps: 1,
        max_concurrent_per_peer: 1,
        max_total_exposure_sat: 100_000,
        max_exposure_per_peer_sat: 100_000,
        min_onchain_reserve_sat: 0,
        max_new_swaps_per_peer_per_hour: 1,
    };
    let manager = risk::RiskManager::new(limits);
    let first = Uuid::new_v4();
    drop(manager.reserve("owner", first, 100_000).unwrap());
    let retry = manager.reserve_pending("owner", first, 100_000).unwrap();
    assert!(manager.reserve_pending("owner", Uuid::new_v4(), 1).is_err());
    assert!(manager.reserve_pending("other", Uuid::new_v4(), 1).is_err());
    assert_eq!(manager.committed_sat(), 100_000);
    assert_eq!(manager.in_flight(), 1);
    assert_eq!(manager.per_peer()[0].starts_this_hour, 1);
    drop(retry);
    assert!(manager.reserve_pending("owner", first, 100_001).is_err());
    assert!(manager.reserve_pending("owner", first, 100_000).is_ok());
}

fn accepted_record(direction: SwapDirection, script_type: SwapScript) -> SwapRecord {
    let secp = Secp256k1::new();
    let (claim_key, claim) = swap_common::random_keypair(&secp);
    let (refund_key, refund) = swap_common::random_keypair(&secp);
    let hash = payment_hash(&[9; 32]);
    let request = SwapRequest {
        script_type,
        quote_id: Uuid::new_v4(),
        client_pkarr: "owner".into(),
        direction,
        payment_hash_hex: hex::encode(hash),
        client_claim_pubkey_hex: Some(hex::encode(claim.to_bytes())),
        client_refund_pubkey_hex: Some(hex::encode(refund.to_bytes())),
        invoice: (direction == SwapDirection::Submarine).then(|| "invoice".into()),
    };
    let taproot = (script_type == SwapScript::TaprootBoltz)
        .then(|| BoltzTaprootSwap::new(direction, &hash, &claim, &refund, 800_144).unwrap());
    let script = if taproot.is_some() {
        ScriptBuf::new()
    } else {
        build_htlc_script(&hash, &claim, &refund, 800_144)
    };
    let address = taproot.as_ref().map_or_else(
        || htlc_p2wsh_address(&script, Network::Regtest),
        |contract| contract.address(Network::Regtest),
    );
    let (provider_key, provider_pubkey) = match direction {
        SwapDirection::Submarine => (claim_key, claim),
        SwapDirection::Reverse => (refund_key, refund),
    };
    let swap_id = Uuid::new_v4();
    let accept = SwapAccept {
        script_type,
        swap_tree: taproot.as_ref().map(BoltzTaprootSwap::swap_tree),
        quote_id: request.quote_id,
        swap_id,
        direction,
        htlc_script_hex: hex::encode(script.as_bytes()),
        htlc_address: address.to_string(),
        onchain_amount_sat: 100_000,
        timeout_block_height: 800_144,
        provider_pubkey_hex: hex::encode(provider_pubkey.to_bytes()),
        invoice: (direction == SwapDirection::Reverse).then(|| "hold-invoice".into()),
    };
    SwapRecord {
        swap_id,
        swap_request: Some(request),
        swap_accept: Some(accept),
        taproot,
        peer: "owner".into(),
        direction,
        network: NetworkSpec::Regtest,
        payment_hash_hex: hex::encode(hash),
        onchain_amount_sat: 100_000,
        fee_rate_sat_vb: 2,
        htlc_script_hex: hex::encode(script.as_bytes()),
        timeout_height: 800_144,
        secret_key_hex: hex::encode(provider_key.secret_bytes()),
        invoice: match direction {
            SwapDirection::Reverse => "hold-invoice".into(),
            SwapDirection::Submarine => "invoice".into(),
        },
        required_confirmations: 2,
        ..SwapRecord::new_progress()
    }
}

#[test]
fn creation_replay_survives_restart_and_rejects_changed_requests() {
    let directory = std::env::temp_dir().join(format!("swap-replay-{}", Uuid::new_v4()));
    let record = accepted_record(SwapDirection::Reverse, SwapScript::TaprootBoltz);
    let request = record.swap_request.as_ref().unwrap();
    let expected = serde_json::to_value(&record.swap_accept).unwrap();
    JsonFileSwapStore::new(&directory)
        .unwrap()
        .put(&record)
        .unwrap();

    // A fresh store instance has none of the provider's in-memory quotes.
    let restarted = JsonFileSwapStore::new(&directory).unwrap();
    let replay = replay_record(&restarted, "owner", request)
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(&replay.swap_accept).unwrap(), expected);
    assert!(replay_record(&restarted, "other", request).is_err());
    let mut changed = request.clone();
    changed.payment_hash_hex = hex::encode([4; 32]);
    assert!(replay_record(&restarted, "owner", &changed).is_err());
    changed = request.clone();
    changed.client_claim_pubkey_hex = changed.client_refund_pubkey_hex.clone();
    assert!(replay_record(&restarted, "owner", &changed).is_err());
    changed = request.clone();
    changed.script_type = SwapScript::P2wsh;
    assert!(replay_record(&restarted, "owner", &changed).is_err());

    let mut completed = record.clone();
    completed.state = SwapState::Claimed;
    restarted.mark_terminal(&completed).unwrap();
    let replay = replay_record(&restarted, "owner", request)
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(&replay.swap_accept).unwrap(), expected);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn status_recovery_is_correlated_owner_only_and_contains_no_secrets() {
    let directory = std::env::temp_dir().join(format!("swap-status-{}", Uuid::new_v4()));
    let store = JsonFileSwapStore::new(&directory).unwrap();
    let mut record = accepted_record(SwapDirection::Submarine, SwapScript::TaprootBoltz);
    record.preimage_hex = Some(hex::encode([7; 32]));
    store.put(&record).unwrap();
    let request = SwapStatusRequest {
        request_id: Some(Uuid::new_v4()),
        swap_id: Some(record.swap_id),
        quote_id: None,
    };
    let snapshot = status_snapshot(&store, "owner", &request).unwrap();
    assert_eq!(snapshot.request_id, request.request_id);
    assert_eq!(snapshot.required_confirmations, 2);
    assert_eq!(snapshot.accept.swap_id, record.swap_id);
    let public_json = serde_json::to_string(&snapshot).unwrap();
    for secret in [
        "secret_key_hex",
        "preimage_hex",
        &record.secret_key_hex,
        record.preimage_hex.as_deref().unwrap(),
    ] {
        assert!(!public_json.contains(secret));
    }
    assert!(status_snapshot(&store, "other", &request).is_err());
    let by_quote = SwapStatusRequest {
        swap_id: None,
        quote_id: Some(record.swap_request.as_ref().unwrap().quote_id),
        ..request.clone()
    };
    assert_eq!(
        status_snapshot(&store, "owner", &by_quote)
            .unwrap()
            .accept
            .swap_id,
        record.swap_id
    );
    assert!(status_snapshot(&store, "other", &by_quote).is_err());
    let ambiguous = SwapStatusRequest {
        swap_id: request.swap_id,
        ..by_quote
    };
    assert!(status_snapshot(&store, "owner", &ambiguous).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn recovery_reconstructs_each_contract_and_its_provider_branch() {
    for script_type in [SwapScript::P2wsh, SwapScript::TaprootBoltz] {
        for direction in [SwapDirection::Submarine, SwapDirection::Reverse] {
            let original = accepted_record(direction, script_type);
            let record: SwapRecord =
                serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
            let expected = record.htlc_spk().unwrap();
            match direction {
                SwapDirection::Submarine => {
                    let swap =
                        submarine_swap_from_record(&record, TimelockParams::default()).unwrap();
                    assert_eq!(swap.htlc_spk, expected);
                    assert_eq!(swap.claim_key, record.secret_key().unwrap());
                    assert_eq!(
                        swap.taproot.is_some(),
                        script_type == SwapScript::TaprootBoltz
                    );
                }
                SwapDirection::Reverse => {
                    let swap =
                        reverse_swap_from_record(&record, TimelockParams::default()).unwrap();
                    assert_eq!(swap.htlc_spk, expected);
                    assert_eq!(swap.refund_key, record.secret_key().unwrap());
                    assert_eq!(
                        swap.taproot.is_some(),
                        script_type == SwapScript::TaprootBoltz
                    );
                }
            }
        }
    }
}

#[test]
fn legacy_creation_messages_default_to_p2wsh() {
    let record = accepted_record(SwapDirection::Reverse, SwapScript::P2wsh);
    let mut request = serde_json::to_value(record.swap_request.unwrap()).unwrap();
    request.as_object_mut().unwrap().remove("script_type");
    let request: SwapRequest = serde_json::from_value(request).unwrap();
    assert_eq!(request.script_type, SwapScript::P2wsh);

    let mut accept = serde_json::to_value(record.swap_accept.unwrap()).unwrap();
    accept.as_object_mut().unwrap().remove("script_type");
    accept.as_object_mut().unwrap().remove("swap_tree");
    let accept: SwapAccept = serde_json::from_value(accept).unwrap();
    assert_eq!(accept.script_type, SwapScript::P2wsh);
    assert!(accept.swap_tree.is_none());
}

#[test]
fn recovery_rejects_disagreement_between_record_and_accepted_taproot_contract() {
    let record = accepted_record(SwapDirection::Reverse, SwapScript::TaprootBoltz);
    assert!(validate_persisted_contract(&record).is_ok());
    let mut changed = record.clone();
    changed.timeout_height += 1;
    assert!(validate_persisted_contract(&changed).is_err());
    changed = record.clone();
    changed.payment_hash_hex = hex::encode([4; 32]);
    assert!(validate_persisted_contract(&changed).is_err());
    changed = record.clone();
    changed.secret_key_hex = hex::encode([3; 32]);
    assert!(validate_persisted_contract(&changed).is_err());
    changed = record.clone();
    changed.swap_accept.as_mut().unwrap().htlc_address = "different".into();
    assert!(validate_persisted_contract(&changed).is_err());
    changed = record;
    changed.taproot = None;
    assert!(validate_persisted_contract(&changed).is_err());
}

#[test]
fn negotiation_only_providers_do_not_advertise_execution_capabilities() {
    let config = ProviderConfig::default();
    let idle = build_offer(&config, "provider", Network::Regtest, None, 2, false).unwrap();
    assert!(idle.features.is_empty());
    let executable = build_offer(&config, "provider", Network::Regtest, None, 2, true).unwrap();
    assert!(executable
        .features
        .iter()
        .any(|feature| feature == "boltz-taproot-v1"));
    assert!(executable
        .features
        .iter()
        .any(|feature| feature == "swap-status-v1"));
}
