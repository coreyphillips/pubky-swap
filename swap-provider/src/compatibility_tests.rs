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
        // A real lookup is an RPC, so anything else waiting on this swap is polled while it is in
        // flight. That window is where a concurrent replay used to slip through.
        tokio::task::yield_now().await;
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
    let pending = status_snapshot(store.as_ref(), "owner", None, &request).unwrap_err();
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
        replay_record(
            &restarted,
            "owner",
            None,
            record.swap_request.as_ref().unwrap()
        )
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

/// Two sessions replaying one `SwapRequest` used to admit the same swap twice.
///
/// Session requests are handled in their own tasks. Both handlers found the invoice intent
/// pending, both completed it against a backend that answers the second lookup with the invoice
/// the first one registered, and both spawned a driver over one record. Each driver keeps its own
/// copy of that record, so neither sees the other's funding marker and both can fund the HTLC.
/// The second reservation also overwrote the first, so releasing both left half the exposure
/// committed for the life of the process.
#[tokio::test]
async fn concurrent_replays_admit_a_pending_swap_once() {
    let directory = std::env::temp_dir().join(format!("swap-replay-race-{}", Uuid::new_v4()));
    let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
    let record = invoice_intent();
    store.put(&record).unwrap();
    let ln = IntentLightning::new(store.clone(), record.swap_id);
    // The backend registered the invoice and then lost the response: the state a replay exists to
    // recover, and the one both replays would recover from.
    ln.fail_after_create.store(true, Ordering::SeqCst);
    assert!(
        complete_invoice_intent(&ln, store.as_ref(), record.swap_id, false)
            .await
            .is_err()
    );

    let risk = risk::RiskManager::new(risk::RiskLimits::default());
    let admissions = AdmissionLocks::default();
    let reserve = |pending: SwapRecord| {
        let risk = risk.clone();
        async move {
            risk.reserve_pending(&pending.peer, pending.swap_id, pending.onchain_amount_sat)
                .map_err(|reason| anyhow!("{reason}"))
        }
    };
    let replay =
        || recover_pending_admission(&admissions, store.as_ref(), &ln, record.swap_id, reserve);
    let (first, second) = tokio::join!(replay(), replay());

    let (first, first_reservation) = first.unwrap();
    let (second, second_reservation) = second.unwrap();
    assert_eq!(
        [&first_reservation, &second_reservation]
            .iter()
            .filter(|reservation| reservation.is_some())
            .count(),
        1,
        "only one replay may own the swap, and only its owner starts a driver for it"
    );
    assert_eq!(
        ln.create_calls.load(Ordering::SeqCst),
        1,
        "the recovered invoice is the one already registered"
    );
    // Both replies describe the same admitted swap, whichever of them did the work.
    assert!(first.pending_hold_invoice.is_none() && second.pending_hold_invoice.is_none());
    assert_eq!(
        first.swap_accept.as_ref().unwrap().invoice.as_deref(),
        Some("hold-invoice")
    );
    assert_eq!(first.swap_accept, second.swap_accept);

    assert_eq!(risk.in_flight(), 1);
    assert_eq!(risk.committed_sat(), record.onchain_amount_sat);
    drop((first_reservation, second_reservation));
    assert_eq!(risk.in_flight(), 0);
    assert_eq!(
        risk.committed_sat(),
        0,
        "the finished swap gives back everything it committed"
    );
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
    let error = status_snapshot(&store, "owner", None, &query).unwrap_err();
    assert!(error.downcast_ref::<SwapLookupError>().is_none());
    assert!(replay_record(&store, "owner", None, request).is_err());
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
        owner_ref: None,
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
    let replay = replay_record(&restarted, "owner", None, request)
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(&replay.swap_accept).unwrap(), expected);
    assert!(replay_record(&restarted, "other", None, request).is_err());
    let mut changed = request.clone();
    changed.payment_hash_hex = hex::encode([4; 32]);
    assert!(replay_record(&restarted, "owner", None, &changed).is_err());
    changed = request.clone();
    changed.client_claim_pubkey_hex = changed.client_refund_pubkey_hex.clone();
    assert!(replay_record(&restarted, "owner", None, &changed).is_err());
    changed = request.clone();
    changed.script_type = SwapScript::P2wsh;
    assert!(replay_record(&restarted, "owner", None, &changed).is_err());

    let mut completed = record.clone();
    completed.state = SwapState::Claimed;
    restarted.mark_terminal(&completed).unwrap();
    let replay = replay_record(&restarted, "owner", None, request)
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(&replay.swap_accept).unwrap(), expected);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn status_recovery_is_correlated_owner_only_and_contains_no_secrets() {
    let directory = std::env::temp_dir().join(format!("swap-status-{}", Uuid::new_v4()));
    let store = JsonFileSwapStore::new(&directory).unwrap();
    let mut record = accepted_record(SwapDirection::Reverse, SwapScript::TaprootBoltz);
    record.preimage_hex = Some(hex::encode([7; 32]));
    let claim_txid = "cc".repeat(32);
    record.claim_observed_txid_hex = Some(claim_txid.clone());
    store.put(&record).unwrap();
    let request = SwapStatusRequest {
        request_id: Some(Uuid::new_v4()),
        swap_id: Some(record.swap_id),
        quote_id: None,
    };
    let snapshot = status_snapshot(&store, "owner", None, &request).unwrap();
    assert_eq!(snapshot.request_id, request.request_id);
    assert_eq!(snapshot.required_confirmations, 2);
    assert_eq!(snapshot.accept.swap_id, record.swap_id);
    assert_eq!(snapshot.claim_observed_txid_hex.as_ref(), Some(&claim_txid));
    let public_json = serde_json::to_string(&snapshot).unwrap();
    assert!(public_json.contains(&claim_txid));
    for secret in [
        "secret_key_hex",
        "preimage_hex",
        &record.secret_key_hex,
        record.preimage_hex.as_deref().unwrap(),
    ] {
        assert!(!public_json.contains(secret));
    }
    assert!(status_snapshot(&store, "other", None, &request).is_err());
    let by_quote = SwapStatusRequest {
        swap_id: None,
        quote_id: Some(record.swap_request.as_ref().unwrap().quote_id),
        ..request.clone()
    };
    assert_eq!(
        status_snapshot(&store, "owner", None, &by_quote)
            .unwrap()
            .accept
            .swap_id,
        record.swap_id
    );
    assert!(status_snapshot(&store, "other", None, &by_quote).is_err());
    let ambiguous = SwapStatusRequest {
        swap_id: request.swap_id,
        ..by_quote
    };
    assert!(status_snapshot(&store, "owner", None, &ambiguous).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn session_recovery_requires_the_original_account_and_transport_key() {
    let directory = std::env::temp_dir().join(format!("session-status-{}", Uuid::new_v4()));
    let store = JsonFileSwapStore::new(&directory).unwrap();
    let mut record = accepted_record(SwapDirection::Submarine, SwapScript::TaprootBoltz);
    record.peer_account = Some("ring-account".into());
    record.peer_authorization_scope = Some("scope".into());
    store.put(&record).unwrap();
    let query = SwapStatusRequest {
        request_id: Some(Uuid::new_v4()),
        swap_id: Some(record.swap_id),
        quote_id: None,
    };
    let request = record.swap_request.as_ref().unwrap();
    assert!(status_snapshot(&store, "owner", Some(("ring-account", "scope")), &query).is_ok());
    assert!(
        replay_record(&store, "owner", Some(("ring-account", "scope")), request)
            .unwrap()
            .is_some()
    );
    for (peer, account) in [
        ("other", Some(("ring-account", "scope"))),
        ("owner", Some(("other-account", "scope"))),
        ("owner", None),
        ("owner", Some(("ring-account", "other-scope"))),
    ] {
        assert!(status_snapshot(&store, peer, account, &query).is_err());
        assert!(replay_record(&store, peer, account, request).is_err());
    }
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

    // The script and address follow from the rest, so an acceptance may leave them out.
    let mut compact = serde_json::to_value(&accept).unwrap();
    compact.as_object_mut().unwrap().remove("htlc_script_hex");
    compact.as_object_mut().unwrap().remove("htlc_address");
    let compact: SwapAccept = serde_json::from_value(compact).unwrap();
    assert!(compact.htlc_script_hex.is_empty());
    assert!(compact.htlc_address.is_empty());
    assert_eq!(compact.provider_pubkey_hex, accept.provider_pubkey_hex);
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
    assert!(executable
        .features
        .iter()
        .any(|feature| feature == "dm-retention-v1"));
    assert!(executable
        .features
        .iter()
        .any(|feature| feature == SWAP_LIST_FEATURE));
}

/// #107: retention is a promise about DMs, so a provider without a homeserver does not make it.
/// Everything else it can do is still advertised.
#[test]
fn a_provider_without_a_homeserver_does_not_advertise_dm_retention() {
    let config = ProviderConfig {
        homeserver: false,
        ..Default::default()
    };
    let offer = build_offer(&config, "provider", Network::Regtest, None, 2, true).unwrap();
    assert!(!offer.features.iter().any(|f| f == "dm-retention-v1"));
    assert!(offer.features.iter().any(|f| f == "swap-status-v1"));
    assert_eq!(
        offer.features.iter().any(|f| f == "direct-rpc-v1"),
        cfg!(feature = "iroh")
    );
}

/// #102: the signed kinds ride `direct/1`, so they are advertised exactly when it is.
#[test]
fn paykit_cap_is_advertised_with_direct_requests() {
    for rendezvous_iroh in [true, false] {
        let config = ProviderConfig {
            rendezvous_iroh,
            ..Default::default()
        };
        let offer = build_offer(&config, "provider", Network::Regtest, None, 2, true).unwrap();
        let has = |feature: &str| offer.features.iter().any(|f| f == feature);
        assert_eq!(has(PAYKIT_CAP_FEATURE), has("direct-rpc-v1"));
        assert_eq!(
            has(PAYKIT_CAP_FEATURE),
            cfg!(feature = "iroh") && rendezvous_iroh
        );
    }
}

#[test]
fn offers_carry_the_configured_fund_within() {
    let config = ProviderConfig {
        fund_within_secs: 120,
        ..Default::default()
    };
    for capable in [false, true] {
        let offer = build_offer(&config, "provider", Network::Regtest, None, 2, capable).unwrap();
        assert_eq!(offer.fund_within_secs, 120);
    }
}

#[cfg(feature = "iroh")]
mod direct_requests {
    use super::*;
    use pubky_transport::p2p::DirectRpc;

    fn context(store: Arc<JsonFileSwapStore>, swap_id: Uuid) -> ExecCtx {
        let config = ProviderConfig::default();
        let transport = Transport::unsigned([40; 32]).unwrap();
        ExecCtx {
            transport: Arc::new(ReplyTransport::direct(transport)),
            ln: Arc::new(IntentLightning::new(store.clone(), swap_id)),
            chain: None,
            wallet: None,
            network: Network::Regtest,
            required_confirmations: config.required_confirmations,
            timelock: timelock_params(&config),
            onchain_fee_rate_sat_vb: 2,
            invoice_expiry_secs: config.invoice_expiry_secs,
            max_routing_fee_msat: config.max_routing_fee_msat,
            quote_ttl_secs: config.quote_ttl_secs,
            access_policy_file: None,
            quotes: Arc::new(Mutex::new(QuoteBook::default())),
            store,
            risk: risk::RiskManager::new(risk_limits(&config)),
            admissions: Arc::new(AdmissionLocks::default()),
            min_onchain_reserve_sat: 0,
            // Nothing new may start: every reply below comes from what is already persisted.
            capable: false,
            homeserver: true,
            wake: Arc::new(crate::wake::Waker::new(&[])),
            cap: Arc::new(crate::cap_adapter::CapState::ephemeral()),
        }
    }

    /// A Lightning node that issues a hold invoice for any request and reports it open, so a
    /// creation completes and its driver then waits for a payment that never comes.
    struct OpenInvoiceLightning;

    #[async_trait::async_trait]
    impl LightningBackend for OpenInvoiceLightning {
        async fn node_info(&self) -> lightning_backend::Result<NodeInfo> {
            unreachable!()
        }
        async fn create_hold_invoice(
            &self,
            request: HoldInvoiceRequest,
        ) -> lightning_backend::Result<HoldInvoice> {
            Ok(HoldInvoice {
                bolt11: "hold-invoice".into(),
                payment_hash: request.payment_hash,
                amount_msat: request.amount_msat,
            })
        }
        async fn lookup_hold_invoice(
            &self,
            _: &HoldInvoiceRequest,
        ) -> lightning_backend::Result<Option<HoldInvoice>> {
            Ok(None)
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
            Ok(InvoiceStatus {
                state: lightning_backend::InvoiceState::Open,
                amount_paid_msat: 0,
                htlcs: Vec::new(),
            })
        }
        async fn settle_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            unreachable!()
        }
        async fn cancel_hold_invoice(&self, _: [u8; 32]) -> lightning_backend::Result<()> {
            Ok(())
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

    fn offer() -> SharedOffer {
        let offer = build_offer(
            &ProviderConfig::default(),
            &pubky_transport::identity_from_secret(&[40; 32]),
            Network::Regtest,
            None,
            2,
            true,
        )
        .unwrap();
        Arc::new(RwLock::new(Some(offer)))
    }

    /// Send one request as `remote_key` would arrive over the direct protocol.
    async fn ask(ctx: &ExecCtx, remote_key: &str, message: SwapMessage) -> Option<SwapMessage> {
        ask_with(ctx, offer(), remote_key, message).await
    }

    async fn ask_with(
        ctx: &ExecCtx,
        offer: SharedOffer,
        remote_key: &str,
        message: SwapMessage,
    ) -> Option<SwapMessage> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let request = DirectRpc {
            remote_key: remote_key.into(),
            message: serde_json::to_value(message).unwrap(),
            reply,
        };
        handle_direct_request(ctx.clone(), offer, request).await;
        let bytes = answer.await.ok()?;
        Some(serde_json::from_slice(&bytes).unwrap())
    }

    /// The refusal a request got, which must carry a code this build knows.
    fn refusal(reply: Option<SwapMessage>) -> (RejectCode, Reject) {
        match reply {
            Some(SwapMessage::Reject(reject)) => {
                let code = reject.code().expect("every refusal carries a known code");
                (code, reject)
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A provider that can start swaps. Each start below is refused before it needs anything
    /// past the chain watcher.
    fn executing(ctx: ExecCtx) -> ExecCtx {
        ExecCtx {
            chain: Some(Arc::new(swap_common::chain::mock::MockChain::new())),
            capable: true,
            ..ctx
        }
    }

    fn quote_request(client: &str, direction: SwapDirection, amount_sat: u64) -> QuoteRequest {
        QuoteRequest {
            request_id: Some(Uuid::new_v4()),
            offer_id: Uuid::nil(),
            client_pkarr: client.into(),
            direction,
            amount_sat,
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        }
    }

    fn owned_record(owner: &str) -> SwapRecord {
        let mut record = accepted_record(SwapDirection::Reverse, SwapScript::TaprootBoltz);
        record.peer = owner.into();
        record.swap_request.as_mut().unwrap().client_pkarr = owner.into();
        record
    }

    #[tokio::test]
    async fn a_creation_made_over_dms_is_recovered_over_a_direct_request_after_restart() {
        let directory = std::env::temp_dir().join(format!("direct-replay-{}", Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[41; 32]);
        let record = owned_record(&owner);
        let request = record.swap_request.clone().unwrap();
        JsonFileSwapStore::new(&directory)
            .unwrap()
            .put(&record)
            .unwrap();

        // A provider that restarted: a fresh store and no in-memory quotes.
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let mut ctx = context(store.clone(), record.swap_id);
        // Policy failures must not strand a persisted swap or break authenticated recovery.
        ctx.access_policy_file = Some(directory.join("missing-policy.json").display().to_string());
        let replay = ask(&ctx, &owner, SwapMessage::SwapRequest(request.clone())).await;
        let Some(SwapMessage::SwapAccept(accept)) = replay else {
            panic!("expected the original acceptance, got {replay:?}");
        };
        assert_eq!(
            serde_json::to_value(&accept).unwrap(),
            serde_json::to_value(&record.swap_accept).unwrap()
        );
        // Replaying created nothing.
        assert_eq!(store.load_all_checked().unwrap().len(), 1);

        let status = SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: None,
            quote_id: Some(request.quote_id),
        };
        let reply = ask(&ctx, &owner, SwapMessage::SwapStatusRequest(status.clone())).await;
        let Some(SwapMessage::SwapStatusSnapshot(snapshot)) = reply else {
            panic!("expected a status snapshot, got {reply:?}");
        };
        assert_eq!(snapshot.request_id, status.request_id);
        assert_eq!(snapshot.accept.swap_id, record.swap_id);

        // Another root key learns nothing about it, even when it names the owner in the request.
        let stranger = pubky_transport::identity_from_secret(&[42; 32]);
        let reply = ask(&ctx, &stranger, SwapMessage::SwapStatusRequest(status)).await;
        assert!(
            matches!(&reply, Some(SwapMessage::Reject(r)) if r.code.as_deref() == Some("not_found")),
            "{reply:?}"
        );
        let reply = ask(&ctx, &stranger, SwapMessage::SwapRequest(request)).await;
        assert!(matches!(reply, Some(SwapMessage::Reject(_))), "{reply:?}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// One `paykit-cap.*` request over the direct protocol, and its raw reply.
    async fn ask_cap(
        ctx: &ExecCtx,
        remote_key: &str,
        message: &swap_common::paykit_cap::CapMessage,
    ) -> Vec<u8> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let request = DirectRpc {
            remote_key: remote_key.into(),
            message: serde_json::to_value(message).unwrap(),
            reply,
        };
        handle_direct_request(ctx.clone(), offer(), request).await;
        answer.await.unwrap()
    }

    /// #102: a replayed commit gets the contract first signed, byte for byte, across a restart,
    /// and `status_request` returns the same stored contract.
    #[tokio::test]
    async fn a_replayed_commit_gets_the_stored_signed_contract_after_restart() {
        use swap_common::paykit_cap::*;
        let directory = std::env::temp_dir().join(format!("cap-replay-{}", Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[41; 32]);
        let record = owned_record(&owner);
        let request = record.swap_request.clone().unwrap();
        JsonFileSwapStore::new(&directory)
            .unwrap()
            .put(&record)
            .unwrap();
        let signer = Arc::new(Ed25519Signer::from_secret(&[40; 32]));
        let provider = |store| ExecCtx {
            cap: Arc::new(crate::cap_adapter::CapState::new(
                signer.clone(),
                pubky_transport::identity_from_secret(&[40; 32]),
            )),
            ..context(store, record.swap_id)
        };
        let commit = CapMessage::Commit(Commit {
            terms_hash: "ab".repeat(32),
            commit: CommitBody::from_request(&request),
            quote: None,
        });

        let ctx = provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let first = ask_cap(&ctx, &owner, &commit).await;
        let CapMessage::Contract(contract) = serde_json::from_slice(&first).unwrap() else {
            panic!("expected a contract: {}", String::from_utf8_lossy(&first));
        };
        contract.signed.verify().unwrap();
        assert_eq!(
            contract.open().unwrap(),
            record.swap_accept.clone().unwrap()
        );
        assert_eq!(ask_cap(&ctx, &owner, &commit).await, first);
        // The driver writes whole records from a snapshot taken before the contract was signed.
        ctx.store.put(&record).unwrap();

        // A restarted provider: a fresh store handle and no terms in memory.
        let ctx = provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let stored = ctx.store.get(record.swap_id).unwrap().unwrap().cap_contract;
        assert_eq!(stored.as_ref(), Some(&contract));
        assert_eq!(ask_cap(&ctx, &owner, &commit).await, first);

        let status = CapMessage::StatusRequest(SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: None,
            quote_id: Some(request.quote_id),
        });
        let reply = ask_cap(&ctx, &owner, &status).await;
        let CapMessage::Status(status) = serde_json::from_slice(&reply).unwrap() else {
            panic!("expected a status: {}", String::from_utf8_lossy(&reply));
        };
        assert_eq!(status.contract.as_ref(), Some(&contract));
        assert_eq!(status.state, "created");
        assert_eq!(status.snapshot.unwrap().accept.invoice, None);

        // The sender is the owner, whatever the body says: a stranger replaying the same commit
        // gets nothing signed.
        let stranger = pubky_transport::identity_from_secret(&[42; 32]);
        let reply = ask_cap(&ctx, &stranger, &commit).await;
        assert!(matches!(
            serde_json::from_slice(&reply).unwrap(),
            CapMessage::Refusal(_)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// An rfq gets a quote signed over the rfq it answered, and a commit naming other terms for
    /// that quote is refused before the engine sees it.
    #[tokio::test]
    async fn an_rfq_gets_a_signed_quote_and_a_commit_must_name_its_terms() {
        use swap_common::paykit_cap::*;
        let directory = std::env::temp_dir().join(format!("cap-quote-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let ctx = executing(context(store, Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[41; 32]);
        let constraints = RfqConstraints {
            offer_id: Uuid::nil(),
            direction: SwapDirection::Reverse,
            amount_sat: 100_000,
        };
        let rfq = CapMessage::Rfq(Rfq {
            request_id: Some(Uuid::new_v4()),
            constraints: constraints.clone(),
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        });
        let reply = ask_cap(&ctx, &owner, &rfq).await;
        let CapMessage::Quote(signed) = serde_json::from_slice(&reply).unwrap() else {
            panic!("expected a quote: {}", String::from_utf8_lossy(&reply));
        };
        let parties = Parties {
            owner: owner.clone(),
            provider: ctx.cap.provider().to_string(),
        };
        signed.verify(&parties, &constraints).unwrap();

        let mut request = owned_record(&owner).swap_request.unwrap();
        request.quote_id = signed.quote.quote_id;
        let commit = CapMessage::Commit(Commit {
            terms_hash: "00".repeat(32),
            commit: CommitBody::from_request(&request),
            quote: None,
        });
        let reply = ask_cap(&ctx, &owner, &commit).await;
        assert!(
            matches!(serde_json::from_slice(&reply).unwrap(), CapMessage::Refusal(r)
                if r.code == "invalid_request" && r.quote_id == Some(request.quote_id)),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// The `paykit-cap` secret of [`signing_provider`].
    const PROVIDER_SECRET: [u8; 32] = [40; 32];

    /// A provider that signs with [`PROVIDER_SECRET`] and can start reverse swaps.
    fn signing_provider(store: Arc<JsonFileSwapStore>) -> ExecCtx {
        ExecCtx {
            ln: Arc::new(OpenInvoiceLightning),
            homeserver: false,
            cap: Arc::new(crate::cap_adapter::CapState::new(
                Arc::new(swap_common::paykit_cap::Ed25519Signer::from_secret(
                    &PROVIDER_SECRET,
                )),
                pubky_transport::identity_from_secret(&PROVIDER_SECRET),
            )),
            ..executing(context(store, Uuid::new_v4()))
        }
    }

    /// The owner's half of `paykit-cap`, talking to [`signing_provider`].
    fn cap_client(owner: &str) -> swap_common::paykit_cap::CapClient {
        use swap_common::paykit_cap::{CapSigner, Ed25519Signer, Parties};
        let key = hex::decode(Ed25519Signer::from_secret(&PROVIDER_SECRET).public_key_hex())
            .unwrap()
            .try_into()
            .unwrap();
        swap_common::paykit_cap::CapClient::new(
            Some(key),
            Parties {
                owner: owner.into(),
                provider: pubky_transport::identity_from_secret(&PROVIDER_SECRET),
            },
        )
    }

    /// A reverse creation for `quote_id` with keys of its own.
    fn reverse_request(owner: &str, quote_id: Uuid, preimage: [u8; 32]) -> SwapRequest {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (_, claim) = swap_common::random_keypair(&secp);
        SwapRequest {
            script_type: SwapScript::P2wsh,
            quote_id,
            client_pkarr: owner.into(),
            direction: SwapDirection::Reverse,
            payment_hash_hex: hex::encode(payment_hash(&preimage)),
            client_claim_pubkey_hex: Some(hex::encode(claim.to_bytes())),
            client_refund_pubkey_hex: None,
            invoice: None,
            owner_ref: None,
        }
    }

    /// One request through `client` to `ctx`: the provider's raw answer, and what the client
    /// made of it.
    async fn exchange_cap(
        ctx: &ExecCtx,
        owner: &str,
        client: &mut swap_common::paykit_cap::CapClient,
        request: SwapMessage,
    ) -> (
        Vec<u8>,
        std::result::Result<SwapMessage, swap_common::paykit_cap::CapError>,
    ) {
        let message = client.request(&request).expect("a paykit-cap kind");
        let bytes = ask_cap(ctx, owner, &message).await;
        let reply = serde_json::from_slice(&bytes).unwrap();
        (bytes.clone(), client.reply(&request, reply))
    }

    /// A signed quote from `ctx` for `owner`, through `client`.
    async fn signed_quote(
        ctx: &ExecCtx,
        owner: &str,
        client: &mut swap_common::paykit_cap::CapClient,
    ) -> Quote {
        let request = quote_request(owner, SwapDirection::Reverse, 100_000);
        let (bytes, reply) =
            exchange_cap(ctx, owner, client, SwapMessage::QuoteRequest(request)).await;
        match reply {
            Ok(SwapMessage::Quote(quote)) => quote,
            other => panic!(
                "expected a quote, got {other:?}: {}",
                String::from_utf8_lossy(&bytes)
            ),
        }
    }

    /// #103: a commit on a quote the provider signed is honoured after a restart, on the quote
    /// it carries. A replay gets the same contract, and another commit on that quote is refused.
    #[tokio::test]
    async fn a_signed_quote_is_honoured_after_a_restart() {
        let directory = std::env::temp_dir().join(format!("cap-restart-{}", Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[51; 32]);
        let mut client = cap_client(&owner);
        let ctx = signing_provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let quote = signed_quote(&ctx, &owner, &mut client).await;

        // Restarted: the same store and key, an empty book and no signed terms in memory.
        let ctx = signing_provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let request = SwapMessage::SwapRequest(reverse_request(&owner, quote.quote_id, [52; 32]));
        let (first, accepted) = exchange_cap(&ctx, &owner, &mut client, request.clone()).await;
        assert!(
            matches!(&accepted, Ok(SwapMessage::SwapAccept(a)) if a.quote_id == quote.quote_id),
            "{accepted:?}: {}",
            String::from_utf8_lossy(&first)
        );
        let (replayed, _) = exchange_cap(&ctx, &owner, &mut client, request).await;
        assert_eq!(replayed, first, "a replay gets the contract first signed");

        let other = SwapMessage::SwapRequest(reverse_request(&owner, quote.quote_id, [53; 32]));
        let (bytes, refused) = exchange_cap(&ctx, &owner, &mut client, other).await;
        assert!(
            matches!(&refused, Ok(SwapMessage::Reject(_))),
            "a spent quote takes no second swap: {}",
            String::from_utf8_lossy(&bytes)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// #103: a quote a full book evicted is honoured on its signature. Before, the same commit
    /// got `quote_expired`.
    #[tokio::test]
    async fn a_signed_quote_is_honoured_after_the_book_evicts_it() {
        use swap_common::paykit_cap::{CapMessage, Commit};
        let directory = std::env::temp_dir().join(format!("cap-evicted-{}", Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[54; 32]);
        let mut client = cap_client(&owner);
        let ctx = signing_provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let quote = signed_quote(&ctx, &owner, &mut client).await;
        let request = SwapMessage::SwapRequest(reverse_request(&owner, quote.quote_id, [55; 32]));
        let Some(CapMessage::Commit(commit)) = client.request(&request) else {
            panic!("a commit follows a signed quote");
        };
        // What a full book does to its oldest quote.
        assert!(ctx
            .quotes
            .lock()
            .await
            .quotes
            .remove(&quote.quote_id)
            .is_some());

        let unsigned = CapMessage::Commit(Commit {
            quote: None,
            ..commit.clone()
        });
        let reply = ask_cap(&ctx, &owner, &unsigned).await;
        assert!(
            matches!(serde_json::from_slice(&reply).unwrap(), CapMessage::Refusal(r) if r.code == "quote_expired"),
            "without the signed quote: {}",
            String::from_utf8_lossy(&reply)
        );
        let (bytes, accepted) = exchange_cap(&ctx, &owner, &mut client, request).await;
        assert!(
            matches!(&accepted, Ok(SwapMessage::SwapAccept(a)) if a.quote_id == quote.quote_id),
            "{accepted:?}: {}",
            String::from_utf8_lossy(&bytes)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// #103: a signed quote vouches only for the owner its terms name, under this provider's key,
    /// before it expires.
    #[tokio::test]
    async fn a_forged_borrowed_or_expired_signed_quote_is_refused() {
        use swap_common::paykit_cap::*;
        let directory = std::env::temp_dir().join(format!("cap-refused-{}", Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[56; 32]);
        let mut client = cap_client(&owner);
        let ctx = signing_provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let quote = signed_quote(&ctx, &owner, &mut client).await;
        let request = SwapMessage::SwapRequest(reverse_request(&owner, quote.quote_id, [57; 32]));
        let Some(CapMessage::Commit(commit)) = client.request(&request) else {
            panic!("a commit follows a signed quote");
        };
        // Restarted, so only the quote the commit carries can vouch for it.
        let ctx = signing_provider(Arc::new(JsonFileSwapStore::new(&directory).unwrap()));
        let refusal = |reply: &[u8]| match serde_json::from_slice(reply).unwrap() {
            CapMessage::Refusal(refusal) => refusal.code,
            other => panic!("expected a refusal, got {other:?}"),
        };
        let parties = Parties {
            owner: owner.clone(),
            provider: ctx.cap.provider().to_string(),
        };
        let resigned = |by: &dyn CapSigner, change: &dyn Fn(&mut Quote)| {
            let mut commit = commit.clone();
            let proof = commit.quote.as_mut().unwrap();
            change(&mut proof.signed.quote);
            proof.signed =
                sign_quote(by, &parties, &proof.rfq.constraints, &proof.signed.quote).unwrap();
            commit.terms_hash = proof.signed.terms_hash.clone();
            CapMessage::Commit(commit)
        };

        let thief = pubky_transport::identity_from_secret(&[58; 32]);
        let borrowed = ask_cap(&ctx, &thief, &CapMessage::Commit(commit.clone())).await;
        assert_eq!(refusal(&borrowed), "invalid_request", "another key's quote");
        let forged = resigned(&Ed25519Signer::from_secret(&[59; 32]), &|_| {});
        assert_eq!(
            refusal(&ask_cap(&ctx, &owner, &forged).await),
            "invalid_request",
            "signed by another key"
        );
        let signer = Ed25519Signer::from_secret(&PROVIDER_SECRET);
        let expired = resigned(&signer, &|quote| quote.valid_until_unix = 1);
        assert_eq!(
            refusal(&ask_cap(&ctx, &owner, &expired).await),
            "quote_expired",
            "past its validity"
        );

        // None of those spent the quote: the genuine commit still goes through.
        let (bytes, accepted) = exchange_cap(&ctx, &owner, &mut client, request).await;
        assert!(
            matches!(&accepted, Ok(SwapMessage::SwapAccept(_))),
            "{accepted:?}: {}",
            String::from_utf8_lossy(&bytes)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn a_root_key_cannot_reach_a_swap_made_under_a_scoped_session() {
        let directory = std::env::temp_dir().join(format!("direct-session-{}", Uuid::new_v4()));
        let key = pubky_transport::identity_from_secret(&[43; 32]);
        let mut record = owned_record(&key);
        record.peer_account = Some("ring-account".into());
        record.peer_authorization_scope = Some("/pub/bitkit.to/bitkit/wallet/".into());
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        store.put(&record).unwrap();
        let ctx = context(store, record.swap_id);

        let status = SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: Some(record.swap_id),
            quote_id: None,
        };
        let reply = ask(&ctx, &key, SwapMessage::SwapStatusRequest(status)).await;
        assert!(
            matches!(&reply, Some(SwapMessage::Reject(r)) if r.code.as_deref() == Some("not_found")),
            "{reply:?}"
        );
        let request = record.swap_request.clone().unwrap();
        let reply = ask(&ctx, &key, SwapMessage::SwapRequest(request)).await;
        assert!(matches!(reply, Some(SwapMessage::Reject(_))), "{reply:?}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// The `version` wire of Capabilities §8.1 and §13.1, beside the older one.
    mod cap_v1 {
        use super::*;
        use serde_json::{json, Value};
        use swap_common::cap_descriptor::{onchain_rail, LIGHTNING_IDENTIFIER};
        use swap_common::paykit_cap::v1::{self as wire, *};
        use swap_common::paykit_cap::{CapSigner, Ed25519Signer};

        /// The owner's key generation in every envelope it sends.
        const GENERATION: u64 = 3;
        /// The owner's capability signing secret at [`GENERATION`].
        const OWNER_CAP_SECRET: [u8; 32] = [62; 32];

        fn key(secret: &[u8; 32]) -> [u8; 32] {
            hex::decode(Ed25519Signer::from_secret(secret).public_key_hex())
                .unwrap()
                .try_into()
                .unwrap()
        }

        /// [`signing_provider`], finding the owner's key for [`GENERATION`] as its published
        /// delegation would name it, and holding wake grants.
        fn provider(directory: &std::path::Path) -> ExecCtx {
            let store = Arc::new(JsonFileSwapStore::new(directory).unwrap());
            let cap = crate::cap_adapter::CapState::new(
                Arc::new(Ed25519Signer::from_secret(&PROVIDER_SECRET)),
                pubky_transport::identity_from_secret(&PROVIDER_SECRET),
            )
            .with_owner_keys(Arc::new(|_, generation| {
                Box::pin(
                    async move { Ok((generation == GENERATION).then(|| key(&OWNER_CAP_SECRET))) },
                )
            }));
            ExecCtx {
                cap: Arc::new(cap),
                wake: Arc::new(crate::wake::Waker::new(&["https://wake.example".into()])),
                ..signing_provider(store)
            }
        }

        async fn send(ctx: &ExecCtx, owner: &str, message: Value) -> Value {
            let (reply, answer) = tokio::sync::oneshot::channel();
            let request = DirectRpc {
                remote_key: owner.into(),
                message,
                reply,
            };
            handle_direct_request(ctx.clone(), offer(), request).await;
            serde_json::from_slice(&answer.await.unwrap()).unwrap()
        }

        async fn exchange(ctx: &ExecCtx, owner: &str, message: &wire::Message) -> wire::Message {
            let reply = send(ctx, owner, serde_json::to_value(message).unwrap()).await;
            wire::Message::parse(reply.clone()).unwrap_or_else(|e| panic!("{e}: {reply}"))
        }

        fn refusal_code(reply: &wire::Message) -> &str {
            match reply {
                wire::Message::Refusal(refusal) => &refusal.body.code,
                other => panic!("expected a refusal, got {other:?}"),
            }
        }

        fn rfq(flow_id: Uuid) -> wire::Rfq {
            let now = crate::now_unix();
            wire::Rfq {
                envelope: Envelope::new("bitkit", flow_id, GENERATION),
                event_id: Uuid::new_v4(),
                body: RfqBody {
                    offer_id: Uuid::nil(),
                    dir: SwapDirection::Reverse,
                    from: LIGHTNING_IDENTIFIER.into(),
                    to: format!("btc-{}-p2wsh", onchain_rail(NetworkSpec::Regtest)),
                    amount_sat: Sat(100_000),
                },
                atomicity_min: "hash".into(),
                respond_by: now + 30,
                valid_until: now + 60,
            }
        }

        /// A quote for `owner`, checked against the provider's key, and the terms it signs.
        async fn quote(ctx: &ExecCtx, owner: &str, rfq: &wire::Rfq) -> (wire::Quote, Terms) {
            let reply = exchange(ctx, owner, &wire::Message::Rfq(rfq.clone())).await;
            let wire::Message::Quote(quote) = reply else {
                panic!("expected a quote, got {reply:?}");
            };
            let terms = wire::terms(owner, rfq, ctx.cap.provider(), &quote);
            wire::verify(&key(&PROVIDER_SECRET), &terms.hash().unwrap(), &quote.sig).unwrap();
            (quote, terms)
        }

        fn commit(
            quote: &wire::Quote,
            terms: &Terms,
            preimage: [u8; 32],
            owner_ref: Option<String>,
        ) -> wire::Commit {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let (_, claim) = swap_common::random_keypair(&secp);
            wire::Commit {
                envelope: Envelope::new("bitkit", terms.flow_id, GENERATION),
                event_id: Uuid::new_v4(),
                quote_event_id: quote.event_id,
                terms_hash: hex::encode(terms.hash().unwrap()),
                body: CommitBody {
                    lock_profile: SwapScript::P2wsh,
                    payment_hash: hex::encode(payment_hash(&preimage)),
                    claim_pubkey: Some(hex::encode(claim.to_bytes())),
                    refund_pubkey: None,
                    invoice: None,
                    owner_ref,
                },
                quote: Some(SignedTerms {
                    terms: terms.clone(),
                    sig: quote.sig.clone(),
                }),
                sig: None,
            }
        }

        fn as_commit(commit: &wire::Commit) -> wire::Message {
            wire::Message::Commit(Box::new(commit.clone()))
        }

        /// RFQ, quote, an unsigned commit and its contract, then the swap's status, wake grant
        /// and listing, all over the `version` wire. A retried event gets the same reply.
        #[tokio::test]
        async fn a_reverse_swap_runs_from_rfq_to_listing() {
            let directory = std::env::temp_dir().join(format!("cap-v1-{}", Uuid::new_v4()));
            let ctx = provider(&directory);
            let owner = pubky_transport::identity_from_secret(&[61; 32]);
            let rfq = rfq(Uuid::new_v4());
            let (quote, terms) = quote(&ctx, &owner, &rfq).await;
            assert_eq!(quote.rfq_event_id, rfq.event_id);
            assert_eq!(quote.envelope.flow_id, rfq.envelope.flow_id);
            assert_eq!(quote.envelope.app_id, PROVIDER_APP_ID);
            assert_eq!(quote.body.dir, SwapDirection::Reverse);
            assert!(quote.body.lock_profiles.contains(&SwapScript::P2wsh));
            assert_eq!(
                quote.body.service_fee_sat.0 + quote.body.onchain_fee_sat.0 + 100_000,
                quote.body.total_sat.0
            );
            let retried = exchange(&ctx, &owner, &wire::Message::Rfq(rfq.clone())).await;
            assert_eq!(retried, wire::Message::Quote(quote.clone()));

            // Bitkit's index is 58 characters.
            let owner_ref = "k".repeat(58);
            let commit = commit(&quote, &terms, [63; 32], Some(owner_ref.clone()));
            let reply = exchange(&ctx, &owner, &as_commit(&commit)).await;
            let wire::Message::Contract(contract) = reply else {
                panic!("expected a contract, got {reply:?}");
            };
            assert_eq!(contract.commit_event_id, commit.event_id);
            assert_eq!(
                contract.commit_hash,
                hex::encode(commit.commit_hash().unwrap())
            );
            contract.verify(&key(&PROVIDER_SECRET)).unwrap();
            let accept = contract.open(&terms).unwrap();
            assert_eq!(accept.quote_id, quote.body.quote_id);
            assert!(accept.invoice.is_some());
            let replayed = exchange(&ctx, &owner, &as_commit(&commit)).await;
            assert_eq!(replayed, wire::Message::Contract(contract.clone()));

            let record = ctx.store.get(accept.swap_id).unwrap().unwrap();
            assert!(
                record.claimable_hint,
                "the RFQ had no features to ask for it"
            );
            let grant = SwapWakeCapability {
                request_id: Some(Uuid::new_v4()),
                swap_id: accept.swap_id,
                capability: WakeCapability {
                    v: 1,
                    gateway: "https://wake.example".into(),
                    topics: vec![swap_common::messages::SWAP_WAKE_TOPIC.into()],
                    token: "wkg_v1".into(),
                    expires_at: u64::MAX,
                },
            };
            let reply = ask(&ctx, &owner, SwapMessage::SwapWakeCapability(grant)).await;
            assert!(
                matches!(&reply, Some(SwapMessage::SwapStatusSnapshot(_))),
                "{reply:?}"
            );
            assert!(ctx.wake.holds(accept.swap_id));

            let listed = page(&ctx, &owner, None, None, false).await;
            assert_eq!(listed.snapshots.len(), 1);
            assert_eq!(
                listed.snapshots[0].owner_ref.as_deref(),
                Some(owner_ref.as_str())
            );

            let request = wire::Message::StatusRequest(StatusRequest {
                envelope: Envelope::new("bitkit", terms.flow_id, GENERATION),
                event_id: Uuid::new_v4(),
                body: StatusRequestBody {
                    swap_id: Some(accept.swap_id),
                    quote_id: None,
                },
            });
            let reply = exchange(&ctx, &owner, &request).await;
            let wire::Message::Status(status) = reply else {
                panic!("expected a status, got {reply:?}");
            };
            assert_eq!(status.body.swap_id, accept.swap_id);
            assert_eq!(status.body.state, "pending");
            assert_eq!(status.body.detail, "created");
            std::fs::remove_dir_all(directory).unwrap();
        }

        /// A commit's `sig` is optional on `direct/1`, but one that is there must be the owner's
        /// capability signing key for the generation its envelope names.
        #[tokio::test]
        async fn a_signed_commit_must_verify_under_its_generation() {
            let directory = std::env::temp_dir().join(format!("cap-v1-sig-{}", Uuid::new_v4()));
            let ctx = provider(&directory);
            let owner = pubky_transport::identity_from_secret(&[61; 32]);
            let (quote, terms) = quote(&ctx, &owner, &rfq(Uuid::new_v4())).await;

            let mut forged = commit(&quote, &terms, [64; 32], None);
            forged.sign(&Ed25519Signer::from_secret(&[65; 32])).unwrap();
            let reply = exchange(&ctx, &owner, &as_commit(&forged)).await;
            assert_eq!(refusal_code(&reply), "invalid_request");
            let wire::Message::Refusal(refusal) = &reply else {
                unreachable!()
            };
            assert_eq!(refusal.commit_event_id, Some(forged.event_id));

            let mut signed = commit(&quote, &terms, [64; 32], None);
            signed
                .sign(&Ed25519Signer::from_secret(&OWNER_CAP_SECRET))
                .unwrap();
            let reply = exchange(&ctx, &owner, &as_commit(&signed)).await;
            assert!(matches!(reply, wire::Message::Contract(_)), "{reply:?}");

            // Generation 0 is the owner's root key, which no delegation names.
            let mut root_rfq = rfq(Uuid::new_v4());
            root_rfq.envelope.key_generation = 0;
            let (quote, terms) = self::quote(&ctx, &owner, &root_rfq).await;
            let mut wrong = commit(&quote, &terms, [70; 32], None);
            wrong.envelope.key_generation = 0;
            wrong
                .sign(&Ed25519Signer::from_secret(&OWNER_CAP_SECRET))
                .unwrap();
            let reply = exchange(&ctx, &owner, &as_commit(&wrong)).await;
            assert_eq!(refusal_code(&reply), "invalid_request");
            let mut root = commit(&quote, &terms, [70; 32], None);
            root.envelope.key_generation = 0;
            root.sign(&Ed25519Signer::from_secret(&[61; 32])).unwrap();
            let reply = exchange(&ctx, &owner, &as_commit(&root)).await;
            assert!(matches!(reply, wire::Message::Contract(_)), "{reply:?}");
            std::fs::remove_dir_all(directory).unwrap();
        }

        /// A commit names its terms' profile, flow and owner key generation, and the terms
        /// carried with it must be the ones the provider signed. A restarted provider takes the
        /// carried quote back, with the claimable hint a reverse quote on this wire always has.
        #[tokio::test]
        async fn a_commit_under_other_terms_is_refused_and_a_restart_takes_the_quote_back() {
            let directory = std::env::temp_dir().join(format!("cap-v1-terms-{}", Uuid::new_v4()));
            let ctx = provider(&directory);
            let owner = pubky_transport::identity_from_secret(&[61; 32]);
            let (quote, terms) = quote(&ctx, &owner, &rfq(Uuid::new_v4())).await;

            let mut other_flow = commit(&quote, &terms, [66; 32], None);
            other_flow.envelope.flow_id = Uuid::new_v4();
            let mut other_generation = commit(&quote, &terms, [66; 32], None);
            other_generation.envelope.key_generation = GENERATION + 1;
            let mut other_terms = commit(&quote, &terms, [66; 32], None);
            other_terms.quote.as_mut().unwrap().terms.flow_id = Uuid::new_v4();
            other_terms.terms_hash =
                hex::encode(other_terms.quote.as_ref().unwrap().terms.hash().unwrap());
            for refused in [&other_flow, &other_generation, &other_terms] {
                let reply = exchange(&ctx, &owner, &as_commit(refused)).await;
                assert_eq!(refusal_code(&reply), "invalid_request", "{refused:?}");
            }
            let mut other_profile = commit(&quote, &terms, [66; 32], None);
            other_profile.envelope.profile = "swap/2".into();
            let reply = exchange(&ctx, &owner, &as_commit(&other_profile)).await;
            assert_eq!(refusal_code(&reply), "unsupported_protocol");
            // A stranger presenting the owner's terms gets nothing.
            let stranger = pubky_transport::identity_from_secret(&[67; 32]);
            let commit = commit(&quote, &terms, [66; 32], None);
            let reply = exchange(&ctx, &stranger, &as_commit(&commit)).await;
            assert_eq!(refusal_code(&reply), "invalid_request");

            // Restarted: the same store and key, an empty book and no terms in memory.
            let ctx = provider(&directory);
            let reply = exchange(&ctx, &owner, &as_commit(&commit)).await;
            let wire::Message::Contract(contract) = reply else {
                panic!("expected a contract, got {reply:?}");
            };
            let record = ctx.store.get(contract.body.swap_id).unwrap().unwrap();
            assert!(record.claimable_hint);
            std::fs::remove_dir_all(directory).unwrap();
        }

        /// An RFQ is a closed object with string amounts, on one of the provider's edges, at an
        /// atomicity `hash` meets. A commit's `owner_ref` is capped at 63 characters here.
        #[tokio::test]
        async fn malformed_rfqs_and_long_owner_refs_are_refused() {
            let directory = std::env::temp_dir().join(format!("cap-v1-rfq-{}", Uuid::new_v4()));
            let ctx = provider(&directory);
            let owner = pubky_transport::identity_from_secret(&[61; 32]);
            let base = serde_json::to_value(wire::Message::Rfq(rfq(Uuid::new_v4()))).unwrap();
            let code = |reply: Value| {
                wire::Message::parse(reply.clone())
                    .map(|m| refusal_code(&m).to_string())
                    .unwrap_or_else(|e| panic!("{e}: {reply}"))
            };

            let mut unknown = base.clone();
            unknown["features"] = json!(["claimable-hint-v1"]);
            assert_eq!(code(send(&ctx, &owner, unknown).await), "invalid_request");
            let mut unknown_in_body = base.clone();
            unknown_in_body["body"]["direction"] = json!("reverse");
            assert_eq!(
                code(send(&ctx, &owner, unknown_in_body).await),
                "invalid_request"
            );
            let mut integer = base.clone();
            integer["body"]["amount_sat"] = json!(100_000);
            assert_eq!(code(send(&ctx, &owner, integer).await), "invalid_request");
            let mut off_edge = base.clone();
            off_edge["body"]["to"] = json!("btc-mainnet-p2wsh");
            assert_eq!(
                code(send(&ctx, &owner, off_edge).await),
                "unsupported_route"
            );
            let mut backwards = base.clone();
            backwards["body"]["dir"] = json!("submarine");
            assert_eq!(
                code(send(&ctx, &owner, backwards).await),
                "unsupported_route"
            );
            let mut atomicity = base.clone();
            atomicity["atomicity_min"] = json!("telepathy");
            assert_eq!(
                code(send(&ctx, &owner, atomicity).await),
                "atomicity_unsupported"
            );

            let (quote, terms) = quote(&ctx, &owner, &rfq(Uuid::new_v4())).await;
            let long = commit(&quote, &terms, [68; 32], Some("k".repeat(64)));
            let reply = exchange(&ctx, &owner, &as_commit(&long)).await;
            assert_eq!(refusal_code(&reply), "invalid_request");
            // The quote is unspent: the same commit within the cap is admitted.
            let short = commit(&quote, &terms, [68; 32], Some("k".repeat(63)));
            let reply = exchange(&ctx, &owner, &as_commit(&short)).await;
            assert!(matches!(reply, wire::Message::Contract(_)), "{reply:?}");
            std::fs::remove_dir_all(directory).unwrap();
        }

        /// The client's half of this wire against the provider: a quote and a contract that
        /// check out become the engine's own `Quote` and `SwapAccept`.
        #[tokio::test]
        async fn the_client_negotiates_a_swap_and_refuses_replies_under_other_terms() {
            let directory = std::env::temp_dir().join(format!("cap-v1-client-{}", Uuid::new_v4()));
            let ctx = provider(&directory);
            let owner = pubky_transport::identity_from_secret(&[61; 32]);
            let mut client = wire::Client::new(
                owner.clone(),
                ctx.cap.provider().to_string(),
                Some(key(&PROVIDER_SECRET)),
            );
            let current = offer().read().await.clone().unwrap();
            let fee_rate_sat_vb = current.fee_rate_sat_vb;
            client.observe(&SwapMessage::Offer(current));

            let asked =
                SwapMessage::QuoteRequest(quote_request(&owner, SwapDirection::Reverse, 100_000));
            let rfq = client.request(&asked).expect("an rfq");
            assert_eq!(
                client.request(&asked),
                Some(rfq.clone()),
                "a retry is the same event"
            );
            let reply = exchange(&ctx, &owner, &rfq).await;
            let wire::Message::Quote(signed) = reply.clone() else {
                panic!("expected a quote, got {reply:?}");
            };
            // A reply under another flow, generation or profile is refused.
            let mut other_flow = signed.clone();
            other_flow.envelope.flow_id = Uuid::new_v4();
            let mut other_generation = signed.clone();
            other_generation.envelope.key_generation += 1;
            let mut other_profile = signed.clone();
            other_profile.envelope.profile = "swap/2".into();
            for refused in [other_flow, other_generation, other_profile] {
                let refused = client.reply(&asked, &rfq, wire::Message::Quote(refused));
                assert!(refused.is_err(), "{refused:?}");
            }
            let Ok(SwapMessage::Quote(quote)) = client.reply(&asked, &rfq, reply) else {
                panic!("the quote does not check out");
            };
            assert_eq!(quote.fee_sat, quote.service_fee_sat + quote.onchain_fee_sat);
            assert_eq!(
                quote.fee_rate_sat_vb, fee_rate_sat_vb,
                "taken from the offer"
            );

            let mut request = reverse_request(&owner, quote.quote_id, [69; 32]);
            request.owner_ref = Some("k".repeat(58));
            let asked = SwapMessage::SwapRequest(request);
            let commit = client.request(&asked).expect("a commit");
            let reply = exchange(&ctx, &owner, &commit).await;
            let wire::Message::Contract(contract) = reply.clone() else {
                panic!("expected a contract, got {reply:?}");
            };
            let mut other_generation = contract.clone();
            other_generation.envelope.key_generation += 1;
            assert!(client
                .reply(&asked, &commit, wire::Message::Contract(other_generation))
                .is_err());
            let Ok(SwapMessage::SwapAccept(accept)) = client.reply(&asked, &commit, reply) else {
                panic!("the contract does not check out");
            };
            assert_eq!(accept.quote_id, quote.quote_id);
            // A retry is the same event, and gets the same contract.
            assert_eq!(client.request(&asked), Some(commit.clone()));
            let replayed = exchange(&ctx, &owner, &commit).await;
            assert_eq!(replayed, wire::Message::Contract(contract));
            std::fs::remove_dir_all(directory).unwrap();
        }

        /// A message without `version` takes today's path, so a client from before this wire
        /// keeps getting today's replies.
        #[tokio::test]
        async fn a_message_without_version_gets_todays_reply() {
            use swap_common::paykit_cap::{CapMessage, Parties, Rfq, RfqConstraints};
            let directory = std::env::temp_dir().join(format!("cap-v1-old-{}", Uuid::new_v4()));
            let ctx = provider(&directory);
            let owner = pubky_transport::identity_from_secret(&[61; 32]);
            let constraints = RfqConstraints {
                offer_id: Uuid::nil(),
                direction: SwapDirection::Reverse,
                amount_sat: 100_000,
            };
            let rfq = CapMessage::Rfq(Rfq {
                request_id: Some(Uuid::new_v4()),
                constraints: constraints.clone(),
                protocol_version: PROTOCOL_VERSION,
                features: Vec::new(),
            });
            let reply = send(&ctx, &owner, serde_json::to_value(&rfq).unwrap()).await;
            assert!(!wire::is_v1(&reply), "{reply}");
            let CapMessage::Quote(signed) = serde_json::from_value(reply.clone()).unwrap() else {
                panic!("expected today's quote, got {reply}");
            };
            let parties = Parties {
                owner: owner.clone(),
                provider: ctx.cap.provider().to_string(),
            };
            signed.verify(&parties, &constraints).unwrap();
            assert_eq!(
                signed.signer,
                Ed25519Signer::from_secret(&PROVIDER_SECRET).public_key_hex()
            );
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[tokio::test]
    async fn a_wake_capability_is_taken_over_a_direct_request() {
        let directory = std::env::temp_dir().join(format!("direct-wake-{}", Uuid::new_v4()));
        let owner = pubky_transport::identity_from_secret(&[44; 32]);
        let mut record = owned_record(&owner);
        record.claimable_hint = true;
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        store.put(&record).unwrap();
        let ctx = ExecCtx {
            wake: Arc::new(crate::wake::Waker::new(&["https://wake.example".into()])),
            ..context(store, record.swap_id)
        };

        let offer = SwapWakeCapability {
            request_id: Some(Uuid::new_v4()),
            swap_id: record.swap_id,
            capability: WakeCapability {
                v: 1,
                gateway: "https://wake.example".into(),
                topics: vec![swap_common::messages::SWAP_WAKE_TOPIC.into()],
                token: "wkg_direct".into(),
                expires_at: u64::MAX,
            },
        };
        let reply = ask(&ctx, &owner, SwapMessage::SwapWakeCapability(offer)).await;
        assert!(
            matches!(&reply, Some(SwapMessage::SwapStatusSnapshot(s)) if !s.claimable),
            "{reply:?}"
        );
        assert!(ctx.wake.holds(record.swap_id));
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn listing(cursor: Option<String>, limit: Option<u32>, active_only: bool) -> SwapMessage {
        SwapMessage::SwapListRequest(SwapListRequest {
            request_id: Some(Uuid::new_v4()),
            cursor,
            limit,
            active_only,
        })
    }

    /// One page as `key` sees it, correlated to its request.
    async fn page(
        ctx: &ExecCtx,
        key: &str,
        cursor: Option<String>,
        limit: Option<u32>,
        active_only: bool,
    ) -> SwapList {
        let request = listing(cursor, limit, active_only);
        let SwapMessage::SwapListRequest(SwapListRequest { request_id, .. }) = &request else {
            unreachable!()
        };
        let request_id = *request_id;
        match ask(ctx, key, request).await {
            Some(SwapMessage::SwapList(list)) => {
                assert_eq!(list.request_id, request_id);
                list
            }
            other => panic!("expected a page, got {other:?}"),
        }
    }

    fn ids(list: &SwapList) -> Vec<Uuid> {
        list.snapshots.iter().map(|s| s.accept.swap_id).collect()
    }

    /// #105: an owner pages through its own swaps, newest first, and a page holds still while
    /// the swaps on it change state. Nobody else sees them, and an admission that is still
    /// creating its invoice is not yet a swap to list.
    #[tokio::test]
    async fn an_owner_pages_through_its_own_swaps_and_nobody_else_sees_them() {
        let directory = std::env::temp_dir().join(format!("direct-list-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let owner = pubky_transport::identity_from_secret(&[41; 32]);
        let other = pubky_transport::identity_from_secret(&[42; 32]);
        let nobody = pubky_transport::identity_from_secret(&[43; 32]);
        let mut owned = Vec::new();
        for (index, created_at_unix) in [100u64, 200, 300].into_iter().enumerate() {
            let mut record = owned_record(&owner);
            record.created_at_unix = created_at_unix;
            record.swap_request.as_mut().unwrap().owner_ref = Some(format!("index:{index}"));
            store.put(&record).unwrap();
            owned.push(record.swap_id);
        }
        store.put(&owned_record(&other)).unwrap();
        let mut admitting = invoice_intent();
        admitting.peer = owner.clone();
        admitting.swap_request.as_mut().unwrap().client_pkarr = owner.clone();
        store.put(&admitting).unwrap();
        let ctx = context(store.clone(), Uuid::new_v4());

        let first = page(&ctx, &owner, None, Some(2), false).await;
        assert_eq!(ids(&first), vec![owned[2], owned[1]]);
        let newest = &first.snapshots[0];
        assert_eq!(newest.created_at_unix, 300);
        assert_eq!(newest.owner_ref.as_deref(), Some("index:2"));
        assert_eq!(newest.payment_hash_hex, hex::encode(payment_hash(&[9; 32])));
        assert!(first.snapshots.iter().all(|s| s.request_id.is_none()));
        let cursor = first.next_cursor.clone().expect("a page follows");

        // The middle swap finishes between pages; the next page is what it would have been.
        store
            .mutate(owned[1], &mut |record| record.state = SwapState::Claimed)
            .unwrap();
        let second = page(&ctx, &owner, Some(cursor.clone()), Some(2), false).await;
        assert_eq!(ids(&second), vec![owned[0]]);
        assert!(second.next_cursor.is_none());
        let past_the_end = page(&ctx, &owner, Some(cursor), Some(1), false).await;
        assert_eq!(ids(&past_the_end), vec![owned[0]]);

        let active = page(&ctx, &owner, None, None, true).await;
        assert_eq!(ids(&active), vec![owned[2], owned[0]]);

        assert_eq!(list_page_limit(None), SWAP_LIST_DEFAULT_PAGE as usize);
        assert_eq!(list_page_limit(Some(0)), SWAP_LIST_DEFAULT_PAGE as usize);
        assert_eq!(list_page_limit(Some(1_000)), SWAP_LIST_MAX_PAGE as usize);
        assert_eq!(list_page_limit(Some(3)), 3);

        // Others see their own, and only their own. No refusal: a listing says nothing about
        // what exists.
        let theirs = page(&ctx, &other, None, None, false).await;
        assert_eq!(theirs.snapshots.len(), 1);
        assert!(page(&ctx, &nobody, None, None, false)
            .await
            .snapshots
            .is_empty());

        // A cursor this provider did not issue is refused with a code.
        let (code, reject) = refusal(
            ask(
                &ctx,
                &owner,
                listing(Some("not-a-cursor".into()), None, false),
            )
            .await,
        );
        assert_eq!(code, RejectCode::InvalidRequest);
        assert!(reject.request_id.is_some());
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A swap made under a scoped session is listed to that session and never to the root key,
    /// exactly as a status query treats it.
    #[tokio::test]
    async fn a_root_key_cannot_list_swaps_made_under_a_scoped_session() {
        let directory = std::env::temp_dir().join(format!("list-session-{}", Uuid::new_v4()));
        let key = pubky_transport::identity_from_secret(&[43; 32]);
        let mut record = owned_record(&key);
        record.peer_account = Some("ring-account".into());
        record.peer_authorization_scope = Some("/pub/bitkit.to/bitkit/wallet/".into());
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        store.put(&record).unwrap();
        let ctx = context(store, record.swap_id);

        assert!(page(&ctx, &key, None, None, false)
            .await
            .snapshots
            .is_empty());

        let (reply, answer) = tokio::sync::oneshot::channel();
        let mut session = ctx.clone();
        session.transport = Arc::new(ctx.transport.session(
            "ring-account".into(),
            "/pub/bitkit.to/bitkit/wallet/".into(),
            reply,
        ));
        handle_message(&session, None, &key, listing(None, None, false))
            .await
            .unwrap();
        let message: SwapMessage = serde_json::from_slice(&answer.await.unwrap()).unwrap();
        let SwapMessage::SwapList(list) = message else {
            panic!("expected a page, got {message:?}");
        };
        assert_eq!(ids(&list), vec![record.swap_id]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// #105: an owner's reference is kept verbatim and echoed by status and listing, and one the
    /// provider would not keep is refused before the quote is spent.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_owner_ref_is_kept_verbatim_and_a_bad_one_is_refused_before_the_quote_is_spent() {
        let directory = std::env::temp_dir().join(format!("owner-ref-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let ctx = ExecCtx {
            ln: Arc::new(OpenInvoiceLightning),
            ..executing(context(store.clone(), Uuid::new_v4()))
        };
        let client = pubky_transport::identity_from_secret(&[50; 32]);
        let reply = ask(
            &ctx,
            &client,
            SwapMessage::QuoteRequest(quote_request(&client, SwapDirection::Reverse, 100_000)),
        )
        .await;
        let Some(SwapMessage::Quote(quote)) = reply else {
            panic!("expected a quote, got {reply:?}");
        };
        let mut creation = owned_record(&client).swap_request.unwrap();
        creation.quote_id = quote.quote_id;

        creation.owner_ref = Some("x".repeat(OWNER_REF_MAX_LEN + 1));
        let (code, _) =
            refusal(ask(&ctx, &client, SwapMessage::SwapRequest(creation.clone())).await);
        assert_eq!(code, RejectCode::InvalidRequest);
        assert!(store.load_all_checked().unwrap().is_empty());

        creation.owner_ref = Some("index:7".into());
        let reply = ask(&ctx, &client, SwapMessage::SwapRequest(creation.clone())).await;
        let Some(SwapMessage::SwapAccept(accept)) = reply else {
            panic!("expected an acceptance, got {reply:?}");
        };

        let status = SwapStatusRequest {
            request_id: Some(Uuid::new_v4()),
            swap_id: Some(accept.swap_id),
            quote_id: None,
        };
        let reply = ask(&ctx, &client, SwapMessage::SwapStatusRequest(status)).await;
        let Some(SwapMessage::SwapStatusSnapshot(snapshot)) = reply else {
            panic!("expected a snapshot, got {reply:?}");
        };
        assert_eq!(snapshot.owner_ref.as_deref(), Some("index:7"));
        assert_eq!(snapshot.payment_hash_hex, creation.payment_hash_hex);
        assert!(snapshot.created_at_unix > 0);

        let listed = page(&ctx, &client, None, None, false).await;
        assert_eq!(ids(&listed), vec![accept.swap_id]);
        assert_eq!(listed.snapshots[0].owner_ref.as_deref(), Some("index:7"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn direct_requests_quote_for_their_key_and_refuse_provider_messages() {
        let directory = std::env::temp_dir().join(format!("direct-quote-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let ctx = context(store, Uuid::new_v4());
        let client = pubky_transport::identity_from_secret(&[44; 32]);

        let request_id = Some(Uuid::new_v4());
        let reply = ask(
            &ctx,
            &client,
            SwapMessage::OfferRequest(OfferRequest { request_id }),
        )
        .await;
        assert!(
            matches!(&reply, Some(SwapMessage::Offer(o)) if o.request_id == request_id
                && o.features.iter().any(|f| f == "direct-rpc-v1")),
            "{reply:?}"
        );

        let quote = QuoteRequest {
            request_id,
            offer_id: Uuid::nil(),
            client_pkarr: client.clone(),
            direction: SwapDirection::Reverse,
            amount_sat: 100_000,
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        };
        let reply = ask(&ctx, &client, SwapMessage::QuoteRequest(quote.clone())).await;
        let Some(SwapMessage::Quote(issued)) = reply else {
            panic!("expected a quote, got {reply:?}");
        };
        assert_eq!(issued.request_id, request_id);
        assert_eq!(
            issued.fund_within_secs,
            ProviderConfig::default().fund_within_secs
        );
        assert!(same_pubky_quote(&ctx, issued.quote_id, &client).await);

        // A request naming somebody else's key is refused.
        let other = pubky_transport::identity_from_secret(&[45; 32]);
        let reply = ask(&ctx, &other, SwapMessage::QuoteRequest(quote)).await;
        assert!(matches!(reply, Some(SwapMessage::Reject(_))), "{reply:?}");

        // Only customer requests are handled; anything else gets no reply at all.
        let reply = ask(&ctx, &client, SwapMessage::Quote(issued)).await;
        assert!(reply.is_none());
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// #107: a provider that never signs in to a homeserver still serves the whole negotiation
    /// over `direct/1`: offer, quote, creation and status. The fixture's transport is unsigned,
    /// and the only thing that could sign it in is a DM path, none of which runs here.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_provider_without_a_homeserver_negotiates_over_direct_requests() {
        let directory = std::env::temp_dir().join(format!("no-homeserver-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let config = ProviderConfig {
            homeserver: false,
            ..Default::default()
        };
        let ctx = ExecCtx {
            ln: Arc::new(OpenInvoiceLightning),
            homeserver: false,
            cap: Arc::new(crate::cap_adapter::CapState::ephemeral()),
            ..executing(context(store.clone(), Uuid::new_v4()))
        };
        let advertised = build_offer(
            &config,
            &pubky_transport::identity_from_secret(&[40; 32]),
            Network::Regtest,
            None,
            2,
            true,
        )
        .unwrap();
        let offer: SharedOffer = Arc::new(RwLock::new(Some(advertised)));
        let client = pubky_transport::identity_from_secret(&[47; 32]);
        let request_id = Some(Uuid::new_v4());

        let reply = ask_with(
            &ctx,
            offer.clone(),
            &client,
            SwapMessage::OfferRequest(OfferRequest { request_id }),
        )
        .await;
        let Some(SwapMessage::Offer(current)) = reply else {
            panic!("expected an offer, got {reply:?}");
        };
        assert!(current.features.iter().any(|f| f == "direct-rpc-v1"));
        assert!(
            !current.features.iter().any(|f| f == "dm-retention-v1"),
            "{:?}",
            current.features
        );

        let reply = ask_with(
            &ctx,
            offer.clone(),
            &client,
            SwapMessage::QuoteRequest(quote_request(&client, SwapDirection::Reverse, 100_000)),
        )
        .await;
        let Some(SwapMessage::Quote(quote)) = reply else {
            panic!("expected a quote, got {reply:?}");
        };

        let mut creation = owned_record(&client).swap_request.unwrap();
        creation.quote_id = quote.quote_id;
        let reply = ask_with(
            &ctx,
            offer.clone(),
            &client,
            SwapMessage::SwapRequest(creation),
        )
        .await;
        let Some(SwapMessage::SwapAccept(accept)) = reply else {
            panic!("expected an acceptance, got {reply:?}");
        };
        assert_eq!(accept.quote_id, quote.quote_id);

        let status = SwapStatusRequest {
            request_id,
            swap_id: Some(accept.swap_id),
            quote_id: None,
        };
        let reply = ask_with(&ctx, offer, &client, SwapMessage::SwapStatusRequest(status)).await;
        let Some(SwapMessage::SwapStatusSnapshot(snapshot)) = reply else {
            panic!("expected a status snapshot, got {reply:?}");
        };
        assert_eq!(snapshot.accept.swap_id, accept.swap_id);

        // Evicting an idle peer touches the poll set and nothing else: an unfollow would be the
        // messenger's first homeserver write.
        let idle = pubky_transport::identity_from_secret(&[48; 32]);
        ctx.transport.register_peer(&idle, false).unwrap();
        assert!(ctx.transport.get_known_peers().contains(&idle));
        evict_peer_if_idle(&ctx, &idle).await;
        assert!(!ctx.transport.get_known_peers().contains(&idle));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn access_changes_recheck_quotes_and_use_the_verified_session_owner() {
        let directory = std::env::temp_dir().join(format!("access-rpc-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let mut ctx = context(store.clone(), Uuid::new_v4());
        let file = directory.join("access.policy");
        ctx.access_policy_file = Some(file.display().to_string());
        let owner = pubky_transport::identity_from_secret(&[41; 32]);
        let device = pubky_transport::identity_from_secret(&[42; 32]);
        let write = |mode: &str, allowed: Vec<&str>, blocked: Vec<&str>| {
            std::fs::write(
                &file,
                serde_json::json!({
                    "mode": mode, "allowed": allowed, "blocked": blocked,
                })
                .to_string(),
            )
            .unwrap();
        };
        let request = QuoteRequest {
            request_id: Some(Uuid::new_v4()),
            offer_id: Uuid::nil(),
            client_pkarr: owner.clone(),
            direction: SwapDirection::Reverse,
            amount_sat: 100_000,
            protocol_version: PROTOCOL_VERSION,
            features: Vec::new(),
        };
        // A configured but absent file denies new business with a correlated response.
        let reply = ask(&ctx, &owner, SwapMessage::QuoteRequest(request.clone())).await;
        assert!(matches!(reply, Some(SwapMessage::Reject(r))
            if r.code.as_deref() == Some("access_denied") && r.request_id == request.request_id));
        write("approved_only", vec![&owner], vec![]);
        let reply = ask(&ctx, &owner, SwapMessage::QuoteRequest(request.clone())).await;
        let Some(SwapMessage::Quote(quote)) = reply else {
            panic!("{reply:?}");
        };
        write("open", vec![], vec![&owner]);
        let mut creation = owned_record(&owner).swap_request.unwrap();
        creation.quote_id = quote.quote_id;
        let reply = ask(&ctx, &owner, SwapMessage::SwapRequest(creation)).await;
        assert!(matches!(reply, Some(SwapMessage::Reject(r))
            if r.code.as_deref() == Some("access_denied") && r.quote_id == Some(quote.quote_id)));
        assert!(store.load_all_checked().unwrap().is_empty());

        // Exercise the shared handler after session verification, with an allowed device but
        // a blocked owner. The device cannot substitute its own key for the account policy.
        for (allowed, blocked, expected) in [
            (vec![device.as_str()], vec![owner.as_str()], false),
            (vec![owner.as_str()], vec![], true),
            (vec![owner.as_str()], vec![device.as_str()], false),
            (vec![device.as_str()], vec![], false),
        ] {
            write("approved_only", allowed, blocked);
            let (reply, answer) = tokio::sync::oneshot::channel();
            let mut session = ctx.clone();
            session.transport = Arc::new(ctx.transport.session(
                owner.clone(),
                "/pub/test/".into(),
                reply,
            ));
            let mut req = request.clone();
            req.client_pkarr = device.clone();
            handle_message(
                &session,
                offer().read().await.as_ref(),
                &device,
                SwapMessage::QuoteRequest(req),
            )
            .await
            .unwrap();
            let message: SwapMessage = serde_json::from_slice(&answer.await.unwrap()).unwrap();
            assert_eq!(matches!(message, SwapMessage::Quote(_)), expected);
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn quote_refusals_name_their_code_and_the_bound_that_was_missed() {
        let directory = std::env::temp_dir().join(format!("quote-codes-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let ctx = context(store, Uuid::new_v4());
        let client = pubky_transport::identity_from_secret(&[46; 32]);
        let current = offer().read().await.clone().unwrap();
        let min = current.effective_min_amount_sat();
        let max = current.max_amount_sat;

        let below = quote_request(&client, SwapDirection::Reverse, min - 1);
        let (code, reject) =
            refusal(ask(&ctx, &client, SwapMessage::QuoteRequest(below.clone())).await);
        assert_eq!(code, RejectCode::AmountBelowMinimum);
        assert!(
            reject.reason.contains(&min.to_string()),
            "{}",
            reject.reason
        );
        assert_eq!(reject.request_id, below.request_id);

        let above = quote_request(&client, SwapDirection::Reverse, max + 1);
        let (code, reject) = refusal(ask(&ctx, &client, SwapMessage::QuoteRequest(above)).await);
        assert_eq!(code, RejectCode::AmountAboveMaximum);
        assert!(
            reject.reason.contains(&max.to_string()),
            "{}",
            reject.reason
        );

        let mut stale = quote_request(&client, SwapDirection::Reverse, 100_000);
        stale.offer_id = Uuid::new_v4();
        let (code, _) = refusal(ask(&ctx, &client, SwapMessage::QuoteRequest(stale)).await);
        assert_eq!(code, RejectCode::OfferStale);

        let mut future = quote_request(&client, SwapDirection::Reverse, 100_000);
        future.protocol_version = PROTOCOL_VERSION + 1;
        let (code, _) = refusal(ask(&ctx, &client, SwapMessage::QuoteRequest(future)).await);
        assert_eq!(code, RejectCode::UnsupportedProtocol);

        let impostor = quote_request("somebody-else", SwapDirection::Reverse, 100_000);
        let (code, _) = refusal(ask(&ctx, &client, SwapMessage::QuoteRequest(impostor)).await);
        assert_eq!(code, RejectCode::InvalidRequest);

        let reverse_only = build_offer(
            &ProviderConfig {
                directions: vec![SwapDirection::Reverse],
                ..Default::default()
            },
            &pubky_transport::identity_from_secret(&[40; 32]),
            Network::Regtest,
            None,
            2,
            true,
        )
        .unwrap();
        let submarine = quote_request(&client, SwapDirection::Submarine, 100_000);
        let reply = ask_with(
            &ctx,
            Arc::new(RwLock::new(Some(reverse_only))),
            &client,
            SwapMessage::QuoteRequest(submarine),
        )
        .await;
        assert_eq!(refusal(reply).0, RejectCode::UnsupportedRoute);

        // Before the first offer is priced, offer and quote requests are answered rather than
        // left to time out. A status query needs no offer and is served as usual.
        let unpriced = || Arc::new(RwLock::new(None));
        let request_id = Some(Uuid::new_v4());
        let reply = ask_with(
            &ctx,
            unpriced(),
            &client,
            SwapMessage::OfferRequest(OfferRequest { request_id }),
        )
        .await;
        let (code, reject) = refusal(reply);
        assert_eq!(code, RejectCode::PricingUnavailable);
        assert_eq!(reject.request_id, request_id);
        let quote = quote_request(&client, SwapDirection::Reverse, 100_000);
        let reply = ask_with(&ctx, unpriced(), &client, SwapMessage::QuoteRequest(quote)).await;
        assert_eq!(refusal(reply).0, RejectCode::PricingUnavailable);
        let status = SwapStatusRequest {
            request_id,
            swap_id: Some(Uuid::new_v4()),
            quote_id: None,
        };
        let reply = ask_with(
            &ctx,
            unpriced(),
            &client,
            SwapMessage::SwapStatusRequest(status),
        )
        .await;
        assert_eq!(refusal(reply).0, RejectCode::NotFound);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn creation_refusals_name_their_code() {
        let directory = std::env::temp_dir().join(format!("creation-codes-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let client = pubky_transport::identity_from_secret(&[47; 32]);
        let creation = || owned_record(&client).swap_request.unwrap();

        // A negotiation-only provider quotes but cannot start anything.
        let idle = context(store.clone(), Uuid::new_v4());
        let unknown = creation();
        let reply = ask(&idle, &client, SwapMessage::SwapRequest(unknown.clone())).await;
        let (code, reject) = refusal(reply);
        assert_eq!(code, RejectCode::UnsupportedRoute);
        assert_eq!(reject.quote_id, Some(unknown.quote_id));

        let mut ctx = executing(context(store.clone(), Uuid::new_v4()));
        let reply = ask(&ctx, &client, SwapMessage::SwapRequest(unknown.clone())).await;
        let (code, reject) = refusal(reply);
        assert_eq!(code, RejectCode::QuoteExpired);
        assert_eq!(reject.quote_id, Some(unknown.quote_id));

        // Quoted while there was room, redeemed once there was none.
        let quote = quote_request(&client, SwapDirection::Reverse, 100_000);
        let Some(SwapMessage::Quote(quote)) =
            ask(&ctx, &client, SwapMessage::QuoteRequest(quote)).await
        else {
            panic!("expected a quote");
        };
        ctx.risk = risk::RiskManager::new(risk::RiskLimits {
            max_total_exposure_sat: 0,
            ..risk_limits(&ProviderConfig::default())
        });
        let mut redeem = creation();
        redeem.quote_id = quote.quote_id;
        let (code, _) = refusal(ask(&ctx, &client, SwapMessage::SwapRequest(redeem)).await);
        assert_eq!(code, RejectCode::LiquidityUnavailable);
        assert!(store.load_all_checked().unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Capacity and rate limits answer a quote request, which is the step a Paykit intent
    /// refusal maps to, and still bind when the quote is redeemed.
    #[tokio::test]
    async fn risk_limits_refuse_at_quote_time_and_again_at_creation() {
        let directory = std::env::temp_dir().join(format!("risk-codes-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let client = pubky_transport::identity_from_secret(&[48; 32]);
        let mut ctx = executing(context(store.clone(), Uuid::new_v4()));
        let quote =
            || SwapMessage::QuoteRequest(quote_request(&client, SwapDirection::Reverse, 100_000));

        ctx.risk = risk::RiskManager::new(risk::RiskLimits {
            max_concurrent_swaps: 0,
            max_concurrent_per_peer: 0,
            max_total_exposure_sat: 0,
            max_exposure_per_peer_sat: 0,
            ..risk_limits(&ProviderConfig::default())
        });
        let (code, reject) = refusal(ask(&ctx, &client, quote()).await);
        assert_eq!(code, RejectCode::LiquidityUnavailable);
        assert!(reject.reason.contains("limit is 0"), "{}", reject.reason);

        ctx.risk = risk::RiskManager::new(risk_limits(&ProviderConfig {
            max_new_swaps_per_peer_per_hour: 5,
            ..Default::default()
        }));
        for _ in 0..4 {
            drop(ctx.risk.reserve(&client, Uuid::new_v4(), 1_000).unwrap());
        }
        // Asking for quotes does not use up starts.
        for _ in 0..3 {
            assert!(matches!(
                ask(&ctx, &client, quote()).await,
                Some(SwapMessage::Quote(_))
            ));
        }
        let Some(SwapMessage::Quote(issued)) = ask(&ctx, &client, quote()).await else {
            panic!("expected a quote");
        };
        // The fifth start lands elsewhere, so redeeming this quote would be the sixth.
        drop(ctx.risk.reserve(&client, Uuid::new_v4(), 1_000).unwrap());
        let mut redeem = owned_record(&client).swap_request.unwrap();
        redeem.quote_id = issued.quote_id;
        let (code, reject) = refusal(ask(&ctx, &client, SwapMessage::SwapRequest(redeem)).await);
        assert_eq!(code, RejectCode::RateLimited);
        assert_eq!(reject.quote_id, Some(issued.quote_id));
        assert!(store.load_all_checked().unwrap().is_empty());
        let (code, _) = refusal(ask(&ctx, &client, quote()).await);
        assert_eq!(code, RejectCode::RateLimited);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A wallet that reports a balance, and never funds anything: the tests below are refused,
    /// or stop, before any funding.
    struct BalanceWallet(std::sync::atomic::AtomicU64);

    impl BalanceWallet {
        fn new(balance_sat: u64) -> Arc<Self> {
            Arc::new(Self(std::sync::atomic::AtomicU64::new(balance_sat)))
        }

        fn set(&self, balance_sat: u64) {
            self.0.store(balance_sat, Ordering::SeqCst);
        }
    }

    impl OnchainWallet for BalanceWallet {
        fn fund_htlc(
            &self,
            _htlc_spk: &ScriptBuf,
            _amount_sat: u64,
        ) -> swap_common::Result<OutPoint> {
            Err(swap_common::SwapError::Other(
                "this test wallet never funds".into(),
            ))
        }

        fn receive_destination(&self) -> ScriptBuf {
            ScriptBuf::new()
        }

        fn spendable_balance_sat(&self) -> swap_common::Result<Option<u64>> {
            Ok(Some(self.0.load(Ordering::SeqCst)))
        }
    }

    /// A reverse swap takes the client's Lightning payment before it funds, so a wallet that
    /// cannot fund it must refuse at creation. Before #108 an `--wallet lnd` provider reported no
    /// balance, skipped this check, and held the client's payment until the HTLC timed out.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_underfunded_wallet_refuses_a_reverse_swap_before_any_invoice() {
        let directory = std::env::temp_dir().join(format!("underfunded-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let client = pubky_transport::identity_from_secret(&[49; 32]);
        let wallet = BalanceWallet::new(50_000);
        let ctx = ExecCtx {
            wallet: Some(wallet.clone()),
            ..executing(context(store.clone(), Uuid::new_v4()))
        };

        let quote = quote_request(&client, SwapDirection::Reverse, 100_000);
        let Some(SwapMessage::Quote(quote)) =
            ask(&ctx, &client, SwapMessage::QuoteRequest(quote)).await
        else {
            panic!("expected a quote");
        };
        let mut redeem = owned_record(&client).swap_request.unwrap();
        redeem.quote_id = quote.quote_id;
        let (code, reject) = refusal(ask(&ctx, &client, SwapMessage::SwapRequest(redeem)).await);
        assert_eq!(code, RejectCode::LiquidityUnavailable);
        assert!(
            reject.reason.contains("50000 sat available"),
            "{}",
            reject.reason
        );
        // No record means no hold invoice: the stand-in Lightning node refuses to create one
        // without a persisted owner.
        assert!(store.load_all_checked().unwrap().is_empty());
        assert_eq!(ctx.risk.claimed_funding_sat(), 0);
        assert_eq!(ctx.risk.in_flight(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Each reverse swap used to be checked against the whole balance, so two admitted together
    /// could each pass and jointly promise more than the wallet held. The first now claims its
    /// funding until it records it.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_reverse_admissions_cannot_overcommit_the_wallet() {
        let directory = std::env::temp_dir().join(format!("overcommit-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let wallet = BalanceWallet::new(150_000);
        let ctx = ExecCtx {
            wallet: Some(wallet.clone()),
            ..executing(context(store.clone(), Uuid::new_v4()))
        };
        let claim = funding_claim_sat(&ctx, 100_000);
        assert!(claim < 150_000 && 2 * claim > 150_000);

        let first = Uuid::new_v4();
        let _first = reserve_for_swap(&ctx, "alice", first, SwapDirection::Reverse, 100_000)
            .await
            .unwrap();
        assert_eq!(ctx.risk.claimed_funding_sat(), claim);

        let error = reserve_for_swap(&ctx, "bob", Uuid::new_v4(), SwapDirection::Reverse, 100_000)
            .await
            .err()
            .expect("the second swap does not fit beside the first");
        assert_eq!(refusal_code(&error), RejectCode::LiquidityUnavailable);
        assert!(
            error
                .to_string()
                .contains("promised to swaps not yet funded"),
            "{error}"
        );

        // Submarine swaps are funded by the client and claim nothing from the wallet.
        let _submarine = reserve_for_swap(
            &ctx,
            "carol",
            Uuid::new_v4(),
            SwapDirection::Submarine,
            100_000,
        )
        .await
        .unwrap();
        assert_eq!(ctx.risk.claimed_funding_sat(), claim);

        // The first swap funds: its coins leave the wallet, and recording the outpoint ends its
        // claim, so what is left is counted once rather than twice.
        let mut record = SwapRecord::new_progress();
        record.swap_id = first;
        let progress = StoreProgress {
            store: store.clone(),
            record: std::sync::Mutex::new(record),
            risk: Some(ctx.risk.clone()),
        };
        progress.funded(OutPoint::null());
        wallet.set(150_000 - claim);
        assert_eq!(ctx.risk.claimed_funding_sat(), 0);
        let _third = reserve_for_swap(&ctx, "dave", Uuid::new_v4(), SwapDirection::Reverse, 40_000)
            .await
            .unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Clients match these strings today, so they stay byte-identical.
    #[tokio::test]
    async fn status_refusals_keep_their_strings() {
        let directory = std::env::temp_dir().join(format!("status-codes-{}", Uuid::new_v4()));
        let store = Arc::new(JsonFileSwapStore::new(&directory).unwrap());
        let owner = pubky_transport::identity_from_secret(&[49; 32]);
        let mut record = invoice_intent();
        record.peer = owner.clone();
        record.swap_request.as_mut().unwrap().client_pkarr = owner.clone();
        store.put(&record).unwrap();
        let ctx = context(store, record.swap_id);
        let status = |swap_id, quote_id| {
            SwapMessage::SwapStatusRequest(SwapStatusRequest {
                request_id: Some(Uuid::new_v4()),
                swap_id,
                quote_id,
            })
        };

        let (_, reject) = refusal(ask(&ctx, &owner, status(Some(record.swap_id), None)).await);
        assert_eq!(reject.code.as_deref(), Some("pending"));
        let (_, reject) = refusal(ask(&ctx, &owner, status(Some(Uuid::new_v4()), None)).await);
        assert_eq!(reject.code.as_deref(), Some("not_found"));
        let quote_id = record.swap_request.as_ref().unwrap().quote_id;
        let both = status(Some(record.swap_id), Some(quote_id));
        assert_eq!(
            refusal(ask(&ctx, &owner, both).await).0,
            RejectCode::InvalidRequest
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    async fn same_pubky_quote(ctx: &ExecCtx, quote_id: Uuid, peer: &str) -> bool {
        ctx.quotes
            .lock()
            .await
            .quotes
            .get(&quote_id)
            .is_some_and(|quote| quote.peer == peer)
    }
}
