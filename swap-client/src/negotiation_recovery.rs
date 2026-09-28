//! Recover the exact creation intent before allowing a new swap or moving funds.

use crate::negotiate::{self, Channel, Negotiator};
use crate::{store, ClientConfig};
use anyhow::{anyhow, Context, Result};
use bitcoin::{Network, PublicKey, ScriptBuf};
use std::path::Path;
use swap_common::htlc::{build_htlc_script, htlc_p2wsh_address, payment_hash};
use swap_common::messages::{Quote, SwapAccept, SwapMessage, SwapScript};
use swap_common::store::{JsonFileSwapStore, SwapRecord, SwapRole, SwapStore};
use swap_common::validate::{self, ClientPolicy, DecodedHoldInvoice};
use swap_common::SwapDirection;
use tracing::warn;

/// Attempt every incomplete negotiation. The caller still resumes funded records on failure.
pub(crate) async fn recover_pending(
    store: &JsonFileSwapStore,
    config: &ClientConfig,
    network: Network,
) -> Result<()> {
    let records = store.load_all_checked()?;
    let pending: Vec<_> = records
        .iter()
        .filter(|record| {
            record.role == SwapRole::Client
                && !record.state.is_terminal()
                && !store::execution_ready(record)
        })
        .cloned()
        .collect();
    let mut failures = Vec::new();
    for record in pending {
        if !record.client_creation_started
            && record.swap_accept.is_none()
            && !record.funds_at_risk()
            && record
                .client_quote
                .as_ref()
                .is_some_and(|quote| quote.is_expired(crate::now_unix()))
        {
            store::record_terminal(store, record.swap_id, swap_common::SwapState::Expired)?;
            continue;
        }
        if let Err(error) = recover_one(store, config, network, &record).await {
            warn!(
                "negotiation recovery for {} remains pending: {error}",
                record.swap_id
            );
            failures.push(record.swap_id);
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "{} creation intent(s) remain unresolved; recover them before starting another swap",
        failures.len()
    ))
}

/// Retry cleanup only where a prior DM run created an outbox. Direct-only histories stay offline.
pub(crate) async fn maintain_completed(store: &JsonFileSwapStore, config: &ClientConfig) {
    let Ok(records) = store.load_all_checked() else {
        warn!("completed swap message cleanup could not read saved records");
        return;
    };
    let mut journals =
        std::collections::BTreeMap::<(String, String), Vec<(String, Option<u64>)>>::new();
    for record in records {
        if record.role != SwapRole::Client {
            continue;
        }
        let deadline = store::cleanup_deadline(&record);
        let Some(request) = &record.swap_request else {
            continue;
        };
        let (Ok(owner), Ok(peer)) = (
            pubky_transport::canonical_pubky(&request.client_pkarr),
            pubky_transport::canonical_pubky(&record.peer),
        ) else {
            continue;
        };
        journals.entry((owner, peer)).or_default().push((
            SwapMessage::SwapRequest(request.clone()).delivery_scope(),
            deadline,
        ));
    }
    for ((owner, peer), scopes) in journals {
        let path = Path::new(&config.data_dir)
            .join("transport")
            .join(&owner)
            .join(&peer)
            .join("outbox.json");
        if !path.is_file() {
            continue;
        }
        let maintenance = async {
            let identity = config.identity()?;
            let transport = pubky_transport::Transport::unsigned_from_recovery(
                identity.method,
                &identity.value,
                &identity.passphrase,
            )?;
            if transport.public_key_string() != owner {
                return Err(anyhow!("cleanup journal belongs to a different identity"));
            }
            let transport = transport.with_outbox(path)?;
            let eligible = scopes.iter().any(|(_, deadline)| {
                deadline.is_some_and(|deadline| deadline <= crate::now_unix())
            });
            for (scope, deadline) in scopes {
                match deadline {
                    Some(deadline) => transport.complete_scope(&peer, &scope, deadline)?,
                    None => transport.reopen_scope(&peer, &scope)?,
                }
            }
            if !eligible {
                return Ok(());
            }
            transport.process_outbox(crate::now_unix(), 8).await?;
            Ok::<_, anyhow::Error>(())
        };
        if !matches!(
            tokio::time::timeout(std::time::Duration::from_secs(2), maintenance).await,
            Ok(Ok(()))
        ) {
            warn!("completed swap message cleanup remains pending");
        }
    }
}

async fn recover_one(
    store: &JsonFileSwapStore,
    config: &ClientConfig,
    network: Network,
    record: &SwapRecord,
) -> Result<()> {
    if record.network != swap_common::NetworkSpec::from_bitcoin_network(network)? {
        return Err(anyhow!("saved swap uses a different Bitcoin network"));
    }
    validate_intent(record)?;
    let chain = crate::build_chain(config).ok();
    let current_tip = chain
        .as_ref()
        .map(|chain| swap_common::chain::run_blocking(|| chain.tip_height()))
        .transpose()
        .context("read chain tip for negotiation recovery")?;
    let accept = if let Some(accept) = &record.swap_accept {
        accept.clone()
    } else {
        let identity = config.identity()?;
        let (negotiator, owner) = negotiate::connect_durable(
            &identity,
            &record.peer,
            config.negotiation,
            config.rendezvous_iroh,
            Path::new(&config.data_dir),
        )
        .await?;
        let result = async {
            let request = record
                .swap_request
                .as_ref()
                .context("missing saved creation request")?;
            if !pubky_transport::same_pubky(&request.client_pkarr, &owner) {
                return Err(anyhow!("saved creation belongs to another client identity"));
            }
            obtain_acceptance(store, record, &negotiator, current_tip).await
        }
        .await;
        negotiator.close().await;
        result?
    };
    // Re-read the record because obtaining the reply may have pinned the creation tip.
    let record = store
        .get(record.swap_id)?
        .context("creation record disappeared")?;
    let policy = crate::client_policy(config, network);
    validate_contract(&record, &accept, network, &policy, current_tip)?;
    let tip = current_tip.context("chain access is required before recovering execution")?;
    validate_execution_window(&record, &accept, &policy, tip)?;
    let quote = record
        .client_quote
        .as_ref()
        .context("missing saved quote")?;
    if record.direction == SwapDirection::Reverse {
        let ln = crate::make_backend(config).await?;
        let invoice = accept
            .invoice
            .as_ref()
            .context("reverse acceptance lacks invoice")?;
        let decoded = ln
            .decode_invoice(invoice)
            .await
            .map_err(|error| anyhow!("decode the saved hold invoice: {error}"))?;
        validate::validate_hold_invoice(
            &DecodedHoldInvoice {
                payment_hash: decoded.payment_hash,
                amount_msat: decoded.amount_msat,
                amount_is_explicit: decoded.amount_is_explicit,
                expires_at_unix: decoded.expires_at_unix,
            },
            quote,
            &record.payment_hash()?,
            crate::now_unix(),
            &policy,
        )
        .context("validate the saved hold invoice before payment")?;
    }
    let destination = match record.dest_spk()? {
        Some(destination) => destination,
        None if record.direction == SwapDirection::Reverse
            && !crate::wallet_is_self_sufficient(config) =>
        {
            crate::parse_address_spk(&config.claim_address, network)?
        }
        None => crate::build_wallet(config, network)
            .await?
            .receive_destination(),
    };
    store::record_accept(
        store,
        record.swap_id,
        &accept,
        hex::encode(destination.as_bytes()),
    )
}

/// Persist before sending, and persist the entire response before acknowledging it.
async fn obtain_acceptance<P: Channel, F: Channel>(
    store: &dyn SwapStore,
    record: &SwapRecord,
    negotiator: &Negotiator<P, F>,
    tip: Option<u32>,
) -> Result<SwapAccept> {
    let request = record
        .swap_request
        .as_ref()
        .context("missing saved creation request")?;
    store::record_creation_started(store, record.swap_id, tip)?;
    let accept = if record.client_creation_started {
        negotiator.recover_creation(request).await?
    } else {
        negotiator.create(request).await?
    };
    store::record_creation_reply(store, record.swap_id, &accept)?;
    negotiator.acknowledge(&SwapMessage::SwapRequest(request.clone()))?;
    Ok(accept)
}

fn validate_intent(record: &SwapRecord) -> Result<&Quote> {
    let request = record
        .swap_request
        .as_ref()
        .context("missing saved creation request")?;
    let quote = record
        .client_quote
        .as_ref()
        .context("missing saved quote")?;
    let our_key = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &record.secret_key()?,
    ));
    let expected_key = hex::encode(our_key.to_bytes());
    let branch = match record.direction {
        SwapDirection::Reverse => request.client_claim_pubkey_hex.as_deref(),
        SwapDirection::Submarine => request.client_refund_pubkey_hex.as_deref(),
    };
    if request.script_type != SwapScript::P2wsh
        || request.quote_id != quote.quote_id
        || request.direction != record.direction
        || quote.direction != record.direction
        || request.payment_hash_hex != record.payment_hash_hex
        || quote.total_sat != record.quote_total_sat
        || branch != Some(expected_key.as_str())
    {
        return Err(anyhow!(
            "saved creation request does not match its keys and quote"
        ));
    }
    match record.direction {
        SwapDirection::Reverse => {
            let preimage = record
                .preimage()?
                .context("reverse creation lacks preimage")?;
            if payment_hash(&preimage) != record.payment_hash()? {
                return Err(anyhow!(
                    "saved preimage does not match the creation payment hash"
                ));
            }
        }
        SwapDirection::Submarine if request.invoice.as_deref() != Some(record.invoice.as_str()) => {
            return Err(anyhow!(
                "saved creation does not match its submarine invoice"
            ))
        }
        _ => {}
    }
    Ok(quote)
}

fn validate_contract(
    record: &SwapRecord,
    accept: &SwapAccept,
    network: Network,
    policy: &ClientPolicy,
    current_tip: Option<u32>,
) -> Result<ScriptBuf> {
    let quote = validate_intent(record)?;
    if accept.script_type != SwapScript::P2wsh || accept.swap_tree.is_some() {
        return Err(anyhow!("saved acceptance uses an unexpected contract type"));
    }
    // A restart must not move the quote's creation anchor forward with the current tip.
    validate::validate_accept(
        accept,
        quote,
        record.client_creation_tip.or(current_tip),
        policy,
    )
    .context("validate the recovered acceptance against its saved quote")?;
    let ours = PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
        &bitcoin::secp256k1::Secp256k1::new(),
        &record.secret_key()?,
    ));
    let theirs = crate::parse_pubkey(&accept.provider_pubkey_hex)?;
    let (claim, refund) = match record.direction {
        SwapDirection::Reverse => (ours, theirs),
        SwapDirection::Submarine => (theirs, ours),
    };
    let script = build_htlc_script(
        &record.payment_hash()?,
        &claim,
        &refund,
        accept.timeout_block_height,
    );
    if hex::encode(script.as_bytes()) != accept.htlc_script_hex
        || htlc_p2wsh_address(&script, network).to_string() != accept.htlc_address
    {
        return Err(anyhow!(
            "recovered HTLC does not match the saved payment hash and branch key"
        ));
    }
    Ok(script)
}

fn validate_execution_window(
    record: &SwapRecord,
    accept: &SwapAccept,
    policy: &ClientPolicy,
    tip: u32,
) -> Result<()> {
    let mut timelock = policy.timelock;
    timelock.required_confirmations = record
        .required_confirmations
        .max(policy.min_required_confirmations);
    match record.direction {
        SwapDirection::Reverse => swap_common::timelock::check_client_reverse_accept(
            tip,
            accept.timeout_block_height,
            &timelock,
        ),
        SwapDirection::Submarine => swap_common::timelock::check_client_submarine_accept(
            tip,
            accept.timeout_block_height,
            &timelock,
        ),
    }
    .context("recovered HTLC no longer has enough time to start execution")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiate::{ExchangeError, Unavailable};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use std::time::Duration;
    use swap_common::messages::{SwapRequest, PROTOCOL_VERSION};
    use uuid::Uuid;

    fn fixture() -> (
        std::path::PathBuf,
        JsonFileSwapStore,
        SwapRecord,
        SwapAccept,
    ) {
        let dir = std::env::temp_dir().join(format!("client-negotiation-{}", Uuid::new_v4()));
        let store = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let (secret, public) = swap_common::random_keypair(&secp);
        let (_, provider) = swap_common::random_keypair(&secp);
        let preimage = [4; 32];
        let hash = payment_hash(&preimage);
        let quote = Quote {
            request_id: Some(Uuid::new_v4()),
            quote_id: Uuid::new_v4(),
            offer_id: Uuid::nil(),
            direction: SwapDirection::Reverse,
            amount_sat: 50_000,
            fee_sat: 100,
            service_fee_sat: 100,
            onchain_fee_sat: 0,
            fee_rate_sat_vb: 1,
            total_sat: 50_100,
            htlc_timeout_blocks: 144,
            required_confirmations: 1,
            valid_until_unix: u64::MAX,
            protocol_version: PROTOCOL_VERSION,
        };
        let request = SwapRequest {
            script_type: SwapScript::P2wsh,
            quote_id: quote.quote_id,
            client_pkarr: pubky_transport::identity_from_secret(&[3; 32]),
            direction: SwapDirection::Reverse,
            payment_hash_hex: hex::encode(hash),
            client_claim_pubkey_hex: Some(hex::encode(public.to_bytes())),
            client_refund_pubkey_hex: None,
            invoice: None,
        };
        let new = store::NewClientSwap {
            swap_id: Uuid::new_v4(),
            direction: SwapDirection::Reverse,
            peer: pubky_transport::identity_from_secret(&[8; 32]),
            network: swap_common::NetworkSpec::Regtest,
            payment_hash: hash,
            branch_key: secret.secret_bytes(),
            preimage: Some(preimage),
            invoice: String::new(),
            quote_total_sat: quote.total_sat,
            required_confirmations: 1,
            fee_rate_sat_vb: 1,
        };
        store::record_negotiation_intent(&store, &new, &quote, &request).unwrap();
        let script = build_htlc_script(&hash, &public, &provider, 244);
        let accept = SwapAccept {
            script_type: SwapScript::P2wsh,
            swap_tree: None,
            quote_id: quote.quote_id,
            swap_id: Uuid::new_v4(),
            direction: SwapDirection::Reverse,
            htlc_script_hex: hex::encode(script.as_bytes()),
            htlc_address: htlc_p2wsh_address(&script, Network::Regtest).to_string(),
            onchain_amount_sat: quote.amount_sat,
            timeout_block_height: 244,
            provider_pubkey_hex: hex::encode(provider.to_bytes()),
            invoice: Some("saved-hold-invoice".into()),
        };
        let record = store.get(new.swap_id).unwrap().unwrap();
        (dir, store, record, accept)
    }

    struct SavedReply<'a> {
        store: &'a dyn SwapStore,
        swap_id: Uuid,
        accept: SwapAccept,
        sent: Mutex<Vec<SwapRequest>>,
        acknowledgments: AtomicUsize,
    }

    impl Channel for SavedReply<'_> {
        const NAME: &'static str = "persisted test reply";
        async fn exchange(
            &self,
            message: &SwapMessage,
            _: fn(&SwapMessage) -> bool,
        ) -> std::result::Result<SwapMessage, ExchangeError> {
            let SwapMessage::SwapRequest(request) = message else {
                panic!("expected exact creation replay")
            };
            let record = self.store.get(self.swap_id).unwrap().unwrap();
            assert!(
                record.client_creation_started,
                "creation marker precedes publication"
            );
            self.sent.lock().unwrap().push(request.clone());
            Ok(SwapMessage::SwapAccept(self.accept.clone()))
        }
        fn acknowledge(&self, _: &SwapMessage) -> Result<()> {
            let record = self.store.get(self.swap_id)?.unwrap();
            assert_eq!(record.swap_accept.as_ref(), Some(&self.accept));
            assert_eq!(record.invoice, self.accept.invoice.clone().unwrap());
            assert!(!record.client_execution_ready);
            self.acknowledgments.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn restart_replays_exact_creation_and_persists_full_reply_before_acknowledgment() {
        let (dir, store, record, accept) = fixture();
        store::record_creation_started(&store, record.swap_id, Some(100)).unwrap();
        drop(store);
        let store = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let record = store.get(record.swap_id).unwrap().unwrap();
        let channel = SavedReply {
            store: &store,
            swap_id: record.swap_id,
            accept: accept.clone(),
            sent: Mutex::new(Vec::new()),
            acknowledgments: AtomicUsize::new(0),
        };
        let negotiator = Negotiator::<_, Unavailable>::new(Some(channel), None);
        obtain_acceptance(&store, &record, &negotiator, Some(120))
            .await
            .unwrap();
        let channel = negotiator.preferred().unwrap();
        assert_eq!(
            *channel.sent.lock().unwrap(),
            vec![record.swap_request.clone().unwrap()]
        );
        assert_eq!(channel.acknowledgments.load(Ordering::SeqCst), 1);
        let saved = store.get(record.swap_id).unwrap().unwrap();
        assert_eq!(saved.client_creation_tip, Some(100));
        assert!(!store::execution_ready(&saved));
        drop(negotiator);
        drop(store);
        let reopened = JsonFileSwapStore::new(dir.join("swaps")).unwrap();
        let saved = reopened.get(record.swap_id).unwrap().unwrap();
        assert_eq!(saved.swap_accept, Some(accept));
        assert_eq!(saved.invoice, "saved-hold-invoice");
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct FailedAcceptance(JsonFileSwapStore);
    impl SwapStore for FailedAcceptance {
        fn mutate(&self, id: Uuid, operation: &mut dyn FnMut(&mut SwapRecord)) -> Result<bool> {
            self.0.mutate(id, operation)
        }
        fn put(&self, record: &SwapRecord) -> Result<()> {
            if record.swap_accept.is_some() {
                return Err(anyhow!("simulated durable write failure"));
            }
            self.0.put(record)
        }
        fn get(&self, id: Uuid) -> Result<Option<SwapRecord>> {
            self.0.get(id)
        }
        fn load_active(&self) -> Result<Vec<SwapRecord>> {
            self.0.load_active()
        }
        fn load_all(&self) -> Result<Vec<SwapRecord>> {
            self.0.load_all()
        }
        fn mark_terminal(&self, record: &SwapRecord) -> Result<()> {
            self.0.mark_terminal(record)
        }
        fn prune_terminal(&self, retain: Duration) -> Result<usize> {
            self.0.prune_terminal(retain)
        }
    }

    #[tokio::test]
    async fn failed_acceptance_write_keeps_the_receipt_unacknowledged() {
        let (dir, store, record, accept) = fixture();
        let store = FailedAcceptance(store);
        let channel = SavedReply {
            store: &store,
            swap_id: record.swap_id,
            accept,
            sent: Mutex::new(Vec::new()),
            acknowledgments: AtomicUsize::new(0),
        };
        let negotiator = Negotiator::<_, Unavailable>::new(Some(channel), None);
        assert!(obtain_acceptance(&store, &record, &negotiator, Some(100))
            .await
            .is_err());
        assert_eq!(
            negotiator
                .preferred()
                .unwrap()
                .acknowledgments
                .load(Ordering::SeqCst),
            0
        );
        assert!(store
            .get(record.swap_id)
            .unwrap()
            .unwrap()
            .swap_accept
            .is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovered_contract_uses_original_tip_and_still_checks_remaining_execution_time() {
        let (dir, _, mut record, accept) = fixture();
        record.client_creation_tip = Some(100);
        let policy = ClientPolicy::for_network(Network::Regtest, Default::default());
        validate_contract(&record, &accept, Network::Regtest, &policy, Some(120)).unwrap();
        validate_execution_window(&record, &accept, &policy, 120).unwrap();
        assert!(validate::validate_accept(
            &accept,
            record.client_quote.as_ref().unwrap(),
            Some(120),
            &policy
        )
        .is_err());
        assert!(validate_execution_window(&record, &accept, &policy, 240).is_err());
        let mut changed = accept.clone();
        changed.htlc_script_hex = "00".into();
        assert!(
            validate_contract(&record, &changed, Network::Regtest, &policy, Some(120)).is_err()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn saved_acceptance_cannot_change_and_only_validated_records_can_execute() {
        let (dir, store, record, accept) = fixture();
        store::record_creation_reply(&store, record.swap_id, &accept).unwrap();
        let mut changed = accept.clone();
        changed.invoice = Some("different-invoice".into());
        assert!(store::record_creation_reply(&store, record.swap_id, &changed).is_err());
        assert!(!store::execution_ready(
            &store.get(record.swap_id).unwrap().unwrap()
        ));
        store::record_accept(&store, record.swap_id, &accept, "0014".into()).unwrap();
        assert!(store::execution_ready(
            &store.get(record.swap_id).unwrap().unwrap()
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn expired_intent_that_was_never_sent_does_not_require_identity_or_block_recovery() {
        let (dir, store, mut record, _) = fixture();
        record.client_quote.as_mut().unwrap().valid_until_unix = 1;
        store.put(&record).unwrap();
        let config = ClientConfig {
            data_dir: dir.to_string_lossy().into_owned(),
            ..ClientConfig::default()
        };
        assert!(config.identity().is_err());
        recover_pending(&store, &config, Network::Regtest)
            .await
            .unwrap();
        let saved = store.get(record.swap_id).unwrap().unwrap();
        assert_eq!(saved.state, swap_common::SwapState::Expired);
        assert!(!saved.client_creation_started);
        assert!(store::unfinished(&store).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cleanup_requires_safe_completion_a_timestamp_and_retention_grace() {
        let (dir, _, mut record, _) = fixture();
        record.state = swap_common::SwapState::Claimed;
        assert_eq!(store::cleanup_deadline(&record), None);
        record.updated_at_unix = 100;
        assert_eq!(store::cleanup_deadline(&record), Some(86_500));
        record.state = swap_common::SwapState::Failed("backend unavailable".into());
        assert_eq!(store::cleanup_deadline(&record), None);
        record.state = swap_common::SwapState::Expired;
        assert_eq!(store::cleanup_deadline(&record), Some(86_500));
        record.invoice_pay_started_at_unix = Some(90);
        assert_eq!(store::cleanup_deadline(&record), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reopened_swap_revokes_cleanup_until_a_new_safe_terminal_timestamp() {
        let (dir, store, record, _) = fixture();
        store::record_terminal(&store, record.swap_id, swap_common::SwapState::Claimed).unwrap();
        let mut saved = store.get(record.swap_id).unwrap().unwrap();
        let first = store::cleanup_deadline(&saved).unwrap();
        saved.state = swap_common::SwapState::ClaimPending;
        store.put(&saved).unwrap();
        assert_eq!(
            store::cleanup_deadline(&store.get(record.swap_id).unwrap().unwrap()),
            None
        );
        saved.state = swap_common::SwapState::Claimed;
        saved.updated_at_unix += 600;
        store.put(&saved).unwrap();
        assert_eq!(
            store::cleanup_deadline(&store.get(record.swap_id).unwrap().unwrap()),
            Some(first + 600)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
