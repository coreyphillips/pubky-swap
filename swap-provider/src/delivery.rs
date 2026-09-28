//! Retry durable publications and retain completed swap messages for a recovery grace period.
//!
//! Only owned transport resources are cleaned here. Local swap records, branch keys, replay
//! protection and status recovery retain their independent policies.

use crate::ExecCtx;
use std::time::Duration;
use swap_common::{
    messages::{SwapMessage, SwapStatusUpdate},
    store::{SwapRecord, SwapRole},
    SwapState,
};
use tracing::warn;

const RECOVERY_GRACE: u64 = 24 * 60 * 60;
const RETRY_TICK: Duration = Duration::from_secs(2);
const DELIVERY_BATCH: usize = 4;

pub(crate) fn spawn(ctx: &ExecCtx) {
    let ctx = ctx.clone();
    tokio::spawn(async move {
        loop {
            let now = crate::now_unix();
            // A reorg or recovery can make a formerly terminal swap active. Refresh eligibility
            // before every batch, and retain all resources when the persisted state is unreadable.
            if refresh_retention(&ctx, now).await
                && ctx
                    .transport
                    .process_outbox(now, DELIVERY_BATCH)
                    .await
                    .is_err()
            {
                warn!("message outbox remains pending after a delivery or cleanup failure");
            }
            tokio::time::sleep(RETRY_TICK).await;
        }
    });
}

/// Persist cleanup ownership before the local record pruner removes old terminal records.
pub(crate) async fn refresh_retention(ctx: &ExecCtx, now: u64) -> bool {
    let store = ctx.store.clone();
    let records = match tokio::task::spawn_blocking(move || store.load_all_checked()).await {
        Ok(Ok(records)) => records,
        _ => {
            warn!("could not read persisted swap outcomes for message retention");
            return false;
        }
    };
    let mut complete = true;
    for record in records {
        if record.role == SwapRole::Provider
            && record.state.is_terminal()
            && record.updated_at_unix == 0
        {
            warn!("terminal swap has no persisted timestamp; retaining its message resources");
            complete = false;
        }
        if schedule_retention(&ctx.transport, &record, now).is_err() {
            warn!("could not persist swap message cleanup eligibility");
            complete = false;
        }
    }
    complete
}

fn schedule_retention(
    transport: &pubky_transport::Transport,
    record: &SwapRecord,
    now: u64,
) -> pubky_transport::Result<()> {
    if record.role != SwapRole::Provider
        || record.peer_account.is_some()
        || !has_dm_history(transport, record)?
    {
        return Ok(());
    }
    let Some((scopes, eligible_after)) = cleanup_plan(record) else {
        for scope in delivery_scopes(record) {
            transport.reopen_scope(&record.peer, &scope)?;
        }
        return Ok(());
    };
    if now < eligible_after {
        // A crash can land between persisting the outcome and preparing its final reply.
        // Recreate that durable publication only inside its recovery window, using exactly
        // the same payload as the driver. Once the window ends, status queries recover it.
        let update = SwapMessage::SwapStatusUpdate(SwapStatusUpdate {
            swap_id: record.swap_id,
            state: record.state.clone(),
            reference: None,
        });
        transport.enqueue_with_scope(&record.peer, &update.delivery_scope(), &update)?;
    }
    for scope in scopes {
        transport.complete_scope(&record.peer, &scope, eligible_after)?;
    }
    Ok(())
}

/// A persisted terminal outcome controls transport retention, never a driver return alone.
fn cleanup_plan(record: &SwapRecord) -> Option<(Vec<String>, u64)> {
    if record.role != SwapRole::Provider
        || record.pending_hold_invoice.is_some()
        || record.peer_account.is_some()
        || record.updated_at_unix == 0
    {
        return None;
    }
    let settled = match record.state {
        SwapState::Claimed | SwapState::Refunded => true,
        SwapState::Expired => !record.funds_at_risk(),
        // Failed may describe funds still awaiting recovery. It never starts cleanup here.
        _ => false,
    };
    if !settled {
        return None;
    }
    Some((
        delivery_scopes(record),
        record.updated_at_unix.saturating_add(RECOVERY_GRACE),
    ))
}

/// A root-key direct request has no account marker. Only retained DM resources establish that
/// this swap used DM delivery, including a direct request that later fell back to DMs.
pub(crate) fn has_dm_history(
    transport: &pubky_transport::Transport,
    record: &SwapRecord,
) -> pubky_transport::Result<bool> {
    for scope in delivery_scopes(record) {
        if transport.has_outbox_scope(&record.peer, &scope)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn delivery_scopes(record: &SwapRecord) -> Vec<String> {
    let mut scopes = vec![format!("swap:{}", record.swap_id)];
    if let Some(request) = &record.swap_request {
        scopes.push(format!("quote:{}", request.quote_id));
    } else if let Some(accept) = &record.swap_accept {
        scopes.push(format!("quote:{}", accept.quote_id));
    }
    scopes
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_common::{
        messages::{SwapAccept, SwapRequest},
        SwapDirection,
    };
    use uuid::Uuid;

    fn record(state: SwapState) -> SwapRecord {
        SwapRecord {
            swap_id: Uuid::new_v4(),
            peer: "peer".into(),
            role: SwapRole::Provider,
            direction: SwapDirection::Reverse,
            state,
            updated_at_unix: 100,
            swap_request: Some(SwapRequest {
                script_type: Default::default(),
                quote_id: Uuid::new_v4(),
                client_pkarr: "peer".into(),
                direction: SwapDirection::Reverse,
                payment_hash_hex: "00".repeat(32),
                client_claim_pubkey_hex: None,
                client_refund_pubkey_hex: None,
                invoice: None,
            }),
            ..SwapRecord::new_progress()
        }
    }

    #[test]
    fn only_completed_swap_scopes_are_eligible() {
        let completed = record(SwapState::Claimed);
        let active = record(SwapState::InvoicePending);
        assert!(cleanup_plan(&active).is_none());
        let (scopes, deadline) = cleanup_plan(&completed).unwrap();
        assert_eq!(
            scopes,
            vec![
                format!("swap:{}", completed.swap_id),
                format!(
                    "quote:{}",
                    completed.swap_request.as_ref().unwrap().quote_id
                )
            ]
        );
        assert!(!scopes.contains(&format!("swap:{}", active.swap_id)));
        assert_eq!(deadline, 100 + RECOVERY_GRACE);
        // A process restart does not grant an ever-extending grace period.
        assert_eq!(cleanup_plan(&completed).unwrap().1, deadline);
    }

    #[test]
    fn failures_and_ambiguous_expiry_preserve_recovery_messages() {
        assert!(cleanup_plan(&record(SwapState::Failed("backend unavailable".into()))).is_none());
        let mut expired = record(SwapState::Expired);
        expired.funding_intent_at_height = Some(1);
        assert!(cleanup_plan(&expired).is_none());
        expired.funding_intent_at_height = None;
        assert!(cleanup_plan(&expired).is_some());
    }

    #[test]
    fn confirmed_refunds_remain_eligible_with_historical_funding_markers() {
        let mut refunded = record(SwapState::Refunded);
        refunded.spend_txid_hex = Some("11".repeat(32));
        assert!(refunded.funds_at_risk());
        assert!(cleanup_plan(&refunded).is_some());
    }

    #[test]
    fn missing_terminal_timestamp_preserves_messages_until_repaired() {
        let mut completed = record(SwapState::Claimed);
        completed.updated_at_unix = 0;
        assert!(cleanup_plan(&completed).is_none());
    }

    #[test]
    fn incomplete_invoice_and_session_records_do_not_publish_root_messages() {
        let mut incomplete = record(SwapState::Claimed);
        incomplete.pending_hold_invoice = Some(swap_common::store::PendingHoldInvoice {
            amount_msat: 1000,
            expiry_secs: 600,
            cltv_expiry_delta: 40,
            memo: String::new(),
        });
        assert!(cleanup_plan(&incomplete).is_none());
        let mut session = record(SwapState::Claimed);
        session.peer_account = Some("account".into());
        assert!(cleanup_plan(&session).is_none());
    }

    #[test]
    fn terminal_status_recovery_reopens_active_scopes_without_losing_resource_identity() {
        use pubky_transport::{outbox::Outbox, Transport};

        let directory = std::env::temp_dir().join(format!("provider-delivery-{}", Uuid::new_v4()));
        let path = directory.join("outbox.json");
        let mut completed = record(SwapState::Claimed);
        completed.peer = Transport::unsigned([42; 32]).unwrap().public_key_string();
        let deadline = completed.updated_at_unix + RECOVERY_GRACE;
        let active = SwapMessage::SwapStatusUpdate(SwapStatusUpdate {
            swap_id: Uuid::new_v4(),
            state: SwapState::Created,
            reference: None,
        });
        let transport = Transport::unsigned([41; 32])
            .unwrap()
            .with_outbox(&path)
            .unwrap();
        transport
            .enqueue_with_scope(&completed.peer, &active.delivery_scope(), &active)
            .unwrap();
        let accept = SwapMessage::SwapAccept(SwapAccept {
            script_type: Default::default(),
            swap_tree: None,
            quote_id: completed.swap_request.as_ref().unwrap().quote_id,
            swap_id: completed.swap_id,
            direction: completed.direction,
            htlc_script_hex: String::new(),
            htlc_address: String::new(),
            onchain_amount_sat: 100_000,
            timeout_block_height: 1000,
            provider_pubkey_hex: String::new(),
            invoice: Some("invoice".into()),
        });
        transport
            .enqueue_with_scope(&completed.peer, &accept.delivery_scope(), &accept)
            .unwrap();
        // The DM acceptance and terminal record exist, but a crash prevented the final send.
        schedule_retention(&transport, &completed, 1000).unwrap();
        drop(transport);
        let journal = Outbox::open(&path).unwrap();
        assert_eq!(journal.due_pending(1000, 10).unwrap().len(), 3);
        assert!(journal
            .eligible_cleanup(deadline - 1, 10)
            .unwrap()
            .is_empty());
        let final_resource = journal.eligible_cleanup(deadline, 10).unwrap();
        assert_eq!(
            final_resource.len(),
            2,
            "active scope must remain untouched"
        );
        let mut completed_ids: Vec<_> = final_resource
            .iter()
            .map(|entry| entry.id().to_owned())
            .collect();
        completed_ids.sort();
        drop(journal);

        let transport = Transport::unsigned([41; 32])
            .unwrap()
            .with_outbox(&path)
            .unwrap();
        schedule_retention(&transport, &completed, 2000).unwrap();
        drop(transport);
        let journal = Outbox::open(&path).unwrap();
        let mut restored_ids: Vec<_> = journal
            .eligible_cleanup(deadline, 10)
            .unwrap()
            .iter()
            .map(|entry| entry.id().to_owned())
            .collect();
        restored_ids.sort();
        assert_eq!(restored_ids, completed_ids);
        drop(journal);

        // A persisted reorg/recovery transition cancels both deadlines before deletion.
        completed.state = SwapState::LockupPending;
        let transport = Transport::unsigned([41; 32])
            .unwrap()
            .with_outbox(&path)
            .unwrap();
        schedule_retention(&transport, &completed, deadline + 1).unwrap();
        drop(transport);
        let journal = Outbox::open(&path).unwrap();
        assert!(journal
            .eligible_cleanup(deadline + 1, 10)
            .unwrap()
            .is_empty());
        assert_eq!(journal.due_pending(deadline + 1, 10).unwrap().len(), 3);
        drop(journal);

        completed.state = SwapState::Claimed;
        completed.updated_at_unix = deadline + 1;
        let new_deadline = completed.updated_at_unix + RECOVERY_GRACE;
        let transport = Transport::unsigned([41; 32])
            .unwrap()
            .with_outbox(&path)
            .unwrap();
        schedule_retention(&transport, &completed, completed.updated_at_unix).unwrap();
        drop(transport);
        let journal = Outbox::open(&path).unwrap();
        assert!(journal
            .eligible_cleanup(new_deadline - 1, 10)
            .unwrap()
            .is_empty());
        let mut renewed_ids: Vec<_> = journal
            .eligible_cleanup(new_deadline, 10)
            .unwrap()
            .iter()
            .map(|entry| entry.id().to_owned())
            .collect();
        renewed_ids.sort();
        assert_eq!(renewed_ids, completed_ids);
        journal
            .remove_deleted(&completed_ids, new_deadline)
            .unwrap();
        drop(journal);

        let transport = Transport::unsigned([41; 32])
            .unwrap()
            .with_outbox(&path)
            .unwrap();
        schedule_retention(&transport, &completed, new_deadline + 1).unwrap();
        drop(transport);
        let journal = Outbox::open(&path).unwrap();
        assert!(journal
            .eligible_cleanup(new_deadline + 1, 10)
            .unwrap()
            .is_empty());
        assert_eq!(journal.due_pending(new_deadline + 1, 10).unwrap().len(), 1);
        drop(journal);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn direct_swap_completion_does_not_create_dm_delivery() {
        use pubky_transport::{outbox::Outbox, Transport};

        let directory =
            std::env::temp_dir().join(format!("provider-direct-retention-{}", Uuid::new_v4()));
        let path = directory.join("outbox.json");
        let mut completed = record(SwapState::Claimed);
        completed.peer = Transport::unsigned([42; 32]).unwrap().public_key_string();
        let transport = Transport::unsigned([41; 32])
            .unwrap()
            .with_outbox(&path)
            .unwrap();
        assert!(!has_dm_history(&transport, &completed).unwrap());
        schedule_retention(&transport, &completed, 1000).unwrap();
        assert_eq!(transport.homeserver_requests(), 0);
        drop(transport);
        let journal = Outbox::open(&path).unwrap();
        assert!(journal.due_pending(1000, 10).unwrap().is_empty());
        assert!(journal.eligible_cleanup(u64::MAX, 10).unwrap().is_empty());
        drop(journal);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn provider_worker_does_not_complete_client_records() {
        let mut completed = record(SwapState::Claimed);
        completed.role = SwapRole::Client;
        assert!(cleanup_plan(&completed).is_none());
    }
}
