//! What happens to a swap whose driver run ended in an error.
//!
//! A backend outage is not a protocol outcome, and the two used to be spelled the same way. Every
//! driver failure counted against one budget of ten immediate re-entries, and the tenth wrote
//! `SwapState::Failed` -- terminal, excluded from restart recovery, and the reservation released
//! with the task. For a swap whose funds are already committed that is the wrong end of the
//! trade: the ten re-entries take milliseconds, so a single Electrum restart can burn the whole
//! budget, and what is discarded is the only thing that will ever refund a funded HTLC or claim an
//! HTLC we have already paid for.
//!
//! So the budget applies to swaps with nothing committed, where giving up costs a swap and
//! nothing else. Past the funding or payment boundary there is no budget: the driver keeps being
//! re-entered, at a cadence that backs off to something a failing backend can carry, until the
//! chain says the swap is over.

use std::time::Duration;
use swap_common::store::SwapRecord;

/// Attempts a driver gets before a swap with nothing committed is given up on.
///
/// Also the point at which a swap that *does* hold funds is reported as needing an operator: it is
/// not a limit there, but it is the same evidence, and it is where "a backend blipped" stops being
/// the likely explanation.
pub(crate) const MAX_DRIVER_RETRIES: u32 = 10;

/// Delay before the first re-entry.
const BACKOFF_BASE: Duration = Duration::from_secs(2);

/// Longest a re-entry waits.
///
/// This is the recovery cadence a funded swap settles into, so it is bounded by what it is
/// watching for: a refund becomes possible at a block height, and blocks are ten minutes apart.
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// What to do after a driver run failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// Re-enter the driver after this delay.
    Retry(Duration),
    /// Stop, and record the swap as failed.
    GiveUp,
}

/// Decide what a failed driver run earns, given the record as it stands after the failure has been
/// counted.
pub(crate) fn after_failure(rec: &SwapRecord, transient: bool) -> Recovery {
    // Committed funds outrank every other consideration here, including the classification of the
    // error. A permanent-looking failure does not make an HTLC stop existing, and the refund or
    // claim that recovers it is ours alone to make.
    if rec.funds_at_risk() {
        return Recovery::Retry(backoff(rec.retry_count));
    }
    if transient && rec.retry_count < MAX_DRIVER_RETRIES {
        return Recovery::Retry(backoff(rec.retry_count));
    }
    Recovery::GiveUp
}

/// How long to wait before attempt `attempt` (1 is the first re-entry): exponential, capped, and
/// jittered.
///
/// The exponent is what stops an outage burning a retry budget in milliseconds. The jitter is what
/// stops every swap waiting on the same dead backend coming back at the same instant.
pub(crate) fn backoff(attempt: u32) -> Duration {
    let doublings = attempt.saturating_sub(1).min(16);
    let base = BACKOFF_BASE
        .saturating_mul(1u32 << doublings)
        .min(BACKOFF_MAX);
    // Clamped after the jitter as well, so the maximum is one.
    jitter(base).min(BACKOFF_MAX)
}

/// Spread a delay over ±25% of itself.
fn jitter(d: Duration) -> Duration {
    let millis = d.as_millis() as u64;
    let spread = millis / 4;
    if spread == 0 {
        return d;
    }
    let offset = rand::random::<u64>() % (spread * 2 + 1);
    Duration::from_millis(millis - spread + offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_common::{SwapDirection, SwapState};

    /// A reverse swap the provider has funded, as the record looks the instant the funding
    /// transaction goes on the wire.
    fn funded_reverse() -> SwapRecord {
        SwapRecord {
            direction: SwapDirection::Reverse,
            funding_intent_at_height: Some(800_000),
            state: SwapState::LockupPending,
            ..SwapRecord::new_progress()
        }
    }

    /// A submarine swap whose Lightning invoice the provider has paid.
    fn paid_submarine() -> SwapRecord {
        SwapRecord {
            direction: SwapDirection::Submarine,
            invoice_pay_started_at_unix: Some(1),
            state: SwapState::InvoicePaid,
            ..SwapRecord::new_progress()
        }
    }

    /// The bug this module exists for: ten transient failures used to make a funded swap terminal,
    /// which excluded it from restart recovery and released its exposure while its coins sat in an
    /// HTLC nobody was watching.
    #[test]
    fn a_swap_with_committed_funds_is_never_given_up_on() {
        for mut rec in [funded_reverse(), paid_submarine()] {
            for attempt in 1..=100 {
                rec.retry_count = attempt;
                assert!(
                    matches!(after_failure(&rec, true), Recovery::Retry(_)),
                    "attempt {attempt} on {:?} must not end the swap",
                    rec.direction
                );
                // Nor does the error's classification decide it. An HTLC does not stop existing
                // because the failure looks permanent, and only we can refund it.
                assert!(
                    matches!(after_failure(&rec, false), Recovery::Retry(_)),
                    "attempt {attempt} on {:?} must not end the swap",
                    rec.direction
                );
            }
        }
    }

    /// The budget still applies before the boundary, where giving up costs a swap and nothing
    /// more: the client's payment is returned and nobody's coins are locked.
    #[test]
    fn a_swap_with_nothing_committed_still_has_a_budget() {
        let mut rec = SwapRecord {
            direction: SwapDirection::Reverse,
            ..SwapRecord::new_progress()
        };
        for attempt in 1..MAX_DRIVER_RETRIES {
            rec.retry_count = attempt;
            assert!(matches!(after_failure(&rec, true), Recovery::Retry(_)));
        }
        rec.retry_count = MAX_DRIVER_RETRIES;
        assert_eq!(after_failure(&rec, true), Recovery::GiveUp);

        // And an error nothing has classified as retryable ends it at once.
        rec.retry_count = 1;
        assert_eq!(after_failure(&rec, false), Recovery::GiveUp);
    }

    /// Exposure is released when a swap's reservation guard drops, and a swap made terminal
    /// dropped its guard while its coins were still in an HTLC. The provider would then commit its
    /// whole ceiling again on top of money it had not recovered, and a restart would not even know
    /// the money was there, because a terminal record is not loaded.
    #[test]
    fn a_swap_stuck_in_recovery_keeps_its_exposure() {
        use swap_common::store::{JsonFileSwapStore, SwapStore};

        let mut rec = funded_reverse();
        rec.swap_id = uuid::Uuid::new_v4();
        rec.peer = "alice".into();
        rec.onchain_amount_sat = 250_000;
        rec.retry_count = MAX_DRIVER_RETRIES * 5;
        rec.last_error = Some("electrum: connection refused".into());
        assert!(matches!(after_failure(&rec, true), Recovery::Retry(_)));

        let dir = std::env::temp_dir().join(format!("pubky-swap-exposure-{}", rec.swap_id));
        let store = JsonFileSwapStore::new(&dir).unwrap();
        store.put(&rec).unwrap();

        let active = store.load_active().unwrap();
        assert_eq!(active.len(), 1, "a swap holding coins is still in flight");
        assert!(crate::needs_recovery(&active[0]));

        let risk = crate::risk::RiskManager::new(Default::default());
        let guards = risk.restore(&active);
        assert_eq!(guards.len(), 1);
        assert_eq!(risk.committed_sat(), 250_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A persistent outage used to consume ten re-entries in milliseconds, because there was no
    /// delay between them at all.
    #[test]
    fn the_delay_grows_and_is_capped() {
        let mut previous = Duration::ZERO;
        for attempt in 1..=8 {
            let delay = backoff(attempt);
            assert!(
                delay > previous,
                "attempt {attempt} waited {delay:?}, no longer than the {previous:?} before it"
            );
            previous = delay;
        }
        // Ten failures now take minutes rather than microseconds.
        let total: Duration = (1..=MAX_DRIVER_RETRIES).map(backoff).sum();
        assert!(
            total > Duration::from_secs(60),
            "ten attempts took {total:?}"
        );

        // Bounded, so a swap that never recovers settles into a cadence rather than an ever
        // longer silence.
        for attempt in [20, 100, u32::MAX] {
            assert!(backoff(attempt) <= BACKOFF_MAX);
            assert!(backoff(attempt) >= BACKOFF_MAX - BACKOFF_MAX / 4);
        }
    }
}
