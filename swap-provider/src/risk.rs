//! Bounds on what a provider will have at risk at once.
//!
//! Every accepted `SwapRequest` used to spawn a driver, create a hold invoice, and commit the
//! provider to funding up to `max_amount_sat`, with nothing counting how many were in flight or
//! how much was committed. A provider with a 1 M sat maximum and no other limit would happily
//! start a hundred swaps at once against a wallet that could fund three.
//!
//! Two separate problems live here.
//!
//! **Exposure.** How much of the operator's money can be committed at any instant, in total and
//! per counterparty. This is a capital-allocation decision the operator should make, not an
//! emergent property of how many requests arrive.
//!
//! **Griefing.** A reverse swap costs the provider a funding fee, a refund fee, and the timeout's
//! worth of locked capital if the client pays the hold invoice and then never claims. The client
//! pays nothing: its invoice is cancelled and its money returned. Nothing about that is
//! detectable in advance and nothing stops one peer doing it repeatedly. The pricing model
//! reserves for an expected rate of it; the per-peer caps here bound how fast a single
//! counterparty can push past that rate.
//!
//! A reservation is held by a guard for the driver's lifetime and released when it drops, so a
//! panicking or cancelled driver cannot leak exposure.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use swap_common::store::SwapRecord;
use tracing::{info, warn};
use uuid::Uuid;

/// The operator's limits.
#[derive(Debug, Clone)]
pub struct RiskLimits {
    pub max_concurrent_swaps: usize,
    pub max_concurrent_per_peer: usize,
    pub max_total_exposure_sat: u64,
    pub max_exposure_per_peer_sat: u64,
    /// On-chain balance to keep back, so committing to a swap never leaves the wallet unable to
    /// pay the fee on a refund it may owe.
    pub min_onchain_reserve_sat: u64,
    /// New swaps one peer may start per hour.
    pub max_new_swaps_per_peer_per_hour: u32,
}

impl Default for RiskLimits {
    fn default() -> Self {
        Self {
            max_concurrent_swaps: 25,
            max_concurrent_per_peer: 2,
            max_total_exposure_sat: 5_000_000,
            max_exposure_per_peer_sat: 1_000_000,
            min_onchain_reserve_sat: 100_000,
            max_new_swaps_per_peer_per_hour: 6,
        }
    }
}

/// Why a swap was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    AtCapacity { in_flight: usize, max: usize },
    PeerAtCapacity { in_flight: usize, max: usize },
    ExposureExceeded { committed_sat: u64, max_sat: u64 },
    PeerExposureExceeded { committed_sat: u64, max_sat: u64 },
    RateLimited { started: u32, max_per_hour: u32 },
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtCapacity { in_flight, max } => {
                write!(
                    f,
                    "provider is at capacity ({in_flight} of {max} swaps in flight)"
                )
            }
            Self::PeerAtCapacity { in_flight, max } => write!(
                f,
                "you already have {in_flight} swap(s) in flight; the limit is {max}"
            ),
            Self::ExposureExceeded {
                committed_sat,
                max_sat,
            } => write!(
                f,
                "provider has {committed_sat} sat committed against a {max_sat} sat ceiling"
            ),
            Self::PeerExposureExceeded {
                committed_sat,
                max_sat,
            } => write!(
                f,
                "you have {committed_sat} sat committed against a {max_sat} sat per-peer ceiling"
            ),
            Self::RateLimited {
                started,
                max_per_hour,
            } => write!(
                f,
                "you have started {started} swaps in the last hour; the limit is {max_per_hour}"
            ),
        }
    }
}

/// What one counterparty currently holds, projected out of [`PeerState`] for the operator.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerExposure {
    pub peer: String,
    pub committed_sat: u64,
    pub in_flight: usize,
    pub starts_this_hour: usize,
}

#[derive(Default)]
struct PeerState {
    committed_sat: u64,
    in_flight: usize,
    /// When each recent swap was started, for the hourly rate limit.
    recent_starts: Vec<Instant>,
}

struct Inner {
    total_committed_sat: u64,
    total_in_flight: usize,
    peers: HashMap<String, PeerState>,
    /// Which peer each reservation belongs to, so a guard can release the right one.
    reservations: HashMap<Uuid, (String, u64)>,
}

/// Tracks and bounds what is committed.
pub struct RiskManager {
    limits: RiskLimits,
    inner: Mutex<Inner>,
}

/// Holds a reservation for as long as the swap is live; releases it on drop.
///
/// Tied to the driver task rather than to an explicit release call, so a driver that panics or is
/// cancelled cannot leave exposure counted forever.
pub struct ReservationGuard {
    manager: Arc<RiskManager>,
    swap_id: Uuid,
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        self.manager.release(self.swap_id);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReservationMode {
    New,
    Pending,
    Funded,
}

impl RiskManager {
    pub fn new(limits: RiskLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            inner: Mutex::new(Inner {
                total_committed_sat: 0,
                total_in_flight: 0,
                peers: HashMap::new(),
                reservations: HashMap::new(),
            }),
        })
    }

    pub fn limits(&self) -> &RiskLimits {
        &self.limits
    }

    /// Re-establish accounting from persisted records at startup.
    ///
    /// Exposure is a property of the swaps that exist, not of this process's uptime. A restart
    /// that reset the counters to zero would let a provider commit its whole ceiling again on top
    /// of everything already in flight.
    pub fn restore(self: &Arc<Self>, active: &[SwapRecord]) -> Vec<ReservationGuard> {
        let mut guards = Vec::new();
        for rec in active {
            match self.reserve_inner(
                &rec.peer,
                rec.swap_id,
                rec.onchain_amount_sat,
                ReservationMode::Funded,
            ) {
                Ok(guard) => guards.push(guard),
                Err(reason) => {
                    // Never refuse a swap that already exists: the money is committed whether or
                    // not it fits the current limits. Say so instead.
                    warn!(
                        "resumed swap {} exceeds the configured risk limits ({reason}); driving \
                         it anyway, since its funds are already committed",
                        rec.swap_id
                    );
                }
            }
        }
        let inner = self.locked();
        info!(
            "restored risk accounting: {} swap(s) in flight, {} sat committed",
            inner.total_in_flight, inner.total_committed_sat
        );
        drop(inner);
        guards
    }

    /// The accounting, whether or not a previous holder panicked while holding it.
    ///
    /// A poisoned mutex here used to panic, and it is the wrong place to be strict: the state
    /// behind it is a set of counters, not an invariant a panic can leave half-written, and
    /// refusing to unlock it would take out every future reservation *and* every release, so
    /// exposure would be counted forever against a daemon that could no longer serve anyone.
    /// This is the pattern the rest of the workspace already uses.
    fn locked(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reserve capacity for a new swap, or say why not.
    pub fn reserve(
        self: &Arc<Self>,
        peer: &str,
        swap_id: Uuid,
        amount_sat: u64,
    ) -> std::result::Result<ReservationGuard, RejectReason> {
        self.reserve_inner(peer, swap_id, amount_sat, ReservationMode::New)
    }

    /// Re-admit an intent that has not released an acceptance or committed funds. Capacity and
    /// exposure still apply, but retrying the same admission is not another hourly start.
    pub fn reserve_pending(
        self: &Arc<Self>,
        peer: &str,
        swap_id: Uuid,
        amount_sat: u64,
    ) -> std::result::Result<ReservationGuard, RejectReason> {
        self.reserve_inner(peer, swap_id, amount_sat, ReservationMode::Pending)
    }

    fn reserve_inner(
        self: &Arc<Self>,
        peer: &str,
        swap_id: Uuid,
        amount_sat: u64,
        mode: ReservationMode,
    ) -> std::result::Result<ReservationGuard, RejectReason> {
        let forced = mode == ReservationMode::Funded;
        let mut inner = self.locked();
        let now = Instant::now();
        let hour = Duration::from_secs(3600);

        {
            let state = inner.peers.entry(peer.to_string()).or_default();
            state
                .recent_starts
                .retain(|t| now.duration_since(*t) < hour);
            if !forced {
                let started = state.recent_starts.len() as u32;
                if mode == ReservationMode::New
                    && started >= self.limits.max_new_swaps_per_peer_per_hour
                {
                    return Err(RejectReason::RateLimited {
                        started,
                        max_per_hour: self.limits.max_new_swaps_per_peer_per_hour,
                    });
                }
                if state.in_flight >= self.limits.max_concurrent_per_peer {
                    return Err(RejectReason::PeerAtCapacity {
                        in_flight: state.in_flight,
                        max: self.limits.max_concurrent_per_peer,
                    });
                }
                let would_commit = state.committed_sat.saturating_add(amount_sat);
                if would_commit > self.limits.max_exposure_per_peer_sat {
                    return Err(RejectReason::PeerExposureExceeded {
                        committed_sat: would_commit,
                        max_sat: self.limits.max_exposure_per_peer_sat,
                    });
                }
            }
        }

        if !forced {
            if inner.total_in_flight >= self.limits.max_concurrent_swaps {
                return Err(RejectReason::AtCapacity {
                    in_flight: inner.total_in_flight,
                    max: self.limits.max_concurrent_swaps,
                });
            }
            let would_commit = inner.total_committed_sat.saturating_add(amount_sat);
            if would_commit > self.limits.max_total_exposure_sat {
                return Err(RejectReason::ExposureExceeded {
                    committed_sat: would_commit,
                    max_sat: self.limits.max_total_exposure_sat,
                });
            }
        }

        inner.total_committed_sat = inner.total_committed_sat.saturating_add(amount_sat);
        inner.total_in_flight += 1;
        inner
            .reservations
            .insert(swap_id, (peer.to_string(), amount_sat));
        let state = inner.peers.entry(peer.to_string()).or_default();
        state.committed_sat = state.committed_sat.saturating_add(amount_sat);
        state.in_flight += 1;
        if mode == ReservationMode::New {
            state.recent_starts.push(now);
        }

        Ok(ReservationGuard {
            manager: self.clone(),
            swap_id,
        })
    }

    fn release(&self, swap_id: Uuid) {
        let mut inner = self.locked();
        let Some((peer, amount)) = inner.reservations.remove(&swap_id) else {
            return;
        };
        inner.total_committed_sat = inner.total_committed_sat.saturating_sub(amount);
        inner.total_in_flight = inner.total_in_flight.saturating_sub(1);
        if let Some(state) = inner.peers.get_mut(&peer) {
            state.committed_sat = state.committed_sat.saturating_sub(amount);
            state.in_flight = state.in_flight.saturating_sub(1);
            // Keep the rate-limit history: forgetting it the moment a swap ends would let a peer
            // cycle through swaps faster than the hourly limit intends.
            if state.committed_sat == 0 && state.in_flight == 0 && state.recent_starts.is_empty() {
                inner.peers.remove(&peer);
            }
        }
    }

    /// Total committed right now, for logging and the status surface.
    pub fn committed_sat(&self) -> u64 {
        self.locked().total_committed_sat
    }

    /// Swaps in flight right now.
    pub fn in_flight(&self) -> usize {
        self.locked().total_in_flight
    }

    /// What each counterparty currently holds, for the operator.
    ///
    /// The totals say whether the provider is near a ceiling; they do not say who put it there.
    /// A per-peer view is the difference between "exposure is high" and "one counterparty has
    /// most of it", which are the same number and different problems.
    pub fn per_peer(&self) -> Vec<PeerExposure> {
        let inner = self.locked();
        let mut out: Vec<PeerExposure> = inner
            .peers
            .iter()
            .filter(|(_, s)| s.in_flight > 0 || s.committed_sat > 0)
            .map(|(peer, s)| PeerExposure {
                peer: peer.clone(),
                committed_sat: s.committed_sat,
                in_flight: s.in_flight,
                starts_this_hour: s.recent_starts.len(),
            })
            .collect();
        out.sort_by(|a, b| {
            b.committed_sat
                .cmp(&a.committed_sat)
                .then(a.peer.cmp(&b.peer))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> RiskLimits {
        RiskLimits {
            max_concurrent_swaps: 3,
            max_concurrent_per_peer: 2,
            max_total_exposure_sat: 1_000_000,
            max_exposure_per_peer_sat: 400_000,
            min_onchain_reserve_sat: 0,
            max_new_swaps_per_peer_per_hour: 5,
        }
    }

    /// A driver that hands back control keeps its place in the limits.
    ///
    /// The guard is released by `Drop`, which is right while a swap is over: the task ends and
    /// the capacity comes back. It is exactly wrong when the task ends only to be replaced,
    /// which is what happens on every transient failure and every non-terminal return. Re-entry
    /// used to give the new driver `None`, so one Electrum hiccup was enough to make a swap stop
    /// counting against total exposure and concurrency while its coins were still in an HTLC,
    /// and the daemon would start more swaps on top of it.
    ///
    /// This is the handoff, in the shape `finish_driver_run` performs it.
    #[test]
    fn a_reservation_handed_to_the_next_run_still_counts() {
        let m = RiskManager::new(limits());
        let swap = Uuid::new_v4();
        let first = m.reserve("alice", swap, 300_000).unwrap();
        assert_eq!(m.committed_sat(), 300_000);

        // The driver returns, and its reservation goes to the run that takes over rather than
        // being dropped with the task.
        let handover = |reservation: Option<ReservationGuard>| reservation;
        let second = handover(Some(first));

        assert_eq!(
            m.committed_sat(),
            300_000,
            "the swap's coins are still locked, so it must still be counted"
        );
        assert_eq!(m.in_flight(), 1);

        // Only when the swap is really over does the capacity come back.
        drop(second);
        assert_eq!(m.committed_sat(), 0);
        assert_eq!(m.in_flight(), 0);
    }

    #[test]
    fn exposure_is_bounded_in_total_and_per_peer() {
        let m = RiskManager::new(limits());
        let a = m.reserve("alice", Uuid::new_v4(), 300_000).unwrap();
        // Alice's second swap would take her past her own ceiling.
        assert!(matches!(
            m.reserve("alice", Uuid::new_v4(), 200_000),
            Err(RejectReason::PeerExposureExceeded { .. })
        ));
        // But a different peer is unaffected.
        let b = m.reserve("bob", Uuid::new_v4(), 300_000).unwrap();
        let c = m.reserve("carol", Uuid::new_v4(), 300_000).unwrap();
        // The fourth swap hits the concurrency ceiling before the exposure one.
        assert!(matches!(
            m.reserve("dave", Uuid::new_v4(), 1),
            Err(RejectReason::AtCapacity { .. })
        ));
        assert_eq!(m.committed_sat(), 900_000);
        drop(a);
        assert_eq!(m.committed_sat(), 600_000);
        drop((b, c));
        assert_eq!(m.committed_sat(), 0);
        assert_eq!(m.in_flight(), 0);
    }

    #[test]
    fn a_peer_cannot_hold_more_swaps_than_its_share() {
        let m = RiskManager::new(limits());
        let _a = m.reserve("alice", Uuid::new_v4(), 1_000).unwrap();
        let _b = m.reserve("alice", Uuid::new_v4(), 1_000).unwrap();
        assert!(matches!(
            m.reserve("alice", Uuid::new_v4(), 1_000),
            Err(RejectReason::PeerAtCapacity { .. })
        ));
    }

    /// A client that pays the hold invoice and never claims costs the provider two on-chain fees
    /// and a timeout of locked capital, at no cost to itself. The rate limit bounds how fast one
    /// peer can repeat that, and it counts *starts*, not concurrency, so finishing a swap does
    /// not buy another turn.
    #[test]
    fn repeated_starts_are_rate_limited_even_when_each_one_finishes() {
        let m = RiskManager::new(limits());
        for _ in 0..limits().max_new_swaps_per_peer_per_hour {
            let g = m.reserve("griefer", Uuid::new_v4(), 1_000).unwrap();
            drop(g); // completes immediately, freeing concurrency
        }
        assert_eq!(m.in_flight(), 0, "nothing is in flight");
        assert!(
            matches!(
                m.reserve("griefer", Uuid::new_v4(), 1_000),
                Err(RejectReason::RateLimited { .. })
            ),
            "cycling through swaps must not evade the hourly limit"
        );
        // An honest peer is unaffected.
        assert!(m.reserve("alice", Uuid::new_v4(), 1_000).is_ok());
    }

    /// Exposure belongs to the swaps that exist, not to this process's uptime.
    #[test]
    fn restarting_does_not_forget_committed_funds() {
        let m = RiskManager::new(limits());
        let mut rec = SwapRecord::new_progress();
        rec.swap_id = Uuid::new_v4();
        rec.peer = "alice".into();
        rec.onchain_amount_sat = 350_000;

        let _guards = m.restore(&[rec]);
        assert_eq!(m.committed_sat(), 350_000);
        assert_eq!(m.in_flight(), 1);
        // And the restored swap counts against the ceiling for anything new.
        assert!(matches!(
            m.reserve("alice", Uuid::new_v4(), 100_000),
            Err(RejectReason::PeerExposureExceeded { .. })
        ));
    }

    /// A swap that already exists is always driven, whatever the limits now say: its funds are
    /// committed either way, and refusing would strand them.
    #[test]
    fn resumed_swaps_are_never_refused() {
        let m = RiskManager::new(RiskLimits {
            max_total_exposure_sat: 1,
            max_concurrent_swaps: 0,
            ..limits()
        });
        let mut rec = SwapRecord::new_progress();
        rec.swap_id = Uuid::new_v4();
        rec.peer = "alice".into();
        rec.onchain_amount_sat = 999_999;
        let guards = m.restore(&[rec]);
        assert_eq!(guards.len(), 1);
        assert_eq!(m.committed_sat(), 999_999);
    }
}
