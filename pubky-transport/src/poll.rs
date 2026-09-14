//! Scheduled polling of the peer set.
//!
//! Pubky messages are pulled, one conversation per peer, so receiving is a poll loop. Polling every
//! peer together and waiting for the slowest one meant a single stalled homeserver held back
//! messages that had already arrived from everyone else, and an idle peer cost as many requests
//! as a busy one. This scheduler polls each peer on its own clock instead: a peer that just sent
//! something is polled again quickly, a quiet or failing one backs off, and every completed poll is
//! handed to the caller as soon as it lands.
//!
//! Everything is bounded. At most [`PollConfig::max_in_flight`] polls run at once, each under
//! [`PollConfig::poll_timeout`]. Polls run only while the caller is waiting in
//! [`PeerInbox::recv`], so a completed result never queues behind anything but the caller itself,
//! and a caller that stops reading stops the polling. The inbox is driven in place rather than
//! from a spawned task because the messenger's read future is not `Send`.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Notify;
use tokio::time::{sleep_until, timeout, Instant};
use tracing::debug;

use crate::{Result, TransportError};

/// How often the scheduler re-reads the peer set when nothing has told it the set changed.
const PEER_REFRESH: Duration = Duration::from_secs(1);

/// A peer that delivered something this recently counts as active in [`PollStats`].
const ACTIVE_WINDOW: Duration = Duration::from_secs(60);

/// How often a summary of [`PollStats`] is logged.
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Limits and intervals for [`Transport::receiver`](crate::Transport::receiver).
#[derive(Debug, Clone)]
pub struct PollConfig {
    /// Polls allowed to run at once across all peers.
    pub max_in_flight: usize,
    /// How long one poll may take before it counts as failed and is retried later.
    pub poll_timeout: Duration,
    /// Poll interval for a peer that has just sent something, been added, or been woken.
    pub active_interval: Duration,
    /// How long a peer stays at `active_interval` before quiet polls start backing off. A
    /// conversation has pauses between replies, and backing off inside them would add seconds
    /// to every exchange.
    pub active_hold: Duration,
    /// Ceiling for the interval of a peer whose polls keep coming back empty.
    pub idle_max_interval: Duration,
    /// Ceiling for the interval of a peer whose polls keep failing.
    pub failure_max_interval: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 16,
            poll_timeout: Duration::from_secs(10),
            active_interval: Duration::from_millis(200),
            active_hold: Duration::from_secs(10),
            // Well inside the thirty seconds a client waits for a reply.
            idle_max_interval: Duration::from_secs(5),
            failure_max_interval: Duration::from_secs(30),
        }
    }
}

/// New messages from one peer, in the order that peer's conversation holds them.
#[derive(Debug)]
pub struct PeerBatch<M> {
    pub peer: String,
    pub messages: Vec<M>,
}

/// Counters describing the poll loop. Carries no message contents.
#[derive(Debug, Clone, Default)]
pub struct PollStats {
    /// Peers in the poll set.
    pub peers: usize,
    /// Peers that delivered a message within the last minute.
    pub active_peers: usize,
    /// Polls currently running.
    pub in_flight: usize,
    /// Completed polls, whatever their outcome.
    pub polls: u64,
    /// Polls that succeeded with nothing new.
    pub empty_polls: u64,
    /// Polls that returned an error.
    pub failed_polls: u64,
    /// Polls abandoned at [`PollConfig::poll_timeout`].
    pub timed_out_polls: u64,
    /// Duration of the most recently completed poll.
    pub last_latency: Duration,
    /// Sum of all poll durations, for an average.
    pub total_latency: Duration,
}

/// Tells the scheduler that the peer set changed, or that a peer should be polled right away.
#[derive(Default)]
pub(crate) struct PollWaker {
    woken: Mutex<HashSet<String>>,
    notify: Notify,
}

impl PollWaker {
    /// Poll this peer now and drop any backoff it had built up.
    pub(crate) fn wake(&self, peer: &str) {
        if let Ok(mut woken) = self.woken.lock() {
            woken.insert(peer.to_string());
        }
        self.notify.notify_one();
    }

    /// The peer set changed without any particular peer needing a prompt poll.
    pub(crate) fn changed(&self) {
        self.notify.notify_one();
    }

    fn take(&self) -> HashSet<String> {
        self.woken
            .lock()
            .map(|mut w| std::mem::take(&mut *w))
            .unwrap_or_default()
    }
}

pub(crate) type Fetch<M> = Box<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<Vec<M>>>>>>;
pub(crate) type ListPeers = Box<dyn Fn() -> Vec<String>>;

type InFlight<M> = FuturesUnordered<Pin<Box<dyn Future<Output = (String, Duration, Outcome<M>)>>>>;

enum Outcome<M> {
    Messages(Vec<M>),
    Failed(TransportError),
    TimedOut,
}

struct PeerPoll {
    due: Instant,
    idle_streak: u32,
    failure_streak: u32,
    in_flight: bool,
    /// Woken since its last poll started, so the next one skips any backoff and goes ahead of
    /// peers that are merely overdue.
    woken: bool,
    last_delivery: Option<Instant>,
    /// Polled at the active interval until then, however quiet.
    hot_until: Instant,
}

impl PeerPoll {
    fn new(now: Instant, hold: Duration) -> Self {
        Self {
            hot_until: now + hold,
            due: now,
            idle_streak: 0,
            failure_streak: 0,
            in_flight: false,
            woken: false,
            last_delivery: None,
        }
    }
}

/// Scheduled polls of a transport's peer set. See the [module docs](self).
pub struct PeerInbox<M> {
    config: PollConfig,
    list_peers: ListPeers,
    fetch: Fetch<M>,
    waker: Arc<PollWaker>,
    stats: PollStats,
    peers: HashMap<String, PeerPoll>,
    in_flight: InFlight<M>,
    jitter: Jitter,
    refresh_now: bool,
    next_refresh: Instant,
    next_stats_log: Instant,
}

impl<M: 'static> PeerInbox<M> {
    pub(crate) fn new(
        config: PollConfig,
        list_peers: ListPeers,
        fetch: Fetch<M>,
        waker: Arc<PollWaker>,
    ) -> Self {
        let now = Instant::now();
        Self {
            config,
            list_peers,
            fetch,
            waker,
            stats: PollStats::default(),
            peers: HashMap::new(),
            in_flight: FuturesUnordered::new(),
            jitter: Jitter::seeded(),
            refresh_now: true,
            next_refresh: now,
            next_stats_log: now + STATS_LOG_INTERVAL,
        }
    }

    pub fn stats(&self) -> PollStats {
        self.stats.clone()
    }

    /// The next batch, as soon as any peer's poll completes with something new.
    ///
    /// Cancel-safe: a completed poll is only taken from the in-flight set on the way out, so
    /// dropping this future (in a `select!`, say) loses nothing, and the polls still running
    /// resume on the next call.
    pub async fn recv(&mut self) -> PeerBatch<M> {
        let waker = self.waker.clone();
        loop {
            let now = Instant::now();
            let woken = waker.take();
            if self.refresh_now || !woken.is_empty() || now >= self.next_refresh {
                self.refresh(now);
                self.next_refresh = now + PEER_REFRESH;
                self.refresh_now = false;
            }
            for peer in woken {
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.idle_streak = 0;
                    p.failure_streak = 0;
                    p.hot_until = now + self.config.active_hold;
                    p.woken = true;
                    if !p.in_flight {
                        p.due = now;
                    }
                }
            }

            self.launch(now);
            self.publish(now);
            if now >= self.next_stats_log {
                self.log_stats();
                self.next_stats_log = now + STATS_LOG_INTERVAL;
            }

            // Due peers that could not start are waiting on a slot, which only a completion frees.
            let mut wake_at = self.next_refresh.min(self.next_stats_log);
            if self.in_flight.len() < self.max_in_flight() {
                if let Some(due) = self
                    .peers
                    .values()
                    .filter(|p| !p.in_flight)
                    .map(|p| p.due)
                    .min()
                {
                    wake_at = wake_at.min(due);
                }
            }

            tokio::select! {
                Some((peer, latency, outcome)) = self.in_flight.next(), if !self.in_flight.is_empty() => {
                    if let Some(messages) = self.complete(&peer, latency, outcome) {
                        return PeerBatch { peer, messages };
                    }
                }
                _ = sleep_until(wake_at) => {}
                _ = waker.notify.notified() => self.refresh_now = true,
            }
        }
    }

    fn max_in_flight(&self) -> usize {
        self.config.max_in_flight.max(1)
    }

    /// Bring the schedule in line with the peer set. A peer removed mid-poll keeps its entry
    /// until that poll completes, so the slot it holds is still accounted for.
    fn refresh(&mut self, now: Instant) {
        let listed: HashSet<String> = (self.list_peers)().into_iter().collect();
        let hold = self.config.active_hold;
        self.peers
            .retain(|peer, p| p.in_flight || listed.contains(peer));
        for peer in listed {
            self.peers
                .entry(peer)
                .or_insert_with(|| PeerPoll::new(now, hold));
        }
    }

    fn launch(&mut self, now: Instant) {
        let free = self.max_in_flight().saturating_sub(self.in_flight.len());
        if free == 0 {
            return;
        }
        // Woken peers first, then longest-overdue, so a large peer set cannot starve the peers at
        // the back of it and a doorbell is not queued behind that backlog.
        let mut due: Vec<(bool, Instant, String)> = self
            .peers
            .iter()
            .filter(|(_, p)| !p.in_flight && p.due <= now)
            .map(|(peer, p)| (!p.woken, p.due, peer.clone()))
            .collect();
        due.sort();
        for (_, _, peer) in due.into_iter().take(free) {
            if let Some(p) = self.peers.get_mut(&peer) {
                p.in_flight = true;
                p.woken = false;
            }
            let poll = (self.fetch)(peer.clone());
            let deadline = self.config.poll_timeout;
            self.in_flight.push(Box::pin(async move {
                let started = Instant::now();
                let outcome = match timeout(deadline, poll).await {
                    Ok(Ok(messages)) => Outcome::Messages(messages),
                    Ok(Err(e)) => Outcome::Failed(e),
                    Err(_) => Outcome::TimedOut,
                };
                (peer, started.elapsed(), outcome)
            }));
        }
    }

    /// Record a finished poll and schedule the peer's next one. Returns anything to deliver.
    fn complete(&mut self, peer: &str, latency: Duration, outcome: Outcome<M>) -> Option<Vec<M>> {
        let now = Instant::now();
        let active = self.config.active_interval;
        let hold = self.config.active_hold;
        let stats = &mut self.stats;
        stats.polls += 1;
        stats.last_latency = latency;
        stats.total_latency += latency;

        let mut delivery = None;
        let entry = self.peers.get_mut(peer);
        let interval = match outcome {
            Outcome::Messages(messages) if !messages.is_empty() => {
                delivery = Some(messages);
                entry.map(|p| {
                    p.idle_streak = 0;
                    p.failure_streak = 0;
                    p.last_delivery = Some(now);
                    p.hot_until = now + hold;
                    (p, active)
                })
            }
            Outcome::Messages(_) => {
                stats.empty_polls += 1;
                let cap = self.config.idle_max_interval;
                entry.map(|p| {
                    p.failure_streak = 0;
                    if now < p.hot_until {
                        return (p, active);
                    }
                    p.idle_streak = p.idle_streak.saturating_add(1);
                    let interval = backoff(active, p.idle_streak, cap);
                    (p, interval)
                })
            }
            Outcome::Failed(e) => {
                debug!("poll of {peer} failed after {latency:?}: {e}");
                stats.failed_polls += 1;
                let cap = self.config.failure_max_interval;
                entry.map(|p| {
                    p.failure_streak = p.failure_streak.saturating_add(1);
                    let interval = backoff(active, p.failure_streak, cap);
                    (p, interval)
                })
            }
            Outcome::TimedOut => {
                debug!("poll of {peer} timed out after {latency:?}");
                stats.timed_out_polls += 1;
                let cap = self.config.failure_max_interval;
                entry.map(|p| {
                    p.failure_streak = p.failure_streak.saturating_add(1);
                    let interval = backoff(active, p.failure_streak, cap);
                    (p, interval)
                })
            }
        };

        // A peer evicted mid-poll has no entry left; what it delivered is still handed over.
        if let Some((p, interval)) = interval {
            p.in_flight = false;
            p.due = if p.woken {
                now
            } else {
                now + self.jitter.apply(interval)
            };
        }
        delivery
    }

    fn publish(&mut self, now: Instant) {
        self.stats.peers = self.peers.len();
        self.stats.in_flight = self.in_flight.len();
        self.stats.active_peers = self
            .peers
            .values()
            .filter(|p| {
                p.last_delivery
                    .is_some_and(|t| now.duration_since(t) < ACTIVE_WINDOW)
            })
            .count();
    }

    fn log_stats(&self) {
        let s = &self.stats;
        let average = s
            .total_latency
            .checked_div(u32::try_from(s.polls).unwrap_or(u32::MAX))
            .unwrap_or_default();
        debug!(
            peers = s.peers,
            active_peers = s.active_peers,
            in_flight = s.in_flight,
            polls = s.polls,
            empty_polls = s.empty_polls,
            failed_polls = s.failed_polls,
            timed_out_polls = s.timed_out_polls,
            last_latency_ms = s.last_latency.as_millis() as u64,
            average_latency_ms = average.as_millis() as u64,
            "peer poll stats"
        );
    }
}

/// `base * 2^streak`, capped.
fn backoff(base: Duration, streak: u32, cap: Duration) -> Duration {
    base.saturating_mul(1u32 << streak.min(16)).min(cap)
}

/// Spreads intervals over 75..100% of their nominal length, so peers that went quiet together
/// are not polled together forever after.
struct Jitter(u64);

impl Jitter {
    fn seeded() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Self(seed)
    }

    /// splitmix64: plenty for spreading timers, and no dependency for it.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn apply(&mut self, interval: Duration) -> Duration {
        let fraction = 0.75 + 0.25 * (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        interval.mul_f64(fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn backoff_doubles_up_to_its_cap() {
        let base = Duration::from_millis(200);
        let cap = Duration::from_secs(5);
        assert_eq!(backoff(base, 0, cap), base);
        assert_eq!(backoff(base, 1, cap), Duration::from_millis(400));
        assert_eq!(backoff(base, 4, cap), Duration::from_millis(3200));
        assert_eq!(backoff(base, 5, cap), cap);
        assert_eq!(backoff(base, u32::MAX, cap), cap);
    }

    #[test]
    fn jitter_only_shortens() {
        let mut jitter = Jitter(42);
        for _ in 0..1000 {
            let d = jitter.apply(Duration::from_secs(4));
            assert!(d >= Duration::from_secs(3) && d <= Duration::from_secs(4));
        }
    }

    /// A fake conversation per peer, driven by virtual time.
    #[derive(Clone)]
    enum Behaviour {
        /// Has something new at each of these offsets from the start.
        Messages(Vec<Duration>),
        /// Never answers within any reasonable deadline.
        Stalled,
        /// Every poll errors.
        Failing,
    }

    struct Fake {
        start: Instant,
        peers: Mutex<HashMap<String, (Behaviour, usize)>>,
        requests: Mutex<HashMap<String, usize>>,
        running: AtomicUsize,
        max_running: AtomicUsize,
    }

    impl Fake {
        fn new(peers: Vec<(&str, Behaviour)>) -> Arc<Self> {
            Arc::new(Self {
                start: Instant::now(),
                peers: Mutex::new(
                    peers
                        .into_iter()
                        .map(|(p, b)| (p.to_string(), (b, 0)))
                        .collect(),
                ),
                requests: Mutex::new(HashMap::new()),
                running: AtomicUsize::new(0),
                max_running: AtomicUsize::new(0),
            })
        }

        fn requests(&self, peer: &str) -> usize {
            self.requests
                .lock()
                .unwrap()
                .get(peer)
                .copied()
                .unwrap_or(0)
        }

        fn say(&self, peer: &str) {
            let elapsed = self.start.elapsed();
            if let Some((Behaviour::Messages(at), _)) = self.peers.lock().unwrap().get_mut(peer) {
                at.push(elapsed);
            }
        }

        fn list(self: &Arc<Self>) -> ListPeers {
            let fake = self.clone();
            Box::new(move || fake.peers.lock().unwrap().keys().cloned().collect())
        }

        fn fetch(self: &Arc<Self>) -> Fetch<Duration> {
            let fake = self.clone();
            Box::new(move |peer: String| {
                let fake = fake.clone();
                Box::pin(async move {
                    *fake
                        .requests
                        .lock()
                        .unwrap()
                        .entry(peer.clone())
                        .or_default() += 1;
                    let running = fake.running.fetch_add(1, Ordering::SeqCst) + 1;
                    fake.max_running.fetch_max(running, Ordering::SeqCst);
                    let result = fake.answer(&peer).await;
                    fake.running.fetch_sub(1, Ordering::SeqCst);
                    result
                })
            })
        }

        async fn answer(&self, peer: &str) -> Result<Vec<Duration>> {
            // Every real poll is a network round trip.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let behaviour = self.peers.lock().unwrap().get(peer).map(|(b, _)| b.clone());
            match behaviour {
                Some(Behaviour::Stalled) => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok(Vec::new())
                }
                Some(Behaviour::Failing) => {
                    Err(TransportError::Messenger("homeserver unavailable".into()))
                }
                Some(Behaviour::Messages(_)) => {
                    let elapsed = self.start.elapsed();
                    let mut peers = self.peers.lock().unwrap();
                    let Some((Behaviour::Messages(at), read)) = peers.get_mut(peer) else {
                        return Ok(Vec::new());
                    };
                    let fresh: Vec<Duration> = at
                        .iter()
                        .skip(*read)
                        .copied()
                        .filter(|t| *t <= elapsed)
                        .collect();
                    *read += fresh.len();
                    Ok(fresh)
                }
                None => Ok(Vec::new()),
            }
        }

        fn inbox(
            self: &Arc<Self>,
            config: PollConfig,
            waker: Arc<PollWaker>,
        ) -> PeerInbox<Duration> {
            PeerInbox::new(config, self.list(), self.fetch(), waker)
        }
    }

    type Deliveries = HashMap<String, Vec<(Duration, Duration)>>;

    /// Everything each peer delivered, as (message time, delivery time) offsets from the start.
    async fn collect(
        inbox: &mut PeerInbox<Duration>,
        start: Instant,
        run_for: Duration,
    ) -> Deliveries {
        let mut delivered = Deliveries::new();
        while let Ok(batch) = tokio::time::timeout_at(start + run_for, inbox.recv()).await {
            let at = start.elapsed();
            let entry = delivered.entry(batch.peer).or_default();
            entry.extend(batch.messages.into_iter().map(|sent| (sent, at)));
        }
        delivered
    }

    fn worst_latency(delivered: &[(Duration, Duration)]) -> Duration {
        delivered
            .iter()
            .map(|(sent, at)| at.saturating_sub(*sent))
            .max()
            .unwrap_or_default()
    }

    /// The loop this replaces: poll everyone, wait for everyone, then sleep 200 ms.
    async fn baseline(fake: &Arc<Fake>, run_for: Duration) -> Deliveries {
        let list = fake.list();
        let fetch = fake.fetch();
        let mut delivered = Deliveries::new();
        let end = fake.start + run_for;
        while Instant::now() < end {
            let polls = list().into_iter().map(|peer| {
                let poll = fetch(peer.clone());
                async move { (peer, poll.await) }
            });
            let Ok(results) = tokio::time::timeout_at(end, futures::future::join_all(polls)).await
            else {
                break;
            };
            let at = fake.start.elapsed();
            for (peer, result) in results {
                if let Ok(messages) = result {
                    let entry = delivered.entry(peer).or_default();
                    entry.extend(messages.into_iter().map(|sent| (sent, at)));
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        delivered
    }

    fn scenario(with_slow_peer: bool) -> Vec<(&'static str, Behaviour)> {
        let mut peers = vec![
            // Mid-conversation: something every two seconds for the first minute.
            (
                "active",
                Behaviour::Messages((0..30).map(|i| Duration::from_secs(i * 2)).collect()),
            ),
            // Quiet for four minutes, then back.
            ("idle", Behaviour::Messages(vec![Duration::from_secs(240)])),
            ("failing", Behaviour::Failing),
        ];
        if with_slow_peer {
            peers.push(("slow", Behaviour::Stalled));
        }
        peers
    }

    /// The comparison fixture: the same five simulated minutes and the same peers, under the old
    /// poll-everyone loop and under the scheduler, once without a stalled peer and once with one.
    /// Virtual time makes it exact and instant. Run with `--nocapture` to see the table.
    #[tokio::test(start_paused = true)]
    async fn fixture_compares_latency_and_request_volume() {
        let run_for = Duration::from_secs(300);
        for with_slow_peer in [false, true] {
            let old = Fake::new(scenario(with_slow_peer));
            let old_delivered = baseline(&old, run_for).await;

            let new = Fake::new(scenario(with_slow_peer));
            let mut inbox = new.inbox(PollConfig::default(), Arc::default());
            let new_delivered = collect(&mut inbox, new.start, run_for).await;
            let stats = inbox.stats();

            println!("\nstalled peer present: {with_slow_peer}");
            println!(
                "{:<8} {:>13} {:>13} {:>13} {:>13} {:>13} {:>13}",
                "peer",
                "old requests",
                "new requests",
                "old received",
                "new received",
                "old worst ms",
                "new worst ms"
            );
            for (peer, _) in scenario(with_slow_peer) {
                let received = |d: &Deliveries| d.get(peer).map_or(0, Vec::len);
                let latency = |d: &Deliveries| {
                    d.get(peer).map_or("-".to_string(), |v| {
                        worst_latency(v).as_millis().to_string()
                    })
                };
                println!(
                    "{peer:<8} {:>13} {:>13} {:>13} {:>13} {:>13} {:>13}",
                    old.requests(peer),
                    new.requests(peer),
                    received(&old_delivered),
                    received(&new_delivered),
                    latency(&old_delivered),
                    latency(&new_delivered),
                );
            }
            println!("{stats:?}");

            // An active peer is heard within one active interval, stalled neighbour or not.
            let active = &new_delivered["active"];
            assert_eq!(active.len(), 30, "every active message is delivered");
            assert!(worst_latency(active) < Duration::from_millis(300));

            // A peer that went quiet costs a fraction of the requests and is still heard in time.
            // The old loop polled it 1200 times in five minutes.
            assert!(new.requests("idle") < 300, "{}", new.requests("idle"));
            assert!(worst_latency(&new_delivered["idle"]) <= Duration::from_millis(5_100));

            // Failures are counted apart from empty polls, and keep being retried.
            assert!(new.requests("failing") > 5);
            assert!(stats.failed_polls > 5 && stats.empty_polls > 0);

            if with_slow_peer {
                assert!(
                    old_delivered.get("active").is_none_or(|v| v.len() < 30),
                    "the old loop is stuck behind the stalled peer"
                );
                assert!(new.requests("slow") > 5 && stats.timed_out_polls > 5);
            }
        }
    }

    /// A peer woken by the doorbell skips the backoff it built up while quiet.
    #[tokio::test(start_paused = true)]
    async fn a_woken_peer_is_polled_at_once() {
        let fake = Fake::new(vec![("idle", Behaviour::Messages(Vec::new()))]);
        let waker = Arc::new(PollWaker::default());
        let config = PollConfig {
            idle_max_interval: Duration::from_secs(30),
            ..PollConfig::default()
        };
        let mut inbox = fake.inbox(config, waker.clone());

        // Quiet long enough to back off, then stop right after a poll so the next is far away.
        let _ = tokio::time::timeout(Duration::from_secs(120), inbox.recv()).await;
        while inbox.peers["idle"].in_flight
            || inbox.peers["idle"].due < Instant::now() + Duration::from_secs(10)
        {
            let _ = tokio::time::timeout(Duration::from_millis(10), inbox.recv()).await;
        }

        fake.say("idle");
        waker.wake("idle");
        let woken_at = Instant::now();
        let batch = inbox.recv().await;
        assert_eq!(batch.peer, "idle");
        assert!(woken_at.elapsed() <= Duration::from_millis(60));
    }

    /// A doorbell is answered ahead of a backlog of overdue peers.
    #[tokio::test(start_paused = true)]
    async fn a_woken_peer_goes_ahead_of_overdue_peers() {
        let mut peers: Vec<(String, Behaviour)> = (0..1000)
            .map(|i| {
                (
                    format!("peer-{i}"),
                    Behaviour::Messages(vec![Duration::ZERO]),
                )
            })
            .collect();
        peers.push(("late".into(), Behaviour::Messages(Vec::new())));
        let fake = Fake::new(peers.iter().map(|(n, b)| (n.as_str(), b.clone())).collect());
        let waker = Arc::new(PollWaker::default());
        let config = PollConfig {
            max_in_flight: 8,
            ..PollConfig::default()
        };
        let mut inbox = fake.inbox(config, waker.clone());
        let _ = inbox.recv().await;

        fake.say("late");
        waker.wake("late");
        let woken_at = Instant::now();
        while inbox.recv().await.peer != "late" {}
        assert!(woken_at.elapsed() <= Duration::from_millis(110));
    }

    /// However many peers there are, only `max_in_flight` polls run at once, a caller that is not
    /// reading causes no polling at all, and every peer is still reached.
    #[tokio::test(start_paused = true)]
    async fn polls_are_bounded_and_fair_over_a_large_peer_set() {
        let names: Vec<String> = (0..1000).map(|i| format!("peer-{i}")).collect();
        let fake = Fake::new(
            names
                .iter()
                .map(|n| (n.as_str(), Behaviour::Messages(vec![Duration::ZERO])))
                .collect(),
        );
        let config = PollConfig {
            max_in_flight: 8,
            ..PollConfig::default()
        };
        let mut inbox = fake.inbox(config, Arc::default());

        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(fake.running.load(Ordering::SeqCst), 0);

        let mut seen = HashSet::new();
        while seen.len() < names.len() {
            assert!(
                seen.insert(inbox.recv().await.peer),
                "a peer was polled twice first"
            );
        }
        assert!(fake.max_running.load(Ordering::SeqCst) <= 8);
        assert!(inbox.stats().in_flight <= 8);
    }
}
