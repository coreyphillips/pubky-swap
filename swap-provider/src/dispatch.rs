//! Handing received messages to handlers without letting one peer's slow handler hold up another.
//!
//! Each peer with work gets its own queue and task, so its messages are handled one at a time and
//! in the order they arrived, while other peers' messages proceed alongside. A shared semaphore
//! caps how many handlers run at once, and each queue is bounded.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Semaphore};
use tracing::warn;

pub(crate) type Handler<M> =
    Arc<dyn Fn(String, M) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

struct Worker<M> {
    tx: mpsc::Sender<M>,
    /// Messages sent to this worker and not yet handled.
    pending: Arc<AtomicUsize>,
}

pub(crate) struct Dispatcher<M> {
    workers: HashMap<String, Worker<M>>,
    handler: Handler<M>,
    permits: Arc<Semaphore>,
    per_peer_capacity: usize,
}

impl<M: Send + 'static> Dispatcher<M> {
    pub(crate) fn new(max_handlers: usize, per_peer_capacity: usize, handler: Handler<M>) -> Self {
        Self {
            workers: HashMap::new(),
            handler,
            permits: Arc::new(Semaphore::new(max_handlers.max(1))),
            per_peer_capacity: per_peer_capacity.max(1),
        }
    }

    /// Queue a peer's messages behind anything of theirs still being handled. Never waits.
    pub(crate) fn dispatch(&mut self, peer: String, messages: Vec<M>) {
        // Only this method adds to `pending`, so a worker at zero has nothing queued or running,
        // and dropping its sender lets it exit without losing anything. A closed worker died
        // mid-handler and is replaced.
        self.workers
            .retain(|_, w| w.pending.load(Ordering::SeqCst) > 0 && !w.tx.is_closed());
        let worker = self.workers.entry(peer.clone()).or_insert_with(|| {
            spawn_worker(&peer, self.per_peer_capacity, &self.handler, &self.permits)
        });
        for message in messages {
            worker.pending.fetch_add(1, Ordering::SeqCst);
            if worker.tx.try_send(message).is_err() {
                worker.pending.fetch_sub(1, Ordering::SeqCst);
                warn!(
                    "dropping a message from {peer}: {} of theirs are already waiting to be handled",
                    self.per_peer_capacity
                );
            }
        }
    }

    /// Messages received and not yet handled, across all peers.
    pub(crate) fn queued(&self) -> usize {
        self.workers
            .values()
            .map(|w| w.pending.load(Ordering::SeqCst))
            .sum()
    }

    /// Peers with messages queued or being handled.
    pub(crate) fn busy_peers(&self) -> usize {
        self.workers
            .values()
            .filter(|w| w.pending.load(Ordering::SeqCst) > 0)
            .count()
    }
}

fn spawn_worker<M: Send + 'static>(
    peer: &str,
    capacity: usize,
    handler: &Handler<M>,
    permits: &Arc<Semaphore>,
) -> Worker<M> {
    let (tx, mut rx) = mpsc::channel(capacity);
    let pending = Arc::new(AtomicUsize::new(0));
    let peer = peer.to_string();
    let handler = handler.clone();
    let permits = permits.clone();
    let counter = pending.clone();
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let Ok(_permit) = permits.acquire().await else {
                return;
            };
            handler(peer.clone(), message).await;
            counter.fetch_sub(1, Ordering::SeqCst);
        }
    });
    Worker { tx, pending }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::time::Instant;

    type Log = Arc<Mutex<Vec<(String, u32, Duration)>>>;

    /// Handles `(peer, n)`; message 0 from "slow" takes a minute.
    fn recording(log: &Log, start: Instant) -> Handler<u32> {
        let log = log.clone();
        Arc::new(move |peer, n| {
            let log = log.clone();
            Box::pin(async move {
                if peer == "slow" && n == 0 {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                log.lock().unwrap().push((peer, n, start.elapsed()));
            })
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_handler_holds_up_only_its_own_peer() {
        let log: Log = Arc::default();
        let start = Instant::now();
        let mut dispatcher = Dispatcher::new(4, 8, recording(&log, start));

        dispatcher.dispatch("slow".into(), vec![0, 1, 2]);
        dispatcher.dispatch("fast".into(), vec![0, 1]);
        tokio::time::sleep(Duration::from_secs(1)).await;
        dispatcher.dispatch("fast".into(), vec![2]);
        assert_eq!(dispatcher.busy_peers(), 2);
        tokio::time::sleep(Duration::from_secs(120)).await;

        let log = log.lock().unwrap().clone();
        let of = |peer: &str| -> Vec<(u32, Duration)> {
            log.iter()
                .filter(|(p, _, _)| p == peer)
                .map(|(_, n, t)| (*n, *t))
                .collect()
        };
        let fast = of("fast");
        let slow = of("slow");
        assert_eq!(
            fast.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            slow.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(fast.iter().all(|(_, t)| *t < Duration::from_secs(2)));
        assert!(slow[0].1 >= Duration::from_secs(60));
        assert_eq!(dispatcher.queued(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn handlers_and_queues_are_bounded() {
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let handler: Handler<u32> = {
            let (running, peak) = (running.clone(), peak.clone());
            Arc::new(move |_, _| {
                let (running, peak) = (running.clone(), peak.clone());
                Box::pin(async move {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    running.fetch_sub(1, Ordering::SeqCst);
                })
            })
        };
        let mut dispatcher = Dispatcher::new(3, 2, handler);

        for i in 0..20 {
            dispatcher.dispatch(format!("peer-{i}"), vec![0]);
        }
        // One peer flooding past its queue loses the excess rather than stalling everyone.
        dispatcher.dispatch("flood".into(), (0..10).collect());
        assert!(dispatcher.queued() <= 20 + 3);

        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(peak.load(Ordering::SeqCst) <= 3);
        assert_eq!(dispatcher.queued(), 0);
    }
}
