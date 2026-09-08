//! Running async calls from the synchronous wallet trait.
//!
//! `OnchainWallet` is synchronous because the Electrum client is, but beignet is reached over
//! async HTTP, so something has to bridge the two.
//!
//! The obvious bridge is to spawn onto the caller's runtime and block on a channel. That is what
//! `LndWallet` did, and it deadlocks on a current-thread runtime: the drivers' `run_blocking`
//! runs inline there, so blocking the only thread means the spawned task can never be polled.
//! Not an error, a hang.
//!
//! This owns a thread instead. The worker has its own single-threaded runtime and takes jobs off
//! a channel, so it makes progress regardless of what the caller's runtime is doing, and works
//! with no runtime at all.

use std::sync::mpsc;
use std::time::Duration;
use swap_common::SwapError;

/// A unit of work: a boxed future the worker drives to completion.
///
/// The job is the future itself rather than a closure that blocks on one. A closure calling
/// `block_on` from inside the worker's own runtime would panic, because a runtime cannot be
/// entered reentrantly.
type Job = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

/// A worker thread that runs async work for synchronous callers.
pub struct BlockingBridge {
    jobs: mpsc::Sender<Job>,
    timeout: Duration,
}

impl BlockingBridge {
    pub fn new(timeout: Duration) -> Result<Self, SwapError> {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("beignet-bridge".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("beignet bridge could not start a runtime: {e}");
                        return;
                    }
                };
                // Ends when the sender is dropped, i.e. when the wallet goes away.
                while let Ok(job) = rx.recv() {
                    runtime.block_on(job);
                }
            })
            .map_err(|e| SwapError::Permanent(format!("beignet bridge thread: {e}")))?;
        Ok(Self { jobs: tx, timeout })
    }

    /// Run `fut` on the worker and wait for it.
    pub fn call<T, F>(&self, fut: F) -> Result<T, SwapError>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let job: Job = Box::pin(async move {
            let value = fut.await;
            let _ = tx.send(value);
        });
        self.jobs
            .send(job)
            .map_err(|_| SwapError::Permanent("the beignet bridge worker has stopped".into()))?;
        rx.recv_timeout(self.timeout).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => SwapError::transient(
                "beignet call",
                format!("no response within {:?}", self.timeout),
            ),
            mpsc::RecvTimeoutError::Disconnected => {
                SwapError::transient("beignet call", "the worker dropped the job")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bridge must work from a current-thread runtime, which is where the spawn-and-block
    /// approach deadlocks. `#[tokio::test]` gives us exactly that runtime.
    #[tokio::test]
    async fn works_from_a_current_thread_runtime() {
        let bridge = BlockingBridge::new(Duration::from_secs(5)).unwrap();
        // Blocking the current-thread runtime's only thread, which is exactly what deadlocks a
        // bridge that spawns onto the caller's runtime: nothing would be left to poll the task.
        // This one owns a thread, so it makes progress anyway.
        let result = bridge.call(async { 21 * 2 });
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn works_with_no_runtime_at_all() {
        let bridge = BlockingBridge::new(Duration::from_secs(5)).unwrap();
        assert_eq!(bridge.call(async { "hello" }).unwrap(), "hello");
    }

    #[test]
    fn a_stalled_call_times_out_rather_than_hanging() {
        let bridge = BlockingBridge::new(Duration::from_millis(50)).unwrap();
        let result: Result<(), _> = bridge.call(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        assert!(matches!(result, Err(SwapError::Transient(_))));
    }
}
