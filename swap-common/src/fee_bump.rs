//! Driving an HTLC claim or refund to confirmation, under fee pressure and against a rival.
//!
//! An HTLC output has exactly two ways to be spent, and both parties can try at once. Whoever
//! confirms first wins, so a spend is never simply "waiting to confirm": it is racing. Three
//! things follow, and all three are the caller's business rather than this module's:
//!
//! - **A claim has a deadline.** It must land before the counterparty's refund branch opens, so
//!   the fee has to escalate as that height approaches. A refund has no deadline in the same
//!   sense: giving up on one means abandoning the money, so it keeps trying.
//! - **The race can be lost.** If the counterparty's spend confirms, ours is dead. Re-broadcasting
//!   it forever accomplishes nothing, and the caller usually has something useful to do with the
//!   winning transaction: a reverse-swap provider, for instance, can pull the preimage out of a
//!   client's claim and settle the invoice it had given up on.
//! - **The race can be lost to ourselves.** Every RBF replacement is a different transaction, so
//!   "the spend that confirmed is not the one I last broadcast" does not mean a rival won. Every
//!   transaction we broadcast is remembered so an earlier replacement of ours is recognised as
//!   ours.
//!
//! [`confirm_or_bump`] therefore returns a [`SpendOutcome`] rather than a bare txid, and always
//! terminates: on confirmation, on a rival's spend, or on a deadline.

use crate::chain::{run_blocking, ChainWatcher};
use crate::error::Result;
use crate::onchain::{deadline_fee_rate, resolve_fee_rate};
use bitcoin::{Script, Transaction, Txid};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Wall-clock ceiling on a single [`confirm_or_bump`] call. Reaching it is not failure: the
/// caller persists what it knows and re-enters. It exists so a stalled chain backend can never
/// wedge a driver task forever with nothing in the logs.
pub const DEFAULT_MAX_WALL_DURATION: Duration = Duration::from_secs(6 * 60 * 60);

/// Absolute iteration ceiling, as a backstop against a backend that returns instantly forever.
pub const DEFAULT_MAX_ITERATIONS: u32 = 100_000;

/// Child-pays-for-parent fallback: given the stuck parent spend's txid and a target fee rate
/// (sat/vB), build and broadcast a high-fee child, returning the child txid (or `None`). Used
/// only when an RBF replacement cannot be broadcast.
pub type CpfpBump<'a> = dyn Fn(Txid, u64) -> Option<Txid> + Send + Sync + 'a;

/// How a spend should be driven.
#[derive(Debug, Clone)]
pub struct SpendWatchConfig {
    /// Fee-estimation confirmation target for the initial broadcast.
    pub fee_target_blocks: u16,
    /// The operator's configured fee floor (sat/vB): both the fallback when estimation is
    /// unavailable and the minimum.
    pub floor_rate_sat_vb: u64,
    /// Ceiling on the fee rate this spend may escalate to. Sized against the output's value by
    /// [`crate::onchain::fee_rate_cap`], so a small HTLC is not burned down to dust chasing a fee.
    pub cap_rate_sat_vb: u64,
    /// How long to wait between checks.
    pub poll: Duration,
    /// Depth at which the spend is treated as final.
    pub min_confirmations: u32,
    /// The height by which this spend must confirm.
    ///
    /// `Some` for a **claim**, which races the counterparty's refund window: the fee escalates
    /// toward the cap as this approaches, and the call gives up once it passes.
    ///
    /// `None` for a **refund**, where there is nothing to race and giving up would mean
    /// abandoning the money.
    pub deadline_height: Option<u32>,
    /// Wall-clock ceiling for one call.
    pub max_wall_duration: Duration,
    /// Iteration ceiling for one call.
    pub max_iterations: u32,
    /// Spends this swap broadcast in an *earlier* run, read back from its record.
    ///
    /// The set of our own transactions is rebuilt from nothing on every call, which is right
    /// within one run and wrong across a restart: a replacement we broadcast before the crash is
    /// still in the mempool, and an empty set classifies it as the counterparty's spend. On a
    /// refund that reads as "they claimed it" and the swap is abandoned while we were winning.
    pub known_ours: Vec<Txid>,
}

impl SpendWatchConfig {
    /// A claim: deadline-driven, escalating as `deadline_height` approaches.
    pub fn claim(
        fee_target_blocks: u16,
        floor_rate_sat_vb: u64,
        cap_rate_sat_vb: u64,
        poll: Duration,
        min_confirmations: u32,
        deadline_height: u32,
    ) -> Self {
        Self {
            fee_target_blocks,
            floor_rate_sat_vb,
            cap_rate_sat_vb,
            poll,
            min_confirmations,
            deadline_height: Some(deadline_height),
            max_wall_duration: DEFAULT_MAX_WALL_DURATION,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            known_ours: Vec::new(),
        }
    }

    /// Adopt spends a previous run of this swap put on the wire.
    pub fn with_known_ours(mut self, txids: Vec<Txid>) -> Self {
        self.known_ours = txids;
        self
    }

    /// A refund: no chain deadline, because giving up means losing the money.
    pub fn refund(
        fee_target_blocks: u16,
        floor_rate_sat_vb: u64,
        cap_rate_sat_vb: u64,
        poll: Duration,
        min_confirmations: u32,
    ) -> Self {
        Self {
            fee_target_blocks,
            floor_rate_sat_vb,
            cap_rate_sat_vb,
            poll,
            min_confirmations,
            deadline_height: None,
            max_wall_duration: DEFAULT_MAX_WALL_DURATION,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            known_ours: Vec::new(),
        }
    }
}

/// How driving a spend ended. Every variant is terminal for the call; there is no path that
/// keeps looping.
#[derive(Debug, Clone)]
pub enum SpendOutcome {
    /// One of our broadcasts is buried `min_confirmations` deep.
    Confirmed { txid: Txid },
    /// The HTLC outpoint was spent by a transaction we did not broadcast: the counterparty won,
    /// or is winning. The transaction is returned because it is usually worth something to the
    /// caller -- a claim reveals the preimage that settles the other leg.
    ConflictingSpend { tx: Transaction },
    /// Neither confirmed nor conflicted before the deadline, the wall-clock cap, or the
    /// iteration cap. The caller persists and decides whether to re-enter.
    DeadlineExceeded { last_txid: Txid, tip: u32 },
}

/// Broadcast a spend and drive it to one of the [`SpendOutcome`]s.
///
/// - `build(rate)` produces the signed spend for a fee rate (sat/vB). It may error when the fee
///   would push the output below dust; escalation stops there rather than failing the call.
/// - `htlc_outpoint` is the output being spent, needed to notice a rival spending it.
/// - `cpfp` is tried only when an RBF replacement cannot be broadcast.
/// - `on_spend` is called with the txid of every transaction about to go on the wire, *before*
///   the broadcast. Recording it afterwards would leave the crash window this exists to close:
///   the caller persists it so a later run knows the transaction is its own. A txid recorded for
///   a broadcast that then failed is harmless, since nothing will ever see it on chain.
pub async fn confirm_or_bump(
    chain: &dyn ChainWatcher,
    htlc_spk: &Script,
    htlc_outpoint: bitcoin::OutPoint,
    cfg: &SpendWatchConfig,
    cpfp: Option<&CpfpBump<'_>>,
    // `Sync` so the returned future stays `Send`: these drivers run as spawned tasks.
    on_spend: &(dyn Fn(Txid) + Sync),
    mut build: impl FnMut(u64) -> Result<Transaction>,
) -> Result<SpendOutcome> {
    let estimate = |target: u16| run_blocking(|| chain.estimate_fee_rate(target)).unwrap_or(None);

    let mut rate = resolve_fee_rate(
        estimate(cfg.fee_target_blocks),
        cfg.floor_rate_sat_vb,
        cfg.cap_rate_sat_vb,
    );
    // Every transaction we have put on the wire. An RBF replacement is a *different* transaction,
    // so without this an earlier replacement of ours confirming would be misread as a rival's
    // spend and the swap would take the wrong branch. Seeded from the record, so the same is true
    // of a replacement an earlier run broadcast before a restart.
    let mut ours: HashSet<Txid> = cfg.known_ours.iter().copied().collect();

    // Before putting anything new on the wire, ask whether a spend from an earlier run is already
    // the live one. Rebuilding produces a *different* transaction: the fee rate is re-derived from
    // today's estimate with no memory of what the earlier run escalated to, so the replacement is
    // usually cheaper than the one it would replace and the node rejects it under BIP125 rule 3.
    // That rejection is `?`-propagated, so the call would fail outright rather than watching a
    // perfectly good transaction of ours confirm.
    let live = if ours.is_empty() {
        None
    } else {
        run_blocking(|| chain.find_spend(htlc_spk, &htlc_outpoint))?
            .map(|tx| tx.compute_txid())
            .filter(|id| ours.contains(id))
    };

    let mut txid = match live {
        Some(id) => {
            info!("adopting spend {id} from an earlier run of this swap rather than replacing it");
            id
        }
        None => {
            let initial = build(rate)?;
            on_spend(initial.compute_txid());
            run_blocking(|| chain.broadcast(&initial))?
        }
    };
    ours.insert(txid);

    let started = Instant::now();
    let mut iterations: u32 = 0;

    loop {
        iterations += 1;
        let tip = run_blocking(|| chain.tip_height())?;

        // Has anyone spent the output? Ask before checking our own transaction's depth: a rival's
        // spend removes ours from the picture entirely, and the answer is more useful than
        // "not found".
        if let Some(spend) = run_blocking(|| chain.find_spend(htlc_spk, &htlc_outpoint))? {
            let spend_txid = spend.compute_txid();
            if !ours.contains(&spend_txid) {
                warn!(
                    "the HTLC output was spent by {spend_txid}, which we did not broadcast; \
                     handing it back to the caller"
                );
                return Ok(SpendOutcome::ConflictingSpend { tx: spend });
            }
            // One of ours, possibly an earlier replacement. Track it as the live one.
            if spend_txid != txid {
                debug!("an earlier replacement of ours ({spend_txid}) is the live spend");
                txid = spend_txid;
            }
        }

        match run_blocking(|| chain.tx_confirmations(htlc_spk, &txid))? {
            // Buried deep enough: final.
            Some(c) if c >= cfg.min_confirmations => return Ok(SpendOutcome::Confirmed { txid }),

            // Not in the mempool and not in a block. Either it was dropped, or it confirmed and a
            // reorg orphaned it. Either way, get it back on the wire.
            None => {
                debug!("spend {txid} is not in the mempool or a block; re-broadcasting");
                if let Ok(tx) = build(rate) {
                    on_spend(tx.compute_txid());
                    if let Ok(id) = run_blocking(|| chain.broadcast(&tx)) {
                        ours.insert(id);
                        txid = id;
                    }
                }
            }

            // In the mempool, unconfirmed. Escalate if the deadline warrants it.
            Some(0) => {
                let next = deadline_fee_rate(
                    tip,
                    cfg.deadline_height,
                    rate,
                    &estimate,
                    cfg.floor_rate_sat_vb,
                    cfg.cap_rate_sat_vb,
                );
                if next > rate {
                    // `build` errors only when the higher fee would dust the output. That is the
                    // end of escalation, not an error: let the current transaction ride.
                    if let Ok(replacement) = build(next) {
                        on_spend(replacement.compute_txid());
                        match run_blocking(|| chain.broadcast(&replacement)) {
                            Ok(id) => {
                                info!("fee-bumped the spend to {id} at {next} sat/vB");
                                ours.insert(id);
                                txid = id;
                                rate = next;
                            }
                            Err(e) => {
                                // The replacement was rejected (often BIP125 rule 3 or 4). Pull
                                // the parent in with a high-fee child instead, when the swept
                                // output is one we can spend.
                                debug!("RBF replacement rejected ({e}); trying CPFP");
                                match cpfp.and_then(|f| f(txid, next)) {
                                    Some(child) => {
                                        info!("CPFP child {child} for stuck spend {txid}");
                                        // The child pays the fee now, so the parent's effective
                                        // rate has risen even though `rate` has not.
                                        rate = next;
                                    }
                                    None => debug!("no CPFP available for {txid}"),
                                }
                            }
                        }
                    }
                }
            }

            // Mined but shallow: nothing to do but wait for depth.
            Some(_) => {}
        }

        // Terminate rather than spin. A claim past its deadline cannot be won; a call that has
        // run for hours, or spun for a very large number of iterations, has stopped making
        // progress and should hand control back.
        if let Some(deadline) = cfg.deadline_height {
            if tip >= deadline {
                warn!("spend {txid} did not confirm before its deadline at height {deadline}");
                return Ok(SpendOutcome::DeadlineExceeded {
                    last_txid: txid,
                    tip,
                });
            }
        }
        if started.elapsed() >= cfg.max_wall_duration || iterations >= cfg.max_iterations {
            warn!(
                "spend {txid} has not resolved after {:?} / {iterations} checks; handing back",
                started.elapsed()
            );
            return Ok(SpendOutcome::DeadlineExceeded {
                last_txid: txid,
                tip,
            });
        }

        tokio::time::sleep(cfg.poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::mock::MockChain;
    use bitcoin::absolute::LockTime;
    use bitcoin::{OutPoint, TxOut};
    use std::sync::Mutex;

    fn spk() -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::from_hex("0014abababababababababababababababababababab").unwrap()
    }

    fn tx_paying(value: u64) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: spk(),
            }],
        }
    }

    fn htlc_outpoint() -> OutPoint {
        OutPoint {
            txid: tx_paying(1).compute_txid(),
            vout: 0,
        }
    }

    fn chain(confs: Vec<Option<u32>>) -> MockChain {
        MockChain::new().with_tip(800_000).with_confirmations(confs)
    }

    fn cfg(deadline: Option<u32>) -> SpendWatchConfig {
        SpendWatchConfig {
            fee_target_blocks: 3,
            floor_rate_sat_vb: 5,
            cap_rate_sat_vb: 1_000,
            poll: Duration::from_millis(0),
            min_confirmations: 2,
            deadline_height: deadline,
            max_wall_duration: Duration::from_secs(5),
            max_iterations: 50,
            known_ours: Vec::new(),
        }
    }

    #[tokio::test]
    async fn confirms_once_buried() {
        let chain = chain(vec![Some(0), Some(1), Some(2)]);
        let out = confirm_or_bump(
            &chain,
            spk().as_script(),
            htlc_outpoint(),
            &cfg(None),
            None,
            &|_| {},
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        assert!(matches!(out, SpendOutcome::Confirmed { .. }));
    }

    /// The defect this rewrite exists for.
    ///
    /// When the counterparty's spend confirms, our transaction leaves the HTLC's script history,
    /// so `tx_confirmations` answers `None`. The old loop read that as "dropped from the
    /// mempool" and re-broadcast a transaction double-spending an already-spent output, every
    /// two seconds, forever. The node rejected each attempt and the error was swallowed. The
    /// driver task never ended, the swap record was never cleared, and in the reverse refund
    /// path the preimage sat unclaimed in the winning transaction while the hold invoice went
    /// unsettled: both legs lost, silently.
    #[tokio::test]
    async fn a_counterparty_spend_ends_the_loop_and_is_handed_back() {
        let rival = tx_paying(42);
        let rival_txid = rival.compute_txid();
        // `None` forever: our transaction is nowhere to be found, exactly as when a rival wins.
        let chain = chain(vec![None]).with_spend(rival);

        let out = tokio::time::timeout(
            Duration::from_secs(5),
            confirm_or_bump(
                &chain,
                spk().as_script(),
                htlc_outpoint(),
                &cfg(None),
                None,
                &|_| {},
                |rate| Ok(tx_paying(100_000 - rate)),
            ),
        )
        .await
        .expect("must not loop forever")
        .unwrap();

        match out {
            SpendOutcome::ConflictingSpend { tx } => assert_eq!(tx.compute_txid(), rival_txid),
            other => panic!("expected the rival spend to be returned, got {other:?}"),
        }
        // And it stopped immediately rather than re-broadcasting into a spent output.
        assert_eq!(chain.broadcast_count(), 1);
    }

    /// An RBF replacement is a different transaction, so "the spend that confirmed is not the one
    /// I last broadcast" must not be read as a rival winning. Every transaction we broadcast is
    /// remembered.
    #[tokio::test]
    async fn a_spend_from_an_earlier_run_is_not_mistaken_for_a_rival() {
        // The transaction a previous run of this swap broadcast before the process died. It is
        // still in the mempool, so the first thing this run sees is its own work.
        let earlier = tx_paying(99_000);
        let earlier_txid = earlier.compute_txid();
        let chain = chain(vec![Some(2)]).with_spend(earlier);

        let out = tokio::time::timeout(
            Duration::from_secs(5),
            confirm_or_bump(
                &chain,
                spk().as_script(),
                htlc_outpoint(),
                &cfg(None).with_known_ours(vec![earlier_txid]),
                None,
                &|_| {},
                |rate| Ok(tx_paying(100_000 - rate)),
            ),
        )
        .await
        .expect("must not loop forever")
        .unwrap();

        // Without the seed this is a `ConflictingSpend`, which a refund driver reads as "the
        // counterparty claimed" and gives up on a swap it was winning.
        match out {
            SpendOutcome::Confirmed { txid } => assert_eq!(txid, earlier_txid),
            other => panic!("expected our own earlier spend to confirm, got {other:?}"),
        }
        // And nothing new went on the wire. Rebuilding produces a different transaction at
        // today's fee rate, usually cheaper than the one it would replace, so broadcasting it is
        // at best a rejected replacement and at worst an error that aborts the whole call while a
        // perfectly good spend of ours sits in the mempool.
        assert_eq!(
            chain.broadcast_count(),
            0,
            "a live spend of ours is adopted, not replaced"
        );
    }

    /// Every transaction goes on the record before it goes on the wire.
    ///
    /// The other order leaves the gap this whole mechanism exists to close: broadcast, crash,
    /// and the next run has no idea the transaction in the mempool is its own.
    #[tokio::test]
    async fn a_spend_is_reported_before_it_is_broadcast() {
        let chain = chain(vec![Some(0), Some(2)]);
        let seen: Mutex<Vec<(Txid, usize)>> = Mutex::new(Vec::new());

        confirm_or_bump(
            &chain,
            spk().as_script(),
            htlc_outpoint(),
            &cfg(None),
            None,
            &|txid| seen.lock().unwrap().push((txid, chain.broadcast_count())),
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();

        let seen = seen.lock().unwrap();
        let broadcasts = chain.broadcasts();
        assert!(!seen.is_empty());
        assert_eq!(seen.len(), broadcasts.len(), "one report per broadcast");
        for (i, (txid, count_at_report)) in seen.iter().enumerate() {
            // The i-th report happens when i transactions have gone out, so its own has not.
            // Reporting afterwards is the ordering that loses the txid to a crash.
            assert_eq!(*count_at_report, i, "report {i} came after its broadcast");
            assert_eq!(*txid, broadcasts[i].compute_txid());
        }
    }

    #[tokio::test]
    async fn our_own_replacement_is_not_mistaken_for_a_rival() {
        // The first build (at the floor rate) is what `find_spend` will report.
        let ours = tx_paying(100_000 - 5);
        let chain = chain(vec![Some(0), Some(3)]).with_spend(ours);
        let out = confirm_or_bump(
            &chain,
            spk().as_script(),
            htlc_outpoint(),
            &cfg(None),
            None,
            &|_| {},
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        assert!(
            matches!(out, SpendOutcome::Confirmed { .. }),
            "our own earlier broadcast must count as ours, got {out:?}"
        );
    }

    /// A claim that never confirms must give up at its deadline rather than spinning.
    #[tokio::test]
    async fn a_claim_gives_up_at_its_deadline() {
        let chain = chain(vec![Some(0)]);
        chain.set_tip(800_000);
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            confirm_or_bump(
                &chain,
                spk().as_script(),
                htlc_outpoint(),
                &cfg(Some(800_000)), // the deadline is already here
                None,
                &|_| {},
                |rate| Ok(tx_paying(100_000 - rate)),
            ),
        )
        .await
        .expect("must not loop forever")
        .unwrap();
        assert!(matches!(out, SpendOutcome::DeadlineExceeded { .. }));
    }

    /// A refund has no chain deadline, but must still hand control back rather than running for
    /// ever against a stalled backend.
    #[tokio::test]
    async fn a_refund_without_a_deadline_still_terminates() {
        let chain = chain(vec![Some(0)]);
        let mut c = cfg(None);
        c.max_iterations = 5;
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            confirm_or_bump(
                &chain,
                spk().as_script(),
                htlc_outpoint(),
                &c,
                None,
                &|_| {},
                |rate| Ok(tx_paying(100_000 - rate)),
            ),
        )
        .await
        .expect("must not loop forever")
        .unwrap();
        assert!(matches!(out, SpendOutcome::DeadlineExceeded { .. }));
    }

    #[tokio::test]
    async fn a_reorged_out_spend_is_rebroadcast() {
        // Confirms, then vanishes (reorged out), then confirms again.
        let chain = chain(vec![Some(1), None, Some(2)]);
        confirm_or_bump(
            &chain,
            spk().as_script(),
            htlc_outpoint(),
            &cfg(None),
            None,
            &|_| {},
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        assert!(
            chain.broadcast_count() >= 2,
            "a reorged-out spend must be put back on the wire"
        );
    }

    #[tokio::test]
    async fn cpfp_is_tried_when_a_replacement_is_rejected() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let chain = chain(vec![Some(0), Some(2)]).rejecting_replacements();
        let called = AtomicBool::new(false);
        let cpfp = |_parent: Txid, _rate: u64| -> Option<Txid> {
            called.store(true, Ordering::SeqCst);
            Some(tx_paying(1).compute_txid())
        };
        confirm_or_bump(
            &chain,
            spk().as_script(),
            htlc_outpoint(),
            &cfg(Some(800_010)),
            Some(&cpfp),
            &|_| {},
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn already_final_returns_without_bumping() {
        let chain = chain(vec![Some(6)]);
        confirm_or_bump(
            &chain,
            spk().as_script(),
            htlc_outpoint(),
            &cfg(None),
            None,
            &|_| {},
            |rate| Ok(tx_paying(100_000 - rate)),
        )
        .await
        .unwrap();
        assert_eq!(chain.broadcast_count(), 1);
    }
}
