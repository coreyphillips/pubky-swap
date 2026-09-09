//! Cross-leg timelock invariants.
//!
//! A swap has two legs with independent clocks: an on-chain HTLC that refunds at an absolute
//! block height, and a Lightning HTLC that expires at a block height derived from the invoice's
//! final CLTV delta at the moment the payment is routed. Atomicity only holds while the two are
//! ordered correctly, and the ordering is *not* something either leg enforces on its own.
//!
//! The rule for a reverse swap is that the Lightning leg must **outlive** the on-chain leg. If
//! the incoming LN HTLC expires first, the client gets its sats back over Lightning and can then
//! still claim the on-chain HTLC before the provider's refund branch opens: the provider loses
//! the full on-chain amount for free. Nothing in the script or the invoice prevents that; only
//! this arithmetic does.
//!
//! The rule for a submarine swap is that the provider must not perform its irreversible act
//! (paying the client's invoice) unless enough blocks remain to get its on-chain claim confirmed
//! before the client's refund branch opens.
//!
//! Every function here is pure and total. They take heights and deltas, never a clock or a chain,
//! so the whole model is unit- and property-testable without any I/O.

use std::fmt;

/// Blocks a party should assume it needs to get an on-chain refund confirmed once its refund
/// window opens. Sized for a fee-bumped sweep under ordinary congestion.
pub const REFUND_CONFIRM_BLOCKS: u32 = 18;

/// Blocks before an accepted HTLC's expiry at which a Lightning node force-cancels a held
/// invoice to protect its channel. LND's `--invoices.holdexpirydelta` defaults to 24, and
/// beignet's hold sweeper uses 18; the larger value is the safe one to reserve.
///
/// The provider must be finished with the invoice *before* this point, so it is reserved on top
/// of the on-chain refund window rather than shared with it.
pub const LN_HOLD_EXPIRY_DELTA: u32 = 24;

/// Extra headroom in the hold invoice's final CLTV delta to absorb the gap between issuing the
/// invoice and the client actually paying it. The on-chain timeout is fixed at accept time while
/// the LN expiry is only fixed at payment time, so a late payment pushes the LN expiry *later*,
/// never earlier. This slack covers the reverse: a client that pays immediately still gets an LN
/// expiry comfortably past the on-chain timeout.
pub const REVERSE_LATE_PAYMENT_SLACK: u32 = 30;

/// Blocks a provider needs to get a submarine claim confirmed before the client's refund branch
/// opens. Also the minimum window it will accept before paying the invoice at all.
pub const PROVIDER_MIN_CLAIM_WINDOW: u32 = 18;

/// Blocks a client needs to get a reverse claim confirmed before the provider's refund branch
/// opens.
pub const CLIENT_CLAIM_WINDOW: u32 = 18;

/// Never *start* a claim this close to the counterparty's refund window. Broadcasting a first
/// claim inside this margin reveals the preimage into a race that cannot be won, which is
/// strictly worse than not claiming: the counterparty learns the preimage and refunds anyway.
///
/// A claim already in flight keeps being fee-bumped past this point; only the first broadcast is
/// gated.
pub const CLAIM_ABORT_MARGIN: u32 = 6;

/// Slack between a funding reaching its required depth and the claim window being usable.
pub const FUNDING_GRACE: u32 = 6;

/// Ceiling on how far out a counterparty may push a timeout. Anything beyond this locks the
/// funding party's capital for an unreasonable time and is refused.
pub const MAX_TIMEOUT_BLOCKS: u32 = 1_008; // ~1 week

/// Tunable half of the timelock model. The constants above are protocol-shaped and rarely need
/// changing; these are the operator's knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimelockParams {
    /// Blocks from the accept height to the on-chain HTLC's refund branch opening.
    pub htlc_timeout_blocks: u32,
    /// Confirmations a funding needs before it is acted on.
    pub required_confirmations: u32,
    /// Minimum blocks that must remain before an irreversible act (the provider paying a
    /// submarine invoice, or a first claim broadcast).
    pub min_claim_window_blocks: u32,
    /// Blocks reserved for getting a refund confirmed.
    pub refund_confirm_blocks: u32,
    /// Blocks the Lightning node reserves before an accepted HTLC's expiry.
    pub ln_hold_expiry_delta: u32,
    /// Headroom added to the hold invoice's final CLTV delta.
    pub late_payment_slack: u32,
    /// Ceiling on an accepted timeout height, relative to the current tip.
    pub max_timeout_blocks: u32,
}

impl Default for TimelockParams {
    fn default() -> Self {
        Self {
            htlc_timeout_blocks: 144,
            required_confirmations: 1,
            min_claim_window_blocks: PROVIDER_MIN_CLAIM_WINDOW,
            refund_confirm_blocks: REFUND_CONFIRM_BLOCKS,
            ln_hold_expiry_delta: LN_HOLD_EXPIRY_DELTA,
            late_payment_slack: REVERSE_LATE_PAYMENT_SLACK,
            max_timeout_blocks: MAX_TIMEOUT_BLOCKS,
        }
    }
}

/// Why a timelock check refused. Each variant carries what was seen and what was needed, so the
/// operator log says which number to change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelockViolation {
    /// The incoming Lightning HTLC expires before our on-chain refund can be confirmed. This is
    /// the reverse-swap theft condition: refusing here is what makes the swap safe.
    LnExpiryTooEarly {
        ln_expiry: u32,
        onchain_timeout: u32,
        need: u32,
    },
    /// Too few blocks remain before the counterparty's refund branch opens to risk an
    /// irreversible act.
    ClaimWindowTooShort { tip: u32, timeout: u32, need: u32 },
    /// Our *outgoing* Lightning HTLC could outlive the on-chain leg it is paying for. This is
    /// the submarine-swap theft condition, and the mirror of `LnExpiryTooEarly`: a payee that
    /// holds the payment until after the on-chain refund opens can take its coins back on chain
    /// and *then* settle, collecting both legs.
    LnExpiryTooLate {
        ln_expiry: u32,
        onchain_timeout: u32,
        latest: u32,
    },
    /// The counterparty proposed a timeout further out than we will lock capital for.
    TimeoutTooFar { timeout: u32, tip: u32, max: u32 },
    /// The proposed timeout is already at or behind the tip.
    TimeoutInPast { timeout: u32, tip: u32 },
    /// The configured parameters cannot satisfy the invariants at any tip.
    ParamsUnsatisfiable { detail: &'static str },
    /// A height computation overflowed `u32`.
    Overflow,
}

impl fmt::Display for TimelockViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LnExpiryTooEarly {
                ln_expiry,
                onchain_timeout,
                need,
            } => write!(
                f,
                "lightning HTLC expires at height {ln_expiry} but the on-chain HTLC refunds at \
                 {onchain_timeout}; the lightning leg must survive to at least {need}"
            ),
            Self::LnExpiryTooLate {
                ln_expiry,
                onchain_timeout,
                latest,
            } => write!(
                f,
                "the outgoing lightning HTLC could expire as late as {ln_expiry}, but the \
                 on-chain HTLC refunds at {onchain_timeout}; it must end by {latest} to leave \
                 room to claim"
            ),
            Self::ClaimWindowTooShort { tip, timeout, need } => write!(
                f,
                "only {} block(s) remain to the timeout at {timeout} (tip {tip}); {need} are needed",
                timeout.saturating_sub(*tip)
            ),
            Self::TimeoutTooFar { timeout, tip, max } => write!(
                f,
                "timeout height {timeout} is {} blocks past the tip {tip}; the ceiling is {max}",
                timeout.saturating_sub(*tip)
            ),
            Self::TimeoutInPast { timeout, tip } => {
                write!(f, "timeout height {timeout} is not ahead of the tip {tip}")
            }
            Self::ParamsUnsatisfiable { detail } => {
                write!(f, "timelock parameters are unsatisfiable: {detail}")
            }
            Self::Overflow => write!(f, "block height arithmetic overflowed"),
        }
    }
}

impl std::error::Error for TimelockViolation {}

/// The absolute height at which the on-chain HTLC's refund branch opens, for a swap accepted at
/// `tip`. Checked, so a pathological configuration cannot wrap into a past height.
pub fn onchain_timeout(tip: u32, p: &TimelockParams) -> Result<u32, TimelockViolation> {
    tip.checked_add(p.htlc_timeout_blocks)
        .ok_or(TimelockViolation::Overflow)
}

/// The final CLTV expiry delta (in blocks) to put on a reverse swap's hold invoice.
///
/// The incoming Lightning HTLC must survive long enough for the provider to notice the on-chain
/// timeout, get a refund confirmed, and still be inside the window where its node will let it
/// settle. Because the delta is applied at payment time and the on-chain timeout is fixed at
/// accept time, the realised LN expiry is always at least this far past the accept height.
pub fn reverse_invoice_cltv_delta(p: &TimelockParams) -> Result<u32, TimelockViolation> {
    p.htlc_timeout_blocks
        .checked_add(p.refund_confirm_blocks)
        .and_then(|v| v.checked_add(p.ln_hold_expiry_delta))
        .and_then(|v| v.checked_add(p.late_payment_slack))
        .ok_or(TimelockViolation::Overflow)
}

/// The height the Lightning leg must survive to, for an on-chain timeout at `onchain_timeout`.
pub fn required_ln_expiry(
    onchain_timeout: u32,
    p: &TimelockParams,
) -> Result<u32, TimelockViolation> {
    onchain_timeout
        .checked_add(p.refund_confirm_blocks)
        .and_then(|v| v.checked_add(p.ln_hold_expiry_delta))
        .ok_or(TimelockViolation::Overflow)
}

/// Provider-side gate for a reverse swap, run **after** the hold invoice is accepted and
/// **before** any on-chain funds are committed.
///
/// `ln_expiry` is the realised expiry height of the accepted incoming HTLC as the node reports
/// it, not the delta we asked for. Verifying the realised value is the point: a node that
/// ignored or clamped the requested delta would otherwise leave the swap in exactly the unsafe
/// configuration this check exists to catch.
///
/// Refusing here costs nobody anything. The client's payment is still held, so cancelling the
/// invoice returns it in full.
pub fn check_reverse_before_fund(
    tip: u32,
    onchain_timeout: u32,
    ln_expiry: u32,
    p: &TimelockParams,
) -> Result<(), TimelockViolation> {
    // I-R3: the lightning leg must outlive the on-chain leg plus our refund window.
    let need = required_ln_expiry(onchain_timeout, p)?;
    if ln_expiry < need {
        return Err(TimelockViolation::LnExpiryTooEarly {
            ln_expiry,
            onchain_timeout,
            need,
        });
    }

    // I-R4: enough blocks must remain for the client to confirm its claim and for us to still
    // have a refund window afterwards. A client that pays very late gets refused rather than
    // handed an HTLC it cannot safely claim.
    let need_blocks = p
        .required_confirmations
        .checked_add(CLIENT_CLAIM_WINDOW)
        .and_then(|v| v.checked_add(p.refund_confirm_blocks))
        .ok_or(TimelockViolation::Overflow)?;
    let remaining = onchain_timeout.saturating_sub(tip);
    if remaining < need_blocks {
        return Err(TimelockViolation::ClaimWindowTooShort {
            tip,
            timeout: onchain_timeout,
            need: need_blocks,
        });
    }
    Ok(())
}

/// Provider-side gate for a submarine swap, run immediately **before** paying the client's
/// invoice. Paying is irreversible; the on-chain claim that recovers the money is not guaranteed,
/// so it must have a real window to confirm in.
pub fn check_submarine_before_pay(
    tip: u32,
    timeout_height: u32,
    p: &TimelockParams,
) -> Result<(), TimelockViolation> {
    if timeout_height <= tip {
        return Err(TimelockViolation::TimeoutInPast {
            timeout: timeout_height,
            tip,
        });
    }
    let remaining = timeout_height - tip;
    if remaining < p.min_claim_window_blocks {
        return Err(TimelockViolation::ClaimWindowTooShort {
            tip,
            timeout: timeout_height,
            need: p.min_claim_window_blocks,
        });
    }
    Ok(())
}

/// The furthest out a submarine provider's outgoing Lightning HTLC may expire.
///
/// The payee decides when to settle, any time up to that height, and settling is what reveals the
/// preimage the provider needs to claim on chain. So the Lightning leg has to end early enough
/// that a claim still fits before the client's refund branch opens. Everything after that point
/// belongs to the client: they refund on chain, then settle, and the provider has paid for
/// nothing.
///
/// Returns `None` if there is no room at all, which is itself a refusal.
pub fn submarine_cltv_budget(tip: u32, timeout_height: u32, p: &TimelockParams) -> Option<u32> {
    timeout_height
        .checked_sub(tip)?
        .checked_sub(p.min_claim_window_blocks)
        .filter(|budget| *budget > 0)
}

/// Gate on the client's invoice before a submarine provider commits to paying it.
///
/// `min_final_cltv_expiry` is the payee's own demand, and only the floor of what the outgoing
/// HTLC will carry: the route adds its own deltas on top. Both are bounded by the `cltv_limit`
/// the payment is sent with, which is what actually enforces this; refusing here means a request
/// that could never fit is turned down before a payment is attempted rather than after.
pub fn check_submarine_invoice_cltv(
    tip: u32,
    timeout_height: u32,
    min_final_cltv_expiry: u32,
    p: &TimelockParams,
) -> Result<(), TimelockViolation> {
    let budget = submarine_cltv_budget(tip, timeout_height, p).ok_or(
        TimelockViolation::ClaimWindowTooShort {
            tip,
            timeout: timeout_height,
            need: p.min_claim_window_blocks,
        },
    )?;
    if min_final_cltv_expiry >= budget {
        return Err(TimelockViolation::LnExpiryTooLate {
            ln_expiry: tip.saturating_add(min_final_cltv_expiry),
            onchain_timeout: timeout_height,
            latest: tip.saturating_add(budget),
        });
    }
    Ok(())
}

/// Client-side gate on a provider's proposed reverse-swap timeout, run before paying anything.
pub fn check_client_reverse_accept(
    tip: u32,
    timeout_height: u32,
    p: &TimelockParams,
) -> Result<(), TimelockViolation> {
    check_timeout_ceiling(tip, timeout_height, p)?;
    let need = p
        .required_confirmations
        .checked_add(CLIENT_CLAIM_WINDOW)
        .and_then(|v| v.checked_add(CLAIM_ABORT_MARGIN))
        .ok_or(TimelockViolation::Overflow)?;
    let remaining = timeout_height - tip;
    if remaining < need {
        return Err(TimelockViolation::ClaimWindowTooShort {
            tip,
            timeout: timeout_height,
            need,
        });
    }
    Ok(())
}

/// Client-side gate on a provider's proposed submarine-swap timeout, run before funding.
///
/// The client is the funder here, so the risk is inverted: too *short* a timeout and the provider
/// cannot claim, too *long* and the client's capital is locked. Both ends are checked.
pub fn check_client_submarine_accept(
    tip: u32,
    timeout_height: u32,
    p: &TimelockParams,
) -> Result<(), TimelockViolation> {
    check_timeout_ceiling(tip, timeout_height, p)?;
    let need = p
        .required_confirmations
        .checked_add(PROVIDER_MIN_CLAIM_WINDOW)
        .and_then(|v| v.checked_add(FUNDING_GRACE))
        .ok_or(TimelockViolation::Overflow)?;
    let remaining = timeout_height - tip;
    if remaining < need {
        return Err(TimelockViolation::ClaimWindowTooShort {
            tip,
            timeout: timeout_height,
            need,
        });
    }
    Ok(())
}

/// Whether a *first* claim broadcast is still safe. An in-flight claim keeps being bumped past
/// this point; this only gates revealing the preimage in the first place.
pub fn claim_start_is_safe(tip: u32, timeout_height: u32) -> bool {
    timeout_height > tip && timeout_height - tip > CLAIM_ABORT_MARGIN
}

/// Startup validation: can these parameters ever satisfy the submarine invariant?
///
/// `htlc_timeout_blocks` has to cover the funding depth, a grace period, and the provider's claim
/// window. A configuration that cannot is refused at startup rather than at the first swap.
pub fn validate_params(p: &TimelockParams) -> Result<(), TimelockViolation> {
    let need = p
        .required_confirmations
        .checked_add(FUNDING_GRACE)
        .and_then(|v| v.checked_add(p.min_claim_window_blocks))
        .ok_or(TimelockViolation::Overflow)?;
    if p.htlc_timeout_blocks < need {
        return Err(TimelockViolation::ParamsUnsatisfiable {
            detail: "htlc_timeout_blocks is shorter than required_confirmations + funding grace \
                     + min_claim_window_blocks",
        });
    }
    if p.htlc_timeout_blocks > p.max_timeout_blocks {
        return Err(TimelockViolation::ParamsUnsatisfiable {
            detail: "htlc_timeout_blocks exceeds max_timeout_blocks",
        });
    }
    // The invoice delta must be expressible, and must stay inside the range Lightning nodes
    // accept for a final CLTV expiry (LND's --max-cltv-expiry defaults to 2016).
    let delta = reverse_invoice_cltv_delta(p)?;
    if delta > 2016 {
        return Err(TimelockViolation::ParamsUnsatisfiable {
            detail: "the derived hold-invoice CLTV delta exceeds the 2016-block ceiling most \
                     Lightning nodes enforce; lower htlc_timeout_blocks",
        });
    }
    Ok(())
}

fn check_timeout_ceiling(
    tip: u32,
    timeout_height: u32,
    p: &TimelockParams,
) -> Result<(), TimelockViolation> {
    if timeout_height <= tip {
        return Err(TimelockViolation::TimeoutInPast {
            timeout: timeout_height,
            tip,
        });
    }
    if timeout_height - tip > p.max_timeout_blocks {
        return Err(TimelockViolation::TimeoutTooFar {
            timeout: timeout_height,
            tip,
            max: p.max_timeout_blocks,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped defaults: a 144-block on-chain timeout at 1 confirmation.
    fn params() -> TimelockParams {
        TimelockParams::default()
    }

    #[test]
    fn defaults_are_satisfiable() {
        validate_params(&params()).expect("the shipped defaults must be usable");
    }

    #[test]
    fn invoice_delta_outlives_the_onchain_timeout() {
        let p = params();
        // 144 + 18 + 24 + 30
        assert_eq!(reverse_invoice_cltv_delta(&p).unwrap(), 216);
        // The delta must exceed the on-chain timeout by at least the refund window plus the
        // node's hold-expiry reserve, or the lightning leg dies first.
        assert!(
            reverse_invoice_cltv_delta(&p).unwrap()
                >= p.htlc_timeout_blocks + p.refund_confirm_blocks + p.ln_hold_expiry_delta
        );
    }

    /// The bug this module exists to prevent: LND's default final CLTV delta is 80 blocks while
    /// the on-chain HTLC refunds after 144. The lightning leg expires roughly 64 blocks early, so
    /// a client can take its sats back over Lightning and still claim the on-chain HTLC for free.
    #[test]
    fn rejects_lnds_default_cltv_delta_against_a_144_block_timeout() {
        let p = params();
        let tip = 800_000;
        let onchain_timeout = onchain_timeout(tip, &p).unwrap();
        // What LND produces when `cltv_expiry` is left at 0: tip + bitcoin.timelockdelta.
        let ln_expiry = tip + 80;

        let err = check_reverse_before_fund(tip, onchain_timeout, ln_expiry, &p)
            .expect_err("an 80-block lightning leg against a 144-block on-chain leg is theft");
        match err {
            TimelockViolation::LnExpiryTooEarly {
                ln_expiry: got,
                onchain_timeout: t,
                need,
            } => {
                assert_eq!(got, tip + 80);
                assert_eq!(t, tip + 144);
                assert_eq!(need, tip + 144 + 18 + 24);
            }
            other => panic!("expected LnExpiryTooEarly, got {other:?}"),
        }
    }

    #[test]
    fn accepts_an_ln_expiry_derived_from_our_own_delta() {
        let p = params();
        let tip = 800_000;
        let onchain_timeout = onchain_timeout(tip, &p).unwrap();
        // A payment routed at the tip with the delta we asked for.
        let ln_expiry = tip + reverse_invoice_cltv_delta(&p).unwrap();
        check_reverse_before_fund(tip, onchain_timeout, ln_expiry, &p)
            .expect("our own delta must satisfy the invariant it was derived from");
    }

    #[test]
    fn a_late_payment_only_pushes_the_ln_expiry_further_out() {
        let p = params();
        let accept_tip = 800_000;
        let onchain_timeout = onchain_timeout(accept_tip, &p).unwrap();
        // The client waits 130 blocks before paying. The LN expiry is measured from the
        // payment, so it moves later while the on-chain timeout stays put: the lightning
        // ordering only gets safer.
        let pay_tip = accept_tip + 130;
        let ln_expiry = pay_tip + reverse_invoice_cltv_delta(&p).unwrap();
        // The lightning ordering still holds...
        assert!(ln_expiry >= required_ln_expiry(onchain_timeout, &p).unwrap());
        // ...but the on-chain window has shrunk too far to hand the client an HTLC it can claim.
        assert!(matches!(
            check_reverse_before_fund(pay_tip, onchain_timeout, ln_expiry, &p),
            Err(TimelockViolation::ClaimWindowTooShort { .. })
        ));
    }

    #[test]
    fn ln_expiry_exactly_at_the_boundary_is_accepted() {
        let p = params();
        let tip = 800_000;
        let t = onchain_timeout(tip, &p).unwrap();
        let need = required_ln_expiry(t, &p).unwrap();
        check_reverse_before_fund(tip, t, need, &p).expect("exactly at the boundary is safe");
        assert!(check_reverse_before_fund(tip, t, need - 1, &p).is_err());
    }

    #[test]
    fn submarine_refuses_to_pay_inside_the_claim_window() {
        let p = params();
        let tip = 800_000;
        let timeout = tip + p.min_claim_window_blocks;
        check_submarine_before_pay(tip, timeout, &p).expect("exactly the window is enough");
        // One block less and paying is a race the client's refund wins.
        assert!(matches!(
            check_submarine_before_pay(tip, timeout - 1, &p),
            Err(TimelockViolation::ClaimWindowTooShort { .. })
        ));
        // The audit's concrete attack: funding lands two blocks before the refund opens.
        assert!(check_submarine_before_pay(tip, tip + 2, &p).is_err());
        // And a timeout already reached.
        assert!(matches!(
            check_submarine_before_pay(tip, tip, &p),
            Err(TimelockViolation::TimeoutInPast { .. })
        ));
    }

    #[test]
    fn client_rejects_a_timeout_that_is_too_near_or_too_far() {
        let p = params();
        let tip = 800_000;
        // A hostile provider setting the timeout at the tip so its refund branch is live at once.
        assert!(check_client_reverse_accept(tip, tip, &p).is_err());
        assert!(check_client_reverse_accept(tip, tip + 1, &p).is_err());
        // A hostile provider locking the client's coins for years.
        assert!(matches!(
            check_client_submarine_accept(tip, tip + p.max_timeout_blocks + 1, &p),
            Err(TimelockViolation::TimeoutTooFar { .. })
        ));
        // The honest default is accepted by both directions.
        check_client_reverse_accept(tip, tip + p.htlc_timeout_blocks, &p).unwrap();
        check_client_submarine_accept(tip, tip + p.htlc_timeout_blocks, &p).unwrap();
    }

    #[test]
    fn claim_start_is_gated_by_the_abort_margin() {
        let tip = 800_000;
        assert!(claim_start_is_safe(tip, tip + CLAIM_ABORT_MARGIN + 1));
        assert!(!claim_start_is_safe(tip, tip + CLAIM_ABORT_MARGIN));
        assert!(!claim_start_is_safe(tip, tip));
        assert!(!claim_start_is_safe(tip, tip - 1));
    }

    #[test]
    fn heights_near_the_ceiling_do_not_wrap() {
        let p = params();
        let tip = u32::MAX - 1;
        assert_eq!(onchain_timeout(tip, &p), Err(TimelockViolation::Overflow));
        assert_eq!(
            required_ln_expiry(u32::MAX, &p),
            Err(TimelockViolation::Overflow)
        );
        let huge = TimelockParams {
            htlc_timeout_blocks: u32::MAX,
            ..p
        };
        assert_eq!(
            reverse_invoice_cltv_delta(&huge),
            Err(TimelockViolation::Overflow)
        );
    }

    #[test]
    fn unsatisfiable_params_are_refused_at_startup() {
        // A timeout shorter than the depth + grace + claim window can never work.
        let too_short = TimelockParams {
            htlc_timeout_blocks: 10,
            ..params()
        };
        assert!(matches!(
            validate_params(&too_short),
            Err(TimelockViolation::ParamsUnsatisfiable { .. })
        ));
        // A timeout so long the derived invoice delta exceeds what nodes accept.
        let too_long = TimelockParams {
            htlc_timeout_blocks: 2000,
            max_timeout_blocks: 4000,
            ..params()
        };
        assert!(matches!(
            validate_params(&too_long),
            Err(TimelockViolation::ParamsUnsatisfiable { .. })
        ));
        // A shorter reverse-style timeout is fine.
        let reverse = TimelockParams {
            htlc_timeout_blocks: 72,
            ..params()
        };
        validate_params(&reverse).unwrap();
    }

    /// Exhaustive sweep over a wide parameter space: whenever the provider agrees to fund, the
    /// four events must be strictly ordered, so no reachable configuration reproduces the bug.
    #[test]
    fn accepted_configurations_always_order_the_two_legs_correctly() {
        let mut checked = 0u32;
        for htlc_timeout_blocks in [24u32, 72, 144, 288, 1008] {
            for required_confirmations in [1u32, 2, 3, 6] {
                for min_claim_window_blocks in [6u32, 12, 18, 36] {
                    let p = TimelockParams {
                        htlc_timeout_blocks,
                        required_confirmations,
                        min_claim_window_blocks,
                        ..TimelockParams::default()
                    };
                    if validate_params(&p).is_err() {
                        continue;
                    }
                    let delta = reverse_invoice_cltv_delta(&p).unwrap();
                    for tip in [1u32, 500_000, 800_000] {
                        for pay_delay in [0u32, 1, 10, 60] {
                            let t = onchain_timeout(tip, &p).unwrap();
                            let pay_tip = tip + pay_delay;
                            let ln_expiry = pay_tip + delta;
                            if check_reverse_before_fund(pay_tip, t, ln_expiry, &p).is_err() {
                                continue;
                            }
                            checked += 1;

                            // The client must be able to confirm a claim before the refund opens.
                            let client_claim_deadline =
                                pay_tip + p.required_confirmations + CLIENT_CLAIM_WINDOW;
                            assert!(
                                client_claim_deadline <= t,
                                "client claim deadline {client_claim_deadline} must not pass the \
                                 refund open {t}"
                            );
                            // The provider must be able to confirm its refund before its node
                            // force-cancels the held invoice.
                            let refund_confirmed_by = t + p.refund_confirm_blocks;
                            assert!(refund_confirmed_by < ln_expiry - p.ln_hold_expiry_delta + 1);
                            // And the whole ordering holds end to end.
                            assert!(client_claim_deadline <= t);
                            assert!(t < refund_confirmed_by);
                            assert!(refund_confirmed_by <= ln_expiry - p.ln_hold_expiry_delta);
                        }
                    }
                }
            }
        }
        assert!(
            checked > 100,
            "the sweep must actually accept configurations"
        );
    }
}
