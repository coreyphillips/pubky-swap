//! What a swap costs the provider to run, so the quote can cover it.
//!
//! The provider pays a miner fee on every swap it completes, and the fee lands on a different
//! transaction in each direction: it funds the HTLC in a reverse swap, and claims one in a
//! submarine swap. On top of that, some fraction of reverse swaps end in a refund sweep the
//! provider also pays for and earns nothing on, because the client that walked away is not
//! charged.
//!
//! None of that was in the price. With the shipped defaults (500 sat base, 2000 ppm) a 100k sat
//! swap earned 700 sat against a funding transaction costing about 770 sat at the 5 sat/vB
//! mainnet floor: a loss on every swap, before routing fees and before the refund sweeps. The
//! numbers below turn that into something an operator can reason about.

use bitcoin::Script;
use swap_common::onchain::spend_vsize;
use swap_common::SwapDirection;

/// vsize of a typical HTLC funding transaction: one P2WPKH input, a P2WSH output, and change.
///
/// The wallet chooses the real shape, so this is an estimate, but it is the right order and errs
/// slightly high.
pub const FUNDING_VSIZE: u64 = 154;

/// Share of reverse swaps assumed to end in a refund, in basis points.
///
/// A client that pays the hold invoice and then never claims costs the provider a funding fee, a
/// refund fee, and the timeout's worth of locked capital, while paying nothing itself: the
/// invoice is cancelled and its money returned. Nothing stops a client doing that repeatedly.
/// Pricing an expected refund rate into every swap is what makes honest flow cover it; the
/// per-peer limits elsewhere bound how fast one counterparty can exploit it.
pub const REFUND_RESERVE_BPS: u16 = 2_500; // 25%

/// Margin over the point estimate, in basis points.
///
/// The fee is quoted now and paid later, at whatever the mempool is doing then. Pricing at the
/// current rate exactly means being wrong half the time in the direction that costs money.
pub const FEE_SAFETY_BPS: u32 = 15_000; // 150%

/// What the provider expects to spend on chain for one swap in `direction`.
pub fn expected_onchain_cost_sat(
    direction: SwapDirection,
    fee_rate_sat_vb: u64,
    redeem_script: &Script,
    dest_spk: &Script,
) -> u64 {
    let claim = spend_vsize(redeem_script, dest_spk, true);
    let refund = spend_vsize(redeem_script, dest_spk, false);

    let base_vsize = match direction {
        // We fund the HTLC, and pay for a refund sweep on the share of swaps the client abandons.
        SwapDirection::Reverse => {
            FUNDING_VSIZE + (refund.saturating_mul(u64::from(REFUND_RESERVE_BPS)) / 10_000)
        }
        // We claim the client's HTLC. If we never pay the invoice we never claim, so there is no
        // refund share to reserve for: the client refunds its own funding.
        SwapDirection::Submarine => claim,
    };

    let point = base_vsize.saturating_mul(fee_rate_sat_vb);
    point.saturating_mul(u64::from(FEE_SAFETY_BPS)) / 10_000
}

/// A representative HTLC script, for pricing before a real one exists.
///
/// An offer is advertised before any counterparty keys are known, so the cost estimate needs a
/// script of the right shape. Every HTLC this crate builds has the same structure and length, so
/// a placeholder built from fixed keys measures the same.
pub fn representative_htlc_script() -> bitcoin::ScriptBuf {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let key = |b: u8| {
        bitcoin::PublicKey::new(
            SecretKey::from_slice(&[b; 32])
                .expect("a fixed non-zero scalar is a valid secret key")
                .public_key(&secp),
        )
    };
    swap_common::htlc::build_htlc_script(&[0u8; 32], &key(1), &key(2), 800_000)
}

/// A representative P2WPKH sweep destination, for the same reason.
pub fn representative_dest_spk() -> bitcoin::ScriptBuf {
    bitcoin::ScriptBuf::from(vec![
        0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this module exists for: at the shipped defaults, a mainnet swap cost more than
    /// it earned.
    #[test]
    fn the_quote_covers_what_the_swap_costs() {
        let script = representative_htlc_script();
        let dest = representative_dest_spk();
        // The mainnet fee floor the provider refuses to start below.
        let rate = 5;

        let reverse = expected_onchain_cost_sat(SwapDirection::Reverse, rate, &script, &dest);
        let submarine = expected_onchain_cost_sat(SwapDirection::Submarine, rate, &script, &dest);

        // The old pricing: 500 sat base + 2000 ppm on 100k sat.
        let old_fee = 500 + 100_000 * 2_000 / 1_000_000;
        assert_eq!(old_fee, 700);
        assert!(
            reverse > old_fee,
            "a reverse swap costs {reverse} sat, which the old 700 sat fee did not cover"
        );

        // Both are in a sane range: hundreds to low thousands of sats, not tens.
        assert!((700..5_000).contains(&reverse), "reverse cost {reverse}");
        assert!(
            (700..5_000).contains(&submarine),
            "submarine cost {submarine}"
        );

        // A reverse swap costs more than a submarine one: it pays for a funding transaction plus
        // a share of refund sweeps, against a single claim.
        assert!(reverse > submarine);
    }

    #[test]
    fn cost_scales_with_the_fee_environment() {
        let script = representative_htlc_script();
        let dest = representative_dest_spk();
        let cheap = expected_onchain_cost_sat(SwapDirection::Reverse, 1, &script, &dest);
        let busy = expected_onchain_cost_sat(SwapDirection::Reverse, 100, &script, &dest);
        assert!(
            busy > cheap * 50,
            "cost must track the mempool: {cheap} -> {busy}"
        );
    }

    #[test]
    fn an_absurd_fee_rate_saturates_rather_than_overflowing() {
        let script = representative_htlc_script();
        let dest = representative_dest_spk();
        let _ = expected_onchain_cost_sat(SwapDirection::Reverse, u64::MAX, &script, &dest);
    }

    /// The advertised minimum has to rise with the fee environment, or a swap priced when fees
    /// were low becomes one where the fee is most of the trade.
    #[test]
    fn the_minimum_swap_size_tracks_the_fee_environment() {
        use swap_common::messages::SwapOffer;
        use swap_common::NetworkSpec;
        use uuid::Uuid;

        let offer = |onchain_fee_sat| SwapOffer {
            offer_id: Uuid::nil(),
            provider_pkarr: String::new(),
            network: NetworkSpec::Bitcoin,
            directions: vec![SwapDirection::Reverse],
            min_amount_sat: 10_000,
            max_amount_sat: 1_000_000,
            base_fee_sat: 500,
            fee_ppm: 2_000,
            required_confirmations: 2,
            htlc_timeout_blocks: 144,
            lightning_node_id: None,
            valid_until_unix: 0,
            onchain_fee_sat,
            fee_rate_sat_vb: 5,
            protocol_version: swap_common::messages::PROTOCOL_VERSION,
            features: Vec::new(),
        };

        // Quiet mempool: the configured minimum stands.
        assert_eq!(offer(500).effective_min_amount_sat(), 10_000);
        // Busy: a 10k sat swap would be mostly fee, so the floor rises.
        assert_eq!(offer(2_000).effective_min_amount_sat(), 20_000);
        assert!(!offer(2_000).accepts_amount(10_000));

        // And the quote itemises what the client is paying for.
        let fee = offer(1_400).quote_fee(100_000);
        assert_eq!(fee.service_fee_sat, 700);
        assert_eq!(fee.onchain_fee_sat, 1_400);
        assert_eq!(fee.total_fee_sat, 2_100);
    }
}
