//! Client-side validation of a provider's quote, acceptance, and invoice.
//!
//! The client already rebuilds the HTLC redeem script from its own key and payment hash and
//! compares it byte-for-byte, which binds the hash, both pubkeys, and the timeout height. What a
//! script comparison cannot bind is **value**: how much the client locks on-chain, how much it
//! pays over Lightning, and how deeply it insists a funding is buried before it reveals the
//! preimage. Those are the numbers a hostile provider gets to choose, so they are the ones that
//! have to be checked here.
//!
//! The governing rule is that a provider-supplied number must never reach a wallet call. Every
//! amount the client acts on is taken from the quote it already agreed to, and the provider's
//! echo of that amount is compared against it rather than used.

use crate::messages::{Quote, QuoteRequest, SwapAccept};
use crate::swap::SwapDirection;
use crate::timelock::{self, TimelockParams, TimelockViolation};
use std::fmt;

/// How long a quote may claim to be valid for. A provider offering an implausibly long window is
/// either broken or trying to get an old price honoured later.
pub const MAX_QUOTE_VALIDITY_SECS: u64 = 3_600;

/// Slack allowed between the timeout height a quote promised and the one the acceptance carries,
/// to absorb blocks found between the two messages.
pub const ACCEPT_TIMEOUT_SLACK_BLOCKS: u32 = 6;

/// Confirmations a client insists on before revealing a preimage, regardless of what the
/// provider quoted. Two blocks on mainnet; a single confirmation is cheap to reorg out.
pub const MIN_MAINNET_CONFIRMATIONS: u32 = 2;

/// A ceiling on the confirmations a provider may demand. An absurd depth is a griefing vector:
/// the client's Lightning payment is held while it waits for a funding to bury.
pub const MAX_REQUIRED_CONFIRMATIONS: u32 = 12;

/// What a client will and will not accept from a provider.
#[derive(Debug, Clone, Copy)]
pub struct ClientPolicy {
    /// Confirmations the client requires before acting, whatever the provider quoted. The
    /// effective value is `max(policy, quoted)`.
    pub min_required_confirmations: u32,
    /// Most confirmations the client will wait for.
    pub max_required_confirmations: u32,
    /// Most the client will pay in total fees, in basis points of the swap amount.
    pub max_fee_bps: u16,
    /// Hard ceiling on anything the client will lock on-chain or pay over Lightning.
    pub max_total_sat: u64,
    /// The timelock model the client checks the provider's heights against.
    pub timelock: TimelockParams,
}

impl ClientPolicy {
    /// A policy sized for `network`, with a mainnet-appropriate confirmation floor.
    pub fn for_network(network: bitcoin::Network, timelock: TimelockParams) -> Self {
        Self {
            min_required_confirmations: match network {
                bitcoin::Network::Bitcoin => MIN_MAINNET_CONFIRMATIONS,
                _ => 1,
            },
            max_required_confirmations: MAX_REQUIRED_CONFIRMATIONS,
            max_fee_bps: 500, // 5%
            max_total_sat: u64::MAX,
            timelock,
        }
    }

    /// The confirmations to actually act on: never fewer than our own floor.
    pub fn effective_confirmations(&self, quoted: u32) -> u32 {
        quoted.max(self.min_required_confirmations)
    }
}

/// Why the client refused to proceed. Each variant names what was seen and what was expected, so
/// the message alone is enough to tell an honest mismatch from an attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    QuoteIdMissing,
    OfferMismatch { got: String, want: String },
    DirectionMismatch,
    AmountMismatch { got: u64, want: u64 },
    QuoteExpired { now_unix: u64, valid_until: u64 },
    QuoteNeverExpires,
    QuoteValidTooLong { valid_for_secs: u64, max: u64 },
    TotalNotAmountPlusFee { total: u64, amount: u64, fee: u64 },
    FeeTooHigh { fee_sat: u64, max_sat: u64 },
    TotalTooLarge { total_sat: u64, max_sat: u64 },
    ConfirmationsTooLow { got: u32, min: u32 },
    ConfirmationsTooHigh { got: u32, max: u32 },
    SwapIdMissing,
    OnchainAmountMismatch { got: u64, want: u64 },
    TimeoutMismatch { got: u32, want: u32, slack: u32 },
    Timelock(TimelockViolation),
    PaymentHashMismatch,
    InvoiceAmountMismatch { got_msat: u64, want_msat: u64 },
    InvoiceHasNoAmount,
    InvoiceExpiresTooSoon { expires_at_unix: u64, need: u64 },
    MissingInvoice,
    Overflow,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuoteIdMissing => write!(f, "quote carries no id"),
            Self::OfferMismatch { got, want } => {
                write!(f, "quote is for offer {got}, not the requested {want}")
            }
            Self::DirectionMismatch => write!(f, "the reply is for a different swap direction"),
            Self::AmountMismatch { got, want } => {
                write!(f, "quoted amount {got} sat, requested {want} sat")
            }
            Self::QuoteExpired {
                now_unix,
                valid_until,
            } => write!(f, "quote expired at {valid_until} (now {now_unix})"),
            Self::QuoteNeverExpires => write!(
                f,
                "quote claims never to expire; a firm price must carry an expiry"
            ),
            Self::QuoteValidTooLong {
                valid_for_secs,
                max,
            } => write!(
                f,
                "quote claims {valid_for_secs}s of validity; the ceiling is {max}s"
            ),
            Self::TotalNotAmountPlusFee { total, amount, fee } => write!(
                f,
                "quote total {total} sat is not amount {amount} + fee {fee}"
            ),
            Self::FeeTooHigh { fee_sat, max_sat } => {
                write!(f, "fee {fee_sat} sat exceeds our ceiling of {max_sat} sat")
            }
            Self::TotalTooLarge { total_sat, max_sat } => {
                write!(
                    f,
                    "total {total_sat} sat exceeds our ceiling of {max_sat} sat"
                )
            }
            Self::ConfirmationsTooLow { got, min } => write!(
                f,
                "provider asks us to act at {got} confirmation(s); we require at least {min}"
            ),
            Self::ConfirmationsTooHigh { got, max } => write!(
                f,
                "provider demands {got} confirmations; our ceiling is {max}"
            ),
            Self::SwapIdMissing => write!(f, "acceptance carries no swap id"),
            Self::OnchainAmountMismatch { got, want } => write!(
                f,
                "provider asks for {got} sat on-chain but the quote agreed {want} sat"
            ),
            Self::TimeoutMismatch { got, want, slack } => write!(
                f,
                "acceptance sets the timeout at {got}, but the quote implied {want} \
                 (tolerance {slack} blocks)"
            ),
            Self::Timelock(v) => write!(f, "{v}"),
            Self::PaymentHashMismatch => {
                write!(f, "the invoice is not locked to our payment hash")
            }
            Self::InvoiceAmountMismatch {
                got_msat,
                want_msat,
            } => write!(
                f,
                "invoice asks for {got_msat} msat but the quote agreed {want_msat} msat"
            ),
            Self::InvoiceHasNoAmount => write!(
                f,
                "invoice carries no amount, so paying it would let the provider choose"
            ),
            Self::InvoiceExpiresTooSoon {
                expires_at_unix,
                need,
            } => write!(
                f,
                "invoice expires at {expires_at_unix}, before the swap can complete (need {need})"
            ),
            Self::MissingInvoice => write!(f, "acceptance carries no invoice"),
            Self::Overflow => write!(f, "amount arithmetic overflowed"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl From<TimelockViolation> for ValidationError {
    fn from(v: TimelockViolation) -> Self {
        ValidationError::Timelock(v)
    }
}

/// Check a quote against the request that produced it and against our own policy.
pub fn validate_quote(
    quote: &Quote,
    request: &QuoteRequest,
    now_unix: u64,
    policy: &ClientPolicy,
) -> Result<(), ValidationError> {
    if quote.quote_id.is_nil() {
        return Err(ValidationError::QuoteIdMissing);
    }
    // A nil offer id in the request means "your current offer", so only a named one binds.
    if !request.offer_id.is_nil() && quote.offer_id != request.offer_id {
        return Err(ValidationError::OfferMismatch {
            got: quote.offer_id.to_string(),
            want: request.offer_id.to_string(),
        });
    }
    if quote.direction != request.direction {
        return Err(ValidationError::DirectionMismatch);
    }
    if quote.amount_sat != request.amount_sat {
        return Err(ValidationError::AmountMismatch {
            got: quote.amount_sat,
            want: request.amount_sat,
        });
    }

    // A quote with no expiry is not a firm price, and one valid for hours lets a provider hold a
    // stale rate open. Both are refused.
    if quote.valid_until_unix == 0 {
        return Err(ValidationError::QuoteNeverExpires);
    }
    if quote.is_expired(now_unix) {
        return Err(ValidationError::QuoteExpired {
            now_unix,
            valid_until: quote.valid_until_unix,
        });
    }
    let valid_for = quote.valid_until_unix.saturating_sub(now_unix);
    if valid_for > MAX_QUOTE_VALIDITY_SECS {
        return Err(ValidationError::QuoteValidTooLong {
            valid_for_secs: valid_for,
            max: MAX_QUOTE_VALIDITY_SECS,
        });
    }

    // The total has to be exactly amount + fee, so there is nowhere for an unexplained charge.
    let expected_total = quote
        .amount_sat
        .checked_add(quote.fee_sat)
        .ok_or(ValidationError::Overflow)?;
    if quote.total_sat != expected_total {
        return Err(ValidationError::TotalNotAmountPlusFee {
            total: quote.total_sat,
            amount: quote.amount_sat,
            fee: quote.fee_sat,
        });
    }
    let max_fee = (u128::from(quote.amount_sat) * u128::from(policy.max_fee_bps) / 10_000) as u64;
    if quote.fee_sat > max_fee {
        return Err(ValidationError::FeeTooHigh {
            fee_sat: quote.fee_sat,
            max_sat: max_fee,
        });
    }
    if quote.total_sat > policy.max_total_sat {
        return Err(ValidationError::TotalTooLarge {
            total_sat: quote.total_sat,
            max_sat: policy.max_total_sat,
        });
    }

    // A provider quoting zero confirmations is asking us to act on a mempool-only funding it can
    // still replace. It would then learn the preimage from our claim and settle against a funding
    // that never confirmed.
    if quote.required_confirmations < policy.min_required_confirmations {
        return Err(ValidationError::ConfirmationsTooLow {
            got: quote.required_confirmations,
            min: policy.min_required_confirmations,
        });
    }
    if quote.required_confirmations > policy.max_required_confirmations {
        return Err(ValidationError::ConfirmationsTooHigh {
            got: quote.required_confirmations,
            max: policy.max_required_confirmations,
        });
    }
    Ok(())
}

/// Check an acceptance against the quote it answers.
///
/// The HTLC script itself is verified separately by rebuilding it from our own key material; this
/// covers everything a script comparison cannot.
///
/// `tip` is optional so a client that is only negotiating (no chain access configured) still gets
/// the amount and quote-binding checks. The height-relative checks are skipped in that case, and
/// they are the ones that only matter to a client that is about to move funds.
pub fn validate_accept(
    accept: &SwapAccept,
    quote: &Quote,
    tip: Option<u32>,
    policy: &ClientPolicy,
) -> Result<(), ValidationError> {
    if accept.quote_id != quote.quote_id {
        return Err(ValidationError::OfferMismatch {
            got: accept.quote_id.to_string(),
            want: quote.quote_id.to_string(),
        });
    }
    if accept.swap_id.is_nil() {
        return Err(ValidationError::SwapIdMissing);
    }
    if accept.direction != quote.direction {
        return Err(ValidationError::DirectionMismatch);
    }

    // The on-chain leg's size, which is what a hostile provider would inflate. For a submarine
    // swap this is what we lock; for a reverse swap it is what we receive.
    let expected_onchain = match quote.direction {
        SwapDirection::Submarine => quote.total_sat,
        SwapDirection::Reverse => quote.amount_sat,
    };
    if accept.onchain_amount_sat != expected_onchain {
        return Err(ValidationError::OnchainAmountMismatch {
            got: accept.onchain_amount_sat,
            want: expected_onchain,
        });
    }

    let Some(tip) = tip else {
        return Ok(());
    };

    // The timeout must match what the quote implied, within the blocks that may have been found
    // between the two messages.
    let implied = tip.saturating_add(quote.htlc_timeout_blocks);
    if accept.timeout_block_height > implied.saturating_add(ACCEPT_TIMEOUT_SLACK_BLOCKS)
        || accept.timeout_block_height + ACCEPT_TIMEOUT_SLACK_BLOCKS < implied
    {
        return Err(ValidationError::TimeoutMismatch {
            got: accept.timeout_block_height,
            want: implied,
            slack: ACCEPT_TIMEOUT_SLACK_BLOCKS,
        });
    }

    let mut timelock = policy.timelock;
    timelock.required_confirmations = policy.effective_confirmations(quote.required_confirmations);
    match quote.direction {
        SwapDirection::Reverse => {
            timelock::check_client_reverse_accept(tip, accept.timeout_block_height, &timelock)?
        }
        SwapDirection::Submarine => {
            timelock::check_client_submarine_accept(tip, accept.timeout_block_height, &timelock)?
        }
    }
    Ok(())
}

/// The decoded facts about a hold invoice that the client checks before paying it.
///
/// Deliberately not `lightning_backend::DecodedInvoice`: `swap-common` does not depend on the
/// Lightning crate, and keeping the check over a plain struct means the client can decode the
/// BOLT11 itself rather than asking the provider's own backend what it says.
#[derive(Debug, Clone, Copy)]
pub struct DecodedHoldInvoice {
    pub payment_hash: [u8; 32],
    pub amount_msat: u64,
    pub amount_is_explicit: bool,
    /// Unix seconds at which the invoice expires.
    pub expires_at_unix: u64,
}

/// Check the hold invoice a reverse-swap provider asked us to pay.
///
/// Without this the client pays whatever BOLT11 it is handed. The invoice is the client's entire
/// exposure in a reverse swap, so every field of it is bound to the quote.
pub fn validate_hold_invoice(
    invoice: &DecodedHoldInvoice,
    quote: &Quote,
    our_payment_hash: &[u8; 32],
    now_unix: u64,
    policy: &ClientPolicy,
) -> Result<(), ValidationError> {
    // It must be locked to the preimage we hold, or claiming on-chain would reveal a preimage
    // that settles nothing for us.
    if &invoice.payment_hash != our_payment_hash {
        return Err(ValidationError::PaymentHashMismatch);
    }
    if !invoice.amount_is_explicit {
        return Err(ValidationError::InvoiceHasNoAmount);
    }
    let want_msat = quote
        .total_sat
        .checked_mul(1000)
        .ok_or(ValidationError::Overflow)?;
    if invoice.amount_msat != want_msat {
        return Err(ValidationError::InvoiceAmountMismatch {
            got_msat: invoice.amount_msat,
            want_msat,
        });
    }

    // The invoice has to outlive the on-chain leg we are about to wait on, or the provider could
    // let it lapse after we have already committed to watching for a funding.
    let confirmations = policy.effective_confirmations(quote.required_confirmations);
    let blocks_needed = u64::from(confirmations)
        .checked_add(u64::from(timelock::CLIENT_CLAIM_WINDOW))
        .ok_or(ValidationError::Overflow)?;
    let need = now_unix.saturating_add(blocks_needed.saturating_mul(600));
    if invoice.expires_at_unix != 0 && invoice.expires_at_unix < need {
        return Err(ValidationError::InvoiceExpiresTooSoon {
            expires_at_unix: invoice.expires_at_unix,
            need,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swap::SwapDirection;
    use uuid::Uuid;

    const TIP: u32 = 800_000;
    const NOW: u64 = 1_700_000_000;
    const AMOUNT: u64 = 100_000;
    const FEE: u64 = 700;

    fn policy() -> ClientPolicy {
        ClientPolicy::for_network(bitcoin::Network::Bitcoin, TimelockParams::default())
    }

    fn request(direction: SwapDirection) -> QuoteRequest {
        QuoteRequest {
            offer_id: Uuid::nil(),
            client_pkarr: "client".into(),
            direction,
            amount_sat: AMOUNT,
        }
    }

    fn quote(direction: SwapDirection) -> Quote {
        Quote {
            quote_id: Uuid::new_v4(),
            offer_id: Uuid::new_v4(),
            direction,
            amount_sat: AMOUNT,
            fee_sat: FEE,
            total_sat: AMOUNT + FEE,
            htlc_timeout_blocks: 144,
            required_confirmations: 2,
            valid_until_unix: NOW + 300,
        }
    }

    fn accept(q: &Quote) -> SwapAccept {
        SwapAccept {
            quote_id: q.quote_id,
            swap_id: Uuid::new_v4(),
            direction: q.direction,
            htlc_script_hex: String::new(),
            htlc_address: String::new(),
            onchain_amount_sat: match q.direction {
                SwapDirection::Submarine => q.total_sat,
                SwapDirection::Reverse => q.amount_sat,
            },
            timeout_block_height: TIP + q.htlc_timeout_blocks,
            provider_pubkey_hex: String::new(),
            invoice: None,
        }
    }

    #[test]
    fn an_honest_exchange_validates() {
        for direction in [SwapDirection::Reverse, SwapDirection::Submarine] {
            let q = quote(direction);
            validate_quote(&q, &request(direction), NOW, &policy()).unwrap();
            validate_accept(&accept(&q), &q, Some(TIP), &policy()).unwrap();
        }
    }

    /// A provider that quotes 100k sat and then asks the client to lock 10M.
    ///
    /// The HTLC script check cannot catch this: the script is perfectly well formed and pays the
    /// right keys under the right hash. Only comparing the amount against the agreed quote does.
    #[test]
    fn rejects_an_inflated_onchain_amount() {
        let q = quote(SwapDirection::Submarine);
        let mut a = accept(&q);
        a.onchain_amount_sat = 10_000_000;
        match validate_accept(&a, &q, Some(TIP), &policy()) {
            Err(ValidationError::OnchainAmountMismatch { got, want }) => {
                assert_eq!(got, 10_000_000);
                assert_eq!(want, q.total_sat);
            }
            other => panic!("expected an amount mismatch, got {other:?}"),
        }
        // Even one satoshi over is refused; there is no tolerance to hide a skim in.
        let mut a = accept(&q);
        a.onchain_amount_sat = q.total_sat + 1;
        assert!(validate_accept(&a, &q, Some(TIP), &policy()).is_err());
    }

    /// A reverse-swap provider that pays out less on-chain than it quoted.
    #[test]
    fn rejects_a_shrunken_reverse_payout() {
        let q = quote(SwapDirection::Reverse);
        let mut a = accept(&q);
        a.onchain_amount_sat = q.amount_sat - 1;
        assert!(validate_accept(&a, &q, Some(TIP), &policy()).is_err());
    }

    /// A provider quoting zero confirmations gets the client to claim against a mempool-only
    /// funding. The provider then reads the preimage out of the mempool, replaces its own funding
    /// transaction, and settles the hold invoice with a preimage it was handed for free.
    #[test]
    fn rejects_a_zero_confirmation_quote() {
        let mut q = quote(SwapDirection::Reverse);
        q.required_confirmations = 0;
        match validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()) {
            Err(ValidationError::ConfirmationsTooLow { got, min }) => {
                assert_eq!(got, 0);
                assert_eq!(min, MIN_MAINNET_CONFIRMATIONS);
            }
            other => panic!("expected a confirmations floor, got {other:?}"),
        }
        // One confirmation is also below the mainnet floor.
        q.required_confirmations = 1;
        assert!(validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()).is_err());
    }

    /// Even if a low quote slipped through, the client acts on its own floor.
    #[test]
    fn the_effective_confirmation_count_is_never_below_our_floor() {
        let p = policy();
        assert_eq!(p.effective_confirmations(0), MIN_MAINNET_CONFIRMATIONS);
        assert_eq!(p.effective_confirmations(1), MIN_MAINNET_CONFIRMATIONS);
        assert_eq!(p.effective_confirmations(6), 6);
    }

    #[test]
    fn rejects_an_absurd_confirmation_demand() {
        let mut q = quote(SwapDirection::Reverse);
        q.required_confirmations = 1_000;
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()),
            Err(ValidationError::ConfirmationsTooHigh { .. })
        ));
    }

    #[test]
    fn rejects_a_quote_whose_total_does_not_add_up() {
        let mut q = quote(SwapDirection::Reverse);
        q.total_sat = q.amount_sat + q.fee_sat + 5_000;
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()),
            Err(ValidationError::TotalNotAmountPlusFee { .. })
        ));
    }

    #[test]
    fn rejects_an_extortionate_fee() {
        let mut q = quote(SwapDirection::Reverse);
        q.fee_sat = AMOUNT / 2;
        q.total_sat = q.amount_sat + q.fee_sat;
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()),
            Err(ValidationError::FeeTooHigh { .. })
        ));
    }

    #[test]
    fn rejects_a_quote_that_never_expires_or_expired_already() {
        let mut q = quote(SwapDirection::Reverse);
        q.valid_until_unix = 0;
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()),
            Err(ValidationError::QuoteNeverExpires)
        ));
        q.valid_until_unix = NOW - 1;
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()),
            Err(ValidationError::QuoteExpired { .. })
        ));
        q.valid_until_unix = NOW + MAX_QUOTE_VALIDITY_SECS + 1;
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Reverse), NOW, &policy()),
            Err(ValidationError::QuoteValidTooLong { .. })
        ));
    }

    #[test]
    fn rejects_a_quote_for_a_different_amount_or_direction() {
        let q = quote(SwapDirection::Reverse);
        assert!(matches!(
            validate_quote(&q, &request(SwapDirection::Submarine), NOW, &policy()),
            Err(ValidationError::DirectionMismatch)
        ));
        let mut r = request(SwapDirection::Reverse);
        r.amount_sat = AMOUNT * 2;
        assert!(matches!(
            validate_quote(&q, &r, NOW, &policy()),
            Err(ValidationError::AmountMismatch { .. })
        ));
    }

    /// A provider that sets the timeout at the tip so its own refund branch is live immediately,
    /// or so far out that it locks the client's capital for a year.
    #[test]
    fn rejects_a_timeout_that_does_not_match_the_quote() {
        let q = quote(SwapDirection::Submarine);
        let mut a = accept(&q);
        a.timeout_block_height = TIP;
        assert!(validate_accept(&a, &q, Some(TIP), &policy()).is_err());

        let mut a = accept(&q);
        a.timeout_block_height = TIP + 100_000;
        assert!(validate_accept(&a, &q, Some(TIP), &policy()).is_err());

        // Blocks found between the quote and the acceptance are tolerated.
        let mut a = accept(&q);
        a.timeout_block_height = TIP + q.htlc_timeout_blocks + ACCEPT_TIMEOUT_SLACK_BLOCKS;
        validate_accept(&a, &q, Some(TIP), &policy()).unwrap();
        a.timeout_block_height = TIP + q.htlc_timeout_blocks + ACCEPT_TIMEOUT_SLACK_BLOCKS + 1;
        assert!(validate_accept(&a, &q, Some(TIP), &policy()).is_err());
    }

    #[test]
    fn rejects_an_acceptance_for_the_wrong_quote() {
        let q = quote(SwapDirection::Reverse);
        let mut a = accept(&q);
        a.quote_id = Uuid::new_v4();
        assert!(validate_accept(&a, &q, Some(TIP), &policy()).is_err());
        let mut a = accept(&q);
        a.swap_id = Uuid::nil();
        assert!(matches!(
            validate_accept(&a, &q, Some(TIP), &policy()),
            Err(ValidationError::SwapIdMissing)
        ));
    }

    fn hold_invoice(q: &Quote, ph: [u8; 32]) -> DecodedHoldInvoice {
        DecodedHoldInvoice {
            payment_hash: ph,
            amount_msat: q.total_sat * 1000,
            amount_is_explicit: true,
            expires_at_unix: NOW + 86_400,
        }
    }

    /// The reverse client currently pays whatever BOLT11 it is handed. These are the checks that
    /// stop a provider naming its own price.
    #[test]
    fn rejects_a_hold_invoice_that_does_not_match_the_quote() {
        let q = quote(SwapDirection::Reverse);
        let ph = [7u8; 32];
        validate_hold_invoice(&hold_invoice(&q, ph), &q, &ph, NOW, &policy()).unwrap();

        // Locked to someone else's hash: claiming on-chain would settle nothing for us.
        let mut inv = hold_invoice(&q, ph);
        inv.payment_hash = [9u8; 32];
        assert!(matches!(
            validate_hold_invoice(&inv, &q, &ph, NOW, &policy()),
            Err(ValidationError::PaymentHashMismatch)
        ));

        // Asking for ten times the quote.
        let mut inv = hold_invoice(&q, ph);
        inv.amount_msat = q.total_sat * 10_000;
        assert!(matches!(
            validate_hold_invoice(&inv, &q, &ph, NOW, &policy()),
            Err(ValidationError::InvoiceAmountMismatch { .. })
        ));

        // Amountless, so our node would choose, or be told to choose.
        let mut inv = hold_invoice(&q, ph);
        inv.amount_is_explicit = false;
        assert!(matches!(
            validate_hold_invoice(&inv, &q, &ph, NOW, &policy()),
            Err(ValidationError::InvoiceHasNoAmount)
        ));

        // Expiring before the on-chain leg could possibly complete.
        let mut inv = hold_invoice(&q, ph);
        inv.expires_at_unix = NOW + 60;
        assert!(matches!(
            validate_hold_invoice(&inv, &q, &ph, NOW, &policy()),
            Err(ValidationError::InvoiceExpiresTooSoon { .. })
        ));
    }
}
