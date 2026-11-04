//! Which `swap/1` Capability Descriptor to write next, and which one is still good to serve.
//!
//! The refresher rebuilds the offer with a new `offer_id` and a new expiry every period, and an
//! RFQ naming an old `offer_id` is refused. So every rebuilt offer is a rewrite, and a descriptor
//! lapses with the offer it names.

use anyhow::{bail, Result};
use std::sync::Arc;
use swap_common::cap_descriptor::{self, Descriptor, Publication};
use swap_common::messages::SwapOffer;
use swap_common::paykit_cap::CapSigner;
use tokio::sync::RwLock;
use uuid::Uuid;

/// The publisher writes it and the status API serves it.
pub(crate) type SharedDescriptors = Arc<RwLock<DescriptorBook>>;

#[cfg_attr(not(feature = "paykit"), allow(dead_code))]
#[derive(Default)]
pub(crate) struct DescriptorBook {
    last_seq: u64,
    published: Option<Descriptor>,
}

#[cfg_attr(not(feature = "paykit"), allow(dead_code))]
impl DescriptorBook {
    /// Whether the file on the homeserver no longer describes `offer`.
    pub(crate) fn needs_rewrite(&self, offer: &SwapOffer) -> bool {
        self.published.as_ref().map(offer_id) != Some(offer.offer_id)
    }

    /// Sign the descriptor for `offer`, with a `seq` above every one this book has issued.
    ///
    /// `seq` never falls below the clock, so it keeps rising across restarts without being
    /// stored: the refresher rewrites at most every 30 seconds.
    pub(crate) fn next(
        &mut self,
        offer: &SwapOffer,
        owner: &str,
        key_generation: u64,
        signer: &dyn CapSigner,
        now: u64,
    ) -> Result<(Descriptor, Vec<u8>)> {
        if offer.valid_until_unix <= now {
            bail!(
                "offer {} expired at {}",
                offer.offer_id,
                offer.valid_until_unix
            );
        }
        let seq = self.last_seq.saturating_add(1).max(now);
        self.last_seq = seq;
        let publication = Publication {
            owner: owner.to_string(),
            key_generation,
            seq,
            created_at: now,
        };
        Ok(cap_descriptor::build(offer, &publication).sign(signer)?)
    }

    /// Record a descriptor the homeserver accepted.
    pub(crate) fn published(&mut self, descriptor: Descriptor) {
        self.published = Some(descriptor);
    }

    /// The published descriptor, unless it has lapsed.
    #[cfg_attr(not(feature = "status"), allow(dead_code))]
    pub(crate) fn current(&self, now: u64) -> Option<&Descriptor> {
        self.published.as_ref().filter(|d| d.is_current(now))
    }
}

fn offer_id(descriptor: &Descriptor) -> Uuid {
    descriptor
        .profiles
        .first()
        .map(|profile| profile.terms.offer_id)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_common::paykit_cap::Ed25519Signer;
    use swap_common::{NetworkSpec, SwapDirection, PROTOCOL_VERSION};

    const NOW: u64 = 1_793_000_000;

    fn offer(onchain_fee_sat: u64) -> SwapOffer {
        SwapOffer {
            request_id: None,
            offer_id: Uuid::new_v4(),
            provider_pkarr: "provider".into(),
            network: NetworkSpec::Regtest,
            directions: vec![SwapDirection::Reverse, SwapDirection::Submarine],
            min_amount_sat: 10_000,
            max_amount_sat: 1_000_000,
            base_fee_sat: 500,
            fee_ppm: 2_000,
            required_confirmations: 1,
            htlc_timeout_blocks: 144,
            lightning_node_id: None,
            valid_until_unix: NOW + 300,
            fund_within_secs: 60,
            onchain_fee_sat,
            fee_rate_sat_vb: 2,
            protocol_version: PROTOCOL_VERSION,
            features: vec![],
        }
    }

    #[test]
    fn seq_rises_across_rewrites_and_restarts() {
        let signer = Ed25519Signer::from_secret(&[5; 32]);
        let mut book = DescriptorBook::default();
        let first = offer(300);
        assert!(book.needs_rewrite(&first));
        let (one, _) = book.next(&first, "owner", 1, &signer, NOW).unwrap();
        book.published(one.clone());
        assert!(!book.needs_rewrite(&first));

        // A fee move rebuilds the offer, which moves the minimum and forces a rewrite, even
        // within the same second.
        let repriced = offer(3_000);
        assert!(book.needs_rewrite(&repriced));
        let (two, _) = book.next(&repriced, "owner", 1, &signer, NOW).unwrap();
        assert!(two.seq > one.seq);
        assert_eq!(two.profiles[0].edges[0].min, "30000");
        assert_eq!(one.profiles[0].edges[0].min, "10000");

        // A restarted provider has an empty book, and still writes above what it wrote before.
        let mut restarted = DescriptorBook::default();
        let (three, _) = restarted
            .next(&offer(300), "owner", 1, &signer, NOW + 30)
            .unwrap();
        assert!(three.seq > two.seq);
    }

    #[test]
    fn an_expired_descriptor_is_not_served_or_written() {
        let signer = Ed25519Signer::from_secret(&[5; 32]);
        let mut book = DescriptorBook::default();
        let current = offer(300);
        let (descriptor, _) = book.next(&current, "owner", 1, &signer, NOW).unwrap();
        book.published(descriptor);
        assert!(book.current(NOW + 299).is_some());
        assert!(book.current(NOW + 300).is_none());
        assert!(book
            .next(&current, "owner", 1, &signer, current.valid_until_unix)
            .is_err());
    }
}
