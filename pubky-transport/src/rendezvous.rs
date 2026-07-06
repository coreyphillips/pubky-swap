//! DHT-based provider rendezvous (feature `dht`).
//!
//! Pubky already resolves identities over the mainline BitTorrent DHT (via `pkarr`), so this
//! reuses the DHT the stack already ships with: no indexer, no new infrastructure. A provider is
//! a long-running daemon, so it can hold an open announce on a topic derived from its own pubky.
//! A client that already knows the provider's pubky (out-of-band) derives the *same* topic and
//! looks it up, learning the provider's socket address(es) directly. That inverts the current
//! pull/poll model into "a client walks up to a listening provider" and needs no pre-existing
//! follow relationship.
//!
//! ## Scope
//!
//! This module implements the **discovery** half only: [`Rendezvous::announce`] (provider) and
//! [`Rendezvous::discover`] (client). Establishing the authenticated, encrypted P2P stream over a
//! discovered address (the `connect` / `accept` layer: a Noise handshake plus NAT holepunching)
//! is the intended next step and is deliberately left out here so this stays reviewable.
//!
//! Two properties that layer MUST enforce, noted here so they are not forgotten:
//!
//! * **Authenticate the peer.** DHT topics are public and anyone can announce on one, so a client
//!   must verify the connected peer's key equals the expected provider pubky before trusting any
//!   quote. Discovery locates a socket; it does not prove who is behind it.
//! * **IP exposure.** Holepunching reveals IP addresses to the counterparty (and lookups leak
//!   interest to DHT nodes). Prefer ephemeral identities on the wire, and Tor / a relay if
//!   network-level privacy matters. Store-and-forward Pubky DMs never exposed the client's IP to
//!   the provider, so a deployment may reasonably use the DHT to *meet* and durable DMs to
//!   *finish* a swap (execution spans blocks/hours and must survive disconnects).

use mainline::{Dht, Id};
use std::net::SocketAddrV4;

use crate::{Result, TransportError};

/// Domain-separation tag so a pubky-swap topic can never collide with another protocol that
/// happens to reuse the same DHT keyed by the same pubky.
const TOPIC_DOMAIN: &[u8] = b"pubky-swap:rendezvous:v1:";

/// Derive the DHT rendezvous topic (a 20-byte infohash) for a provider from its pubky string.
///
/// Deterministic: the provider and any client that knows the pubky compute the identical topic
/// with no coordination.
pub fn swap_topic(provider_pubky: &str) -> Id {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TOPIC_DOMAIN);
    hasher.update(provider_pubky.as_bytes());
    let digest = hasher.finalize();
    // blake3 produces 32 bytes; a mainline Id is 20. Take the first 20 (160 bits), which is all
    // the DHT keyspace provides anyway.
    Id::from_bytes(&digest.as_bytes()[..20]).expect("a 20-byte slice is always a valid Id")
}

/// Announce presence on, and discover peers for, a provider's rendezvous topic.
pub trait Rendezvous {
    /// Publish our address under the topic so seekers can find us (provider side).
    fn announce(&self) -> Result<()>;
    /// Look up addresses currently announced under the topic (client side).
    fn discover(&self) -> Result<Vec<SocketAddrV4>>;
    /// The rendezvous topic in use.
    fn topic(&self) -> Id;
}

/// A [`Rendezvous`] backed by the mainline DHT.
///
/// The underlying [`Dht`] runs its own background thread, so these calls are synchronous and can
/// be driven from an async caller via `tokio::task::spawn_blocking` (mirroring how the rest of
/// this workspace treats blocking chain/DHT work).
pub struct DhtRendezvous {
    dht: Dht,
    topic: Id,
    /// Port to advertise when announcing. `None` uses the DHT socket's implied port (BEP5).
    announce_port: Option<u16>,
}

impl DhtRendezvous {
    /// Provider-side announcer: a DHT node in server mode that advertises `port` under the topic
    /// derived from `provider_pubky`.
    pub fn announcer(provider_pubky: &str, port: Option<u16>) -> Result<Self> {
        let dht =
            Dht::server().map_err(|e| TransportError::Dht(format!("start dht server: {e}")))?;
        Ok(Self::from_dht(dht, provider_pubky, port))
    }

    /// Client-side seeker: a DHT node that looks up the topic derived from `provider_pubky`.
    pub fn seeker(provider_pubky: &str) -> Result<Self> {
        let dht =
            Dht::client().map_err(|e| TransportError::Dht(format!("start dht client: {e}")))?;
        Ok(Self::from_dht(dht, provider_pubky, None))
    }

    /// Wrap an existing [`Dht`] (e.g. one bootstrapped against a local `Testnet` in tests).
    pub fn from_dht(dht: Dht, provider_pubky: &str, announce_port: Option<u16>) -> Self {
        Self {
            dht,
            topic: swap_topic(provider_pubky),
            announce_port,
        }
    }
}

impl Rendezvous for DhtRendezvous {
    fn announce(&self) -> Result<()> {
        self.dht
            .announce_peer(self.topic, self.announce_port)
            .map_err(|e| TransportError::Dht(format!("announce_peer: {e}")))?;
        Ok(())
    }

    fn discover(&self) -> Result<Vec<SocketAddrV4>> {
        let mut peers = Vec::new();
        // `get_peers` yields a batch per responding node as the query fans out. Stop at the first
        // non-empty batch so a seeker returns as soon as it has a hit instead of blocking for the
        // full traversal.
        for batch in self.dht.get_peers(self.topic) {
            peers.extend(batch);
            if !peers.is_empty() {
                break;
            }
        }
        Ok(peers)
    }

    fn topic(&self) -> Id {
        self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_is_deterministic() {
        assert_eq!(
            swap_topic("provider-pubky-aaa"),
            swap_topic("provider-pubky-aaa")
        );
    }

    #[test]
    fn distinct_providers_get_distinct_topics() {
        assert_ne!(swap_topic("provider-aaa"), swap_topic("provider-bbb"));
    }

    /// End-to-end announce -> discover against a local in-process DHT swarm (no public network).
    /// Ignored by default because it spins up a `Testnet` and runs real (local) DHT queries.
    #[test]
    #[ignore]
    fn announce_then_discover_on_testnet() {
        use mainline::Testnet;

        let testnet = Testnet::new(10).expect("spin up local dht testnet");
        let provider_dht = Dht::builder()
            .server_mode()
            .bootstrap(&testnet.bootstrap)
            .build()
            .expect("provider dht");
        provider_dht.bootstrapped();
        let seeker_dht = Dht::builder()
            .bootstrap(&testnet.bootstrap)
            .build()
            .expect("seeker dht");
        seeker_dht.bootstrapped();

        let pubky = "provider-under-test";
        let provider = DhtRendezvous::from_dht(provider_dht, pubky, Some(45555));
        provider.announce().expect("announce");

        let seeker = DhtRendezvous::from_dht(seeker_dht, pubky, None);
        let peers = seeker.discover().expect("discover");
        assert!(
            peers.iter().any(|a| a.port() == 45555),
            "expected to discover the announced port 45555, got {peers:?}"
        );
    }
}
