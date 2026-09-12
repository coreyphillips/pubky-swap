//! Provider daemon library.
//!
//! Negotiation (offer → quote → swap-accept) is always available. When the provider is
//! fully configured — a real LND backend (`lnd`), an Electrum chain watcher (`chain`), and a
//! BDK funding wallet (`bdk-wallet`) — it also **executes** swaps: on a `SwapRequest` it
//! creates the HTLC (and, for reverse, a hold invoice), replies with a `SwapAccept`, and
//! spawns a per-swap task that drives it to completion (see [`reverse`] / [`submarine`]),
//! sending the client a final `SwapStatusUpdate`. Without those pieces it stays
//! negotiation-only and rejects `SwapRequest`s.

// `rendezvous_iroh` is on by default, and without the `iroh` feature it is a setting with nothing
// behind it: the provider would be reachable only by pubkys it already follows, which on a fresh
// install is nobody. `full` is what the Umbrel image and every doc build, so the two travel
// together, and this fires the moment someone separates them.
#[cfg(all(feature = "full", not(feature = "iroh")))]
compile_error!(
    "`full` must include `iroh`: without it the provider answers no doorbell and can only be \
     reached by pubkys it already follows."
);

pub mod preflight;
pub mod pricing;
pub(crate) mod recovery;
pub mod reverse;
pub mod risk;
#[cfg(feature = "status")]
pub mod status;
/// Re-exported from `swap-common`, where the store now lives so the client can use it too.
pub use swap_common::store;
#[cfg(test)]
mod compatibility_tests;
pub mod submarine;
#[cfg(feature = "bdk-wallet")]
pub mod wallet;

use anyhow::{anyhow, Context, Result};
#[cfg(feature = "beignet")]
use beignet_backend::BeignetLightningBackend;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Network, OutPoint, PublicKey, Txid};
#[cfg(feature = "lnd")]
use lightning_backend::LndBackend;
use lightning_backend::{LightningBackend, LndConfig, StubBackend};
use pubky_transport::Transport;
mod reply_transport;
use reply_transport::ReplyTransport;
use std::collections::HashMap;
use std::sync::Arc;
use swap_common::chain::{run_blocking, ChainWatcher};
use swap_common::htlc::{htlc_p2wsh_address, PaymentHash};
use swap_common::{messages::*, NetworkSpec, SwapDirection, SwapState};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::recovery::Recovery;
use crate::reverse::{
    drive_reverse_swap, reverse_invoice_request, OnchainWallet, ProgressSink, ReverseSwap,
};
use crate::store::{JsonFileSwapStore, SwapRecord, SwapStore};
use crate::submarine::{drive_submarine_swap, init_submarine_swap, SubmarineSwap};
use swap_common::timelock::{self, TimelockParams};

/// Provider configuration (typically populated from the CLI).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ProviderConfig {
    /// Path to a Pubky recovery file. Mutually exclusive with `recovery_phrase`.
    pub recovery_file: String,
    /// The Pubky recovery phrase, from the environment, a config file, or a file named by
    /// `recovery_phrase_file`.
    ///
    /// Never from a flag. An argv value is readable by anything that can see the process table,
    /// and lands in shell history on the way there.
    pub recovery_phrase: swap_config::SecretSource,
    /// Passphrase protecting the recovery file or phrase.
    pub passphrase: swap_config::SecretSource,
    pub network: String,
    pub min_amount_sat: u64,
    pub max_amount_sat: u64,
    pub base_fee_sat: u64,
    pub fee_ppm: u64,
    pub required_confirmations: u32,
    pub htlc_timeout_blocks: u32,
    /// Minimum blocks that must remain before the on-chain timeout for the provider to take
    /// an irreversible step (paying a submarine invoice, or committing funds to a reverse
    /// HTLC). Guards the race where a counterparty times its move so our sweep cannot land.
    pub min_claim_window_blocks: u32,
    /// Swaps this provider will drive at once.
    pub max_concurrent_swaps: usize,
    /// Swaps one counterparty may have in flight at once.
    pub max_concurrent_per_peer: usize,
    /// Most this provider will have committed on chain across all live swaps.
    pub max_total_exposure_sat: u64,
    /// Most this provider will have committed to any one counterparty.
    pub max_exposure_per_peer_sat: u64,
    /// On-chain balance kept back, so committing to a swap never leaves the wallet unable to
    /// pay for a refund it may owe.
    pub min_onchain_reserve_sat: u64,
    /// New swaps one counterparty may start per hour.
    pub max_new_swaps_per_peer_per_hour: u32,
    pub directions: Vec<SwapDirection>,
    /// Push the offer to all discovered followers on startup.
    pub broadcast_offer: bool,
    /// Which Lightning backend to use: `"lnd"` or `"beignet"`.
    pub lightning_backend: String,
    pub lnd_address: String,
    pub lnd_cert_path: String,
    pub lnd_macaroon_path: String,
    /// Base URL of a beignet daemon, e.g. `http://127.0.0.1:2112`.
    pub beignet_url: String,
    /// Bearer token for that daemon.
    pub beignet_token: swap_config::SecretSource,
    /// PEM root certificate, when the daemon was started with `--tls-cert`.
    pub beignet_tls_cert: String,
    /// Optional `/v1` API prefix.
    pub beignet_api_prefix: String,
    /// SOCKS5 proxy for Electrum, e.g. `127.0.0.1:9050`. Required to reach a `.onion`
    /// server; empty means a direct connection.
    pub electrum_socks5: String,
    /// Per-call Electrum socket timeout, in seconds.
    pub electrum_timeout_secs: u8,
    /// Electrum server URL for the chain watcher (e.g. `tcp://127.0.0.1:60001`).
    pub electrum_url: String,
    /// BIP39 mnemonic for the on-chain funding wallet.
    pub wallet_mnemonic: swap_config::SecretSource,
    /// Fee rate (sat/vB) for claim/refund transactions.
    pub onchain_fee_rate_sat_vb: u64,
    /// Hold-invoice expiry (seconds).
    pub invoice_expiry_secs: u64,
    /// Routing-fee cap (msat) when paying invoices (submarine swaps).
    pub max_routing_fee_msat: u64,
    /// Explicitly permit unsafe mainnet parameters (low confirmations / fee floor). Off by
    /// default so a misconfigured mainnet provider refuses to start.
    pub allow_unsafe: bool,
    /// How long an issued quote stays valid, in seconds. After this it is rejected and pruned.
    pub quote_ttl_secs: u64,
    /// Directory for persisted in-flight swap state (so a restart can resume them).
    pub data_dir: String,
    /// On-chain funding wallet backend: `"lnd"` (fund from LND's own wallet, no seed) or `"bdk"`
    /// (a separate BIP84 wallet from `wallet_mnemonic`).
    pub wallet_backend: String,
    /// Seconds of inactivity after which an unpinned peer (a client that contacted us but never
    /// reached a terminal swap) is evicted from the poll set and unfollowed, so the poll set and
    /// follow graph do not grow without bound. `0` disables idle reaping. Peers are also evicted
    /// as soon as their swap completes, regardless of this value.
    pub peer_idle_ttl_secs: u64,
    /// Address for the read-only status API, e.g. `127.0.0.1:9737`. Absent means no API.
    ///
    /// Loopback by default and read-only by design: it exists so a dashboard or a health check
    /// can see what the daemon is doing without parsing its logs, not so anything can drive it.
    pub status_addr: Option<String>,
    /// Accept iroh P2P rendezvous connections (the "doorbell"): a client that knows our pubky can
    /// connect and be added to the poll set without a pre-existing follow. Requires the `iroh`
    /// build feature, which `full` includes.
    ///
    /// On by default, because off is a provider nobody new can reach. Pubky's private messages
    /// live at a path derived from an ECDH shared secret between the two parties: unlinkable by
    /// design, and therefore not enumerable, so `receive_all` can only poll pubkys already in the
    /// peer set. That set comes from the follow graph. Someone handed only our pubky, which is
    /// exactly what the docs tell them to ask for, writes into a conversation nothing will ever
    /// look in. The doorbell is how they say "look at me" first.
    ///
    /// Set it false to run as a private provider that serves only counterparties it follows.
    pub rendezvous_iroh: bool,
}

impl ProviderConfig {
    /// Resolve the Pubky identity, or say precisely what is missing.
    pub fn identity(&self) -> Result<swap_config::Identity> {
        swap_config::resolve_identity(&self.recovery_file, &self.recovery_phrase, &self.passphrase)
    }
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            recovery_file: String::new(),
            recovery_phrase: Default::default(),
            passphrase: Default::default(),
            network: "regtest".to_string(),
            min_amount_sat: 10_000,
            max_amount_sat: 1_000_000,
            base_fee_sat: 500,
            fee_ppm: 2_000,
            required_confirmations: 1,
            htlc_timeout_blocks: 144,
            min_claim_window_blocks: swap_common::timelock::PROVIDER_MIN_CLAIM_WINDOW,
            max_concurrent_swaps: 25,
            max_concurrent_per_peer: 2,
            max_total_exposure_sat: 5_000_000,
            max_exposure_per_peer_sat: 1_000_000,
            min_onchain_reserve_sat: 100_000,
            max_new_swaps_per_peer_per_hour: 6,
            directions: vec![SwapDirection::Submarine, SwapDirection::Reverse],
            broadcast_offer: false,
            lightning_backend: "lnd".to_string(),
            lnd_address: "https://127.0.0.1:10009".to_string(),
            lnd_cert_path: String::new(),
            lnd_macaroon_path: String::new(),
            beignet_url: "http://127.0.0.1:2112".to_string(),
            beignet_token: Default::default(),
            beignet_tls_cert: String::new(),
            beignet_api_prefix: String::new(),
            electrum_socks5: String::new(),
            electrum_timeout_secs: 30,
            electrum_url: String::new(),
            wallet_mnemonic: Default::default(),
            onchain_fee_rate_sat_vb: 2,
            invoice_expiry_secs: 3600,
            max_routing_fee_msat: 10_000,
            allow_unsafe: false,
            quote_ttl_secs: 300,
            data_dir: "./pubky-swap-data".to_string(),
            wallet_backend: "bdk".to_string(),
            peer_idle_ttl_secs: 3600,
            rendezvous_iroh: true,
            status_addr: None,
        }
    }
}

/// Current Unix time in seconds (saturating at 0 if the clock is before the epoch).
fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Upper bound on retained quotes, so a flood of `QuoteRequest`s cannot grow the map without
/// limit even before they expire.
const MAX_TRACKED_QUOTES: usize = 10_000;

/// Drop expired quotes from the map.
fn prune_quotes(quotes: &mut HashMap<Uuid, IssuedQuote>, now: u64) {
    quotes.retain(|_, q| q.expires_at_unix == 0 || now < q.expires_at_unix);
}

/// Remove and return a still-valid quote issued to `peer` for `direction` (single-use, so a quote
/// can't be replayed). Also prunes any other expired quotes while the map is locked.
///
/// A quote is authorization to swap on terms we already priced, so it belongs to the authenticated
/// pubky we quoted and to nobody else: a quote id is not a bearer token. Everything is checked
/// before the quote leaves the map, so a request from the wrong peer, or for the wrong direction,
/// cannot burn the quote its owner is still holding.
async fn take_valid_quote(
    quotes: &Mutex<HashMap<Uuid, IssuedQuote>>,
    quote_id: Uuid,
    peer: &str,
    direction: SwapDirection,
) -> Result<IssuedQuote> {
    use std::collections::hash_map::Entry;

    let mut quotes = quotes.lock().await;
    prune_quotes(&mut quotes, now_unix());
    let Entry::Occupied(entry) = quotes.entry(quote_id) else {
        return Err(anyhow!("unknown or expired quote"));
    };
    if !pubky_transport::same_pubky(&entry.get().peer, peer) {
        return Err(anyhow!("quote {quote_id} was not issued to {peer}"));
    }
    if entry.get().direction != direction {
        return Err(anyhow!("quote {quote_id} is not for a {direction:?} swap"));
    }
    Ok(entry.remove())
}

/// Refuse a request whose self-declared `client_pkarr` is not the pubky it arrived from.
///
/// The transport identity is the authenticated one and the only one anything is authorized
/// against; `client_pkarr` is whatever the sender typed into a field. They should always agree,
/// so a request where they do not is either a confused client or one asking to be treated as
/// somebody else, and neither is worth quoting.
fn check_client_pkarr(claimed: &str, sender: &str) -> Result<()> {
    if pubky_transport::same_pubky(claimed, sender) {
        return Ok(());
    }
    Err(anyhow!(
        "client_pkarr '{claimed}' is not the pubky this message came from"
    ))
}

/// Minimum HTLC funding confirmations the provider will accept on mainnet without `allow_unsafe`.
const MIN_MAINNET_CONFIRMATIONS: u32 = 2;
/// Minimum on-chain fee floor (sat/vB) the provider will accept on mainnet without `allow_unsafe`.
/// The dynamic estimator (see `onchain::resolve_fee_rate`) can raise the effective rate above
/// this; the floor only guards the fallback used when estimation is unavailable.
const MIN_MAINNET_FEE_FLOOR_SAT_VB: u64 = 5;

/// The risk limits derived from the operator's configuration.
fn risk_limits(c: &ProviderConfig) -> risk::RiskLimits {
    risk::RiskLimits {
        max_concurrent_swaps: c.max_concurrent_swaps,
        max_concurrent_per_peer: c.max_concurrent_per_peer,
        max_total_exposure_sat: c.max_total_exposure_sat,
        max_exposure_per_peer_sat: c.max_exposure_per_peer_sat,
        min_onchain_reserve_sat: c.min_onchain_reserve_sat,
        max_new_swaps_per_peer_per_hour: c.max_new_swaps_per_peer_per_hour,
    }
}

/// The timelock model derived from the operator's configuration.
fn timelock_params(c: &ProviderConfig) -> TimelockParams {
    TimelockParams {
        htlc_timeout_blocks: c.htlc_timeout_blocks,
        required_confirmations: c.required_confirmations,
        min_claim_window_blocks: c.min_claim_window_blocks,
        ..TimelockParams::default()
    }
}

/// Reject a timelock configuration that cannot satisfy the cross-leg invariants at any height.
///
/// Checked on every network, not just mainnet: a configuration that cannot order the two legs
/// correctly is broken everywhere, and finding out at the first swap means finding out with a
/// counterparty's payment already held.
fn validate_timelocks(c: &ProviderConfig) -> Result<()> {
    let p = timelock_params(c);
    timelock::validate_params(&p).map_err(|e| {
        anyhow!(
            "unusable timelock configuration: {e} (htlc_timeout_blocks={}, \
             required_confirmations={}, min_claim_window_blocks={})",
            c.htlc_timeout_blocks,
            c.required_confirmations,
            c.min_claim_window_blocks
        )
    })?;
    let delta = timelock::reverse_invoice_cltv_delta(&p)
        .map_err(|e| anyhow!("hold invoice CLTV delta: {e}"))?;
    tracing::debug!(
        "timelocks: on-chain refund opens {} blocks after accept; hold invoices carry a \
         {delta}-block final CLTV so the lightning leg outlives it",
        c.htlc_timeout_blocks
    );
    Ok(())
}

/// Reject obviously-unsafe parameters on mainnet unless the operator opts in via `allow_unsafe`.
/// A no-op on non-mainnet networks.
fn validate_mainnet_safety(c: &ProviderConfig, network: Network) -> Result<()> {
    if network != Network::Bitcoin || c.allow_unsafe {
        return Ok(());
    }
    if c.required_confirmations < MIN_MAINNET_CONFIRMATIONS {
        return Err(anyhow!(
            "unsafe mainnet config: required_confirmations={} (< {}); raise it or pass --allow-unsafe",
            c.required_confirmations,
            MIN_MAINNET_CONFIRMATIONS
        ));
    }
    if c.onchain_fee_rate_sat_vb < MIN_MAINNET_FEE_FLOOR_SAT_VB {
        return Err(anyhow!(
            "unsafe mainnet config: onchain_fee_rate_sat_vb={} (< {} sat/vB floor); raise it or pass --allow-unsafe",
            c.onchain_fee_rate_sat_vb,
            MIN_MAINNET_FEE_FLOOR_SAT_VB
        ));
    }
    Ok(())
}

/// Map LND's reported chain network string to a [`Network`]. Returns `None` for networks with no
/// `bitcoin::Network` equivalent (e.g. `"simnet"`).
fn lnd_network_to_bitcoin(s: &str) -> Option<Network> {
    Some(match s {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return None,
    })
}

pub fn parse_network(s: &str) -> Result<Network> {
    Ok(match s {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(anyhow!("unknown network: {other}")),
    })
}

/// Parse a comma-separated `submarine,reverse` list.
pub fn parse_directions(s: &str) -> Result<Vec<SwapDirection>> {
    s.split(',')
        .map(|d| match d.trim().to_lowercase().as_str() {
            "submarine" => Ok(SwapDirection::Submarine),
            "reverse" => Ok(SwapDirection::Reverse),
            other => Err(anyhow!("unknown direction: {other}")),
        })
        .collect()
}

/// A quote the provider has issued, retained so a later `SwapRequest` can be priced/validated.
#[derive(Debug, Clone)]
struct IssuedQuote {
    /// The authenticated pubky this quote was sent to, and the only one that may redeem it.
    peer: String,
    direction: SwapDirection,
    amount_sat: u64,
    fee_sat: u64,
    /// The two halves of `fee_sat`, kept so the swap's record can say what it earned. The quote
    /// map is single-use and pruned, so this is the last moment either number exists.
    service_fee_sat: u64,
    onchain_fee_sat: u64,
    /// Unix seconds after which this quote is no longer honoured (0 = never).
    expires_at_unix: u64,
}

/// The advertised offer, which does not exist for the first moments of a run.
///
/// Empty until the backends have been probed and it can be priced. That window used to be
/// invisible because nothing could ask about it; the status API can, and it exists precisely to
/// answer while the daemon is still working out whether it can serve anything.
pub type SharedOffer = Arc<RwLock<Option<SwapOffer>>>;

/// Shared execution context handed to message handlers and spawned driver tasks.
#[derive(Clone)]
struct ExecCtx {
    transport: Arc<ReplyTransport>,
    ln: Arc<dyn LightningBackend>,
    chain: Option<Arc<dyn ChainWatcher>>,
    wallet: Option<Arc<dyn OnchainWallet>>,
    network: Network,
    required_confirmations: u32,
    timelock: TimelockParams,
    onchain_fee_rate_sat_vb: u64,
    invoice_expiry_secs: u64,
    max_routing_fee_msat: u64,
    quote_ttl_secs: u64,
    quotes: Arc<Mutex<HashMap<Uuid, IssuedQuote>>>,
    store: Arc<dyn SwapStore>,
    risk: Arc<risk::RiskManager>,
    min_onchain_reserve_sat: u64,
    /// True when the provider can execute swaps (real LN + chain + wallet present).
    capable: bool,
}

/// A [`ProgressSink`] that records driver progress into the persistent [`SwapStore`], so a
/// restart can resume the swap.
struct StoreProgress {
    store: Arc<dyn SwapStore>,
    record: std::sync::Mutex<SwapRecord>,
}

impl StoreProgress {
    /// Apply `f` to the record and persist it.
    ///
    /// A failure to persist is logged at `error!`, not `warn!`: a record that is not on disk is
    /// a swap that will not be resumed, which for a funded HTLC means a refund that never
    /// happens. It is the loudest thing this daemon can be quiet about.
    fn update(&self, what: &str, f: impl FnOnce(&mut SwapRecord)) {
        let _ = self.try_update(what, f);
    }

    /// Apply `f` to the record and persist it, reporting whether the write landed.
    ///
    /// Most callers cannot do anything about a failure and use [`update`](Self::update). The ones
    /// that are about to do something irreversible can, and must: they stop.
    fn try_update(&self, what: &str, f: impl FnOnce(&mut SwapRecord)) -> anyhow::Result<()> {
        let mut rec = match self.record.lock() {
            Ok(r) => r,
            Err(poisoned) => poisoned.into_inner(),
        };
        let before = rec.state.clone();
        f(&mut rec);
        // The retry metadata is cleared here rather than by the callbacks, because only a write
        // that moves the state is progress. `spend_broadcast` in particular runs *before* the
        // broadcast it names, so it cannot attest to anything having worked.
        if rec.state != before {
            rec.progressed();
        }
        rec.updated_at_unix = now_unix();
        if let Err(e) = self.store.put(&rec) {
            error!(
                "FAILED TO PERSIST {what} for swap {}: {e}. This swap will not be resumed after \
                 a restart; if it is funded, its refund depends on this process staying up.",
                rec.swap_id
            );
            return Err(anyhow!("could not persist {what}: {e}"));
        }
        Ok(())
    }

    fn set_state(&self, state: SwapState) {
        self.update("state", |rec| rec.state = state);
    }

    fn set_terminal(&self, state: SwapState) {
        let mut rec = match self.record.lock() {
            Ok(r) => r,
            Err(poisoned) => poisoned.into_inner(),
        };
        rec.state = state;
        // Reaching an outcome is progress, and the retry metadata describes work still owed.
        rec.progressed();
        rec.updated_at_unix = now_unix();
        if let Err(e) = self.store.mark_terminal(&rec) {
            warn!(
                "failed to record the terminal state of swap {}: {e}",
                rec.swap_id
            );
        }
    }

    /// Note a failure, work out what it earns the swap, and write down when the next run is due.
    ///
    /// One write rather than two, and the decision is taken inside it: the delay depends on the
    /// count this call increments, and `next_retry_at_unix` is what makes the delay survive a
    /// restart rather than being a `sleep` that dies with the process.
    fn record_failure(&self, e: &anyhow::Error, transient: bool) -> (SwapRecord, Recovery) {
        let mut recovery = Recovery::GiveUp;
        self.update("driver failure", |rec| {
            rec.last_error = Some(e.to_string());
            rec.retry_count = rec.retry_count.saturating_add(1);
            recovery = recovery::after_failure(rec, transient);
            rec.next_retry_at_unix = match recovery {
                Recovery::Retry(delay) => Some(now_unix().saturating_add(delay.as_secs())),
                Recovery::GiveUp => None,
            };
        });
        (self.snapshot(), recovery)
    }

    /// The record as it stands.
    ///
    /// Poison-tolerant, like every other use of this lock. `lock().ok()` would return `None` after
    /// any panic that touched it, and the callers of this are the re-entry paths: a `None` there
    /// silently ends the swap *and* releases its place in the risk limits, while its coins sit in
    /// an HTLC.
    fn snapshot(&self) -> SwapRecord {
        match self.record.lock() {
            Ok(r) => r.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl ProgressSink for StoreProgress {
    fn funding_intent(&self, tip: u32) -> anyhow::Result<()> {
        // Written *before* the funding transaction is broadcast.
        //
        // Recording the outpoint afterwards is not enough: a crash between broadcast and persist
        // leaves a funded HTLC with no record of it, and a resumed driver that cannot find the
        // output (because the counterparty already claimed it, or Electrum is lagging, or the
        // value does not match exactly) funds a second one. This marker tells a resumed driver
        // that a funding may exist and to go looking for it rather than paying again.
        self.try_update("funding intent", |rec| {
            rec.funding_intent_at_height = Some(tip);
            rec.funding_attempts = rec.funding_attempts.saturating_add(1);
            rec.state = SwapState::LockupPending;
        })
    }

    fn funded(&self, outpoint: OutPoint) {
        self.update("funding outpoint", |rec| {
            rec.funding_txid_hex = Some(outpoint.txid.to_string());
            rec.funding_vout = Some(outpoint.vout);
            rec.funding_intent_at_height = None;
            rec.state = SwapState::LockupConfirmed;
        });
    }

    fn invoice_pay_started(&self) -> anyhow::Result<()> {
        // Written before `pay_invoice`, so a resumed driver knows a payment may be in flight and
        // consults the node rather than paying a second time.
        self.try_update("invoice payment intent", |rec| {
            rec.invoice_pay_started_at_unix = Some(now_unix());
            rec.state = SwapState::InvoicePending;
        })
    }

    fn invoice_paid(&self) {
        self.update("invoice paid", |rec| {
            rec.state = SwapState::InvoicePaid;
        });
    }

    fn claim_observed(&self, txid: Txid) {
        // Written before the hold invoice is settled. The preimage itself is deliberately not
        // persisted: on resume it is re-extracted from this transaction on chain.
        self.update("observed claim", |rec| {
            rec.claim_observed_txid_hex = Some(txid.to_string());
            rec.state = SwapState::InvoicePaid;
        });
    }

    fn spend_broadcast(&self, txid: Txid) {
        // Deliberately does not touch the state. This is called for a claim *and* for a refund,
        // and the record's state is the operator's only view of a swap: labelling a refund
        // `ClaimPending` would describe it as the opposite of what it is.
        self.update("broadcast spend", |rec| {
            rec.note_our_spend(txid);
        });
    }
}

/// How often the reorg monitor samples the chain.
const REORG_POLL: Duration = Duration::from_secs(30);

/// Height-to-hash samples the reorg monitor retains. Well past any plausible reorg depth, and now
/// cheap to verify: the whole watched window is read in one request.
const REORG_CHECKPOINTS: usize = 200;

/// Consecutive failed reorg samples before the operator is told the detector is off.
const REORG_FAILURES_BEFORE_ALARM: u32 = 3;

/// How long a terminal swap record is kept before the background sweeper removes it.
const TERMINAL_RECORD_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Whether a driver error looks like something retrying could fix.
///
/// The drivers return `anyhow::Error`, so the structured `SwapError` classification is recovered
/// from the chain rather than by matching a variant. Anything unrecognised counts as permanent:
/// an unclassified error should not silently earn itself an unbounded retry loop.
fn is_transient(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<swap_common::SwapError>()
            .is_some_and(|s| s.is_transient())
    })
}

/// Finish a driver run: persist what happened, tell the peer, and decide whether to try again.
///
/// The record is never deleted here. It used to be, unconditionally, on every return including
/// errors -- and every `?` in a driver propagates, including `chain.tip_height()?`. So a single
/// Electrum blip on a funded swap deleted its record, which meant no resume, which meant the
/// refund was never attempted and the provider's coins sat in an HTLC nobody was watching.
///
/// It is not marked terminal here either, once the swap holds funds. `Failed` is terminal, and
/// terminal is the same disappearance by another route: excluded from restart recovery, exposure
/// released, nothing left driving the refund. See [`recovery`].
async fn finish_driver_run(
    ctx: &ExecCtx,
    progress: &StoreProgress,
    peer: &str,
    swap_id: Uuid,
    result: Result<SwapState>,
    // The swap's place in the risk limits, passed on to the re-entered driver rather than
    // dropped here. Re-entry used to hand the new driver `None`, so a swap that hit one transient
    // failure stopped counting against total exposure and concurrency for the rest of its life,
    // while its coins were still very much at risk.
    reservation: Option<risk::ReservationGuard>,
    respawn: impl FnOnce(&ExecCtx, SwapRecord, Option<risk::ReservationGuard>, Duration),
) {
    match result {
        Ok(state) if state.is_terminal() => {
            progress.set_terminal(state.clone());
            notify_terminal_peer(ctx, progress, peer, swap_id, state).await;
        }
        Ok(state) => {
            // A non-terminal return means the driver handed control back rather than finishing:
            // re-enter it on the state it left behind.
            warn!("swap {swap_id} returned non-terminal state {state:?}; re-entering the driver");
            progress.set_state(state);
            respawn(ctx, progress.snapshot(), reservation, Duration::ZERO);
        }
        Err(e) => {
            let transient = is_transient(&e);
            let (rec, recovery) = progress.record_failure(&e, transient);
            match recovery {
                Recovery::Retry(delay) => {
                    if rec.funds_at_risk() && rec.retry_count >= recovery::MAX_DRIVER_RETRIES {
                        // Loud, and repeated at the recovery cadence rather than once: this swap
                        // holds committed funds, the daemon can no longer make progress on it, and
                        // nothing but an operator is going to change that.
                        error!(
                            "swap {swap_id} holds committed funds and its driver has now failed \
                             {} times in a row ({e}). It stays live and is re-entered in {}s; the \
                             claim or refund it owes will not happen without it. Check the chain, \
                             Lightning and wallet backends.",
                            rec.retry_count,
                            delay.as_secs()
                        );
                    } else {
                        warn!(
                            "swap {swap_id} hit a failure ({e}); attempt {}, re-entering the \
                             driver in {}s",
                            rec.retry_count,
                            delay.as_secs()
                        );
                    }
                    respawn(ctx, rec, reservation, delay);
                }
                Recovery::GiveUp => {
                    error!("swap {swap_id} failed permanently: {e}");
                    let state = SwapState::Failed(e.to_string());
                    progress.set_terminal(state.clone());
                    notify_terminal_peer(ctx, progress, peer, swap_id, state).await;
                }
            }
        }
    }
}

/// Keep the advertised offer current.
///
/// An offer carries an expiry and a fee estimate, and both go stale. Built once at startup it
/// advertised an expired validity window for the life of the process and a fee environment from
/// whenever the daemon happened to boot.
fn spawn_offer_refresher(
    ctx: &ExecCtx,
    config: &ProviderConfig,
    provider_pkarr: &str,
    network: Network,
    lightning_node_id: Option<String>,
    offer: SharedOffer,
) {
    let ctx = ctx.clone();
    let config = config.clone();
    let provider_pkarr = provider_pkarr.to_string();
    // Refresh well inside the validity window so it never lapses between rebuilds.
    let period = Duration::from_secs((config.quote_ttl_secs / 2).max(30));
    tokio::spawn(async move {
        loop {
            sleep(period).await;
            let rate = offer_fee_rate(ctx.chain.as_ref(), config.onchain_fee_rate_sat_vb);
            // A network this build cannot name is a startup failure, not something to keep
            // repricing against; `run` has already refused to start in that case.
            let Ok(fresh) = build_offer(
                &config,
                &provider_pkarr,
                network,
                lightning_node_id.clone(),
                rate,
                ctx.capable,
            ) else {
                continue;
            };
            let changed = {
                let current = offer.read().await;
                current.as_ref().map(|o| o.onchain_fee_sat) != Some(fresh.onchain_fee_sat)
            };
            if changed {
                info!(
                    "repriced the offer: on-chain cost now {} sat at {rate} sat/vB (effective \
                     minimum {} sat)",
                    fresh.onchain_fee_sat,
                    fresh.effective_min_amount_sat()
                );
            }
            *offer.write().await = Some(fresh);
        }
    });
}

/// Sweep terminal swap records that are old enough to drop.
fn spawn_record_pruner(ctx: &ExecCtx) {
    let store = ctx.store.clone();
    tokio::spawn(async move {
        loop {
            match store.prune_terminal(TERMINAL_RECORD_RETENTION) {
                Ok(n) if n > 0 => info!("pruned {n} terminal swap record(s)"),
                Ok(_) => {}
                Err(e) => warn!("pruning terminal swap records failed: {e}"),
            }
            sleep(Duration::from_secs(3600)).await;
        }
    });
}

/// Run the provider daemon.
pub async fn run(config: ProviderConfig) -> Result<()> {
    // Mutable so a backend capability probe can narrow the advertised directions.
    #[cfg_attr(not(feature = "beignet"), allow(unused_mut))]
    let mut config = config;
    let network = parse_network(&config.network)?;
    // Refuse to start with unsafe mainnet parameters (guards programmatic callers too).
    validate_timelocks(&config)?;
    validate_mainnet_safety(&config, network)?;

    let identity = config.identity()?;
    let transport = match identity.method {
        "file" => Transport::from_recovery_file(&identity.value, &identity.passphrase).await?,
        _ => Transport::from_recovery_phrase(&identity.value, Some(&identity.passphrase)).await?,
    };
    let provider_pkarr = transport.public_key_string();
    info!("Provider pubky: {provider_pkarr}");

    // Everything the status API needs, built before anything that talks to a network.
    //
    // The order matters more than it looks. Probing the backends is where a start can take half a
    // minute: an Electrum server that is down answers with a timeout, not a refusal. That is
    // exactly the moment an operator opens the dashboard, and until this moved the dashboard had
    // nothing to ask, because the API started after the probes it was needed to report on.
    let store: Arc<dyn SwapStore> = Arc::new(
        JsonFileSwapStore::new(format!("{}/swaps", config.data_dir)).context("open swap store")?,
    );
    let risk = risk::RiskManager::new(risk_limits(&config));
    let offer: SharedOffer = Arc::new(RwLock::new(None));
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(feature = "status")]
    status::spawn(status::State {
        config: Arc::new(config.clone()),
        store: store.clone(),
        risk: risk.clone(),
        offer: offer.clone(),
        ready: ready.clone(),
        provider_pkarr: provider_pkarr.clone(),
    })
    .await?;
    // A build without the feature cannot serve the address it was given, and saying nothing
    // leaves a dashboard polling a port that will never answer.
    #[cfg(not(feature = "status"))]
    if config.status_addr.as_deref().is_some_and(|a| !a.is_empty()) {
        warn!(
            "status_addr is set to {} but this build has no status API; rebuild with \
             --features status (or full)",
            config.status_addr.as_deref().unwrap_or_default()
        );
    }

    // Lightning backend (real with `--features lnd`, else a stub).
    let ln = make_backend(&config).await;
    let mut lightning_node_id: Option<String> = None;
    let ln_ready = match ln.node_info().await {
        Ok(info) => {
            // Advertise the node id so a client can see who it would be paying, and route to it.
            lightning_node_id = Some(info.pubkey.clone());
            info!(
                "Connected to LND node {} (alias {})",
                info.pubkey, info.alias
            );
            // Guard against a network mismatch (e.g. a regtest config pointed at mainnet LND).
            match info.chain_network.as_deref() {
                Some(reported) => match lnd_network_to_bitcoin(reported) {
                    Some(lnd_net) if lnd_net != network => {
                        return Err(anyhow!(
                            "network mismatch: provider configured for {network:?} but LND is on \
                             {lnd_net:?} ({reported}); aborting"
                        ));
                    }
                    Some(_) => {}
                    None => warn!(
                        "LND reported unrecognized network '{reported}'; skipping network guard"
                    ),
                },
                None => warn!("LND did not report a chain network; skipping network guard"),
            }
            true
        }
        Err(e) => {
            warn!("Lightning backend not ready: {e}");
            false
        }
    };

    // Ask a beignet daemon what it is and what it can do, before advertising anything. A
    // network mismatch or a competing swap role aborts here rather than surfacing mid-swap.
    let beignet = beignet_preflight(&config, network).await?;

    let chain = build_chain(&config);
    let wallet = build_wallet(&config, chain.clone()).await;

    // Reverse swaps need a hold invoice whose final CLTV outlives the on-chain refund. A beignet
    // that cannot set one cannot serve them safely, so drop the direction rather than advertising
    // something we would have to refuse after a counterparty's payment is already held.
    #[cfg(feature = "beignet")]
    if let Some(p) = &beignet {
        if !p.can_serve_reverse_swaps() && config.directions.contains(&SwapDirection::Reverse) {
            warn!(
                "this beignet cannot set a hold invoice's final CLTV expiry, so reverse swaps \
                 will not be advertised (see beignet#744)."
            );
            config.directions.retain(|d| *d != SwapDirection::Reverse);
        }
        // A submarine provider pays first and claims second, so the only thing keeping the
        // Lightning leg from outliving the on-chain one is a bound on the payment's total CLTV
        // expiry. Without it a client can hold the payment past its own refund height, take its
        // coins back on chain, and settle afterwards.
        if !p.can_serve_submarine_swaps() && config.directions.contains(&SwapDirection::Submarine) {
            warn!(
                "this beignet cannot bound a payment's total CLTV expiry, so submarine swaps \
                 will not be advertised (see beignet#751)."
            );
            config.directions.retain(|d| *d != SwapDirection::Submarine);
        }
        if config.directions.is_empty() {
            return Err(anyhow!(
                "this beignet cannot serve either configured direction safely; use an LND \
                 backend, or upgrade beignet"
            ));
        }
    }
    let _ = &beignet;

    let capable = ln_ready && chain.is_some() && wallet.is_some();
    if capable {
        info!("Provider is execution-capable (LND + chain watcher + funding wallet present)");
    } else {
        warn!(
            "Provider is negotiation-only (LND ready: {ln_ready}, chain: {}, wallet: {}); \
             SwapRequests will be rejected. Build with --features full and configure \
             --electrum-url / --wallet-mnemonic to enable execution.",
            chain.is_some(),
            wallet.is_some()
        );
    }

    let transport = Arc::new(ReplyTransport::direct(transport));
    let ctx = ExecCtx {
        transport: transport.clone(),
        ln,
        chain,
        wallet,
        network,
        required_confirmations: config.required_confirmations,
        timelock: timelock_params(&config),
        onchain_fee_rate_sat_vb: config.onchain_fee_rate_sat_vb,
        invoice_expiry_secs: config.invoice_expiry_secs,
        max_routing_fee_msat: config.max_routing_fee_msat,
        quote_ttl_secs: config.quote_ttl_secs,
        quotes: Arc::new(Mutex::new(HashMap::new())),
        store,
        risk,
        min_onchain_reserve_sat: config.min_onchain_reserve_sat,
        capable,
    };
    // The daemon has worked out what it can do; tell anything watching.
    ready.store(capable, std::sync::atomic::Ordering::Relaxed);

    // Resume any swaps that were in flight when we last shut down / crashed.
    resume_swaps(&ctx).await;
    // Watch for chain reorganizations affecting in-flight swaps.
    spawn_reorg_monitor(&ctx);
    // Sweep terminal swap records once they are old enough to drop. Records are retained
    // rather than deleted on completion, so a driver failure can never take one with it.
    spawn_record_pruner(&ctx);
    // Reap idle, unpinned peers so the poll set / follow graph stay bounded as clients come and go.
    spawn_peer_reaper(&ctx, Duration::from_secs(config.peer_idle_ttl_secs));

    // The offer is rebuilt periodically rather than once at startup.
    //
    // It carries `valid_until_unix`, computed from the quote TTL, so an offer built once went
    // stale after `quote_ttl_secs` and stayed that way for the life of the process. It also
    // carries a fee estimate, which is only meaningful if it tracks the mempool.
    {
        let built = build_offer(
            &config,
            &provider_pkarr,
            network,
            lightning_node_id.clone(),
            offer_fee_rate(ctx.chain.as_ref(), config.onchain_fee_rate_sat_vb),
            ctx.capable,
        )?;
        info!(
            "Advertising offer {} ({}..{} sat, dirs: {:?}); on-chain cost priced at {} sat at \
             {} sat/vB, so the effective minimum is {} sat",
            built.offer_id,
            built.min_amount_sat,
            built.max_amount_sat,
            built.directions,
            built.onchain_fee_sat,
            built.fee_rate_sat_vb,
            built.effective_min_amount_sat()
        );
        *offer.write().await = Some(built);
    }

    maybe_spawn_iroh_rendezvous(&ctx, &config, offer.clone());

    spawn_offer_refresher(
        &ctx,
        &config,
        &provider_pkarr,
        network,
        lightning_node_id,
        offer.clone(),
    );

    if let Err(e) = transport.discover_peers().await {
        warn!("peer discovery failed: {e}");
    }

    if config.broadcast_offer {
        for peer in transport.get_known_peers() {
            let Some(current) = offer.read().await.clone() else {
                break;
            };
            if let Err(e) = transport.send(&peer, &SwapMessage::Offer(current)).await {
                debug!("failed to send offer to {peer}: {e}");
            }
        }
    }

    info!("Provider running; waiting for quote/swap requests...");
    loop {
        let messages = transport
            .receive_all::<SwapMessage>()
            .await
            .unwrap_or_default();
        for (sender, msg) in messages {
            // No offer yet means the daemon is still working out what it can serve. Nothing to
            // quote against, so nothing to answer; the message stays unprocessed and comes round
            // again on the next poll.
            let Some(current) = offer.read().await.clone() else {
                continue;
            };
            if let Err(e) = handle_message(&ctx, &current, &sender, msg).await {
                warn!("error handling message from {sender}: {e}");
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// A shared HTTP client for the configured beignet daemon.
///
/// One client for both roles, so a provider using beignet for Lightning and for its wallet opens
/// one connection pool and runs one preflight rather than two.
#[cfg(feature = "beignet")]
fn beignet_http(config: &ProviderConfig) -> Result<Arc<beignet_backend::BeignetHttp>> {
    let mut cfg = beignet_backend::BeignetConfig::new(&config.beignet_url);
    // `BEIGNET_API_TOKEN` first, because that is the name beignet's own tooling uses and an
    // operator who has already set it should not have to set it twice.
    let token = match std::env::var("BEIGNET_API_TOKEN") {
        Ok(t) if !t.is_empty() => Some(t),
        _ => config
            .beignet_token
            .resolve("the beignet API token")?
            .map(|s| s.expose().to_string()),
    };
    cfg = cfg.with_token(token);
    cfg.api_prefix = config.beignet_api_prefix.clone();
    if !config.beignet_tls_cert.is_empty() {
        cfg.tls_cert_pem = Some(
            std::fs::read(&config.beignet_tls_cert)
                .with_context(|| format!("read {}", config.beignet_tls_cert))?,
        );
    }
    Ok(Arc::new(
        beignet_backend::BeignetHttp::new(cfg).map_err(|e| anyhow!("{e}"))?,
    ))
}

/// Check the beignet daemon is one we can safely use, and say what it can do.
#[cfg(feature = "beignet")]
async fn beignet_preflight(
    config: &ProviderConfig,
    network: Network,
) -> Result<Option<beignet_backend::Preflight>> {
    if config.lightning_backend != "beignet" && config.wallet_backend != "beignet" {
        return Ok(None);
    }
    let http = beignet_http(config)?;
    let preflight = match beignet_backend::capability::probe(&http).await {
        Ok(p) => p,
        Err(e) => {
            warn!("beignet is not reachable ({e}); the provider will run negotiation-only");
            return Ok(None);
        }
    };
    // A network mismatch or a competing swap role is fatal, not a warning: both are ways to lose
    // money quietly.
    preflight.report(network).map_err(|e| anyhow!("{e}"))?;
    Ok(Some(preflight))
}

#[cfg(not(feature = "beignet"))]
async fn beignet_preflight(_config: &ProviderConfig, _network: Network) -> Result<Option<()>> {
    Ok(None)
}

/// Construct the Lightning backend. Real LND with the `lnd` feature (and a successful
/// connection), otherwise a stub.
async fn make_backend(config: &ProviderConfig) -> Arc<dyn LightningBackend> {
    if config.lightning_backend == "beignet" {
        #[cfg(feature = "beignet")]
        {
            match beignet_http(config) {
                Ok(http) => return Arc::new(BeignetLightningBackend::new(http)),
                Err(e) => {
                    warn!("beignet client could not be built ({e}); falling back to stub");
                    // The reason travels with the stub. Everything downstream, the health check
                    // included, reports whatever the backend says, and a generic answer sends an
                    // operator looking in the wrong place.
                    return Arc::new(StubBackend::with_reason(format!(
                        "the beignet client could not be built: {e}"
                    )));
                }
            }
        }
        #[cfg(not(feature = "beignet"))]
        {
            warn!(
                "--lightning beignet needs a build with --features beignet; falling back to stub"
            );
            return Arc::new(StubBackend::with_reason(
                "this build has no beignet backend; rebuild with --features beignet",
            ));
        }
    }

    let lnd_config = LndConfig {
        address: config.lnd_address.clone(),
        tls_cert_path: config.lnd_cert_path.clone(),
        macaroon_path: config.lnd_macaroon_path.clone(),
    };
    #[cfg(feature = "lnd")]
    {
        let address = lnd_config.address.clone();
        match LndBackend::connect(lnd_config).await {
            Ok(b) => Arc::new(b),
            Err(e) => {
                warn!("LND connect failed ({e}); falling back to stub backend");
                Arc::new(StubBackend::with_reason(format!(
                    "could not connect to LND at {address}: {e}"
                )))
            }
        }
    }
    #[cfg(not(feature = "lnd"))]
    {
        let _ = lnd_config;
        Arc::new(StubBackend::with_reason(
            "this build has no LND backend; rebuild with --features lnd (or full)",
        ))
    }
}

#[cfg(feature = "chain")]
fn build_chain(config: &ProviderConfig) -> Option<Arc<dyn ChainWatcher>> {
    if config.electrum_url.is_empty() {
        return None;
    }
    let mut electrum = swap_common::chain::ElectrumConfig::new(&config.electrum_url);
    electrum.timeout_secs = config.electrum_timeout_secs;
    if !config.electrum_socks5.is_empty() {
        electrum.socks5 = Some(config.electrum_socks5.clone());
    }
    match swap_common::chain::ElectrumWatcher::connect(electrum) {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("chain watcher unavailable: {e}");
            None
        }
    }
}
#[cfg(not(feature = "chain"))]
fn build_chain(_config: &ProviderConfig) -> Option<Arc<dyn ChainWatcher>> {
    None
}

/// Build the on-chain funding wallet. `wallet_backend = "lnd"` funds from LND's own on-chain
/// balance (no separate seed); anything else uses the BDK wallet from `--wallet-mnemonic`.
async fn build_wallet(
    config: &ProviderConfig,
    chain: Option<Arc<dyn ChainWatcher>>,
) -> Option<Arc<dyn OnchainWallet>> {
    match config.wallet_backend.as_str() {
        "lnd" => build_lnd_wallet(config).await,
        "beignet" => build_beignet_wallet(config, chain).await,
        _ => build_bdk_wallet(config),
    }
}

#[cfg(feature = "beignet")]
async fn build_beignet_wallet(
    config: &ProviderConfig,
    chain: Option<Arc<dyn ChainWatcher>>,
) -> Option<Arc<dyn OnchainWallet>> {
    let network = parse_network(&config.network).ok()?;
    let http = match beignet_http(config) {
        Ok(h) => h,
        Err(e) => {
            warn!("beignet wallet unavailable: {e}");
            return None;
        }
    };
    // The chain watcher is passed through so the wallet can locate a funding output if the daemon
    // ever stops returning the raw transaction. It is a fallback, not the normal path.
    match beignet_backend::BeignetWallet::connect(
        http,
        network,
        config.onchain_fee_rate_sat_vb,
        chain,
    )
    .await
    {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("beignet wallet unavailable: {e}");
            None
        }
    }
}

#[cfg(not(feature = "beignet"))]
async fn build_beignet_wallet(
    _config: &ProviderConfig,
    _chain: Option<Arc<dyn ChainWatcher>>,
) -> Option<Arc<dyn OnchainWallet>> {
    warn!("--wallet beignet needs a build with --features beignet");
    None
}

#[cfg(feature = "lnd")]
async fn build_lnd_wallet(config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    let lnd_config = LndConfig {
        address: config.lnd_address.clone(),
        tls_cert_path: config.lnd_cert_path.clone(),
        macaroon_path: config.lnd_macaroon_path.clone(),
    };
    match lightning_backend::LndWallet::connect(lnd_config, config.onchain_fee_rate_sat_vb).await {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("LND on-chain wallet unavailable: {e}");
            None
        }
    }
}
#[cfg(not(feature = "lnd"))]
async fn build_lnd_wallet(_config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    warn!("wallet-backend 'lnd' requires the `lnd` feature");
    None
}

#[cfg(feature = "bdk-wallet")]
fn build_bdk_wallet(config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    if config.electrum_url.is_empty() {
        return None;
    }
    let mnemonic = match config.wallet_mnemonic.resolve("the wallet mnemonic") {
        Ok(Some(m)) => m,
        Ok(None) => return None,
        Err(e) => {
            warn!("funding wallet unavailable: {e}");
            return None;
        }
    };
    let network = parse_network(&config.network).ok()?;
    match crate::wallet::BdkWallet::from_mnemonic(
        mnemonic.expose(),
        network,
        &config.electrum_url,
        config.onchain_fee_rate_sat_vb,
        &std::path::Path::new(&config.data_dir).join("wallet"),
    ) {
        Ok(w) => Some(Arc::new(w)),
        Err(e) => {
            warn!("funding wallet unavailable: {e}");
            None
        }
    }
}
#[cfg(not(feature = "bdk-wallet"))]
fn build_bdk_wallet(_config: &ProviderConfig) -> Option<Arc<dyn OnchainWallet>> {
    None
}

/// The chain fee rate to price an offer at: a live estimate, clamped to the operator's floor.
fn offer_fee_rate(ctx_chain: Option<&Arc<dyn ChainWatcher>>, floor: u64) -> u64 {
    let estimate = ctx_chain
        .and_then(|c| run_blocking(|| c.estimate_fee_rate(FUNDING_FEE_TARGET_BLOCKS)).ok())
        .flatten();
    swap_common::onchain::resolve_fee_rate(
        estimate,
        floor,
        swap_common::onchain::ABSOLUTE_MAX_FEE_RATE_SAT_VB,
    )
}

/// Confirmation target for pricing an offer's on-chain component.
const FUNDING_FEE_TARGET_BLOCKS: u16 = 3;

fn build_offer(
    config: &ProviderConfig,
    provider_pkarr: &str,
    network: Network,
    lightning_node_id: Option<String>,
    fee_rate_sat_vb: u64,
    capable: bool,
) -> Result<SwapOffer> {
    // Price the on-chain component from the direction that costs the most, so a single advertised
    // figure covers whichever direction a client picks.
    let script = pricing::representative_htlc_script();
    let dest = pricing::representative_dest_spk();
    let onchain_fee_sat = config
        .directions
        .iter()
        .map(|d| pricing::expected_onchain_cost_sat(*d, fee_rate_sat_vb, &script, &dest))
        .max()
        .unwrap_or(0);

    Ok(SwapOffer {
        request_id: None,
        offer_id: Uuid::new_v4(),
        provider_pkarr: provider_pkarr.to_string(),
        network: NetworkSpec::from_bitcoin_network(network)?,
        directions: config.directions.clone(),
        min_amount_sat: config.min_amount_sat,
        max_amount_sat: config.max_amount_sat,
        base_fee_sat: config.base_fee_sat,
        fee_ppm: config.fee_ppm,
        required_confirmations: config.required_confirmations,
        htlc_timeout_blocks: config.htlc_timeout_blocks,
        lightning_node_id,
        // Advisory: clients should always request a fresh Quote (which carries the firm,
        // enforced expiry) before committing.
        valid_until_unix: now_unix().saturating_add(config.quote_ttl_secs),
        onchain_fee_sat,
        fee_rate_sat_vb,
        protocol_version: PROTOCOL_VERSION,
        features: if capable {
            let mut features = vec!["boltz-taproot-v1".into(), "swap-status-v1".into()];
            if cfg!(feature = "iroh") && config.rendezvous_iroh {
                features.push("session-rpc-v1".into());
            }
            features
        } else {
            Vec::new()
        },
    })
}

async fn handle_message(
    ctx: &ExecCtx,
    offer: &SwapOffer,
    sender: &str,
    msg: SwapMessage,
) -> Result<()> {
    match msg {
        SwapMessage::OfferRequest(req) => {
            let mut current = offer.clone();
            current.request_id = req.request_id;
            ctx.transport
                .send(sender, &SwapMessage::Offer(current))
                .await?;
        }
        SwapMessage::SwapStatusRequest(req) => {
            match status_snapshot(
                ctx.store.as_ref(),
                sender,
                ctx.transport.authorization(),
                &req,
            ) {
                Ok(snapshot) => {
                    ctx.transport
                        .send(sender, &SwapMessage::SwapStatusSnapshot(snapshot))
                        .await?
                }
                Err(error) => {
                    let code = match error.downcast_ref::<SwapLookupError>() {
                        Some(SwapLookupError::NotFound) => Some("not_found"),
                        Some(SwapLookupError::Pending) => Some("pending"),
                        None => None,
                    };
                    reject_coded(
                        &ctx.transport,
                        sender,
                        req.request_id,
                        req.swap_id,
                        req.quote_id,
                        &error.to_string(),
                        code,
                    )
                    .await?
                }
            }
        }

        SwapMessage::QuoteRequest(req) => {
            if req.offer_id != Uuid::nil() && req.offer_id != offer.offer_id {
                return Ok(());
            }
            // The cheapest place to find a mismatch: nothing is quoted, nothing reserved, and no
            // key generated. Finding it later means finding it with money already committed.
            if !protocol_version_supported(req.protocol_version) {
                return reject_request(
                    &ctx.transport,
                    sender,
                    req.request_id,
                    None,
                    None,
                    &format!(
                        "protocol version {} is not supported (this provider speaks {}..={})",
                        req.protocol_version, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION
                    ),
                )
                .await;
            }
            if let Err(e) = check_client_pkarr(&req.client_pkarr, sender) {
                return reject_request(
                    &ctx.transport,
                    sender,
                    req.request_id,
                    None,
                    None,
                    &e.to_string(),
                )
                .await;
            }
            if !offer.supports(req.direction) {
                return reject_request(
                    &ctx.transport,
                    sender,
                    req.request_id,
                    None,
                    None,
                    "unsupported direction",
                )
                .await;
            }
            if !offer.accepts_amount(req.amount_sat) {
                return reject_request(
                    &ctx.transport,
                    sender,
                    req.request_id,
                    None,
                    None,
                    "amount out of range",
                )
                .await;
            }
            let fee = offer.quote_fee(req.amount_sat);
            let now = now_unix();
            let expires_at_unix = now.saturating_add(ctx.quote_ttl_secs);
            let quote = Quote {
                request_id: req.request_id,
                quote_id: Uuid::new_v4(),
                offer_id: offer.offer_id,
                direction: req.direction,
                amount_sat: req.amount_sat,
                fee_sat: fee.total_fee_sat,
                service_fee_sat: fee.service_fee_sat,
                onchain_fee_sat: fee.onchain_fee_sat,
                fee_rate_sat_vb: offer.fee_rate_sat_vb,
                total_sat: req.amount_sat.saturating_add(fee.total_fee_sat),
                htlc_timeout_blocks: offer.htlc_timeout_blocks,
                required_confirmations: offer.required_confirmations,
                valid_until_unix: expires_at_unix,
                protocol_version: PROTOCOL_VERSION,
            };
            {
                let mut quotes = ctx.quotes.lock().await;
                prune_quotes(&mut quotes, now);
                // Bound memory under a quote flood: drop the request if we're already at capacity.
                if quotes.len() >= MAX_TRACKED_QUOTES {
                    warn!(
                        "quote cache full ({MAX_TRACKED_QUOTES}); dropping request from {sender}"
                    );
                    return reject_request(
                        &ctx.transport,
                        sender,
                        req.request_id,
                        None,
                        None,
                        "provider busy",
                    )
                    .await;
                }
                quotes.insert(
                    quote.quote_id,
                    IssuedQuote {
                        peer: sender.to_string(),
                        direction: req.direction,
                        amount_sat: req.amount_sat,
                        fee_sat: fee.total_fee_sat,
                        service_fee_sat: fee.service_fee_sat,
                        onchain_fee_sat: fee.onchain_fee_sat,
                        expires_at_unix,
                    },
                );
            }
            info!("Sending quote {} to {sender}", quote.quote_id);
            ctx.transport
                .send(sender, &SwapMessage::Quote(quote))
                .await?;
        }

        SwapMessage::SwapRequest(req) => {
            if let Err(error) = check_client_pkarr(&req.client_pkarr, sender) {
                return reject(
                    &ctx.transport,
                    sender,
                    None,
                    Some(req.quote_id),
                    &error.to_string(),
                )
                .await;
            }
            match replay_record(
                ctx.store.as_ref(),
                sender,
                ctx.transport.authorization(),
                &req,
            ) {
                Ok(Some(mut record)) => {
                    if record.pending_hold_invoice.is_some() {
                        let reservation = Some(reserve_pending_swap(ctx, &record).await?);
                        record = complete_invoice_intent(
                            ctx.ln.as_ref(),
                            ctx.store.as_ref(),
                            record.swap_id,
                            true,
                        )
                        .await?;
                        let swap = reverse_swap_from_record(&record, ctx.timelock)?;
                        spawn_reverse_driver(
                            ctx,
                            swap,
                            record.clone(),
                            reservation,
                            Duration::ZERO,
                        );
                    }
                    let accept = record
                        .swap_accept
                        .ok_or_else(|| anyhow!("persisted creation is missing its acceptance"))?;
                    return ctx
                        .transport
                        .send(sender, &SwapMessage::SwapAccept(accept))
                        .await
                        .map_err(Into::into);
                }
                Ok(None) => {}
                Err(error) => {
                    return reject(
                        &ctx.transport,
                        sender,
                        None,
                        Some(req.quote_id),
                        &error.to_string(),
                    )
                    .await
                }
            }
            if !ctx.capable {
                return reject(
                    &ctx.transport,
                    sender,
                    None,
                    Some(req.quote_id),
                    "provider is not configured for swap execution",
                )
                .await;
            }
            let direction = req.direction;
            let quote_id = req.quote_id;
            let result = match direction {
                SwapDirection::Reverse => start_reverse(ctx, sender, req).await,
                SwapDirection::Submarine => start_submarine(ctx, sender, req).await,
            };
            if let Err(e) = result {
                warn!("failed to start {direction:?} swap: {e}");
                reject(
                    &ctx.transport,
                    sender,
                    None,
                    Some(quote_id),
                    &format!("swap start failed: {e}"),
                )
                .await?;
            }
        }

        other => debug!("ignoring message variant: {}", variant_name(&other)),
    }
    Ok(())
}

/// One Lightning payment hash cannot fund multiple reverse contracts.
fn ensure_reverse_hash_available(store: &dyn SwapStore, hash: &PaymentHash) -> Result<()> {
    for record in store.load_all_checked()? {
        if record.direction == SwapDirection::Reverse && record.payment_hash()? == *hash {
            return Err(anyhow!(
                "payment hash already belongs to an admitted reverse swap"
            ));
        }
    }
    Ok(())
}

/// Finish only the invoice associated with a previously persisted admission.
async fn complete_invoice_intent(
    ln: &dyn LightningBackend,
    store: &dyn SwapStore,
    swap_id: Uuid,
    recover_existing: bool,
) -> Result<SwapRecord> {
    let mut record = store
        .get(swap_id)?
        .ok_or_else(|| anyhow!("reverse invoice intent was not persisted"))?;
    validate_persisted_contract(&record)?;
    let pending = record
        .pending_hold_invoice
        .as_ref()
        .ok_or_else(|| anyhow!("missing reverse invoice intent"))?;
    let expected_amount = record
        .onchain_amount_sat
        .checked_add(record.service_fee_sat)
        .and_then(|value| value.checked_add(record.onchain_fee_sat))
        .and_then(|value| value.checked_mul(1000))
        .ok_or_else(|| anyhow!("persisted invoice amount overflows"))?;
    if record.direction != SwapDirection::Reverse
        || !record.invoice.is_empty()
        || record.funding_outpoint().is_some()
        || record.funding_intent_at_height.is_some()
        || pending.amount_msat != expected_amount
        || pending.memo != format!("pubky-swap reverse {}", record.swap_id)
        || pending.cltv_expiry_delta == 0
        || pending.expiry_secs == 0
    {
        return Err(anyhow!("invalid persisted reverse invoice intent"));
    }
    let request = lightning_backend::HoldInvoiceRequest {
        payment_hash: record.payment_hash()?,
        amount_msat: pending.amount_msat,
        expiry_secs: pending.expiry_secs,
        cltv_expiry_delta: pending.cltv_expiry_delta,
        memo: pending.memo.clone(),
    };
    let existing = if recover_existing {
        ln.lookup_hold_invoice(&request)
            .await
            .context("recover hold invoice")?
    } else {
        None
    };
    let invoice = match existing {
        Some(invoice) => invoice,
        None => ln
            .create_hold_invoice(request.clone())
            .await
            .context("create hold invoice")?,
    };
    if invoice.payment_hash != request.payment_hash
        || invoice.amount_msat != request.amount_msat
        || invoice.bolt11.is_empty()
    {
        return Err(anyhow!(
            "hold invoice response does not match the persisted intent"
        ));
    }
    record.invoice = invoice.bolt11.clone();
    record
        .swap_accept
        .as_mut()
        .ok_or_else(|| anyhow!("invoice intent has no acceptance"))?
        .invoice = Some(invoice.bolt11);
    record.pending_hold_invoice = None;
    record.updated_at_unix = now_unix();
    validate_persisted_contract(&record)?;
    store
        .put(&record)
        .context("persist completed reverse invoice creation")?;
    Ok(record)
}

fn authorized_peer(record: &SwapRecord, sender: &str, authorization: Option<(&str, &str)>) -> bool {
    pubky_transport::same_pubky(&record.peer, sender)
        && record.peer_account.as_deref() == authorization.map(|(account, _)| account)
        && record.peer_authorization_scope.as_deref() == authorization.map(|(_, scope)| scope)
}

/// Find an already admitted creation without spending another quote or generating new keys.
fn replay_record(
    store: &dyn SwapStore,
    sender: &str,
    authorization: Option<(&str, &str)>,
    request: &SwapRequest,
) -> Result<Option<SwapRecord>> {
    for record in store.load_all_checked()? {
        let Some(original) = record.swap_request.as_ref() else {
            continue;
        };
        if original.quote_id != request.quote_id {
            continue;
        }
        if !authorized_peer(&record, sender, authorization) {
            return Err(anyhow!("unknown or expired quote"));
        }
        if original != request {
            return Err(anyhow!(
                "quote was already accepted with a different request"
            ));
        }
        if record.swap_accept.is_none() {
            return Err(anyhow!("persisted creation is missing its acceptance"));
        }
        return Ok(Some(record));
    }
    Ok(None)
}

/// Restrict recovery to the transport-authenticated counterparty and expose only public data.
fn status_snapshot(
    store: &dyn SwapStore,
    sender: &str,
    authorization: Option<(&str, &str)>,
    request: &SwapStatusRequest,
) -> Result<SwapStatusSnapshot> {
    let record = match (request.swap_id, request.quote_id) {
        (Some(swap_id), None) => store.get(swap_id)?,
        (None, Some(quote_id)) => store.load_all_checked()?.into_iter().find(|record| {
            record
                .swap_request
                .as_ref()
                .is_some_and(|original| original.quote_id == quote_id)
        }),
        _ => return Err(anyhow!("exactly one of swap_id and quote_id is required")),
    }
    .ok_or(SwapLookupError::NotFound)?;
    if !authorized_peer(&record, sender, authorization) {
        return Err(SwapLookupError::NotFound.into());
    }
    if record.pending_hold_invoice.is_some() {
        return Err(SwapLookupError::Pending.into());
    }
    let accept = record
        .swap_accept
        .ok_or_else(|| anyhow!("this older swap has no persisted acceptance"))?;
    Ok(SwapStatusSnapshot {
        request_id: request.request_id,
        accept,
        network: record.network,
        state: record.state,
        funding_txid_hex: record.funding_txid_hex,
        funding_vout: record.funding_vout,
        spend_txid_hex: record.spend_txid_hex,
        required_confirmations: record.required_confirmations,
        updated_at_unix: record.updated_at_unix,
        observed_at_unix: now_unix(),
    })
}

#[derive(Debug)]
enum SwapLookupError {
    NotFound,
    Pending,
}

impl std::fmt::Display for SwapLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "unknown swap",
            Self::Pending => "swap admission is persisted; invoice creation is pending",
        })
    }
}

impl std::error::Error for SwapLookupError {}

/// Reserve capacity and check the wallet can actually fund this swap, before anything is
/// promised to the counterparty.
///
/// Ordering is the point. A reverse swap creates a hold invoice, takes the client's Lightning
/// payment, and only then tries to fund the HTLC. Discovering there is nothing to fund with at
/// that moment is the worst possible time, because the counterparty's money is already held and
/// the only way out is cancelling an invoice they have already paid.
async fn reserve_for_swap(
    ctx: &ExecCtx,
    peer: &str,
    swap_id: Uuid,
    direction: SwapDirection,
    onchain_amount_sat: u64,
) -> Result<risk::ReservationGuard> {
    let guard = ctx
        .risk
        .reserve(
            ctx.transport.account().unwrap_or(peer),
            swap_id,
            onchain_amount_sat,
        )
        .map_err(|reason| anyhow!("{reason}"))?;

    check_funding_balance(ctx, direction, onchain_amount_sat).await?;
    Ok(guard)
}

async fn reserve_pending_swap(
    ctx: &ExecCtx,
    record: &SwapRecord,
) -> Result<risk::ReservationGuard> {
    let guard = ctx
        .risk
        .reserve_pending(
            record.peer_account.as_deref().unwrap_or(&record.peer),
            record.swap_id,
            record.onchain_amount_sat,
        )
        .map_err(|reason| anyhow!("{reason}"))?;
    check_funding_balance(ctx, record.direction, record.onchain_amount_sat).await?;
    Ok(guard)
}

async fn check_funding_balance(
    ctx: &ExecCtx,
    direction: SwapDirection,
    onchain_amount_sat: u64,
) -> Result<()> {
    // Only a reverse swap spends the provider's own coins on chain; in a submarine swap the
    // client funds and we claim.
    if direction == SwapDirection::Reverse {
        if let Some(wallet) = ctx.wallet.as_ref() {
            let balance = run_blocking(|| wallet.spendable_balance_sat())
                .map_err(|e| anyhow!("wallet balance: {e}"))?;
            if let Some(available) = balance {
                let needed = onchain_amount_sat
                    .saturating_add(ctx.min_onchain_reserve_sat)
                    .saturating_add(
                        ctx.onchain_fee_rate_sat_vb
                            .saturating_mul(pricing::FUNDING_VSIZE),
                    );
                if available < needed {
                    return Err(anyhow!(
                        "insufficient on-chain balance: {available} sat available, {needed} sat \
                         needed for a {onchain_amount_sat} sat swap plus fees and the \
                         {} sat reserve",
                        ctx.min_onchain_reserve_sat
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Start a reverse swap: create the hold invoice + HTLC, reply with `SwapAccept`, and spawn
/// the driver.
async fn start_reverse(ctx: &ExecCtx, sender: &str, req: SwapRequest) -> Result<()> {
    let chain = ctx
        .chain
        .clone()
        .ok_or_else(|| anyhow!("no chain watcher"))?;
    // Everything the request has to get right is checked before the quote is spent, so a
    // malformed request cannot burn a quote its sender could otherwise still use.
    let claim_pk = parse_pubkey(
        req.client_claim_pubkey_hex
            .as_deref()
            .ok_or_else(|| anyhow!("reverse swap requires client_claim_pubkey"))?,
    )?;
    let payment_hash = parse_hash32(&req.payment_hash_hex)?;

    ensure_reverse_hash_available(ctx.store.as_ref(), &payment_hash)?;
    let quote = take_valid_quote(&ctx.quotes, req.quote_id, sender, SwapDirection::Reverse).await?;

    // Reserve capacity and check the wallet before the hold invoice exists. Creating the
    // invoice first would mean discovering we cannot fund only after the client has paid it.
    let swap_id = Uuid::new_v4();
    let reservation = reserve_for_swap(
        ctx,
        sender,
        swap_id,
        SwapDirection::Reverse,
        quote.amount_sat,
    )
    .await?;

    let secp = Secp256k1::new();
    let (refund_sk, refund_pk) = swap_common::random_keypair(&secp);
    let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?;
    let timeout_height = timelock::onchain_timeout(tip, &ctx.timelock)
        .map_err(|e| anyhow!("timeout height: {e}"))?;

    let taproot = match req.script_type {
        SwapScript::P2wsh => None,
        SwapScript::TaprootBoltz => Some(swap_common::taproot::BoltzTaprootSwap::new(
            SwapDirection::Reverse,
            &parse_hash32(&req.payment_hash_hex)?,
            &claim_pk,
            &refund_pk,
            timeout_height,
        )?),
    };
    let htlc_script = if taproot.is_some() {
        bitcoin::ScriptBuf::new()
    } else {
        swap_common::htlc::build_htlc_script(&payment_hash, &claim_pk, &refund_pk, timeout_height)
    };
    let htlc_spk = taproot.as_ref().map_or_else(
        || htlc_p2wsh_address(&htlc_script, ctx.network).script_pubkey(),
        |contract| contract.address(ctx.network).script_pubkey(),
    );
    let swap = ReverseSwap {
        taproot,
        payment_hash,
        onchain_amount_sat: quote.amount_sat,
        fee_rate_sat_vb: ctx.onchain_fee_rate_sat_vb,
        htlc_script,
        htlc_spk,
        timeout_height,
        refund_key: refund_sk,
        invoice: String::new(),
        timelock: ctx.timelock,
    };
    let mut invoice_request = reverse_invoice_request(
        payment_hash,
        quote.amount_sat,
        quote.fee_sat,
        ctx.invoice_expiry_secs,
        ctx.timelock,
    )?;
    invoice_request.memo = format!("pubky-swap reverse {swap_id}");

    // Persist before telling the client anything. The record is what makes the swap resumable,
    // and the moment the `SwapAccept` is on the wire the client can pay the hold invoice; a
    // record written after that leaves a window where the counterparty is committed and we have
    // nothing on disk to come back to. Writing first also means a failure here costs nothing:
    // nobody has acted yet.
    let accept = SwapAccept {
        script_type: req.script_type,
        swap_tree: swap.taproot.as_ref().map(|contract| contract.swap_tree()),
        quote_id: req.quote_id,
        swap_id,
        direction: SwapDirection::Reverse,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        htlc_address: swap
            .taproot
            .as_ref()
            .map_or_else(
                || htlc_p2wsh_address(&swap.htlc_script, ctx.network),
                |contract| contract.address(ctx.network),
            )
            .to_string(),
        onchain_amount_sat: swap.onchain_amount_sat,
        timeout_block_height: swap.timeout_height,
        provider_pubkey_hex: hex::encode(refund_pk.to_bytes()),
        invoice: None,
    };
    let record = SwapRecord {
        pending_hold_invoice: Some(store::PendingHoldInvoice {
            amount_msat: invoice_request.amount_msat,
            expiry_secs: invoice_request.expiry_secs,
            cltv_expiry_delta: invoice_request.cltv_expiry_delta,
            memo: invoice_request.memo,
        }),
        swap_request: Some(req.clone()),
        swap_accept: Some(accept.clone()),
        taproot: swap.taproot.clone(),
        created_at_unix: now_unix(),
        updated_at_unix: now_unix(),
        swap_id,
        direction: SwapDirection::Reverse,
        peer: sender.to_string(),
        peer_account: ctx.transport.account().map(str::to_owned),
        peer_authorization_scope: ctx
            .transport
            .authorization()
            .map(|(_, scope)| scope.to_owned()),
        network: NetworkSpec::from_bitcoin_network(ctx.network)?,
        payment_hash_hex: hex::encode(swap.payment_hash),
        onchain_amount_sat: swap.onchain_amount_sat,
        fee_rate_sat_vb: swap.fee_rate_sat_vb,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        timeout_height: swap.timeout_height,
        secret_key_hex: hex::encode(swap.refund_key.secret_bytes()),
        invoice: swap.invoice.clone(),
        max_routing_fee_msat: 0,
        service_fee_sat: quote.service_fee_sat,
        onchain_fee_sat: quote.onchain_fee_sat,
        required_confirmations: ctx.required_confirmations,
        funding_txid_hex: None,
        funding_vout: None,
        state: SwapState::Created,
        ..SwapRecord::new_progress()
    };
    // The durable intent exists before the invoice RPC, including its owner and immutable hash.
    ctx.store
        .put(&record)
        .context("persist reverse invoice intent")?;
    let record =
        complete_invoice_intent(ctx.ln.as_ref(), ctx.store.as_ref(), record.swap_id, false).await?;
    let swap = reverse_swap_from_record(&record, ctx.timelock)?;
    let accept = record
        .swap_accept
        .clone()
        .ok_or_else(|| anyhow!("completed reverse swap has no acceptance"))?;

    if let Err(e) = ctx
        .transport
        .send(sender, &SwapMessage::SwapAccept(accept))
        .await
    {
        warn!("could not send acceptance for {swap_id}: {e}; keeping its persisted driver active for recovery");
    }
    info!("Reverse swap {swap_id} started (timeout height {timeout_height})");

    spawn_reverse_driver(ctx, swap, record, Some(reservation), Duration::ZERO);
    Ok(())
}

/// Spawn the per-swap reverse driver task (shared by fresh starts and restart-resume), persisting
/// progress and cleaning up the store + sending a final status on completion.
fn spawn_reverse_driver(
    ctx: &ExecCtx,
    swap: ReverseSwap,
    record: SwapRecord,
    // Held for the driver's lifetime, so exposure is released when the task ends however it
    // ends. A driver that panics or is cancelled cannot leave capacity counted forever.
    reservation: Option<risk::ReservationGuard>,
    // How long to wait before driving, after a failure. Waited out inside the task rather than
    // before spawning it, so the reservation is held across the delay: a swap backing off is a
    // swap whose funds are still committed.
    delay: Duration,
) {
    let chain = match ctx.chain.clone() {
        Some(c) => c,
        None => return,
    };
    let wallet = match ctx.wallet.clone() {
        Some(w) => w,
        None => return,
    };
    let resume = record.resume();
    let peer = record.peer.clone();
    let swap_id = record.swap_id;
    let required_confirmations = record.required_confirmations;
    let progress = Arc::new(StoreProgress {
        store: ctx.store.clone(),
        record: std::sync::Mutex::new(record),
    });
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        if !delay.is_zero() {
            sleep(delay).await;
        }
        let result = drive_reverse_swap(
            ctx2.ln.as_ref(),
            chain.as_ref(),
            wallet.as_ref(),
            &swap,
            required_confirmations,
            Duration::from_secs(2),
            &resume,
            progress.as_ref(),
        )
        .await;
        finish_driver_run(
            &ctx2,
            &progress,
            &peer,
            swap_id,
            result,
            reservation,
            |ctx, rec, reservation, delay| match reverse_swap_from_record(&rec, ctx.timelock) {
                Ok(swap) => spawn_reverse_driver(ctx, swap, rec, reservation, delay),
                Err(e) => error!("cannot re-enter reverse swap {swap_id}: {e}"),
            },
        )
        .await;
    });
}

/// Start a submarine swap: build the HTLC the client funds, reply with `SwapAccept`, and
/// spawn the driver.
async fn start_submarine(ctx: &ExecCtx, sender: &str, req: SwapRequest) -> Result<()> {
    let chain = ctx
        .chain
        .clone()
        .ok_or_else(|| anyhow!("no chain watcher"))?;
    // As in the reverse direction: nothing about the request is taken on trust until it has been
    // checked, and the quote is only spent once it has.
    let invoice = req
        .invoice
        .clone()
        .ok_or_else(|| anyhow!("submarine swap requires an invoice"))?;
    let client_refund_pk = parse_pubkey(
        req.client_refund_pubkey_hex
            .as_deref()
            .ok_or_else(|| anyhow!("submarine swap requires client_refund_pubkey"))?,
    )?;

    let quote =
        take_valid_quote(&ctx.quotes, req.quote_id, sender, SwapDirection::Submarine).await?;

    // Reserve before anything is promised. A submarine swap does not spend our coins on chain,
    // but it does commit our Lightning liquidity and a driver slot, and one counterparty should
    // not be able to take all of either.
    let swap_id = Uuid::new_v4();
    let reservation = reserve_for_swap(
        ctx,
        sender,
        swap_id,
        SwapDirection::Submarine,
        quote.amount_sat.saturating_add(quote.fee_sat),
    )
    .await?;

    let secp = Secp256k1::new();
    let (claim_sk, claim_pk) = swap_common::random_keypair(&secp);
    let tip = run_blocking(|| chain.tip_height()).map_err(|e| anyhow!("tip height: {e}"))?;
    let timeout_height = timelock::onchain_timeout(tip, &ctx.timelock)
        .map_err(|e| anyhow!("timeout height: {e}"))?;

    let taproot = match req.script_type {
        SwapScript::P2wsh => None,
        SwapScript::TaprootBoltz => Some(swap_common::taproot::BoltzTaprootSwap::new(
            SwapDirection::Submarine,
            &parse_hash32(&req.payment_hash_hex)?,
            &claim_pk,
            &client_refund_pk,
            timeout_height,
        )?),
    };
    let mut swap = init_submarine_swap(
        ctx.ln.as_ref(),
        &invoice,
        &client_refund_pk,
        claim_sk,
        &claim_pk,
        quote.amount_sat,
        quote.fee_sat,
        ctx.onchain_fee_rate_sat_vb,
        ctx.max_routing_fee_msat,
        tip,
        timeout_height,
        ctx.network,
        ctx.timelock,
    )
    .await?;
    if let Some(contract) = taproot {
        // The invoice and the script must commit to the same client-supplied hash.
        if swap.payment_hash != parse_hash32(&req.payment_hash_hex)? {
            return Err(anyhow!("request payment hash does not match the invoice"));
        }
        swap.htlc_spk = contract.address(ctx.network).script_pubkey();
        swap.htlc_script = bitcoin::ScriptBuf::new();
        swap.taproot = Some(contract);
    }

    // Persist before the `SwapAccept` goes out, for the same reason as the reverse direction:
    // once the client has the HTLC address it can fund it, and a claim key that only exists in
    // this process is a claim key one crash away from being gone.
    let accept = SwapAccept {
        script_type: req.script_type,
        swap_tree: swap.taproot.as_ref().map(|contract| contract.swap_tree()),
        quote_id: req.quote_id,
        swap_id,
        direction: SwapDirection::Submarine,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        htlc_address: swap
            .taproot
            .as_ref()
            .map_or_else(
                || htlc_p2wsh_address(&swap.htlc_script, ctx.network),
                |contract| contract.address(ctx.network),
            )
            .to_string(),
        onchain_amount_sat: swap.onchain_amount_sat,
        timeout_block_height: swap.timeout_height,
        provider_pubkey_hex: hex::encode(claim_pk.to_bytes()),
        invoice: None,
    };
    let record = SwapRecord {
        swap_request: Some(req.clone()),
        swap_accept: Some(accept.clone()),
        taproot: swap.taproot.clone(),
        created_at_unix: now_unix(),
        updated_at_unix: now_unix(),
        swap_id,
        direction: SwapDirection::Submarine,
        peer: sender.to_string(),
        peer_account: ctx.transport.account().map(str::to_owned),
        peer_authorization_scope: ctx
            .transport
            .authorization()
            .map(|(_, scope)| scope.to_owned()),
        network: NetworkSpec::from_bitcoin_network(ctx.network)?,
        payment_hash_hex: hex::encode(swap.payment_hash),
        onchain_amount_sat: swap.onchain_amount_sat,
        fee_rate_sat_vb: swap.fee_rate_sat_vb,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        timeout_height: swap.timeout_height,
        secret_key_hex: hex::encode(swap.claim_key.secret_bytes()),
        invoice: swap.invoice.clone(),
        max_routing_fee_msat: swap.max_routing_fee_msat,
        service_fee_sat: quote.service_fee_sat,
        onchain_fee_sat: quote.onchain_fee_sat,
        required_confirmations: ctx.required_confirmations,
        funding_txid_hex: None,
        funding_vout: None,
        state: SwapState::Created,
        ..SwapRecord::new_progress()
    };
    if let Err(e) = ctx.store.put(&record) {
        return Err(anyhow!("cannot start submarine swap {swap_id}: {e}"));
    }

    if let Err(e) = ctx
        .transport
        .send(sender, &SwapMessage::SwapAccept(accept))
        .await
    {
        warn!("could not send acceptance for {swap_id}: {e}; keeping its persisted driver active for recovery");
    }
    info!(
        "Submarine swap {swap_id} started (fund {} to the HTLC)",
        swap.onchain_amount_sat
    );
    spawn_submarine_driver(ctx, swap, record, Some(reservation), Duration::ZERO);
    Ok(())
}

/// Spawn the per-swap submarine driver task (shared by fresh starts and restart-resume).
fn spawn_submarine_driver(
    ctx: &ExecCtx,
    swap: SubmarineSwap,
    record: SwapRecord,
    // Held for the driver's lifetime, so exposure is released when the task ends however it
    // ends. A driver that panics or is cancelled cannot leave capacity counted forever.
    reservation: Option<risk::ReservationGuard>,
    // How long to wait before driving, after a failure. As in the reverse direction, waited out
    // inside the task so the reservation is held across it.
    delay: Duration,
) {
    let chain = match ctx.chain.clone() {
        Some(c) => c,
        None => return,
    };
    let wallet = match ctx.wallet.clone() {
        Some(w) => w,
        None => return,
    };
    let resume = record.resume();
    let already_attempted_payment = record.invoice_pay_started_at_unix.is_some();
    let peer = record.peer.clone();
    let swap_id = record.swap_id;
    let required_confirmations = record.required_confirmations;
    let progress = Arc::new(StoreProgress {
        store: ctx.store.clone(),
        record: std::sync::Mutex::new(record),
    });
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        if !delay.is_zero() {
            sleep(delay).await;
        }
        let result = drive_submarine_swap(
            ctx2.ln.as_ref(),
            chain.as_ref(),
            wallet.as_ref(),
            &swap,
            required_confirmations,
            Duration::from_secs(2),
            &resume,
            already_attempted_payment,
            progress.as_ref(),
        )
        .await;
        finish_driver_run(
            &ctx2,
            &progress,
            &peer,
            swap_id,
            result,
            reservation,
            |ctx, rec, reservation, delay| match submarine_swap_from_record(&rec, ctx.timelock) {
                Ok(swap) => spawn_submarine_driver(ctx, swap, rec, reservation, delay),
                Err(e) => error!("cannot re-enter submarine swap {swap_id}: {e}"),
            },
        )
        .await;
    });
}

/// Reconstruct a [`ReverseSwap`] from a persisted record (resume path).
fn reverse_swap_from_record(rec: &SwapRecord, timelock: TimelockParams) -> Result<ReverseSwap> {
    validate_persisted_contract(rec)?;
    if rec.pending_hold_invoice.is_some() {
        return Err(anyhow!("reverse invoice creation is still pending"));
    }
    Ok(ReverseSwap {
        payment_hash: rec.payment_hash()?,
        onchain_amount_sat: rec.onchain_amount_sat,
        fee_rate_sat_vb: rec.fee_rate_sat_vb,
        htlc_script: rec.htlc_script()?,
        htlc_spk: rec.htlc_spk()?,
        taproot: rec.taproot.clone(),
        timeout_height: rec.timeout_height,
        refund_key: rec.secret_key()?,
        invoice: rec.invoice.clone(),
        timelock,
    })
}

/// Reconstruct a [`SubmarineSwap`] from a persisted record (resume path).
fn submarine_swap_from_record(rec: &SwapRecord, timelock: TimelockParams) -> Result<SubmarineSwap> {
    validate_persisted_contract(rec)?;
    Ok(SubmarineSwap {
        payment_hash: rec.payment_hash()?,
        onchain_amount_sat: rec.onchain_amount_sat,
        fee_rate_sat_vb: rec.fee_rate_sat_vb,
        htlc_script: rec.htlc_script()?,
        htlc_spk: rec.htlc_spk()?,
        taproot: rec.taproot.clone(),
        timeout_height: rec.timeout_height,
        claim_key: rec.secret_key()?,
        invoice: rec.invoice.clone(),
        max_routing_fee_msat: rec.max_routing_fee_msat,
        timelock,
    })
}

/// A resumed driver must use the exact contract accepted by its original counterparty.
fn validate_persisted_contract(rec: &SwapRecord) -> Result<()> {
    let Some(contract) = &rec.taproot else {
        if rec
            .swap_request
            .as_ref()
            .is_some_and(|request| request.script_type == SwapScript::TaprootBoltz)
            || rec
                .swap_accept
                .as_ref()
                .is_some_and(|accept| accept.script_type == SwapScript::TaprootBoltz)
        {
            return Err(anyhow!("Taproot record is missing its contract parameters"));
        }
        return Ok(());
    };
    let request = rec
        .swap_request
        .as_ref()
        .ok_or_else(|| anyhow!("Taproot record is missing its request"))?;
    let accept = rec
        .swap_accept
        .as_ref()
        .ok_or_else(|| anyhow!("Taproot record is missing its acceptance"))?;
    let provider_key = PublicKey::new(rec.secret_key()?.public_key(&Secp256k1::new()));
    let client_key = match rec.direction {
        SwapDirection::Submarine => request.client_refund_pubkey_hex.as_deref(),
        SwapDirection::Reverse => request.client_claim_pubkey_hex.as_deref(),
    }
    .ok_or_else(|| anyhow!("Taproot record is missing its counterparty public key"))?;
    let client_key = parse_pubkey(client_key)?;
    let (claim, refund) = match rec.direction {
        SwapDirection::Submarine => (&provider_key, &client_key),
        SwapDirection::Reverse => (&client_key, &provider_key),
    };
    let expected = swap_common::taproot::BoltzTaprootSwap::new(
        rec.direction,
        &rec.payment_hash()?,
        claim,
        refund,
        rec.timeout_height,
    )?;
    if expected != *contract
        || request.script_type != SwapScript::TaprootBoltz
        || accept.script_type != SwapScript::TaprootBoltz
        || request.direction != rec.direction
        || accept.direction != rec.direction
        || parse_hash32(&request.payment_hash_hex)? != rec.payment_hash()?
        || !pubky_transport::same_pubky(&request.client_pkarr, &rec.peer)
        || accept.quote_id != request.quote_id
        || accept.swap_id != rec.swap_id
        || accept.timeout_block_height != rec.timeout_height
        || accept.onchain_amount_sat != rec.onchain_amount_sat
        || parse_pubkey(&accept.provider_pubkey_hex)? != provider_key
        || accept.htlc_address
            != expected
                .address(rec.network.to_bitcoin_network())
                .to_string()
        || accept.swap_tree.as_ref() != Some(&expected.swap_tree())
        || !accept.htlc_script_hex.is_empty()
        || !rec.htlc_script_hex.is_empty()
        || match rec.direction {
            SwapDirection::Submarine => request.invoice.as_deref() != Some(rec.invoice.as_str()),
            SwapDirection::Reverse if rec.pending_hold_invoice.is_some() => {
                accept.invoice.is_some() || !rec.invoice.is_empty()
            }
            SwapDirection::Reverse => accept.invoice.as_deref() != Some(rec.invoice.as_str()),
        }
    {
        return Err(anyhow!(
            "persisted Taproot parameters do not match the accepted contract"
        ));
    }
    Ok(())
}

/// Spawn a background task that watches for chain reorganizations and re-validates the funding of
/// in-flight swaps. The per-swap drivers already self-heal (the submarine driver re-confirms the
/// funding depth before paying; `confirm_or_bump` re-broadcasts a reorged-out claim/refund and
/// only treats a spend as final once it is buried), so this primarily surfaces reorgs to the
/// operator and flags any funding that may have been orphaned.
fn spawn_reorg_monitor(ctx: &ExecCtx) {
    let chain = match ctx.chain.clone() {
        Some(c) => c,
        None => return,
    };
    let store = ctx.store.clone();
    tokio::spawn(async move {
        let mut monitor = swap_common::reorg::ReorgMonitor::new(REORG_CHECKPOINTS);
        let mut consecutive_failures: u32 = 0;
        loop {
            match run_blocking(|| monitor.observe(chain.as_ref())) {
                Ok(Some(fork)) => {
                    consecutive_failures = 0;
                    warn!("chain reorg detected at height {fork}; re-validating in-flight swaps");
                    // The drivers poll every two seconds, so the marker this writes is picked
                    // up almost immediately without a wake-up channel to keep in sync.
                    react_to_reorg(chain.as_ref(), store.as_ref(), fork);
                }
                Ok(None) => consecutive_failures = 0,
                Err(e) => {
                    // A monitor that cannot read the chain is a monitor that is off, and it used
                    // to say so at `debug!`: an Electrum server that had been unreachable for
                    // hours left reorg detection silently disabled. Say it once, loudly, and
                    // then stop repeating it.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    if consecutive_failures == REORG_FAILURES_BEFORE_ALARM {
                        error!(
                            "reorg detection has failed {consecutive_failures} times in a row \
                             ({e}). Until the chain backend answers again, a reorg affecting a \
                             live swap will not be noticed."
                        );
                    } else {
                        debug!("reorg monitor: {e}");
                    }
                }
            }
            sleep(REORG_POLL).await;
        }
    });
}

/// Record a reorg against every swap it could have affected, and put back anything of ours that
/// left the chain with it.
///
/// This used to end in a log line. The per-swap drivers do re-validate a great deal on their own,
/// but two things only this can do: write the fact down, so a restart in the window inherits it,
/// and re-broadcast a *funding* transaction, which no driver watches once its outpoint is known
/// and which has no fee-bump loop of its own.
fn react_to_reorg(chain: &dyn ChainWatcher, store: &dyn SwapStore, fork: u32) {
    let records = match store.load_active() {
        Ok(r) => r,
        Err(e) => {
            error!("reorg at {fork}: could not read in-flight swaps to re-validate them: {e}");
            return;
        }
    };
    for rec in records {
        let Ok(spk) = rec.htlc_spk() else { continue };
        let swap_id = rec.swap_id;

        // Write the fact down first. Everything below is a best effort against a chain that may
        // still be settling; the marker is what survives if this process does not.
        //
        // Through `mutate`, not `put`. `records` is a snapshot, and the swap's own driver is
        // running against the same store: it writes a funding intent before it broadcasts and a
        // payment intent before it pays, and those markers are the only thing stopping a resumed
        // driver doing either a second time. Putting this stale copy back would erase whichever
        // of them was written since the snapshot was taken, and this task runs on every reorg,
        // which is exactly when a driver is busiest.
        match store.mutate(swap_id, &mut |r: &mut SwapRecord| {
            r.reorg_seen_at_height = Some(match r.reorg_seen_at_height {
                Some(seen) => seen.min(fork),
                None => fork,
            });
            r.updated_at_unix = now_unix();
        }) {
            Ok(true) => {}
            // Terminal and pruned between the snapshot and now. Nothing to mark, nothing wrong.
            Ok(false) => continue,
            Err(e) => error!("reorg at {fork}: could not mark swap {swap_id}: {e}"),
        }

        let Some(op) = rec.funding_outpoint() else {
            continue;
        };
        // Classify rather than asking for an exact value. The old check used `find_funding`,
        // which matches the amount exactly and ignores depth, so an accepted overpayment always
        // reported as "gone after the reorg" and the log said "at required depth" about a
        // question it had not asked.
        let outputs = match run_blocking(|| chain.find_outputs(&spk)) {
            Ok(o) => o,
            Err(e) => {
                warn!("reorg at {fork}: could not re-read the funding of swap {swap_id}: {e}");
                continue;
            }
        };
        let still_funded = outputs
            .iter()
            .any(|u| u.outpoint == op && u.confirmations >= rec.required_confirmations);
        if still_funded {
            continue;
        }

        // The funding is not where the record says it is. The marker above is what makes that
        // actionable: a driver reading it stops treating its recorded outpoint as established and
        // goes back to the chain, which is the only thing that knows where the funding ended up.
        warn!(
            "reorg at {fork}: swap {swap_id}'s funding {op} is no longer confirmed to depth {}; \
             its driver will re-establish it from the chain rather than trust the record",
            rec.required_confirmations
        );
    }
}

/// On startup, re-spawn drivers for any swaps that were in flight at the last shutdown/crash.
async fn resume_swaps(ctx: &ExecCtx) {
    let records = match ctx.store.load_active() {
        Ok(r) => r,
        Err(e) => {
            warn!("failed to load persisted swaps: {e}");
            return;
        }
    };
    if records.is_empty() {
        return;
    }
    if !ctx.capable {
        // Refusing to start is the honest reaction here. These records may be funded HTLCs whose
        // refunds only happen if something is driving them, and a daemon that comes up
        // negotiation-only looks healthy while quietly abandoning them. Better to fail loudly
        // than to run in a state where the operator has no reason to look.
        error!(
            "{} in-flight swap(s) are persisted under the data directory, but this provider \
             cannot execute swaps (LND, Electrum, or a funding wallet is missing). Some of those \
             swaps may hold committed on-chain funds whose refund depends on being driven. \
             Refusing to start: fix the backend configuration, or move the records aside if you \
             are certain they are dead.",
            records.len()
        );
        std::process::exit(1);
    }
    // Re-establish exposure accounting before spawning anything: the money committed by these
    // swaps is committed whether or not this process has been up, and starting from zero would
    // let the provider commit its whole ceiling again on top of them.
    let accepted_records: Vec<_> = records
        .iter()
        .filter(|record| record.pending_hold_invoice.is_none())
        .cloned()
        .collect();
    let mut guards: std::collections::HashMap<Uuid, risk::ReservationGuard> = ctx
        .risk
        .restore(&accepted_records)
        .into_iter()
        .zip(accepted_records.iter().map(|r| r.swap_id))
        .map(|(g, id)| (id, g))
        .collect();
    info!("Resuming {} persisted swap(s)", records.len());
    let needing_recovery = records.iter().filter(|r| needs_recovery(r)).count();
    if needing_recovery > 0 {
        error!(
            "{needing_recovery} of them hold committed funds and were failing against a backend \
             when this daemon last ran. They are resumed, not abandoned, but they will keep \
             failing until whatever they could not reach is working."
        );
    }
    for mut rec in records {
        let swap_id = rec.swap_id;
        let mut guard = guards.remove(&swap_id);
        if rec.pending_hold_invoice.is_some() {
            match reserve_pending_swap(ctx, &rec).await {
                Ok(reservation) => guard = Some(reservation),
                Err(error) => {
                    warn!("pending swap {swap_id} must wait for capacity or liquidity: {error}");
                    continue;
                }
            }
            match complete_invoice_intent(ctx.ln.as_ref(), ctx.store.as_ref(), rec.swap_id, true)
                .await
            {
                Ok(completed) => rec = completed,
                Err(error) => {
                    warn!("cannot resume reverse invoice creation {swap_id}: {error}; its intent remains recoverable");
                    continue;
                }
            }
        }
        let delay = resume_delay(&rec);
        match rec.direction {
            SwapDirection::Reverse => match reverse_swap_from_record(&rec, ctx.timelock) {
                Ok(swap) => spawn_reverse_driver(ctx, swap, rec, guard, delay),
                Err(e) => warn!("cannot resume reverse swap {swap_id}: {e}"),
            },
            SwapDirection::Submarine => match submarine_swap_from_record(&rec, ctx.timelock) {
                Ok(swap) => spawn_submarine_driver(ctx, swap, rec, guard, delay),
                Err(e) => warn!("cannot resume submarine swap {swap_id}: {e}"),
            },
        }
    }
}

/// How long a resumed swap waits before its driver runs.
///
/// The backoff a failing swap had built up is on its record, so a restart continues it rather than
/// resetting it: an operator bouncing the daemon during an outage would otherwise put every
/// waiting swap back onto the backend at once. Capped, because the value is a wall-clock time and
/// a clock that jumped should not park a funded swap indefinitely.
fn resume_delay(rec: &SwapRecord) -> Duration {
    rec.next_retry_at_unix
        .map(|at| Duration::from_secs(at.saturating_sub(now_unix())))
        .unwrap_or_default()
        .min(recovery::BACKOFF_MAX)
}

/// Whether this swap holds committed funds and has stopped being able to make progress on them.
///
/// The threshold is the retry budget an unfunded swap gets. It is not a limit here -- a funded
/// swap is never given up on -- but it is the same evidence, and past it "a backend blipped" is no
/// longer the likely explanation.
fn needs_recovery(rec: &SwapRecord) -> bool {
    rec.funds_at_risk() && rec.retry_count >= recovery::MAX_DRIVER_RETRIES
}

/// Start accepting iroh rendezvous (doorbell) connections when enabled and built with the `iroh`
/// feature: a client that knows our pubky connects, and its authenticated pubky is added to the
/// poll set (unpinned, so eviction still applies) so the swap can proceed over pubky-DM.
#[cfg(feature = "iroh")]
fn maybe_spawn_iroh_rendezvous(ctx: &ExecCtx, config: &ProviderConfig, offer: SharedOffer) {
    if !config.rendezvous_iroh {
        return;
    }
    let identity = match config.identity() {
        Ok(i) => i,
        Err(e) => {
            warn!("iroh rendezvous disabled: {e}");
            return;
        }
    };
    let secret = match pubky_transport::identity::secret_from_recovery(
        identity.method,
        &identity.value,
        &identity.passphrase,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("iroh rendezvous disabled: {e}");
            return;
        }
    };
    let ctx = ctx.clone();
    tokio::spawn(async move {
        match pubky_transport::p2p::RendezvousServer::bind_with_sessions(secret).await {
            Ok(mut server) => {
                match server.pubky() {
                    Ok(pk) => info!("iroh rendezvous online (doorbell) as {pk}"),
                    Err(_) => info!("iroh rendezvous online (doorbell)"),
                }
                let provider = match server.pubky() {
                    Ok(key) => key,
                    Err(_) => return,
                };
                while let Some(event) = server.next_event().await {
                    match event {
                        pubky_transport::p2p::RendezvousEvent::Peer(pubky) => {
                            ctx.transport.add_known_peer(pubky)
                        }
                        pubky_transport::p2p::RendezvousEvent::Session(request) => {
                            let ctx = ctx.clone();
                            let offer = offer.clone();
                            let provider = provider.clone();
                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(60),
                                    handle_session_request(ctx, offer, provider, request),
                                )
                                .await;
                            });
                        }
                    }
                }
                warn!("iroh rendezvous accept loop ended");
            }
            Err(e) => warn!("iroh rendezvous failed to start: {e}"),
        }
    });
}

#[cfg(feature = "iroh")]
async fn handle_session_request(
    mut ctx: ExecCtx,
    offer: SharedOffer,
    provider: String,
    request: pubky_transport::p2p::SessionRpc,
) {
    let owner = match pubky_transport::session_rpc::verify_request(
        &request.request,
        &request.remote_key,
        &provider,
    )
    .await
    {
        Ok(owner) => owner,
        Err(_) => return,
    };
    let Ok(message) = serde_json::from_value::<SwapMessage>(request.request.message) else {
        return;
    };
    // Only customer requests are accepted over this protocol.
    if !matches!(
        message,
        SwapMessage::OfferRequest(_)
            | SwapMessage::QuoteRequest(_)
            | SwapMessage::SwapRequest(_)
            | SwapMessage::SwapStatusRequest(_)
    ) {
        return;
    }
    let Some(current) = offer.read().await.clone() else {
        return;
    };
    ctx.transport = Arc::new(
        ctx.transport
            .session(owner, request.request.scope, request.reply),
    );
    if handle_message(&ctx, &current, &request.remote_key, message)
        .await
        .is_err()
    {
        warn!("could not handle authorized session swap request");
    }
}

#[cfg(not(feature = "iroh"))]
fn maybe_spawn_iroh_rendezvous(_ctx: &ExecCtx, config: &ProviderConfig, _offer: SharedOffer) {
    if config.rendezvous_iroh {
        warn!("--rendezvous-iroh set but this build lacks the `iroh` feature; ignoring");
    }
}

/// Evict a peer from the poll set (and best-effort unfollow it) once it has no remaining active
/// swaps, so the provider stops polling and following counterparties after their swaps finish.
/// This keeps the poll set and the persistent follow graph bounded. A returning client must be
/// re-discovered (e.g. via DHT rendezvous) to be polled again.
async fn evict_peer_if_idle(ctx: &ExecCtx, peer: &str) {
    let still_active = match ctx.store.load_active() {
        Ok(recs) => recs.iter().any(|r| r.peer == peer),
        // On a store error, keep the peer rather than risk evicting one mid-swap.
        Err(e) => {
            warn!("could not check active swaps before evicting {peer}: {e}");
            true
        }
    };
    if still_active {
        return;
    }
    ctx.transport.evict_peer(peer).await;
    info!("Evicted peer {peer} (no active swaps remaining)");
}

/// Periodically evict idle, unpinned peers: clients that contacted us but never reached a
/// terminal swap state (e.g. requested a quote and vanished). Peers that complete a swap are
/// evicted immediately by [`evict_peer_if_idle`]; this reaper only catches abandoned ones.
/// Operator-curated follows are pinned and never idle-reaped.
fn spawn_peer_reaper(ctx: &ExecCtx, idle_ttl: Duration) {
    if idle_ttl.is_zero() {
        return;
    }
    let ctx = ctx.clone();
    tokio::spawn(async move {
        // Check periodically, bounded so a small TTL stays responsive without busy-looping.
        let interval = idle_ttl
            .min(Duration::from_secs(60))
            .max(Duration::from_secs(1));
        loop {
            sleep(interval).await;
            for peer in ctx.transport.idle_unpinned_peers(idle_ttl) {
                evict_peer_if_idle(&ctx, &peer).await;
            }
        }
    });
}

async fn notify_terminal_peer(
    ctx: &ExecCtx,
    progress: &StoreProgress,
    peer: &str,
    swap_id: Uuid,
    state: SwapState,
) {
    if progress.snapshot().peer_account.is_some() {
        return;
    }
    send_final_status(&ctx.transport, peer, swap_id, Ok(state)).await;
    evict_peer_if_idle(ctx, peer).await;
}

async fn send_final_status(
    transport: &ReplyTransport,
    peer: &str,
    swap_id: Uuid,
    result: Result<SwapState>,
) {
    let state = result.unwrap_or_else(|e| SwapState::Failed(e.to_string()));
    info!("Swap {swap_id} finished: {state:?}");
    let update = SwapStatusUpdate {
        swap_id,
        state,
        reference: None,
    };
    if let Err(e) = transport
        .send(peer, &SwapMessage::SwapStatusUpdate(update))
        .await
    {
        warn!("failed to send final status for swap {swap_id}: {e}");
    }
}

async fn reject(
    transport: &ReplyTransport,
    sender: &str,
    swap_id: Option<Uuid>,
    quote_id: Option<Uuid>,
    reason: &str,
) -> Result<()> {
    reject_request(transport, sender, None, swap_id, quote_id, reason).await
}

async fn reject_request(
    transport: &ReplyTransport,
    sender: &str,
    request_id: Option<Uuid>,
    swap_id: Option<Uuid>,
    quote_id: Option<Uuid>,
    reason: &str,
) -> Result<()> {
    reject_coded(
        transport, sender, request_id, swap_id, quote_id, reason, None,
    )
    .await
}

async fn reject_coded(
    transport: &ReplyTransport,
    sender: &str,
    request_id: Option<Uuid>,
    swap_id: Option<Uuid>,
    quote_id: Option<Uuid>,
    reason: &str,
    code: Option<&str>,
) -> Result<()> {
    transport
        .send(
            sender,
            &SwapMessage::Reject(Reject {
                code: code.map(str::to_string),
                request_id,
                swap_id,
                quote_id,
                reason: reason.to_string(),
            }),
        )
        .await?;
    Ok(())
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str).context("decode pubkey hex")?;
    PublicKey::from_slice(&bytes).context("parse public key")
}

fn parse_hash32(hex_str: &str) -> Result<PaymentHash> {
    let bytes = hex::decode(hex_str).context("decode hash hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("payment hash must be 32 bytes"))?;
    Ok(arr)
}

fn variant_name(msg: &SwapMessage) -> &'static str {
    match msg {
        SwapMessage::Offer(_) => "Offer",
        SwapMessage::OfferRequest(_) => "OfferRequest",
        SwapMessage::QuoteRequest(_) => "QuoteRequest",
        SwapMessage::Quote(_) => "Quote",
        SwapMessage::SwapRequest(_) => "SwapRequest",
        SwapMessage::SwapAccept(_) => "SwapAccept",
        SwapMessage::SwapStatusUpdate(_) => "SwapStatusUpdate",
        SwapMessage::SwapStatusRequest(_) => "SwapStatusRequest",
        SwapMessage::SwapStatusSnapshot(_) => "SwapStatusSnapshot",
        SwapMessage::CoopSignature(_) => "CoopSignature",
        SwapMessage::Reject(_) => "Reject",
    }
}

#[cfg(test)]
mod tests {

    /// One momentary Electrum failure used to delete a funded swap's record, because the driver
    /// called `store.remove` on every return including errors and every `?` in a driver
    /// propagates. No record meant no resume, which meant the refund was never attempted.
    #[test]
    fn transient_backend_failures_are_classified_as_retryable() {
        let transient: anyhow::Error =
            swap_common::SwapError::transient("electrum tip", "connection reset").into();
        assert!(is_transient(&transient));

        // Wrapped in context, as the drivers do.
        let wrapped = transient.context("tip height");
        assert!(is_transient(&wrapped));

        // A protocol violation is not retryable, and neither is an unclassified error: an error
        // nobody has thought about should not silently earn an unbounded retry loop.
        let permanent: anyhow::Error =
            swap_common::SwapError::Permanent("preimage does not match".into()).into();
        assert!(!is_transient(&permanent));
        let unclassified: anyhow::Error = swap_common::SwapError::Other("who knows".into()).into();
        assert!(!is_transient(&unclassified));
        assert!(!is_transient(&anyhow!("a bare string error")));
    }
    use super::*;

    /// A driver stuck on one step still rewrites what it already knows on every re-entry: the
    /// invoice it has already paid, and the claim it is about to broadcast. Clearing the retry
    /// metadata on those left the count at one however long the outage ran, so the backoff never
    /// grew past the first delay and `needs_recovery` never fired.
    #[test]
    fn re_recording_what_we_already_knew_does_not_reset_the_backoff() {
        use swap_common::store::{JsonFileSwapStore, SwapRecord};

        let mut rec = SwapRecord {
            direction: SwapDirection::Submarine,
            invoice_pay_started_at_unix: Some(1),
            state: SwapState::InvoicePaid,
            ..SwapRecord::new_progress()
        };
        rec.swap_id = Uuid::new_v4();
        let dir = std::env::temp_dir().join(format!("pubky-swap-backoff-{}", rec.swap_id));
        let store = JsonFileSwapStore::new(&dir).unwrap();

        let progress = StoreProgress {
            store: Arc::new(store),
            record: std::sync::Mutex::new(rec),
        };
        let txid = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<Txid>()
            .unwrap();
        for attempt in 1..=12 {
            progress.invoice_paid();
            progress.spend_broadcast(txid);
            let e: anyhow::Error =
                swap_common::SwapError::transient("broadcast", "connection reset").into();
            let (rec, recovery) = progress.record_failure(&e, true);
            assert_eq!(rec.retry_count, attempt);
            assert!(matches!(recovery, Recovery::Retry(_)));
        }
        assert!(needs_recovery(&progress.snapshot()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A provider that does not answer its doorbell can only be reached by someone it already
    /// follows, which is nobody on a fresh install.
    ///
    /// Pubky's private messages live at a path derived from an ECDH shared secret, so they are
    /// unlinkable and therefore not enumerable: `receive_all` can only poll pubkys already in the
    /// peer set, and that set comes from the follow graph. Everything the project tells a user to
    /// do, "share the pubky it prints", depends on the rendezvous being on. It was off, and the
    /// feature that implements it was not in `full`.
    #[test]
    fn a_default_provider_answers_its_doorbell() {
        assert!(
            ProviderConfig::default().rendezvous_iroh,
            "the default provider must be reachable by someone who only has its pubky"
        );
    }

    fn cfg(confs: u32, fee_floor: u64, allow_unsafe: bool) -> ProviderConfig {
        ProviderConfig {
            required_confirmations: confs,
            onchain_fee_rate_sat_vb: fee_floor,
            allow_unsafe,
            ..Default::default()
        }
    }

    #[test]
    fn mainnet_safety_allows_safe_and_non_mainnet() {
        // Regtest defaults (1 conf, 2 sat/vB) are fine off-mainnet.
        assert!(validate_mainnet_safety(&cfg(1, 2, false), Network::Regtest).is_ok());
        // Safe mainnet values pass.
        assert!(validate_mainnet_safety(&cfg(2, 5, false), Network::Bitcoin).is_ok());
    }

    #[test]
    fn mainnet_safety_rejects_unsafe_unless_overridden() {
        // Too few confirmations on mainnet.
        assert!(validate_mainnet_safety(&cfg(1, 10, false), Network::Bitcoin).is_err());
        // Fee floor too low on mainnet.
        assert!(validate_mainnet_safety(&cfg(3, 2, false), Network::Bitcoin).is_err());
        // The override permits both.
        assert!(validate_mainnet_safety(&cfg(1, 2, true), Network::Bitcoin).is_ok());
    }

    fn issued(peer: &str, direction: SwapDirection, expires_at_unix: u64) -> IssuedQuote {
        IssuedQuote {
            peer: peer.to_string(),
            direction,
            amount_sat: 100_000,
            fee_sat: 700,
            service_fee_sat: 500,
            onchain_fee_sat: 200,
            expires_at_unix,
        }
    }

    /// One quote per direction, issued to peer A.
    async fn quote_map(direction: SwapDirection) -> (Mutex<HashMap<Uuid, IssuedQuote>>, Uuid) {
        let id = Uuid::new_v4();
        let quotes = Mutex::new(HashMap::new());
        quotes.lock().await.insert(
            id,
            issued("peer-a", direction, now_unix().saturating_add(300)),
        );
        (quotes, id)
    }

    /// A quote id used to be a bearer token: whoever held it could spend it, on their own
    /// invoice and their own keys, and the rightful holder's later request found it gone.
    #[tokio::test]
    async fn a_quote_belongs_to_the_pubky_it_was_issued_to() {
        for direction in [SwapDirection::Reverse, SwapDirection::Submarine] {
            let (quotes, id) = quote_map(direction).await;

            let stolen = take_valid_quote(&quotes, id, "peer-b", direction).await;
            assert!(
                stolen.is_err(),
                "{direction:?}: another pubky must not redeem peer A's quote"
            );
            assert_eq!(
                quotes.lock().await.len(),
                1,
                "{direction:?}: the rejected attempt must not consume the quote"
            );

            let mine = take_valid_quote(&quotes, id, "peer-a", direction)
                .await
                .unwrap_or_else(|e| {
                    panic!("{direction:?}: peer A must still be able to redeem: {e}")
                });
            assert_eq!(mine.peer, "peer-a");
            assert!(
                quotes.lock().await.is_empty(),
                "{direction:?}: redeeming is single-use"
            );
            assert!(
                take_valid_quote(&quotes, id, "peer-a", direction)
                    .await
                    .is_err(),
                "{direction:?}: a spent quote cannot be replayed"
            );
        }
    }

    /// The direction check used to run after the quote had been removed, so a request naming the
    /// wrong one spent a quote that was never eligible for it.
    #[tokio::test]
    async fn a_wrong_direction_request_does_not_spend_the_quote() {
        let (quotes, id) = quote_map(SwapDirection::Reverse).await;
        assert!(
            take_valid_quote(&quotes, id, "peer-a", SwapDirection::Submarine)
                .await
                .is_err()
        );
        assert_eq!(quotes.lock().await.len(), 1);
        assert!(
            take_valid_quote(&quotes, id, "peer-a", SwapDirection::Reverse)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn expired_quotes_are_rejected_and_pruned() {
        let quotes = Mutex::new(HashMap::new());
        let (mine, stale) = (Uuid::new_v4(), Uuid::new_v4());
        {
            let mut map = quotes.lock().await;
            map.insert(mine, issued("peer-a", SwapDirection::Reverse, 1));
            map.insert(stale, issued("peer-b", SwapDirection::Reverse, 1));
        }
        assert!(
            take_valid_quote(&quotes, mine, "peer-a", SwapDirection::Reverse)
                .await
                .is_err(),
            "a quote past its expiry is not redeemable by its owner either"
        );
        assert!(
            quotes.lock().await.is_empty(),
            "every expired quote goes, not just the one asked for"
        );
    }

    /// `client_pkarr` is self-declared. Believing it over the sender the message authenticated as
    /// would put the whole point of the ownership check back in the client's hands.
    #[test]
    fn a_self_declared_pubky_must_match_the_sender() {
        assert!(check_client_pkarr("peer-a", "peer-a").is_ok());
        assert!(check_client_pkarr("peer-a", "peer-b").is_err());
        assert!(check_client_pkarr("", "peer-a").is_err());
    }

    #[test]
    fn lnd_network_mapping() {
        assert_eq!(lnd_network_to_bitcoin("mainnet"), Some(Network::Bitcoin));
        assert_eq!(lnd_network_to_bitcoin("regtest"), Some(Network::Regtest));
        assert_eq!(lnd_network_to_bitcoin("signet"), Some(Network::Signet));
        assert_eq!(lnd_network_to_bitcoin("simnet"), None);
    }
}
