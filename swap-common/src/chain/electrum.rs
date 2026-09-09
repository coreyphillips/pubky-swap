//! Electrum-backed [`ChainWatcher`] (feature `electrum`).
//!
//! Two things shape this beyond wrapping the RPCs.
//!
//! **Every failure is [`SwapError::Transient`].** A server that is unreachable, slow, or
//! mid-reindex is the normal case over the hours a swap runs, not a reason to abandon one. The
//! drivers rely on that classification to retry rather than discard a record, and a discarded
//! record for a funded HTLC is a refund that never happens.
//!
//! **The connection is expected to break.** `Client::new` gives no timeout, no retry, and no
//! reconnection, so a dropped socket used to turn every subsequent call into an error for the
//! lifetime of the process. Calls now route through [`ElectrumWatcher::call`], which retries with
//! backoff and rebuilds the client when the failure looks like a dead connection.

use super::{ChainWatcher, FundingUtxo, HistoricalOutput};
use crate::error::{Result, SwapError};
use bitcoin::{BlockHash, OutPoint, Script, Transaction, Txid};
use electrum_client::{Client, ConfigBuilder, ElectrumApi, Socks5Config};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::Duration;
use tracing::{debug, warn};

/// How the Electrum connection is made.
#[derive(Debug, Clone)]
pub struct ElectrumConfig {
    /// `tcp://host:port` or `ssl://host:port`. A bare `host:port` is treated as `tcp://`.
    pub url: String,
    /// SOCKS5 proxy, e.g. `127.0.0.1:9050` for Tor. Required to reach a `.onion` server.
    pub socks5: Option<String>,
    /// Per-call socket timeout.
    pub timeout_secs: u8,
    /// Retries inside the Electrum client itself.
    pub client_retries: u8,
    /// Attempts this wrapper makes, rebuilding the client between them.
    pub call_attempts: u32,
    /// Whether to validate the TLS domain on `ssl://`. Automatically off for `.onion`, whose
    /// certificates have no domain to validate.
    pub validate_domain: bool,
}

impl ElectrumConfig {
    pub fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        let onion = url.contains(".onion");
        Self {
            url,
            socks5: None,
            timeout_secs: 30,
            client_retries: 2,
            call_attempts: 4,
            validate_domain: !onion,
        }
    }

    pub fn with_socks5(mut self, proxy: Option<String>) -> Self {
        self.socks5 = proxy;
        self
    }

    fn build_client(&self) -> Result<Client> {
        let mut builder = ConfigBuilder::new()
            .timeout(Some(self.timeout_secs))
            .retry(self.client_retries)
            .validate_domain(self.validate_domain);
        if let Some(proxy) = &self.socks5 {
            builder = builder.socks5(Some(Socks5Config::new(proxy)));
        }
        Client::from_config(&self.url, builder.build())
            .map_err(|e| SwapError::transient("electrum connect", e))
    }
}

pub struct ElectrumWatcher {
    config: ElectrumConfig,
    client: RwLock<Client>,
    /// Transactions already fetched, keyed by txid.
    ///
    /// `find_spend` walks an address's history and fetches each transaction to see which one
    /// spends our outpoint, and the drivers call it every two seconds per swap. Without a cache
    /// that is O(history) fetches per second per swap against a server that is usually shared and
    /// often rate-limited. Confirmed transactions never change, so caching them is free.
    tx_cache: Mutex<HashMap<Txid, Transaction>>,
}

/// Bound on the transaction cache. An HTLC address sees a handful of transactions in its life, so
/// this is generous; it exists so a long-running provider cannot grow without limit.
const TX_CACHE_LIMIT: usize = 4_096;

impl ElectrumWatcher {
    /// Connect with default settings. `url` is e.g. `tcp://127.0.0.1:50001` or `ssl://host:50002`.
    pub fn new(url: &str) -> Result<Self> {
        Self::connect(ElectrumConfig::new(url))
    }

    pub fn connect(config: ElectrumConfig) -> Result<Self> {
        let client = config.build_client()?;
        Ok(Self {
            config,
            client: RwLock::new(client),
            tx_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Run an Electrum call, retrying with backoff and rebuilding the connection when it looks
    /// dead.
    ///
    /// The client's own `retry` setting handles a request that fails; it cannot handle a socket
    /// that has gone away, because that needs a new client. Both happen over the hours a swap
    /// runs.
    fn call<T>(
        &self,
        what: &'static str,
        f: impl Fn(&Client) -> std::result::Result<T, electrum_client::Error>,
    ) -> Result<T> {
        let mut backoff = Duration::from_millis(250);
        let mut last: Option<electrum_client::Error> = None;

        for attempt in 1..=self.config.call_attempts {
            let result = {
                let guard = self
                    .client
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                f(&guard)
            };
            match result {
                Ok(v) => return Ok(v),
                Err(e) => {
                    debug!("electrum {what} failed (attempt {attempt}): {e}");
                    let reconnect = looks_like_a_dead_connection(&e);
                    last = Some(e);
                    if attempt == self.config.call_attempts {
                        break;
                    }
                    if reconnect {
                        self.reconnect(what);
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(4));
                }
            }
        }
        Err(SwapError::transient(
            what,
            last.map(|e| e.to_string())
                .unwrap_or_else(|| "no attempts made".into()),
        ))
    }

    fn reconnect(&self, what: &'static str) {
        match self.config.build_client() {
            Ok(fresh) => {
                let mut guard = self
                    .client
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *guard = fresh;
                debug!("reconnected to {} after {what}", self.config.url);
            }
            Err(e) => warn!("could not reconnect to {}: {e}", self.config.url),
        }
    }

    /// Fetch a transaction, using the cache for ones already seen.
    fn transaction(&self, txid: &Txid) -> Result<Transaction> {
        if let Some(tx) = self
            .tx_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(txid)
        {
            return Ok(tx.clone());
        }
        let tx = self.call("tx_get", |c| c.transaction_get(txid))?;
        let mut cache = self.tx_cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= TX_CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(*txid, tx.clone());
        Ok(tx)
    }

    fn confirmations_from_height(&self, height: i32, tip: u32) -> u32 {
        if height <= 0 {
            0
        } else {
            tip.saturating_sub(height as u32).saturating_add(1)
        }
    }
}

/// Whether an error means the connection is gone rather than the request being bad.
///
/// Erring toward reconnecting is cheap; erring the other way strands a driver on a dead socket.
fn looks_like_a_dead_connection(e: &electrum_client::Error) -> bool {
    matches!(
        e,
        electrum_client::Error::IOError(_)
            | electrum_client::Error::CouldntLockReader
            | electrum_client::Error::SharedIOError(_)
    )
}

impl ChainWatcher for ElectrumWatcher {
    fn tip_height(&self) -> Result<u32> {
        let header = self.call("tip", |c| c.block_headers_subscribe())?;
        u32::try_from(header.height)
            .map_err(|_| SwapError::Permanent(format!("absurd tip height {}", header.height)))
    }

    fn find_funding(&self, spk: &Script, expected_value_sat: u64) -> Result<Option<FundingUtxo>> {
        Ok(self
            .find_outputs(spk)?
            .into_iter()
            .find(|u| u.value_sat == expected_value_sat))
    }

    fn find_outputs(&self, spk: &Script) -> Result<Vec<FundingUtxo>> {
        let utxos = self.call("list_unspent", |c| c.script_list_unspent(spk))?;
        let tip = self.tip_height()?;
        Ok(utxos
            .into_iter()
            .map(|u| FundingUtxo {
                outpoint: OutPoint {
                    txid: u.tx_hash,
                    vout: u.tx_pos as u32,
                },
                value_sat: u.value,
                confirmations: self.confirmations_from_height(u.height as i32, tip),
            })
            .collect())
    }

    fn find_historical_outputs(&self, spk: &Script) -> Result<Vec<HistoricalOutput>> {
        let history = self.call("history", |c| c.script_get_history(spk))?;
        let tip = self.tip_height()?;

        // Two passes over the same transactions: the first collects every output that paid this
        // script, the second asks which of them something has since spent. Both come from the one
        // history call, so a spend and the funding it consumed are always read from the same view
        // of the chain rather than two that could disagree.
        let mut txs = Vec::with_capacity(history.len());
        for entry in &history {
            txs.push((self.transaction(&entry.tx_hash)?, entry.height));
        }

        let mut outputs = Vec::new();
        for (tx, height) in &txs {
            let txid = tx.txid();
            for (vout, out) in tx.output.iter().enumerate() {
                if out.script_pubkey.as_script() != spk {
                    continue;
                }
                outputs.push(HistoricalOutput {
                    outpoint: OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    value_sat: out.value,
                    confirmations: self.confirmations_from_height(*height, tip),
                    spent_by: None,
                });
            }
        }

        for (tx, _) in &txs {
            for input in &tx.input {
                if let Some(o) = outputs
                    .iter_mut()
                    .find(|o| o.outpoint == input.previous_output)
                {
                    o.spent_by = Some(tx.txid());
                }
            }
        }

        Ok(outputs)
    }

    fn outpoint_status(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<FundingUtxo>> {
        Ok(self
            .find_outputs(spk)?
            .into_iter()
            .find(|u| &u.outpoint == outpoint))
    }

    fn find_spend(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<Transaction>> {
        let history = self.call("history", |c| c.script_get_history(spk))?;
        // Newest first: a spend is more likely to be recent than the funding that preceded it.
        for entry in history.into_iter().rev() {
            // The funding transaction itself pays this script but does not spend our outpoint,
            // so skip it without a fetch when we already know its txid.
            if entry.tx_hash == outpoint.txid {
                continue;
            }
            let tx = self.transaction(&entry.tx_hash)?;
            if tx.input.iter().any(|i| i.previous_output == *outpoint) {
                return Ok(Some(tx));
            }
        }
        Ok(None)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        // Deliberately not retried through `call`: a rejection is an answer, and repeating a
        // broadcast the node has already refused only delays finding that out.
        let guard = self
            .client
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .transaction_broadcast(tx)
            .map_err(|e| SwapError::transient("electrum broadcast", e))
    }

    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>> {
        // Electrum's `blockchain.estimatefee` returns BTC/kB (and `-1` when it has no estimate,
        // e.g. on regtest). Convert to sat/vB, yielding `None` for the unavailable sentinel.
        let btc_per_kvb = self.call("estimatefee", |c| c.estimate_fee(target_blocks as usize))?;
        Ok(crate::onchain::btc_per_kvb_to_sat_per_vb(btc_per_kvb))
    }

    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>> {
        let tip = self.tip_height()?;
        if height > tip {
            return Ok(None);
        }
        let header = self.call("block_header", |c| c.block_header(height as usize))?;
        Ok(Some(header.block_hash()))
    }

    fn tx_confirmations(&self, spk: &Script, txid: &Txid) -> Result<Option<u32>> {
        let history = self.call("history", |c| c.script_get_history(spk))?;
        let tip = self.tip_height()?;
        for entry in history {
            if entry.tx_hash == *txid {
                return Ok(Some(self.confirmations_from_height(entry.height, tip)));
            }
        }
        Ok(None)
    }

    fn health_check(&self) -> Result<()> {
        self.tip_height().map(|_| ())
    }
}
