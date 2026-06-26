//! Electrum-backed [`ChainWatcher`] (feature `electrum`).

use super::{ChainWatcher, FundingUtxo};
use crate::error::{Result, SwapError};
use bitcoin::{OutPoint, Script, Transaction, Txid};
use electrum_client::{Client, ElectrumApi};

pub struct ElectrumWatcher {
    client: Client,
}

impl ElectrumWatcher {
    /// Connect to an Electrum server, e.g. `tcp://127.0.0.1:50001` or `ssl://host:50002`.
    pub fn new(url: &str) -> Result<Self> {
        let client =
            Client::new(url).map_err(|e| SwapError::Other(format!("electrum connect: {e}")))?;
        Ok(Self { client })
    }
}

impl ChainWatcher for ElectrumWatcher {
    fn tip_height(&self) -> Result<u32> {
        let header = self
            .client
            .block_headers_subscribe()
            .map_err(|e| SwapError::Other(format!("electrum tip: {e}")))?;
        Ok(header.height as u32)
    }

    fn find_funding(&self, spk: &Script, expected_value_sat: u64) -> Result<Option<FundingUtxo>> {
        let utxos = self
            .client
            .script_list_unspent(spk)
            .map_err(|e| SwapError::Other(format!("electrum list_unspent: {e}")))?;
        let tip = self.tip_height()?;
        for u in utxos {
            if u.value == expected_value_sat {
                let confirmations = if u.height == 0 {
                    0
                } else {
                    tip.saturating_sub(u.height as u32).saturating_add(1)
                };
                return Ok(Some(FundingUtxo {
                    outpoint: OutPoint {
                        txid: u.tx_hash,
                        vout: u.tx_pos as u32,
                    },
                    value_sat: u.value,
                    confirmations,
                }));
            }
        }
        Ok(None)
    }

    fn find_spend(&self, spk: &Script, outpoint: &OutPoint) -> Result<Option<Transaction>> {
        let history = self
            .client
            .script_get_history(spk)
            .map_err(|e| SwapError::Other(format!("electrum history: {e}")))?;
        for entry in history {
            let tx = self
                .client
                .transaction_get(&entry.tx_hash)
                .map_err(|e| SwapError::Other(format!("electrum tx_get: {e}")))?;
            if tx.input.iter().any(|i| i.previous_output == *outpoint) {
                return Ok(Some(tx));
            }
        }
        Ok(None)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        self.client
            .transaction_broadcast(tx)
            .map_err(|e| SwapError::Other(format!("electrum broadcast: {e}")))
    }

    fn estimate_fee_rate(&self, target_blocks: u16) -> Result<Option<u64>> {
        // Electrum's `blockchain.estimatefee` returns BTC/kB (and `-1` when it has no estimate,
        // e.g. on regtest). Convert to sat/vB, yielding `None` for the unavailable sentinel.
        let btc_per_kvb = self
            .client
            .estimate_fee(target_blocks as usize)
            .map_err(|e| SwapError::Other(format!("electrum estimatefee: {e}")))?;
        Ok(crate::onchain::btc_per_kvb_to_sat_per_vb(btc_per_kvb))
    }

    fn tx_confirmations(&self, spk: &Script, txid: &Txid) -> Result<Option<u32>> {
        let history = self
            .client
            .script_get_history(spk)
            .map_err(|e| SwapError::Other(format!("electrum history: {e}")))?;
        let tip = self.tip_height()?;
        for entry in history {
            if entry.tx_hash == *txid {
                // Electrum reports height 0 for mempool, <=0 for unconfirmed-with-unconfirmed-parent.
                let confirmations = if entry.height <= 0 {
                    0
                } else {
                    tip.saturating_sub(entry.height as u32).saturating_add(1)
                };
                return Ok(Some(confirmations));
            }
        }
        Ok(None)
    }
}
