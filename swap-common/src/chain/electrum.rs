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
}
