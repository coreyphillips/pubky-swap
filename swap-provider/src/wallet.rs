//! A BDK-backed [`OnchainWallet`] (feature `bdk-wallet`).
//!
//! Provides the on-chain funding capability a reverse-swap provider needs: build, sign, and
//! broadcast a transaction paying the HTLC P2WSH, and supply a sweep address. Uses a BIP84
//! (P2WPKH) wallet synced over Electrum.

use crate::reverse::OnchainWallet;
use anyhow::{anyhow, Result};
use bdk::blockchain::{Blockchain, ElectrumBlockchain};
use bdk::database::MemoryDatabase;
use bdk::electrum_client::Client;
use bdk::keys::bip39::{Language, Mnemonic};
use bdk::keys::{DerivableKey, ExtendedKey};
use bdk::template::Bip84;
use bdk::wallet::AddressIndex;
use bdk::{FeeRate, KeychainKind, SignOptions, SyncOptions, Wallet};
use bitcoin::{Address, Network, OutPoint, ScriptBuf};
use std::sync::Mutex;

/// A BIP84 wallet that funds HTLCs over Electrum.
pub struct BdkWallet {
    wallet: Mutex<Wallet<MemoryDatabase>>,
    blockchain: ElectrumBlockchain,
    fee_rate_sat_vb: f32,
    /// Cached provider-controlled sweep address (refund/claim destination).
    receive_spk: ScriptBuf,
}

impl BdkWallet {
    /// Build a wallet from a BIP39 mnemonic, synced against `electrum_url`
    /// (e.g. `tcp://127.0.0.1:60001`).
    pub fn from_mnemonic(
        mnemonic: &str,
        network: Network,
        electrum_url: &str,
        fee_rate_sat_vb: f32,
    ) -> Result<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| anyhow!("mnemonic: {e}"))?;
        let xkey: ExtendedKey = mnemonic
            .into_extended_key()
            .map_err(|e| anyhow!("extended key: {e}"))?;
        let xprv = xkey
            .into_xprv(network)
            .ok_or_else(|| anyhow!("could not derive xprv"))?;

        let wallet = Wallet::new(
            Bip84(xprv, KeychainKind::External),
            Some(Bip84(xprv, KeychainKind::Internal)),
            network,
            MemoryDatabase::default(),
        )
        .map_err(|e| anyhow!("wallet: {e}"))?;

        let client = Client::new(electrum_url).map_err(|e| anyhow!("electrum connect: {e}"))?;
        let blockchain = ElectrumBlockchain::from(client);

        let receive_spk = wallet
            .get_address(AddressIndex::New)
            .map_err(|e| anyhow!("receive address: {e}"))?
            .script_pubkey();

        Ok(Self {
            wallet: Mutex::new(wallet),
            blockchain,
            fee_rate_sat_vb,
            receive_spk,
        })
    }

    /// Sync and return the total balance in sats.
    pub fn balance(&self) -> Result<u64> {
        let w = self.wallet.lock().unwrap();
        w.sync(&self.blockchain, SyncOptions::default())
            .map_err(|e| anyhow!("sync: {e}"))?;
        let b = w.get_balance().map_err(|e| anyhow!("balance: {e}"))?;
        Ok(b.confirmed + b.immature + b.trusted_pending + b.untrusted_pending)
    }

    /// A fresh deposit address (for funding the wallet).
    pub fn deposit_address(&self) -> Result<Address> {
        let w = self.wallet.lock().unwrap();
        Ok(w.get_address(AddressIndex::New)
            .map_err(|e| anyhow!("deposit address: {e}"))?
            .address)
    }
}

impl OnchainWallet for BdkWallet {
    fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint> {
        let w = self.wallet.lock().unwrap();
        w.sync(&self.blockchain, SyncOptions::default())
            .map_err(|e| anyhow!("sync: {e}"))?;

        let mut builder = w.build_tx();
        builder
            .add_recipient(htlc_spk.clone(), amount_sat)
            .enable_rbf()
            .fee_rate(FeeRate::from_sat_per_vb(self.fee_rate_sat_vb));
        let (mut psbt, _details) = builder.finish().map_err(|e| anyhow!("build_tx: {e}"))?;

        let finalized = w
            .sign(&mut psbt, SignOptions::default())
            .map_err(|e| anyhow!("sign: {e}"))?;
        if !finalized {
            return Err(anyhow!(
                "wallet could not fully sign the funding transaction"
            ));
        }
        let tx = psbt.extract_tx();
        self.blockchain
            .broadcast(&tx)
            .map_err(|e| anyhow!("broadcast: {e}"))?;

        let vout =
            tx.output
                .iter()
                .position(|o| &o.script_pubkey == htlc_spk)
                .ok_or_else(|| anyhow!("funding output not found in built tx"))? as u32;
        Ok(OutPoint {
            txid: tx.txid(),
            vout,
        })
    }

    fn receive_destination(&self) -> ScriptBuf {
        self.receive_spk.clone()
    }
}
