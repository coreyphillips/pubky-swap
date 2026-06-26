//! On-chain funding wallet: the capability a swap party needs to lock funds into an HTLC and to
//! receive swept funds. A reverse-swap **provider** funds the HTLC it offers; a submarine-swap
//! **client** funds the HTLC the provider will claim. The [`OnchainWallet`] trait is always
//! available; a BDK-backed implementation is provided behind the `bdk-wallet` feature.

use crate::error::Result;
use bitcoin::{OutPoint, ScriptBuf, Txid};

/// A wallet that can fund HTLCs and supply a sweep destination.
pub trait OnchainWallet: Send + Sync {
    /// Build, sign, and broadcast a transaction paying `amount_sat` to `htlc_spk`, returning the
    /// funding outpoint.
    fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint>;
    /// A wallet-controlled scriptPubKey for swept funds (a reverse-swap refund or submarine-swap
    /// claim destination).
    fn receive_destination(&self) -> ScriptBuf;
    /// Best-effort **child-pays-for-parent**: spend `parent` (a stuck claim/refund output that
    /// pays this wallet) with a high-fee child at `fee_rate_sat_vb`, pulling the parent in. Used as
    /// a fallback when an RBF replacement can't be broadcast. Returns the child txid, or `Ok(None)`
    /// if unsupported (the default) — e.g. when the swept output isn't wallet-controlled.
    fn cpfp_bump(&self, parent: OutPoint, fee_rate_sat_vb: u64) -> Result<Option<Txid>> {
        let _ = (parent, fee_rate_sat_vb);
        Ok(None)
    }
}

#[cfg(feature = "bdk-wallet")]
mod bdk_impl {
    use super::OnchainWallet;
    use crate::error::{Result, SwapError};
    use bdk::blockchain::{Blockchain, ElectrumBlockchain};
    use bdk::database::MemoryDatabase;
    use bdk::electrum_client::Client;
    use bdk::keys::bip39::{Language, Mnemonic};
    use bdk::keys::{DerivableKey, ExtendedKey};
    use bdk::template::Bip84;
    use bdk::wallet::AddressIndex;
    use bdk::{FeeRate, KeychainKind, SignOptions, SyncOptions, Wallet};
    use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid};
    use std::sync::{Mutex, MutexGuard};

    /// Fee-estimation confirmation target (blocks) for the HTLC funding transaction.
    const FUNDING_FEE_TARGET_BLOCKS: usize = 3;

    /// A BIP84 (P2WPKH) wallet that funds HTLCs over Electrum.
    pub struct BdkWallet {
        wallet: Mutex<Wallet<MemoryDatabase>>,
        blockchain: ElectrumBlockchain,
        fee_rate_sat_vb: f32,
        /// Cached wallet-controlled sweep address (refund/claim destination).
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
                .map_err(|e| SwapError::Other(format!("mnemonic: {e}")))?;
            let xkey: ExtendedKey = mnemonic
                .into_extended_key()
                .map_err(|e| SwapError::Other(format!("extended key: {e}")))?;
            let xprv = xkey
                .into_xprv(network)
                .ok_or_else(|| SwapError::Other("could not derive xprv".into()))?;

            let wallet = Wallet::new(
                Bip84(xprv, KeychainKind::External),
                Some(Bip84(xprv, KeychainKind::Internal)),
                network,
                MemoryDatabase::default(),
            )
            .map_err(|e| SwapError::Other(format!("wallet: {e}")))?;

            let client = Client::new(electrum_url)
                .map_err(|e| SwapError::Other(format!("electrum connect: {e}")))?;
            let blockchain = ElectrumBlockchain::from(client);

            let receive_spk = wallet
                .get_address(AddressIndex::New)
                .map_err(|e| SwapError::Other(format!("receive address: {e}")))?
                .script_pubkey();

            Ok(Self {
                wallet: Mutex::new(wallet),
                blockchain,
                fee_rate_sat_vb,
                receive_spk,
            })
        }

        /// Lock the inner wallet, turning a poisoned lock into a clean error instead of a panic.
        fn locked(&self) -> Result<MutexGuard<'_, Wallet<MemoryDatabase>>> {
            self.wallet
                .lock()
                .map_err(|_| SwapError::Other("wallet lock poisoned".into()))
        }

        /// Resolve the funding fee rate: prefer a live Electrum estimate, but never drop below the
        /// configured floor. bdk's `ElectrumBlockchain::estimate_fee` does not guard the `-1`
        /// regtest sentinel (it yields a negative `FeeRate`), so only accept an estimate above the
        /// floor.
        fn resolved_fee_rate(&self) -> FeeRate {
            let floor = FeeRate::from_sat_per_vb(self.fee_rate_sat_vb);
            match self.blockchain.estimate_fee(FUNDING_FEE_TARGET_BLOCKS) {
                Ok(est) if est.as_sat_per_vb() > self.fee_rate_sat_vb => est,
                _ => floor,
            }
        }

        /// Sync and return the total balance in sats.
        pub fn balance(&self) -> Result<u64> {
            let w = self.locked()?;
            w.sync(&self.blockchain, SyncOptions::default())
                .map_err(|e| SwapError::Other(format!("sync: {e}")))?;
            let b = w
                .get_balance()
                .map_err(|e| SwapError::Other(format!("balance: {e}")))?;
            Ok(b.confirmed + b.immature + b.trusted_pending + b.untrusted_pending)
        }

        /// A fresh deposit address (for funding the wallet).
        pub fn deposit_address(&self) -> Result<Address> {
            let w = self.locked()?;
            Ok(w.get_address(AddressIndex::New)
                .map_err(|e| SwapError::Other(format!("deposit address: {e}")))?
                .address)
        }
    }

    impl OnchainWallet for BdkWallet {
        fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint> {
            let w = self.locked()?;
            w.sync(&self.blockchain, SyncOptions::default())
                .map_err(|e| SwapError::Other(format!("sync: {e}")))?;

            let mut builder = w.build_tx();
            builder
                .add_recipient(htlc_spk.clone(), amount_sat)
                .enable_rbf()
                .fee_rate(self.resolved_fee_rate());
            let (mut psbt, _details) = builder
                .finish()
                .map_err(|e| SwapError::Other(format!("build_tx: {e}")))?;

            let finalized = w
                .sign(&mut psbt, SignOptions::default())
                .map_err(|e| SwapError::Other(format!("sign: {e}")))?;
            if !finalized {
                return Err(SwapError::Other(
                    "wallet could not fully sign the funding transaction".into(),
                ));
            }
            let tx = psbt.extract_tx();
            self.blockchain
                .broadcast(&tx)
                .map_err(|e| SwapError::Other(format!("broadcast: {e}")))?;

            let vout = tx
                .output
                .iter()
                .position(|o| &o.script_pubkey == htlc_spk)
                .ok_or_else(|| SwapError::Other("funding output not found in built tx".into()))?
                as u32;
            Ok(OutPoint {
                txid: tx.txid(),
                vout,
            })
        }

        fn receive_destination(&self) -> ScriptBuf {
            self.receive_spk.clone()
        }

        fn cpfp_bump(&self, parent: OutPoint, fee_rate_sat_vb: u64) -> Result<Option<Txid>> {
            let w = self.locked()?;
            w.sync(&self.blockchain, SyncOptions::default())
                .map_err(|e| SwapError::Other(format!("sync: {e}")))?;

            // Build a child that spends ONLY the parent's swept output (which pays this wallet),
            // draining it back to a wallet address at a high fee — pulling the parent in.
            let mut builder = w.build_tx();
            builder
                .manually_selected_only()
                .add_utxo(parent)
                .map_err(|e| SwapError::Other(format!("cpfp add_utxo: {e}")))?
                .drain_to(self.receive_spk.clone())
                .enable_rbf()
                .fee_rate(FeeRate::from_sat_per_vb(fee_rate_sat_vb as f32));
            let (mut psbt, _details) = builder
                .finish()
                .map_err(|e| SwapError::Other(format!("cpfp build_tx: {e}")))?;

            let finalized = w
                .sign(&mut psbt, SignOptions::default())
                .map_err(|e| SwapError::Other(format!("cpfp sign: {e}")))?;
            if !finalized {
                return Ok(None);
            }
            let tx = psbt.extract_tx();
            self.blockchain
                .broadcast(&tx)
                .map_err(|e| SwapError::Other(format!("cpfp broadcast: {e}")))?;
            Ok(Some(tx.txid()))
        }
    }
}

#[cfg(feature = "bdk-wallet")]
pub use bdk_impl::BdkWallet;
