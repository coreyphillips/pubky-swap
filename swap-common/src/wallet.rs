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

    /// Confirmed balance available to fund a swap, if the wallet can report one.
    ///
    /// Used as a preflight: a reverse swap creates a hold invoice, takes the client's Lightning
    /// payment, and only then tries to fund the HTLC. Discovering there is nothing to fund with
    /// at that point is the worst possible moment, because the counterparty's money is already
    /// held. `None` means "cannot say", which callers treat as "do not block on this" rather than
    /// as zero.
    fn spendable_balance_sat(&self) -> Result<Option<u64>> {
        Ok(None)
    }
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
    use bdk_electrum::electrum_client::{Client, ConfigBuilder, ElectrumApi};
    use bdk_electrum::BdkElectrumClient;
    use bdk_wallet::keys::bip39::{Language, Mnemonic};
    use bdk_wallet::keys::{DerivableKey, ExtendedKey};
    use bdk_wallet::rusqlite::Connection;
    use bdk_wallet::template::Bip84;
    use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Wallet};
    use bitcoin::{Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Txid};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// Fee-estimation confirmation target (blocks) for the HTLC funding transaction.
    const FUNDING_FEE_TARGET_BLOCKS: usize = 3;

    /// Consecutive unused addresses a full scan looks past before deciding a keychain has ended.
    ///
    /// Only ever used on a wallet with no persisted state, which for this crate means a first run
    /// or a restored mnemonic. Twenty is the usual figure and generous for a wallet that only
    /// ever funds HTLCs.
    const STOP_GAP: usize = 20;

    /// Scripts fetched per Electrum request while scanning.
    const BATCH_SIZE: usize = 10;

    /// A BIP84 (P2WPKH) wallet that funds HTLCs over Electrum.
    ///
    /// Backed by a SQLite database under the provider's data directory rather than by memory.
    /// A memory-backed wallet forgets everything on exit, which means rescanning the whole
    /// descriptor from scratch on every start, losing UTXO metadata, and -- because the address
    /// index restarts at zero -- handing out the *same* receive address for every swap, on every
    /// run, linking an operator's entire book on chain to anyone watching.
    pub struct BdkWallet {
        /// The wallet and the connection it persists through, together: every mutation has to
        /// reach disk under the same lock that made it, or an index revealed in one thread can be
        /// written by another that has since revealed a different one.
        inner: Mutex<Persisted>,
        chain: BdkElectrumClient<Client>,
        /// A separate Electrum client for fee estimation. `estimate_fee` returns the `-1` sentinel
        /// on regtest, which is not a fee rate; this asks for the raw figure and converts it
        /// through the shared guard rather than letting a rate constructor decide what to do.
        fee_client: Client,
        fee_rate_sat_vb: u64,
        /// Set until the first successful full scan.
        ///
        /// A wallet with no persisted state has never looked at the chain, and a mnemonic being
        /// restored may have a history behind it. A loaded wallet has its own checkpoint and only
        /// needs the difference.
        needs_full_scan: AtomicBool,
        /// A sweep destination resolved at construction.
        ///
        /// `receive_destination` is infallible, so it cannot derive a fresh address on demand.
        /// Callers that can take one per swap use [`BdkWallet::fresh_receive_spk`]; this is the
        /// fallback for the rest.
        receive_spk: ScriptBuf,
    }

    struct Persisted {
        wallet: PersistedWallet<Connection>,
        conn: Connection,
    }

    impl Persisted {
        /// Write the wallet's staged changes through its own connection.
        ///
        /// Split out because the two fields have to be borrowed separately, and because every
        /// mutation here has to reach disk: a revealed address index that is not written is an
        /// address handed out twice on the next run.
        fn persist(&mut self) -> Result<()> {
            let Self { wallet, conn } = self;
            wallet
                .persist(conn)
                .map_err(|e| SwapError::Other(format!("persist wallet: {e}")))?;
            Ok(())
        }
    }

    impl BdkWallet {
        /// Build a wallet from a BIP39 mnemonic, synced against `electrum_url`
        /// (e.g. `tcp://127.0.0.1:60001`).
        pub fn from_mnemonic(
            mnemonic: &str,
            network: Network,
            electrum_url: &str,
            fee_rate_sat_vb: u64,
            data_dir: &std::path::Path,
        ) -> Result<Self> {
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
                .map_err(|e| SwapError::Other(format!("mnemonic: {e}")))?;
            let xkey: ExtendedKey = mnemonic
                .into_extended_key()
                .map_err(|e| SwapError::Other(format!("extended key: {e}")))?;
            let xprv = xkey
                .into_xprv(network.into())
                .ok_or_else(|| SwapError::Other("could not derive xprv".into()))?;

            std::fs::create_dir_all(data_dir)
                .map_err(|e| SwapError::Other(format!("create wallet dir {data_dir:?}: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700));
            }
            let db_path = data_dir.join("wallet.sqlite");
            let mut conn = Connection::open(&db_path)
                .map_err(|e| SwapError::Other(format!("open {db_path:?}: {e}")))?;

            let external = Bip84(xprv, KeychainKind::External);
            let internal = Bip84(xprv, KeychainKind::Internal);

            // Load or create, in that order. `Wallet::new` used to do both at once; splitting them
            // is what makes the descriptors and the network checkable against what is already on
            // disk, so pointing an existing data directory at a different seed is an error rather
            // than a wallet that quietly sees none of its own funds.
            let loaded = Wallet::load()
                .descriptor(KeychainKind::External, Some(external.clone()))
                .descriptor(KeychainKind::Internal, Some(internal.clone()))
                .extract_keys()
                .check_network(network)
                .load_wallet(&mut conn)
                .map_err(|e| SwapError::Other(format!("load wallet from {db_path:?}: {e}")))?;

            let is_new = loaded.is_none();
            let mut wallet = match loaded {
                Some(w) => w,
                None => Wallet::create(external, internal)
                    .network(network)
                    .create_wallet(&mut conn)
                    .map_err(|e| SwapError::Other(format!("create wallet: {e}")))?,
            };

            let client = Client::from_config(
                electrum_url,
                ConfigBuilder::new().validate_domain(true).build(),
            )
            .map_err(|e| SwapError::Other(format!("electrum connect: {e}")))?;
            let chain = BdkElectrumClient::new(client);
            let fee_client = Client::new(electrum_url)
                .map_err(|e| SwapError::Other(format!("electrum connect (fee): {e}")))?;

            // Revealing an address changes the wallet, so it has to be persisted like any other
            // change: an index handed out and then forgotten is an address reused on the next run.
            let receive_spk = wallet
                .next_unused_address(KeychainKind::External)
                .script_pubkey();
            wallet
                .persist(&mut conn)
                .map_err(|e| SwapError::Other(format!("persist wallet: {e}")))?;

            Ok(Self {
                inner: Mutex::new(Persisted { wallet, conn }),
                chain,
                fee_client,
                fee_rate_sat_vb,
                needs_full_scan: AtomicBool::new(is_new),
                receive_spk,
            })
        }

        /// Lock the inner wallet, turning a poisoned lock into a clean error instead of a panic.
        fn locked(&self) -> Result<MutexGuard<'_, Persisted>> {
            self.inner
                .lock()
                .map_err(|_| SwapError::Other("wallet lock poisoned".into()))
        }

        /// Bring the wallet up to date with the chain.
        ///
        /// Two different requests, and the difference matters. A full scan walks each keychain
        /// until `STOP_GAP` consecutive unused addresses, which is what finds the history behind a
        /// restored mnemonic; a sync asks only about what the wallet has already revealed, which
        /// is all a wallet with a checkpoint needs and is far cheaper. Doing the expensive one
        /// every time would make every start proportional to the wallet's whole history.
        fn sync(&self, p: &mut Persisted) -> Result<()> {
            if self.needs_full_scan.load(Ordering::Relaxed) {
                let request = p.wallet.start_full_scan().build();
                let update = self
                    .chain
                    .full_scan(request, STOP_GAP, BATCH_SIZE, true)
                    .map_err(|e| SwapError::transient("wallet full scan", e))?;
                p.wallet
                    .apply_update(update)
                    .map_err(|e| SwapError::Other(format!("apply full scan: {e}")))?;
                self.needs_full_scan.store(false, Ordering::Relaxed);
            } else {
                let request = p.wallet.start_sync_with_revealed_spks().build();
                let update = self
                    .chain
                    .sync(request, BATCH_SIZE, true)
                    .map_err(|e| SwapError::transient("wallet sync", e))?;
                p.wallet
                    .apply_update(update)
                    .map_err(|e| SwapError::Other(format!("apply sync: {e}")))?;
            }
            p.persist()?;
            Ok(())
        }

        /// Resolve the funding fee rate: prefer a live Electrum estimate, but never drop below the
        /// configured floor. Queries the raw `estimatefee` (BTC/kB) and converts via the shared
        /// `-1`-safe helper, so the regtest sentinel falls back to the floor.
        fn resolved_fee_rate(&self) -> FeeRate {
            let estimate = self
                .fee_client
                .estimate_fee(FUNDING_FEE_TARGET_BLOCKS, None)
                .ok()
                .and_then(crate::onchain::btc_per_kvb_to_sat_per_vb);
            let sat_vb = match estimate {
                Some(estimated) if estimated > self.fee_rate_sat_vb => estimated,
                _ => self.fee_rate_sat_vb,
            };
            // `from_sat_per_vb` is `None` only on overflow, which needs a rate no mempool has ever
            // seen. Falling back to the floor there beats refusing to build a transaction.
            FeeRate::from_sat_per_vb(sat_vb)
                .or_else(|| FeeRate::from_sat_per_vb(self.fee_rate_sat_vb))
                .unwrap_or(FeeRate::BROADCAST_MIN)
        }

        /// Sync and return the total balance in sats.
        pub fn balance(&self) -> Result<u64> {
            let mut p = self.locked()?;
            self.sync(&mut p)?;
            Ok(p.wallet.balance().total().to_sat())
        }

        /// A fresh, previously-unused sweep destination.
        ///
        /// Reusing one address for every sweep links an operator's whole book on chain. The
        /// index persists, so successive calls really do advance rather than restarting at zero
        /// on each run.
        pub fn fresh_receive_spk(&self) -> Result<ScriptBuf> {
            let mut p = self.locked()?;
            let spk = p
                .wallet
                .reveal_next_address(KeychainKind::External)
                .script_pubkey();
            p.persist()?;
            Ok(spk)
        }

        /// A fresh deposit address (for funding the wallet).
        pub fn deposit_address(&self) -> Result<Address> {
            let mut p = self.locked()?;
            let address = p.wallet.reveal_next_address(KeychainKind::External).address;
            p.persist()?;
            Ok(address)
        }
    }

    impl OnchainWallet for BdkWallet {
        fn fund_htlc(&self, htlc_spk: &ScriptBuf, amount_sat: u64) -> Result<OutPoint> {
            let mut p = self.locked()?;
            self.sync(&mut p)?;

            // RBF is the default in this version of the builder, so there is no longer an
            // `enable_rbf()` to call; the signalling the fee-bump loop depends on is still there.
            let mut builder = p.wallet.build_tx();
            builder
                .add_recipient(htlc_spk.clone(), Amount::from_sat(amount_sat))
                .fee_rate(self.resolved_fee_rate());
            let mut psbt = builder
                .finish()
                .map_err(|e| SwapError::Other(format!("build_tx: {e}")))?;

            let finalized = p
                .wallet
                .sign(&mut psbt, SignOptions::default())
                .map_err(|e| SwapError::Other(format!("sign: {e}")))?;
            if !finalized {
                return Err(SwapError::Other(
                    "wallet could not fully sign the funding transaction".into(),
                ));
            }
            let tx = psbt
                .extract_tx()
                .map_err(|e| SwapError::Other(format!("extract funding tx: {e}")))?;

            // Persist before broadcasting. The wallet has spent its UTXOs and revealed a change
            // address to build this; a crash between the broadcast and the write would leave it
            // able to select the same coins again.
            p.persist()?;

            self.chain
                .inner
                .transaction_broadcast(&tx)
                .map_err(|e| SwapError::Other(format!("broadcast: {e}")))?;

            let vout = tx
                .output
                .iter()
                .position(|o| &o.script_pubkey == htlc_spk)
                .ok_or_else(|| SwapError::Other("funding output not found in built tx".into()))?
                as u32;
            Ok(OutPoint {
                txid: tx.compute_txid(),
                vout,
            })
        }

        fn spendable_balance_sat(&self) -> Result<Option<u64>> {
            // Only confirmed funds count. Unconfirmed change is not something to promise a
            // counterparty a funded HTLC against.
            let mut p = self.locked()?;
            self.sync(&mut p)?;
            Ok(Some(p.wallet.balance().confirmed.to_sat()))
        }

        fn receive_destination(&self) -> ScriptBuf {
            self.receive_spk.clone()
        }

        fn cpfp_bump(&self, parent: OutPoint, fee_rate_sat_vb: u64) -> Result<Option<Txid>> {
            let mut p = self.locked()?;
            self.sync(&mut p)?;

            // Build a child that spends ONLY the parent's swept output (which pays this wallet),
            // draining it back to a wallet address at a high fee, pulling the parent in.
            let Some(rate) = FeeRate::from_sat_per_vb(fee_rate_sat_vb) else {
                return Ok(None);
            };
            let mut builder = p.wallet.build_tx();
            builder
                .manually_selected_only()
                .add_utxo(parent)
                .map_err(|e| SwapError::Other(format!("cpfp add_utxo: {e}")))?
                .drain_to(self.receive_spk.clone())
                .fee_rate(rate);
            let mut psbt = builder
                .finish()
                .map_err(|e| SwapError::Other(format!("cpfp build_tx: {e}")))?;

            let finalized = p
                .wallet
                .sign(&mut psbt, SignOptions::default())
                .map_err(|e| SwapError::Other(format!("cpfp sign: {e}")))?;
            if !finalized {
                return Ok(None);
            }
            let tx = psbt
                .extract_tx()
                .map_err(|e| SwapError::Other(format!("extract cpfp tx: {e}")))?;
            p.persist()?;
            self.chain
                .inner
                .transaction_broadcast(&tx)
                .map_err(|e| SwapError::Other(format!("cpfp broadcast: {e}")))?;
            Ok(Some(tx.compute_txid()))
        }
    }
}

#[cfg(feature = "bdk-wallet")]
pub use bdk_impl::BdkWallet;
