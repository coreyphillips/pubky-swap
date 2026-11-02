//! Rebuilding this client's records from a provider's listing, for a wallet that has only its
//! seed.
//!
//! A wallet restored from its seed has no records, and a reverse swap it started may be in
//! flight: the hold invoice paid, the provider's lockup confirmed, a claim window closing.
//! `swap-list-v1` lets it ask each provider it used for every swap it owns. What a provider cannot
//! give back are the branch key and the preimage, which never left the wallet. A wallet that
//! derives them from its seed, by the index it put in `owner_ref` or by scanning around the
//! listed creation time, supplies them through a resolver. Everything it supplies is checked
//! against the listed contract before a record is written, and the record is one `resume` drives
//! like any other.
//!
//! Only reverse swaps are rebuilt. A submarine swap's refund needs the client's own invoice,
//! which the listing does not carry, so those are reported for the caller to handle.

use crate::negotiate::{Channel, Negotiator, Rejected};
use anyhow::{anyhow, Context, Result};
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use bitcoin::{Network, PublicKey, ScriptBuf};
use swap_common::htlc::{build_htlc_script, payment_hash};
use swap_common::messages::{RejectCode, SwapScript, SwapStatusSnapshot, SWAP_LIST_FEATURE};
use swap_common::store::{SwapRecord, SwapRole, SwapStore};
use swap_common::taproot::BoltzTaprootSwap;
use swap_common::validate::verify_contract;
use swap_common::{NetworkSpec, SwapDirection, SwapState};
use tracing::{info, warn};
use uuid::Uuid;

/// The secrets a wallet rebuilt for one listed swap.
pub struct RestoredKeys {
    /// The branch key only this side holds: the claim key of a reverse swap.
    pub branch_key: SecretKey,
    /// The preimage of a reverse swap.
    pub preimage: Option<[u8; 32]>,
}

/// Where restored swaps are written, and what their claims need.
pub struct Restore<'a> {
    pub store: &'a dyn SwapStore,
    pub network: Network,
    /// Where a restored reverse swap's claim pays out.
    pub dest_spk: ScriptBuf,
    /// The fee rate (sat/vB) a restored claim starts at.
    pub fee_rate_sat_vb: u64,
}

/// What a restore did with each listed swap.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Written to the store, ready for `resume`.
    pub restored: Vec<Uuid>,
    /// Already in the store, left as they were.
    pub known: Vec<Uuid>,
    /// Already terminal at the provider; nothing left to drive.
    pub finished: Vec<Uuid>,
    /// The resolver found no keys, or what it found did not match the contract.
    pub unresolved: Vec<Uuid>,
    /// A direction this restore does not rebuild (submarine).
    pub unsupported: Vec<Uuid>,
}

/// List every swap this client owns at `provider` and rebuild the ones the resolver can key.
///
/// Refused with `unsupported_protocol` when the provider's offer lacks `swap-list-v1`, before
/// any listing is attempted: an older provider would never answer one.
pub async fn restore_from_provider<P: Channel, F: Channel>(
    negotiator: &Negotiator<P, F>,
    provider: &str,
    restore: &Restore<'_>,
    resolve: impl Fn(&SwapStatusSnapshot) -> Option<RestoredKeys>,
) -> Result<RestoreReport> {
    let offer = negotiator.offer().await?;
    if !offer.features.iter().any(|f| f == SWAP_LIST_FEATURE) {
        return Err(Rejected {
            code: Some(RejectCode::UnsupportedProtocol),
            reason: format!(
                "the provider does not advertise {SWAP_LIST_FEATURE}, so it cannot list this \
                 client's swaps"
            ),
        }
        .into());
    }
    let snapshots = negotiator.list_all_swaps(false).await?;
    restore_snapshots(restore, provider, &snapshots, resolve)
}

/// Rebuild records from snapshots already in hand. `provider` is the pubky they came from.
pub fn restore_snapshots(
    restore: &Restore<'_>,
    provider: &str,
    snapshots: &[SwapStatusSnapshot],
    resolve: impl Fn(&SwapStatusSnapshot) -> Option<RestoredKeys>,
) -> Result<RestoreReport> {
    let mut report = RestoreReport::default();
    for snapshot in snapshots {
        let swap_id = snapshot.accept.swap_id;
        if restore.store.get(swap_id)?.is_some() {
            report.known.push(swap_id);
            continue;
        }
        if snapshot.state.is_terminal() {
            report.finished.push(swap_id);
            continue;
        }
        if snapshot.accept.direction != SwapDirection::Reverse {
            report.unsupported.push(swap_id);
            continue;
        }
        let Some(keys) = resolve(snapshot) else {
            report.unresolved.push(swap_id);
            continue;
        };
        match reverse_record(restore, provider, snapshot, &keys) {
            Ok(record) => {
                restore
                    .store
                    .put(&record)
                    .with_context(|| format!("persist restored swap {swap_id}"))?;
                info!(
                    "restored swap {swap_id} from {provider}: {:?}, timeout height {}",
                    record.state, record.timeout_height
                );
                report.restored.push(swap_id);
            }
            Err(error) => {
                warn!("swap {swap_id} listed by {provider} could not be rebuilt: {error}");
                report.unresolved.push(swap_id);
            }
        }
    }
    Ok(report)
}

/// The record `resume` drives, from the listing and the wallet's own secrets, once the contract
/// has been checked against both.
fn reverse_record(
    restore: &Restore<'_>,
    provider: &str,
    snapshot: &SwapStatusSnapshot,
    keys: &RestoredKeys,
) -> Result<SwapRecord> {
    let accept = &snapshot.accept;
    let preimage = keys
        .preimage
        .ok_or_else(|| anyhow!("a reverse swap needs its preimage"))?;
    let hash = payment_hash(&preimage);
    if !snapshot.payment_hash_hex.is_empty() && snapshot.payment_hash_hex != hex::encode(hash) {
        return Err(anyhow!(
            "the preimage does not hash to the listed payment hash"
        ));
    }
    let network = NetworkSpec::from_bitcoin_network(restore.network)?;
    if snapshot.network != network {
        return Err(anyhow!(
            "the swap is on {:?}, not {network:?}",
            snapshot.network
        ));
    }
    let secp = Secp256k1::new();
    let claim = PublicKey::new(SecpPublicKey::from_secret_key(&secp, &keys.branch_key));
    // Derived from our key and hash; the provider's copy of the contract is only compared.
    verify_contract(
        accept,
        SwapDirection::Reverse,
        &hash,
        &claim,
        restore.network,
    )
    .map_err(|error| anyhow!("the listed contract does not match these keys: {error}"))?;
    let provider_key: PublicKey = accept
        .provider_pubkey_hex
        .parse()
        .context("provider_pubkey_hex")?;
    let timeout = accept.timeout_block_height;
    let (htlc_script_hex, taproot) = match accept.script_type {
        SwapScript::P2wsh => (
            hex::encode(build_htlc_script(&hash, &claim, &provider_key, timeout).as_bytes()),
            None,
        ),
        SwapScript::TaprootBoltz => (
            String::new(),
            Some(BoltzTaprootSwap::new(
                SwapDirection::Reverse,
                &hash,
                &claim,
                &provider_key,
                timeout,
            )?),
        ),
    };
    let invoice = accept
        .invoice
        .clone()
        .ok_or_else(|| anyhow!("the listed acceptance has no hold invoice"))?;
    Ok(SwapRecord {
        swap_id: accept.swap_id,
        role: SwapRole::Client,
        direction: SwapDirection::Reverse,
        peer: provider.to_string(),
        network,
        payment_hash_hex: hex::encode(hash),
        secret_key_hex: hex::encode(keys.branch_key.secret_bytes()),
        preimage_hex: Some(hex::encode(preimage)),
        invoice,
        required_confirmations: snapshot.required_confirmations,
        fee_rate_sat_vb: restore.fee_rate_sat_vb,
        htlc_script_hex,
        taproot,
        timeout_height: timeout,
        onchain_amount_sat: accept.onchain_amount_sat,
        swap_accept: Some(accept.clone()),
        dest_spk_hex: Some(hex::encode(restore.dest_spk.as_bytes())),
        funding_txid_hex: snapshot.funding_txid_hex.clone(),
        funding_vout: snapshot.funding_vout,
        // A request went out, whatever this device remembers. With no saved request, `resume`
        // treats the invoice payment as possibly started and asks the node before paying.
        client_creation_started: true,
        client_execution_ready: true,
        state: restored_state(snapshot),
        created_at_unix: snapshot.created_at_unix,
        ..SwapRecord::new_progress()
    })
}

/// What this side's record says about a swap it is only now learning of.
fn restored_state(snapshot: &SwapStatusSnapshot) -> SwapState {
    if snapshot.funding_txid_hex.is_some() {
        SwapState::LockupConfirmed
    } else if snapshot.state == SwapState::Created {
        SwapState::Created
    } else {
        SwapState::InvoicePending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use swap_common::htlc::htlc_p2wsh_address;
    use swap_common::messages::SwapAccept;
    use swap_common::store::JsonFileSwapStore;
    use swap_common::{random_keypair, random_secret_key};

    struct Listed {
        snapshot: SwapStatusSnapshot,
        claim_key: SecretKey,
        preimage: [u8; 32],
    }

    /// What a provider lists for a reverse swap this client started, with the keys it would
    /// have to rebuild from its seed.
    fn listed(script_type: SwapScript, state: SwapState) -> Listed {
        let secp = Secp256k1::new();
        let (claim_key, claim) = random_keypair(&secp);
        let (_, provider) = random_keypair(&secp);
        let preimage = random_secret_key().secret_bytes();
        let hash = payment_hash(&preimage);
        let timeout = 800_144;
        let taproot = (script_type == SwapScript::TaprootBoltz).then(|| {
            BoltzTaprootSwap::new(SwapDirection::Reverse, &hash, &claim, &provider, timeout)
                .unwrap()
        });
        let script = build_htlc_script(&hash, &claim, &provider, timeout);
        let accept = SwapAccept {
            script_type,
            swap_tree: taproot.as_ref().map(BoltzTaprootSwap::swap_tree),
            quote_id: Uuid::new_v4(),
            swap_id: Uuid::new_v4(),
            direction: SwapDirection::Reverse,
            htlc_script_hex: if taproot.is_none() {
                hex::encode(script.as_bytes())
            } else {
                String::new()
            },
            htlc_address: taproot.as_ref().map_or_else(
                || htlc_p2wsh_address(&script, Network::Regtest).to_string(),
                |contract| contract.address(Network::Regtest).to_string(),
            ),
            onchain_amount_sat: 100_000,
            timeout_block_height: timeout,
            provider_pubkey_hex: hex::encode(provider.to_bytes()),
            invoice: Some("hold-invoice".into()),
        };
        Listed {
            snapshot: SwapStatusSnapshot {
                request_id: None,
                accept,
                network: NetworkSpec::Regtest,
                state,
                funding_txid_hex: None,
                funding_vout: None,
                spend_txid_hex: None,
                claim_observed_txid_hex: None,
                required_confirmations: 1,
                updated_at_unix: 5,
                observed_at_unix: 6,
                created_at_unix: 4,
                payment_hash_hex: hex::encode(hash),
                owner_ref: Some("index:3".into()),
            },
            claim_key,
            preimage,
        }
    }

    fn temp_store() -> (JsonFileSwapStore, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(format!("restore-{}", Uuid::new_v4()));
        (JsonFileSwapStore::new(&directory).unwrap(), directory)
    }

    fn restore(store: &JsonFileSwapStore) -> Restore<'_> {
        Restore {
            store,
            network: Network::Regtest,
            dest_spk: ScriptBuf::from_bytes(vec![0x00, 0x14, 7, 7, 7]),
            fee_rate_sat_vb: 3,
        }
    }

    /// #105: a listed swap whose keys the wallet can rebuild becomes a record `resume` drives,
    /// for either contract type.
    #[test]
    fn a_keyed_snapshot_becomes_a_record_resume_can_drive() {
        for script_type in [SwapScript::P2wsh, SwapScript::TaprootBoltz] {
            let (store, directory) = temp_store();
            let listed = listed(script_type, SwapState::InvoicePaid);
            let report = restore_snapshots(
                &restore(&store),
                "provider",
                std::slice::from_ref(&listed.snapshot),
                |s| {
                    (s.owner_ref.as_deref() == Some("index:3")).then_some(RestoredKeys {
                        branch_key: listed.claim_key,
                        preimage: Some(listed.preimage),
                    })
                },
            )
            .unwrap();
            assert_eq!(report.restored, vec![listed.snapshot.accept.swap_id]);

            let record = store.get(listed.snapshot.accept.swap_id).unwrap().unwrap();
            assert!(crate::store::execution_ready(&record));
            assert_eq!(record.role, SwapRole::Client);
            assert_eq!(record.peer, "provider");
            assert_eq!(record.state, SwapState::InvoicePending);
            assert_eq!(record.created_at_unix, 4);
            assert_eq!(record.preimage().unwrap(), Some(listed.preimage));
            assert_eq!(record.secret_key().unwrap(), listed.claim_key);
            assert_eq!(record.invoice, "hold-invoice");
            assert_eq!(
                record.htlc_spk().unwrap().to_hex_string(),
                bitcoin::Address::from_str(&listed.snapshot.accept.htlc_address)
                    .unwrap()
                    .assume_checked()
                    .script_pubkey()
                    .to_hex_string()
            );
            assert_eq!(record.dest_spk().unwrap(), Some(restore(&store).dest_spk));
            // `resume` treats the payment as possibly started, so it asks the node first.
            assert!(!crate::resume::reverse_resume(&record).is_fresh());
            assert_eq!(crate::store::unfinished(&store).unwrap().len(), 1);

            // Listing it again changes nothing.
            let again =
                restore_snapshots(&restore(&store), "provider", &[listed.snapshot], |_| None)
                    .unwrap();
            assert_eq!(again.known, vec![record.swap_id]);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    /// Keys that do not fit the listed contract write nothing, and so does a listing with no
    /// keys at all. Finished and submarine swaps are reported, not rebuilt.
    #[test]
    fn what_cannot_be_rebuilt_is_reported_and_never_written() {
        let (store, directory) = temp_store();
        let wrong_preimage = listed(SwapScript::P2wsh, SwapState::Created);
        let wrong_key = listed(SwapScript::P2wsh, SwapState::Created);
        let finished = listed(SwapScript::P2wsh, SwapState::Claimed);
        let mut submarine = listed(SwapScript::P2wsh, SwapState::Created);
        submarine.snapshot.accept.direction = SwapDirection::Submarine;
        let unkeyed = listed(SwapScript::P2wsh, SwapState::Created);
        let snapshots = [
            wrong_preimage.snapshot.clone(),
            wrong_key.snapshot.clone(),
            finished.snapshot.clone(),
            submarine.snapshot.clone(),
            unkeyed.snapshot.clone(),
        ];
        let report = restore_snapshots(&restore(&store), "provider", &snapshots, |s| {
            if s.accept.swap_id == wrong_preimage.snapshot.accept.swap_id {
                Some(RestoredKeys {
                    branch_key: wrong_preimage.claim_key,
                    preimage: Some([1; 32]),
                })
            } else if s.accept.swap_id == wrong_key.snapshot.accept.swap_id {
                Some(RestoredKeys {
                    branch_key: random_secret_key(),
                    preimage: Some(wrong_key.preimage),
                })
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(report.finished, vec![finished.snapshot.accept.swap_id]);
        assert_eq!(report.unsupported, vec![submarine.snapshot.accept.swap_id]);
        assert_eq!(
            report.unresolved,
            vec![
                wrong_preimage.snapshot.accept.swap_id,
                wrong_key.snapshot.accept.swap_id,
                unkeyed.snapshot.accept.swap_id,
            ]
        );
        assert!(report.restored.is_empty());
        assert!(store.load_all().unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A funded swap resumes at its lockup, and one the provider has not yet seen paid starts
    /// from the beginning.
    #[test]
    fn the_restored_state_follows_what_the_provider_has_seen() {
        let mut funded = listed(SwapScript::P2wsh, SwapState::LockupConfirmed).snapshot;
        funded.funding_txid_hex = Some("aa".repeat(32));
        assert_eq!(restored_state(&funded), SwapState::LockupConfirmed);
        let created = listed(SwapScript::P2wsh, SwapState::Created).snapshot;
        assert_eq!(restored_state(&created), SwapState::Created);
        let paid = listed(SwapScript::P2wsh, SwapState::InvoicePaid).snapshot;
        assert_eq!(restored_state(&paid), SwapState::InvoicePending);
    }
}
