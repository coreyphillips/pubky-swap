//! A reverse swap finished by a client that lost its records mid-swap and rebuilt them from the
//! provider's listing (#105), across two real LND nodes + bitcoind + electrs.
//!
//! The first client pays the hold invoice and vanishes. Once the provider has funded the lockup,
//! a second client with only the keys it can derive (here, handed over by the test as a wallet
//! would derive them from its seed) restores the swap from what the provider lists, resumes it,
//! and claims. `#[ignore]`d; run as `full_swap_regtest` is.

#![cfg(all(feature = "lnd", feature = "bdk-wallet", feature = "chain"))]

use bitcoin::{Address, Network, ScriptBuf};
use lightning_backend::{InvoiceState, LightningBackend, LndBackend, LndConfig};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use swap_client::restore::{restore_snapshots, Restore, RestoredKeys};
use swap_client::resume::resume_unfinished;
use swap_common::chain::{ChainWatcher, ElectrumWatcher};
use swap_common::htlc::{generate_preimage, payment_hash};
use swap_common::messages::{SwapAccept, SwapRequest, SwapScript};
use swap_common::store::{JsonFileSwapStore, SwapRecord, SwapStore};
use swap_common::timelock::TimelockParams;
use swap_common::{random_keypair, NetworkSpec, SwapDirection, SwapState};
use swap_provider::reverse::{drive_reverse_swap, init_reverse_swap, OnchainWallet, Resume};
use swap_provider::wallet::BdkWallet;

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("pubky-swap-{prefix}-{}", uuid::Uuid::new_v4()))
}
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT_SAT: u64 = 50_000;
const PROVIDER_FEE_SAT: u64 = 1_000;

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

fn cli(args: &[&str]) -> String {
    let mut full = vec![
        "exec".to_string(),
        env("REGTEST_BTC_CONTAINER", "bitcoin"),
        "bitcoin-cli".to_string(),
        "-regtest".to_string(),
        "-rpcport=43782".to_string(),
        "-rpcuser=polaruser".to_string(),
        "-rpcpassword=polarpass".to_string(),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = Command::new("docker")
        .args(&full)
        .output()
        .expect("docker exec");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn mine(n: u32) {
    let addr = cli(&["getnewaddress", "", "bech32"]);
    cli(&["generatetoaddress", &n.to_string(), &addr]);
}

fn spk_of(addr: &str) -> ScriptBuf {
    Address::from_str(addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey()
}

fn lnd_cfg(prefix: &str) -> LndConfig {
    LndConfig {
        address: std::env::var(format!("LND_{prefix}_URL")).expect("LND url env"),
        tls_cert_path: std::env::var(format!("LND_{prefix}_CERT")).expect("LND cert env"),
        macaroon_path: std::env::var(format!("LND_{prefix}_MAC")).expect("LND macaroon env"),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs"]
async fn a_client_restored_from_the_listing_claims_a_reverse_swap() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let electrum = env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001");
    let provider_ln: Arc<dyn LightningBackend> = Arc::new(
        LndBackend::connect(lnd_cfg("A"))
            .await
            .expect("connect provider LND"),
    );
    let client_ln: Arc<dyn LightningBackend> = Arc::new(
        LndBackend::connect(lnd_cfg("B"))
            .await
            .expect("connect client LND"),
    );
    let chain_p: Arc<dyn ChainWatcher> = Arc::new(ElectrumWatcher::new(&electrum).unwrap());
    let chain_c: Arc<dyn ChainWatcher> = Arc::new(ElectrumWatcher::new(&electrum).unwrap());
    let wallet: Arc<dyn OnchainWallet> = if env("WALLET_BACKEND", "bdk") == "lnd" {
        Arc::new(
            lightning_backend::LndWallet::connect(lnd_cfg("A"), 5)
                .await
                .expect("connect LND on-chain wallet"),
        )
    } else {
        let bdk = BdkWallet::from_mnemonic(
            &env("WALLET_MNEMONIC", MNEMONIC),
            Network::Regtest,
            &electrum,
            5,
            &temp_dir("restore-wallet"),
        )
        .expect("build funding wallet");
        if bdk.balance().unwrap() < AMOUNT_SAT + 50_000 {
            let deposit = bdk.deposit_address().unwrap().to_string();
            cli(&["sendtoaddress", &deposit, "0.5"]);
            mine(1);
            for _ in 0..30 {
                if bdk.balance().unwrap() >= AMOUNT_SAT + 50_000 {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Arc::new(bdk)
    };

    // The keys a wallet derives from its seed, and the preimage it keeps for the swap.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (client_claim_sk, client_claim_pk) = random_keypair(&secp);
    let (refund_sk, refund_pk) = random_keypair(&secp);
    let preimage = generate_preimage();
    let ph = payment_hash(&preimage);
    let timelock = TimelockParams {
        htlc_timeout_blocks: 200,
        required_confirmations: 1,
        ..TimelockParams::default()
    };
    let timeout = chain_p.tip_height().unwrap() + timelock.htlc_timeout_blocks;

    // Provider: the hold invoice and the contract.
    let swap = init_reverse_swap(
        provider_ln.as_ref(),
        &client_claim_pk,
        refund_sk,
        &refund_pk,
        ph,
        AMOUNT_SAT,
        PROVIDER_FEE_SAT,
        2,
        timeout,
        3600,
        Network::Regtest,
        timelock,
    )
    .await
    .expect("init reverse swap");

    // What the provider wrote down, and therefore what it lists for this owner.
    let swap_id = uuid::Uuid::new_v4();
    let accept = SwapAccept {
        script_type: SwapScript::P2wsh,
        swap_tree: None,
        quote_id: uuid::Uuid::new_v4(),
        swap_id,
        direction: SwapDirection::Reverse,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        htlc_address: Address::from_script(&swap.htlc_spk, Network::Regtest)
            .unwrap()
            .to_string(),
        onchain_amount_sat: swap.onchain_amount_sat,
        timeout_block_height: timeout,
        provider_pubkey_hex: hex::encode(refund_pk.to_bytes()),
        invoice: Some(swap.invoice.clone()),
    };
    let provider_record = SwapRecord {
        swap_id,
        swap_request: Some(SwapRequest {
            script_type: SwapScript::P2wsh,
            quote_id: accept.quote_id,
            client_pkarr: "client".into(),
            direction: SwapDirection::Reverse,
            payment_hash_hex: hex::encode(ph),
            client_claim_pubkey_hex: Some(hex::encode(client_claim_pk.to_bytes())),
            client_refund_pubkey_hex: None,
            invoice: None,
            owner_ref: Some("index:0".into()),
        }),
        swap_accept: Some(accept),
        direction: SwapDirection::Reverse,
        peer: "client".into(),
        network: NetworkSpec::Regtest,
        payment_hash_hex: hex::encode(ph),
        onchain_amount_sat: swap.onchain_amount_sat,
        fee_rate_sat_vb: 2,
        htlc_script_hex: hex::encode(swap.htlc_script.as_bytes()),
        timeout_height: timeout,
        secret_key_hex: hex::encode(swap.refund_key.secret_bytes()),
        invoice: swap.invoice.clone(),
        required_confirmations: 1,
        state: SwapState::Created,
        created_at_unix: now_unix(),
        updated_at_unix: now_unix(),
        ..SwapRecord::new_progress()
    };
    let listed = provider_record.status_snapshot(None, now_unix()).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let miner = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                mine(1);
                std::thread::sleep(Duration::from_millis(1500));
            }
        })
    };

    let provider_task = {
        let ln = provider_ln.clone();
        let chain = chain_p.clone();
        let wallet = wallet.clone();
        tokio::spawn(async move {
            drive_reverse_swap(
                ln.as_ref(),
                chain.as_ref(),
                wallet.as_ref(),
                &swap,
                1,
                Duration::from_secs(1),
                &Resume::default(),
                &(),
            )
            .await
        })
    };

    // The first client pays the hold invoice and is never heard from again: no record exists.
    let paying = {
        let ln = client_ln.clone();
        let invoice = listed.accept.invoice.clone().unwrap();
        tokio::spawn(async move { ln.pay_invoice(&invoice, 100_000, None).await })
    };

    // The provider funds the lockup once the payment is held.
    let htlc_spk = spk_of(&listed.accept.htlc_address);
    let funded = async {
        loop {
            if !chain_c.find_outputs(&htlc_spk).unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(90), funded)
        .await
        .expect("the provider funded the lockup");
    println!("lockup funded; restoring the client from the listing");

    // The second client: an empty store, the listing, and the keys its seed gives back for
    // `owner_ref`. Then resume drives the swap like any other.
    let client_store = JsonFileSwapStore::new(temp_dir("restore-client")).unwrap();
    let client_dest = spk_of(&cli(&["getnewaddress", "", "bech32"]));
    let report = restore_snapshots(
        &Restore {
            store: &client_store,
            network: Network::Regtest,
            dest_spk: client_dest,
            fee_rate_sat_vb: 2,
        },
        "provider",
        &[listed],
        |snapshot| {
            (snapshot.owner_ref.as_deref() == Some("index:0")).then_some(RestoredKeys {
                branch_key: client_claim_sk,
                preimage: Some(preimage),
            })
        },
    )
    .unwrap();
    assert_eq!(report.restored, vec![swap_id]);

    tokio::time::timeout(
        Duration::from_secs(120),
        resume_unfinished(
            &client_store,
            client_ln.clone(),
            chain_c.clone(),
            None,
            100_000,
        ),
    )
    .await
    .expect("resume timed out")
    .expect("resume failed");
    let record = client_store.get(swap_id).unwrap().unwrap();
    assert_eq!(
        record.state,
        SwapState::Claimed,
        "the restored client claimed"
    );

    let provider_state = tokio::time::timeout(Duration::from_secs(90), provider_task)
        .await
        .expect("provider task timed out")
        .expect("provider task panicked")
        .expect("provider driver error");
    assert_eq!(provider_state, SwapState::Claimed);
    let payment = tokio::time::timeout(Duration::from_secs(30), paying)
        .await
        .expect("the first client's payment did not settle")
        .expect("pay task panicked");
    assert!(payment.is_ok(), "{payment:?}");

    stop.store(true, Ordering::Relaxed);
    let _ = miner.join();
    assert_eq!(
        provider_ln.invoice_state(ph).await.expect("invoice_state"),
        InvoiceState::Settled
    );
    println!("restored client claimed swap {swap_id}; provider invoice Settled");
}
