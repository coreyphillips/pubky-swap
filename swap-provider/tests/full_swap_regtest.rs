//! End-to-end reverse swap across two real LND nodes + bitcoind + electrs.
//!
//! `#[ignore]`d; needs the `full` feature and a regtest with: a provider LND, a client LND
//! with a channel to the provider, and a BDK-fundable wallet. Run with:
//!
//! ```bash
//! LND_A_URL=https://127.0.0.1:10011 LND_A_CERT=.../A/tls.cert LND_A_MAC=.../A/admin.macaroon \
//! LND_B_URL=https://127.0.0.1:10012 LND_B_CERT=.../B/tls.cert LND_B_MAC=.../B/admin.macaroon \
//! REGTEST_ELECTRUM_URL=tcp://127.0.0.1:60001 WALLET_MNEMONIC="abandon ... about" \
//! cargo test -p swap-provider --features full --test full_swap_regtest -- --ignored --nocapture
//! ```

#![cfg(all(feature = "lnd", feature = "bdk-wallet", feature = "chain"))]

use bitcoin::{Address, Network, ScriptBuf};
use lightning_backend::{InvoiceState, LightningBackend, LndBackend, LndConfig};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use swap_client::reverse::{execute_reverse_swap, ReverseClaim};
use swap_common::chain::{ChainWatcher, ElectrumWatcher};
use swap_common::htlc::{generate_preimage, payment_hash};
use swap_common::{random_keypair, SwapState};
use swap_provider::reverse::{drive_reverse_swap, init_reverse_swap, OnchainWallet};
use swap_provider::wallet::BdkWallet;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs"]
async fn full_reverse_swap_two_nodes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let electrum = env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001");

    // Backends: provider LND (A), client LND (B), a shared electrs, and the provider's wallet.
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
    // Funding wallet: BDK by default, or LND's own on-chain wallet with WALLET_BACKEND=lnd (which
    // exercises swap_provider::lnd_wallet::LndWallet — funds from the provider LND's balance).
    let wallet: Arc<dyn OnchainWallet> = if env("WALLET_BACKEND", "bdk") == "lnd" {
        Arc::new(
            swap_provider::lnd_wallet::LndWallet::connect(lnd_cfg("A"), 5)
                .await
                .expect("connect LND on-chain wallet"),
        )
    } else {
        let bdk = BdkWallet::from_mnemonic(
            &env("WALLET_MNEMONIC", MNEMONIC),
            Network::Regtest,
            &electrum,
            5.0,
        )
        .expect("build funding wallet");
        // Make sure the BDK wallet has coins to fund the HTLC.
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

    // Shared swap secrets / keys.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (client_claim_sk, client_claim_pk) = random_keypair(&secp);
    let (refund_sk, refund_pk) = random_keypair(&secp);
    let preimage = generate_preimage();
    let ph = payment_hash(&preimage);
    let timeout = chain_p.tip_height().unwrap() + 200;

    // Provider: create the hold invoice + HTLC.
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
    )
    .await
    .expect("init reverse swap");

    println!(
        "swap created: onchain_amount={} htlc_spk={}",
        swap.onchain_amount_sat,
        swap.htlc_spk.to_hex_string()
    );

    let client_dest = spk_of(&cli(&["getnewaddress", "", "bech32"]));
    let claim = ReverseClaim {
        htlc_script: swap.htlc_script.clone(),
        htlc_spk: swap.htlc_spk.clone(),
        onchain_amount_sat: swap.onchain_amount_sat,
        invoice: swap.invoice.clone(),
        preimage,
        claim_key: client_claim_sk,
        dest_spk: client_dest,
        fee_rate_sat_vb: 2,
    };

    // Mine continuously so confirmations accrue while the swap runs.
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

    // Run both sides concurrently.
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
                None,
                &(),
            )
            .await
        })
    };
    let client_task = tokio::spawn(execute_reverse_swap(
        client_ln.clone(),
        chain_c.clone(),
        claim,
        100_000,
        1,
        Duration::from_secs(1),
    ));

    let provider_result = tokio::time::timeout(Duration::from_secs(90), provider_task)
        .await
        .expect("provider task timed out")
        .expect("provider task panicked");
    let client_result = tokio::time::timeout(Duration::from_secs(90), client_task)
        .await
        .expect("client task timed out")
        .expect("client task panicked");

    stop.store(true, Ordering::Relaxed);
    let _ = miner.join();

    let provider_state = provider_result.expect("provider driver error");
    assert_eq!(
        provider_state,
        SwapState::Claimed,
        "provider should reach Claimed"
    );

    let claim_txid = client_result.expect("client execution error");
    println!("client claim txid: {claim_txid}");

    // The provider's hold invoice must now be settled (it got paid over Lightning, atomically
    // with the client's on-chain claim).
    let inv_state = provider_ln.invoice_state(ph).await.expect("invoice_state");
    assert_eq!(
        inv_state,
        InvoiceState::Settled,
        "hold invoice should be settled"
    );

    println!("✅ full reverse swap: client claim {claim_txid}, provider invoice Settled");
}
