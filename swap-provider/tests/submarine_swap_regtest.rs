//! End-to-end submarine swap across two real LND nodes + bitcoind + electrs.
//!
//! `#[ignore]`d; needs the `full` feature and a regtest with: a provider LND with outbound
//! liquidity to a client LND, and a BDK-fundable client wallet. Run with:
//!
//! ```bash
//! LND_A_URL=https://127.0.0.1:10011 LND_A_CERT=.../A/tls.cert LND_A_MAC=.../A/admin.macaroon \
//! LND_B_URL=https://127.0.0.1:10012 LND_B_CERT=.../B/tls.cert LND_B_MAC=.../B/admin.macaroon \
//! REGTEST_ELECTRUM_URL=tcp://127.0.0.1:60001 WALLET_MNEMONIC="abandon ... about" \
//! cargo test -p swap-provider --features full --test submarine_swap_regtest -- --ignored --nocapture
//! ```
//!
//! Direction: the provider (A) pays the client's (B) invoice, so the A→B channel must have
//! outbound balance on A's side.

#![cfg(all(feature = "lnd", feature = "bdk-wallet", feature = "chain"))]

use bitcoin::Network;
use lightning_backend::{InvoiceState, LightningBackend, LndBackend, LndConfig};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use swap_client::submarine::{execute_submarine_swap, SubmarineFunding};
use swap_common::chain::{ChainWatcher, ElectrumWatcher};
use swap_common::wallet::{BdkWallet, OnchainWallet};
use swap_common::{random_keypair, SwapState};
use swap_provider::submarine::{drive_submarine_swap, init_submarine_swap};

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

fn lnd_cfg(prefix: &str) -> LndConfig {
    LndConfig {
        address: std::env::var(format!("LND_{prefix}_URL")).expect("LND url env"),
        tls_cert_path: std::env::var(format!("LND_{prefix}_CERT")).expect("LND cert env"),
        macaroon_path: std::env::var(format!("LND_{prefix}_MAC")).expect("LND macaroon env"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs"]
async fn full_submarine_swap_two_nodes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let electrum = env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001");

    // Provider LND (A) pays; client LND (B) issues the invoice it wants paid.
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

    // The client funds the HTLC, so the client wallet needs coins; the provider only needs a
    // sweep destination for its claim.
    let client_wallet: Arc<dyn OnchainWallet> = Arc::new(
        BdkWallet::from_mnemonic(
            &env("WALLET_MNEMONIC", MNEMONIC),
            Network::Regtest,
            &electrum,
            5.0,
        )
        .expect("client funding wallet"),
    );
    let provider_wallet: Arc<dyn OnchainWallet> = Arc::new(
        BdkWallet::from_mnemonic(
            &env("WALLET_MNEMONIC", MNEMONIC),
            Network::Regtest,
            &electrum,
            5.0,
        )
        .expect("provider claim wallet"),
    );

    // Make sure the client wallet has coins to fund the HTLC.
    {
        let bdk = BdkWallet::from_mnemonic(
            &env("WALLET_MNEMONIC", MNEMONIC),
            Network::Regtest,
            &electrum,
            5.0,
        )
        .unwrap();
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
    }

    // Client issues the invoice it wants paid.
    let invoice = client_ln
        .create_invoice(AMOUNT_SAT * 1000, 3600, "pubky-swap submarine test")
        .await
        .expect("client create invoice");

    // Keys: provider claims, client refunds.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (provider_claim_sk, provider_claim_pk) = random_keypair(&secp);
    let (client_refund_sk, client_refund_pk) = random_keypair(&secp);
    let timeout = chain_p.tip_height().unwrap() + 200;

    // Provider: decode the invoice and build the HTLC the client must fund.
    let swap = init_submarine_swap(
        provider_ln.as_ref(),
        &invoice.bolt11,
        &client_refund_pk,
        provider_claim_sk,
        &provider_claim_pk,
        PROVIDER_FEE_SAT,
        2,
        100_000,
        timeout,
        Network::Regtest,
    )
    .await
    .expect("init submarine swap");

    println!(
        "submarine swap: onchain_amount={} htlc_spk={}",
        swap.onchain_amount_sat,
        swap.htlc_spk.to_hex_string()
    );

    let funding = SubmarineFunding {
        htlc_script: swap.htlc_script.clone(),
        htlc_spk: swap.htlc_spk.clone(),
        onchain_amount_sat: swap.onchain_amount_sat,
        payment_hash: swap.payment_hash,
        refund_key: client_refund_sk,
        timeout_height: swap.timeout_height,
        fee_rate_sat_vb: 2,
    };

    // The payment hash is needed after `swap` is moved into the provider task.
    let payment_hash = swap.payment_hash;

    // Mine continuously so the client's funding confirms while the swap runs.
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

    // Run both sides concurrently: client funds + waits; provider waits for funding, pays, claims.
    let provider_task = {
        let ln = provider_ln.clone();
        let chain = chain_p.clone();
        let wallet = provider_wallet.clone();
        tokio::spawn(async move {
            drive_submarine_swap(
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
    let client_task = tokio::spawn(execute_submarine_swap(
        client_ln.clone(),
        chain_c.clone(),
        client_wallet.clone(),
        funding,
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
        "provider should claim the HTLC"
    );

    let client_state = client_result.expect("client execution error");
    assert_eq!(
        client_state,
        SwapState::Claimed,
        "client should see the invoice settled"
    );

    // The client's invoice must now be settled (the provider paid it to learn the preimage).
    let inv_state = client_ln
        .invoice_state(payment_hash)
        .await
        .expect("invoice_state");
    assert_eq!(
        inv_state,
        InvoiceState::Settled,
        "invoice should be settled"
    );

    println!("✅ full submarine swap: provider claimed on-chain, client invoice Settled");
}
