//! Regtest integration test for the BDK funding wallet (feature `bdk-wallet`).
//!
//! `#[ignore]`d; drives a real bitcoind via `docker exec` and syncs the wallet over electrs.
//!
//! ```bash
//! cargo test -p swap-provider --features bdk-wallet --test wallet_regtest -- --ignored --nocapture
//! ```

#![cfg(feature = "bdk-wallet")]

use bitcoin::Network;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use swap_common::htlc::{build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash};
use swap_common::random_keypair;
use swap_provider::reverse::OnchainWallet;
use swap_provider::wallet::BdkWallet;

// A standard BIP39 test mnemonic.
const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn container() -> String {
    std::env::var("REGTEST_BTC_CONTAINER").unwrap_or_else(|_| "bitcoin".to_string())
}

fn electrum_url() -> String {
    std::env::var("REGTEST_ELECTRUM_URL").unwrap_or_else(|_| "tcp://127.0.0.1:60001".to_string())
}

fn cli(args: &[&str]) -> String {
    let mut full = vec![
        "exec".to_string(),
        container(),
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
        .expect("docker exec bitcoin-cli");
    if !out.status.success() {
        return format!("ERROR: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn mine(n: u32) {
    let addr = cli(&["getnewaddress", "", "bech32"]);
    cli(&["generatetoaddress", &n.to_string(), &addr]);
}

#[test]
#[ignore = "requires docker regtest bitcoind + electrs"]
fn bdk_wallet_funds_htlc() {
    // Ensure the bitcoind wallet has spendable coins to fund us.
    let bal: f64 = cli(&["getbalance"]).parse().unwrap_or(0.0);
    if bal < 1.0 {
        mine(110);
    }

    let wallet =
        BdkWallet::from_mnemonic(MNEMONIC, Network::Regtest, &electrum_url(), 5.0).unwrap();

    // Fund the BDK wallet with 0.5 BTC and confirm it.
    let deposit = wallet.deposit_address().unwrap().to_string();
    let send = cli(&["sendtoaddress", &deposit, "0.5"]);
    assert!(!send.starts_with("ERROR"), "funding deposit failed: {send}");
    mine(1);

    // Wait for the wallet to see the confirmed balance (electrs indexing lag).
    let mut balance = 0;
    for _ in 0..30 {
        balance = wallet.balance().unwrap();
        if balance >= 40_000_000 {
            break;
        }
        sleep(Duration::from_secs(1));
    }
    assert!(balance >= 40_000_000, "wallet balance too low: {balance}");

    // Build an HTLC address and fund it from the wallet.
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (_c, claim_pk) = random_keypair(&secp);
    let (_r, refund_pk) = random_keypair(&secp);
    let ph = payment_hash(&generate_preimage());
    let redeem = build_htlc_script(&ph, &claim_pk, &refund_pk, 10_000);
    let htlc_addr = htlc_p2wsh_address(&redeem, Network::Regtest);
    let htlc_spk = htlc_addr.script_pubkey();

    let outpoint = wallet.fund_htlc(&htlc_spk, 100_000).expect("fund_htlc");
    println!("BDK wallet funded HTLC at {outpoint} (addr {htlc_addr})");

    // Confirm and verify the funding UTXO via bitcoind.
    mine(1);
    let txout = cli(&[
        "gettxout",
        &outpoint.txid.to_string(),
        &outpoint.vout.to_string(),
    ]);
    assert!(
        !txout.starts_with("ERROR") && !txout.is_empty(),
        "gettxout returned nothing: {txout}"
    );
    assert!(
        txout.contains("0.00100000"),
        "unexpected funding value: {txout}"
    );
    assert!(
        txout.contains(&htlc_spk.to_hex_string()),
        "funding scriptPubKey mismatch; expected {} in {txout}",
        htlc_spk.to_hex_string()
    );
}
