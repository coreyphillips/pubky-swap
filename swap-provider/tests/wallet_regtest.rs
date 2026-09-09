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

/// A unique wallet directory per run, so tests never share a database.
fn temp_wallet_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("pubky-swap-test-wallet-{}", uuid::Uuid::new_v4()))
}
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

    let wallet = BdkWallet::from_mnemonic(
        MNEMONIC,
        Network::Regtest,
        &electrum_url(),
        5,
        &temp_wallet_dir(),
    )
    .unwrap();

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

/// A wallet whose database exists but whose first full scan never finished must still scan.
///
/// `needs_full_scan` was set from "did this process create the database", which is only the same
/// thing on a start that gets all the way through. A first start that creates the database and
/// then dies before the scan completes, and an Electrum full scan against a seed with history is
/// exactly the slow part, comes back as a load: the flag is false, the scan is never attempted
/// again, and the wallet syncs only the addresses it has revealed. For a restored mnemonic that
/// is none of them, so its coins are never seen. Nothing errors; the balance is simply zero.
///
/// This is that sequence: fund the seed, throw the wallet away mid-life leaving the database
/// behind with no completed-scan marker, and reopen it.
#[test]
#[ignore = "requires docker regtest bitcoind + electrs"]
fn a_wallet_whose_first_scan_never_finished_scans_again() {
    let bal: f64 = cli(&["getbalance"]).parse().unwrap_or(0.0);
    if bal < 1.0 {
        mine(110);
    }

    let dir = temp_wallet_dir();

    // First life: fund the seed so there is history behind it, and let the scan complete.
    let deposit = {
        let wallet =
            BdkWallet::from_mnemonic(MNEMONIC, Network::Regtest, &electrum_url(), 5, &dir).unwrap();
        let deposit = wallet.deposit_address().unwrap().to_string();
        let send = cli(&["sendtoaddress", &deposit, "0.25"]);
        assert!(!send.starts_with("ERROR"), "funding deposit failed: {send}");
        mine(1);
        for _ in 0..30 {
            if wallet.balance().unwrap() >= 20_000_000 {
                break;
            }
            sleep(Duration::from_secs(1));
        }
        assert!(wallet.balance().unwrap() >= 20_000_000);
        deposit
    };

    // Now make it look like the scan never finished: the database survives, the marker does not.
    // This is what a process killed part-way through its first scan leaves behind.
    let marker = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "scanned"))
        .expect("a completed scan records that it completed");
    std::fs::remove_file(&marker).unwrap();

    // Second life: the database is there, so this is a load, not a create.
    let wallet =
        BdkWallet::from_mnemonic(MNEMONIC, Network::Regtest, &electrum_url(), 5, &dir).unwrap();
    let mut balance = 0;
    for _ in 0..30 {
        balance = wallet.balance().unwrap();
        if balance >= 20_000_000 {
            break;
        }
        sleep(Duration::from_secs(1));
    }
    assert!(
        balance >= 20_000_000,
        "a wallet that never finished its first scan must scan again, not report {balance} for a \
         seed holding coins at {deposit}"
    );
    assert!(
        marker.exists(),
        "and record that this scan finished, so the next start need not repeat it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
