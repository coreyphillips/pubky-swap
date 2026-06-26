//! Regtest integration tests for the on-chain HTLC engine + Electrum chain watcher.
//!
//! These talk to a real bitcoind (driven via `docker exec ... bitcoin-cli`) and a real
//! electrs, so they are `#[ignore]`d by default and require the `electrum` feature. Run with:
//!
//! ```bash
//! cargo test -p swap-common --features electrum --test regtest -- --ignored --nocapture
//! ```
//!
//! Environment (overridable via env vars):
//! - `REGTEST_ELECTRUM_URL`  (default `tcp://127.0.0.1:60001`)
//! - `REGTEST_BTC_CONTAINER` (default `bitcoin`)
//! - bitcoind RPC: port 43782, user `polaruser`, pass `polarpass` (Polar defaults)

#![cfg(feature = "electrum")]

use bitcoin::{Address, Network, OutPoint, ScriptBuf};
use std::process::Command;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use swap_common::chain::{ChainWatcher, ElectrumWatcher};
use swap_common::htlc::{build_htlc_script, generate_preimage, htlc_p2wsh_address, payment_hash};
use swap_common::onchain::{build_claim_tx, build_refund_tx, estimate_spend_fee, extract_preimage};
use swap_common::random_keypair;

const VALUE_SAT: u64 = 100_000;
const VALUE_BTC: &str = "0.001";
const FEE_RATE: u64 = 5;

fn electrum_url() -> String {
    std::env::var("REGTEST_ELECTRUM_URL").unwrap_or_else(|_| "tcp://127.0.0.1:60001".to_string())
}

fn container() -> String {
    std::env::var("REGTEST_BTC_CONTAINER").unwrap_or_else(|_| "bitcoin".to_string())
}

/// Run a bitcoin-cli command inside the bitcoind container, returning trimmed stdout.
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
        .expect("run docker exec bitcoin-cli");
    if !out.status.success() {
        // Return the error so callers can assert on rejection (e.g. non-final refund).
        return format!("ERROR: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn block_count() -> u32 {
    cli(&["getblockcount"]).parse().expect("getblockcount")
}

fn new_address() -> String {
    cli(&["getnewaddress", "", "bech32"])
}

fn mine(n: u32) {
    let addr = new_address();
    cli(&["generatetoaddress", &n.to_string(), &addr]);
}

fn ensure_funds() {
    let bal: f64 = cli(&["getbalance"]).parse().unwrap_or(0.0);
    if bal < 0.01 {
        // Mine past coinbase maturity so we have spendable coins.
        mine(110);
    }
}

fn spk_of(addr: &str) -> ScriptBuf {
    Address::from_str(addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey()
}

/// Poll until the HTLC funding UTXO is visible (electrs indexing lag), or panic after ~30s.
fn wait_for_funding(chain: &ElectrumWatcher, spk: &ScriptBuf) -> OutPoint {
    for _ in 0..30 {
        if let Some(u) = chain.find_funding(spk, VALUE_SAT).unwrap() {
            if u.confirmations >= 1 {
                return u.outpoint;
            }
        }
        sleep(Duration::from_secs(1));
    }
    panic!("funding UTXO not found via electrs within timeout");
}

fn wait_for_spend(
    chain: &ElectrumWatcher,
    spk: &ScriptBuf,
    outpoint: &OutPoint,
) -> bitcoin::Transaction {
    for _ in 0..30 {
        if let Some(tx) = chain.find_spend(spk, outpoint).unwrap() {
            return tx;
        }
        sleep(Duration::from_secs(1));
    }
    panic!("spend of HTLC not found via electrs within timeout");
}

#[test]
#[ignore = "requires docker regtest bitcoind + electrs"]
fn htlc_claim_roundtrip() {
    ensure_funds();
    let chain = ElectrumWatcher::new(&electrum_url()).expect("connect electrs");

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (claim_sk, claim_pk) = random_keypair(&secp);
    let (_refund_sk, refund_pk) = random_keypair(&secp);
    let preimage = generate_preimage();
    let ph = payment_hash(&preimage);
    let timeout = block_count() + 20; // claim path doesn't depend on this

    let redeem = build_htlc_script(&ph, &claim_pk, &refund_pk, timeout);
    let htlc_addr = htlc_p2wsh_address(&redeem, Network::Regtest);
    let htlc_spk = htlc_addr.script_pubkey();

    // Fund the HTLC and confirm it.
    let fund_txid = cli(&["sendtoaddress", &htlc_addr.to_string(), VALUE_BTC]);
    assert!(!fund_txid.starts_with("ERROR"), "fund failed: {fund_txid}");
    mine(1);

    let outpoint = wait_for_funding(&chain, &htlc_spk);
    println!("HTLC funded at {outpoint}");

    // Build and broadcast the claim (reveals the preimage).
    let dest = spk_of(&new_address());
    let fee = estimate_spend_fee(FEE_RATE, true);
    let claim_tx =
        build_claim_tx(outpoint, VALUE_SAT, &redeem, dest, fee, preimage, &claim_sk).unwrap();
    let txid = chain
        .broadcast(&claim_tx)
        .expect("broadcast claim accepted by bitcoind");
    println!("claim broadcast: {txid}");
    mine(1);

    // The provider recovers the preimage from the on-chain claim.
    let spend = wait_for_spend(&chain, &htlc_spk, &outpoint);
    let recovered = extract_preimage(&spend, &outpoint, &ph);
    assert_eq!(
        recovered,
        Some(preimage),
        "preimage recovered from on-chain claim"
    );
}

#[test]
#[ignore = "requires docker regtest bitcoind + electrs"]
fn htlc_refund_is_rejected_before_timeout_and_accepted_after() {
    ensure_funds();
    let chain = ElectrumWatcher::new(&electrum_url()).expect("connect electrs");

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (_claim_sk, claim_pk) = random_keypair(&secp);
    let (refund_sk, refund_pk) = random_keypair(&secp);
    let preimage = generate_preimage();
    let ph = payment_hash(&preimage);
    let timeout = block_count() + 6;

    let redeem = build_htlc_script(&ph, &claim_pk, &refund_pk, timeout);
    let htlc_addr = htlc_p2wsh_address(&redeem, Network::Regtest);
    let htlc_spk = htlc_addr.script_pubkey();

    let fund_txid = cli(&["sendtoaddress", &htlc_addr.to_string(), VALUE_BTC]);
    assert!(!fund_txid.starts_with("ERROR"), "fund failed: {fund_txid}");
    mine(1);
    let outpoint = wait_for_funding(&chain, &htlc_spk);

    let dest = spk_of(&new_address());
    let fee = estimate_spend_fee(FEE_RATE, false);
    let refund_tx =
        build_refund_tx(outpoint, VALUE_SAT, &redeem, dest, fee, timeout, &refund_sk).unwrap();

    // Before the timeout height, the refund is non-final and must be rejected.
    let early = chain.broadcast(&refund_tx);
    assert!(
        early.is_err(),
        "refund must be rejected before the timeout height (got {early:?})"
    );

    // Advance the chain to the timeout height.
    while block_count() < timeout {
        mine(1);
    }

    // Now the refund (locktime == timeout) is final and CLTV is satisfied.
    let txid = chain
        .broadcast(&refund_tx)
        .expect("refund accepted at/after timeout");
    println!("refund broadcast: {txid}");
    mine(1);

    let spend = wait_for_spend(&chain, &htlc_spk, &outpoint);
    assert_eq!(
        extract_preimage(&spend, &outpoint, &ph),
        None,
        "a refund reveals no preimage"
    );
}
