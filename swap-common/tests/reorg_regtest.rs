//! Reorg detection against a real bitcoind + electrs (feature `electrum`, `#[ignore]`d).
//!
//! Forces a reorg with bitcoin-cli `invalidateblock` and asserts that
//! [`ChainWatcher::block_hash_at`] / [`ReorgMonitor`] notice it, and that a transaction in an
//! orphaned block loses its confirmations. Uses the Polar regtest defaults (override via env):
//!
//! ```bash
//! cargo test -p swap-common --features electrum --test reorg_regtest -- --ignored --nocapture
//! ```
//! Env: `REGTEST_ELECTRUM_URL` (default `tcp://127.0.0.1:60001`), `REGTEST_BTC_CONTAINER`
//! (default `bitcoin`); assumes bitcoind RPC `polaruser`/`polarpass` on port 43782.

#![cfg(feature = "electrum")]

use std::process::Command;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use swap_common::chain::{ChainWatcher, ElectrumWatcher};
use swap_common::reorg::ReorgMonitor;

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
        .expect("docker exec bitcoin-cli");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn mine(n: u32) -> Vec<String> {
    let addr = cli(&["getnewaddress", "", "bech32"]);
    let json = cli(&["generatetoaddress", &n.to_string(), &addr]);
    // crude parse of the returned ["hash", ...] array
    json.trim_matches(|c| c == '[' || c == ']' || c == '\n' || c == ' ')
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Wait for electrs to catch up to bitcoind's tip height.
fn wait_for_tip(watcher: &ElectrumWatcher, target: u32) {
    for _ in 0..30 {
        if watcher.tip_height().unwrap_or(0) >= target {
            return;
        }
        sleep(Duration::from_millis(500));
    }
    panic!("electrs did not reach height {target}");
}

#[test]
#[ignore = "requires regtest bitcoind + electrs"]
fn reorg_monitor_detects_invalidated_block() {
    let url = env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001");
    let watcher = ElectrumWatcher::new(&url).expect("connect electrs");

    // Establish a baseline a few blocks up so electrs is synced.
    mine(3);
    let base_tip = u32::from_str(&cli(&["getblockcount"])).unwrap();
    wait_for_tip(&watcher, base_tip);

    let mut monitor = ReorgMonitor::new(50);
    assert_eq!(
        monitor.observe(&watcher).unwrap(),
        None,
        "no reorg on the first observation"
    );

    // Mine two blocks we will orphan, and record the first one's height/hash.
    let new_hashes = mine(2);
    let reorg_height = base_tip + 1;
    wait_for_tip(&watcher, base_tip + 2);
    assert_eq!(
        monitor.observe(&watcher).unwrap(),
        None,
        "extending the chain is not a reorg"
    );
    let hash_before = watcher.block_hash_at(reorg_height).unwrap();
    assert!(hash_before.is_some());

    // Force a reorg: invalidate the block at `reorg_height`, then mine a longer competing branch.
    cli(&["invalidateblock", &new_hashes[0]]);
    let replacement = mine(3);
    assert!(!replacement.is_empty());
    let new_tip = u32::from_str(&cli(&["getblockcount"])).unwrap();
    wait_for_tip(&watcher, new_tip);

    // The hash at `reorg_height` changed → the monitor reports the fork there (or below).
    let hash_after = watcher.block_hash_at(reorg_height).unwrap();
    assert_ne!(
        hash_before, hash_after,
        "the block at the reorg height must have changed"
    );
    let fork = monitor
        .observe(&watcher)
        .unwrap()
        .expect("monitor must detect the reorg");
    assert!(
        fork <= reorg_height,
        "fork height {fork} should be at or below the invalidated height {reorg_height}"
    );

    println!(
        "✅ reorg detected at height {fork} (invalidated {})",
        new_hashes[0]
    );
}
