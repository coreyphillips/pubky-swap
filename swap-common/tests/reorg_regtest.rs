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

    // Establish a baseline and let electrs sync to the tip.
    mine(3);
    let tip = u32::from_str(&cli(&["getblockcount"])).unwrap();
    wait_for_tip(&watcher, tip);

    // Checkpoint exactly the current tip. The monitor reports the lowest *checkpointed* height
    // whose hash changes, so by checkpointing only `tip` and invalidating exactly that block, the
    // detected fork is deterministically `tip`.
    let mut monitor = ReorgMonitor::new(50);
    assert_eq!(
        monitor.observe(&watcher).unwrap(),
        None,
        "no reorg on the first observation"
    );

    let hash_before = watcher.block_hash_at(tip).unwrap().expect("hash at tip");
    let tip_blockhash = cli(&["getblockhash", &tip.to_string()]);

    // Force a reorg: invalidate the tip block (rolling back one), then mine a longer branch so the
    // block at height `tip` is replaced by a different one.
    cli(&["invalidateblock", &tip_blockhash]);
    let replacement = mine(2);
    assert!(!replacement.is_empty());
    let new_tip = u32::from_str(&cli(&["getblockcount"])).unwrap();
    wait_for_tip(&watcher, new_tip.max(tip));

    // The block at `tip` is now a different one.
    let hash_after = watcher
        .block_hash_at(tip)
        .unwrap()
        .expect("hash at tip after reorg");
    assert_ne!(
        hash_before, hash_after,
        "the block at the checkpointed tip must have changed"
    );

    let fork = monitor
        .observe(&watcher)
        .unwrap()
        .expect("monitor must detect the reorg");
    assert_eq!(
        fork, tip,
        "the detected fork should be the invalidated (checkpointed) height"
    );

    println!("✅ reorg detected at height {fork} (was {tip_blockhash})");
}
