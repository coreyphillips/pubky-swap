//! Startup checks, and the diagnostics behind `--doctor`.
//!
//! The provider used to degrade silently. A wrong macaroon path, an Electrum server that was not
//! up yet, a mnemonic nobody set: each of those turned into a `warn!` and a daemon that carried
//! on serving quotes it could never honour. The operator's first sign of trouble was a
//! counterparty complaining.
//!
//! So checks produce a report rather than a boolean, every failure carries the thing to actually
//! do about it, and the same report backs both the startup path and the `--doctor` flag. One
//! implementation means the diagnostic cannot drift from what the daemon really requires.

use std::fmt::Write as _;

/// How a single check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    /// Works, but something about it is worth knowing.
    Warn,
    /// Does not work.
    Fail,
}

impl Status {
    fn marker(self) -> &'static str {
        match self {
            Status::Pass => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        }
    }
}

/// One thing that was checked.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// What to do about it. Present on every `Fail`, because a diagnostic that does not say how
    /// to fix the problem has only told the operator they have one.
    pub remedy: Option<String>,
}

impl Check {
    pub fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Pass,
            detail: detail.into(),
            remedy: None,
        }
    }

    pub fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
            detail: detail.into(),
            remedy: None,
        }
    }

    pub fn fail(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }

    pub fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

/// Everything that was checked, and what it means.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    pub fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count()
    }

    pub fn warnings(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Warn)
            .count()
    }

    /// Whether the provider can execute swaps.
    pub fn is_capable(&self) -> bool {
        self.failures() == 0
    }

    /// A human-readable rendering, for the terminal and for the dashboard's health view.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for check in &self.checks {
            let _ = writeln!(
                out,
                "  [{}] {:<22} {}",
                check.status.marker(),
                check.name,
                check.detail
            );
            if let Some(remedy) = &check.remedy {
                // Indented under the failure it belongs to, so a long list stays readable.
                for line in remedy.lines() {
                    let _ = writeln!(out, "         -> {line}");
                }
            }
        }
        let _ = writeln!(
            out,
            "\n  {} check(s): {} failed, {} warning(s)",
            self.checks.len(),
            self.failures(),
            self.warnings()
        );
        out
    }
}

/// Run every check the daemon depends on, and report what to do about anything that fails.
///
/// The same code backs `--doctor` and the startup path, which is the point: a diagnostic that is
/// written separately from the thing it diagnoses drifts, and the drift is always discovered by
/// an operator whose daemon is running and useless.
pub async fn diagnose(config: &crate::ProviderConfig) -> Report {
    let mut report = Report::new();

    // Network first: every other check is about a specific chain.
    let network = match crate::parse_network(&config.network) {
        Ok(n) => {
            report.push(Check::pass("network", format!("{n:?}")));
            Some(n)
        }
        Err(e) => {
            report.push(Check::fail(
                "network",
                e.to_string(),
                "set network to one of: bitcoin, testnet, signet, regtest",
            ));
            None
        }
    };

    check_identity(config, &mut report);
    check_parameters(config, network, &mut report);
    check_data_dir(config, &mut report);
    check_lightning(config, network, &mut report).await;
    check_chain(config, network, &mut report).await;
    check_wallet(config, &mut report).await;

    report
}

fn check_identity(config: &crate::ProviderConfig, report: &mut Report) {
    match config.identity() {
        Ok(id) => report.push(Check::pass(
            "identity",
            format!("a recovery {} is configured", id.method),
        )),
        Err(e) => report.push(Check::fail(
            "identity",
            e.to_string(),
            "put the phrase in a file readable only by this user and set \
             PUBKY_SWAP_RECOVERY_PHRASE__FILE to its path, or pass a recovery file as the first \
             argument. There is deliberately no flag for the phrase itself.",
        )),
    }
}

/// The parameter guards that already refuse to start, reported rather than thrown.
fn check_parameters(
    config: &crate::ProviderConfig,
    network: Option<bitcoin::Network>,
    report: &mut Report,
) {
    match crate::validate_timelocks(config) {
        Ok(()) => report.push(Check::pass(
            "timelocks",
            format!(
                "{} block timeout, {} block claim window",
                config.htlc_timeout_blocks, config.min_claim_window_blocks
            ),
        )),
        Err(e) => report.push(Check::fail(
            "timelocks",
            e.to_string(),
            "raise --timeout-blocks or lower --min-claim-window-blocks until the swap has room \
             for both legs",
        )),
    }
    if let Some(network) = network {
        match crate::validate_mainnet_safety(config, network) {
            Ok(()) => report.push(Check::pass("mainnet-safety", "parameters are safe")),
            Err(e) => report.push(Check::fail(
                "mainnet-safety",
                e.to_string(),
                "raise --confirmations to at least 2 and --onchain-fee-rate to at least 5 on \
                 mainnet. --allow-unsafe exists for testing and does not make either safe.",
            )),
        }
    }
}

fn check_data_dir(config: &crate::ProviderConfig, report: &mut Report) {
    let dir = std::path::Path::new(&config.data_dir);
    match std::fs::create_dir_all(dir) {
        Ok(()) => {
            // Writable is the property that matters: a swap record that cannot be written is a
            // swap that cannot be resumed, and the driver refuses to fund without one.
            let probe = dir.join(".pubky-swap-write-probe");
            match std::fs::write(&probe, b"") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&probe);
                    report.push(Check::pass("data-dir", config.data_dir.clone()));
                }
                Err(e) => report.push(Check::fail(
                    "data-dir",
                    format!("{} is not writable: {e}", config.data_dir),
                    format!(
                        "make {} writable by the user this daemon runs as",
                        config.data_dir
                    ),
                )),
            }
        }
        Err(e) => report.push(Check::fail(
            "data-dir",
            format!("cannot create {}: {e}", config.data_dir),
            format!(
                "create {} and make it writable, or set --data-dir elsewhere",
                config.data_dir
            ),
        )),
    }
}

async fn check_lightning(
    config: &crate::ProviderConfig,
    network: Option<bitcoin::Network>,
    report: &mut Report,
) {
    let name = if config.lightning_backend == "beignet" {
        "lightning.beignet"
    } else {
        "lightning.lnd"
    };
    let ln = crate::make_backend(config).await;
    match ln.node_info().await {
        Ok(info) => {
            report.push(Check::pass(
                name,
                format!("{} (alias {})", info.pubkey, info.alias),
            ));
            // A node on another chain is the failure that costs money rather than time: it would
            // settle a Lightning leg against an on-chain leg nobody else is looking at.
            match (network, info.chain_network.as_deref()) {
                (Some(want), Some(reported)) => match crate::lnd_network_to_bitcoin(reported) {
                    Some(got) if got != want => report.push(Check::fail(
                        "chain.agreement",
                        format!("configured for {want:?} but the node is on {got:?} ({reported})"),
                        "point this daemon at a node on the same chain, or change --network",
                    )),
                    Some(got) => {
                        report.push(Check::pass("chain.agreement", format!("both on {got:?}")))
                    }
                    None => report.push(Check::warn(
                        "chain.agreement",
                        format!("the node reports an unrecognised network '{reported}'"),
                    )),
                },
                _ => report.push(Check::warn(
                    "chain.agreement",
                    "the node did not report a chain network",
                )),
            }
            if !info.synced_to_chain {
                report.push(Check::warn(
                    "lightning.sync",
                    "the node is not synced to chain yet",
                ));
            }
        }
        Err(e) => {
            let remedy = if config.lightning_backend == "beignet" {
                format!(
                    "check that a beignet daemon is reachable at {} and that its API token is \
                     set (PUBKY_SWAP_BEIGNET_TOKEN__VALUE or BEIGNET_API_TOKEN)",
                    config.beignet_url
                )
            } else {
                lnd_remedy(config, network)
            };
            report.push(Check::fail(name, e.to_string(), remedy));
        }
    }
}

/// What to try when LND cannot be reached, naming credentials that are actually on this machine.
fn lnd_remedy(config: &crate::ProviderConfig, network: Option<bitcoin::Network>) -> String {
    let mut out = format!(
        "could not reach LND at {}. Check the address, the TLS certificate and the macaroon.",
        config.lnd_address
    );
    let candidates =
        lightning_backend::discover::lnd_candidates(network.unwrap_or(bitcoin::Network::Bitcoin));
    if candidates.is_empty() {
        return out;
    }
    out.push_str("\nCredentials found on this machine:");
    for c in candidates.iter().take(3) {
        out.push_str(&format!(
            "\n  {} -> --lnd-address {} --lnd-cert {} --lnd-macaroon {}",
            c.label,
            c.address,
            c.cert.display(),
            c.macaroon.display()
        ));
    }
    out
}

async fn check_chain(
    config: &crate::ProviderConfig,
    network: Option<bitcoin::Network>,
    report: &mut Report,
) {
    if config.electrum_url.is_empty() {
        report.push(Check::fail(
            "chain.electrum",
            "no Electrum server configured",
            electrum_remedy(network),
        ));
        return;
    }
    // Feature-absent and connect-failed are different problems with different answers, and
    // reporting one as the other sends an operator to rebuild a binary that is fine.
    if !cfg!(feature = "chain") {
        report.push(Check::fail(
            "chain.electrum",
            "this build has no chain watcher",
            "rebuild with --features full",
        ));
        return;
    }
    match crate::build_chain(config) {
        Some(chain) => match swap_common::chain::run_blocking(|| chain.tip_height()) {
            Ok(tip) => report.push(Check::pass(
                "chain.electrum",
                format!("{} at height {tip}", config.electrum_url),
            )),
            Err(e) => report.push(Check::fail(
                "chain.electrum",
                format!("{} answered: {e}", config.electrum_url),
                electrum_remedy(network),
            )),
        },
        None => report.push(Check::fail(
            "chain.electrum",
            format!("could not connect to {}", config.electrum_url),
            electrum_remedy(network),
        )),
    }
}

fn electrum_remedy(network: Option<bitcoin::Network>) -> String {
    let candidates = lightning_backend::discover::electrum_candidates(
        network.unwrap_or(bitcoin::Network::Bitcoin),
    );
    let mut out = String::from("set --electrum-url to a reachable Electrum server.");
    if !candidates.is_empty() {
        out.push_str(&format!(
            "\nCommon ones for this network: {}",
            candidates.join(", ")
        ));
    }
    out
}

async fn check_wallet(config: &crate::ProviderConfig, report: &mut Report) {
    let network = match crate::parse_network(&config.network) {
        Ok(n) => n,
        Err(_) => return,
    };
    match crate::build_wallet(config, crate::build_chain(config)).await {
        Some(wallet) => {
            let backend = config.wallet_backend.clone();
            match swap_common::chain::run_blocking(|| wallet.spendable_balance_sat()) {
                Ok(Some(sats)) => {
                    let check = Check::pass("wallet", format!("{backend}: {sats} sat spendable"));
                    // Not a failure: an operator may be funding it right now. But a provider with
                    // less than its own reserve cannot honour a reverse swap.
                    if sats < config.min_onchain_reserve_sat {
                        report.push(Check::warn(
                            "wallet",
                            format!(
                                "{backend}: {sats} sat spendable, below the {} sat reserve",
                                config.min_onchain_reserve_sat
                            ),
                        ));
                    } else {
                        report.push(check);
                    }
                }
                Ok(None) => report.push(Check::pass(
                    "wallet",
                    format!("{backend}: connected (it does not report a balance)"),
                )),
                Err(e) => report.push(Check::fail(
                    "wallet",
                    format!("{backend}: {e}"),
                    "check the wallet's Electrum server and, for --wallet bdk, its mnemonic",
                )),
            }
        }
        None => report.push(Check::fail(
            "wallet",
            format!("the {} wallet is not available", config.wallet_backend),
            match config.wallet_backend.as_str() {
                "bdk" => "set PUBKY_SWAP_WALLET_MNEMONIC__FILE to a file holding the BIP39 \
                          mnemonic, and --electrum-url to a reachable server"
                    .to_string(),
                other => format!(
                    "--wallet {other} needs that backend reachable; see the lightning check above"
                ),
            },
        )),
    }
    let _ = network;
}

#[cfg(test)]
mod diagnose_tests {
    use super::*;

    /// The checks that need nothing but the configuration itself, on a config that has none of it.
    ///
    /// The point of the assertions is not the wording: it is that a daemon which cannot start
    /// says which of the things it needs is missing, and what to do about each. Before this, all
    /// of these were `warn!` lines and the daemon carried on serving quotes it could not honour.
    #[tokio::test]
    async fn a_bare_configuration_reports_what_is_missing_and_what_to_do() {
        let config = crate::ProviderConfig {
            data_dir: std::env::temp_dir()
                .join(format!("pubky-swap-doctor-{}", std::process::id()))
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        };
        let report = diagnose(&config).await;

        assert!(
            !report.is_capable(),
            "nothing is configured, so it cannot run"
        );
        let named = |name: &str| report.checks.iter().find(|c| c.name == name).cloned();

        // The identity is the first thing an operator has to supply, and the one with no flag.
        let identity = named("identity").expect("identity is checked");
        assert_eq!(identity.status, Status::Fail);
        let remedy = identity.remedy.unwrap_or_default();
        assert!(
            remedy.contains("PUBKY_SWAP_RECOVERY_PHRASE__FILE"),
            "the remedy names the way to supply it: {remedy}"
        );
        assert!(
            remedy.contains("no flag"),
            "and says why there is no flag for it: {remedy}"
        );

        // Parameters and the data directory are checkable without touching the network, so they
        // pass here: this is a config that is incomplete, not one that is wrong.
        assert_eq!(named("timelocks").map(|c| c.status), Some(Status::Pass));
        assert_eq!(named("data-dir").map(|c| c.status), Some(Status::Pass));

        // And every failure carries a remedy, which is the invariant the whole report exists for.
        for check in report.checks.iter().filter(|c| c.status == Status::Fail) {
            assert!(
                check.remedy.is_some(),
                "the {} check failed without saying what to do",
                check.name
            );
        }
    }

    /// A network nobody can serve is caught before anything tries to use it.
    #[tokio::test]
    async fn an_unknown_network_is_a_failure_with_the_list_of_real_ones() {
        let config = crate::ProviderConfig {
            network: "mainet".to_string(),
            ..Default::default()
        };
        let report = diagnose(&config).await;
        let network = report
            .checks
            .iter()
            .find(|c| c.name == "network")
            .expect("network is checked");
        assert_eq!(network.status, Status::Fail);
        assert!(network
            .remedy
            .as_deref()
            .unwrap_or_default()
            .contains("regtest"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A diagnostic that does not say how to fix the problem has only told the operator they
    /// have one, so every failure must carry a remedy.
    #[test]
    fn every_failure_carries_something_to_do_about_it() {
        let mut report = Report::default();
        report.push(Check::pass("identity", "signed in"));
        report.push(Check::fail(
            "lnd.connect",
            "connection refused",
            "check --lnd-address points at a running node",
        ));
        report.push(Check::warn("chain.agreement", "electrs is 3 blocks behind"));

        for check in &report.checks {
            if check.status == Status::Fail {
                assert!(
                    check.remedy.is_some(),
                    "the {} failure has no remedy",
                    check.name
                );
            }
        }
        assert_eq!(report.failures(), 1);
        assert_eq!(report.warnings(), 1);
        assert!(!report.is_capable());

        let rendered = report.render();
        assert!(rendered.contains("FAIL"));
        assert!(rendered.contains("--lnd-address"));
        assert!(rendered.contains("1 failed, 1 warning"));
    }

    #[test]
    fn a_report_with_only_warnings_is_still_capable() {
        let mut report = Report::default();
        report.push(Check::pass("identity", "ok"));
        report.push(Check::warn("wallet", "balance is low"));
        assert!(report.is_capable());
    }
}
