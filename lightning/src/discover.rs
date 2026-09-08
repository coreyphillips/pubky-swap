//! Finding an existing node's credentials.
//!
//! Pointing pubky-swap at a node you already run means naming a gRPC address, a TLS certificate
//! and a macaroon. Those live in well-known places, and which place depends on how the node was
//! installed rather than on anything the operator chose. Asking them to find three paths in an
//! Umbrel data directory is asking them to do a lookup we can do ourselves.
//!
//! Nothing here connects. It reports what exists on disk, so `init` can propose a configuration
//! and `doctor` can say "these are the places I looked".

use bitcoin::Network;
use std::path::{Path, PathBuf};

/// A set of LND credentials that appears to be present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LndCandidate {
    /// Where this came from, for the operator's benefit.
    pub label: &'static str,
    pub address: String,
    pub cert: PathBuf,
    pub macaroon: PathBuf,
}

/// LND's own name for a network, which is what appears in its directory layout.
fn lnd_chain_dir(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        _ => "regtest",
    }
}

fn home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// Credential sets that exist on this machine, most likely first.
///
/// A candidate is only returned when both files are actually readable, so a caller can propose
/// one without a second round of checks.
pub fn lnd_candidates(network: Network) -> Vec<LndCandidate> {
    let chain = lnd_chain_dir(network);
    let macaroon_rel = format!("data/chain/bitcoin/{chain}/admin.macaroon");
    let mut roots: Vec<(&'static str, PathBuf, String)> = Vec::new();

    // A container that has been given the node's data directory read-only. Checked first because
    // when it is present it is unambiguous.
    roots.push((
        "bind-mounted LND data directory",
        PathBuf::from("/lnd"),
        "https://127.0.0.1:10009".into(),
    ));

    if let Some(home) = home() {
        roots.push((
            "Umbrel",
            home.join("umbrel/app-data/lightning/data/lnd"),
            // Umbrel's own exported address for the lightning app.
            "https://10.21.21.9:10009".into(),
        ));
        roots.push((
            "Umbrel (0.5.x layout)",
            home.join("umbrel/lnd"),
            "https://10.21.21.9:10009".into(),
        ));
        roots.push((
            "default LND directory",
            home.join(".lnd"),
            "https://127.0.0.1:10009".into(),
        ));
        roots.push((
            "macOS LND directory",
            home.join("Library/Application Support/Lnd"),
            "https://127.0.0.1:10009".into(),
        ));
    }

    if let Ok(dir) = std::env::var("LND_DIR") {
        if !dir.is_empty() {
            roots.insert(
                0,
                (
                    "LND_DIR",
                    PathBuf::from(dir),
                    "https://127.0.0.1:10009".into(),
                ),
            );
        }
    }

    let mut found: Vec<LndCandidate> = roots
        .into_iter()
        .filter_map(|(label, root, address)| {
            let cert = root.join("tls.cert");
            let macaroon = root.join(&macaroon_rel);
            (cert.is_file() && macaroon.is_file()).then_some(LndCandidate {
                label,
                address,
                cert,
                macaroon,
            })
        })
        .collect();

    // Polar puts each node under its own directory, so it needs a glob rather than a fixed path.
    if let Some(home) = home() {
        found.extend(polar_candidates(&home.join(".polar/networks"), chain));
    }
    found
}

fn polar_candidates(networks: &Path, chain: &str) -> Vec<LndCandidate> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(networks) else {
        return out;
    };
    for network_dir in entries.flatten() {
        let lnd_root = network_dir.path().join("volumes/lnd");
        let Ok(nodes) = std::fs::read_dir(&lnd_root) else {
            continue;
        };
        for node in nodes.flatten() {
            let cert = node.path().join("tls.cert");
            let macaroon = node
                .path()
                .join(format!("data/chain/bitcoin/{chain}/admin.macaroon"));
            if cert.is_file() && macaroon.is_file() {
                out.push(LndCandidate {
                    label: "Polar",
                    address: "https://127.0.0.1:10001".into(),
                    cert,
                    macaroon,
                });
            }
        }
    }
    out
}

/// Electrum servers worth trying, most likely first.
///
/// Unlike the LND candidates these cannot be checked without connecting, so they are suggestions
/// rather than findings.
pub fn electrum_candidates(network: Network) -> Vec<&'static str> {
    match network {
        Network::Regtest => vec![
            "tcp://127.0.0.1:60001",
            "tcp://127.0.0.1:50001",
            "tcp://electrs:60001",
        ],
        _ => vec![
            "tcp://127.0.0.1:50001",
            // Umbrel's exported address for the Electrs app.
            "tcp://10.21.21.10:50001",
            "tcp://umbrel.local:50001",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lnd_directory_layout_follows_the_network() {
        assert_eq!(lnd_chain_dir(Network::Bitcoin), "mainnet");
        assert_eq!(lnd_chain_dir(Network::Testnet), "testnet");
        assert_eq!(lnd_chain_dir(Network::Signet), "signet");
        assert_eq!(lnd_chain_dir(Network::Regtest), "regtest");
    }

    /// A candidate is only offered when both files are really there, so a caller can propose one
    /// without checking again.
    #[test]
    fn a_candidate_needs_both_files_present() {
        let dir = std::env::temp_dir().join(format!("pubky-swap-discover-{}", std::process::id()));
        let chain = dir.join("data/chain/bitcoin/regtest");
        std::fs::create_dir_all(&chain).unwrap();
        std::env::set_var("LND_DIR", &dir);

        // Only the certificate so far: not a candidate.
        std::fs::write(dir.join("tls.cert"), b"cert").unwrap();
        assert!(
            !lnd_candidates(Network::Regtest)
                .iter()
                .any(|c| c.label == "LND_DIR"),
            "a certificate with no macaroon is not usable"
        );

        std::fs::write(chain.join("admin.macaroon"), b"mac").unwrap();
        let found = lnd_candidates(Network::Regtest);
        let candidate = found
            .iter()
            .find(|c| c.label == "LND_DIR")
            .expect("both files present, so it should be offered");
        assert_eq!(candidate.cert, dir.join("tls.cert"));

        std::env::remove_var("LND_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn electrum_suggestions_differ_by_network() {
        assert!(electrum_candidates(Network::Regtest)[0].contains("60001"));
        assert!(electrum_candidates(Network::Bitcoin)
            .iter()
            .any(|c| c.contains("10.21.21.10")));
    }
}
