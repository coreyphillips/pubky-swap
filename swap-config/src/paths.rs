//! Where a configuration file lives.

use std::path::PathBuf;

/// Resolve the configuration file to use, in order of specificity.
///
/// 1. `--config <path>`
/// 2. `$PUBKY_SWAP_CONFIG`
/// 3. `$PUBKY_SWAP_DATA_DIR/config.toml` (how the container is wired)
/// 4. `$XDG_CONFIG_HOME/pubky-swap/config.toml`, else `~/.config/pubky-swap/config.toml`
/// 5. `./pubky-swap.toml`
///
/// Returns the first that exists, or the most specific candidate when none do, so a caller
/// creating a file has somewhere sensible to put it.
pub fn resolve_config_path(explicit: Option<&str>) -> PathBuf {
    if let Some(path) = explicit.filter(|p| !p.is_empty()) {
        return PathBuf::from(path);
    }
    let candidates = candidates();
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .unwrap_or_else(|| candidates.into_iter().next().unwrap_or_default())
}

fn candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(path) = std::env::var("PUBKY_SWAP_CONFIG") {
        if !path.is_empty() {
            out.push(PathBuf::from(path));
        }
    }
    if let Ok(dir) = std::env::var("PUBKY_SWAP_DATA_DIR") {
        if !dir.is_empty() {
            out.push(PathBuf::from(dir).join("config.toml"));
        }
    }
    if let Some(dir) = config_home() {
        out.push(dir.join("pubky-swap").join("config.toml"));
    }
    out.push(PathBuf::from("pubky-swap.toml"));
    out
}

fn config_home() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".config"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_path_wins_over_everything() {
        assert_eq!(
            resolve_config_path(Some("/tmp/explicit.toml")),
            PathBuf::from("/tmp/explicit.toml")
        );
        // An empty string is "not given", not a path.
        assert_ne!(resolve_config_path(Some("")), PathBuf::new());
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment's Jail error type, not ours
    fn a_data_directory_gives_the_container_a_natural_home() {
        figment::Jail::expect_with(|jail| {
            std::fs::create_dir_all("data").unwrap();
            jail.create_file("data/config.toml", "network = \"regtest\"\n")?;
            jail.set_env("PUBKY_SWAP_DATA_DIR", "data");
            assert_eq!(
                resolve_config_path(None),
                PathBuf::from("data").join("config.toml")
            );
            Ok(())
        });
    }
}
