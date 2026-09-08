//! Layered configuration: CLI over environment over file over defaults.
//!
//! Every setting used to be a command-line flag and nothing else, which has two problems.
//!
//! The first is secrets. `--recovery-phrase "<twelve words>"` puts a seed in the process's argv,
//! which anything on the machine can read out of the process table, and which lands in shell
//! history on the way there. A daemon that needs a seed should be able to read it from a file
//! with restrictive permissions, or from its environment, without the operator having to think
//! about it.
//!
//! The second is packaging. A container has environment variables, not a hand-typed argv, and an
//! Umbrel app has a compose file. Neither can express a long flag list, and neither should have
//! to.
//!
//! So: a TOML file for the settings that persist, environment variables for what a deployment
//! injects, and flags on top for what an operator types once. Secrets are wrapped in [`Secret`],
//! which redacts in `Debug`, `Display` **and** `Serialize`, so a config dump cannot leak one.

pub mod paths;
pub mod secret;

pub use secret::Secret;

use anyhow::{Context, Result};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Where a secret comes from.
///
/// Deliberately several options, because the right one differs by deployment: a systemd unit has
/// `LoadCredential`, a container has environment variables, and someone running it by hand has a
/// file. What none of them should need is the command line.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretSource {
    /// The value itself. Settable from the environment or a config file; never from a flag.
    pub value: Secret,
    /// A file holding the value, whose first line is read and trimmed.
    pub file: String,
}

impl SecretSource {
    /// Resolve to the actual value, reading the file if that is where it lives.
    pub fn resolve(&self, what: &str) -> Result<Option<Secret>> {
        if !self.value.is_empty() {
            return Ok(Some(self.value.clone()));
        }
        if self.file.is_empty() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&self.file)
            .with_context(|| format!("read {what} from {}", self.file))?;
        warn_if_world_readable(&self.file);
        let trimmed = raw.lines().next().unwrap_or("").trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("{} is empty, so there is no {what} to read", self.file);
        }
        Ok(Some(Secret::new(trimmed)))
    }
}

/// Complain about a secret file anyone can read.
///
/// Not fatal: an operator may have deliberate reasons, and refusing to start over a permission
/// bit would be worse than saying so. But it should never pass unremarked.
fn warn_if_world_readable(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    "{path} is mode {mode:o}: it holds a secret and should be 0600. \
                     Run: chmod 600 {path}"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Load a configuration by layering, most specific last.
///
/// `cli_overrides` is serialized with `skip_serializing_if = "Option::is_none"` on every field, so
/// a flag the operator did not pass leaves the lower layers alone rather than overwriting them
/// with a null.
pub fn load<T, O>(config_path: Option<&Path>, env_prefix: &str, cli_overrides: &O) -> Result<T>
where
    T: Default + Serialize + for<'de> Deserialize<'de>,
    O: Serialize,
{
    let mut figment = Figment::from(Serialized::defaults(T::default()));

    if let Some(path) = config_path {
        if path.exists() {
            figment = figment.merge(Toml::file(path));
            tracing::debug!("loaded configuration from {}", path.display());
        }
    }

    // `__` separates nesting, so PUBKY_SWAP_LND__ADDRESS reaches `lnd.address`.
    figment = figment.merge(Env::prefixed(env_prefix).split("__"));
    figment = figment.merge(Serialized::defaults(cli_overrides));

    figment.extract().context("assembling the configuration")
}

/// Render a configuration as TOML, with secrets redacted.
///
/// Safe to print or paste into an issue: [`Secret`] serializes as `<redacted>`.
pub fn to_redacted_toml<T: Serialize>(config: &T) -> Result<String> {
    toml::to_string_pretty(config).context("rendering the configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct Demo {
        network: String,
        amount: u64,
        nested: Nested,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct Nested {
        url: String,
        secret: Secret,
    }

    impl Default for Demo {
        fn default() -> Self {
            Self {
                network: "regtest".into(),
                amount: 10,
                nested: Nested {
                    url: "http://default".into(),
                    secret: Secret::default(),
                },
            }
        }
    }

    impl Default for Nested {
        fn default() -> Self {
            Demo::default().nested
        }
    }

    #[derive(Default, Serialize)]
    struct Overrides {
        #[serde(skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        amount: Option<u64>,
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment's Jail error type, not ours
    fn layers_apply_in_order_and_absent_flags_leave_lower_layers_alone() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "config.toml",
                r#"
                network = "signet"
                amount = 20
                [nested]
                url = "http://from-file"
                "#,
            )?;
            // The environment wins over the file...
            jail.set_env("DEMO_AMOUNT", "30");
            jail.set_env("DEMO_NESTED__URL", "http://from-env");

            // ...and a flag wins over both. `network` is not passed, so the file's value stands
            // rather than being clobbered by a null.
            let overrides = Overrides {
                network: None,
                amount: Some(40),
            };
            let cfg: Demo = load(Some(Path::new("config.toml")), "DEMO_", &overrides).unwrap();

            assert_eq!(cfg.network, "signet", "the file's value must survive");
            assert_eq!(cfg.amount, 40, "the flag must win");
            assert_eq!(
                cfg.nested.url, "http://from-env",
                "the environment must win"
            );
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment's Jail error type, not ours
    fn defaults_stand_when_nothing_else_is_set() {
        figment::Jail::expect_with(|_| {
            let cfg: Demo = load(None, "DEMO_", &Overrides::default()).unwrap();
            assert_eq!(cfg, Demo::default());
            Ok(())
        });
    }

    /// A rendered config is something an operator will paste into an issue, so it must not carry
    /// the seed that funds the wallet.
    #[test]
    fn rendering_a_config_redacts_its_secrets() {
        let cfg = Demo {
            nested: Nested {
                url: "http://x".into(),
                secret: Secret::new("abandon abandon abandon"),
            },
            ..Demo::default()
        };
        let rendered = to_redacted_toml(&cfg).unwrap();
        assert!(!rendered.contains("abandon"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("http://x"));
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment's Jail error type, not ours
    fn a_secret_can_come_from_a_file() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("seed.txt", "  abandon abandon about  \n")?;
            let source = SecretSource {
                value: Secret::default(),
                file: "seed.txt".into(),
            };
            let resolved = source.resolve("recovery phrase").unwrap().unwrap();
            assert_eq!(resolved.expose(), "abandon abandon about");
            Ok(())
        });
    }

    #[test]
    fn an_inline_value_wins_over_a_file_and_a_missing_one_is_not_an_error() {
        let inline = SecretSource {
            value: Secret::new("inline"),
            file: "does-not-exist".into(),
        };
        assert_eq!(inline.resolve("x").unwrap().unwrap().expose(), "inline");

        let neither = SecretSource::default();
        assert!(neither.resolve("x").unwrap().is_none());

        let missing = SecretSource {
            value: Secret::default(),
            file: "definitely-not-here".into(),
        };
        assert!(
            missing.resolve("x").is_err(),
            "a named file that is absent is an error"
        );
    }
}
