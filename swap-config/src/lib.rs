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
#[derive(Debug, Clone, Default, Serialize)]
pub struct SecretSource {
    /// The value itself. Settable from the environment or a config file; never from a flag.
    pub value: Secret,
    /// A file holding the value, whose first line is read and trimmed.
    pub file: String,
}

/// Accepts either the struct or a bare string.
///
/// `PUBKY_SWAP_RECOVERY_PHRASE=<phrase>` is the name an operator reaches for; the `__VALUE`
/// suffix is a consequence of this being a two-field struct, not something anyone would guess.
/// Before this, that spelling was a type error, and figment's type errors quote the offending
/// value: the seed went to stderr, which on a packaged install is the app's log.
///
/// Taking the bare string is the fix rather than a nicety. It removes the error, and with it the
/// only way that particular mistake could print a secret.
impl<'de> Deserialize<'de> for SecretSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Fields {
            value: Secret,
            file: String,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Inline(String),
            Fields(Fields),
        }

        Ok(match Either::deserialize(d)? {
            Either::Inline(value) => SecretSource {
                value: Secret::new(value),
                file: String::new(),
            },
            Either::Fields(f) => SecretSource {
                value: f.value,
                file: f.file,
            },
        })
    }
}

impl SecretSource {
    /// Whether a secret has been configured at all, without reading it.
    ///
    /// Callers that only need to know "is this backend usable" should not have to open a file,
    /// and should not have the value in a local while they decide.
    pub fn is_configured(&self) -> bool {
        !self.value.is_empty() || !self.file.is_empty()
    }

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

/// Pubky identity material, resolved from wherever the operator configured it.
///
/// Both binaries need this and both used to do it inline, in slightly different ways: the "one of
/// a file or a phrase, not both" rule was stated twice and could have drifted, and each of the
/// three call sites read the secret separately.
pub struct Identity {
    /// `"file"` or `"phrase"`, as `pubky-transport` names them.
    pub method: &'static str,
    /// A file path when `method` is `"file"`, and the recovery phrase itself when it is
    /// `"phrase"`. Redacted in `Debug` either way, because one of the two is a seed.
    pub value: String,
    pub passphrase: String,
}

impl std::fmt::Debug for Identity {
    /// Written by hand. A derived one prints the recovery phrase, and this is the sort of value
    /// that ends up in a `warn!` while someone is working out why a daemon will not start.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("method", &self.method)
            .field(
                "value",
                &match self.method {
                    "file" => self.value.as_str(),
                    _ => "<redacted>",
                },
            )
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// Resolve an identity, or say precisely what is missing.
pub fn resolve_identity(
    recovery_file: &str,
    recovery_phrase: &SecretSource,
    passphrase: &SecretSource,
) -> Result<Identity> {
    let phrase = recovery_phrase.resolve("the recovery phrase")?;
    let passphrase = passphrase
        .resolve("the passphrase")?
        .map(|s| s.expose().to_string())
        .unwrap_or_default();
    match (!recovery_file.is_empty(), phrase) {
        (true, None) => Ok(Identity {
            method: "file",
            value: recovery_file.to_string(),
            passphrase,
        }),
        (false, Some(phrase)) => Ok(Identity {
            method: "phrase",
            value: phrase.expose().to_string(),
            passphrase,
        }),
        (true, Some(_)) => anyhow::bail!(
            "both a recovery file and a recovery phrase are configured; use exactly one"
        ),
        (false, None) => anyhow::bail!(
            "no Pubky identity configured. Set PUBKY_SWAP_RECOVERY_PHRASE__FILE to a file \
             holding the phrase, or PUBKY_SWAP_RECOVERY_PHRASE__VALUE, or pass a recovery file \
             path as the first argument"
        ),
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

    figment.extract().map_err(redact_config_error)
}

/// Turn a figment error into one that cannot contain a configuration value.
///
/// figment's messages quote what it found: `invalid type: found string "abandon abandon ..."`.
/// That is the right message for a port number and the wrong one for a seed, and the layer that
/// raises it does not know which it is holding. A packaged install makes it worse: the message
/// goes to stderr, which is the app's log buffer, which the dashboard renders.
///
/// So no value is quoted, whatever the key. What an operator needs is the key and what was
/// expected there, and both survive. The one thing lost is being able to see the offending value
/// in the error, which is not a thing to want from a file that holds seeds.
fn redact_config_error(err: figment::Error) -> anyhow::Error {
    let mut lines = Vec::new();
    for e in err {
        let where_ = if e.path.is_empty() {
            String::new()
        } else {
            format!(" for `{}`", e.path.join("."))
        };
        let source = e
            .metadata
            .as_ref()
            .map(|m| format!(" (from {})", m.name))
            .unwrap_or_default();
        lines.push(match &e.kind {
            // The three kinds that carry a value. `Actual` renders the value itself, so only its
            // shape is reported.
            figment::error::Kind::InvalidType(actual, expected) => format!(
                "invalid type{where_}{source}: expected {expected}, found {}",
                actual_shape(actual)
            ),
            figment::error::Kind::InvalidValue(actual, expected) => format!(
                "invalid value{where_}{source}: expected {expected}, found {}",
                actual_shape(actual)
            ),
            figment::error::Kind::Unsupported(actual) => {
                format!(
                    "unsupported value{where_}{source}: {}",
                    actual_shape(actual)
                )
            }
            figment::error::Kind::UnsupportedKey(actual, expected) => format!(
                "unsupported key{where_}{source}: expected {expected}, found {}",
                actual_shape(actual)
            ),
            // Everything else names keys and types, not values.
            other => format!("{other}{where_}{source}"),
        });
    }
    if lines.is_empty() {
        lines.push("the configuration could not be assembled".into());
    }
    anyhow::anyhow!(lines.join("; ")).context("assembling the configuration")
}

/// The shape of a value, never the value.
fn actual_shape(actual: &figment::error::Actual) -> &'static str {
    use figment::error::Actual;
    match actual {
        Actual::Bool(_) => "a boolean",
        Actual::Unsigned(_) | Actual::Signed(_) => "an integer",
        Actual::Float(_) => "a decimal",
        Actual::Char(_) => "a character",
        Actual::Str(_) => "a string",
        Actual::Bytes(_) => "bytes",
        Actual::Unit => "a unit",
        Actual::Option => "an option",
        Actual::NewtypeStruct | Actual::NewtypeVariant => "a newtype",
        Actual::Seq | Actual::TupleVariant => "a list",
        Actual::Map | Actual::StructVariant => "a table",
        Actual::Enum | Actual::UnitVariant => "an enum",
        // `Other` carries a free-form description that may quote a value, so it is not printed.
        Actual::Other(_) => "a value of another type",
    }
}

/// Render a configuration as TOML, with secrets redacted.
///
/// Safe to print or paste into an issue: [`Secret`] serializes as `<redacted>`.
pub fn to_redacted_toml<T: Serialize>(config: &T) -> Result<String> {
    toml::to_string_pretty(config).context("rendering the configuration")
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn phrase(value: &str) -> SecretSource {
        SecretSource {
            value: Secret::new(value),
            file: String::new(),
        }
    }

    #[test]
    fn a_phrase_and_a_file_are_told_apart() {
        let id = resolve_identity("", &phrase("twelve words"), &SecretSource::default()).unwrap();
        assert_eq!(id.method, "phrase");
        assert_eq!(id.value, "twelve words");

        let id = resolve_identity(
            "/tmp/recovery.pkarr",
            &SecretSource::default(),
            &SecretSource::default(),
        )
        .unwrap();
        assert_eq!(id.method, "file");
        assert_eq!(id.value, "/tmp/recovery.pkarr");
    }

    /// Two identities configured at once is ambiguous, and guessing which the operator meant is
    /// how a daemon comes up as the wrong pubky and advertises to nobody.
    #[test]
    fn configuring_both_is_refused() {
        let err = resolve_identity(
            "/tmp/recovery.pkarr",
            &phrase("twelve words"),
            &SecretSource::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "{err}");
    }

    /// And the message for none of them says what to actually do, because a daemon that will not
    /// start is the moment an operator most needs the answer.
    #[test]
    fn configuring_neither_says_how_to_fix_it() {
        let err =
            resolve_identity("", &SecretSource::default(), &SecretSource::default()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("PUBKY_SWAP_RECOVERY_PHRASE__FILE"), "{msg}");
    }

    /// The secret reaches the caller, and never reaches a log line on the way.
    #[test]
    fn a_resolved_identity_does_not_print_its_secret() {
        let source = phrase("correct horse battery staple");
        assert!(!format!("{source:?}").contains("correct horse"));
        assert!(!serde_json::to_string(&source)
            .unwrap()
            .contains("correct horse"));
        let id = resolve_identity("", &source, &SecretSource::default()).unwrap();
        assert_eq!(id.value, "correct horse battery staple");
        // And the resolved identity is just as quiet, which is where it matters: this is the
        // value that reaches a `warn!` when a daemon cannot start.
        assert!(!format!("{id:?}").contains("correct horse"));
    }
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

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default, Serialize, Deserialize)]
    #[serde(default)]
    struct Conf {
        recovery_phrase: SecretSource,
        min_amount_sat: u64,
    }

    /// What the binaries pass when no flag was given: a struct whose every field is skipped.
    #[derive(Default, Serialize)]
    struct NoOverrides {}

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// The obvious spelling has to work, because the alternative is that it fails in a way that
    /// prints the value.
    ///
    /// `PUBKY_SWAP_RECOVERY_PHRASE=<phrase>` is what an operator reaches for; `__VALUE` is a
    /// consequence of the field being a two-field struct and is not something anyone would guess.
    #[test]
    #[allow(clippy::result_large_err)] // figment\'s Jail error type, not ours
    fn a_secret_can_be_given_as_a_bare_string() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PUBKY_SWAP_RECOVERY_PHRASE", PHRASE);
            let c: Conf = load(None, "PUBKY_SWAP_", &NoOverrides {}).unwrap();
            assert_eq!(c.recovery_phrase.value.expose(), PHRASE);
            assert!(c.recovery_phrase.file.is_empty());
            Ok(())
        });
    }

    /// And the explicit form still means what it meant.
    #[test]
    #[allow(clippy::result_large_err)] // figment\'s Jail error type, not ours
    fn the_explicit_forms_still_work() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PUBKY_SWAP_RECOVERY_PHRASE__VALUE", PHRASE);
            let c: Conf = load(None, "PUBKY_SWAP_", &NoOverrides {}).unwrap();
            assert_eq!(c.recovery_phrase.value.expose(), PHRASE);

            jail.clear_env();
            jail.set_env("PUBKY_SWAP_RECOVERY_PHRASE__FILE", "/tmp/somewhere");
            let c: Conf = load(None, "PUBKY_SWAP_", &NoOverrides {}).unwrap();
            assert_eq!(c.recovery_phrase.file, "/tmp/somewhere");
            assert!(c.recovery_phrase.value.is_empty());
            Ok(())
        });
    }

    /// No configuration error may quote a configuration value.
    ///
    /// figment reports what it found: `invalid type: found string "abandon abandon ..."`. That is
    /// right for a port and catastrophic for a seed, and the layer raising it cannot tell which
    /// it is holding. On a packaged install the message goes to stderr, which is the app's log
    /// buffer, which the dashboard renders.
    #[test]
    #[allow(clippy::result_large_err)] // figment\'s Jail error type, not ours
    fn a_failing_secret_never_reaches_the_error_message() {
        figment::Jail::expect_with(|jail| {
            // A shape `SecretSource` cannot accept, so the deserializer has to complain about
            // something that is a seed.
            jail.create_file(
                "c.toml",
                &format!("recovery_phrase = {{ value = {{ nested = \"{PHRASE}\" }} }}\n"),
            )?;
            let err = load::<Conf, _>(
                Some(std::path::Path::new("c.toml")),
                "NOTHING_",
                &NoOverrides {},
            )
            .expect_err("this cannot deserialize");
            let printed = format!("{err:#}");
            assert!(
                !printed.contains("abandon"),
                "the secret reached the error: {printed}"
            );
            Ok(())
        });
    }

    /// Redacting must not cost the operator the ability to fix their configuration: the key and
    /// the expected type are what they need, and neither is the value.
    /// The second line of defence, and the one that does not depend on knowing which keys hold
    /// secrets. figment quotes what it found for any key; a value that lands in the wrong field
    /// is a mistake an operator makes precisely when they are moving secrets around.
    #[test]
    #[allow(clippy::result_large_err)] // figment\'s Jail error type, not ours
    fn no_error_quotes_a_value_even_for_a_key_that_is_not_a_secret() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PUBKY_SWAP_MIN_AMOUNT_SAT", PHRASE);
            let err = load::<Conf, _>(None, "PUBKY_SWAP_", &NoOverrides {}).expect_err("not a u64");
            let printed = format!("{err:#}");
            assert!(
                !printed.contains("abandon"),
                "a secret pasted into the wrong key still reached the error: {printed}"
            );
            assert!(printed.contains("min_amount_sat"), "{printed}");
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment\'s Jail error type, not ours
    fn a_failing_value_still_says_which_key_and_what_was_expected() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("PUBKY_SWAP_MIN_AMOUNT_SAT", "not-a-number");
            let err = load::<Conf, _>(None, "PUBKY_SWAP_", &NoOverrides {})
                .expect_err("a string is not a u64");
            let printed = format!("{err:#}");
            assert!(printed.contains("min_amount_sat"), "{printed}");
            assert!(printed.contains("u64"), "{printed}");
            assert!(printed.contains("found a string"), "{printed}");
            assert!(
                !printed.contains("not-a-number"),
                "the value is not quoted, even a harmless one: {printed}"
            );
            Ok(())
        });
    }
}
