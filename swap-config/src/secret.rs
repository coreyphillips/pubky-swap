//! A string that does not print itself.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A configuration value that must not reach a log line.
///
/// `Debug`, `Display` and `Serialize` all redact. Serialization matters as much as the others: a
/// `config show` command, or anything that round-trips the config to disk for inspection, would
/// otherwise write a seed out in the clear. Reading is unaffected, so a config file still loads
/// normally.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The only way to get the value out. Deliberately named so it is visible in review.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() {
            "Secret(empty)"
        } else {
            "Secret(<redacted>)"
        })
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "" } else { "<redacted>" })
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret)
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0.is_empty() {
            s.serialize_str("")
        } else {
            s.serialize_str("<redacted>")
        }
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_never_prints_itself() {
        let s = Secret::new("abandon abandon abandon about");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(format!("{s}"), "<redacted>");
        // Serialization too: a `config show` that round-trips would otherwise write the seed out.
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"<redacted>\"");
        // And it survives being inside a struct that derives Debug, which is the realistic leak.
        #[derive(Debug)]
        #[allow(dead_code)] // read only via the derived Debug, which is the point
        struct Config {
            phrase: Secret,
        }
        let printed = format!("{:?}", Config { phrase: s.clone() });
        assert!(!printed.contains("abandon"), "{printed}");
        // The value is still reachable where it is meant to be.
        assert_eq!(s.expose(), "abandon abandon abandon about");
    }

    #[test]
    fn an_empty_secret_says_so_rather_than_looking_set() {
        let s = Secret::default();
        assert_eq!(format!("{s:?}"), "Secret(empty)");
        assert!(s.is_empty());
    }
}
