//! Admission policy for authenticated Pubky accounts. Existing swaps remain recoverable.

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{collections::HashSet, io::Read};

const MAX_BYTES: u64 = 65_536;
const MAX_KEYS: usize = 256;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Open,
    ApprovedOnly,
}

/// All fields are required in a configured file to avoid silently relaxing a broken policy.
#[derive(Debug, Default)]
pub struct Policy {
    mode: Mode,
    allowed: HashSet<String>,
    blocked: HashSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    mode: Mode,
    allowed: Vec<String>,
    blocked: Vec<String>,
}

impl Policy {
    /// An absent setting preserves public service. An unreadable configured file fails closed.
    pub fn load(path: Option<&str>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .context("open access policy")?
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read access policy")?;
        ensure!(
            bytes.len() as u64 <= MAX_BYTES,
            "access policy is too large"
        );
        let policy: PolicyFile = serde_json::from_slice(&bytes).context("parse access policy")?;
        Ok(Self {
            mode: policy.mode,
            allowed: normalize(policy.allowed, "allowed")?,
            blocked: normalize(policy.blocked, "blocked")?,
        })
    }

    /// Allowlist membership follows the verified account; either identity can be blocked.
    pub fn allows_request(&self, account: &str, sender: &str) -> bool {
        let Ok(sender) = pubky_transport::canonical_pubky(sender) else {
            return false;
        };
        self.allows(account) && !self.blocked.contains(&sender)
    }

    pub fn allows(&self, account: &str) -> bool {
        let Ok(key) = pubky_transport::canonical_pubky(account) else {
            return false;
        };
        !self.blocked.contains(&key)
            && (matches!(self.mode, Mode::Open) || self.allowed.contains(&key))
    }
}

fn normalize(keys: Vec<String>, list: &str) -> Result<HashSet<String>> {
    ensure!(
        keys.len() <= MAX_KEYS,
        "access list exceeds {MAX_KEYS} pubkys"
    );
    keys.into_iter()
        .enumerate()
        .map(|(index, key)| {
            pubky_transport::canonical_pubky(&key)
                .with_context(|| format!("invalid {list} pubky at entry {}", index + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_policy_is_strict_and_blocked_accounts_take_precedence() {
        let path = std::env::temp_dir().join(format!("access-{}.json", uuid::Uuid::new_v4()));
        let key = pubky_transport::identity_from_secret(&[41; 32]);
        let other = pubky_transport::identity_from_secret(&[42; 32]);
        let load = || Policy::load(Some(path.to_str().unwrap()));
        let write = |value: serde_json::Value| std::fs::write(&path, value.to_string()).unwrap();
        assert!(Policy::load(None).unwrap().allows(&key));
        assert!(load().is_err());
        write(serde_json::json!({"mode":"approved_only","allowed":[],"blocked":[]}));
        assert!(!load().unwrap().allows(&key));
        write(
            serde_json::json!({"mode":"approved_only","allowed":[format!("pubky://{key}")],"blocked":[]}),
        );
        assert!(load().unwrap().allows(&key));
        assert!(!load().unwrap().allows(&other));
        for mode in ["open", "approved_only"] {
            write(serde_json::json!({"mode":mode,"allowed":[key],"blocked":[key]}));
            assert!(!load().unwrap().allows(&key));
        }
        for value in [
            serde_json::json!({}),
            serde_json::json!({"mode":"typo","allowed":[],"blocked":[]}),
            serde_json::json!({"mode":"open","allowed":[],"blocked":["bad-key"]}),
            serde_json::json!({"mode":"open","allowed":[],"blocked":[],"typo":true}),
        ] {
            write(value);
            assert!(load().is_err());
        }
        std::fs::write(&path, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        assert!(load().is_err());
        std::fs::remove_file(path).unwrap();
    }
}
