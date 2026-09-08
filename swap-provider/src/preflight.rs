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
