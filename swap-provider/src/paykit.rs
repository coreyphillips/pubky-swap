//! The provider's Paykit identity (feature `paykit`): `--paykit-setup` and the doctor's check.

use anyhow::Result;

use crate::preflight::{Check, Report};
use crate::ProviderConfig;

fn identity_secret(config: &ProviderConfig) -> Result<[u8; 32]> {
    let id = config.identity()?;
    Ok(pubky_transport::identity::secret_from_recovery(
        id.method,
        &id.value,
        &id.passphrase,
    )?)
}

/// Publish the App Registry entry and the Noise Key Authorization, and say what changed.
pub async fn setup(config: &ProviderConfig, generation: Option<u64>) -> Result<String> {
    let report = paykit_identity::sign_in_and_setup(&identity_secret(config)?, generation).await?;
    Ok(format!(
        "Paykit generation {}, routing key {}\n  App Registry ({}): {:?}\n  Noise Key \
         Authorization: {:?}\n",
        report.generation,
        report.routing_key,
        paykit_identity::APP_ID,
        report.registry,
        report.authorization,
    ))
}

pub async fn check(config: &ProviderConfig, report: &mut Report) {
    // The identity check has already said what is wrong with a missing identity, but not with
    // one that is configured and does not decrypt.
    let secret = match identity_secret(config) {
        Ok(secret) => secret,
        Err(_) if config.identity().is_err() => return,
        Err(e) => {
            return report.push(Check::fail(
                "paykit",
                format!("cannot restore the identity secret: {e:#}"),
                "check the recovery file and its passphrase, or the recovery phrase",
            ))
        }
    };
    report.push(describe(paykit_identity::inspect_published(&secret).await));
}

fn describe(inspection: Result<paykit_identity::Inspection>) -> Check {
    let inspection = match inspection {
        Ok(inspection) => inspection,
        Err(e) => {
            return Check::warn(
                "paykit",
                format!("could not read the Paykit records: {e:#}"),
            )
        }
    };
    let Some(generation) = inspection.generation else {
        return Check::warn("paykit", "no Noise Key Authorization is published")
            .with_remedy("run swap-provider --paykit-setup once to publish it");
    };
    if !inspection.routing_key_matches {
        return Check::fail(
            "paykit",
            format!(
                "generation {generation}: the published routing key is not the one this \
                 identity derives"
            ),
            format!(
                "peers will reject what this provider signs. If you did not publish it, the \
                 identity secret has leaked. Otherwise rotate with swap-provider --paykit-setup \
                 --paykit-generation {}",
                generation.saturating_add(1)
            ),
        );
    }
    if !inspection.app_registered || !inspection.registry_matches {
        return Check::warn(
            "paykit",
            format!(
                "generation {generation}, routing key matches, but the App Registry does not \
                 list {} at this generation",
                paykit_identity::APP_ID
            ),
        )
        .with_remedy("rerun swap-provider --paykit-setup");
    }
    Check::pass(
        "paykit",
        format!("generation {generation}, routing key matches, App Registry lists pubky-swap"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preflight::Status;
    use paykit_identity::Inspection;

    fn inspection(generation: Option<u64>, routing_key_matches: bool) -> Inspection {
        Inspection {
            generation,
            routing_key_matches,
            app_registered: true,
            registry_matches: true,
        }
    }

    #[test]
    fn a_routing_key_mismatch_fails_the_doctor() {
        let check = describe(Ok(inspection(Some(3), false)));
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("generation 3"), "{}", check.detail);
        assert!(check
            .remedy
            .unwrap_or_default()
            .contains("--paykit-generation 4"));
    }

    #[test]
    fn a_matching_key_reports_its_generation() {
        let check = describe(Ok(inspection(Some(2), true)));
        assert_eq!(check.status, Status::Pass);
        assert!(check.detail.contains("generation 2"), "{}", check.detail);
    }

    #[test]
    fn an_unpublished_identity_is_a_warning() {
        let check = describe(Ok(inspection(None, false)));
        assert_eq!(check.status, Status::Warn);
        assert!(check.remedy.unwrap_or_default().contains("--paykit-setup"));
    }
}
