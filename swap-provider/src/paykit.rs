//! The provider's Paykit identity (feature `paykit`): `--paykit-setup`, the doctor's check, and
//! the `swap/1` Capability Descriptor it publishes.

use anyhow::Result;
use swap_common::cap_descriptor::DESCRIPTOR_PATH;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, info, warn};

use crate::descriptor::SharedDescriptors;
use crate::preflight::{Check, Report};
use crate::{ProviderConfig, SharedOffer};

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

/// Keep the `swap/1` Capability Descriptor on the homeserver describing the current offer.
///
/// Each rebuilt offer is written once. A failed write or sign-in is retried with a growing delay,
/// and nothing is written while the offer has expired, so the file lapses rather than lies.
pub(crate) fn spawn_descriptor_publisher(
    config: &ProviderConfig,
    offer: SharedOffer,
    book: SharedDescriptors,
    cap: &crate::cap_adapter::CapState,
) {
    const POLL: Duration = Duration::from_secs(5);
    const MAX_BACKOFF: Duration = Duration::from_secs(1800);
    // Signing in again checks the Paykit records again, so a rotated key generation reaches the
    // descriptor within this long, and a session the homeserver dropped is replaced before use.
    const SESSION_AGE: Duration = Duration::from_secs(3600);
    let secret = match identity_secret(config) {
        Ok(secret) => secret,
        Err(e) => return warn!("not publishing the swap/1 descriptor: {e:#}"),
    };
    let signer = cap.signer();
    let owner = cap.provider().to_string();
    tokio::spawn(async move {
        let mut writer: Option<(paykit_identity::DescriptorWriter, Instant)> = None;
        let mut backoff = POLL;
        let mut quiet = false;
        loop {
            if writer
                .as_ref()
                .is_some_and(|(_, since)| since.elapsed() > SESSION_AGE)
            {
                writer = None;
            }
            let current = offer.read().await.clone();
            let stale = match &current {
                Some(o) => book.read().await.needs_rewrite(o),
                None => false,
            };
            // An offer the refresher failed to renew has nothing current to describe.
            let Some(current) = current.filter(|o| stale && o.valid_until_unix > crate::now_unix())
            else {
                sleep(POLL).await;
                continue;
            };
            let outcome = async {
                if writer.is_none() {
                    let session = paykit_identity::DescriptorWriter::sign_in(&secret).await?;
                    writer = Some((session, Instant::now()));
                }
                let (session, _) = writer.as_ref().expect("signed in above");
                let (descriptor, bytes) = book.write().await.next(
                    &current,
                    &owner,
                    session.generation(),
                    signer.as_ref(),
                    crate::now_unix(),
                )?;
                session.put(DESCRIPTOR_PATH, bytes).await?;
                anyhow::Ok(descriptor)
            }
            .await;
            match outcome {
                Ok(descriptor) => {
                    // Every refresh rewrites it, so only the first after a failure is news.
                    let message = format!(
                        "published the swap/1 descriptor: seq {}, offer {}, minimum {} sat, \
                         valid until {}",
                        descriptor.seq,
                        current.offer_id,
                        current.effective_min_amount_sat(),
                        descriptor.valid_until
                    );
                    if quiet {
                        debug!("{message}");
                    } else {
                        info!("{message}");
                        quiet = true;
                    }
                    book.write().await.published(descriptor);
                    backoff = POLL;
                    sleep(POLL).await;
                }
                Err(e) => {
                    // A session can lapse, and the Paykit records can be rotated or removed:
                    // sign in again, checking them, before the next write.
                    writer = None;
                    quiet = false;
                    warn!(
                        "could not publish the swap/1 descriptor, retrying in {}s: {e:#}",
                        backoff.as_secs()
                    );
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    });
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
