//! A read-only status API, for a dashboard or a health check.
//!
//! The daemon had no status surface at all: everything an operator could learn about it came from
//! `tracing` lines. That is why the Umbrel app decided whether the provider was healthy by
//! matching regexes against its stdout, which works until a message is reworded and then fails
//! silently, reporting a healthy daemon or an unhealthy one with equal confidence.
//!
//! Everything here already existed and had no reader: the store keeps every record and retains
//! terminal ones, the risk manager knows what is committed (its `committed_sat` doc comment has
//! said "for the status surface" since it was written), the offer is behind an `RwLock` and
//! refreshed on a timer, and `preflight` produces a report the daemon itself starts up on.
//!
//! Three properties, in the order they matter:
//!
//! **Read-only.** Nothing here moves money or changes a swap. A control plane that can start and
//! stop swaps is a different thing with a different threat model, and this daemon does not need
//! one to be operable.
//!
//! **Loopback only, with a token.** Binding is opt-in and defaults to `127.0.0.1`. The token is
//! generated into the data directory at `0600` so a supervisor sharing that volume can read it,
//! and nothing else can.
//!
//! **Projected, never serialized.** A `SwapRecord` holds the branch key, and on the client side
//! the preimage. Every response is built from a view type that has no field for either, so the
//! secret cannot reach the wire through a struct someone later adds a `Serialize` to.

use crate::{risk, ProviderConfig, SharedOffer};
use anyhow::{Context, Result};
use axum::extract::State as Extract;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use swap_common::store::SwapRecord;
use swap_common::SwapState;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// The file the token lives in, under the data directory.
const TOKEN_FILE: &str = "status.token";

/// How often the health report is recomputed.
///
/// It is not computed per request. Every check in it is a network call, some against a node that
/// answers a timeout rather than a refusal when it is down, so serving it on demand would make a
/// dashboard's poll take thirty seconds and would have it reconnecting to LND every few seconds
/// for as long as anyone had the page open.
const HEALTH_REFRESH: Duration = Duration::from_secs(15);

/// How many finished swaps `/swaps` reports, newest first.
///
/// The store keeps terminal records for weeks and a dashboard wants the recent ones; an operator
/// looking further back is looking at the records themselves.
const RECENT_LIMIT: usize = 50;

/// What a caller has to present, and where it comes from.
///
/// Generated rather than configured: a token an operator has to invent is a token that ends up
/// being `changeme`, and one they have to pass on a command line is one in the process table.
fn load_or_create_token(data_dir: &str) -> Result<String> {
    let path = std::path::Path::new(data_dir).join(TOKEN_FILE);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let token = hex::encode(swap_common::htlc::generate_preimage());
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create the data directory {data_dir}"))?;
    // Created 0600 and renamed into place, so the token never exists at any other mode.
    //
    // It used to be `fs::write` followed by a chmod. `fs::write` follows the umask, 0022 on a
    // default install, so the token sat at 0644 for the window between the two calls, and it is
    // the credential for the whole status API. Writing a temp file that is created with the mode
    // and renaming over the target closes the window and needs no chmod: a rename does not change
    // the mode, so there is no moment at which a wrong one is visible.
    //
    // The rename also tightens a loose token left by an earlier build, since it replaces the file
    // rather than opening it.
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("write {tmp:?}"))?;
        f.write_all(token.as_bytes())
            .with_context(|| format!("write {tmp:?}"))?;
        f.sync_all().with_context(|| format!("write {tmp:?}"))?;
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("install {path:?}"))?;
    info!("status API token written to {}", path.display());
    Ok(token)
}

/// What the status API reports on.
///
/// Deliberately not the execution context. This reports *on* the daemon rather than being part of
/// it, and building it out of parts rather than out of `ExecCtx` is what lets it start before the
/// backends are probed. Everything here exists before anything talks to a network.
pub(crate) struct State {
    pub config: Arc<ProviderConfig>,
    pub store: Arc<dyn swap_common::store::SwapStore>,
    pub risk: Arc<risk::RiskManager>,
    pub offer: SharedOffer,
    /// Set once the daemon has worked out whether it can execute swaps. False until then, which
    /// is the honest answer while it is still finding out.
    pub ready: Arc<AtomicBool>,
    pub provider_pkarr: String,
}

/// The last health report, and when it was taken.
type CachedHealth = Arc<RwLock<Option<(crate::preflight::Report, u64)>>>;

#[derive(Clone)]
struct Api {
    state: Arc<State>,
    token: String,
    health: CachedHealth,
}

/// Start the status API, if one is configured.
///
/// A bind failure is fatal rather than a warning: an operator who asked for a status API and did
/// not get one would find out from a dashboard that says nothing is wrong.
pub(crate) async fn spawn(state: State) -> Result<()> {
    let Some(addr) = state.config.status_addr.clone().filter(|a| !a.is_empty()) else {
        return Ok(());
    };
    let token = load_or_create_token(&state.config.data_dir)?;
    let api = Api {
        state: Arc::new(state),
        token,
        health: Arc::new(RwLock::new(None)),
    };
    let data_dir = api.state.config.data_dir.clone();
    spawn_health_refresher(api.clone());

    let router = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/swaps", get(swaps))
        .route("/limits", get(limits))
        .route("/offer", get(offer_route))
        .route("/earnings", get(earnings))
        .with_state(api);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind the status API to {addr}"))?;
    info!("status API on http://{addr} (token in {data_dir}/{TOKEN_FILE})");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            warn!("status API stopped: {e}");
        }
    });
    Ok(())
}

/// Reject anything without the token.
///
/// Compared in full rather than early-exiting on the first differing byte. The comparison is not
/// the weak point here, but a token check that leaks its own progress is not worth having.
fn authorised(api: &Api, headers: &axum::http::HeaderMap) -> bool {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(presented) = value.strip_prefix("Bearer ") else {
        return false;
    };
    let expected = api.token.as_bytes();
    let presented = presented.as_bytes();
    if presented.len() != expected.len() {
        return false;
    }
    presented
        .iter()
        .zip(expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// A response, or a 401.
macro_rules! guard {
    ($api:expr, $headers:expr) => {
        if !authorised(&$api, &$headers) {
            return (StatusCode::UNAUTHORIZED, "invalid or missing bearer token").into_response();
        }
    };
}

/// A swap as the operator may see it.
///
/// Deliberately not `SwapRecord`. That struct carries `secret_key_hex`, and on the client side the
/// preimage; a view with no field for either cannot leak one however this file changes later.
#[derive(Serialize)]
struct SwapView {
    swap_id: String,
    direction: String,
    state: &'static str,
    /// The reason, when the state carries one. `Failed` is the only variant that does.
    state_detail: Option<String>,
    peer: String,
    onchain_amount_sat: u64,
    service_fee_sat: u64,
    onchain_fee_sat: u64,
    timeout_height: u32,
    funding: Option<String>,
    spend: Option<String>,
    reorg_seen_at_height: Option<u32>,
    last_error: Option<String>,
    /// Consecutive failed driver runs, and when the next one is due.
    retry_count: u32,
    next_retry_at_unix: Option<u64>,
    /// This swap holds committed funds and its driver can no longer make progress on them. The
    /// daemon keeps retrying, but only an operator is going to fix what it is failing against.
    needs_recovery: bool,
    updated_at_unix: u64,
}

impl From<&SwapRecord> for SwapView {
    fn from(rec: &SwapRecord) -> Self {
        Self {
            swap_id: rec.swap_id.to_string(),
            direction: format!("{:?}", rec.direction).to_lowercase(),
            // Not `{:?}`: a failed swap would render as `Failed("the peer never paid")`, quotes
            // and all, and a dashboard would put that in a badge.
            state: match rec.state {
                SwapState::Created => "created",
                SwapState::LockupPending => "lockup_pending",
                SwapState::LockupConfirmed => "lockup_confirmed",
                SwapState::InvoicePending => "invoice_pending",
                SwapState::InvoicePaid => "invoice_paid",
                SwapState::ClaimPending => "claim_pending",
                SwapState::Claimed => "claimed",
                SwapState::Refunded => "refunded",
                SwapState::Expired => "expired",
                SwapState::Failed(_) => "failed",
            },
            state_detail: match &rec.state {
                SwapState::Failed(reason) => Some(reason.clone()),
                _ => None,
            },
            peer: rec.peer.clone(),
            onchain_amount_sat: rec.onchain_amount_sat,
            service_fee_sat: rec.service_fee_sat,
            onchain_fee_sat: rec.onchain_fee_sat,
            timeout_height: rec.timeout_height,
            funding: rec.funding_outpoint().map(|o| o.to_string()),
            spend: rec.spend_txid_hex.clone(),
            reorg_seen_at_height: rec.reorg_seen_at_height,
            last_error: rec.last_error.clone(),
            retry_count: rec.retry_count,
            next_retry_at_unix: rec.next_retry_at_unix,
            needs_recovery: crate::needs_recovery(rec),
            updated_at_unix: rec.updated_at_unix,
        }
    }
}

#[derive(Serialize)]
struct CheckView {
    name: &'static str,
    status: &'static str,
    detail: String,
    remedy: Option<String>,
}

/// Recompute the health report on a timer, starting immediately.
fn spawn_health_refresher(api: Api) {
    tokio::spawn(async move {
        loop {
            let report = crate::preflight::diagnose(&api.state.config).await;
            *api.health.write().await = Some((report, crate::now_unix()));
            tokio::time::sleep(HEALTH_REFRESH).await;
        }
    });
}

/// Swaps holding committed funds that the daemon can no longer make progress on.
///
/// Read from the store rather than counted in memory: these are exactly the swaps that outlive a
/// process, so a restart must not make the daemon look healthy again.
fn recovery_required(api: &Api) -> Vec<SwapRecord> {
    api.state
        .store
        .load_active()
        .unwrap_or_default()
        .into_iter()
        .filter(crate::needs_recovery)
        .collect()
}

/// The health check for swaps needing recovery.
///
/// A funded swap the daemon cannot drive is not a swap-shaped problem, it is money that will not
/// come back on its own, so it belongs beside the backend checks rather than only in a list of
/// swaps somebody has to go and read.
fn recovery_check(stuck: &[SwapRecord]) -> crate::preflight::Check {
    use crate::preflight::Check;
    if stuck.is_empty() {
        return Check::pass("swap recovery", "no swap is waiting on recovery");
    }
    let mut detail = format!(
        "{} swap(s) hold committed funds their driver can no longer make progress on",
        stuck.len()
    );
    for rec in stuck.iter().take(3) {
        detail.push_str(&format!(
            "; {} ({} failures, last: {})",
            rec.swap_id,
            rec.retry_count,
            rec.last_error.as_deref().unwrap_or("unknown")
        ));
    }
    Check::fail(
        "swap recovery",
        detail,
        "fix whatever the errors name (chain, Lightning or wallet backend). The swaps stay live \
         and keep retrying; their claims and refunds do not happen without them.",
    )
}

async fn health(Extract(api): Extract<Api>, headers: axum::http::HeaderMap) -> Response {
    guard!(api, headers);
    // The first report can take as long as the slowest backend takes to answer, and until it
    // lands there is nothing to say. Saying so beats blocking the caller for a timeout.
    let Some((mut report, checked_at_unix)) = api.health.read().await.clone() else {
        return Json(serde_json::json!({
            "checking": true,
            "detail": "the first health check has not finished yet",
        }))
        .into_response();
    };
    // Read before the recovery check joins the report: `capable` answers whether this daemon can
    // take on a new swap, and a stuck old one does not change that answer.
    let capable = report.is_capable();
    let stuck = recovery_required(&api);
    report.push(recovery_check(&stuck));
    let checks: Vec<CheckView> = report
        .checks
        .iter()
        .map(|c| CheckView {
            name: c.name,
            status: match c.status {
                crate::preflight::Status::Pass => "pass",
                crate::preflight::Status::Warn => "warn",
                crate::preflight::Status::Fail => "fail",
            },
            detail: c.detail.clone(),
            remedy: c.remedy.clone(),
        })
        .collect();
    let recovery: Vec<SwapView> = stuck.iter().map(SwapView::from).collect();
    Json(serde_json::json!({
        "capable": capable,
        "failures": report.failures(),
        "warnings": report.warnings(),
        "checks": checks,
        // Named separately as well as counted, because acting on one means knowing which swap it
        // is: the record holds the key that recovers those funds by hand if it comes to that.
        "recovery_required": recovery,
        // So a dashboard can say how fresh this is rather than implying it is live.
        "checked_at_unix": checked_at_unix,
        "refresh_secs": HEALTH_REFRESH.as_secs(),
    }))
    .into_response()
}

async fn status(Extract(api): Extract<Api>, headers: axum::http::HeaderMap) -> Response {
    guard!(api, headers);
    // `null` while the daemon is still working out what it can serve, which is a state the
    // dashboard shows rather than an error it reports.
    let directions = api
        .state
        .offer
        .read()
        .await
        .as_ref()
        .map(|o| o.directions.clone());
    Json(serde_json::json!({
        "pubky": api.state.provider_pkarr,
        "network": api.state.config.network,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": swap_common::messages::PROTOCOL_VERSION,
        "capable": api.state.ready.load(Ordering::Relaxed),
        "directions": directions,
        "in_flight": api.state.risk.in_flight(),
        "committed_sat": api.state.risk.committed_sat(),
        // The one number here that is not about capacity. A daemon can be capable, within its
        // limits, and still be holding funds it has stopped being able to recover.
        "recovery_required": recovery_required(&api).len(),
    }))
    .into_response()
}

async fn swaps(Extract(api): Extract<Api>, headers: axum::http::HeaderMap) -> Response {
    guard!(api, headers);
    let store = api.state.store.clone();
    let all = match store.load_all() {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not read the swap store: {e}"),
            )
                .into_response()
        }
    };
    let (mut done, active): (Vec<_>, Vec<_>) = all.iter().partition(|r| r.state.is_terminal());
    done.sort_by_key(|r| std::cmp::Reverse(r.updated_at_unix));
    let recent: Vec<SwapView> = done
        .iter()
        .take(RECENT_LIMIT)
        .map(|r| (*r).into())
        .collect();
    let active: Vec<SwapView> = active.iter().map(|r| (*r).into()).collect();
    Json(serde_json::json!({
        "active": active,
        "recent": recent,
        "recent_limit": RECENT_LIMIT,
        "finished_total": done.len(),
    }))
    .into_response()
}

async fn limits(Extract(api): Extract<Api>, headers: axum::http::HeaderMap) -> Response {
    guard!(api, headers);
    let risk = &api.state.risk;
    let limits: &risk::RiskLimits = risk.limits();
    Json(serde_json::json!({
        "committed_sat": risk.committed_sat(),
        "max_total_exposure_sat": limits.max_total_exposure_sat,
        "in_flight": risk.in_flight(),
        "max_concurrent_swaps": limits.max_concurrent_swaps,
        "max_exposure_per_peer_sat": limits.max_exposure_per_peer_sat,
        "max_concurrent_per_peer": limits.max_concurrent_per_peer,
        "max_new_swaps_per_peer_per_hour": limits.max_new_swaps_per_peer_per_hour,
        "min_onchain_reserve_sat": limits.min_onchain_reserve_sat,
        "peers": risk.per_peer(),
    }))
    .into_response()
}

async fn offer_route(Extract(api): Extract<Api>, headers: axum::http::HeaderMap) -> Response {
    guard!(api, headers);
    let offer = api.state.offer.read().await.clone();
    Json(offer).into_response()
}

async fn earnings(Extract(api): Extract<Api>, headers: axum::http::HeaderMap) -> Response {
    guard!(api, headers);
    let all = match api.state.store.load_all() {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not read the swap store: {e}"),
            )
                .into_response()
        }
    };
    // Only completed swaps earned anything. A refunded or failed one may still have cost an
    // on-chain fee, which is why they are counted separately rather than folded in as zero.
    let mut completed = 0u64;
    let mut service_fee_sat = 0u64;
    let mut expected_onchain_cost_sat = 0u64;
    let mut volume_sat = 0u64;
    let mut refunded = 0u64;
    let mut failed = 0u64;
    for rec in &all {
        match rec.state {
            SwapState::Claimed => {
                completed += 1;
                service_fee_sat += rec.service_fee_sat;
                expected_onchain_cost_sat += rec.onchain_fee_sat;
                volume_sat += rec.onchain_amount_sat;
            }
            SwapState::Refunded | SwapState::Expired => refunded += 1,
            SwapState::Failed(_) => failed += 1,
            _ => {}
        }
    }
    Json(serde_json::json!({
        "completed": completed,
        "refunded_or_expired": refunded,
        "failed": failed,
        "volume_sat": volume_sat,
        "service_fee_sat": service_fee_sat,
        // What the swaps were priced to cost on chain, not what they actually cost: the realised
        // figure is only knowable by reading the transactions, and saying so beats implying a
        // precision this does not have.
        "expected_onchain_cost_sat": expected_onchain_cost_sat,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swap_common::store::SwapRecord;

    /// The one property this file cannot get wrong.
    ///
    /// A record holds the branch key that can move the funds on this side's HTLC, and on the
    /// client side the preimage as well. The view has no field for either, and this is what would
    /// catch someone adding one.
    #[test]
    fn a_swap_view_carries_no_key_material() {
        let mut rec = SwapRecord::new_progress();
        rec.secret_key_hex = "aa".repeat(32);
        rec.preimage_hex = Some("bb".repeat(32));
        rec.peer = "peer".into();

        let json = serde_json::to_string(&SwapView::from(&rec)).unwrap();
        assert!(
            !json.contains(&"aa".repeat(32)),
            "the branch key reached the wire"
        );
        assert!(
            !json.contains(&"bb".repeat(32)),
            "the preimage reached the wire"
        );
        assert!(json.contains("peer"), "and the view is not simply empty");
    }

    /// The token is the credential for the whole status API, so it must never exist readable.
    ///
    /// It used to be written with `fs::write`, which follows the umask (0022 on a default
    /// install, so 0644), and chmodded afterwards. Between those two calls any user on the host
    /// could read it. Creating the file with the mode closes the window; the chmod stays, to
    /// tighten a token an earlier build already left behind.
    #[cfg(unix)]
    #[test]
    fn the_status_token_is_never_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("pubky-swap-token-{}", uuid::Uuid::new_v4()));
        let path = dir.join(TOKEN_FILE);

        let token = load_or_create_token(dir.to_str().unwrap()).unwrap();
        assert!(!token.is_empty());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a freshly created token must be 0600, not {mode:o}"
        );

        // The same token comes back rather than being regenerated, so a supervisor that already
        // read it keeps working across a restart.
        assert_eq!(load_or_create_token(dir.to_str().unwrap()).unwrap(), token);

        // A token an earlier build left world-readable is replaced rather than adopted, so an
        // upgrade fixes the mode instead of inheriting it.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        load_or_create_token(dir.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "an existing loose token must be tightened");

        // Nothing is left behind that the API would try to serve or a reader would trip over.
        assert!(!path.with_extension("tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A funded swap the daemon can no longer drive has to reach the operator through the same
    /// surface as a dead backend, because it is the same kind of problem: money that does not come
    /// back on its own. Before this it was invisible, and the swap it describes used to be marked
    /// `Failed` and pruned instead.
    #[test]
    fn a_swap_needing_recovery_fails_the_health_check_and_names_itself() {
        let mut rec = SwapRecord::new_progress();
        rec.swap_id = uuid::Uuid::new_v4();
        rec.direction = swap_common::SwapDirection::Reverse;
        rec.funding_txid_hex = Some("11".repeat(32));
        rec.funding_vout = Some(0);
        rec.retry_count = crate::recovery::MAX_DRIVER_RETRIES;
        rec.last_error = Some("electrum: connection refused".into());
        assert!(crate::needs_recovery(&rec));

        let check = recovery_check(std::slice::from_ref(&rec));
        assert_eq!(check.status, crate::preflight::Status::Fail);
        assert!(check.detail.contains(&rec.swap_id.to_string()));
        assert!(check.detail.contains("connection refused"));
        assert!(check.remedy.is_some(), "a failure must say what to do");

        // The view a dashboard reads says the same thing per swap.
        let view = SwapView::from(&rec);
        assert!(view.needs_recovery);
        assert_eq!(view.retry_count, crate::recovery::MAX_DRIVER_RETRIES);

        // A swap that is merely in flight is not an alarm.
        let mut healthy = SwapRecord::new_progress();
        healthy.state = SwapState::LockupConfirmed;
        assert!(!crate::needs_recovery(&healthy));
        assert!(!SwapView::from(&healthy).needs_recovery);
        assert_eq!(
            recovery_check(&[]).status,
            crate::preflight::Status::Pass,
            "and with nothing stuck the check passes rather than going missing"
        );
    }

    /// The reason a swap failed belongs in a field, not inside the state name.
    ///
    /// `format!("{:?}")` on `Failed(String)` renders `Failed("the peer never paid")`, quotes
    /// included, and a dashboard puts whatever it is given into a badge. Anything that reads this
    /// API has to be able to switch on the state without parsing it.
    #[test]
    fn a_failure_reason_is_a_field_rather_than_part_of_the_state() {
        let mut rec = SwapRecord::new_progress();
        rec.state = SwapState::Failed("the peer never paid".into());
        let view = SwapView::from(&rec);
        assert_eq!(view.state, "failed");
        assert_eq!(view.state_detail.as_deref(), Some("the peer never paid"));

        let mut rec = SwapRecord::new_progress();
        rec.state = SwapState::LockupConfirmed;
        let view = SwapView::from(&rec);
        assert_eq!(view.state, "lockup_confirmed");
        assert_eq!(view.state_detail, None);
    }
}
