//! Liveness, readiness, and the per-dependency report.
//!
//! [`live`] and [`ready`] are on the policy-routing lint's allowlist. They must be: an orchestrator
//! probes them without a token, and a readiness endpoint that required authentication would report
//! a healthy service as unhealthy the moment authentication broke — precisely when you need the
//! truth.
//!
//! Neither reports anything tenant-specific. `docs/06-SECURITY-DLP-ACCESS.md §1` assumes the caller
//! is hostile, and an unauthenticated endpoint is the most hostile of all.
//!
//! [`dependencies`] is the third, and it is the one with a security shape.
//! `docs/05-API.md §19` gives its contract as *unauthenticated summary / authenticated detail*, and
//! the reason the two halves differ is not preference: a dependency report is a description of the
//! deployment's internals. An anonymous caller learns that something is degraded. It does not learn
//! **what**, and no caller at any level learns **where** — see [`Dependency`].

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use enclave_core::{Action, ContainerAction, ReasonCode, RequestContext, ResourceKind, ResourceRef};
use enclave_db::DbError;
use enclave_storage::BlobStore;
use serde::Serialize;
use uuid::Uuid;

use crate::auth::Authenticated;
use crate::error::{ApiError, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::routes::bootstrap::MaybeAuthenticated;
use crate::state::ApiState;

/// The action the detailed half asks the chain about.
///
/// The same self-read `GET /api/v1/me` and `GET /api/v1/bootstrap` take, and for the same reason:
/// `docs/05-API.md §19` says *authenticated* detail, not *administrative* detail, so the question
/// being asked is "is this a principal this deployment knows" and not "may this principal
/// administer the tenant". `Admin(ReadConfig)` would have been the wrong question — it would refuse
/// every non-administrator, which is not what the contract says — and the disclosure it would have
/// been protecting against is prevented structurally instead, by never putting an address in the
/// response at all.
const READ: Action = Action::Container(ContainerAction::Read);

/// The process is up.
pub async fn live() -> StatusCode {
    StatusCode::OK
}

/// The process can serve traffic: PostgreSQL answers.
///
/// Deliberately narrow. Milvus, the embedding provider, SMTP and antivirus can all be degraded
/// without making file APIs unready (`docs/03-LLD.md §19`) — folding them in here would take the
/// whole service out of rotation for a degraded search index.
pub async fn ready(State(state): State<ApiState>) -> StatusCode {
    match state.db.health_check().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(?error, "readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The wire types. As in `routes/bootstrap.rs`, the split is a pair of types rather than a filter.
// ---------------------------------------------------------------------------------------------

/// What an unauthenticated caller learns: one word.
///
/// Not a count, not a list of names with their statuses elided, not "3 of 5 healthy". Each of those
/// leaks the shape of the deployment, and the leak survives every future edit that adds a
/// dependency. One enum with two arms cannot grow a field by accident.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencySummary {
    status: Health,
}

/// What an authenticated caller learns: the summary, and which component produced it.
///
/// Embeds [`DependencySummary`] rather than restating `status`, so the two halves cannot disagree
/// about whether the deployment is healthy.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyDetail {
    #[serde(flatten)]
    summary: DependencySummary,
    dependencies: Vec<Dependency>,
}

/// The overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    /// Every component this process actually probed answered.
    Healthy,
    /// At least one probed component did not.
    Degraded,
}

/// One component, what is known about it, and how that came to be known.
///
/// # `evidence` exists so that "not measured" cannot be read as "fine"
///
/// This process holds a connection pool and a [`BlobStore`]. It holds no client for Milvus, Redis,
/// NATS, ClamAV or SMTP — those live in `enclave-worker` — so a report that simply omitted them
/// would say *everything I could see is healthy* in a shape indistinguishable from *everything is
/// healthy*. They are therefore listed, with [`Evidence::None`] and [`DependencyStatus::Unknown`],
/// and `unknown` is not an arm of [`Health`]: an unprobed dependency cannot make the deployment
/// look degraded and cannot make it look healthy either. `ENC-729` is the row for giving them a
/// real probe.
///
/// [`Evidence::Configuration`] is the third case and is genuinely different from both: object
/// storage is *known to be unconfigured* rather than unreachable. `enclave_api::Delivery`
/// substitutes `UnconfiguredBlobStore` when a deployment supplies none, and reporting that as
/// `down` would page an operator about a component they chose not to install.
///
/// # What never appears on this type
///
/// A host, a port, a URL, a bucket, a database name, a version string, or a provider error message.
/// `sqlx::Error`'s own `Display` carries the connection target, so [`reason`](Dependency::reason)
/// is a closed vocabulary derived from the [`DbError`] *variant* and never from its text — which is
/// why the mapping is a `match` in [`reason`] and not a `to_string`. "PostgreSQL unreachable at
/// 10.0.3.14:5432" is a map of the deployment's internal network, and an authenticated tenant user
/// is not entitled to one. The operator who is entitled to it reads the log line, which does carry
/// the source error.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    name: &'static str,
    evidence: Evidence,
    status: DependencyStatus,
    /// A stable code for *why*, present only on a failure. Never a message, never an address.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// How a component's status came to be known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Evidence {
    /// This request asked the component and it answered, or did not.
    Probe,
    /// Read from what the deployment was configured with; nothing was asked of the component.
    Configuration,
    /// Nothing was measured. This process holds no handle to the component.
    None,
}

/// A component's state, in the vocabulary its [`Evidence`] can support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyStatus {
    /// Probed and answered.
    Up,
    /// Probed and did not answer.
    Down,
    /// A backend is configured. Says nothing about whether it is reachable.
    Configured,
    /// No backend is configured, so the capability it provides is refused by design.
    Unconfigured,
    /// Not measured. Deliberately not a synonym for `up`.
    Unknown,
}

/// The components this process cannot see, named so their absence is not mistaken for health.
///
/// A constant rather than a list built from what happens to be wired, because the value of the list
/// is exactly that it does not shrink when somebody forgets a component.
const UNPROBED: &[&str] = &["milvus", "redis", "nats", "antivirus", "smtp", "embedding_provider"];

// ---------------------------------------------------------------------------------------------
// The handler.
// ---------------------------------------------------------------------------------------------

/// Handles `GET /health/dependencies`.
///
/// # Why this is always `200`, even when degraded
///
/// It is a *report*, not a rotation signal. `/health/ready` is the rotation signal and answers
/// `503` (`docs/03-LLD.md §19`); a second endpoint answering `503` for a degraded search index
/// would be one misconfigured load balancer away from taking the service out of rotation for a
/// condition `ready` deliberately tolerates. The verdict is in the body, where reading it is a
/// decision rather than a side effect.
///
/// # The lint, and why there is no allowlist entry
///
/// `crates/api/src/routes/bootstrap.rs` carries the argument in full: an exemption is granted per
/// handler and not per branch, so allowlisting this would exempt the authenticated half as well as
/// the anonymous one. The handler reaches `PolicyEngine::enforce` on the branch that needs it, so
/// the lint passes on its own terms. `live` and `ready` stay allowlisted because *neither* of their
/// halves has an actor — they have no halves.
///
/// # Errors
///
/// [`ApiError`] when a presented credential does not verify, when the chain refuses, or when the
/// caller is a principal with no user record. Never for the anonymous path.
pub async fn dependencies(
    State(state): State<ApiState>,
    Extension(store): Extension<Arc<dyn BlobStore>>,
    caller: MaybeAuthenticated,
) -> Result<Response, ApiError> {
    let Some(Authenticated { ctx }) = caller.0 else {
        // The anonymous half. The probe still runs — the summary would be worthless otherwise —
        // and its result is collapsed to one word before it can reach a serializer.
        let observed = observe(&state, store.as_ref()).await;
        return Ok(render(DependencySummary { status: verdict(&observed) }));
    };

    // The chain runs *before* anything is probed. Not for the probe's sake — it touches no tenant
    // data — but so that a caller the chain refuses learns nothing about how long a probe took, and
    // so the ordering here matches every other authenticated handler in this crate rather than
    // being the one that is different.
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
        }
    };
    let resource = ResourceRef::new(ctx.tenant_id, ResourceKind::User, subject);

    let decision = state
        .policy
        .enforce(&ctx, READ, &resource)
        .await
        .map_err(|error| ApiError::new(error, ctx.request_id))?;

    // `PolicyDecision` is `#[must_use]`; consuming it is what proves nothing was dropped. There is
    // no rendition to watermark and no justification to collect on a health report, so an
    // obligation arriving here is a refusal (`CLAUDE.md` rule 8), audited for `ENC-606`'s reason.
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
    }

    let observed = observe(&state, store.as_ref()).await;
    Ok(render(DependencyDetail {
        summary: DependencySummary { status: verdict(&observed) },
        dependencies: observed,
    }))
}

/// Renders either half with the one header a health report must carry.
///
/// `no-store` because a cached health report is a health report about the past, and the caller
/// cannot tell how far in the past. It is the one response in this crate where a stale copy is
/// actively misleading rather than merely wasteful.
fn render<T: Serialize>(body: T) -> Response {
    ([(header::CACHE_CONTROL, NO_STORE)], Json(body)).into_response()
}

/// Asks what can be asked, and records what cannot.
///
/// Order is fixed — probed first, configured second, unprobed last — so two runs of this endpoint
/// diff cleanly.
async fn observe(state: &ApiState, store: &dyn BlobStore) -> Vec<Dependency> {
    let mut observed = Vec::with_capacity(2 + UNPROBED.len());

    observed.push(match state.db.health_check().await {
        Ok(()) => Dependency {
            name: "postgresql",
            evidence: Evidence::Probe,
            status: DependencyStatus::Up,
            reason: None,
        },
        Err(error) => {
            // The source error goes to the log, where an operator needs the address, and the
            // caller receives the variant's name. This is the line the module header is about.
            tracing::warn!(?error, "dependency probe failed: postgresql");
            Dependency {
                name: "postgresql",
                evidence: Evidence::Probe,
                status: DependencyStatus::Down,
                reason: Some(reason(&error)),
            }
        }
    });

    // Not a probe. `capabilities()` reports what was wired, and `Delivery::unconfigured` wires
    // `UnconfiguredBlobStore` when a deployment supplies nothing — the same signal `main.rs` prints
    // at start-up through `Delivery::unconfigured_capabilities`.
    let configured = store.capabilities().backend != "unconfigured";
    observed.push(Dependency {
        name: "object_storage",
        evidence: Evidence::Configuration,
        status: if configured {
            DependencyStatus::Configured
        } else {
            DependencyStatus::Unconfigured
        },
        reason: None,
    });

    observed.extend(UNPROBED.iter().map(|name| Dependency {
        name,
        evidence: Evidence::None,
        status: DependencyStatus::Unknown,
        reason: None,
    }));

    observed
}

/// The one word the summary carries.
///
/// **Probed components only.** An unconfigured object store is not a degradation — it is a
/// deployment that chose not to install one — and an unprobed component is not evidence of
/// anything. Folding either into this verdict would make the community profile report itself as
/// permanently degraded, which is the fastest way to teach an operator to ignore the field.
fn verdict(observed: &[Dependency]) -> Health {
    let failed = observed
        .iter()
        .any(|d| d.evidence == Evidence::Probe && d.status == DependencyStatus::Down);
    if failed {
        Health::Degraded
    } else {
        Health::Healthy
    }
}

/// A stable code for a database failure, derived from the variant and never from the message.
///
/// An exhaustive `match` with no wildcard arm, so a variant added to [`DbError`] fails to compile
/// here rather than falling into a catch-all — the same argument `enclave_core::Action` makes for
/// not being `#[non_exhaustive]`. A wildcard would be the exact mechanism by which a future variant
/// carrying an address became the caller's problem.
const fn reason(error: &DbError) -> &'static str {
    match error {
        DbError::InvalidConfig { .. } => "misconfigured",
        DbError::Connect(_) => "unreachable",
        DbError::Acquire(_) => "pool_exhausted",
        DbError::TenantContext(_) => "tenant_context_failed",
        DbError::Transaction(_) => "transaction_failed",
        DbError::Query(_) => "query_failed",
        _ => "unavailable",
    }
}

/// The subject a self-read can be about.
///
/// A function that returns a [`Refused`], for the reason `crates/api/src/me.rs` gives: that is what
/// `cargo run -p xtask -- audit-coverage` reads to decide the refusal is audited.
///
/// # Errors
///
/// [`Refused`] for a principal with no `users` row — [`enclave_core::Actor::System`] and every
/// machine caller.
fn subject(ctx: &RequestContext) -> Result<Uuid, Refused> {
    ctx.actor.subject_id().ok_or_else(|| Refused::actor(ReasonCode::AccessDenied))
}
