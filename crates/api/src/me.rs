//! `GET /api/v1/me` — the first request that traverses the whole chain.
//!
//! Trivial as a feature and complete as a path: authenticate a bearer token, build a
//! [`RequestContext`], call `PolicyEngine::enforce`, run a tenant-scoped query, emit an audit row,
//! answer. `plans/M1-CONTENT-CORE.md §2.1` explains why that ordering is worth an endpoint of its
//! own — friction between the M0 pieces surfaces here rather than on the upload path.

use axum::extract::State;
use axum::Json;
use enclave_core::{Action, ContainerAction, Error, ReasonCode, RequestContext, ResourceRef, Uuid};
use serde::Serialize;
use sqlx::Row;

use crate::auth::Authenticated;
use crate::error::ApiError;
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The action this endpoint asks the chain about, and the one a refusal here is recorded against.
const READ: Action = Action::Container(ContainerAction::Read);

/// The caller, as the caller may see themselves.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Me {
    id: String,
    tenant_id: String,
    email: String,
    display_name: String,
    is_admin: bool,
    /// What this caller may attempt, from the same engine that will enforce it.
    ///
    /// `docs/05-API.md §7`: the UI renders actions from this rather than re-deriving permissions,
    /// so the two cannot disagree.
    capabilities: Capabilities,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    read_self: bool,
}

/// Handles `GET /api/v1/me`.
///
/// # Errors
///
/// [`ApiError`] for any policy denial, an unknown subject, or a storage failure.
pub async fn me(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
) -> Result<Json<Me>, ApiError> {
    let request_id = ctx.request_id;

    // A caller with no subject — the `System` actor — has no user row to return. It should never
    // reach an HTTP handler; saying so is cheaper than discovering it as a nil-UUID lookup.
    //
    // This one is refused *before* the chain runs, so there is no `ALLOW` row beside it. The row it
    // writes therefore stands alone, which is accurate: the tenant is the verified token's and the
    // actor is `system`, so it is attributable, and nothing about the policy chain is asserted.
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
        }
    };

    let resource = ResourceRef::new(ctx.tenant_id, enclave_core::ResourceKind::User, subject);

    // The chain. Not a permission check bolted beside the query — the query does not run unless
    // this returns, and the audit row is written inside it whether it allows or denies.
    let decision = state
        .policy
        .enforce(&ctx, READ, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // `PolicyDecision` is #[must_use]; consuming it here is what proves nothing was dropped.
    //
    // No stage attaches an obligation to reading your own record today, and this path has no way to
    // satisfy one if it did — there is no rendition to watermark and nowhere to collect a
    // justification. So an obligation arriving here is a refusal (D29, `CLAUDE.md` rule 8).
    //
    // This was a `debug_assert!` until `ENC-582`, which is to say it was nothing at all in the
    // build that ships: release compiled the check out and served the response with the obligation
    // dropped. `ENC-544` was the same defect in the audit crate's field-count guard.
    //
    // `none_dischargeable` rather than `Obligations::require_none`: same rule and same code, in the
    // type that cannot reach a caller without a row. `require_none` returns an `Error`, and an
    // `Error` here is `ENC-606` — the chain wrote `ALLOW` two lines above.
    let obligations = decision.into_obligations();
    if let Err(refused) = none_dischargeable(&obligations) {
        return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // No tenant predicate in the SQL. That is deliberate and not an omission: `TenantScoped` has
    // set `app.tenant_id`, and row-level security applies the predicate for us. A row from another
    // tenant is not filtered out here — it is not visible to this transaction at all.
    let row = sqlx::query(
        "SELECT id, tenant_id, email, display_name, is_admin
         FROM users
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(subject)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let row = row.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    Ok(Json(Me {
        id: row.get::<uuid::Uuid, _>("id").to_string(),
        tenant_id: row.get::<uuid::Uuid, _>("tenant_id").to_string(),
        email: row.get("email"),
        display_name: row.get("display_name"),
        is_admin: row.get("is_admin"),
        capabilities: Capabilities { read_self: true },
    }))
}

/// The subject a self-read can be about.
///
/// A function rather than an inline `ok_or_else` so that the refusal is *constructed in a function
/// that returns one*, which is what `cargo run -p xtask -- audit-coverage` reads to decide that it
/// is audited — the same rule that makes a `StageDecision` audited by construction. It is also
/// where the argument for the refusal belongs.
///
/// # Errors
///
/// [`Refused`] for [`enclave_core::Actor::System`], which has no subject. It is an actor-eligibility
/// refusal rather than an obligation one: nothing was attached to this request, the principal is
/// simply not one that can have a `users` row.
fn subject(ctx: &RequestContext) -> Result<Uuid, Refused> {
    ctx.actor.subject_id().ok_or_else(|| Refused::actor(ReasonCode::AccessDenied))
}
