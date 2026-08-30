//! `GET /api/v1/admin/audit` — the compliance log, read by the people it is kept for (`ENC-961`).
//!
//! # What was missing
//!
//! `audit_events` has been written since Phase 0, hash-chained, partitioned and covered by a gate
//! that fails CI when an enforcement point forgets to write to it. Until `ENC-960` nothing had ever
//! read it. That built the narrowest reader deliberately — `GET /me/activity`, changes only, no
//! denials, no actor circumstances — and said in its own module documentation that the
//! administrative surface `docs/05 §14` has specified since it was drawn was still unbuilt. This is
//! that surface.
//!
//! # It is the deliberate opposite of `/me/activity`
//!
//! `routes/activity.rs` excludes denials, reads, and everything that identifies the actor's
//! circumstances, and argues each exclusion at length. Every one of those arguments turns on the
//! same fact: that feed is readable by any member. None of them survives here.
//!
//! - **Denials are the point.** A `DENY` row is what an investigation is looking for. The reason
//!   `/me/activity` withholds them — that a refusal discloses the resource exists, which rule 7
//!   spends a `404` to protect — does not apply to a caller who already holds
//!   `AdminAction::ReadAudit` over the whole tenant.
//! - **Reads are included.** *Who looked at what* is surveillance on a member surface and is the
//!   first question asked after a suspected exfiltration. Same rows, different reader.
//! - **The actor's circumstances are included.** `ip`, `country`, `user_agent`, `session_id`,
//!   `device_id` and `detail` exist so a session can be reconstructed. This is the only surface
//!   they are reachable from.
//!
//! # What it is still not
//!
//! **Not a verifier.** `PgAuditSink::verify_tenant` and `chain::verify_chain` are implemented,
//! tested, and called by nothing: the product writes a tamper-evident log and has never had a way
//! to check that it has not been tampered with. Reading rows shows what the table *says*; only the
//! chain walk shows whether the table has been edited underneath. That is `ENC-969`, kept out of
//! this change because `verify_tenant` hangs off the concrete sink while handlers hold an
//! `Arc<dyn AuditSink>`, and widening a write trait to carry a verifier is a decision worth making
//! on its own.
//!
//! **Not an export.** `/admin/audit/export` is the third route in `docs/05 §14` and is a different
//! shape — a job, a signed artifact, a retention question of its own.

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use enclave_audit::{AuditEvent, AuditFilter};
use enclave_core::{
    Action, AdminAction, Error, FieldError, RequestContext, RequestId, ResourceRef, ValidationCode,
};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, NO_STORE};
use crate::refusal::none_dischargeable;
use crate::state::ApiState;

/// Reading the log is its own permission, and it is not `ReadConfig`.
///
/// `AdminAction::ReadAudit` has existed in the vocabulary since it was written and, until now, was
/// named by no route — the sibling admin surfaces all read configuration. Keeping them separate is
/// the point: an administrator who may see which DLP rules exist is not thereby someone who may see
/// every file every colleague opened.
const READ_ACTION: Action = Action::Admin(AdminAction::ReadAudit);

/// Page sizes. Larger than the member listings' thirty because an investigation reads in bulk, and
/// bounded because the rows are wide.
const DEFAULT_LIMIT: u32 = 50;
/// See [`DEFAULT_LIMIT`].
const MAX_LIMIT: u32 = 200;
/// See [`DEFAULT_LIMIT`].
const MIN_LIMIT: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditParams {
    limit: Option<String>,
    /// The previous page's `nextCursor`, which is a `sequence`.
    before: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    outcome: Option<String>,
    since: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    items: Vec<AuditRow>,
    /// The `sequence` to pass as `before` for the next page, or `null` at the end of the log.
    ///
    /// Present only when the page was filled: a short page is the last one, and offering a cursor
    /// there would invite a request that can only come back empty.
    next_cursor: Option<String>,
}

/// One row, whole.
///
/// Written out field by field rather than serializing [`AuditEvent`] directly. The struct derives
/// `Serialize` for the canonical encoding, and letting the wire shape follow it would mean a field
/// added for hashing appears in an HTTP response nobody decided to put it in.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRow {
    id: String,
    /// Monotonic within the tenant. Also the cursor.
    sequence: i64,
    occurred_at: DateTime<Utc>,
    /// `user`, `guest`, `service`, `mcp`, `link` or `system`.
    actor_type: String,
    /// The actor's identifier, absent for `system`.
    actor_id: Option<String>,
    /// Set when a service acted for a person (`docs/03 §5`).
    on_behalf_of: Option<String>,
    /// The `family.verb` spelling.
    action: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
    workspace_id: Option<String>,
    /// `ALLOW`, `DENY` or `ERROR`.
    outcome: String,
    /// Why, when the chain refused.
    reason_code: Option<String>,
    /// Which policies were consulted, and at which version.
    policy_refs: Vec<serde_json::Value>,
    /// Ties a row to the envelope a user was shown.
    request_id: String,
    session_id: Option<String>,
    client_type: Option<String>,
    device_id: Option<String>,
    ip: Option<String>,
    country: Option<String>,
    user_agent: Option<String>,
    /// Structured context, already redacted at write time (`crates/audit/src/redact.rs`).
    detail: serde_json::Value,
    /// Hex. `null` on the genesis row and whenever the chain is disabled.
    previous_hash: Option<String>,
    /// See [`Self::previous_hash`].
    event_hash: Option<String>,
}

/// Handles `GET /api/v1/admin/audit`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unparseable filter, or a database failure.
pub async fn read(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Query(params): Query<AuditParams>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let limit = limit(params.limit.as_deref(), request_id)?;
    let filter = filter(&params, request_id)?;

    enforce(&state, &ctx, READ_ACTION).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let events = enclave_audit::read_page(&mut tx, &filter, i64::from(limit))
        .await
        .map_err(|error| ApiError::new(Error::Internal(anyhow::anyhow!(error)), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // A cursor only when the page was filled — see [`AuditPage::next_cursor`].
    let next_cursor = (events.len() == limit as usize)
        .then(|| events.last().map(|event| event.sequence.to_string()))
        .flatten();

    // `no-store`: this is the one response in the product whose body is the security record itself.
    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(AuditPage { items: events.iter().map(row).collect(), next_cursor }),
    )
        .into_response())
}

fn row(event: &AuditEvent) -> AuditRow {
    AuditRow {
        id: event.id.to_string(),
        sequence: event.sequence,
        occurred_at: event.occurred_at,
        actor_type: event.actor.kind().as_str().to_owned(),
        actor_id: event.actor.subject_id().map(|id| id.to_string()),
        on_behalf_of: event.on_behalf_of.map(|id| id.to_string()),
        action: event.action.to_string(),
        resource_type: event.resource_kind().map(|kind| kind.as_str().to_owned()),
        resource_id: event.resource_id().map(|id| id.to_string()),
        workspace_id: event.workspace_id.map(|id| id.to_string()),
        outcome: event.outcome.as_str().to_owned(),
        reason_code: event.reason_code.map(|code| code.as_str().to_owned()),
        policy_refs: event
            .policy_refs
            .iter()
            .map(|reference| serde_json::to_value(reference).unwrap_or(serde_json::Value::Null))
            .collect(),
        request_id: event.request_id.to_string(),
        session_id: event.session_id.map(|id| id.to_string()),
        client_type: event.client_type.map(|kind| kind.as_str().to_owned()),
        device_id: event.device_id.map(|id| id.to_string()),
        ip: event.ip.map(|ip| ip.to_string()),
        country: event.country.clone(),
        user_agent: event.user_agent.clone(),
        detail: serde_json::to_value(&event.detail).unwrap_or(serde_json::Value::Null),
        previous_hash: event.previous_hash.map(|hash| hash.to_hex()),
        event_hash: event.event_hash.map(|hash| hash.to_hex()),
    }
}

/// The chain decides before a single row is read.
async fn enforce(state: &ApiState, ctx: &RequestContext, action: Action) -> Result<(), ApiError> {
    let resource = ResourceRef::tenant(ctx.tenant_id);
    let decision = state
        .policy
        .enforce(ctx, action, &resource)
        .await
        .map_err(|error| ApiError::new(error, ctx.request_id))?;
    // `PolicyDecision` is `#[must_use]`. Reading the log discharges nothing — there is no rendition
    // to watermark — so an obligation arriving here is a refusal (D29, rule 8).
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(ctx, action, &resource, refused).await);
    }
    Ok(())
}

/// Reads the narrowings, refusing anything unparseable rather than ignoring it.
///
/// **A filter that is silently dropped is the dangerous failure here.** An auditor who asks for one
/// actor and is handed the whole log will notice; one who asks for `outcome=DENY`, is quietly given
/// everything, and reads the first page has been told something false about what happened.
fn filter(params: &AuditParams, request_id: RequestId) -> Result<AuditFilter, ApiError> {
    let before = match params.before.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(text) => Some(text.parse::<i64>().map_err(|_error| invalid("before", request_id))?),
    };
    let actor = match params.actor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(text) => {
            Some(text.parse::<uuid::Uuid>().map_err(|_error| invalid("actor", request_id))?)
        }
    };
    let since = match params.since.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(text) => Some(
            DateTime::parse_from_rfc3339(text)
                .map_err(|_error| invalid("since", request_id))?
                .with_timezone(&Utc),
        ),
    };
    // `outcome` is checked against the vocabulary rather than passed through: an unknown value would
    // match no row, and an empty page is indistinguishable from "nothing happened".
    let outcome = match params.outcome.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(text) => {
            let upper = text.to_ascii_uppercase();
            if !["ALLOW", "DENY", "ERROR"].contains(&upper.as_str()) {
                return Err(invalid("outcome", request_id));
            }
            Some(upper)
        }
    };
    // `action` is not validated against the vocabulary. The column holds whatever spelling was
    // written, the vocabulary grows, and an audit reader that refuses to look for a verb this build
    // does not know is one that cannot investigate the past.
    let action =
        params.action.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned);

    Ok(AuditFilter { before, actor, action, outcome, since })
}

fn invalid(field: &'static str, request_id: RequestId) -> ApiError {
    ApiError::new(
        Error::Validation(vec![FieldError::new(field, ValidationCode::InvalidFormat)]),
        request_id,
    )
}

/// Reads `?limit=`, clamping to the range, as every sibling listing does.
fn limit(raw: Option<&str>, request_id: RequestId) -> Result<u32, ApiError> {
    match raw {
        None => Ok(DEFAULT_LIMIT),
        Some(text) => text
            .trim()
            .parse::<u32>()
            .map(|asked| asked.clamp(MIN_LIMIT, MAX_LIMIT))
            .map_err(|_error| invalid("limit", request_id)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn params() -> AuditParams {
        AuditParams {
            limit: None,
            before: None,
            actor: None,
            action: None,
            outcome: None,
            since: None,
        }
    }

    /// Reading the log is `ReadAudit` and never `ReadConfig`.
    ///
    /// The plausible mistake, because every sibling admin route reads configuration and this one was
    /// written next to them. It would hand every configuration reader the record of who opened what.
    #[test]
    fn reading_the_log_is_its_own_permission() {
        assert_eq!(READ_ACTION, Action::Admin(AdminAction::ReadAudit));
    }

    /// An unparseable narrowing is refused, never dropped.
    ///
    /// A dropped filter widens the answer, and widening is the direction that lies: the auditor
    /// asked about one actor and is reading everybody.
    #[test]
    fn an_unparseable_filter_is_refused_rather_than_ignored() {
        let id = RequestId::new_v7();
        for (field, mut given) in
            [("actor", params()), ("before", params()), ("since", params()), ("outcome", params())]
        {
            match field {
                "actor" => given.actor = Some("not-a-uuid".into()),
                "before" => given.before = Some("head".into()),
                "since" => given.since = Some("last tuesday".into()),
                _ => given.outcome = Some("MAYBE".into()),
            }
            assert!(
                filter(&given, id).is_err(),
                "`{field}` was unparseable and the filter was built anyway — the caller would be \
                 handed a wider answer than the one they asked for, and nothing would say so"
            );
        }
    }

    /// The control for the test above: a filter that parses is carried through, every field of it.
    #[test]
    fn a_filter_that_parses_is_carried_through_whole() {
        let mut given = params();
        given.actor = Some("6f1d7ad4-4b1e-4d55-9a2f-4c9a7b2e1d33".into());
        given.before = Some("4200".into());
        given.since = Some("2026-01-02T03:04:05Z".into());
        given.outcome = Some("deny".into());
        given.action = Some("file.download".into());

        let built = filter(&given, RequestId::new_v7()).expect("every field is valid");
        assert_eq!(built.before, Some(4200));
        assert_eq!(
            built.actor.map(|id| id.to_string()).as_deref(),
            Some("6f1d7ad4-4b1e-4d55-9a2f-4c9a7b2e1d33")
        );
        assert_eq!(built.action.as_deref(), Some("file.download"));
        assert_eq!(built.outcome.as_deref(), Some("DENY"), "the vocabulary is upper case");
        assert!(built.since.is_some());
    }

    /// The default filter reads the whole log and narrows nothing.
    ///
    /// Asserted because the opposite failure is silent in the other direction: a filter that
    /// defaulted to, say, denials only would show an auditor a plausible page and hide the rest.
    #[test]
    fn asking_for_nothing_in_particular_narrows_nothing() {
        let built = filter(&params(), RequestId::new_v7()).expect("an empty filter is valid");
        assert!(built.before.is_none());
        assert!(built.actor.is_none());
        assert!(built.action.is_none());
        assert!(built.outcome.is_none());
        assert!(built.since.is_none());
    }

    /// `limit` is clamped rather than trusted.
    #[test]
    fn the_page_size_is_bounded_at_both_ends() {
        let id = RequestId::new_v7();
        assert_eq!(limit(None, id).expect("absent is the default"), DEFAULT_LIMIT);
        assert_eq!(limit(Some("100000"), id).expect("clamped"), MAX_LIMIT);
        assert_eq!(limit(Some("0"), id).expect("clamped"), MIN_LIMIT);
        assert!(limit(Some("many"), id).is_err());
    }
}
