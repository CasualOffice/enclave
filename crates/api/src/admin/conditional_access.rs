//! `/api/v1/admin/conditional-access/rules` — writing the rules that decide who may reach a tenant.
//!
//! `ENC-603`. `ENC-590` gave conditional-access rules a table, a repository, a strict decoder and
//! the wiring; the write path was `enclave_db::insert_rule`, which nothing called. An
//! administrator's only route to a rule was a `psql` session, which is not the surface
//! `docs/06-SECURITY-DLP-ACCESS.md §7` describes them using. This module is that surface.
//!
//! `docs/05-API.md §14.1` is authoritative for the contract. What follows is why it has the shape
//! it does.
//!
//! # The request body may not be more permissive than the decoder
//!
//! The Q19 separation (`docs/06 §7.4`) is a *type* separation: [`MachineCondition`] has no
//! `posture_below`, so a device-posture rule against a service account is not skipped, it cannot be
//! written. `ENC-590` established that storage may not dissolve that — the audience is a column, it
//! selects which Rust type the document is decoded into, and a `MACHINE` row naming `posture_below`
//! is refused **by name** rather than trimmed to the clauses that parsed, because a rule missing a
//! condition matches *more* requests than the administrator wrote and every rule in this stage
//! denies.
//!
//! An API is the other place that guarantee is easily lost, and losing it would be silent. A body
//! deserialized into a lenient shape — `#[serde(other)]`, an untagged enum, a `HashMap<String,
//! Value>` filtered to the clauses that parsed — would accept the rule the decoder refuses and
//! store what was left of it. So this module **never decodes a condition itself**:
//!
//! 1. the body's `when` is carried as raw JSON, exactly as sent;
//! 2. it is assembled into a [`RuleRow`] — the stored form — and handed to
//!    [`decode_rule`], the same function the loader uses on every request;
//! 3. the decoded [`Rule`] is then re-encoded with [`encode_rule`], and *that* is what is written.
//!
//! **Step 2 is what holds the property**, and step 3 is belt-and-braces — which is worth stating
//! precisely, because the opposite was written here first and a deliberate break disproved it.
//! Removing step 3 and storing the request's own document fails *no* test in this crate: the
//! refusal of an inexpressible clause is `decode_rule`'s, and PostgreSQL's `jsonb` normalises key
//! order and whitespace, so a document that decoded is stored identically either way. Step 3 stays
//! because a guarantee should not rest on the storage engine's normalisation — it is the difference
//! between "the column holds a value the type produced" and "the column holds what the caller sent,
//! which happened to parse" — and because it stops being free the day `when` is carried as a raw
//! string rather than parsed into `serde_json::Value`. The finding is recorded in
//! `crates/api/tests/admin_conditional_access.rs` beside the assertion that replaced the claim.
//!
//! A second vocabulary in this module — even a list of condition names for validation — would be
//! the drift `ENC-590` designed the column split to prevent, and it does not exist here.
//!
//! # `ALLOW` is refused, and told why
//!
//! There is no allow effect (`docs/06 §7.4`): under most-restrictive-wins an allow can never change
//! an outcome, so accepting one would let an administrator write an exception, see it stored, and
//! have it do nothing. It is already refused twice — by [`Effect::from_sql`] and by
//! `migrations/0019`'s `CHECK`. Here it is refused a third time in the only way that helps the
//! person writing it: with the reason, and the sentence that says what to write instead.
//!
//! # What a rejected rule is told, and what it is never told
//!
//! The rule's **name** is operator-facing. It is in every response body and in no error: an error
//! naming a rule would leak the tenant's policy vocabulary onto a path that is reachable before the
//! object has been shown to exist, and `RuleError`'s own `Display` embeds it — so this module reads
//! the *source* of a decode failure rather than its message. The clause that was refused is
//! reported, because *`unknown variant `posture_below`*` is the whole diagnostic value of a strict
//! decoder and an administrator told only "rejected" goes back to `psql`.

use core::str::FromStr as _;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use enclave_conditional_access::{
    decode_rule, encode_rule, HumanRule, MachineRule, PolicySet, Rule, RuleError, RuleMode,
    TenantConditionalAccess,
};
use enclave_core::{
    Action, Actor, AdminAction, AuthStrength, Error, RequestContext, RequestId, ResourceRef,
    TenantId, UserId, ValidationCode,
};
use enclave_db::{DbError, RuleId, RuleRow};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;
use crate::state::StepUpPolicy;

/// How recently a privileged mutation's caller must have authenticated.
///
/// `docs/05-API.md §14`: an access token whose `acr` is `mfa` and whose `auth_time` is within the
/// configured step-up window, default fifteen minutes, for the privileged mutations
/// `docs/06 §22` lists — and *changing conditional access* is on that list.
///
/// A constant rather than a configuration key because `enclave_config` carries no step-up section
/// and adding one touches a file this change does not own (`ENC-621`). Fifteen minutes is the
/// documented default, so the constant is the documented behaviour rather than a guess. In seconds,
/// because `chrono::TimeDelta`'s constructors are not `const`.
const STEP_UP_MAX_AGE_SECS: i64 = 15 * 60;

/// The action every write on this surface is authorized as.
///
/// `docs/06 §22` groups *changing conditional access* with disabling DLP and changing identity
/// providers, which is what [`AdminAction::ManagePolicy`] names. It is deliberately not
/// [`AdminAction::WriteConfig`]: a deployment that one day grants a junior administrator the right
/// to change branding must not thereby grant the right to decide which networks may reach the
/// tenant.
const WRITE_ACTION: Action = Action::Admin(AdminAction::ManagePolicy);

/// The action reading this surface is authorized as.
const READ_ACTION: Action = Action::Admin(AdminAction::ReadConfig);

/// The longest decoder message that reaches a caller.
///
/// serde quotes the offending name, and the offending name came from the request — so an
/// administrator who posts a hundred-kilobyte key would otherwise have it echoed back. The clause
/// name is what carries the diagnosis and it is short.
const MAX_DETAIL_CHARS: usize = 240;

/// Forgetting one tenant's cached rules on the replica that changed them.
///
/// # Why this is a trait rather than the concrete type
///
/// [`TenantConditionalAccess`] needs a `DbPool`, and a test that wants to know whether the write
/// path invalidates should not need a database to find out. The trait is also the honest shape of
/// what a handler needs: the write path does not read this cache, evaluate against it, or depend on
/// it — it tells it that something changed.
///
/// # Why the API's correctness does not depend on it
///
/// `ENC-590`'s bound is the 15-second TTL, and invalidation is the shortcut for the one replica
/// that made the change: *a message reaches one replica; a deployment is several.* So this is
/// called on every write and no response, decision or test outcome turns on whether anything is
/// listening — [`ApiState::rule_cache`](crate::ApiState) is an `Option`, and a deployment that has
/// not wired it is exactly as correct, fifteen seconds later.
pub trait RuleCache: Send + Sync + std::fmt::Debug {
    /// Forgets this tenant's cached rules, so this replica reads them again on the next request.
    fn invalidate(&self, tenant: TenantId);
}

impl RuleCache for TenantConditionalAccess {
    fn invalidate(&self, tenant: TenantId) {
        Self::invalidate(self, tenant);
    }
}

// --- Wire types ---------------------------------------------------------------------------------

/// A rule as an administrator writes one.
///
/// `deny_unknown_fields`, and it is load-bearing rather than tidy: `{"mdoe": "ENFORCE"}` accepted
/// silently is a rule that rehearses while its author believes it is deciding, which is the exact
/// failure `plans/M4-GOVERNANCE.md §2` is written against.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleRequest {
    /// `HUMAN` or `MACHINE` — which rule set this rule belongs to. Never inferred from `when`;
    /// see the module header.
    audience: String,
    /// What the administrator calls it.
    name: String,
    /// One of the seven effects. `ALLOW` is not one of them.
    effect: String,
    /// `ENFORCE` or `SIMULATION`. Absent means `SIMULATION`, matching `migrations/0019`'s column
    /// default and its argument: a rule written without saying which it is rehearses, and
    /// enforcing is the statement an administrator has to make.
    #[serde(default)]
    mode: Option<String>,
    /// The conjunctive condition list, in the stored vocabulary, carried verbatim.
    when: Vec<serde_json::Value>,
}

/// The body of a mode change — the rollout step (`plans/M4-GOVERNANCE.md §2`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeRequest {
    /// `ENFORCE` or `SIMULATION`.
    mode: String,
}

/// A stored rule, as an administrator reads one back.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    /// The rule's identifier, unique within the tenant.
    id: String,
    /// Which rule set it belongs to.
    audience: String,
    /// What the administrator called it. Operator-facing, and here rather than in any error.
    name: String,
    /// The effect.
    effect: String,
    /// Whether it decides or rehearses.
    mode: String,
    /// The conditions, exactly as stored.
    when: serde_json::Value,
    /// Whether the stored document still decodes into the rule the audience names.
    ///
    /// Always `true` for a rule written through this API, which round-trips it through the decoder
    /// before storing it. It can be `false` for a row written by a repair script or a `psql`
    /// session — and that is the case this field exists for; see [`list_rules`].
    decodes: bool,
    /// The decoder's account of why it does not, when it does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    decode_error: Option<String>,
}

/// A page of rules.
///
/// The `page` object is `docs/05-API.md §6`'s, with no cursor: the whole live set is returned,
/// because it is the whole set the loader reads on *every request in the chain* anyway
/// (`TenantConditionalAccess::policies_for`). A tenant with enough rules for the page envelope to
/// matter has a rule set no administrator can read and a per-request cost nobody has measured;
/// paging this before that is true would be inventing a cursor to page a list that is already
/// loaded whole. The envelope's shape is kept so that adding one later is not a `v2` change.
#[derive(Debug, Serialize)]
pub struct RuleList {
    /// The tenant's live rules, ordered by name.
    items: Vec<RuleView>,
    /// Pagination, per `docs/05-API.md §6`.
    page: Page,
}

/// The pagination object of `docs/05-API.md §6`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    /// Always absent here — see [`RuleList`].
    next_cursor: Option<String>,
    /// Always `false` here.
    has_more: bool,
}

// --- Handlers -----------------------------------------------------------------------------------

/// Handles `GET /api/v1/admin/conditional-access/rules`.
///
/// # Why one undecodable row does not fail this list
///
/// `ENC-590` made a stored rule that cannot be decoded fail the **whole** set, so that a policy is
/// never silently missing a refusal — and `crates/conditional_access/tests/stored_rules.rs` C9
/// proves the consequence: one hostile row and every request in the tenant errors. This is the
/// surface an administrator repairs that from, so the same rule applied here would make the repair
/// impossible: they could not see which rule to withdraw, or its id, because listing them is what
/// failed.
///
/// So this endpoint decodes each row **individually** and reports the outcome per rule. Nothing is
/// weakened by that: it reads, it never writes, and a row it reports as `decodes: false` is a row
/// the chain is still refusing every request over. The leniency is in what is *shown*, which is
/// strictly more information than a `500`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial or a database failure.
pub async fn list_rules(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, READ_ACTION).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let rows = enclave_db::load_rules(&mut tx)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // `no-store` for the same reason the delivery paths use it: a shared cache holding this would
    // serve one tenant's security policy from a response another caller's proxy had kept.
    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(RuleList {
            items: rows.iter().map(view).collect(),
            page: Page { next_cursor: None, has_more: false },
        }),
    )
        .into_response())
}

/// Handles `POST /api/v1/admin/conditional-access/rules`.
///
/// # Ordering
///
/// The chain runs before the body is looked at. A caller the chain refuses learns nothing about the
/// request schema, the vocabulary or the tenant's rules — not even that their JSON was malformed —
/// which is the same reason `crates/api/src/download.rs` does no file lookup above its `enforce`.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unusable caller, or a database failure. Rejected bodies are
/// rendered as `docs/05-API.md §5` envelopes in the `Ok` arm, because their statuses — `400`,
/// `409`, `422` — are ones [`Error`] cannot express.
pub async fn create_rule(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, WRITE_ACTION).await?;
    if let Err(envelope) = require_step_up(&ctx, state.step_up) {
        return Ok(envelope.into_response(request_id));
    }
    let author = match author(&ctx) {
        Ok(author) => author,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, WRITE_ACTION, &resource, refused).await);
        }
    };

    let request: RuleRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };

    let id = RuleId::new_v7();
    let candidate = match rule_from(id, &request) {
        Ok(rule) => rule,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    if let Err(envelope) = refuse_self_lockout(&candidate, &ctx) {
        return Ok(envelope.into_response(request_id));
    }

    // The row that is stored is the serialization of the decoded rule, never the bytes that
    // arrived — so the column holds a value the *type* produced. See the module header for what
    // that is and is not worth: the refusal itself is `decode_rule`'s, one line above.
    let row = encode_rule(id, &candidate)
        .map_err(|error| ApiError::new(Error::from(error), request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    if let Err(error) = enclave_db::insert_rule(&mut tx, &row, author).await {
        return write_failure(error, request_id);
    }
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    written(&state, &ctx, "created", &row);

    let location = format!("/api/v1/admin/conditional-access/rules/{id}");
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, NO_STORE)],
        [(header::LOCATION, location)],
        Json(view(&row)),
    )
        .into_response())
}

/// Handles `PATCH /api/v1/admin/conditional-access/rules/{id}` — the rollout step.
///
/// Moving a rule from `SIMULATION` to `ENFORCE` is the moment it starts refusing people, so it
/// carries the same lockout check as writing an enforcing rule; moving it the other way is a
/// relaxation and carries none.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unknown rule, or a database failure.
pub async fn change_rule_mode(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, WRITE_ACTION).await?;
    if let Err(envelope) = require_step_up(&ctx, state.step_up) {
        return Ok(envelope.into_response(request_id));
    }

    // A malformed id is answered exactly as an unknown one, and an unknown one exactly as another
    // tenant's: `CLAUDE.md` rule 7, and one answer is easier to keep than to re-derive.
    let id = rule_id(&id).ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let request: ModeRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return Ok(unreadable_body(&error).into_response(request_id)),
    };
    let mode = match RuleMode::from_sql(&request.mode, "") {
        Ok(mode) => mode,
        Err(_error) => return Ok(unknown_mode().into_response(request_id)),
    };

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Read inside the same transaction as the write: the rule the lockout check is run against has
    // to be the rule the `UPDATE` then enforces, and re-reading it afterwards would leave a window
    // in which a concurrent change decided something this check never saw.
    let rows = enclave_db::load_rules(&mut tx)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let Some(row) = rows.into_iter().find(|row| row.id == id) else {
        return Err(ApiError::new(Error::NotFound, request_id));
    };

    if mode == RuleMode::Enforce {
        // A stored rule that no longer decodes cannot be enforced — it is already failing every
        // request in the tenant (`decode_rules`), and this is the surface that withdraws it.
        let stored = match decode_rule(&row) {
            Ok(rule) => rule,
            Err(error) => return Ok(rejected_rule(&error).into_response(request_id)),
        };
        if let Err(envelope) = refuse_self_lockout(&enforcing(stored), &ctx) {
            return Ok(envelope.into_response(request_id));
        }
    }

    let changed = enclave_db::set_rule_mode(&mut tx, id, mode.as_sql())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    if !changed {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    let row = RuleRow { mode: mode.as_sql().to_owned(), ..row };
    written(&state, &ctx, "mode changed", &row);
    Ok(([(header::CACHE_CONTROL, NO_STORE)], Json(view(&row))).into_response())
}

/// Handles `DELETE /api/v1/admin/conditional-access/rules/{id}` — withdrawal.
///
/// # `DELETE` at the edge is an `UPDATE` underneath, and that is the whole point
///
/// `migrations/0019` grants `enclave_app` no `DELETE` on this table: one such statement lifts every
/// network restriction a tenant has and leaves nothing to say it existed. Withdrawal sets
/// `deleted_at`; the row and its text stay, so an administrator can see what a rule said and when
/// it stopped applying, and an investigation can reconstruct the policy that was in force. The verb
/// is `DELETE` because that is what the caller is doing — removing the rule from the set that
/// decides — and `docs/05-API.md §14.1` says what it does underneath.
///
/// # Errors
///
/// [`ApiError`] for a policy denial, an unknown or already-withdrawn rule, or a database failure.
pub async fn withdraw_rule(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    enforce(&state, &ctx, WRITE_ACTION).await?;
    if let Err(envelope) = require_step_up(&ctx, state.step_up) {
        return Ok(envelope.into_response(request_id));
    }
    let id = rule_id(&id).ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let withdrawn = enclave_db::withdraw_rule(&mut tx, id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // Withdrawing another tenant's rule, an unknown rule and an already-withdrawn rule all move
    // zero rows, and all three are told the same thing. The first is `CLAUDE.md` rule 7; the other
    // two are `enclave_db::withdraw_rule`'s own note — the record of *when* a rule stopped applying
    // is written once, so a repeat is not an update.
    if !withdrawn {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    invalidate(&state, ctx.tenant_id);
    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        rule_id = %id,
        "conditional-access rule withdrawn"
    );
    Ok((StatusCode::NO_CONTENT, [(header::CACHE_CONTROL, NO_STORE)]).into_response())
}

// --- The chain, and the two checks that sit beside it --------------------------------------------

/// Runs the policy chain for an administrative action on this tenant.
///
/// The resource is the tenant itself rather than the rule, for the reason [`crate::admin`] gives:
/// the question is whether this caller may manage this tenant's policy, and the rule's existence is
/// settled afterwards by a statement that moves no rows.
///
/// # What no deployment currently grants
///
/// `crates/api/src/main.rs` hands the engine `SelfServiceAuthorization`, which allows a principal to
/// read *itself* and refuses everything else — so in a running deployment every route in this module
/// is refused at the authorization stage today. That is the correct direction and it is stated
/// rather than worked around: an admin surface that authorized itself would be a second permission
/// model beside the chain, which is what `CLAUDE.md` rule 1 forbids. `ENC-619` is the row for an
/// authorization service that can answer an [`AdminAction`] — the tenant administrator flag exists
/// (`users.is_admin`) and nothing resolves it into a decision yet.
async fn enforce(state: &ApiState, ctx: &RequestContext, action: Action) -> Result<(), ApiError> {
    let decision = state
        .policy
        .enforce(ctx, action, &ResourceRef::tenant(ctx.tenant_id))
        .await
        .map_err(|error| ApiError::new(error, ctx.request_id))?;

    // `PolicyDecision` is `#[must_use]`; consuming it here is what proves nothing was dropped. No
    // stage attaches an obligation to an administrative action today, and this path could not
    // satisfy one — there is no rendition to watermark and nowhere to collect a justification — so
    // an obligation arriving here is a refusal (D29, `CLAUDE.md` rule 8).
    //
    // `none_dischargeable` rather than `Obligations::require_none`, for `ENC-606`'s reason: the
    // chain wrote its `ALLOW` one statement above, so a refusal that reached the caller as a bare
    // `Error` would be a `403` the audit table records as a success.
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state
            .audit
            .refuse(ctx, action, &ResourceRef::tenant(ctx.tenant_id), refused)
            .await);
    }
    Ok(())
}

/// Refuses a privileged mutation that is not backed by recent multi-factor authentication.
///
/// `docs/06 §22` requires recent MFA plus audit for changing conditional access, and
/// `docs/05-API.md §14` states it as a property of the admin surface.
///
/// # Why it is here, after the chain, and where it belongs instead
///
/// It runs **after** `enforce` so that the chain decides first: tenant isolation, the tenant's own
/// conditional-access rules and the audit row all precede it, and a caller refused by the chain is
/// refused for the chain's reason rather than for this one.
///
/// The cost of that ordering is honest and worth stating: the engine has already written an
/// *allow* row when this refuses, so the audit log records a decision the request then did not act
/// on. The right home for this requirement is the conditional-access stage — it is a
/// `RequireMfa` effect that every deployment holds for one action, and there it would be audited as
/// the denial it is. That is `ENC-620`, and it is a change to `crates/conditional_access`, which
/// this task does not own.
fn require_step_up(ctx: &RequestContext, policy: StepUpPolicy) -> Result<(), Envelope> {
    // `policy` rather than a constant: `security.mfa.admins_required` existed, was documented, and
    // was read by nothing, so this demanded a second factor the binary's `MfaVerifier` could never
    // check. A tenant administrator was refused their own policy surface for want of a factor they
    // had no way to present (`ENC-771`).
    if policy.satisfied_by(ctx.auth_strength, ctx.auth_age(chrono::Utc::now()).num_seconds()) {
        return Ok(());
    }

    tracing::warn!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        "a conditional-access rule change was refused for want of a recent second factor"
    );
    Err(Envelope::new(
        StatusCode::FORBIDDEN,
        "STEP_UP_REQUIRED",
        "This action needs a fresher sign-in.",
        "Re-authenticate with a second factor and retry.",
    )
    .with_details(vec![serde_json::json!({
        "acr": "mfa",
        "maxAge": policy.max_age_secs(),
    })]))
}

/// The user this rule will be attributed to.
///
/// `conditional_access_rules.created_by` is `NOT NULL` and carries a composite foreign key onto
/// `users (tenant_id, id)`, because *"the system" is not an answer to "who locked the finance team
/// out on Friday"*. A service account, an MCP client or `system` has no row in `users`; rather than
/// let the foreign key report that as an internal error, the requirement is stated here.
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        // An actor-eligibility refusal, and the one in `ENC-606`'s class that matters most: by the
        // time it fires the chain has written its `ALLOW` for `admin.manage_policy`, so before
        // `ENC-606` a non-human principal's attempt to write a conditional-access rule was recorded
        // as a success. *Who tried to change the access rules* is the investigation this table
        // exists for. The caller of this function records the refusal before returning it.
        _ => Err(Refused::actor(enclave_core::ReasonCode::AccessDenied)),
    }
}

// --- The lockout check ---------------------------------------------------------------------------

/// Refuses a rule that would deny its own author's session.
///
/// # The risk, and why this is a refusal rather than a warning
///
/// `plans/M4-GOVERNANCE.md §5`: *a zone rule that denies the network an administrator is on is a
/// control that cannot be undone through the product.* Undoing it needs database access, which is
/// the support incident this surface exists to remove — and a warning in a response body is a
/// warning nothing enforces, read by an administrator who has already clicked the button.
///
/// # Why refusing costs the administrator nothing they cannot recover
///
/// The refusal is narrow in three ways, and each one is what keeps it from blocking legitimate
/// configuration:
///
/// * **It applies only when the rule would begin *deciding*** — a create in `ENFORCE`, or a change
///   to `ENFORCE`. A rule may always be written and rehearsed, which is the rollout
///   `plans/M4-GOVERNANCE.md §2` asks for and the direction `migrations/0019`'s default already
///   points.
/// * **The question asked is exactly the lockout**: would this rule deny *this caller's own
///   current session* the [`AdminAction::ManagePolicy`] action — the one that would undo it? A
///   rule denying downloads from abroad, or requiring a managed device for sync, does not match an
///   administrative action and is unaffected.
/// * **The way out is the one that verifies the rule**: enforce it from a session the rule permits.
///   An administrator writing "block everything outside the corporate zone" enforces it from inside
///   the corporate zone, which is also the only place they can see that the rule they wrote admits
///   the network they meant.
///
/// Break-glass is deliberately **not** honoured here, though the rest of the stage honours it: the
/// question is whether an *ordinary* session of this administrator would be refused, and a
/// break-glass session is by definition not one. Evaluating with the exemption on would let the one
/// session that can always get in authorize a rule that locks out every session that cannot.
///
/// # The consequence worth knowing about
///
/// `DevicePosture` is `Unknown` for every caller until a device registry exists, so an enforcing
/// `REQUIRE_MANAGED_DEVICE` rule with no narrowing condition denies its author and is refused. That
/// is not a false positive: enforcing it today would lock every administrator out of the product,
/// because nothing can attest a device. It rehearses until posture is real.
fn refuse_self_lockout(candidate: &Rule, ctx: &RequestContext) -> Result<(), Envelope> {
    if !locks_out(candidate, ctx) {
        return Ok(());
    }
    Err(Envelope::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "RULE_WOULD_DENY_ITS_AUTHOR",
        "This rule would refuse your own session, and nobody could undo it from here.",
        "Store it in SIMULATION and enforce it from a session the rule allows.",
    )
    .with_details(vec![serde_json::json!({
        "field": "mode",
        "code": ValidationCode::Inconsistent.as_str(),
        "detail": "enforcing this rule would deny this session the admin/manage_policy action, \
                   which is the action that would withdraw it",
    })]))
}

/// Whether the rule, enforcing, would deny this caller's own attempt to manage policy.
///
/// Evaluated as a policy set containing **only** this rule, which is exact rather than convenient:
/// rules do not interact — every one of them denies or constrains, and the set's outcome is the
/// union — so the only new denial a write can introduce is this rule's own.
///
/// A machine rule is never a lockout for a person: `PolicySet::evaluate` chooses one rule set from
/// the principal's kind, and a human administrator is never decided by the machine set (Q19). It is
/// therefore *not* checked, rather than checked and found harmless — a machine rule that refuses
/// every service account is a legitimate thing to write and locks no administrator out of anything.
fn locks_out(candidate: &Rule, ctx: &RequestContext) -> bool {
    let Rule::Human(rule) = candidate else {
        return false;
    };
    // Evaluated in the mode the rule carries, which is what makes a rehearsal free: a
    // `SIMULATION` rule is matched by the same code and contributes nothing to the decision, so it
    // is not a lockout — and the caller that is about to *enforce* one asks about the enforcing
    // form ([`enforcing`]) rather than about the row as stored.
    let set = PolicySet::empty().with_break_glass(None).with_human_rules([rule.clone()]);
    !set.evaluate(ctx, WRITE_ACTION).peek().is_allowed()
}

/// The same rule, enforcing — what a `SIMULATION` rule becomes when it is rolled out.
fn enforcing(rule: Rule) -> Rule {
    match rule {
        Rule::Human(rule) => Rule::Human(HumanRule { mode: RuleMode::Enforce, ..rule }),
        Rule::Machine(rule) => Rule::Machine(MachineRule { mode: RuleMode::Enforce, ..rule }),
    }
}

// --- Decoding a request into a rule ---------------------------------------------------------------

/// Turns a request body into a rule, through the decoder the loader uses.
///
/// Every refusal here is the *stored* decoder's refusal, reported against the field the
/// administrator wrote. See the module header for why this function has no vocabulary of its own.
fn rule_from(id: RuleId, request: &RuleRequest) -> Result<Rule, Envelope> {
    if request.name.trim().is_empty() || request.name.chars().count() > 200 {
        return Err(bad_field(
            "name",
            ValidationCode::InvalidFormat,
            "a rule name is between 1 and 200 characters, and is what an operator reads in a \
             denial's log line",
        ));
    }

    let conditions = serde_json::to_string(&request.when).map_err(|_error| {
        bad_field("when", ValidationCode::InvalidFormat, "the condition list could not be read")
    })?;

    let row = RuleRow {
        id,
        audience: request.audience.clone(),
        name: request.name.clone(),
        conditions,
        effect: request.effect.clone(),
        mode: request.mode.clone().unwrap_or_else(|| RuleMode::Simulation.as_sql().to_owned()),
    };

    decode_rule(&row).map_err(|error| rejected_rule(&error))
}

/// Renders a decoder refusal as a `docs/05-API.md §5` envelope.
///
/// The rule's **name** is not in any of these, though `RuleError`'s `Display` carries it: this
/// reads the error's structure rather than its message. See the module header.
fn rejected_rule(error: &RuleError) -> Envelope {
    match error {
        RuleError::UnknownAudience { .. } => bad_field(
            "audience",
            ValidationCode::Unsupported,
            "a rule belongs to the HUMAN rule set or the MACHINE one, and the two have different \
             condition vocabularies — the audience selects which, and is never inferred from the \
             conditions",
        ),
        RuleError::UnknownEffect { effect, .. } if effect.eq_ignore_ascii_case("ALLOW") => {
            bad_field(
                "effect",
                ValidationCode::Unsupported,
                "there is no ALLOW effect: the most restrictive matching effect wins, so an allow \
                 could never change an outcome and would be an exception that appears to exist. \
                 Write the exception as a narrower condition on the restrictive rule \
                 (docs/06 §7.4)",
            )
        }
        RuleError::UnknownEffect { .. } => bad_field(
            "effect",
            ValidationCode::Unsupported,
            "the effect is one of BLOCK, REQUIRE_TRUSTED_NETWORK, REQUIRE_MANAGED_DEVICE, \
             REQUIRE_MFA, PREVIEW_ONLY, NO_DOWNLOAD, NO_SYNC",
        ),
        RuleError::UnknownMode { .. } => unknown_mode(),
        // The one that carries serde's own account, because the offending clause is named in it and
        // that name is the whole diagnostic value of a closed decoder.
        RuleError::Conditions { source, .. } => {
            detailed("when", ValidationCode::Unsupported, clip(&source.to_string()))
        }
        // Serialization of a value that decoded — not the caller's doing — and whatever a future
        // variant turns out to be. `RuleError` is `#[non_exhaustive]`.
        _ => bad_field(
            "when",
            ValidationCode::InvalidFormat,
            "the condition list could not be stored as written",
        ),
    }
}

/// The refusal for a mode that is neither `ENFORCE` nor `SIMULATION`.
///
/// Note the direction: an unrecognised mode is refused, never quietly treated as `SIMULATION`. An
/// administrator whose enforcing rule was demoted by a typo would hold a control that reports itself
/// as on and refuses nothing.
fn unknown_mode() -> Envelope {
    bad_field(
        "mode",
        ValidationCode::Unsupported,
        "a rule either ENFORCEs or runs in SIMULATION; there is no third state and an \
         unrecognised one is never demoted to SIMULATION",
    )
}

/// A body that is not the shape this endpoint reads.
///
/// serde's message quotes the input, so it is not repeated; the caller is told which field shape
/// was expected. An unknown field is called out by name because `deny_unknown_fields` is how a
/// misspelled `mode` is stopped from silently becoming a rehearsal, and "unknown field" with no
/// further explanation reads as a bug in the client.
fn unreadable_body(error: &serde_json::Error) -> Envelope {
    let detail = if error.to_string().starts_with("unknown field") {
        "the body carries a field this endpoint does not read; a misspelled `mode` would otherwise \
         store a rule that rehearses while its author believes it decides"
    } else {
        "the body could not be read as a rule"
    };
    detailed("body", ValidationCode::InvalidFormat, detail.to_owned())
}

/// A `400` naming one field, with a fixed sentence.
fn bad_field(field: &'static str, code: ValidationCode, detail: &'static str) -> Envelope {
    detailed(field, code, detail.to_owned())
}

/// A `400` naming one field, with a sentence assembled at run time.
fn detailed(field: &'static str, code: ValidationCode, detail: String) -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "VALIDATION_FAILED",
        "The rule could not be accepted as sent.",
        "Correct the field named in `details` and retry.",
    )
    .with_details(vec![serde_json::json!({
        "field": field,
        "code": code.as_str(),
        "detail": detail,
    })])
}

/// Bounds what a decoder message can echo back. See [`MAX_DETAIL_CHARS`].
fn clip(text: &str) -> String {
    if text.chars().count() <= MAX_DETAIL_CHARS {
        return text.to_owned();
    }
    text.chars().take(MAX_DETAIL_CHARS).collect::<String>() + "…"
}

// --- Writing ---------------------------------------------------------------------------------------

/// Maps a failed insert onto an answer.
///
/// The only one a caller can act on is the unique index over live names: one live rule per name per
/// tenant, because the name is what an operator reads in a denial's log line and two rules sharing
/// one would make both ambiguous at exactly the moment somebody is working out which rule fired.
/// It is reported as a `409`, per `docs/05-API.md §5`'s row for a name collision.
///
/// The name is **not** echoed: the caller sent it, but this endpoint is reachable by anyone the
/// chain allows, and a collision report is the one place a rule an administrator has not been shown
/// could be named back to them.
fn write_failure(error: DbError, request_id: RequestId) -> Result<Response, ApiError> {
    if let DbError::Query(sqlx::Error::Database(ref db_error)) = error {
        if db_error.constraint() == Some(LIVE_NAME_INDEX) {
            return Ok(Envelope::new(
                StatusCode::CONFLICT,
                "RULE_NAME_IN_USE",
                "A live rule already has that name.",
                "Choose another name, or withdraw the rule that holds it.",
            )
            .into_response(request_id));
        }
    }
    Err(ApiError::new(error.into(), request_id))
}

/// The unique index `migrations/0019` puts over live rule names.
const LIVE_NAME_INDEX: &str = "uq_conditional_access_rules_live_name";

/// Records a write, and tells this replica's cache about it.
///
/// The log line is not the audit trail — audit happens inside the policy engine, for denials as
/// well as allows (`CLAUDE.md` rule 10), and the engine has already written the row for this
/// action. This adds what the audit row cannot carry: *which* rule, by the name an operator
/// recognises. `docs/04 §12.1`'s `name` column exists for that, and the audit schema has no field
/// for it (`ENC-622`).
fn written(state: &ApiState, ctx: &RequestContext, what: &'static str, row: &RuleRow) {
    invalidate(state, ctx.tenant_id);
    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        rule_id = %row.id,
        rule = %row.name,
        audience = %row.audience,
        effect = %row.effect,
        mode = %row.mode,
        "conditional-access rule {what}"
    );
}

/// Tells this replica's cache that a tenant's rules changed, if anything is listening.
///
/// The TTL is the bound and this is the shortcut; see [`RuleCache`].
fn invalidate(state: &ApiState, tenant: TenantId) {
    match state.rule_cache.as_ref() {
        Some(cache) => cache.invalidate(tenant),
        None => tracing::debug!(
            %tenant,
            "no conditional-access rule cache is wired to this API; the change applies everywhere \
             within the cache TTL"
        ),
    }
}

// --- Views -----------------------------------------------------------------------------------------

/// Renders a stored row, decoding it to report whether it still decodes. See [`list_rules`].
fn view(row: &RuleRow) -> RuleView {
    let (decodes, decode_error) = match decode_rule(row) {
        Ok(_rule) => (true, None),
        Err(RuleError::Conditions { ref source, .. }) => (false, Some(clip(&source.to_string()))),
        Err(ref error) => (false, Some(clip(&stored_fault(error)))),
    };
    RuleView {
        id: row.id.to_string(),
        audience: row.audience.clone(),
        name: row.name.clone(),
        effect: row.effect.clone(),
        mode: row.mode.clone(),
        when: serde_json::from_str(&row.conditions).unwrap_or(serde_json::Value::Null),
        decodes,
        decode_error,
    }
}

/// What is wrong with a stored row, without the rule's name — the caller already has that field.
fn stored_fault(error: &RuleError) -> String {
    match error {
        RuleError::UnknownAudience { audience, .. } => {
            format!("`{audience}` is not a rule set")
        }
        RuleError::UnknownEffect { effect, .. } => {
            format!("`{effect}` is not an effect this stage can apply")
        }
        RuleError::UnknownMode { mode, .. } => {
            format!("`{mode}` is neither ENFORCE nor SIMULATION")
        }
        other => other.to_string(),
    }
}

/// Parses a path id, or reports nothing at all about why it did not.
fn rule_id(value: &str) -> Option<RuleId> {
    uuid::Uuid::from_str(value).ok().map(RuleId::from_uuid)
}

/// The cache handle as [`ApiState`] holds it — for `main.rs`, which wires one in a line.
pub type SharedRuleCache = Arc<dyn RuleCache>;

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_conditional_access::{Effect, HumanCondition, MachineCondition};
    use enclave_core::{ActorKind, ClientType, DevicePosture, ServiceAccountId, TenantId, UserId};

    use super::*;

    /// An administrator on an untrusted network, multi-factor, just now.
    fn admin(tenant: TenantId) -> RequestContext {
        let mut ctx = RequestContext::system(tenant);
        ctx.actor = Actor::User(UserId::new_v7());
        ctx.client = ClientType::Web;
        ctx.auth_strength = AuthStrength::MultiFactor;
        ctx.auth_time = chrono::Utc::now();
        ctx.network.source_ip = "192.0.2.44".parse().expect("a fixture address");
        ctx
    }

    fn request(
        audience: &str,
        effect: &str,
        mode: Option<&str>,
        when: serde_json::Value,
    ) -> RuleRequest {
        RuleRequest {
            audience: audience.to_owned(),
            name: "night shift".to_owned(),
            effect: effect.to_owned(),
            mode: mode.map(ToOwned::to_owned),
            when: serde_json::from_value(when).expect("a condition array"),
        }
    }

    /// The Q19 refusal, at the API boundary: a machine rule may not name a posture condition, and
    /// the refusal names the clause.
    ///
    /// The positive control is in the same test and is what stops it passing against a handler that
    /// refuses every body: the *identical* document under `HUMAN` decodes into the condition it
    /// names.
    #[test]
    fn a_machine_rule_naming_a_posture_condition_is_refused_by_name() {
        let posture = serde_json::json!([{ "posture_below": "MANAGED" }]);

        let refused =
            rule_from(RuleId::new_v7(), &request("MACHINE", "BLOCK", None, posture.clone()))
                .expect_err("a machine rule has no posture vocabulary");
        assert_eq!(refused.details()[0]["field"], "when");
        assert!(
            detail_of(&refused).contains("posture_below"),
            "the refused clause is the diagnosis: {}",
            detail_of(&refused)
        );

        let accepted = rule_from(RuleId::new_v7(), &request("HUMAN", "BLOCK", None, posture))
            .expect("the same document is a human rule");
        let Rule::Human(rule) = accepted else { panic!("the audience column selects the type") };
        assert_eq!(rule.when, vec![HumanCondition::PostureBelow(DevicePosture::Managed)]);
    }

    /// A clause that parsed is never kept when a sibling clause did not.
    ///
    /// This is the failure the strict decoder exists to prevent — a rule missing a condition matches
    /// *more* requests than the administrator wrote — and it is asserted here because an API is
    /// where it would be reintroduced.
    #[test]
    fn a_rule_is_never_trimmed_to_the_clauses_that_parsed() {
        let mixed = serde_json::json!([
            { "client_is": ["SYNC"] },
            { "posture_below": "MANAGED" },
        ]);
        assert!(
            rule_from(RuleId::new_v7(), &request("MACHINE", "NO_SYNC", None, mixed)).is_err(),
            "one unknown clause refuses the whole rule"
        );
    }

    /// `ALLOW` is refused, and the refusal says why rather than merely that.
    #[test]
    fn allow_is_refused_with_the_reason_it_does_not_exist() {
        let refused =
            rule_from(RuleId::new_v7(), &request("HUMAN", "ALLOW", None, serde_json::json!([])))
                .expect_err("there is no allow effect");
        assert_eq!(refused.details()[0]["field"], "effect");
        let detail = detail_of(&refused);
        assert!(detail.contains("most restrictive"), "the reason, not just the refusal: {detail}");
        // The positive control: an effect that does exist is accepted through the same path.
        assert!(rule_from(
            RuleId::new_v7(),
            &request("HUMAN", "REQUIRE_MFA", None, serde_json::json!([]))
        )
        .is_ok());
    }

    /// A rule written without a mode rehearses (`migrations/0019`), and a misspelled mode is
    /// refused rather than demoted to one.
    #[test]
    fn an_unstated_mode_rehearses_and_an_unrecognised_one_is_refused() {
        let rule =
            rule_from(RuleId::new_v7(), &request("HUMAN", "BLOCK", None, serde_json::json!([])))
                .expect("a rule with no mode");
        let Rule::Human(rule) = rule else { panic!("human") };
        assert_eq!(rule.mode, RuleMode::Simulation);

        assert!(rule_from(
            RuleId::new_v7(),
            &request("HUMAN", "BLOCK", Some("ENFORCED"), serde_json::json!([]))
        )
        .is_err());
    }

    /// No error carries the rule's name, and the response does.
    ///
    /// An assertion about an absence, so it is not made alone: the same name is asserted *present*
    /// in the view of the same rule, which is what stops this passing against a handler that omits
    /// the name everywhere.
    #[test]
    fn the_rules_name_is_in_the_response_and_in_no_refusal() {
        let named =
            request("MACHINE", "BLOCK", None, serde_json::json!([{"posture_below": "MANAGED"}]));
        let refused = rule_from(RuleId::new_v7(), &named).expect_err("refused");
        assert!(
            !serde_json::to_string(refused.details()).unwrap_or_default().contains("night shift"),
            "an error may not name a rule"
        );

        let row = RuleRow {
            id: RuleId::new_v7(),
            audience: "HUMAN".to_owned(),
            name: "night shift".to_owned(),
            conditions: "[]".to_owned(),
            effect: "BLOCK".to_owned(),
            mode: "SIMULATION".to_owned(),
        };
        assert_eq!(view(&row).name, "night shift");
    }

    /// The lockout check: a rule that would deny its author's own management action is refused, and
    /// one that would not is accepted.
    ///
    /// Both halves in one test, because "the rule was accepted" passes against a check that never
    /// fires and "the rule was refused" passes against one that refuses everything.
    #[test]
    fn a_rule_that_would_deny_its_authors_own_session_is_refused_and_a_narrower_one_is_not() {
        let ctx = admin(TenantId::new_v7());

        // The caller is in no zone, so "outside the corporate zone, then block" denies them.
        let lockout = Rule::Human(HumanRule::new(
            "corporate only",
            vec![HumanCondition::OutsideEveryZone(vec!["corporate".to_owned()])],
            Effect::Block,
        ));
        let refusal = refuse_self_lockout(&lockout, &ctx).expect_err("a lockout is refused");
        assert_eq!(refusal.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refusal.code(), "RULE_WOULD_DENY_ITS_AUTHOR");

        // The same rule, narrowed to an action an administrator is not performing.
        let narrower = Rule::Human(HumanRule::new(
            "no downloads from outside",
            vec![
                HumanCondition::OutsideEveryZone(vec!["corporate".to_owned()]),
                HumanCondition::ActionIs(vec![Action::File(enclave_core::FileAction::Download)]),
            ],
            Effect::Block,
        ));
        assert!(refuse_self_lockout(&narrower, &ctx).is_ok());
    }

    /// A rule that only rehearses locks nobody out, so it is never refused for it.
    #[test]
    fn a_simulated_rule_is_never_a_lockout() {
        let ctx = admin(TenantId::new_v7());
        let rule = HumanRule::new("corporate only", vec![], Effect::Block).simulated();
        assert!(!locks_out(&Rule::Human(rule.clone()), &ctx));
        // The control: the same rule, enforcing, is a lockout.
        assert!(locks_out(&Rule::Human(HumanRule { mode: RuleMode::Enforce, ..rule }), &ctx));
    }

    /// A machine rule cannot lock a person out, so it is not checked — and the check would not fire
    /// on one if it were, because `PolicySet::evaluate` runs one rule set chosen by principal kind.
    #[test]
    fn a_machine_rule_is_not_a_lockout_for_a_human_administrator() {
        let ctx = admin(TenantId::new_v7());
        assert_eq!(enclave_conditional_access::Audience::of(ActorKind::User).as_sql(), "HUMAN");
        let rule = Rule::Machine(enclave_conditional_access::MachineRule::new(
            "service accounts from the datacentre only",
            vec![MachineCondition::SourceOutside { networks: Vec::new(), zones: Vec::new() }],
            Effect::Block,
        ));
        assert!(!locks_out(&rule, &ctx));

        // The control: the same shape as a *human* rule with an always-matching condition list does
        // lock the administrator out, so "not a lockout" is not the answer this check always gives.
        assert!(locks_out(
            &Rule::Human(HumanRule::new("everyone", Vec::new(), Effect::Block)),
            &ctx
        ));
    }

    /// Break-glass does not authorize a lockout, though it waives network rules everywhere else.
    #[test]
    fn a_break_glass_session_may_not_enforce_a_rule_that_locks_out_ordinary_sessions() {
        let mut ctx = admin(TenantId::new_v7());
        ctx.scopes = enclave_core::ScopeSet::from_iter(["admin:break_glass".to_owned()]);
        let rule = Rule::Human(HumanRule::new(
            "corporate only",
            vec![HumanCondition::OutsideEveryZone(vec!["corporate".to_owned()])],
            Effect::Block,
        ));
        assert!(locks_out(&rule, &ctx), "the exemption is not honoured by this check");
    }

    /// Step-up: multi-factor *and* recent, with each half asserted against its control.
    #[test]
    fn a_privileged_mutation_needs_a_second_factor_and_a_recent_one() {
        let tenant = TenantId::new_v7();
        assert!(
            require_step_up(&admin(tenant), StepUpPolicy::Required { max_age_secs: 900 }).is_ok(),
            "the control: an MFA session just now"
        );

        let mut single = admin(tenant);
        single.auth_strength = AuthStrength::SingleFactor;
        let refusal = require_step_up(&single).expect_err("one factor is not recent MFA");
        assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
        assert_eq!(refusal.code(), "STEP_UP_REQUIRED");

        let mut stale = admin(tenant);
        stale.auth_time = chrono::Utc::now() - chrono::TimeDelta::minutes(16);
        assert!(require_step_up(&stale).is_err());
    }

    /// A rule is attributed to a person, because the column is `NOT NULL` and a service account has
    /// no row in `users`.
    #[test]
    fn only_a_user_may_author_a_rule() {
        let tenant = TenantId::new_v7();
        assert!(author(&admin(tenant)).is_ok());

        let mut machine = admin(tenant);
        machine.actor = Actor::ServiceAccount(ServiceAccountId::new_v7());
        assert!(author(&machine).is_err());

        let mut system = admin(tenant);
        system.actor = Actor::System;
        assert!(author(&system).is_err());
    }

    /// A stored row that no longer decodes is listed rather than hidden, with the clause named.
    ///
    /// The control is the good row beside it: a view that reported `decodes: false` for everything
    /// would satisfy the first assertion on its own.
    #[test]
    fn an_undecodable_stored_row_is_listed_with_the_reason() {
        let hostile = RuleRow {
            id: RuleId::new_v7(),
            audience: "MACHINE".to_owned(),
            name: "posture for a service account".to_owned(),
            conditions: r#"[{"posture_below":"MANAGED"}]"#.to_owned(),
            effect: "BLOCK".to_owned(),
            mode: "ENFORCE".to_owned(),
        };
        let rendered = view(&hostile);
        assert!(!rendered.decodes);
        assert!(rendered.decode_error.expect("a reason").contains("posture_below"));

        let good = RuleRow { conditions: "[]".to_owned(), ..hostile };
        let rendered = view(&good);
        assert!(rendered.decodes, "the control: a good row decodes");
        assert!(rendered.decode_error.is_none());
    }

    /// A decoder message is bounded before it is echoed.
    #[test]
    fn a_decoder_message_cannot_echo_an_unbounded_body() {
        let long = "x".repeat(MAX_DETAIL_CHARS * 3);
        assert!(clip(&long).chars().count() <= MAX_DETAIL_CHARS + 1);
        // The control: a short message is passed through whole, so this does not pass against a
        // function that truncates everything to nothing.
        assert_eq!(clip("unknown variant `posture_below`"), "unknown variant `posture_below`");
    }

    /// The one detail sentence an envelope carries.
    fn detail_of(envelope: &Envelope) -> String {
        envelope.details()[0]["detail"].as_str().unwrap_or_default().to_owned()
    }
}
