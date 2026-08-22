//! `/api/v1/admin/dlp/rules` — writing the rules that decide what content may leave.
//!
//! `ENC-633`, and the exact shape of [`super::conditional_access`] one stage over. `ENC-615` gave
//! DLP rules a table, a repository, a strict decoder and the wired stage; the write path was
//! `enclave_db::insert_dlp_rule`, which nothing called, so a security administrator's only route to
//! the rule that makes `ENFORCE` refuse anything was a `psql` session against the application role.
//!
//! `docs/05-API.md §14.2` is authoritative for the contract. What follows is why it has this shape,
//! and the three places it differs from the conditional-access surface — each difference is a
//! property of the DLP rule model rather than a choice made here.
//!
//! # The request body may not be more permissive than the decoder
//!
//! **Q16 — structured detectors, no regex on the synchronous path.** `enclave_dlp::Condition` is a
//! comparison against a count, a rank, a severity or a score, and there is no variant a pattern
//! could occupy. Storage is where that is most easily lost, and `ENC-615` closed it by making
//! decoding strict and closed. An API is the *other* place, and losing it there would be silent: a
//! body deserialized into a lenient shape accepts the rule the decoder refuses and stores what was
//! left of it. The break `ENC-615` watched is exact — removing `deny_unknown_fields` lets
//! `{"category_at_least":{"category":"FINANCIAL","count":1,"pattern":"x"}}` decode as an ordinary
//! count comparison **with the pattern silently dropped**.
//!
//! So this module holds **no condition vocabulary of its own**:
//!
//! 1. the body's `scope` and `conditions` are carried as raw JSON, exactly as sent;
//! 2. they are assembled into a [`DlpRuleRow`] — the stored form — and handed to [`decode_rule`],
//!    the same function `enclave_dlp::TenantDlp` runs on every request;
//! 3. the decoded [`DlpRule`] is re-encoded with [`encode_rule`], and *that* is what is written.
//!
//! Step 2 is what holds the property. Step 3 is belt-and-braces, and `ENC-603` recorded a deliberate
//! break proving it: `jsonb` normalises key order, so storing the request's own document instead
//! fails no test. It stays for the reason given there — the column should hold a value the *type*
//! produced — and the same honesty applies here.
//!
//! # `ALLOW` is refused, and told why
//!
//! `docs/06 §10` lists it and [`DlpAction::Allow`] exists, but it cannot be stored: its demand is
//! `Demand::Nothing`, and `Verdict::blocking_code` **scans past** a `Nothing` to the next fired
//! rule. An `ALLOW` written above a `BLOCK` therefore fires and changes nothing — the administrator
//! writes the exception, sees it stored, watches it fire and is refused anyway. It is refused twice
//! already, by `DlpAction::from_sql` and by `migrations/0021`'s `CHECK`; here it is refused a third
//! time in the only way that helps the person writing it, with the reason and what to write instead.
//!
//! # Three differences from the conditional-access surface
//!
//! **There is no `PATCH`.** That one carries `mode`, and a DLP rule has no mode: D28 keeps
//! `SIMULATION` and `ENFORCE` from diverging by giving `RuleSet::evaluate` no mode argument, so
//! there is no per-rule rollout step to expose (`ENC-632` is the row for a tenant-level one).
//! Conditions, scope, action and priority are not editable for the reason `docs/05 §14.1` gives for
//! conditional access: changing what a rule refuses is a withdrawal and a new rule, so the text of
//! what was in force during any period stays readable.
//!
//! **There is no `DELETE` underneath the `DELETE`.** Withdrawal sets `deleted_at` and `enclave_app`
//! holds no `DELETE` grant — and here the argument is stronger than "history is evidence":
//! `docs/06 §9`'s mandatory-simulation gate is *a query over past observations that names a rule*,
//! so a deleted rule is a rule whose rehearsal cannot be found, and enforcement of its successor
//! cannot be justified.
//!
//! **The lockout check asks a different question**, and the answer is in [`refuse_self_lockout`].
//!
//! # What a rejected rule is told, and what it is never told
//!
//! As `ENC-603`: the rule's **name** is operator-facing, is in every response, and is in no error —
//! `DlpRuleError`'s own `Display` embeds it, so this module reads the error's *structure* rather
//! than its message. The clause that was refused **is** reported, because *unknown variant
//! `pattern`* is the whole diagnostic value of a closed decoder.

use core::str::FromStr as _;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::Json;
use enclave_core::Exposure;
use enclave_core::{
    Action, Actor, AdminAction, AuthStrength, Error, RequestContext, RequestId, ResourceRef,
    TenantId, UserId, ValidationCode,
};
use enclave_db::{DbError, DlpRuleId, DlpRuleRow};
use enclave_dlp::{decode_rule, encode_rule, DlpRule, DlpRuleError, TenantDlp};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticated;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// How recently a privileged mutation's caller must have authenticated.
///
/// `docs/06 §22` lists *disabling or weakening DLP* among the operations needing recent MFA plus
/// audit, and writing a rule is the same surface: the rule that is not written is the refusal that
/// does not happen. Fifteen minutes is `docs/05-API.md §14`'s documented default.
///
/// A second constant rather than one shared with [`super::conditional_access`], deliberately kept
/// where a reader of either module meets it: the value is the same and the *reason* is per-surface,
/// and `ENC-620` moves both into the conditional-access stage where they can be audited as the
/// denials they are.
const STEP_UP_MAX_AGE_SECS: i64 = 15 * 60;

/// The action every write on this surface is authorized as.
///
/// `docs/06 §22` groups *disabling or weakening DLP* with changing conditional access and changing
/// identity providers, which is what [`AdminAction::ManagePolicy`] names — deliberately not
/// [`AdminAction::WriteConfig`], which is branding and domains.
const WRITE_ACTION: Action = Action::Admin(AdminAction::ManagePolicy);

/// The action reading this surface is authorized as.
const READ_ACTION: Action = Action::Admin(AdminAction::ReadConfig);

/// The action a rule may not govern. See [`refuse_self_lockout`].
const WITHDRAWAL_ACTION: Action = Action::Admin(AdminAction::ManagePolicy);

/// The longest decoder message that reaches a caller.
///
/// serde quotes the offending name, and the offending name came from the request.
const MAX_DETAIL_CHARS: usize = 240;

/// `migrations/0021`'s default, applied here so the stored row and the response agree.
const DEFAULT_PRIORITY: i32 = 100;

/// The unique index `migrations/0021` puts over live rule names.
const LIVE_NAME_INDEX: &str = "uq_dlp_rules_live_name";

/// Forgetting one tenant's cached rules on the replica that changed them.
///
/// A trait rather than the concrete type for [`super::conditional_access::RuleCache`]'s two
/// reasons: a test that wants to know whether the write path invalidates should not need a
/// database, and the trait is the honest shape of what a handler needs — it does not read this
/// cache or decide against it, it tells it that something changed.
///
/// **The API's correctness does not depend on it.** `ENC-615`'s bound is the 15-second TTL and this
/// is the shortcut for the one replica that made the change; a deployment that has not wired it is
/// exactly as correct, fifteen seconds later.
pub trait DlpRuleCache: Send + Sync + std::fmt::Debug {
    /// Forgets this tenant's cached rules, so this replica reads them again on the next request.
    fn invalidate(&self, tenant: TenantId);
}

impl DlpRuleCache for TenantDlp {
    fn invalidate(&self, tenant: TenantId) {
        Self::invalidate(self, tenant);
    }
}

/// The cache handle as [`ApiState`] holds it — for `main.rs`, which wires one in a line.
pub type SharedDlpRuleCache = Arc<dyn DlpRuleCache>;

// --- Wire types ---------------------------------------------------------------------------------

/// A rule as an administrator writes one.
///
/// `deny_unknown_fields`, and it is the whole of Q16 at this boundary rather than tidiness: see the
/// module header for the document it stops.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleRequest {
    /// What the administrator calls it. Unique among the tenant's live rules, and the identity the
    /// evaluator uses — `enclave_dlp::RuleId` *is* the name.
    name: String,
    /// Rule order, ascending. Absent means `migrations/0021`'s default.
    #[serde(default)]
    priority: Option<i32>,
    /// Which actions the rule governs, in the stored vocabulary, carried verbatim.
    scope: Vec<serde_json::Value>,
    /// The conjunctive condition list, in the stored vocabulary, carried verbatim.
    conditions: Vec<serde_json::Value>,
    /// One of the twelve storable actions. `ALLOW` is not one of them.
    action: String,
    /// The rank `RECLASSIFY` raises the resource to, and absent for every other action.
    #[serde(default, rename = "reclassifyTo")]
    reclassify_to: Option<i32>,
}

/// A stored rule, as an administrator reads one back.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    /// The rule's identifier, unique within the tenant.
    id: String,
    /// What the administrator called it. Operator-facing, and here rather than in any error.
    name: String,
    /// Rule order.
    priority: i32,
    /// The scopes, exactly as stored.
    scope: serde_json::Value,
    /// The conditions, exactly as stored.
    conditions: serde_json::Value,
    /// The action.
    action: String,
    /// The reclassification target, for the one action that has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    reclassify_to: Option<i32>,
    /// Whether the stored document still decodes into a rule this stage can evaluate.
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
/// The `page` object is `docs/05-API.md §6`'s, with no cursor, for [`super::conditional_access`]'s
/// reason: the whole live set is what `TenantDlp` loads on every request in the chain anyway, so a
/// tenant with enough rules for the envelope to matter has a per-request cost nobody has measured.
#[derive(Debug, Serialize)]
pub struct RuleList {
    /// The tenant's live rules, in evaluation order — `priority`, then `name`.
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

/// Handles `GET /api/v1/admin/dlp/rules`.
///
/// # Why one undecodable row does not fail this list
///
/// `enclave_dlp::store::decode_rules` fails the **whole** set when one row cannot be decoded, so
/// that a policy is never silently missing a refusal — and `TenantDlp` carries that error to the
/// caller, so every request in the tenant fails while such a row is live. This is the surface an
/// administrator repairs that from, and a list that failed the way the loader does could not be
/// used to repair anything: they could not learn which rule to withdraw, or its id, because listing
/// them is what failed.
///
/// So each row is decoded **individually** and the outcome reported per rule. Nothing is weakened:
/// it reads, it never writes, and a row reported as `decodes: false` is a row the chain is still
/// failing every request over. The leniency is in what is *shown*.
///
/// The same caveat `ENC-623` records for conditional access applies here and is asserted rather
/// than worked around: the chain runs first, its DLP stage loads the same rows, and it fails on the
/// same one — so this endpoint answers `500` in a tenant whose rules do not decode, and the repair
/// surface is inside its own blast radius.
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
    let rows = enclave_db::load_dlp_rules(&mut tx)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // `no-store`: a shared cache holding this would serve one tenant's security policy out of a
    // proxy another caller's browser talked to.
    Ok((
        [(header::CACHE_CONTROL, NO_STORE)],
        Json(RuleList {
            items: rows.iter().map(view).collect(),
            page: Page { next_cursor: None, has_more: false },
        }),
    )
        .into_response())
}

/// Handles `POST /api/v1/admin/dlp/rules`.
///
/// # Ordering
///
/// The chain runs before the body is looked at. A caller the chain refuses learns nothing about the
/// request schema, the condition vocabulary or the tenant's rules — not even that their JSON was
/// malformed.
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
    if let Err(envelope) = require_step_up(&ctx) {
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

    let id = DlpRuleId::new_v7();
    let priority = request.priority.unwrap_or(DEFAULT_PRIORITY);
    let candidate = match rule_from(id, priority, &request) {
        Ok(rule) => rule,
        Err(envelope) => return Ok(envelope.into_response(request_id)),
    };

    if let Err(envelope) = refuse_self_lockout(&candidate) {
        return Ok(envelope.into_response(request_id));
    }

    // The row that is stored is the serialization of the decoded rule, never the bytes that
    // arrived. See the module header for what that is and is not worth.
    let row = encode_rule(id, priority, &candidate)
        .map_err(|error| ApiError::new(Error::from(error), request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    if let Err(error) = enclave_db::insert_dlp_rule(&mut tx, &row, author).await {
        return write_failure(error, request_id);
    }
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    written(&state, &ctx, "created", &row);

    let location = format!("/api/v1/admin/dlp/rules/{id}");
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, NO_STORE)],
        [(header::LOCATION, location)],
        Json(view(&row)),
    )
        .into_response())
}

/// Handles `DELETE /api/v1/admin/dlp/rules/{id}` — withdrawal.
///
/// # `DELETE` at the edge is an `UPDATE` underneath, and here that is load-bearing twice
///
/// `migrations/0021` grants `enclave_app` no `DELETE`. The first reason is the one every policy
/// table has: a statement that stops a tenant's content inspection refusing anything, leaving
/// nothing to say it ever did. The second is specific to DLP — `docs/06 §9` refuses enforcement of
/// a policy that has never been simulated, and that gate is a **query over observation history that
/// names a rule**. A deleted rule is one whose rehearsal cannot be found.
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
    if let Err(envelope) = require_step_up(&ctx) {
        return Ok(envelope.into_response(request_id));
    }

    // A malformed id is answered exactly as an unknown one, and an unknown one exactly as another
    // tenant's: `CLAUDE.md` rule 7, and one answer is easier to keep than to re-derive.
    let id = rule_id(&id).ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    let withdrawn = enclave_db::withdraw_dlp_rule(&mut tx, id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;
    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // Withdrawing another tenant's rule, an unknown rule and an already-withdrawn rule all move
    // zero rows, and all three are told the same thing. The first is `CLAUDE.md` rule 7; the other
    // two are `enclave_db::withdraw_dlp_rule`'s own note — the record of *when* a rule stopped
    // applying is written once, so a repeat is not an update.
    if !withdrawn {
        return Err(ApiError::new(Error::NotFound, request_id));
    }

    invalidate(&state, ctx.tenant_id);
    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        rule_id = %id,
        "DLP rule withdrawn"
    );
    Ok((StatusCode::NO_CONTENT, [(header::CACHE_CONTROL, NO_STORE)]).into_response())
}

// --- The chain, and the two checks that sit beside it --------------------------------------------

/// Runs the policy chain for an administrative action on this tenant.
///
/// The resource is the tenant itself rather than the rule, for [`super`]'s reason: the question is
/// whether this caller may manage this tenant's policy, and the rule's existence is settled
/// afterwards by a statement that moves no rows.
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
    // Note what that means for the check below: a DLP rule whose scope reaches an administrative
    // action refuses this request *whatever* it demands, because every demand is undischargeable
    // here. `refuse_self_lockout` is the reason that cannot be written through this surface.
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
/// `docs/06 §22`, `docs/05-API.md §14`. It runs **after** `enforce` so the chain decides first, and
/// the cost of that ordering is the one [`super::conditional_access::require_step_up`] records:
/// the engine has already written an *allow* row when this refuses. `ENC-620` is the row for moving
/// it into the conditional-access stage, where it would be audited as the denial it is.
fn require_step_up(ctx: &RequestContext) -> Result<(), Envelope> {
    if ctx.auth_strength.meets(AuthStrength::MultiFactor)
        && ctx.auth_age(chrono::Utc::now()).num_seconds() <= STEP_UP_MAX_AGE_SECS
    {
        return Ok(());
    }

    tracing::warn!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        "a DLP rule change was refused for want of a recent second factor"
    );
    Err(Envelope::new(
        StatusCode::FORBIDDEN,
        "STEP_UP_REQUIRED",
        "This action needs a fresher sign-in.",
        "Re-authenticate with a second factor and retry.",
    )
    .with_details(vec![serde_json::json!({
        "acr": "mfa",
        "maxAge": STEP_UP_MAX_AGE_SECS,
    })]))
}

/// The user this rule will be attributed to.
///
/// `dlp_rules.created_by` is `NOT NULL` and carries a composite foreign key onto
/// `users (tenant_id, id)`, because *"the system" is not an answer to "who stopped the finance
/// team downloading their own reports"*. A service account, an MCP client or `system` has no row in
/// `users`; rather than let the foreign key report that as an internal error, the requirement is
/// stated here — and the caller records the refusal before returning it, because by this point the
/// chain has written its `ALLOW` for `admin.manage_policy` (`ENC-606`).
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        _ => Err(Refused::actor(enclave_core::ReasonCode::AccessDenied)),
    }
}

// --- The lockout check ---------------------------------------------------------------------------

/// Refuses a rule that would govern the action able to withdraw it.
///
/// # Does a DLP rule have a self-lockout, and is it the same one?
///
/// It has one, and it is **worse than conditional access's** in two ways, which is why the check
/// here is structural rather than a rehearsal of the caller's own session.
///
/// The DLP stage runs on every action the chain decides, administrative actions included, and
/// [`ActionScope`] can name them: `any` covers every action, and `exactly` takes an
/// `enclave_core::Action`, whose wire form has an `admin` family. So a rule scoped `["any"]` — the
/// obvious way to write *"notify security whenever anything happens to a document with a card
/// number in it"* — also governs `admin.manage_policy` on the tenant.
///
/// Once it governs that action, **three separate routes refuse the request**, and none of them
/// depends on the rule's conditions being satisfied:
///
/// * A demand that refuses (`BLOCK`, `QUARANTINE`) refuses it directly.
/// * A demand that obliges (`WATERMARK`, `READ_ONLY`, `NO_DOWNLOAD`, `RECLASSIFY`, …) refuses it
///   too: this surface can discharge no obligation, so `none_dischargeable` in [`enforce`] turns
///   any of them into a refusal (D29).
/// * And the one that needs no rule to fire at all: `RuleSet::evaluate` consults the facts only
///   **after** deciding that some rule governs the action, so a governed action on a resource with
///   no facts — which is every administrative action, because a tenant has no version to have been
///   scanned — is refused outright under `facts_unavailable: FAIL_CLOSED`, the default
///   (`docs/06 §12`, `crates/core/src/policy.rs`). One `any`-scoped rule of any action whatsoever
///   therefore refuses **every administrative request in the tenant**.
///
/// The second difference is the escape. A conditional-access rule may be written, rehearsed in
/// `SIMULATION` and promoted from a session it allows — that is why `ENC-603` refuses only the
/// promotion. A DLP rule has no per-rule mode by construction (D28), so there is no rehearsal to
/// write it into and no session it decides differently for: DLP conditions are about the
/// *resource*, not the principal, so the rule that locks out its author locks out every
/// administrator equally. The only way back would be a `psql` session — the support incident this
/// surface exists to remove.
///
/// So the question asked is the narrow structural one: **does this rule's scope govern
/// `admin.manage_policy`** — the action that would withdraw it? A rule scoped to
/// `exposes_content`, to `external_sharing`, or to explicit file actions does not, and is
/// unaffected. What it costs an administrator is the `any` scope, and the refusal says what to
/// write instead.
///
/// # Why the exposure passed here is `Internal`
///
/// [`ActionScope::matches`] consults the resource's exposure for one scope only —
/// `external_sharing` matches `share.update` on an already-external resource — and no
/// administrative action is a share action, so the answer is the same under either exposure. The
/// internal one is passed because it is the one an administrative call against a tenant has.
fn refuse_self_lockout(candidate: &DlpRule) -> Result<(), Envelope> {
    if !candidate.governs(WITHDRAWAL_ACTION, Exposure::Internal) {
        return Ok(());
    }
    Err(Envelope::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "RULE_WOULD_GOVERN_ITS_OWN_WITHDRAWAL",
        "This rule would let DLP decide the administrative action that withdraws it.",
        "Scope it to the actions it is about — exposes_content, external_sharing, or the exact \
         file actions — rather than to every action.",
    )
    .with_details(vec![serde_json::json!({
        "field": "scope",
        "code": ValidationCode::Inconsistent.as_str(),
        "detail": "a rule governing admin/manage_policy is evaluated against a tenant, which has no \
                   content and therefore no security facts — so under the default \
                   facts_unavailable policy it refuses every administrative request in this tenant, \
                   including the one that would withdraw it, whatever its conditions say",
    })]))
}

// --- Decoding a request into a rule ---------------------------------------------------------------

/// Turns a request body into a rule, through the decoder the loader uses.
///
/// Every refusal below the field checks is the *stored* decoder's refusal, reported against the
/// field the administrator wrote. See the module header for why this function has no vocabulary of
/// its own.
fn rule_from(id: DlpRuleId, priority: i32, request: &RuleRequest) -> Result<DlpRule, Envelope> {
    // The three checks `migrations/0021`'s constraints make, made here so that an administrator
    // meets a named field rather than a `500` carrying a constraint name.
    if request.name.trim().is_empty() || request.name.chars().count() > 200 {
        return Err(bad_field(
            "name",
            ValidationCode::InvalidFormat,
            "a rule name is between 1 and 200 characters, is unique among this tenant's live rules, \
             and is the identity the evaluator records when the rule fires",
        ));
    }
    if priority < 0 {
        return Err(bad_field(
            "priority",
            ValidationCode::OutOfRange,
            "priority is zero or greater, ascending; it decides which reason code a refused caller \
             sees when two rules refuse, and it does not decide whether a rule fires",
        ));
    }
    if request.scope.is_empty() {
        // Not tidiness, and not something to leave to the `CHECK`: `DlpRule::governs` reads an
        // empty scope as governing *nothing*, which is the right default and makes an empty scope
        // a rule that silently protects nothing. An administrator should learn that now rather
        // than during the incident it failed to prevent.
        return Err(bad_field(
            "scope",
            ValidationCode::Required,
            "a rule with no scope governs no action at all, so it would be stored, listed and never \
             fire; name the actions it is about",
        ));
    }

    let scope = serde_json::to_string(&request.scope).map_err(|_error| {
        bad_field("scope", ValidationCode::InvalidFormat, "the scope list could not be read")
    })?;
    let conditions = serde_json::to_string(&request.conditions).map_err(|_error| {
        bad_field(
            "conditions",
            ValidationCode::InvalidFormat,
            "the condition list could not be read",
        )
    })?;

    let row = DlpRuleRow {
        id,
        name: request.name.clone(),
        priority,
        scope,
        conditions,
        action: request.action.clone(),
        reclassify_to: request.reclassify_to,
    };

    decode_rule(&row).map_err(|error| rejected_rule(&error))
}

/// Renders a decoder refusal as a `docs/05-API.md §5` envelope.
///
/// The rule's **name** is not in any of these, though `DlpRuleError`'s `Display` carries it: this
/// reads the error's structure rather than its message. See the module header.
fn rejected_rule(error: &DlpRuleError) -> Envelope {
    match error {
        DlpRuleError::UnknownAction { action, .. } if action.eq_ignore_ascii_case("ALLOW") => {
            bad_field(
                "action",
                ValidationCode::Unsupported,
                "there is no storable ALLOW: its demand is nothing, and the evaluator scans past a \
                 rule that demands nothing to the next one that refuses — so an ALLOW written above \
                 a BLOCK fires, changes nothing, and the caller is refused anyway. Write the \
                 exception as a narrower scope or condition on the restrictive rule (docs/06 §10, \
                 ENC-631)",
            )
        }
        DlpRuleError::UnknownAction { .. } => bad_field(
            "action",
            ValidationCode::Unsupported,
            "the action is one of AUDIT, WARN, REQUIRE_JUSTIFICATION, REQUIRE_APPROVAL, BLOCK, \
             QUARANTINE, REMOVE_SHARE, READ_ONLY, NO_DOWNLOAD, WATERMARK, RECLASSIFY, \
             NOTIFY_SECURITY",
        ),
        DlpRuleError::ReclassifyTarget { .. } => bad_field(
            "reclassifyTo",
            ValidationCode::Inconsistent,
            "RECLASSIFY raises a resource to a rank and needs one; every other action has no rank \
             to raise, and a rank stored beside it is a value nothing reads",
        ),
        // The two that carry serde's own account, because the offending clause is named in it and
        // that name is the whole diagnostic value of a closed decoder.
        DlpRuleError::Scope { source, .. } => {
            detailed("scope", ValidationCode::Unsupported, clip(&source.to_string()))
        }
        DlpRuleError::Conditions { source, .. } => {
            detailed("conditions", ValidationCode::Unsupported, clip(&source.to_string()))
        }
        // Serialization of a value that decoded — not the caller's doing — and whatever a future
        // variant turns out to be. `DlpRuleError` is `#[non_exhaustive]`.
        _ => bad_field(
            "conditions",
            ValidationCode::InvalidFormat,
            "the rule could not be stored as written",
        ),
    }
}

/// A body that is not the shape this endpoint reads.
///
/// serde's message quotes the input, so it is not repeated. An unknown field is called out by name
/// because `deny_unknown_fields` is what stops a misspelled key being dropped in silence, and
/// "unknown field" with no further explanation reads as a bug in the client.
fn unreadable_body(error: &serde_json::Error) -> Envelope {
    let detail = if error.to_string().starts_with("unknown field") {
        "the body carries a field this endpoint does not read; a condition or scope key that is \
         quietly dropped is a rule that governs more requests than its author wrote"
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
/// tenant, because the name **is** the rule's identity to the evaluator (`enclave_dlp::RuleId`) and
/// two rules sharing one would make an observation ambiguous at exactly the moment somebody is
/// working out which rule fired.
///
/// The name is **not** echoed: the caller sent it, but a collision report is the one place a rule
/// an administrator has not been shown could be named back to them.
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

/// Records a write, and tells this replica's cache about it.
///
/// The log line is not the audit trail — audit happens inside the policy engine, for denials as
/// well as allows (`CLAUDE.md` rule 10), and the engine has already written the row for this
/// action. This adds what the audit row cannot carry: *which* rule, by the name an operator
/// recognises, and what it will demand (`ENC-622`).
fn written(state: &ApiState, ctx: &RequestContext, what: &'static str, row: &DlpRuleRow) {
    invalidate(state, ctx.tenant_id);
    tracing::info!(
        %ctx.request_id,
        %ctx.tenant_id,
        actor = ?ctx.actor.kind(),
        rule_id = %row.id,
        rule = %row.name,
        priority = row.priority,
        action = %row.action,
        "DLP rule {what}"
    );
}

/// Tells this replica's cache that a tenant's rules changed, if anything is listening.
///
/// The TTL is the bound and this is the shortcut; see [`DlpRuleCache`].
fn invalidate(state: &ApiState, tenant: TenantId) {
    match state.dlp_rule_cache.as_ref() {
        Some(cache) => cache.invalidate(tenant),
        None => tracing::debug!(
            %tenant,
            "no DLP rule cache is wired to this API; the change applies everywhere within the \
             cache TTL"
        ),
    }
}

// --- Views -----------------------------------------------------------------------------------------

/// Renders a stored row, decoding it to report whether it still decodes. See [`list_rules`].
fn view(row: &DlpRuleRow) -> RuleView {
    let (decodes, decode_error) = match decode_rule(row) {
        Ok(_rule) => (true, None),
        Err(DlpRuleError::Scope { ref source, .. })
        | Err(DlpRuleError::Conditions { ref source, .. }) => {
            (false, Some(clip(&source.to_string())))
        }
        Err(ref error) => (false, Some(clip(&stored_fault(error)))),
    };
    RuleView {
        id: row.id.to_string(),
        name: row.name.clone(),
        priority: row.priority,
        scope: serde_json::from_str(&row.scope).unwrap_or(serde_json::Value::Null),
        conditions: serde_json::from_str(&row.conditions).unwrap_or(serde_json::Value::Null),
        action: row.action.clone(),
        reclassify_to: row.reclassify_to,
        decodes,
        decode_error,
    }
}

/// What is wrong with a stored row, without the rule's name — the caller already has that field.
fn stored_fault(error: &DlpRuleError) -> String {
    match error {
        DlpRuleError::UnknownAction { action, .. } => {
            format!("`{action}` is not an action this stage can demand")
        }
        DlpRuleError::ReclassifyTarget { problem, .. } => {
            format!("the reclassification target is {problem}")
        }
        other => other.to_string(),
    }
}

/// Parses a path id, or reports nothing at all about why it did not.
fn rule_id(value: &str) -> Option<DlpRuleId> {
    uuid::Uuid::from_str(value).ok().map(DlpRuleId::from_uuid)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{ClientType, FileAction, ServiceAccountId, TenantId, UserId};
    use enclave_dlp::{ActionScope, Condition, DlpAction};

    use super::*;

    /// An administrator, multi-factor, just now.
    fn admin(tenant: TenantId) -> RequestContext {
        let mut ctx = RequestContext::system(tenant);
        ctx.actor = Actor::User(UserId::new_v7());
        ctx.client = ClientType::Web;
        ctx.auth_strength = AuthStrength::MultiFactor;
        ctx.auth_time = chrono::Utc::now();
        ctx
    }

    fn request(
        scope: serde_json::Value,
        conditions: serde_json::Value,
        action: &str,
    ) -> RuleRequest {
        RuleRequest {
            name: "payment data may not leave".to_owned(),
            priority: None,
            scope: serde_json::from_value(scope).expect("a scope array"),
            conditions: serde_json::from_value(conditions).expect("a condition array"),
            action: action.to_owned(),
            reclassify_to: None,
        }
    }

    fn built(request: &RuleRequest) -> Result<DlpRule, Envelope> {
        rule_from(DlpRuleId::new_v7(), DEFAULT_PRIORITY, request)
    }

    /// The one detail sentence an envelope carries.
    fn detail_of(envelope: &Envelope) -> String {
        envelope.details()[0]["detail"].as_str().unwrap_or_default().to_owned()
    }

    /// **Q16, at the API boundary.** A condition may not carry a pattern, and the refusal names it.
    ///
    /// The positive control is in the same test and is what stops it passing against a handler that
    /// refuses every body: the same clause *without* the pattern decodes into the comparison it
    /// names. `ENC-615` watched the break this asserts — dropping `deny_unknown_fields` makes the
    /// third document below decode as an ordinary count comparison with `pattern` discarded.
    #[test]
    fn a_condition_carrying_a_pattern_is_refused_by_name() {
        for smuggled in [
            serde_json::json!([{ "pattern": "\\d{16}" }]),
            serde_json::json!([{ "regex": "[A-Z]{2}\\d{2}" }]),
            serde_json::json!([{ "category_at_least": {
                "category": "FINANCIAL", "count": 1, "pattern": "x" } }]),
        ] {
            let refused =
                built(&request(serde_json::json!(["external_sharing"]), smuggled, "BLOCK"))
                    .expect_err("a pattern is not a condition");
            assert_eq!(refused.details()[0]["field"], "conditions");
            let detail = detail_of(&refused);
            assert!(
                detail.contains("unknown variant") || detail.contains("unknown field"),
                "serde must name what it refused: {detail}"
            );
        }

        // The control: the same shape, with a condition this stage does have.
        let accepted = built(&request(
            serde_json::json!(["external_sharing"]),
            serde_json::json!([{ "category_at_least": { "category": "FINANCIAL", "count": 1 } }]),
            "BLOCK",
        ))
        .expect("a count comparison is a condition");
        assert_eq!(
            accepted.conditions(),
            [Condition::CategoryAtLeast {
                category: enclave_core::DetectorCategory::Financial,
                count: 1
            }]
        );
    }

    /// A rule is refused whole, never trimmed to the clauses that parsed.
    ///
    /// Both halves — a rule that lost a *condition* fires on more requests than its author wrote,
    /// and one that lost a *scope* governs fewer.
    #[test]
    fn a_rule_is_never_trimmed_to_the_clauses_that_parsed() {
        let mixed_conditions = built(&request(
            serde_json::json!(["exposes_content"]),
            serde_json::json!([{ "any_finding": null }, { "pattern": "x" }]),
            "BLOCK",
        ));
        assert!(mixed_conditions.is_err(), "one unknown clause refuses the whole rule");

        let mixed_scope = built(&request(
            serde_json::json!(["exposes_content", "everything_ever"]),
            serde_json::json!([]),
            "BLOCK",
        ));
        let refused = mixed_scope.expect_err("one unknown scope refuses the whole rule");
        assert_eq!(refused.details()[0]["field"], "scope");

        // The control: both lists, entirely in vocabulary, are accepted.
        assert!(built(&request(
            serde_json::json!(["exposes_content", "external_sharing"]),
            serde_json::json!([{ "any_finding": null }]),
            "BLOCK",
        ))
        .is_ok());
    }

    /// `ALLOW` is refused, and the refusal says why rather than merely that.
    #[test]
    fn allow_is_refused_with_the_reason_it_cannot_be_stored() {
        let refused =
            built(&request(serde_json::json!(["exposes_content"]), serde_json::json!([]), "ALLOW"));
        let refused = refused.expect_err("ALLOW is not storable");
        assert_eq!(refused.details()[0]["field"], "action");
        let detail = detail_of(&refused);
        assert!(
            detail.contains("scans past"),
            "the reason an ALLOW does nothing, not just the refusal: {detail}"
        );

        // The control: an action that *is* storable, in the same position.
        assert!(built(&request(
            serde_json::json!(["exposes_content"]),
            serde_json::json!([]),
            "NOTIFY_SECURITY",
        ))
        .is_ok());
    }

    /// A scope that governs the withdrawal action is refused, and a narrower one is not.
    ///
    /// Both halves in one test: "the rule was refused" passes against a check that refuses
    /// everything, and "the rule was accepted" against one that never fires.
    #[test]
    fn a_rule_that_would_govern_its_own_withdrawal_is_refused() {
        let sweeping =
            built(&request(serde_json::json!(["any"]), serde_json::json!([]), "NOTIFY_SECURITY"))
                .expect("`any` is a scope this stage can read");
        let refusal = refuse_self_lockout(&sweeping).expect_err("`any` reaches admin actions");
        assert_eq!(refusal.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refusal.code(), "RULE_WOULD_GOVERN_ITS_OWN_WITHDRAWAL");

        // Naming the action explicitly is the same rule by another road.
        let named = built(&request(
            serde_json::json!([{ "exactly": { "resource": "admin", "action": "manage_policy" } }]),
            serde_json::json!([]),
            "BLOCK",
        ))
        .expect("an admin action is expressible in a scope, which is the point");
        assert!(refuse_self_lockout(&named).is_err());

        // The controls: the three scopes an administrator actually wants, none of which reaches an
        // administrative action.
        for scope in [
            serde_json::json!(["exposes_content"]),
            serde_json::json!(["external_sharing"]),
            serde_json::json!([{ "exactly": { "resource": "file", "action": "download" } }]),
            // And an administrative action that is *not* the one that withdraws the rule: the
            // check is narrow, so this passes — recorded rather than left implicit.
            serde_json::json!([{ "exactly": { "resource": "admin", "action": "read_audit" } }]),
        ] {
            let rule = built(&request(scope.clone(), serde_json::json!([]), "BLOCK"))
                .expect("a scope this stage can read");
            assert!(refuse_self_lockout(&rule).is_ok(), "{scope} is not a lockout");
        }
    }

    /// An empty scope is refused rather than stored as a rule that never fires.
    #[test]
    fn a_rule_with_no_scope_is_refused_rather_than_stored_inert() {
        let refused =
            built(&request(serde_json::json!([]), serde_json::json!([]), "BLOCK")).expect_err("");
        assert_eq!(refused.details()[0]["field"], "scope");
        // The control: one scope is enough.
        assert!(built(&request(
            serde_json::json!(["exposes_content"]),
            serde_json::json!([]),
            "BLOCK"
        ))
        .is_ok());
    }

    /// A `RECLASSIFY` and its rank travel together, in both directions.
    #[test]
    fn a_reclassification_without_a_rank_is_refused_and_so_is_a_rank_without_one() {
        let mut without =
            request(serde_json::json!(["exposes_content"]), serde_json::json!([]), "RECLASSIFY");
        let refused = built(&without).expect_err("an obligation with no target");
        assert_eq!(refused.details()[0]["field"], "reclassifyTo");

        let mut stray =
            request(serde_json::json!(["exposes_content"]), serde_json::json!([]), "BLOCK");
        stray.reclassify_to = Some(30);
        assert!(built(&stray).is_err(), "a rank on an action with no target reads nothing");

        // The control: the pairing that is right.
        without.reclassify_to = Some(30);
        let rule = built(&without).expect("a paired rank");
        assert_eq!(
            rule.action(),
            DlpAction::Reclassify { to: enclave_core::ClassificationRank(30) }
        );
    }

    /// A name outside the stored bounds is a named field rather than a constraint violation.
    #[test]
    fn a_name_is_bounded_before_the_database_sees_it() {
        for name in ["", "   ", &"x".repeat(201)] {
            let mut request =
                request(serde_json::json!(["exposes_content"]), serde_json::json!([]), "BLOCK");
            request.name = name.to_owned();
            let refused = built(&request).expect_err("the migration bounds this column");
            assert_eq!(refused.details()[0]["field"], "name");
        }
        // The control: a name inside the bounds.
        assert!(built(&request(
            serde_json::json!(["exposes_content"]),
            serde_json::json!([]),
            "BLOCK"
        ))
        .is_ok());
    }

    /// A negative priority is refused with the field named.
    #[test]
    fn a_negative_priority_is_refused() {
        let request =
            request(serde_json::json!(["exposes_content"]), serde_json::json!([]), "BLOCK");
        let refused =
            rule_from(DlpRuleId::new_v7(), -1, &request).expect_err("priority is zero or greater");
        assert_eq!(refused.details()[0]["field"], "priority");
        // The control: the default.
        assert!(rule_from(DlpRuleId::new_v7(), DEFAULT_PRIORITY, &request).is_ok());
    }

    /// No error carries the rule's name, and the response does.
    ///
    /// An assertion about an absence, so it is not made alone: the same name is asserted *present*
    /// in the view of the same rule.
    #[test]
    fn the_rules_name_is_in_the_response_and_in_no_refusal() {
        let named = request(
            serde_json::json!(["exposes_content"]),
            serde_json::json!([{"pattern":"x"}]),
            "BLOCK",
        );
        let refused = built(&named).expect_err("refused");
        assert!(
            !serde_json::to_string(refused.details())
                .unwrap_or_default()
                .contains("payment data may not leave"),
            "an error may not name a rule"
        );

        let row = DlpRuleRow {
            id: DlpRuleId::new_v7(),
            name: "payment data may not leave".to_owned(),
            priority: 100,
            scope: r#"["exposes_content"]"#.to_owned(),
            conditions: "[]".to_owned(),
            action: "BLOCK".to_owned(),
            reclassify_to: None,
        };
        assert_eq!(view(&row).name, "payment data may not leave");
    }

    /// A stored row that no longer decodes is listed rather than hidden, with the clause named.
    #[test]
    fn an_undecodable_stored_row_is_listed_with_the_reason() {
        let hostile = DlpRuleRow {
            id: DlpRuleId::new_v7(),
            name: "a rule written by psql".to_owned(),
            priority: 100,
            scope: r#"["exposes_content"]"#.to_owned(),
            conditions: r#"[{"pattern":"\\d{16}"}]"#.to_owned(),
            action: "BLOCK".to_owned(),
            reclassify_to: None,
        };
        let rendered = view(&hostile);
        assert!(!rendered.decodes);
        assert!(rendered.decode_error.expect("a reason").contains("pattern"));

        // The control: the same row with a condition list that decodes.
        let good = DlpRuleRow { conditions: "[]".to_owned(), ..hostile };
        let rendered = view(&good);
        assert!(rendered.decodes, "the control: a good row decodes");
        assert!(rendered.decode_error.is_none());
    }

    /// Step-up: multi-factor *and* recent, each half against its control.
    #[test]
    fn a_privileged_mutation_needs_a_second_factor_and_a_recent_one() {
        let tenant = TenantId::new_v7();
        assert!(require_step_up(&admin(tenant)).is_ok(), "the control: an MFA session just now");

        let mut single = admin(tenant);
        single.auth_strength = AuthStrength::SingleFactor;
        let refusal = require_step_up(&single).expect_err("one factor is not recent MFA");
        assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
        assert_eq!(refusal.code(), "STEP_UP_REQUIRED");

        let mut stale = admin(tenant);
        stale.auth_time = chrono::Utc::now() - chrono::TimeDelta::minutes(16);
        assert!(require_step_up(&stale).is_err());
    }

    /// A rule is attributed to a person, because the column is `NOT NULL` onto `users`.
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

    /// A decoder message is bounded before it is echoed.
    #[test]
    fn a_decoder_message_cannot_echo_an_unbounded_body() {
        let long = "x".repeat(MAX_DETAIL_CHARS * 3);
        assert!(clip(&long).chars().count() <= MAX_DETAIL_CHARS + 1);
        // The control: a short message is passed through whole.
        assert_eq!(clip("unknown variant `pattern`"), "unknown variant `pattern`");
    }

    /// The scope vocabulary really can name an administrative action — the premise of the lockout
    /// check, asserted rather than assumed.
    ///
    /// Without this, `a_rule_that_would_govern_its_own_withdrawal_is_refused` could be passing
    /// because `any` is the only scope that reaches an admin action, and the check would look
    /// broader than it is.
    #[test]
    fn an_administrative_action_is_expressible_in_a_scope_and_is_governed_by_any() {
        let sweeping = DlpRule::new(
            enclave_dlp::RuleId::new("any"),
            vec![ActionScope::Any],
            Vec::new(),
            DlpAction::Audit,
        );
        assert!(sweeping.governs(WITHDRAWAL_ACTION, Exposure::Internal));
        assert!(sweeping.governs(Action::File(FileAction::Download), Exposure::Internal));

        let narrow = DlpRule::new(
            enclave_dlp::RuleId::new("downloads"),
            vec![ActionScope::Exactly(Action::File(FileAction::Download))],
            Vec::new(),
            DlpAction::Audit,
        );
        assert!(!narrow.governs(WITHDRAWAL_ACTION, Exposure::Internal));
        assert!(narrow.governs(Action::File(FileAction::Download), Exposure::Internal));
    }
}
