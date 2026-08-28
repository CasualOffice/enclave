//! `GET /api/v1/bootstrap` — the first request a client makes, and the only one it makes holding
//! nothing.
//!
//! `docs/05-API.md §19` gives it one line: *branding, feature flags, locale, policy hints for the
//! SPA*. Three of those four are configuration, which is why the endpoint reads as harmless. It is
//! not: **it is the one surface a caller reaches before authenticating**, so every field on it is a
//! field an anonymous caller may read unless something stops them.
//!
//! # The split, and why it is structural rather than filtered
//!
//! There are two response types and they are not variants of one another:
//!
//! * [`PublicBootstrap`] is what a caller who has presented nothing receives. It has **no field**
//!   for a tenant, a user, or anything a deployment enforces — not an `Option` that is `None`, not
//!   a field a `#[serde(skip_serializing_if)]` hides. There is nothing to forget to clear.
//! * [`SessionBootstrap`] embeds a [`PublicBootstrap`] and adds [`Session`]. [`Session`] has one
//!   constructor, it is private to this module, and it takes a
//!   [`&RequestContext`](RequestContext) — a value produced by exactly one thing in this crate,
//!   [`Authenticated`], which is a verified bearer token or nothing. The authenticated half is
//!   therefore not *withheld* from an anonymous caller; it is unconstructible on that path.
//!
//! A filter would have been three lines shorter and would have had to be re-applied correctly by
//! every future field. `docs/12-TESTING.md §1.2` is explicit that the assertion which matters here
//! — *the anonymous caller did not receive the authenticated fields* — passes for free against a
//! handler that returns nothing at all, so the type-level split is what carries the property and
//! the paired positive control in `crates/api/tests/bootstrap.rs` is what proves the split is not
//! vacuous.
//!
//! # What is deliberately absent, and why an absence beats a placeholder
//!
//! **Branding.** `crates/branding` is five lines of module documentation and `tenants.branding` is
//! a `JSONB` column with a `'{}'` default that nothing writes and nothing reads. `docs/09 §18`
//! specifies a narrow contract — product name, logo, favicon, brand and accent colours, login art,
//! email header, three URLs — and this handler can honestly serve none of it. So there is no
//! `branding` key at all. A key holding deployment defaults would be read by the SPA as *this
//! tenant configured these values*, and a tenant that had configured nothing would be
//! indistinguishable from one whose configuration failed to load. `ENC-727` is the row; the store
//! is `ENC-310` in M8.
//!
//! **Feature flags.** Same rule, two causes. The crates behind every plausible flag — `sync`,
//! `workflows`, `signing`, `search` — are stubs, so a flag reading `true` would name a surface
//! reachable by nothing; and [`ApiState`] carries no [`enclave_config::Config`], so this handler
//! cannot read what a deployment actually configured even for the parts that are real. `ENC-728`.
//!
//! **Policy hints.** `tenants.status` is served because it is a *fact in a row*. Nothing derived
//! from it is: a `writable: false` hint next to a `READ_ONLY` tenant would describe an enforcement
//! that does not exist — no write path in this workspace consults `tenants.status` — and a hint the
//! backend does not honour is worse than no hint, because the SPA hides an affordance for a rule
//! that would not have refused anything.
//!
//! # The unauthenticated half carries nothing tenant-derived, and that is now a choice
//!
//! **This paragraph used to say the opposite, and it was wrong.** It read: *resolving a host to a
//! tenant needs `enclave_db::resolve_routed_tenant`, which does not exist in this tree*. It does —
//! `crates/db/src/routing.rs`, reached through the [`RoutedTenant`](crate::routes::auth::RoutedTenant)
//! extractor that `POST /api/v1/auth/login` has used since `ENC-685`. The handler this module
//! describes was written against an older tree and the prose outlived it. It is corrected here
//! rather than deleted, because what it was justifying survives and the justification changed
//! shape: an inevitability became a decision, and a decision has to be argued and tested.
//!
//! The decision is that [`PublicBootstrap`] stays byte-identical for every `Host`. An anonymous
//! caller who could vary the `Host` header and read a varying response would have a tenant
//! **enumeration oracle** — `tenant-alpha.…` answers one way and `not-a-tenant.…` another, and the
//! deployment has published its customer list to anyone who can spell. That is exactly the
//! disclosure `docs/06-SECURITY-DLP-ACCESS.md §1` assumes an attacker is looking for, and it costs
//! nothing to refuse: the public half has no field a tenant could reach even if one were resolved.
//!
//! So the property is no longer held by an absence in the tree. It is held by this handler never
//! calling the resolver, and `crates/api/tests/bootstrap.rs` asserts it against alpha's host,
//! beta's host and an unknown one — three responses compared byte for byte, with alpha's
//! *authenticated* response in the same test run as the positive control that the comparison is
//! not comparing three copies of nothing.
//!
//! The open question `ENC-730` now carries is the one this closes off: a sign-in page cannot be
//! branded per tenant without disclosing something per tenant. That is a product decision about
//! what a deployment is willing to publish — not a wiring gap — and it belongs in `docs/09 §18`
//! with `ENC-727`'s branding store, not in a handler that quietly starts resolving hosts.

use axum::extract::{FromRequestParts, State};
use axum::http::header;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use enclave_core::{
    Action, ContainerAction, Error, ReasonCode, RequestContext, ResourceKind, ResourceRef, Uuid,
};
use serde::Serialize;
use sqlx::Row as _;

use crate::auth::Authenticated;
use crate::error::{ApiError, NO_STORE};
use crate::refusal::{none_dischargeable, Refused};
use crate::state::ApiState;

/// The action the authenticated half asks the chain about.
///
/// The same decision `GET /api/v1/me` takes, against the same resource — the caller's own user
/// record — and that is deliberate rather than convenient. The authenticated half of bootstrap is
/// a *self*-read: this caller's resolved locale, the tenant they are already inside. It is not
/// `Admin(ReadConfig)`, which would deny every non-administrator and make the endpoint every SPA
/// session starts with unusable for ordinary users; and it is not a read of the tenant as a
/// resource, which no authorization service in this workspace can answer — `acl_entries` has no
/// row on a tenant and `crates/authorization/src/service.rs` correctly calls such a reference
/// unsupported.
const READ: Action = Action::Container(ContainerAction::Read);

/// The version of the surface this document describes.
///
/// A constant rather than a placeholder: it is a fact about the router, not a value awaiting a
/// store, and it cannot be wrong while `/api/v1/**` is the only registered prefix.
const API_VERSION: &str = "v1";

/// The locales this deployment can actually serve.
///
/// **Tier 1 of `docs/14-I18N-L10N.md §2` and nothing beyond it**, and the omission of Tiers 2 and 3
/// is the honest reading rather than a shortfall. `web/src` holds no message catalog — there is no
/// `web/src` to speak of — so the fourteen launch locales are a product commitment, not a
/// capability. Advertising `ja-JP` here would have the SPA offer a language it would then render in
/// English, which is the same class of lie as a feature flag over a stub crate (`ENC-728`).
///
/// The three that are listed are listed because they are servable *today*: they differ from one
/// another only in formatting — date order, and the Indian digit grouping `12,34,567` that
/// `docs/14 §6` singles out — and formatting comes from `Intl`, which needs no catalog. The
/// English strings they share are the strings the product already has.
///
/// This constant grows when a catalog lands, and the negotiation below does not change when it
/// does. That is the point of resolving against a list rather than against a hard-coded match.
const SUPPORTED_LOCALES: &[&str] = &["en-US", "en-GB", "en-IN"];

/// The platform fallback of `docs/14 §3`, step 4.
const FALLBACK_LOCALE: &str = "en-US";

// ---------------------------------------------------------------------------------------------
// The wire types. The split lives here, not in the handler.
// ---------------------------------------------------------------------------------------------

/// Everything a caller who has presented no credential may learn.
///
/// Deployment-level and locale-level only. There is no tenant on this type, no user, no statement
/// about what any deployment enforces, and — the property worth stating out loud — **no field that
/// could be made to carry one without editing this struct**, which is a diff a reviewer sees.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicBootstrap {
    /// Which version of the HTTP surface this process serves.
    api_version: &'static str,
    /// The negotiated locale, and how it was arrived at.
    locale: Locale,
}

/// Everything the authenticated caller learns, which is [`PublicBootstrap`] and strictly more.
///
/// Flattened on the wire so a client parses one object with an optional `session` key rather than
/// two shapes. The nesting in Rust is the part that matters: the public half is *embedded*, so it
/// cannot drift from what an anonymous caller receives.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionBootstrap {
    #[serde(flatten)]
    public: PublicBootstrap,
    session: Session,
}

/// What requires a verified identity.
///
/// The type's whole job is that it cannot be built without one. [`Session::observed`] is private to
/// this module and takes a [`RequestContext`], which in this crate comes from [`Authenticated`] and
/// from nothing else.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// The tenant from the verified token — never from a header, a query parameter or a body
    /// (`CLAUDE.md` rule 3).
    tenant_id: String,
    /// The subject from the verified token.
    user_id: String,
    /// The tenant as its own row describes it.
    tenant: TenantView,
}

/// The tenant's own record, reduced to the two fields a session needs.
///
/// `display_name` is the tenant's name, not the product's — the product name is
/// `docs/09 §18` branding and is absent for `ENC-727`'s reason. `status` is served because a
/// `READ_ONLY` or `SUSPENDED` tenant is a fact a client should be told rather than discover from a
/// refusal; nothing is *derived* from it here, for the reason in the module header.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantView {
    display_name: String,
    status: String,
}

/// The resolved locale, and the step of `docs/14 §3` that resolved it.
///
/// `source` is on the wire because locale resolution is the kind of thing that silently degrades:
/// a deployment whose `users.locale` is never populated by its identity provider resolves every
/// session from `Accept-Language` and looks perfectly healthy. Naming the step makes that visible
/// in one response instead of inferable from a support ticket.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Locale {
    resolved: &'static str,
    source: LocaleSource,
    supported: &'static [&'static str],
}

/// Which step of the precedence chain produced the locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocaleSource {
    /// `users.locale` — step 1.
    User,
    /// `tenants.settings.default_locale` — step 2. Authenticated only: reaching it needs a tenant,
    /// and an anonymous caller has none.
    Tenant,
    /// `Accept-Language` negotiation — step 3.
    AcceptLanguage,
    /// The platform fallback — step 4.
    Fallback,
}

impl Locale {
    /// A resolved locale and the step that resolved it.
    ///
    /// `supported` is attached here rather than by each caller so that the list a client is offered
    /// and the list this deployment resolved against cannot be two different lists.
    const fn new(resolved: &'static str, source: LocaleSource) -> Self {
        Self { resolved, source, supported: SUPPORTED_LOCALES }
    }
}

impl PublicBootstrap {
    /// The half every caller receives.
    fn new(locale: Locale) -> Self {
        Self { api_version: API_VERSION, locale }
    }
}

impl Session {
    /// Builds the authenticated half from a verified context.
    ///
    /// **The `ctx` parameter is the control.** It is not read for convenience — the tenant and the
    /// subject could both have been passed as plain values — it is read so that this constructor
    /// cannot be called from a path that has not authenticated, because [`RequestContext`] is not
    /// something a handler can conjure. `CLAUDE.md` rule 3 in the form the compiler checks.
    fn observed(ctx: &RequestContext, subject: Uuid, tenant: TenantView) -> Self {
        Self {
            tenant_id: ctx.tenant_id.as_uuid().to_string(),
            user_id: subject.to_string(),
            tenant,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Optional authentication.
// ---------------------------------------------------------------------------------------------

/// A caller who may or may not have authenticated.
///
/// # Why the three outcomes are three and not two
///
/// * **No `Authorization` header** — anonymous. The public half, `200`.
/// * **An `Authorization` header that verifies** — the full response, through the chain.
/// * **An `Authorization` header that does not verify** — *refused*, not silently downgraded.
///
/// The third is the one worth having a type for. An endpoint that answered an expired token with
/// the anonymous response and a `200` would hand every client a plausible-looking payload at the
/// exact moment its session ended, and the SPA would render a signed-out shell without ever
/// learning it had been signed out. Presenting a credential is a claim; a claim that fails is an
/// error, never an absence.
///
/// # Why it lives in this module
///
/// Bootstrap is the endpoint optional authentication exists for. `crates/api/src/health.rs` borrows
/// this type rather than growing a second one, which is the same argument `crates/api/src/edge.rs`
/// makes for resolving a client address once: two implementations of one question agree until the
/// day one of them is edited.
///
/// It **delegates** to [`Authenticated`] for everything except the presence check. No second token
/// verification, no second `RequestContext` assembly, no second decision about what a malformed
/// header means.
#[derive(Debug)]
pub struct MaybeAuthenticated(pub Option<Authenticated>);

impl FromRequestParts<ApiState> for MaybeAuthenticated {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if !parts.headers.contains_key(header::AUTHORIZATION) {
            return Ok(Self(None));
        }
        Authenticated::from_request_parts(parts, state).await.map(|caller| Self(Some(caller)))
    }
}

// ---------------------------------------------------------------------------------------------
// The handler.
// ---------------------------------------------------------------------------------------------

/// Handles `GET /api/v1/bootstrap`.
///
/// # The policy-routing lint, and why there is no allowlist entry
///
/// `xtask policy-routing` requires every registered handler to reach `PolicyEngine::enforce` or to
/// be exempted with a written reason. This one reaches it, on the branch that touches tenant data,
/// so the lint passes without an exemption — and that is the outcome to want. Every entry in that
/// allowlist is a *whole* endpoint that legitimately decides nothing: `live` and `ready` have no
/// tenant and no actor at all; `login` and `refresh` are the credential exchange the chain's auth
/// stage presupposes. Bootstrap is neither. It is one endpoint with an anonymous half that has no
/// tenant, no actor and no resource, and an authenticated half that reads a tenant's row — and an
/// exemption is granted per handler, not per branch, so listing it would exempt the half that must
/// never be exempt.
///
/// What the lint cannot see is that `enforce` *dominates* the authenticated branch — it says so
/// itself, in its module header, and dominance needs MIR. So the guarantee is carried by
/// `crates/api/tests/bootstrap.rs`, which asserts that an authenticated request the chain refuses
/// receives a refusal rather than the anonymous payload.
///
/// # Errors
///
/// [`ApiError`] when a presented credential does not verify, when the chain refuses, when the
/// caller is a principal with no user record, or when the tenant's row cannot be read. Never for
/// the anonymous path, which has nothing to refuse.
pub async fn bootstrap(
    State(state): State<ApiState>,
    headers: HeaderMap,
    caller: MaybeAuthenticated,
) -> Result<Response, ApiError> {
    let negotiated = negotiate(&headers);

    let Some(Authenticated { ctx }) = caller.0 else {
        // The anonymous half. No tenant is resolved, because nothing in this tree can resolve one
        // (`ENC-730`); no database is touched; no policy decision is taken, because there is no
        // actor to attribute one to and no resource to take it about.
        return Ok(respond(negotiated.resolved, PublicBootstrap::new(negotiated)));
    };

    let request_id = ctx.request_id;

    // Refused above the chain, exactly as `crates/api/src/me.rs` refuses it, and audited on its own
    // for the same reason: the `System` actor has no `users` row, so there is no subject for a
    // self-read to be about. Saying so is cheaper than discovering it as a nil-UUID lookup.
    let subject = match subject(&ctx) {
        Ok(subject) => subject,
        Err(refused) => {
            let resource = ResourceRef::tenant(ctx.tenant_id);
            return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
        }
    };

    let resource = ResourceRef::new(ctx.tenant_id, ResourceKind::User, subject);

    // The chain. Nothing below this line runs unless it returns, and the audit row is written
    // inside it whether it allows or denies.
    let decision = state
        .policy
        .enforce(&ctx, READ, &resource)
        .await
        .map_err(|error| ApiError::new(error, request_id))?;

    // `PolicyDecision` is `#[must_use]`; consuming it here is what proves nothing was dropped. No
    // stage attaches an obligation to reading your own session, and this path could not satisfy one
    // if it did — there is no rendition to watermark and nowhere to collect a justification — so an
    // obligation arriving here is a refusal (`CLAUDE.md` rule 8). `none_dischargeable` rather than
    // `Obligations::require_none` for `ENC-606`'s reason: the chain wrote its `ALLOW` one statement
    // above, so a refusal reaching the caller as a bare `Error` would be a `403` the audit table
    // records as a success.
    if let Err(refused) = none_dischargeable(&decision.into_obligations()) {
        return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // No tenant predicate, and that is not an omission: `users` is RLS-policied and `TenantScoped`
    // has set `app.tenant_id`, so another tenant's row is not filtered out here — it is invisible
    // to this transaction. The same reasoning `crates/api/src/me.rs` records.
    let user = sqlx::query("SELECT locale FROM users WHERE id = $1 AND deleted_at IS NULL")
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id)
        })?;

    // **`tenants` is different, and the difference is load-bearing.** It is one of the two tables
    // `migrations/0002_rls_policies.sql` deliberately leaves unpolicied — its tenant key is `id`,
    // not `tenant_id`, and it has to be readable during tenant resolution before any context
    // exists. So row-level security applies nothing here, and `WHERE id = $1` is not the second of
    // two layers: it is the only one. Delete it and this handler serves an arbitrary tenant's
    // record.
    //
    // `docs/12-TESTING.md §1.2` records that a dropped `tenant_id` predicate has failed to fail in
    // five separate crates, because RLS held the property alone. This is the case where it does
    // not, and `crates/api/tests/bootstrap.rs` breaks exactly this line to prove it.
    let tenant = sqlx::query(
        "SELECT display_name, status, settings ->> 'default_locale' AS default_locale
           FROM tenants
          WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(ctx.tenant_id.as_uuid())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| ApiError::new(Error::from(enclave_db::DbError::Query(error)), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // A verified token naming a subject or a tenant with no row is `404`, never `403`: a `403`
    // would confirm that the identifier exists somewhere (`CLAUDE.md` rule 7).
    let user = user.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let tenant = tenant.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;

    let user_locale: Option<String> = user.get("locale");
    let tenant_locale: Option<String> = tenant.get("default_locale");

    let locale = resolve(user_locale.as_deref(), tenant_locale.as_deref(), negotiated);
    let resolved = locale.resolved;

    Ok(respond(
        resolved,
        SessionBootstrap {
            public: PublicBootstrap::new(locale),
            session: Session::observed(
                &ctx,
                subject,
                TenantView {
                    display_name: tenant.get("display_name"),
                    status: tenant.get("status"),
                },
            ),
        },
    ))
}

/// Renders either half, with the two headers the answer implies.
///
/// `Content-Language` because `docs/14 §3` says the resolved locale is echoed there as well as
/// carried in the body, and a client that reads only headers must not have to guess.
///
/// `private, no-store` because the authenticated half carries one caller's tenant and subject, and
/// a shared cache holding it would serve them to the next caller. The anonymous half is
/// deployment-wide and would be safe to cache; it is not cached anyway, because a cacheability rule
/// that depends on which branch produced the response is a rule that is one refactor away from
/// being applied to the wrong branch.
fn respond<T: Serialize>(resolved: &'static str, body: T) -> Response {
    (
        [
            (header::CACHE_CONTROL, NO_STORE),
            // Infallible by construction: `resolved` is an element of `SUPPORTED_LOCALES`, which is
            // a compile-time list of BCP 47 tags. A locale that could come from a database row
            // could not use `from_static` and would need handling here.
            (header::CONTENT_LANGUAGE, HeaderValue::from_static(resolved)),
        ],
        Json(body),
    )
        .into_response()
}

// ---------------------------------------------------------------------------------------------
// Locale resolution — `docs/14-I18N-L10N.md §3`.
// ---------------------------------------------------------------------------------------------

/// Applies the precedence chain of `docs/14 §3`, first match wins.
///
/// ```text
/// 1. users.locale
/// 2. tenants.settings.default_locale
/// 3. Accept-Language negotiation
/// 4. en-US
/// ```
///
/// Steps 1 and 2 are matched against [`SUPPORTED_LOCALES`] with the same fallback chaining as
/// step 3, rather than being trusted verbatim. Both come from a place that is not this deployment —
/// SCIM writes `users.locale`, an administrator writes the tenant default — so either can name a
/// locale the deployment cannot render. A stored `fr-CA` therefore *falls through* to the next step
/// instead of being echoed back as resolved, which is the difference between a client that renders
/// English and a client that asks `Intl` for a bundle nobody shipped.
fn resolve(user: Option<&str>, tenant: Option<&str>, negotiated: Locale) -> Locale {
    if let Some(hit) = user.and_then(best_match) {
        return Locale::new(hit, LocaleSource::User);
    }
    if let Some(hit) = tenant.and_then(best_match) {
        return Locale::new(hit, LocaleSource::Tenant);
    }
    negotiated
}

/// Steps 3 and 4 alone, which is all an anonymous caller can reach.
fn negotiate(headers: &HeaderMap) -> Locale {
    headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok())
        .and_then(best_accepted)
        .map_or_else(
            || Locale::new(FALLBACK_LOCALE, LocaleSource::Fallback),
            |hit| Locale::new(hit, LocaleSource::AcceptLanguage),
        )
}

/// The best supported locale named by an `Accept-Language` header, if any.
///
/// RFC 9110 §12.5.4: a comma-separated list of language ranges, each optionally weighted with
/// `;q=`. Three details are handled rather than assumed, because each of them is a real header a
/// browser sends:
///
/// * **A missing `q` is 1**, and ties keep source order, so `en-GB,en-US` prefers `en-GB`.
/// * **`q=0` means *not* acceptable** and is skipped. Treating it as merely lowest-preference would
///   let a header that explicitly refuses English resolve to English through the negotiation step
///   instead of through the fallback, and the two are reported differently.
/// * **`*` matches the platform fallback**, not the first supported entry, so `*` and an absent
///   header agree.
///
/// A malformed weight (`q=banana`) makes the range unusable rather than maximally preferred: it is
/// dropped. The permissive reading — ignore the parameter and keep the range at `q=1` — hands a
/// client the top preference by sending something invalid.
fn best_accepted(header_value: &str) -> Option<&'static str> {
    let mut ranges: Vec<(u32, usize, &str)> = Vec::new();

    for (position, part) in header_value.split(',').enumerate() {
        let mut fields = part.split(';');
        let Some(tag) = fields.next().map(str::trim).filter(|tag| !tag.is_empty()) else {
            continue;
        };

        let mut weight = 1000_u32;
        let mut usable = true;
        for parameter in fields {
            let parameter = parameter.trim();
            if let Some(value) =
                parameter.strip_prefix("q=").or_else(|| parameter.strip_prefix("Q="))
            {
                match parse_weight(value) {
                    Some(parsed) => weight = parsed,
                    None => usable = false,
                }
            }
        }

        if usable && weight > 0 {
            ranges.push((weight, position, tag));
        }
    }

    // Descending by weight, ascending by position within a weight. `sort_by` is stable, so sorting
    // on the negated weight alone would do — the explicit position keeps that from being an
    // accident of the standard library's guarantees.
    ranges.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    ranges.iter().find_map(
        |(_, _, tag)| {
            if *tag == "*" {
                Some(FALLBACK_LOCALE)
            } else {
                best_match(tag)
            }
        },
    )
}

/// A `q` value as thousandths, or `None` if it is not one.
///
/// Integer thousandths rather than `f32` so that ordering is total and two equal weights compare
/// equal — a sort over floats with `partial_cmp` needs an `unwrap` this workspace warns on, and the
/// value it would be unwrapping is attacker-supplied.
fn parse_weight(value: &str) -> Option<u32> {
    let value = value.trim();
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let whole: u32 = whole.parse().ok()?;
    if whole > 1 {
        return None;
    }
    let mut padded = fraction.to_owned();
    while padded.len() < 3 {
        padded.push('0');
    }
    let fraction: u32 = if padded.is_empty() { 0 } else { padded.parse().ok()? };
    let weight = whole * 1000 + fraction;
    (weight <= 1000).then_some(weight)
}

/// The supported locale a single BCP 47 tag resolves to, with `docs/14 §3`'s fallback chaining.
///
/// `fr-CA` → `fr` → nothing here, because no French catalog exists; `en-AU` → `en` → `en-US`, the
/// first supported locale sharing the primary subtag. Case-insensitive throughout: `EN-gb` is
/// `en-GB`, and a client that sends it is not wrong.
fn best_match(tag: &str) -> Option<&'static str> {
    let tag = tag.trim();
    if tag.is_empty() {
        return None;
    }
    if let Some(hit) =
        SUPPORTED_LOCALES.iter().find(|candidate| candidate.eq_ignore_ascii_case(tag))
    {
        return Some(hit);
    }
    let primary = tag.split('-').next()?;
    SUPPORTED_LOCALES.iter().copied().find(|candidate| {
        candidate.split('-').next().is_some_and(|p| p.eq_ignore_ascii_case(primary))
    })
}

/// The subject a self-read can be about.
///
/// A function rather than an inline `ok_or_else`, for the reason `crates/api/src/me.rs` gives: the
/// refusal is *constructed in a function that returns one*, which is what
/// `cargo run -p xtask -- audit-coverage` reads to decide that it is audited.
///
/// # Errors
///
/// [`Refused`] for [`enclave_core::Actor::System`] and for any principal with no subject — a
/// machine caller has no `users` row, and therefore no session to bootstrap.
fn subject(ctx: &RequestContext) -> Result<Uuid, Refused> {
    ctx.actor.subject_id().ok_or_else(|| Refused::actor(ReasonCode::AccessDenied))
}
