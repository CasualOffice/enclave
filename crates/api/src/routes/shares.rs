//! `docs/05-API.md §10` — share links.
//!
//! ```text
//! POST   /api/v1/files/{id}/shares   → 201 { …link…, token }   the token appears exactly once
//! GET    /api/v1/files/{id}/shares   → the links on this resource
//! PATCH  /api/v1/shares/{id}         → expiry, permission, download budget
//! DELETE /api/v1/shares/{id}         → revoke
//! ```
//!
//! # `GET /shares/{token}` is not here, and the reason has changed
//!
//! **This section used to give the tenant as the reason, and that reason has stopped being true.**
//! It read: redemption arrives with a token and nothing else, so resolving it *is* how the tenant is
//! established, and no connection this crate may hold can do that. Two things have landed since.
//! `enclave_db::resolve_routed_tenant` resolves a verified custom domain and then a slug
//! (`ENC-686`, with the `SELECT` it needs granted by `migrations/0026`), reached through the
//! [`RoutedTenant`](crate::routes::auth::RoutedTenant) extractor `POST /api/v1/auth/login` has used
//! since `ENC-685`; and `crates/api/src/main.rs` configures `database.platform_url` and warns when
//! it is unset. So the tenant is available on an unauthenticated route, and the digest then resolves
//! under [`enclave_db::TenantScoped`] with row-level security doing what `migrations/0008` wrote it
//! to do. The correction is recorded rather than deleted, for `crates/api/src/routes/bootstrap.rs`'s
//! reason: the conclusion survived and its justification did not, and a justification that changed
//! shape has to be argued again.
//!
//! What blocks the route now is `ENC-879`, and it is in the chain rather than in the connection.
//! **A redemption arrives with no principal.** [`enclave_core::Actor`] has no variant for the bearer
//! of a link; `acl_entries.principal_type` admits `USER`, `GROUP`, `GUEST`, `SERVICE_ACCOUNT` and
//! `EVERYONE`, none of which can name one; `enclave_authorization::classify` maps
//! [`enclave_core::ResourceKind::Share`] to an unsupported target, so a share object cannot be asked
//! about either; and `PrincipalSet::for_actor` refuses [`Actor::System`] deliberately, precisely so
//! that a principal the ACL model cannot talk about does not fall through to `EVERYONE`. So
//! `PolicyEngine::enforce` — which `CLAUDE.md` rule 1 requires this handler to call — has no answer
//! but `deny`, for every principal a redemption could honestly present.
//!
//! Registering it anyway would refuse every redemption, which is `ENC-170`'s shape; and rendering
//! that denial as anything but `404` would tell an anonymous caller that the token is live, which is
//! rule 7. Both halves are asserted in `crates/api/tests/shares.rs`: the tenant half by a token
//! minted in `tenant-alpha` and presented under `tenant-beta`'s scope, indistinguishable from one
//! that was never minted because RLS makes the row invisible rather than because anything compares
//! ids; and the principal half by
//! `the_chain_can_authorize_no_principal_a_redemption_could_present`, which asks the real engine and
//! carries its positive control in the same run.
//!
//! # Internal and external sharing are two permissions, and the split fails closed
//!
//! `CLAUDE.md` rule 6 and `docs/06 §12`. [`FileAction::Share`] and [`FileAction::ShareExternal`] are
//! separate actions because *"external sharing is the highest-consequence grant in the system"*, and
//! [`action_for`] is the one place the requested audience chooses between them. Only
//! [`ShareAudience::Internal`] asks the internal question; **every other audience asks the external
//! one**, including [`ShareAudience::Specific`], whose named recipients are email addresses that
//! `share_link_grants` does not require to belong to the tenant. An audience whose reach is not
//! provably inside the tenant is treated as leaving it, which is the only reading that cannot be
//! wrong in the dangerous direction.
//!
//! # Where the SQL comes from
//!
//! `ENC-693`. `enclave_sharing::repo` exposes `create`, `find_by_digest` and `revoke` and nothing
//! else, so listing and patching have no repository to call and the three statements below are
//! written here. They run on the [`enclave_db::TenantScoped`] transaction, which is what the
//! no-raw-pool gate asks for, and they never select `token_hash` or `password_hash`: the wire's
//! `hasPassword` is projected as `password_hash IS NOT NULL` in the statement, so the hash is not
//! merely dropped after loading — it is never loaded.
//!
//! # What a share link cannot yet do
//!
//! `ENC-694`. `crates/sharing` says plainly that it *"does not check passwords, OTPs, domains or
//! MFA"*, and nothing else does either. [`CreateShareRequest`] therefore accepts `requireOtp` and
//! `requireMfa` — they are carried on the link so a redeemer can be told what it demands — and
//! deliberately accepts **no** password: a stored credential that nothing verifies is worse than no
//! credential, because it reads as protection.

use core::str::FromStr as _;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::{Json, RequestExt as _};
use chrono::{DateTime, Utc};
use enclave_core::{
    Action, Actor, Error, FileAction, FileId, Obligation, Obligations, ReasonCode, RequestContext,
    RequestId, ResourceRef, ShareAction, TenantId, UserId, ValidationCode,
};
use enclave_files::FileRepository;
use enclave_sharing::{
    NewShareLink, ShareAudience, SharePermission, ShareResourceKind, ShareToken,
};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;

use crate::auth::Authenticated;
use crate::download::conceal_if_not_visible;
use crate::error::{ApiError, Envelope, NO_STORE};
use crate::refusal::Refused;
use crate::state::ApiState;

/// The header `docs/05-API.md §4` reserves for an action carrying a `RequireJustification`
/// obligation.
const JUSTIFICATION: &str = "x-justification";

// ---------------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------------

/// The body of `POST /api/v1/files/{id}/shares`.
///
/// `deny_unknown_fields` is what makes the absent `password` field a refusal rather than a silent
/// drop (`ENC-615`, `ENC-694`): a caller who sets a password on a link and is answered `201` will
/// believe the document is protected.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateShareRequest {
    /// What the holder may do. `PREVIEW_ONLY` is not a weaker `VIEW` — it is `CLAUDE.md` rule 6 as
    /// a share setting.
    #[serde(deserialize_with = "wire")]
    permission: SharePermission,
    /// Whether original bytes may leave. A separate field from `permission` precisely so the two
    /// cannot be collapsed.
    #[serde(default)]
    allow_download: bool,
    /// Who may redeem it. This is what decides whether the request asks `file.share` or
    /// `file.share_external`.
    #[serde(deserialize_with = "wire")]
    audience: ShareAudience,
    /// When it stops working. Absent means never, which is the setting most tenants should not use.
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    /// How many downloads it permits in total. Absent means unlimited.
    #[serde(default)]
    max_downloads: Option<i64>,
    /// The email domains that may redeem a `DOMAIN_RESTRICTED` link.
    #[serde(default)]
    allowed_domains: Option<Vec<String>>,
    /// Whether a one-time code is required per redemption. Carried, not yet enforced (`ENC-694`).
    #[serde(default)]
    require_otp: bool,
    /// Whether the redeemer must have completed MFA. Carried, not yet enforced (`ENC-694`).
    #[serde(default)]
    require_mfa: bool,
}

/// The body of `PATCH /api/v1/shares/{id}`.
///
/// Every field is `Option<Option<_>>`: **absent means unchanged and an explicit `null` means
/// cleared.** The distinction is the whole point of the endpoint — "this link no longer expires"
/// and "leave the expiry alone" are different instructions, and a plain `Option` cannot tell them
/// apart, so `null` would silently become "unchanged" and a caller could never remove a limit.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateShareRequest {
    #[serde(default, deserialize_with = "present_wire")]
    permission: Option<Option<SharePermission>>,
    #[serde(default, deserialize_with = "present")]
    allow_download: Option<Option<bool>>,
    #[serde(default, deserialize_with = "present")]
    expires_at: Option<Option<DateTime<Utc>>>,
    #[serde(default, deserialize_with = "present")]
    max_downloads: Option<Option<i64>>,
}

/// Distinguishes an absent field from one explicitly set to `null`.
///
/// `#[serde(default)]` gives `None` for an absent field; this gives `Some(None)` for `null`. Serde
/// has no attribute for it, and writing it out is cheaper than the class of bug it prevents.
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// Decodes one of `crates/sharing`'s stored vocabularies from its wire spelling.
///
/// The enumerations in `enclave_sharing::model` implement [`FromStr`](core::str::FromStr) against
/// the exact strings their `CHECK` constraints hold, and implement no `serde` traits at all. That
/// is worth preserving rather than working around: the migration's constraint, the crate's
/// `as_str` and this endpoint's accepted values are one list, tested against the migration itself,
/// and a `#[derive(Deserialize)]` on the domain type would create a second spelling that nothing
/// compares to the first.
fn wire<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: core::str::FromStr,
    T::Err: core::fmt::Display,
{
    let raw = String::deserialize(deserializer)?;
    T::from_str(&raw).map_err(serde::de::Error::custom)
}

/// [`wire`] and [`present`] together, for a patch field holding one of those vocabularies.
///
/// An explicit `null` is `Some(None)` — "clear it" — and any string is parsed. The two helpers
/// cannot simply be composed: `deserialize_with` takes one function, and `Option<Option<T>>` needs
/// the null to be observed before the string is parsed.
fn present_wire<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: core::str::FromStr,
    T::Err: core::fmt::Display,
{
    let raw: Option<String> = Option::deserialize(deserializer)?;
    match raw {
        None => Ok(Some(None)),
        Some(raw) => {
            T::from_str(&raw).map(|value| Some(Some(value))).map_err(serde::de::Error::custom)
        }
    }
}

/// A share link as the management API renders it.
///
/// Note what is not here: the token, and the password hash. The token exists exactly twice — in the
/// creation response and in the URL its creator copies — and the hash is never selected at all.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ShareView {
    id: String,
    resource_type: &'static str,
    resource_id: String,
    permission: &'static str,
    allow_download: bool,
    audience: &'static str,
    /// Whether a password is set. Derived in the statement, so the hash never enters this process.
    has_password: bool,
    require_otp: bool,
    require_mfa: bool,
    expires_at: Option<DateTime<Utc>>,
    max_downloads: Option<i64>,
    download_count: i64,
    allowed_domains: Option<Vec<String>>,
    created_by: String,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

/// The creation response — the one place a token is ever on the wire.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedShareView {
    #[serde(flatten)]
    link: ShareView,
    /// The raw token. **Returned once and never again**: only its SHA-256 is stored, so nothing can
    /// reproduce it. The client composes the redemption URL — this API has no configured public
    /// base URL, and inventing one would put a host in a response body that the deployment never
    /// agreed to.
    token: String,
}

/// The listing envelope. Not paginated: `docs/05-API.md §6`'s cursor applies to listings that can
/// grow without bound, and the links on one resource are bounded by how many a person made.
#[derive(Debug, Serialize)]
pub struct ShareList {
    items: Vec<ShareView>,
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Handles `POST /api/v1/files/{id}/shares`.
///
/// # Errors
///
/// [`ApiError`]: `404` when the file is another tenant's, absent, or invisible to this caller;
/// `403` `EXTERNAL_SHARE_BLOCKED` or `ACCESS_DENIED` when the chain refuses a caller who can see
/// the file; `400` for a body that will not decode.
pub async fn create(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;

    let justification = request
        .headers()
        .get(JUSTIFICATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let body: Bytes = match request.extract().await {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };
    let body: CreateShareRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_error) => return Ok(unreadable_body().into_response(request_id)),
    };

    let file = file_id(&file, request_id)?;
    let resource = ResourceRef::file(ctx.tenant_id, file);
    let action = action_for(body.audience);

    let decision = match state.policy.enforce(&ctx, action, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };

    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations, justification.as_deref()) {
        return Err(state.audit.refuse(&ctx, action, &resource, refused).await);
    }

    let created_by = match author(&ctx) {
        Ok(author) => author,
        Err(refused) => return Err(state.audit.refuse(&ctx, action, &resource, refused).await),
    };

    // Minted before the transaction and handed over exactly once. `ShareToken` is not `Clone`, not
    // `Serialize` and not `Display`; the plaintext escapes only through `expose`, which is why
    // every place it can escape is one grep away.
    let token = ShareToken::generate().map_err(|error| ApiError::new(error.into(), request_id))?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // Which *kind* of thing the link points at. Read rather than assumed: `docs/04 §11` gives
    // `resource_type` a `CHECK`, and a folder recorded as a `FILE` is a link the redemption path
    // would resolve against the wrong table. This is also the "authorized but absent" check — the
    // chain allowed against an id whose row is gone.
    let node = FileRepository::find_by_id(&mut tx, ctx.tenant_id, file)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let resource_type =
        if node.is_folder() { ShareResourceKind::Folder } else { ShareResourceKind::File };

    let new = NewShareLink {
        resource_type,
        resource_id: file.as_uuid(),
        permission: body.permission,
        allow_download: body.allow_download,
        audience: body.audience,
        // `ENC-694`. No field can set one, so there is nothing to hash and nothing to store.
        password_hash: None,
        require_otp: body.require_otp,
        require_mfa: body.require_mfa,
        expires_at: body.expires_at,
        max_downloads: body.max_downloads,
        allowed_domains: body.allowed_domains,
        created_by,
    };

    let link =
        enclave_sharing::repo::create(&mut tx, ctx.tenant_id, token.digest(), &new, Utc::now())
            .await
            .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let view = CreatedShareView {
        link: ShareView {
            id: link.id.to_string(),
            resource_type: link.resource_type.as_str(),
            resource_id: link.resource_id.to_string(),
            permission: link.permission.as_str(),
            allow_download: link.allow_download,
            audience: link.audience.as_str(),
            has_password: link.has_password,
            require_otp: link.require_otp,
            require_mfa: link.require_mfa,
            expires_at: link.expires_at,
            max_downloads: link.max_downloads,
            download_count: link.download_count,
            allowed_domains: link.allowed_domains.clone(),
            created_by: link.created_by.to_string(),
            created_at: link.created_at,
            revoked_at: link.revoked_at,
        },
        token: token.expose().to_owned(),
    };

    // `no-store`, and not only out of habit: this response body carries a working credential, and a
    // shared cache holding it would hand the link to whoever asked next.
    Ok((StatusCode::CREATED, [(header::CACHE_CONTROL, NO_STORE)], Json(view)).into_response())
}

/// Handles `GET /api/v1/files/{id}/shares`.
///
/// Revoked and expired links are listed with their real state. The redeemer of a link is told one
/// undifferentiated "this does not work" (`enclave_sharing::error`); the *creator*, authenticated
/// and holding a grant on the resource, is entitled to know which of the two it was — that is the
/// whole reason the two audiences exist.
///
/// # Errors
///
/// [`ApiError`]: `404` for a file this caller cannot see; the denial's own status otherwise.
pub async fn list(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(file): Path<String>,
) -> Result<Json<ShareList>, ApiError> {
    let request_id = ctx.request_id;
    let file = file_id(&file, request_id)?;
    let resource = ResourceRef::file(ctx.tenant_id, file);
    const READ: Action = Action::Share(ShareAction::Read);

    let decision = match state.policy.enforce(&ctx, READ, &resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(&state, &ctx, &resource, error).await;
            return Err(ApiError::new(error, request_id));
        }
    };
    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations, None) {
        return Err(state.audit.refuse(&ctx, READ, &resource, refused).await);
    }

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // No `tenant_id` predicate beyond the one below: `TenantScoped` has set `app.tenant_id` and
    // row-level security applies the second, independent predicate. It is written anyway, because
    // `docs/04 §3` asks for both layers and PR #22's lesson is that they catch different things.
    let rows = sqlx::query(LIST_SQL)
        .bind(ctx.tenant_id.as_uuid())
        .bind(file.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| ApiError::new(query_failed(error), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let items = rows
        .iter()
        .map(view_of)
        .collect::<Result<Vec<_>, Error>>()
        .map_err(|error| ApiError::new(error, request_id))?;

    Ok(Json(ShareList { items }))
}

/// Handles `PATCH /api/v1/shares/{id}` — expiry, permission and download budget.
///
/// # Errors
///
/// [`ApiError`]: `404` for a link that does not exist in this tenant, is already revoked, or whose
/// resource this caller cannot see; `422` when `maxDownloads` is lowered below what the link has
/// already spent; `400` for a body that will not decode.
pub async fn update(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = ctx.request_id;
    let id = link_id(&id, request_id)?;

    let request: UpdateShareRequest = if body.is_empty() {
        UpdateShareRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_error) => return Ok(unreadable_body().into_response(request_id)),
        }
    };

    let resource = governing_resource(&state, &ctx, id).await?;
    const UPDATE: Action = Action::Share(ShareAction::Update);
    authorize(&state, &ctx, UPDATE, &resource).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    // One statement, not read-then-write. Each `CASE WHEN $flag` pair is "was this field present in
    // the body", so an explicit `null` clears the column and an absent field leaves it exactly as
    // it is — including as a concurrent `PATCH` left it. A read-modify-write here would let two
    // patches that each changed one field silently undo each other's other field.
    let row = sqlx::query(UPDATE_SQL)
        .bind(ctx.tenant_id.as_uuid())
        .bind(id)
        .bind(request.permission.is_some())
        .bind(request.permission.flatten().map(|value| value.as_str()))
        .bind(request.allow_download.is_some())
        .bind(request.allow_download.flatten())
        .bind(request.expires_at.is_some())
        .bind(request.expires_at.flatten())
        .bind(request.max_downloads.is_some())
        .bind(request.max_downloads.flatten())
        .fetch_optional(&mut *tx)
        .await;

    let row = match row {
        Ok(row) => row,
        Err(error) => {
            // The `share_links_within_budget` backstop. Lowering the budget below what has already
            // been spent is well-formed and semantically impossible, which is exactly `422`.
            if budget_below_spent(&error) {
                return Ok(budget_refusal().into_response(request_id));
            }
            return Err(ApiError::new(query_failed(error), request_id));
        }
    };

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    // Zero rows: the link was revoked between the decision and the statement. A revoked link is not
    // patchable, and saying so as an absence keeps this endpoint from reporting a state the
    // creator can already read from the listing.
    let row = row.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let view = view_of(&row).map_err(|error| ApiError::new(error, request_id))?;

    Ok(([(header::CACHE_CONTROL, NO_STORE)], Json(view)).into_response())
}

/// Handles `DELETE /api/v1/shares/{id}` — revocation.
///
/// Revoking an already-revoked link is `204`, not an error: it is idempotent from the caller's
/// point of view, and the first revocation's timestamp is the one the audit trail wants
/// (`enclave_sharing::repo::revoke`). The row is not deleted — `revoked_at` is stamped — so
/// `share_link_events` keeps pointing at a link that still exists.
///
/// # Errors
///
/// [`ApiError`]: `404` for a link that does not exist in this tenant or whose resource this caller
/// cannot see.
pub async fn revoke(
    State(state): State<ApiState>,
    Authenticated { ctx }: Authenticated,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let request_id = ctx.request_id;
    let id = link_id(&id, request_id)?;

    let resource = governing_resource(&state, &ctx, id).await?;
    const REVOKE: Action = Action::Share(ShareAction::Revoke);
    authorize(&state, &ctx, REVOKE, &resource).await?;

    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let _first = enclave_sharing::repo::revoke(&mut tx, ctx.tenant_id, id, Utc::now())
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------------
// The pieces the handlers share
// ---------------------------------------------------------------------------------------------

/// The action a requested audience asks for.
///
/// `CLAUDE.md` rule 6, `docs/06 §12`. Only [`ShareAudience::Internal`] is provably inside the
/// tenant. Every other audience — including [`ShareAudience::Specific`], whose recipients are email
/// addresses `share_link_grants` never requires to be tenant members — asks
/// [`FileAction::ShareExternal`], because an audience whose reach cannot be shown to stay inside
/// the tenant has to be treated as leaving it.
///
/// The match is exhaustive on purpose: a new audience must break this function and force somebody
/// to decide which side of the line it falls on, rather than inheriting the permissive arm.
const fn action_for(audience: ShareAudience) -> Action {
    match audience {
        ShareAudience::Internal => Action::File(FileAction::Share),
        ShareAudience::Specific
        | ShareAudience::ExternalAuthenticated
        | ShareAudience::DomainRestricted
        | ShareAudience::Anyone => Action::File(FileAction::ShareExternal),
    }
}

/// The resource whose ACL governs a link.
///
/// **The link's target, never the link.** `enclave_authorization::classify` maps
/// [`enclave_core::ResourceKind::Share`] to `Target::Unsupported` and refuses it, deliberately —
/// share links carry no `acl_entries` rows and no containment the resolver could walk — so a chain
/// asked about the share object would deny every `PATCH` and every `DELETE` in the product. The
/// permission that governs changing a link is the permission on the thing it exposes.
///
/// The row is read before the chain runs, for [`crate::routes::uploads`]'s reason and with the same
/// bound on what it discloses: the read is tenant-scoped, so RLS has already restricted it; a miss
/// and another tenant's id are the same [`Error::NotFound`]; and a link whose target this caller
/// cannot see is refused as an absence by [`authorize`].
async fn governing_resource(
    state: &ApiState,
    ctx: &RequestContext,
    id: uuid::Uuid,
) -> Result<ResourceRef, ApiError> {
    let request_id = ctx.request_id;
    let mut tx = state
        .db
        .begin(ctx.tenant_id)
        .await
        .map_err(|error| ApiError::new(error.into(), request_id))?;

    let row = sqlx::query(TARGET_SQL)
        .bind(ctx.tenant_id.as_uuid())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| ApiError::new(query_failed(error), request_id))?;

    tx.commit().await.map_err(|error| ApiError::new(error.into(), request_id))?;

    let row = row.ok_or_else(|| ApiError::new(Error::NotFound, request_id))?;
    let kind: String =
        row.try_get("resource_type").map_err(|_| ApiError::new(Error::NotFound, request_id))?;
    let resource_id: uuid::Uuid =
        row.try_get("resource_id").map_err(|_| ApiError::new(Error::NotFound, request_id))?;

    resource_of(ctx.tenant_id, &kind, resource_id)
        .ok_or_else(|| ApiError::new(Error::NotFound, request_id))
}

/// Maps a stored `resource_type` onto the reference the chain is asked about.
///
/// An unknown discriminator is `None` rather than a guess: this release cannot decide a permission
/// on a kind it does not know, and the safe answer to "I cannot tell what this points at" is the
/// one that refuses.
fn resource_of(tenant: TenantId, kind: &str, id: uuid::Uuid) -> Option<ResourceRef> {
    match ShareResourceKind::from_str(kind).ok()? {
        ShareResourceKind::File => Some(ResourceRef::file(tenant, FileId::from_uuid(id))),
        ShareResourceKind::Folder => Some(ResourceRef::folder(tenant, FileId::from_uuid(id))),
        ShareResourceKind::Library => {
            Some(ResourceRef::library(tenant, enclave_core::LibraryId::from_uuid(id)))
        }
    }
}

/// Runs the chain and discharges the decision for the two `/shares/{id}` handlers.
async fn authorize(
    state: &ApiState,
    ctx: &RequestContext,
    action: Action,
    resource: &ResourceRef,
) -> Result<(), ApiError> {
    let decision = match state.policy.enforce(ctx, action, resource).await {
        Ok(decision) => decision,
        Err(error) => {
            let error = conceal_if_not_visible(state, ctx, resource, error).await;
            return Err(ApiError::new(error, ctx.request_id));
        }
    };
    let obligations = decision.into_obligations();
    if let Err(refused) = satisfy(&obligations, None) {
        return Err(state.audit.refuse(ctx, action, resource, refused).await);
    }
    Ok(())
}

/// Honours every obligation the chain attached, or turns it into a refusal.
///
/// Exhaustive on purpose, exactly as `crates/api/src/download.rs`'s is: [`Obligation`] is
/// deliberately not `#[non_exhaustive]`, so a new obligation breaks this and forces somebody to
/// decide what it means for a caller who is about to create a credential that can leave the
/// organisation.
///
/// One obligation is genuinely satisfiable here and it is the one `docs/05-API.md §4` provides for:
/// `RequireJustification` arrives in `X-Justification`. The text is never persisted and never
/// logged — it is user-authored prose about a file (`CLAUDE.md` rule 10) — so what the refusal row
/// records is that a justification was required and absent, which is the auditable fact.
///
/// # Errors
///
/// [`Refused`], which cannot reach a caller without an audit row (`ENC-606`).
fn satisfy(obligations: &Obligations, justification: Option<&str>) -> Result<(), Refused> {
    for obligation in obligations {
        match *obligation {
            Obligation::RequireJustification => {
                if justification.is_none_or(|text| text.trim().is_empty()) {
                    return Err(Refused::obligation(Obligation::RequireJustification));
                }
            }

            // A watermark identifies a viewer inside a rendition. A share link has no viewer yet
            // and produces no rendition, so the obligation cannot be discharged here — and an
            // unsatisfiable obligation is a refusal, never a shrug (rule 8).
            Obligation::Watermark => return Err(Refused::obligation(Obligation::Watermark)),

            // Creating a link is a write, so `ReadOnly` refuses it. On the *listing* path it would
            // be satisfied by construction — but this function is shared, and an arm that was
            // correct on one of two paths is how the wrong one ends up permitted.
            Obligation::ReadOnly => return Err(Refused::obligation(Obligation::ReadOnly)),

            // `NoDownload` reaching this path is a policy saying the bytes may not leave, arriving
            // at the endpoint whose whole purpose is to let them. `allow_download` would have to be
            // forced false, which is a *different link* from the one the caller asked for — so it
            // refuses rather than silently substituting one.
            Obligation::NoDownload => return Err(Refused::obligation(Obligation::NoDownload)),

            // A link is not a device replica, and `FileAction::Sync` is a separate action against a
            // separate endpoint — which is the point of them being separate (rule 6).
            Obligation::NoSync => {}

            Obligation::RequireApproval => {
                return Err(Refused::obligation(Obligation::RequireApproval))
            }

            // Raising a resource's classification is a write this handler does not perform. The
            // rank stays out of the row: it is DLP's finding about the content (rule 10).
            Obligation::Reclassify { to } => {
                tracing::warn!(
                    "a reclassification obligation reached the sharing path, which cannot apply \
                     one; refusing rather than minting a link against a stale label"
                );
                return Err(Refused::obligation(Obligation::Reclassify { to }));
            }
        }
    }
    Ok(())
}

/// The user a link is attributed to.
///
/// `share_links.created_by` names a `users` row, so the same argument as
/// [`crate::routes::uploads`]: a guest and a service account both answer `Some` to
/// `Actor::subject_id` and neither is a user id. A [`Refused`] rather than an [`Error`] because the
/// chain has already allowed by the time this is asked (`ENC-606`).
///
/// # Errors
///
/// [`Refused`] for every actor that is not [`Actor::User`].
fn author(ctx: &RequestContext) -> Result<UserId, Refused> {
    match ctx.actor {
        Actor::User(id) => Ok(id),
        Actor::Guest(_) | Actor::ServiceAccount(_) | Actor::McpClient(_) | Actor::System => {
            Err(Refused::actor(ReasonCode::AccessDenied))
        }
    }
}

/// Renders one row.
///
/// Fails as an internal error rather than as a missing field: a row this release cannot decode is
/// schema drift, not something the client did, and `Error::Internal` keeps the detail in the log.
fn view_of(row: &sqlx::postgres::PgRow) -> Result<ShareView, Error> {
    fn column<'r, T>(row: &'r sqlx::postgres::PgRow, name: &'static str) -> Result<T, Error>
    where
        T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
    {
        row.try_get(name).map_err(|_error| {
            // The column name, never the value: a share row holds a token digest and a password
            // hash, and a decode failure must not be the thing that prints one.
            tracing::error!(column = name, "a share_links column is not readable");
            Error::Internal(anyhow::anyhow!("share_links column `{name}` is not readable"))
        })
    }

    fn parse<T: core::str::FromStr>(raw: &str, column: &'static str) -> Result<T, Error> {
        raw.parse().map_err(|_error| {
            tracing::error!(column, "a share_links column holds a value this release cannot name");
            Error::Internal(anyhow::anyhow!("share_links column `{column}` is not a known value"))
        })
    }

    let resource_type: String = column(row, "resource_type")?;
    let permission: String = column(row, "permission")?;
    let audience: String = column(row, "audience")?;
    let domains: Option<serde_json::Value> = column(row, "allowed_domains")?;

    Ok(ShareView {
        id: column::<uuid::Uuid>(row, "id")?.to_string(),
        resource_type: parse::<ShareResourceKind>(&resource_type, "resource_type")?.as_str(),
        resource_id: column::<uuid::Uuid>(row, "resource_id")?.to_string(),
        permission: parse::<SharePermission>(&permission, "permission")?.as_str(),
        allow_download: column(row, "allow_download")?,
        audience: parse::<ShareAudience>(&audience, "audience")?.as_str(),
        has_password: column(row, "has_password")?,
        require_otp: column(row, "require_otp")?,
        require_mfa: column(row, "require_mfa")?,
        expires_at: column(row, "expires_at")?,
        max_downloads: column(row, "max_downloads")?,
        download_count: column(row, "download_count")?,
        allowed_domains: domains.map(serde_json::from_value::<Vec<String>>).transpose().map_err(
            |_error| Error::Internal(anyhow::anyhow!("allowed_domains is not an array of strings")),
        )?,
        created_by: column::<uuid::Uuid>(row, "created_by")?.to_string(),
        created_at: column(row, "created_at")?,
        revoked_at: column(row, "revoked_at")?,
    })
}

/// Whether a failed statement is the `share_links_within_budget` backstop.
///
/// Named by constraint rather than by SQLSTATE alone: `23514` is *any* check constraint, and a
/// future one on this table answered as "your budget is below what you spent" would be a confusing
/// lie rather than a helpful message.
fn budget_below_spent(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(database) = error else { return false };
    database.constraint() == Some("share_links_within_budget")
}

/// The `422` a budget below the spend produces.
fn budget_refusal() -> Envelope {
    Envelope::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "VALIDATION_FAILED",
        "This link has already issued more downloads than the new limit allows.",
        "Read the link's `downloadCount` and set a limit at or above it, or revoke the link.",
    )
    .with_details(vec![serde_json::json!({
        "field": "maxDownloads",
        "code": ValidationCode::OutOfRange.as_str(),
    })])
}

/// The `400` a body that will not decode produces. The decoder's message is not echoed — it quotes
/// an input this endpoint has decided nothing about (`docs/05-API.md §5`).
fn unreadable_body() -> Envelope {
    Envelope::new(
        StatusCode::BAD_REQUEST,
        "VALIDATION_FAILED",
        "The request body could not be read.",
        "Correct the field named in `details` and retry.",
    )
    .with_details(vec![serde_json::json!({
        "field": "body",
        "code": ValidationCode::InvalidFormat.as_str(),
    })])
}

/// Routes a driver failure through `enclave_db`, so retryability is classified in one place.
fn query_failed(error: sqlx::Error) -> Error {
    Error::from(enclave_db::DbError::Query(error))
}

/// Parses the `{id}` of `/files/{id}/shares`. A malformed id is an absence, for
/// `crates/api/src/download.rs`'s reason.
fn file_id(raw: &str, request_id: RequestId) -> Result<FileId, ApiError> {
    FileId::from_str(raw).map_err(|_error| ApiError::new(Error::NotFound, request_id))
}

/// Parses the `{id}` of `/shares/{id}`.
///
/// `share_links.id` is a bare `UUID` in `docs/04 §11` — there is no `ShareLinkId` newtype in
/// `enclave-core` and `enclave-sharing` models the column as a `Uuid` too, so introducing one here
/// would be a third opinion rather than a second.
fn link_id(raw: &str, request_id: RequestId) -> Result<uuid::Uuid, ApiError> {
    uuid::Uuid::parse_str(raw).map_err(|_error| ApiError::new(Error::NotFound, request_id))
}

// --- Statements ------------------------------------------------------------------------------

/// The columns every read here returns, in one place so the two statements cannot drift.
///
/// `token_hash` and `password_hash` are absent. `has_password` is computed in the statement, so the
/// hash never crosses the wire *into this process*, let alone out of it — an Argon2 hash in a log
/// is an offline attack anybody with log access can run at their leisure.
macro_rules! columns {
    () => {
        "id, resource_type, resource_id, permission, allow_download, audience, \
         (password_hash IS NOT NULL) AS has_password, require_otp, require_mfa, expires_at, \
         max_downloads, download_count, allowed_domains, created_by, created_at, revoked_at"
    };
}

const LIST_SQL: &str = concat!(
    "SELECT ",
    columns!(),
    " FROM share_links WHERE tenant_id = $1 AND resource_id = $2 ORDER BY created_at, id"
);

/// Just enough to decide the permission. Reading the whole row here would put a
/// `password_hash` in memory for a request that is about to be refused.
const TARGET_SQL: &str =
    "SELECT resource_type, resource_id FROM share_links WHERE tenant_id = $1 AND id = $2";

/// Patch semantics in one statement. Each odd-numbered parameter is *"was this field present"* and
/// the even one beside it is the value, so `null` clears and absence leaves the column alone.
const UPDATE_SQL: &str = concat!(
    "UPDATE share_links SET
        permission     = CASE WHEN $3 THEN $4  ELSE permission     END,
        allow_download = CASE WHEN $5 THEN $6  ELSE allow_download END,
        expires_at     = CASE WHEN $7 THEN $8  ELSE expires_at     END,
        max_downloads  = CASE WHEN $9 THEN $10 ELSE max_downloads  END
      WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
      RETURNING ",
    columns!()
);

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{ClassificationRank, GuestId, LibraryId, ServiceAccountId};

    use super::*;

    fn obligations(list: impl IntoIterator<Item = Obligation>) -> Obligations {
        list.into_iter().collect()
    }

    fn refused(result: Result<(), Refused>) -> Option<ReasonCode> {
        result.err().map(Refused::code)
    }

    /// The split that `docs/06 §12` and `CLAUDE.md` rule 6 turn on.
    ///
    /// Driven from `ShareAudience::all()` rather than a remembered list, so a new audience fails
    /// here by name until somebody decides which side of the line it is on. The permissive mistake
    /// is grouping `SPECIFIC` with `INTERNAL` — its recipients are email addresses, and nothing
    /// requires them to belong to the tenant.
    #[test]
    fn only_an_internal_audience_asks_the_internal_question() {
        assert_eq!(action_for(ShareAudience::Internal), Action::File(FileAction::Share));

        for audience in ShareAudience::all() {
            if *audience == ShareAudience::Internal {
                continue;
            }
            assert_eq!(
                action_for(*audience),
                Action::File(FileAction::ShareExternal),
                "`{audience}` does not provably stay inside the tenant, so it must ask \
                 file.share_external"
            );
        }

        // The positive control for the sweep: at least one audience is on each side, so neither
        // assertion above is satisfied by a function that answers one action for everything.
        assert_ne!(
            action_for(ShareAudience::Internal),
            action_for(ShareAudience::Anyone),
            "the two actions have collapsed into one"
        );
    }

    /// `docs/05-API.md §4`'s header is the one obligation this path can discharge.
    #[test]
    fn a_justification_is_taken_from_the_header_and_whitespace_is_not_one() {
        let required = obligations([Obligation::RequireJustification]);
        assert_eq!(refused(satisfy(&required, None)), Some(ReasonCode::DlpJustificationRequired));
        assert_eq!(
            refused(satisfy(&required, Some("  \t "))),
            Some(ReasonCode::DlpJustificationRequired)
        );
        assert_eq!(refused(satisfy(&required, Some("Client audit request #4412"))), None);
    }

    /// Every other obligation refuses, and the arms are enumerated rather than sampled.
    #[test]
    fn an_obligation_this_path_cannot_discharge_refuses_rather_than_being_dropped() {
        assert_eq!(
            refused(satisfy(&obligations([Obligation::NoDownload]), Some("why"))),
            Some(ReasonCode::PreviewOnly)
        );
        assert_eq!(
            refused(satisfy(&obligations([Obligation::Watermark]), Some("why"))),
            Some(ReasonCode::PreviewOnly)
        );
        assert_eq!(
            refused(satisfy(&obligations([Obligation::ReadOnly]), Some("why"))),
            Some(ReasonCode::AccessDenied)
        );
        assert_eq!(
            refused(satisfy(&obligations([Obligation::RequireApproval]), Some("why"))),
            Some(ReasonCode::DlpApprovalRequired)
        );
        assert_eq!(
            refused(satisfy(
                &obligations([Obligation::Reclassify { to: ClassificationRank::new(40) }]),
                Some("why")
            )),
            Some(ReasonCode::AccessDenied)
        );

        // The positive control. Without it every assertion above is satisfied by a `satisfy` that
        // refuses unconditionally, which would also refuse every legitimate share.
        assert!(satisfy(&Obligations::none(), None).is_ok());
        assert!(satisfy(&obligations([Obligation::NoSync]), None).is_ok());
    }

    /// `share_links.created_by` names a `users` row, and only one actor kind has one.
    #[test]
    fn only_a_directory_member_can_own_a_share_link() {
        let mut ctx = RequestContext::system(TenantId::new_v7());
        let user = UserId::new_v7();
        ctx.actor = Actor::User(user);
        assert_eq!(author(&ctx).expect("a directory member"), user);

        for actor in [
            Actor::Guest(GuestId::new_v7()),
            Actor::ServiceAccount(ServiceAccountId::new_v7()),
            Actor::System,
        ] {
            ctx.actor = actor;
            assert_eq!(
                author(&ctx).expect_err("not a directory member").control(),
                crate::refusal::Control::ActorEligibility
            );
        }
    }

    /// A link points at one of three kinds, and each resolves to the reference whose ACL the chain
    /// can actually walk.
    #[test]
    fn a_links_target_resolves_to_the_resource_the_resolver_understands() {
        let tenant = TenantId::new_v7();
        let id = uuid::Uuid::now_v7();

        assert_eq!(
            resource_of(tenant, "FILE", id),
            Some(ResourceRef::file(tenant, FileId::from_uuid(id)))
        );
        assert_eq!(
            resource_of(tenant, "FOLDER", id),
            Some(ResourceRef::folder(tenant, FileId::from_uuid(id)))
        );
        assert_eq!(
            resource_of(tenant, "LIBRARY", id),
            Some(ResourceRef::library(tenant, LibraryId::from_uuid(id)))
        );
        // Not a guess. A kind this release cannot name is refused, because it cannot decide a
        // permission on it.
        assert_eq!(resource_of(tenant, "WORKSPACE", id), None);
        assert_eq!(resource_of(tenant, "", id), None);
    }

    /// Absent and `null` are different instructions, and a plain `Option` cannot tell them apart.
    #[test]
    fn a_patch_distinguishes_an_absent_field_from_an_explicit_null() {
        let request: UpdateShareRequest =
            serde_json::from_str(r#"{"maxDownloads":null}"#).expect("a well-formed patch");
        assert_eq!(request.max_downloads, Some(None), "an explicit null clears the budget");
        assert_eq!(request.expires_at, None, "an absent field is unchanged");

        let request: UpdateShareRequest =
            serde_json::from_str(r#"{"maxDownloads":5,"permission":"PREVIEW_ONLY"}"#)
                .expect("a well-formed patch");
        assert_eq!(request.max_downloads, Some(Some(5)));
        assert_eq!(request.permission, Some(Some(SharePermission::PreviewOnly)));
        assert_eq!(request.allow_download, None);

        // `ENC-615`: an unknown field is refused rather than ignored.
        assert!(serde_json::from_str::<UpdateShareRequest>(r#"{"budget":5}"#).is_err());
    }

    /// The one field a caller might expect and must not get, until something verifies it.
    #[test]
    fn a_share_cannot_be_given_a_password_that_nothing_would_check() {
        let with_password = r#"{"permission":"VIEW","audience":"ANYONE","password":"hunter2"}"#;
        assert!(
            serde_json::from_str::<CreateShareRequest>(with_password).is_err(),
            "a password field was accepted, so a caller can believe a link is protected when \
             nothing verifies one (ENC-694)"
        );

        // The positive control: the same body without the field decodes, so the assertion above is
        // about `password` and not about a request type that rejects everything.
        let without = r#"{"permission":"VIEW","audience":"ANYONE"}"#;
        let request: CreateShareRequest = serde_json::from_str(without).expect("well-formed");
        assert_eq!(request.audience, ShareAudience::Anyone);
        assert!(!request.allow_download, "allowDownload defaults closed");
    }

    /// Neither statement may reach a credential column.
    ///
    /// The needles are assembled at run time: this test's own source is inside the file it scans,
    /// and `docs/12 §1.2` records two tests in this repository that failed against themselves.
    #[test]
    fn no_statement_here_selects_a_stored_credential() {
        let column_list = columns!();
        for needle in [format!("token_{}", "hash"), format!("password_{}, ", "hash")] {
            assert!(
                !column_list.contains(&needle),
                "`{needle}` is in the shared column list, so a share credential is being loaded \
                 into this process"
            );
        }
        // The positive control: `password_hash` *does* appear, inside the `IS NOT NULL` projection,
        // which is what makes `hasPassword` answerable without the hash ever being selected.
        assert!(column_list.contains("(password_hash IS NOT NULL) AS has_password"));
        assert!(!LIST_SQL.contains("token_hash"));
        assert!(!UPDATE_SQL.contains("token_hash"));
        assert!(!TARGET_SQL.contains("password_hash"));
    }

    #[test]
    fn a_budget_below_the_spend_names_the_field_and_is_unprocessable() {
        let envelope = budget_refusal();
        assert_eq!(envelope.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let details = envelope.details();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["field"], "maxDownloads");
        assert_eq!(details[0]["code"], ValidationCode::OutOfRange.as_str());
    }

    #[test]
    fn a_malformed_id_is_answered_as_an_absence() {
        let request_id = RequestId::new_v7();
        for junk in ["", "not-a-uuid", "../../etc/passwd"] {
            assert!(matches!(
                file_id(junk, request_id).expect_err("refused").error(),
                Error::NotFound
            ));
            assert!(matches!(
                link_id(junk, request_id).expect_err("refused").error(),
                Error::NotFound
            ));
        }
        // Positive controls, so neither assertion is about a parser that refuses everything.
        let file = FileId::new_v7();
        assert_eq!(file_id(&file.to_string(), request_id).expect("well-formed"), file);
        let id = uuid::Uuid::now_v7();
        assert_eq!(link_id(&id.to_string(), request_id).expect("well-formed"), id);
    }
}
