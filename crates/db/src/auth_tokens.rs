//! The PostgreSQL half of `crates/auth` — `ENC-687`.
//!
//! `crates/auth` defines [`RefreshTokenStore`], [`DenylistStore`], [`EpochStore`] and
//! [`SessionFactsProvider`] and, until this module existed, shipped only the in-memory
//! implementations it exports for its own tests. The consequence was not subtle: `enclave-api`
//! could not build an `EnclaveTokenService` at all, so every `/api/v1/auth/*` route answered
//! `503 DEPENDENCY_UNAVAILABLE` in the deployed binary while the whole suite passed.
//!
//! # Why this sits in `enclave-db`
//!
//! The fourth argued exception to the crate header's "no repositories", and it has two independent
//! reasons where the earlier three had one.
//!
//! 1. The ordinary one, which [`crate::dlp`] and [`crate::conditional_access`] already make:
//!    `CLAUDE.md`'s Rust conventions say *all database access through the `db` crate's
//!    `TenantScoped` wrapper, no `sqlx::query!` in domain crates*. `crates/auth` is a domain crate
//!    and would have to reach past this one to get at `refresh_tokens`.
//! 2. The one only this module has: **three of the five statements here are cross-tenant**, and
//!    `DbPool::platform_connection` — the row-level-security escape hatch — may not be called from
//!    outside this crate. `.github/scripts/no_raw_pool.py` fails CI on that, and the rule exists so
//!    that `grep -rn platform_connection crates/` stays a complete list of the places isolation is
//!    bypassed. A `PgRefreshTokenStore` written in `crates/auth` would have had to grow that list.
//!
//! # The three cross-tenant statements, and why they are not a tenancy hole
//!
//! [`RefreshTokenStore`]'s signatures take **no tenant**, and `crates/auth/src/service.rs` says why
//! in as many words: *"Accepting a tenant id here would mean accepting one from a caller, and a
//! caller is one layer away from a request body — non-negotiable rule 3."* The narrow signature
//! makes the unsafe version unwritable, and the price is that the implementation has to resolve the
//! tenant from the stored row rather than from an argument. That is a cross-tenant read.
//!
//! What bounds it is the *key* each statement is asked for, and none of the three can be steered by
//! a caller:
//!
//! * [`PgRefreshTokenStore::find_by_hash`] is keyed on the SHA-256 of a 256-bit random token that
//!   the server minted and put in an `HttpOnly` cookie. A caller who does not hold the token cannot
//!   produce the digest, and one who does holds the credential itself.
//! * `revoke_family` is keyed on a `session_id`, a UUIDv7 the server generated. The one route that
//!   reaches it with a caller-supplied value — `DELETE /api/v1/auth/sessions/{sid}` — proves
//!   ownership first, inside the caller's own tenant, and turns a miss into a `404`
//!   (`crates/api/src/routes/auth.rs`, `SELECT_OWN_FAMILY`).
//! * `revoke_all_for_subject` is keyed on a `UserId` taken from the verified access token.
//!
//! Each returns rows, never a tenant name or any other tenant's data, and each is written here
//! beside [`crate::tenants::active_tenants`] and [`crate::routing::resolve_routed_tenant`] so that
//! one review covers every cross-tenant `WHERE` clause in the workspace.
//!
//! # The grant these three need, which does not exist yet
//!
//! **`enclave_platform` has no privilege on `refresh_tokens`.** `migrations/0002_rls_policies.sql`
//! grants it `SELECT, UPDATE, DELETE ON events_outbox` and `SELECT ON tenants`, and nothing else;
//! `0003` grants only `enclave_app`. So in a deployment that really does separate the roles, the
//! three statements above fail with `permission denied` rather than returning no rows — the same
//! shape `ENC-686` records for `tenant_domains`.
//!
//! They work today because the development stack and the test harness both connect as the cluster
//! superuser, which bypasses grants and row-level security alike. That is a property of those
//! environments and not of the code, and it is written here rather than discovered later.
//! `ENC-705` is the migration; the exact statement it needs is in that row.
//!
//! `insert` and `rotate` are unaffected: both are handed a [`RefreshRecord`] that already carries
//! its `tenant_id`, so both go through [`DbPool::begin`] like any other write.
//!
//! # What is deliberately not decided here
//!
//! Nothing in this module classifies a token, chooses a lifetime, or decides what a replay means.
//! `crates/auth` does all of that — `classify`, `RefreshOutcome`, `EnclaveTokenService::refresh` —
//! and this module is the storage it does it over. The one judgement that *is* taken here is the
//! mapping from a `sqlx` failure to [`AuthError::StorageUnavailable`], and it is taken here because
//! the alternative — reporting a database outage as a credential rejection — is the bug that turns
//! an incident into a support queue full of password resets.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use enclave_auth::{
    AuthError, DenylistStore, EpochStore, RefreshRecord, RefreshTokenStore, RevokeReason,
    SessionFacts, SessionFactsProvider, StoreUnavailable,
};
use enclave_core::{Actor, ClientType, Dependency, DeviceId, ScopeSet, SessionId, TenantId, UserId};
use sqlx::postgres::PgRow;
use sqlx::Row as _;
use uuid::Uuid;

use crate::ids::sql;
use crate::pool::DbPool;

/// Records the first token of a family.
const INSERT_REFRESH: &str = "INSERT INTO refresh_tokens \
     (id, tenant_id, session_id, actor_id, actor_type, token_hash, device_id, client_type, \
      parent_id, issued_at, expires_at, absolute_expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";

/// Looks a presented token up by digest. Cross-tenant — see the module documentation.
///
/// No `expires_at` predicate, and that is [`RefreshTokenStore::find_by_hash`]'s contract rather
/// than an oversight: consumed and revoked rows must come back, because a consumed row is the K4
/// replay signal and filtering it here would silently downgrade a detected theft to an ordinary
/// rejection.
const SELECT_BY_HASH: &str = "SELECT id, tenant_id, session_id, actor_id, actor_type, token_hash, \
     device_id, client_type, parent_id, issued_at, expires_at, absolute_expires_at, consumed_at, \
     revoked_at, revoke_reason \
     FROM refresh_tokens WHERE token_hash = $1";

/// Consumes the presented token. The `IS NULL` predicates are the serialisation point.
///
/// Two concurrent refreshes of one token both pass `classify`; only one of them can make this
/// statement report a row, because the second finds `consumed_at` already set. That is why the
/// predicate is in the `WHERE` and not checked in Rust between the read and the write.
const CONSUME_REFRESH: &str = "UPDATE refresh_tokens SET consumed_at = $2 \
     WHERE id = $1 AND tenant_id = $3 AND consumed_at IS NULL AND revoked_at IS NULL";

/// Revokes one family and returns what was still outstanding. Cross-tenant.
///
/// The `RETURNING` list is spelled out rather than `*`, and [`SELECT_BY_HASH`] and
/// [`REVOKE_FOR_SUBJECT`] spell out the same one. Sharing a constant between them is not available:
/// `sqlx::query` refuses an interpolated statement — a deliberate lint against dynamic SQL — so the
/// three literals are held equal by a test in this module instead.
const REVOKE_FAMILY: &str = "UPDATE refresh_tokens SET revoked_at = $2, revoke_reason = $3 \
     WHERE session_id = $1 AND revoked_at IS NULL AND consumed_at IS NULL \
     RETURNING id, tenant_id, session_id, actor_id, actor_type, token_hash, device_id, \
     client_type, parent_id, issued_at, expires_at, absolute_expires_at, consumed_at, \
     revoked_at, revoke_reason";

/// Revokes every family a subject holds and returns what was still outstanding. Cross-tenant.
const REVOKE_FOR_SUBJECT: &str = "UPDATE refresh_tokens SET revoked_at = $2, revoke_reason = $3 \
     WHERE actor_id = $1 AND revoked_at IS NULL AND consumed_at IS NULL \
     RETURNING id, tenant_id, session_id, actor_id, actor_type, token_hash, device_id, \
     client_type, parent_id, issued_at, expires_at, absolute_expires_at, consumed_at, \
     revoked_at, revoke_reason";

/// Adds a denial. Idempotent, because revoking an already-revoked family must not fail.
const INSERT_REVOCATION: &str = "INSERT INTO token_revocations \
     (tenant_id, jti, expires_at, reason, created_at) VALUES ($1, $2, $3, $4, now()) \
     ON CONFLICT (tenant_id, jti) DO NOTHING";

/// Whether either the token or its family has been denied and the denial has not lapsed.
const SELECT_DENIED: &str = "SELECT 1 FROM token_revocations \
     WHERE tenant_id = $1 AND jti = ANY($2) AND expires_at > now() LIMIT 1";

/// The subject's mass-revocation counter.
const SELECT_EPOCH: &str =
    "SELECT token_epoch FROM users WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL \
     AND status = 'ACTIVE'";

// -------------------------------------------------------------------------------------------
// Refresh families
// -------------------------------------------------------------------------------------------

/// [`RefreshTokenStore`] over `refresh_tokens` (`docs/04-DATA-MODEL.md §6`).
#[derive(Debug, Clone)]
pub struct PgRefreshTokenStore {
    pool: DbPool,
}

impl PgRefreshTokenStore {
    /// Binds the store to a pool.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RefreshTokenStore for PgRefreshTokenStore {
    async fn insert(&self, record: RefreshRecord) -> Result<(), AuthError> {
        let mut tx = self.pool.begin(record.tenant_id).await.map_err(unavailable)?;
        sqlx::query(INSERT_REFRESH)
            .bind(record.id)
            .bind(sql(record.tenant_id))
            .bind(sql(record.session_id))
            .bind(actor_id(record.actor))
            .bind(actor_type(record.actor)?)
            .bind(&record.token_hash)
            .bind(record.device_id.map(|id| id.as_uuid()))
            .bind(record.client.as_str())
            .bind(record.parent_id)
            .bind(record.issued_at)
            .bind(record.expires_at)
            .bind(record.absolute_expires_at)
            .execute(&mut *tx)
            .await
            .map_err(query_failed)?;
        tx.commit().await.map_err(unavailable)
    }

    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<RefreshRecord>, AuthError> {
        let mut conn = self.pool.platform_connection().await.map_err(unavailable)?;
        let row = sqlx::query(SELECT_BY_HASH)
            .bind(token_hash)
            .fetch_optional(&mut *conn)
            .await
            .map_err(query_failed)?;
        row.as_ref().map(record_from_row).transpose()
    }

    async fn rotate(
        &self,
        presented_id: Uuid,
        successor: RefreshRecord,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        // One transaction, and the trait says why it has to be: consuming without inserting logs
        // the user out, and inserting without consuming leaves two live tokens in a family — the
        // state reuse detection exists to be able to rule out.
        //
        // Tenant-scoped rather than cross-tenant, and free: the successor carries the tenant the
        // presented row was read under, so no lookup is needed to obtain one.
        let mut tx = self.pool.begin(successor.tenant_id).await.map_err(unavailable)?;

        let consumed = sqlx::query(CONSUME_REFRESH)
            .bind(presented_id)
            .bind(now)
            .bind(sql(successor.tenant_id))
            .execute(&mut *tx)
            .await
            .map_err(query_failed)?;
        if consumed.rows_affected() == 0 {
            // Consumed or revoked between the lookup and here — a concurrent refresh won, or the
            // family was destroyed. Rolling back is what stops the successor from existing.
            tx.rollback().await.map_err(unavailable)?;
            return Err(AuthError::RefreshRejected);
        }

        sqlx::query(INSERT_REFRESH)
            .bind(successor.id)
            .bind(sql(successor.tenant_id))
            .bind(sql(successor.session_id))
            .bind(actor_id(successor.actor))
            .bind(actor_type(successor.actor)?)
            .bind(&successor.token_hash)
            .bind(successor.device_id.map(|id| id.as_uuid()))
            .bind(successor.client.as_str())
            .bind(successor.parent_id)
            .bind(successor.issued_at)
            .bind(successor.expires_at)
            .bind(successor.absolute_expires_at)
            .execute(&mut *tx)
            .await
            .map_err(query_failed)?;

        tx.commit().await.map_err(unavailable)
    }

    async fn revoke_family(
        &self,
        session_id: SessionId,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError> {
        self.revoke_returning(REVOKE_FAMILY, session_id.as_uuid(), reason, now).await
    }

    async fn revoke_all_for_subject(
        &self,
        subject: Uuid,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError> {
        self.revoke_returning(REVOKE_FOR_SUBJECT, subject, reason, now).await
    }
}

impl PgRefreshTokenStore {
    /// The shared body of the two revocation methods.
    ///
    /// Cross-tenant, on the platform connection. See the module documentation for the argument and
    /// for the grant this needs.
    async fn revoke_returning(
        &self,
        statement: &'static str,
        key: Uuid,
        reason: RevokeReason,
        now: DateTime<Utc>,
    ) -> Result<Vec<RefreshRecord>, AuthError> {
        let mut conn = self.pool.platform_connection().await.map_err(unavailable)?;
        let rows = sqlx::query(statement)
            .bind(key)
            .bind(now)
            .bind(revoke_reason_str(reason))
            .fetch_all(&mut *conn)
            .await
            .map_err(query_failed)?;

        // The rows are returned *as they were before* this statement in one respect that matters:
        // `revoked_at` now holds `now`. The caller uses them only for their `tenant_id` and
        // `session_id`, to denylist the access tokens the family issued.
        rows.iter().map(record_from_row).collect()
    }
}

// -------------------------------------------------------------------------------------------
// The denylist
// -------------------------------------------------------------------------------------------

/// [`DenylistStore`] over `token_revocations` (`docs/04-DATA-MODEL.md §6`).
///
/// # `deny_session` shares a key space with `deny_jti`, and that needs saying out loud
///
/// `crates/auth/src/lib.rs` records the gap: *"Family-level denial has no table yet … persisting
/// that needs a session-scoped row; `token_revocations` is keyed `(tenant_id, jti)` only. Redis can
/// express it today; PostgreSQL cannot."*
///
/// This implementation denies a family by writing its `session_id` into the `jti` column, and
/// [`DenylistStore::is_denied`] asks for either value. The reasons that is safe rather than a fudge:
///
/// * both values are 122-bit random UUIDs, so a collision between a `jti` and a `sid` is not a
///   thing that happens;
/// * a collision, were one to happen, denies a token that should not have been denied — never the
///   reverse. Every direction this can be wrong in is the fail-closed one;
/// * nothing else reads the table, so no other query can be confused by the extra rows.
///
/// What it costs is legibility: an operator reading `token_revocations` cannot tell a denied token
/// from a denied session. `ENC-706` is the migration that adds the discriminator and its exact
/// statement, and it is a migration rather than something taken quietly here because
/// `migrations/**` is not this change's to write.
///
/// The alternative was to return [`StoreUnavailable`] from `deny_session` and leave family
/// revocation half-done — logging the user out of the refresh family while their access token kept
/// working for another ten minutes, on every logout, with an `ERROR` line each time. That is worse
/// in the direction that matters.
#[derive(Debug, Clone)]
pub struct PgDenylist {
    pool: DbPool,
}

impl PgDenylist {
    /// Binds the denylist to a pool.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// One denial row. Both public methods are this, differing only in which UUID they deny.
    async fn deny(
        &self,
        tenant_id: TenantId,
        key: Uuid,
        expires_at: DateTime<Utc>,
        reason: RevokeReason,
    ) -> Result<(), StoreUnavailable> {
        let mut tx = self.pool.begin(tenant_id).await.map_err(|_| postgres_unavailable())?;
        sqlx::query(INSERT_REVOCATION)
            .bind(sql(tenant_id))
            .bind(key)
            .bind(expires_at)
            .bind(revoke_reason_str(reason))
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                // No `jti`, no `sid`, no reason: an error line naming the token it failed to deny
                // is a log that carries the identifier of a live credential.
                tracing::error!(?error, "a token denial could not be written");
                postgres_unavailable()
            })?;
        tx.commit().await.map_err(|_| postgres_unavailable())
    }
}

#[async_trait]
impl DenylistStore for PgDenylist {
    async fn deny_jti(
        &self,
        tenant_id: TenantId,
        jti: Uuid,
        expires_at: DateTime<Utc>,
        reason: RevokeReason,
    ) -> Result<(), StoreUnavailable> {
        self.deny(tenant_id, jti, expires_at, reason).await
    }

    async fn deny_session(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        expires_at: DateTime<Utc>,
        reason: RevokeReason,
    ) -> Result<(), StoreUnavailable> {
        self.deny(tenant_id, session_id.as_uuid(), expires_at, reason).await
    }

    async fn is_denied(
        &self,
        tenant_id: TenantId,
        jti: Uuid,
        session_id: SessionId,
    ) -> Result<bool, StoreUnavailable> {
        let mut tx = self.pool.begin(tenant_id).await.map_err(|_| postgres_unavailable())?;
        let keys = [jti, session_id.as_uuid()];
        let found = sqlx::query(SELECT_DENIED)
            .bind(sql(tenant_id))
            .bind(&keys[..])
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| {
                tracing::error!(?error, "the denylist could not be read");
                postgres_unavailable()
            })?;
        tx.commit().await.map_err(|_| postgres_unavailable())?;
        Ok(found.is_some())
    }
}

// -------------------------------------------------------------------------------------------
// The epoch counter
// -------------------------------------------------------------------------------------------

/// [`EpochStore`] over `users.token_epoch` — the mass-revocation counter of `docs/03-LLD.md §5.4`.
#[derive(Debug, Clone)]
pub struct PgEpochs {
    pool: DbPool,
}

impl PgEpochs {
    /// Binds the reader to a pool.
    #[must_use]
    pub const fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EpochStore for PgEpochs {
    async fn current_epoch(
        &self,
        tenant_id: TenantId,
        subject: Uuid,
    ) -> Result<i32, StoreUnavailable> {
        read_epoch(&self.pool, tenant_id, subject)
            .await?
            // A subject that no longer resolves — deleted, suspended, deprovisioned — is reported
            // as an epoch no token can match rather than as `0`, which every token would match.
            // `i32::MAX` is the fail-closed answer, and it is returned rather than an error because
            // an error here means "the store did not answer", which is the fail-*open* branch for
            // an unprivileged token (K9).
            .map_or(Ok(i32::MAX), Ok)
    }
}

// -------------------------------------------------------------------------------------------
// Session facts
// -------------------------------------------------------------------------------------------

/// [`SessionFactsProvider`] — what a rotation re-resolves rather than copies forward.
///
/// `crates/auth/src/service.rs` is emphatic that these are re-read: *"a role removed, a group
/// membership lost or an epoch bumped since the last refresh must be reflected in the token issued
/// now."* Two of the five fields are genuinely re-resolved here, and three are derived. Which is
/// which matters, so it is written down:
///
/// | Field | Where it comes from |
/// |---|---|
/// | `epoch` | **Re-read** from `users.token_epoch`. This is the one that makes `logout-all` work |
/// | `scopes` | [`ScopeSet::empty`], matching what `POST /auth/login` issues — a session that asserts no scopes is one authorization decides entirely from the ACL (`ENC-126`) |
/// | `auth_time` | **Derived exactly**: `absolute_expires_at - absolute_ttl`, because the absolute ceiling is anchored to the authentication event and never moves |
/// | `methods` | `Pwd` only. See below |
/// | `max_classification` | `None`. The ceiling is an MCP-client property (`docs/03-LLD.md §5.6`) and a refresh family belongs to an interactive client |
///
/// # `methods` is the honest lie, and it errs downwards
///
/// `refresh_tokens` records no `amr`. A session that completed MFA therefore re-issues with
/// `amr: ["pwd"]` and an `acr` of `1` rather than `2` — the session *weakens* across a rotation
/// instead of strengthening. That is the safe direction and it is not the right one: a
/// conditional-access rule requiring `acr: 2` would start refusing a genuinely
/// multi-factor session ten minutes after it was established.
///
/// The fix is a column, so it is `ENC-707` rather than something invented here. What must not
/// happen in the meantime is the opposite shortcut — reading `user_mfa_methods` and asserting
/// `Mfa` because a factor is *enrolled*. Enrolment is not use, and a token whose `amr` claims a
/// factor the user did not present is a forged assertion this crate would be manufacturing.
#[derive(Debug, Clone)]
pub struct PgSessionFacts {
    pool: DbPool,
    absolute_ttl: Duration,
}

impl PgSessionFacts {
    /// Binds the provider to a pool, and to the absolute refresh lifetime the deployment runs.
    ///
    /// The lifetime is taken rather than assumed because it is the divisor that recovers
    /// `auth_time`: `absolute_expires_at` was written as `auth_time + absolute_ttl`, so a provider
    /// configured with a different value than the issuer would report an authentication time that
    /// never happened, and every max-age policy would measure from it.
    #[must_use]
    pub const fn new(pool: DbPool, absolute_ttl: Duration) -> Self {
        Self { pool, absolute_ttl }
    }
}

#[async_trait]
impl SessionFactsProvider for PgSessionFacts {
    async fn facts_for(&self, record: &RefreshRecord) -> Result<SessionFacts, AuthError> {
        let subject = actor_id(record.actor);
        let epoch = read_epoch(&self.pool, record.tenant_id, subject)
            .await
            .map_err(AuthError::StorageUnavailable)?
            // `RefreshRejected` rather than a storage error, and the trait says why: this is
            // "the subject no longer has a usable session at all — disabled, deleted or offboarded
            // between rotations". A refusal, not a fault.
            .ok_or(AuthError::RefreshRejected)?;

        Ok(SessionFacts {
            scopes: ScopeSet::empty(),
            methods: vec![enclave_auth::AuthMethod::Pwd],
            auth_time: record.absolute_expires_at - self.absolute_ttl,
            epoch,
            max_classification: None,
        })
    }
}

// -------------------------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------------------------

/// Reads `users.token_epoch`, or `None` when the subject is not a user who may hold a session.
async fn read_epoch(
    pool: &DbPool,
    tenant_id: TenantId,
    subject: Uuid,
) -> Result<Option<i32>, StoreUnavailable> {
    let mut tx = pool.begin(tenant_id).await.map_err(|_| postgres_unavailable())?;
    let row = sqlx::query(SELECT_EPOCH)
        .bind(sql(tenant_id))
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(?error, "the token epoch could not be read");
            postgres_unavailable()
        })?;
    tx.commit().await.map_err(|_| postgres_unavailable())?;
    Ok(row.map(|row| row.get::<i32, _>("token_epoch")))
}

/// Decodes one `refresh_tokens` row.
///
/// Every failure here is a malformed row rather than a caller's fault, and every one of them
/// reports [`AuthError::StorageUnavailable`] — not `RefreshRejected`. The distinction is the point:
/// a row this build cannot decode must not be reported to the user as "your session expired", which
/// would send them to re-authenticate and hide a schema problem for as long as they kept doing it.
fn record_from_row(row: &PgRow) -> Result<RefreshRecord, AuthError> {
    let actor_type: String = row.get("actor_type");
    let actor_id: Uuid = row.get("actor_id");
    let client_type: String = row.get("client_type");

    Ok(RefreshRecord {
        id: row.get("id"),
        tenant_id: TenantId::from_uuid(row.get("tenant_id")),
        session_id: SessionId::from_uuid(row.get("session_id")),
        actor: actor_from_parts(&actor_type, actor_id)?,
        token_hash: row.get("token_hash"),
        device_id: row.get::<Option<Uuid>, _>("device_id").map(DeviceId::from_uuid),
        client: client_type.parse::<ClientType>().map_err(|_| malformed())?,
        parent_id: row.get("parent_id"),
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        absolute_expires_at: row.get("absolute_expires_at"),
        consumed_at: row.get("consumed_at"),
        revoked_at: row.get("revoked_at"),
        revoke_reason: row
            .get::<Option<String>, _>("revoke_reason")
            .as_deref()
            .and_then(revoke_reason_from_str),
    })
}

/// The `refresh_tokens.actor_type` vocabulary, which is **not** [`enclave_core::ActorKind`]'s.
///
/// The column's `CHECK` accepts `USER`, `GUEST` and `SERVICE_ACCOUNT`; `ActorKind`'s canonical
/// strings are `user`, `guest` and `service`. `FromStr` on that type is case-insensitive, so two of
/// the three would round-trip by accident and `SERVICE_ACCOUNT` would not — which is the worst
/// possible shape, because it works until the day a service account holds a refresh family.
///
/// So the mapping is written out, in both directions, and the variants the column cannot hold are a
/// refusal rather than a default. `Actor::McpClient` and `Actor::System` are exactly the two
/// `EnclaveTokenService::issues_refresh_token` declines to mint a refresh token for, so this is
/// unreachable through the service — and it is a `Result` rather than an `unreachable!` because a
/// crate that forbids panicking paths in production code does not make an exception for the ones it
/// is sure about.
fn actor_type(actor: Actor) -> Result<&'static str, AuthError> {
    match actor {
        Actor::User(_) => Ok("USER"),
        Actor::Guest(_) => Ok("GUEST"),
        Actor::ServiceAccount(_) => Ok("SERVICE_ACCOUNT"),
        Actor::McpClient(_) | Actor::System => Err(AuthError::Configuration(
            "refresh_tokens.actor_type cannot hold an MCP client or the system actor",
        )),
    }
}

/// The inverse of [`actor_type`].
fn actor_from_parts(actor_type: &str, id: Uuid) -> Result<Actor, AuthError> {
    match actor_type {
        "USER" => Ok(Actor::User(UserId::from_uuid(id))),
        "GUEST" => Ok(Actor::Guest(enclave_core::id::GuestId::from_uuid(id))),
        "SERVICE_ACCOUNT" => {
            Ok(Actor::ServiceAccount(enclave_core::id::ServiceAccountId::from_uuid(id)))
        }
        _ => Err(malformed()),
    }
}

/// The principal's raw id, for the `actor_id` column.
fn actor_id(actor: Actor) -> Uuid {
    match actor {
        Actor::User(id) => id.as_uuid(),
        Actor::Guest(id) => id.as_uuid(),
        Actor::ServiceAccount(id) => id.as_uuid(),
        Actor::McpClient(id) => id.as_uuid(),
        Actor::System => Uuid::nil(),
    }
}

/// The stored spelling of a revoke reason.
///
/// `RevokeReason` derives `Serialize` with `SCREAMING_SNAKE_CASE`, which is the spelling the column
/// wants — but going through `serde_json` to obtain a constant string would mean a fallible
/// conversion and an allocation on the revocation path. The match is exhaustive, so a new variant
/// is a compile error here rather than a row nobody can decode.
const fn revoke_reason_str(reason: RevokeReason) -> &'static str {
    match reason {
        RevokeReason::Logout => "LOGOUT",
        RevokeReason::LogoutAll => "LOGOUT_ALL",
        RevokeReason::SessionReplay => "SESSION_REPLAY",
        RevokeReason::AdminRevoke => "ADMIN_REVOKE",
        RevokeReason::PasswordChange => "PASSWORD_CHANGE",
        RevokeReason::MfaReset => "MFA_RESET",
        RevokeReason::DeviceRevoked => "DEVICE_REVOKED",
        RevokeReason::Offboarded => "OFFBOARDED",
        RevokeReason::PolicyChange => "POLICY_CHANGE",
    }
}

/// The inverse of [`revoke_reason_str`].
///
/// `None` for an unrecognised value rather than an error: a reason this build does not know is a
/// row written by a newer release, and refusing to decode the *whole* record because of an
/// annotation field would turn a rolling upgrade into an outage. The fields that decide anything —
/// `revoked_at`, `consumed_at` — are read regardless.
fn revoke_reason_from_str(stored: &str) -> Option<RevokeReason> {
    Some(match stored {
        "LOGOUT" => RevokeReason::Logout,
        "LOGOUT_ALL" => RevokeReason::LogoutAll,
        "SESSION_REPLAY" => RevokeReason::SessionReplay,
        "ADMIN_REVOKE" => RevokeReason::AdminRevoke,
        "PASSWORD_CHANGE" => RevokeReason::PasswordChange,
        "MFA_RESET" => RevokeReason::MfaReset,
        "DEVICE_REVOKED" => RevokeReason::DeviceRevoked,
        "OFFBOARDED" => RevokeReason::Offboarded,
        "POLICY_CHANGE" => RevokeReason::PolicyChange,
        _ => return None,
    })
}

/// A row that came back in a shape this build cannot read.
fn malformed() -> AuthError {
    AuthError::StorageUnavailable(StoreUnavailable::new(Dependency::Postgres))
}

/// PostgreSQL did not answer.
const fn postgres_unavailable() -> StoreUnavailable {
    StoreUnavailable::new(Dependency::Postgres)
}

/// A pool or transaction-control failure.
///
/// The [`crate::DbError`] is dropped rather than wrapped, and deliberately: it renders a connection
/// string in one of its variants, and this value ends up inside an `Error::Upstream` that an
/// operator reads out of a log. The detail is already logged where it was raised.
fn unavailable(error: crate::DbError) -> AuthError {
    tracing::error!(%error, "an authentication store could not be reached");
    AuthError::StorageUnavailable(postgres_unavailable())
}

/// A statement failed.
fn query_failed(error: sqlx::Error) -> AuthError {
    // `?error` and not the bound parameters: those are a token digest and a session id.
    tracing::error!(?error, "an authentication statement failed");
    AuthError::StorageUnavailable(postgres_unavailable())
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The mapping the column's `CHECK` constraint accepts, in both directions.
    ///
    /// Written as a round trip rather than two lists, because two lists is how the pair drifts.
    #[test]
    fn the_actor_vocabulary_round_trips_through_the_column_spelling() {
        let id = Uuid::new_v4();
        for actor in [
            Actor::User(UserId::from_uuid(id)),
            Actor::Guest(enclave_core::id::GuestId::from_uuid(id)),
            Actor::ServiceAccount(enclave_core::id::ServiceAccountId::from_uuid(id)),
        ] {
            let stored = actor_type(actor).expect("the column accepts these three");
            let decoded = actor_from_parts(stored, id).expect("what was written must read back");
            assert_eq!(decoded, actor, "{stored} did not round-trip");
        }
    }

    /// The half of the vocabulary that is *not* `ActorKind`'s, which is the whole reason the
    /// mapping is written out by hand.
    ///
    /// `ActorKind::from_str` is case-insensitive over the canonical strings, so `USER` and `GUEST`
    /// would have resolved by accident and `SERVICE_ACCOUNT` would not. The positive control is the
    /// round trip above; this is the proof that a shortcut would have been wrong.
    #[test]
    fn the_column_spelling_is_not_the_actor_kind_spelling() {
        use core::str::FromStr as _;

        assert!(
            enclave_core::ActorKind::from_str("SERVICE_ACCOUNT").is_err(),
            "if this ever parses, the hand-written mapping can be deleted — until then, deleting \
             it silently breaks service-account refresh families and nothing else"
        );
        // The positive control: the two that *would* have worked by accident.
        assert!(enclave_core::ActorKind::from_str("USER").is_ok());
    }

    /// The two actors the column cannot hold are refused rather than defaulted.
    #[test]
    fn an_actor_the_column_cannot_hold_is_refused() {
        let mcp = Actor::McpClient(enclave_core::id::McpClientId::from_uuid(Uuid::new_v4()));
        assert!(actor_type(mcp).is_err(), "MCP clients hold no refresh family");
        assert!(actor_type(Actor::System).is_err(), "the system actor holds no refresh family");
        // The positive control, so this does not pass against a function that refuses everything.
        assert!(actor_type(Actor::User(UserId::from_uuid(Uuid::new_v4()))).is_ok());
    }

    /// Every revoke reason round-trips, and the encoding matches the serde spelling the rest of the
    /// system already uses.
    #[test]
    fn every_revoke_reason_round_trips_and_matches_its_wire_form() {
        for reason in [
            RevokeReason::Logout,
            RevokeReason::LogoutAll,
            RevokeReason::SessionReplay,
            RevokeReason::AdminRevoke,
            RevokeReason::PasswordChange,
            RevokeReason::MfaReset,
            RevokeReason::DeviceRevoked,
            RevokeReason::Offboarded,
            RevokeReason::PolicyChange,
        ] {
            let stored = revoke_reason_str(reason);
            assert_eq!(revoke_reason_from_str(stored), Some(reason), "{stored}");
            // The hand-written table must agree with `RevokeReason`'s own `SCREAMING_SNAKE_CASE`
            // serde rename, because the UI and incident response read that spelling.
            let serialised = serde_json::to_string(&reason).expect("serialises");
            assert_eq!(serialised.trim_matches('"'), stored, "the two spellings have drifted");
        }
    }

    /// An unknown reason does not destroy the record it is attached to.
    #[test]
    fn an_unrecognised_revoke_reason_decodes_to_none_rather_than_failing() {
        assert_eq!(revoke_reason_from_str("REASON_FROM_A_NEWER_RELEASE"), None);
        // The positive control: a known one still decodes.
        assert_eq!(revoke_reason_from_str("LOGOUT"), Some(RevokeReason::Logout));
    }

    /// The two `RETURNING` lists and the column list [`record_from_row`] reads must be the same
    /// set.
    ///
    /// They are three literals because `sqlx::query` refuses an interpolated statement, so nothing
    /// but this test stops them diverging — and a divergence is a decode failure at run time, on
    /// the logout path, in production. Whitespace is normalised because the constants are wrapped
    /// with line continuations at different points.
    #[test]
    fn the_revocation_statements_return_exactly_the_columns_that_are_decoded() {
        fn columns(list: &str) -> Vec<String> {
            list.split(',').map(|column| column.split_whitespace().collect()).collect()
        }

        // The source of truth is the read path: whatever `SELECT_BY_HASH` projects is what
        // `record_from_row` was written against.
        let (selected, _) = SELECT_BY_HASH
            .split_once(" FROM ")
            .expect("the lookup projects a column list before its FROM");
        let expected = columns(selected.trim_start_matches("SELECT "));
        assert_eq!(expected.len(), 15, "the decoded set is the fifteen columns of the row");

        for statement in [REVOKE_FAMILY, REVOKE_FOR_SUBJECT] {
            let (_, returning) = statement
                .split_once("RETURNING ")
                .expect("a revocation statement has to return the rows it revoked");
            assert_eq!(columns(returning), expected, "{statement}");
        }

        // The positive control: the comparison is a real one, not two empty lists.
        assert!(expected.contains(&"tenant_id".to_owned()));
        assert!(expected.contains(&"session_id".to_owned()));
    }

    /// A storage failure must never be reportable as a credential rejection.
    ///
    /// This is the property the whole error mapping exists for: `is_authentication_failure` drives
    /// whether the API layer emits `401`, and a database outage rendering as `401` sends every user
    /// to the password-reset form during an incident.
    #[test]
    fn a_storage_failure_is_not_an_authentication_failure() {
        let error = malformed();
        assert!(!error.is_authentication_failure());
        assert!(error.reason_code().is_none(), "the caller did nothing wrong and must learn nothing");
        // The positive control: something that *is* the caller's fault still says so.
        assert!(AuthError::InvalidCredentials.is_authentication_failure());
    }
}
