//! The SQL behind share links.
//!
//! Per `plans/M1-CONTENT-CORE.md` D10 every function takes a `&mut PgConnection` — never a pool —
//! so it cannot run outside the caller's transaction.
//!
//! # The one query that is not tenant-scoped, and why that is safe
//!
//! [`find_by_digest`] has no `tenant_id` predicate, because redemption arrives with a token and
//! nothing else: there is no session, and establishing which tenant the link belongs to is what
//! redeeming it *does*. `uq_share_token` is global for the same reason.
//!
//! That makes it the one place in this crate where the two-layer isolation of
//! `docs/04-DATA-MODEL.md §3` has only one layer, so it is worth being precise about what still
//! holds. The lookup is by SHA-256 of 256 bits of CSPRNG output: to reach another tenant's row a
//! caller must present that tenant's token, which means they already hold the credential the row
//! exists to check. Nothing is enumerable — there is no listing, no prefix match and no partial
//! comparison — and the row it returns carries the `tenant_id` that every subsequent statement is
//! scoped by. The alternative, taking a tenant from the request, is `CLAUDE.md` rule 3's explicit
//! prohibition: never trust the client for tenant identity.
//!
//! The `no-raw-pool` gate and RLS still apply to everything else here.

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UserId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::error::{Result, SharingError};
use crate::model::{ShareAudience, ShareLink, SharePermission, ShareResourceKind};
use crate::token::ShareTokenDigest;

/// What a caller must supply to create a link.
///
/// No token and no password: [`create`] mints the first and takes the second already hashed, so a
/// plaintext credential never enters this struct and therefore never enters a log line that
/// happened to `Debug` it.
#[derive(Debug, Clone)]
pub struct NewShareLink {
    /// What kind of thing the link points at.
    pub resource_type: ShareResourceKind,
    /// Which one.
    pub resource_id: Uuid,
    /// What the holder may do.
    pub permission: SharePermission,
    /// Whether original bytes may leave.
    pub allow_download: bool,
    /// Who may redeem it.
    pub audience: ShareAudience,
    /// Argon2id hash of the link password, if one is set. Never the password.
    pub password_hash: Option<String>,
    /// Whether a one-time code is required per redemption.
    pub require_otp: bool,
    /// Whether the redeemer must have completed MFA.
    pub require_mfa: bool,
    /// When it stops working.
    pub expires_at: Option<DateTime<Utc>>,
    /// How many downloads it permits.
    pub max_downloads: Option<i64>,
    /// Which email domains may redeem it.
    pub allowed_domains: Option<Vec<String>>,
    /// Who is creating it.
    pub created_by: UserId,
}

/// Reads a column, naming it and nothing else on failure.
fn column<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    name: &'static str,
) -> Result<T> {
    row.try_get(name).map_err(|_| SharingError::MalformedRow {
        column: name,
        reason: "missing or of an unexpected type",
    })
}

/// Stores a link and returns it.
///
/// The token digest is supplied by the caller, who holds the only copy of the plaintext and is
/// responsible for handing it over exactly once.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn create(
    conn: &mut PgConnection,
    tenant: TenantId,
    digest: ShareTokenDigest,
    new: &NewShareLink,
    now: DateTime<Utc>,
) -> Result<ShareLink> {
    let domains =
        new.allowed_domains.as_ref().map(serde_json::to_value).transpose().map_err(|_| {
            SharingError::MalformedRow {
                column: "allowed_domains",
                reason: "not representable as json",
            }
        })?;

    let row = sqlx::query(CREATE_SQL)
        .bind(Uuid::now_v7())
        .bind(tenant.as_uuid())
        .bind(new.resource_type.as_str())
        .bind(new.resource_id)
        .bind(digest.to_hex())
        .bind(new.permission.as_str())
        .bind(new.allow_download)
        .bind(new.audience.as_str())
        .bind(new.password_hash.as_deref())
        .bind(new.require_otp)
        .bind(new.require_mfa)
        .bind(new.expires_at)
        .bind(new.max_downloads)
        .bind(domains)
        .bind(new.created_by.as_uuid())
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;

    link_from_row(&row)
}

/// Resolves a token digest to a link, across every tenant.
///
/// See the module documentation for why this one query carries no `tenant_id`.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn find_by_digest(
    conn: &mut PgConnection,
    digest: ShareTokenDigest,
) -> Result<Option<ShareLink>> {
    let row =
        sqlx::query(FIND_BY_DIGEST_SQL).bind(digest.to_hex()).fetch_optional(&mut *conn).await?;
    row.as_ref().map(link_from_row).transpose()
}

/// Revokes a link.
///
/// Returns whether a live link was revoked. Revoking an already-revoked link is `false` rather than
/// an error: it is idempotent from the caller's point of view, and the first revocation's timestamp
/// is the one that matters for the audit trail.
///
/// # Errors
///
/// Storage failures.
pub async fn revoke(
    conn: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<bool> {
    let affected = sqlx::query(REVOKE_SQL)
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(now)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(affected > 0)
}

fn link_from_row(row: &sqlx::postgres::PgRow) -> Result<ShareLink> {
    fn parse<T: core::str::FromStr>(raw: &str, column: &'static str) -> Result<T> {
        raw.parse().map_err(|_| SharingError::MalformedRow {
            column,
            reason: "not a value this crate knows",
        })
    }

    let resource_type: String = column(row, "resource_type")?;
    let permission: String = column(row, "permission")?;
    let audience: String = column(row, "audience")?;
    let password_hash: Option<String> = column(row, "password_hash")?;
    let domains: Option<serde_json::Value> = column(row, "allowed_domains")?;

    Ok(ShareLink {
        id: column(row, "id")?,
        tenant_id: TenantId::from(column::<Uuid>(row, "tenant_id")?),
        resource_type: parse(&resource_type, "resource_type")?,
        resource_id: column(row, "resource_id")?,
        permission: parse(&permission, "permission")?,
        allow_download: column(row, "allow_download")?,
        audience: parse(&audience, "audience")?,
        // The hash itself is dropped here rather than carried. A struct holding it would eventually
        // be `Debug`-printed into a log, and an Argon2 hash in a log is an offline attack anybody
        // with log access can run at their leisure.
        has_password: password_hash.is_some(),
        require_otp: column(row, "require_otp")?,
        require_mfa: column(row, "require_mfa")?,
        expires_at: column(row, "expires_at")?,
        max_downloads: column(row, "max_downloads")?,
        download_count: column(row, "download_count")?,
        allowed_domains: domains.map(serde_json::from_value::<Vec<String>>).transpose().map_err(
            |_| SharingError::MalformedRow {
                column: "allowed_domains",
                reason: "not an array of strings",
            },
        )?,
        created_by: UserId::from(column::<Uuid>(row, "created_by")?),
        created_at: column(row, "created_at")?,
        revoked_at: column(row, "revoked_at")?,
    })
}

/// The columns every read returns, in one place so a `SELECT` and a `RETURNING` cannot drift.
///
/// A macro rather than a `const` because `concat!` only concatenates literals, and the alternative
/// — writing the list out twice — is the drift this exists to prevent.
macro_rules! columns {
    () => {
        "id, tenant_id, resource_type, resource_id, permission, allow_download, \
         audience, password_hash, require_otp, require_mfa, expires_at, max_downloads, \
         download_count, allowed_domains, created_by, created_at, revoked_at"
    };
}

/// `token_hash` is written and never selected back. Nothing in the product reads a stored digest —
/// the lookup compares against one the caller computed — so returning it would only create
/// opportunities to log it.
const CREATE_SQL: &str = concat!(
    "INSERT INTO share_links
        (id, tenant_id, resource_type, resource_id, token_hash, permission, allow_download,
         audience, password_hash, require_otp, require_mfa, expires_at, max_downloads,
         allowed_domains, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
     RETURNING ",
    columns!()
);

const FIND_BY_DIGEST_SQL: &str =
    concat!("SELECT ", columns!(), " FROM share_links WHERE token_hash = $1");

const REVOKE_SQL: &str = "
UPDATE share_links
   SET revoked_at = $3
 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
";
