//! The SQL behind the rendition cache, and the witness that keeps rendering off unscanned content.
//!
//! # Shape
//!
//! Per `plans/M1-CONTENT-CORE.md` D10 every function here takes a `&mut PgConnection` — never a
//! pool — so it physically cannot run outside the caller's `TenantScoped` transaction. Every
//! statement also carries an explicit `tenant_id = $1` predicate: layer 1 of
//! `docs/04-DATA-MODEL.md §3`, and the pair is what makes a leak require two independent failures.
//!
//! # Why [`ReadableVersion`] exists
//!
//! `CLAUDE.md` rule 9: nothing is `AVAILABLE` before antivirus completes, and no read path serves
//! `SCANNING` content. Rendering is a read path — the most dangerous one in the product, because it
//! is the one that hands the bytes to a parser. A quarantined version must never be rendered, and
//! "remember to check the status first" is not a mechanism.
//!
//! So [`ReadableVersion`] has private fields and exactly one constructor: [`readable_version`],
//! whose query splices [`READABLE_PREDICATE`] into its `WHERE` clause. The
//! rendering service takes one by value. A caller who wants to render something unscanned cannot
//! express the request — not because the check is thorough, but because the type that authorises it
//! can only come from a row that passed the filter. This is `plans/M1-CONTENT-CORE.md` D13 ("no read
//! path takes a boolean parameter that could be passed wrongly") taken one step further: no read
//! path takes a *version identifier* that could be passed wrongly either.

use chrono::{DateTime, Utc};
use enclave_core::{FileId, TenantId, VersionId};
use sqlx::{PgConnection, Row};

use crate::error::{PreviewError, Result};
use crate::model::{GeneratorVersion, Rendition, RenditionKey, RenditionProfile};

/// Proof that a version exists, belongs to this tenant, and may be read.
///
/// Cannot be constructed outside this module. See the module documentation for why that is the
/// whole point.
#[derive(Debug, Clone)]
pub struct ReadableVersion {
    version: VersionId,
    file: FileId,
    object_key: String,
    media_type: String,
    size_bytes: i64,
}

impl ReadableVersion {
    /// Which version this is.
    #[must_use]
    pub const fn id(&self) -> VersionId {
        self.version
    }

    /// The file it belongs to.
    #[must_use]
    pub const fn file(&self) -> FileId {
        self.file
    }

    /// Where its bytes live.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    /// The media type the row declares.
    ///
    /// A hint for the renderer, never a trust boundary — see [`crate::render::RenderRequest`].
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// How large the source is, so the input cap can be applied before the bytes are fetched.
    #[must_use]
    pub const fn size_bytes(&self) -> i64 {
        self.size_bytes
    }
}

/// Reads a column, turning a decode failure into a message that names the column and nothing else.
fn column<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    name: &'static str,
) -> Result<T> {
    row.try_get(name).map_err(|_| PreviewError::MalformedRow {
        column: name,
        reason: "missing or of an unexpected type",
    })
}

/// The only way to obtain a [`ReadableVersion`].
///
/// Returns `None` for a version that does not exist, belongs to another tenant, is still scanning,
/// or was quarantined. One answer for all four, deliberately: distinguishing them would tell an
/// uploader whether their malware landed (`CLAUDE.md` rule 7).
///
/// It returns `Some` for a version that is `AVAILABLE`/`SKIPPED` — published under `ALLOW_WITH_FLAG`
/// with nothing having inspected it. That is a decision the tenant wrote down and `status` records;
/// see [`READABLE_PREDICATE`] (`ENC-828`).
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn readable_version(
    conn: &mut PgConnection,
    tenant: TenantId,
    version: VersionId,
) -> Result<Option<ReadableVersion>> {
    let row = sqlx::query(READABLE_VERSION_SQL)
        .bind(tenant.as_uuid())
        .bind(version.as_uuid())
        .fetch_optional(&mut *conn)
        .await?;

    let Some(row) = row else { return Ok(None) };

    Ok(Some(ReadableVersion {
        version,
        file: FileId::from(column::<uuid::Uuid>(&row, "file_id")?),
        object_key: column(&row, "object_key")?,
        media_type: column(&row, "mime_type")?,
        size_bytes: column(&row, "size_bytes")?,
    }))
}

/// Looks a base rendition up.
///
/// A row written by a *different* generator is a miss, not a hit: the predicate carries
/// `generator_version = $4`, so an upgraded pipeline regenerates without anyone having to purge a
/// cache, and an artefact from a build since found to mis-sanitize is never served again.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn find(
    conn: &mut PgConnection,
    tenant: TenantId,
    key: RenditionKey,
) -> Result<Option<Rendition>> {
    let row = sqlx::query(FIND_SQL)
        .bind(tenant.as_uuid())
        .bind(key.version.as_uuid())
        .bind(key.profile.as_str())
        .bind(key.generator.as_str())
        .fetch_optional(&mut *conn)
        .await?;

    row.as_ref().map(rendition_from_row).transpose()
}

/// Records a freshly generated base rendition.
///
/// Upserts on the primary key. The conflict is ordinary rather than exceptional: two requests for a
/// preview nobody has viewed yet race constantly, both render, and both try to record the result.
/// Whichever lands second overwrites — the artefacts are equivalent, since the key already fixes the
/// version, the profile and the generator.
///
/// # Errors
///
/// Storage failures.
pub async fn record(
    conn: &mut PgConnection,
    tenant: TenantId,
    key: RenditionKey,
    object_key: &str,
    size_bytes: i64,
    page_count: Option<i32>,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(RECORD_SQL)
        .bind(tenant.as_uuid())
        .bind(key.version.as_uuid())
        .bind(key.profile.as_str())
        .bind(object_key)
        .bind(size_bytes)
        .bind(page_count)
        .bind(key.generator.as_str())
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Marks a rendition as served, for LRU eviction.
///
/// Separate from [`find`] rather than folded into it as an `UPDATE ... RETURNING`, because the read
/// path must not take a row lock: two viewers opening the same document would then serialise behind
/// each other for no benefit beyond a slightly fresher eviction timestamp.
///
/// # Errors
///
/// Storage failures.
pub async fn touch(
    conn: &mut PgConnection,
    tenant: TenantId,
    key: RenditionKey,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(TOUCH_SQL)
        .bind(tenant.as_uuid())
        .bind(key.version.as_uuid())
        .bind(key.profile.as_str())
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

fn rendition_from_row(row: &sqlx::postgres::PgRow) -> Result<Rendition> {
    let raw_profile: String = column(row, "profile")?;
    let profile =
        raw_profile.parse::<RenditionProfile>().map_err(|_| PreviewError::MalformedRow {
            column: "profile",
            reason: "not a profile this pipeline knows",
        })?;

    Ok(Rendition {
        version_id: VersionId::from(column::<uuid::Uuid>(row, "version_id")?),
        profile,
        object_key: column(row, "object_key")?,
        size_bytes: column(row, "size_bytes")?,
        page_count: column(row, "page_count")?,
        generator_version: column(row, "generator_version")?,
        created_at: column(row, "created_at")?,
        last_access_at: column(row, "last_access_at")?,
    })
}

/// The `status`/`av_status` pair, in the *same words* `enclave_versions` uses.
///
/// # Why this constant exists rather than the text being inlined below
///
/// It is the workspace's second spelling of one rule, and until `ENC-828` nothing held the two
/// together: `enclave_versions::READABLE_PREDICATE` gates `POST /files/{id}/download` and renders
/// `isReadable`, this gates preview, thumbnail, export, indexing and the DLP content scan, and the
/// two were separate hand-written strings. They drifted the moment one was edited — the very first
/// build of `ENC-828`'s fix answered `isReadable: true` and `404` from the preview route in the
/// same breath, which is `ENC-825`'s defect returning through the back door.
///
/// `crates/preview` cannot *import* the definition: `enclave-versions` depends on
/// `enclave-indexing`, which depends on this crate, so the edge would be a cycle. What holds them
/// together instead is a test in a crate that sees both —
/// `crates/worker/src/antivirus.rs::the_two_crates_that_gate_reads_spell_one_predicate` — which is
/// why the text here is byte-identical rather than merely equivalent, and why the query below reads
/// `file_versions` unaliased.
///
/// # What the pair means
///
/// `docs/03-LLD.md §15` and `plans/M1-CONTENT-CORE.md` D13: `AVAILABLE` alone is not enough,
/// because `av_status` distinguishes "scanned clean" from "the scan itself failed" and from "not
/// scanned yet". `SKIPPED` — *deliberately* not scanned, under `docs/06 §6.2`'s `ALLOW_WITH_FLAG` —
/// is admitted because `status` already carries that decision; `PENDING` and `ERROR` are not,
/// because neither is a decision to publish. See `enclave_versions::READABLE_PREDICATE`'s
/// documentation for the whole argument.
pub const READABLE_PREDICATE: &str = "status = 'AVAILABLE' AND av_status IN ('CLEAN', 'SKIPPED')";

const READABLE_VERSION_SQL: &str = concat!(
    "
SELECT file_id, object_key, mime_type, size_bytes
  FROM file_versions
 WHERE tenant_id = $1
   AND id = $2
   AND ",
    "status = 'AVAILABLE' AND av_status IN ('CLEAN', 'SKIPPED')"
);

const FIND_SQL: &str = "
SELECT r.version_id, r.profile, r.object_key, r.size_bytes, r.page_count,
       r.generator_version, r.created_at, r.last_access_at
  FROM renditions r
 WHERE r.tenant_id = $1 AND r.version_id = $2 AND r.profile = $3
   AND r.generator_version = $4
";

const RECORD_SQL: &str = "
INSERT INTO renditions
    (tenant_id, version_id, profile, object_key, size_bytes, page_count, generator_version,
     created_at, last_access_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)
    ON CONFLICT (tenant_id, version_id, profile)
    DO UPDATE SET object_key        = EXCLUDED.object_key,
                  size_bytes        = EXCLUDED.size_bytes,
                  page_count        = EXCLUDED.page_count,
                  generator_version = EXCLUDED.generator_version,
                  created_at        = EXCLUDED.created_at,
                  last_access_at    = NULL
";

const TOUCH_SQL: &str = "
UPDATE renditions
   SET last_access_at = $4
 WHERE tenant_id = $1 AND version_id = $2 AND profile = $3
";

/// Never called; keeps [`GeneratorVersion`] named in this module's signatures for rustdoc.
const _: fn(GeneratorVersion) = |_| ();

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The one constructor's query carries the one predicate — asserted on the text, because the
    /// behavioural assertion (`crates/preview/tests/cache.rs`) needs a database and this does not.
    ///
    /// `concat!` takes only literals, so the predicate appears twice in this file. This is what
    /// makes the second copy safe: an edit to either that does not touch the other fails here.
    #[test]
    fn the_only_constructor_filters_on_the_readable_predicate() {
        assert!(
            READABLE_VERSION_SQL.contains(READABLE_PREDICATE),
            "the ReadableVersion query no longer carries the readable predicate; a quarantined or \
             still-scanning version could be handed to a parser.\n{READABLE_VERSION_SQL}"
        );
        assert!(READABLE_VERSION_SQL.contains("tenant_id = $1"), "layer 1 is missing");
    }

    /// Rule 9's two clauses, on the predicate's own text.
    ///
    /// The cross-crate half — that this text is `enclave_versions::READABLE_PREDICATE` and not
    /// merely something like it — is `crates/worker/src/antivirus.rs`, which can see both crates
    /// where this one cannot (`enclave-versions` → `enclave-indexing` → `enclave-preview`).
    #[test]
    fn the_predicate_admits_only_published_content_with_a_settled_verdict() {
        assert!(READABLE_PREDICATE.contains("'AVAILABLE'"));
        assert!(READABLE_PREDICATE.contains("'CLEAN'"));
        // `ALLOW_WITH_FLAG`: published, unscanned, and the tenant said so (`ENC-828`).
        assert!(READABLE_PREDICATE.contains("'SKIPPED'"));
        for refused in ["'PENDING'", "'ERROR'", "'INFECTED'", "'SCANNING'", "'QUARANTINED'"] {
            assert!(
                !READABLE_PREDICATE.contains(refused),
                "{refused} reached the predicate that gates every rendition"
            );
        }
    }
}
