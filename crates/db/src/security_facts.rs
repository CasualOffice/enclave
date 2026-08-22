//! Stored security facts — `ENC-594`, `docs/04-DATA-MODEL.md §12.2`.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §12` is authoritative for what the facts *mean*; this module is
//! how one is written down, read back, and how the two properties of the **resource** that travel
//! beside them (`ResourceState`) are established. `migrations/0020_security_facts.sql` holds the
//! argument for the table's shape.
//!
//! # Why this sits in `enclave-db`, and why it returns a domain type when
//! [`crate::conditional_access`] returns strings
//!
//! The crate header names two argued exceptions to "no repositories here"; this is the third, and
//! it is the conditional-access argument again: `crates/dlp` is the domain crate, and it would have
//! to reach past this one to read a table. `CLAUDE.md`'s Rust conventions forbid that in the
//! sentence that matters — all database access through [`TenantScoped`], no `sqlx::query!` in a
//! domain crate — so the statements live here.
//!
//! What differs is the return type, and the difference is not inconsistency. A conditional-access
//! rule's vocabulary belongs to `crates/conditional_access`, so this crate handles its columns as
//! opaque strings and holds no opinion about them. [`enclave_core::SecurityFacts`] is not `dlp`'s
//! type at all — it lives in `core`, which this crate already depends on, because several stages
//! read it. Returning a parallel `FactsRow` here would be a *second* spelling of a type both crates
//! can already name, in the layer directly below both of them, which is the drift the string
//! treatment exists to avoid rather than an instance of it.
//!
//! # The conversion is total, and the migration is what makes it so
//!
//! `DetectorCounts` holds `u32`; PostgreSQL's `INT` is signed. A negative row read with `as u32`
//! becomes a count near four billion — a document that appears to carry two billion card numbers
//! and fires every threshold rule the tenant has. So the counts carry `CHECK (… >= 0)` in the
//! migration and [`u32::try_from`] here, and a row that somehow escaped both is a decode **error**
//! rather than a number. The same for the severity: an unrecognised string is refused by name, not
//! silently dropped to `None`, because a fact row that quietly lost its severity is a rule about
//! `HIGH` findings that stops firing.
//!
//! # Nothing calls [`record_facts`] from a binary yet
//!
//! It is the statement a scanner will use, and the absence of that scanner is safe in both
//! configured directions — with no rows every version is *unscanned*, which `FAIL_CLOSED` refuses
//! loudly and `FAIL_OPEN_AUDIT` permits with a high-visibility event. `ENC-613` is the row for the
//! writer. The statement exists here so that the write path is defined in the same place as the
//! read path and cannot be invented differently by whoever adds it.

use enclave_core::{
    DateTime, DetectorCategory, DetectorCounts, DetectorSetVersion, FileId, ResourceKind,
    RiskScore, ScanVersion, SecurityFacts, Severity, Utc, VersionId,
};
use sqlx::Row as _;
use uuid::Uuid;

use crate::ids::{sql, RowIdExt as _};
use crate::tenant::TenantScoped;
use crate::DbError;

/// The facts for one version of one file.
///
/// Keyed on all three columns of the primary key rather than on `(tenant_id, version_id)`, which
/// would also be unique: the three-column form is the key's own prefix, so the lookup is an index
/// probe rather than a scan. The `tenant_id = $1` predicate is written even though row-level
/// security enforces the same thing — the two-layer arrangement of `docs/04 §3` that this crate
/// exists for; see `crates/db/src/lib.rs`.
const LOAD_SQL: &str = "
SELECT file_id,
       version_id,
       pii_count,
       secret_count,
       financial_count,
       health_count,
       max_severity,
       risk_score,
       classification_rank,
       scan_version,
       detector_set_version,
       scanned_at
  FROM security_facts
 WHERE tenant_id = $1
   AND file_id   = $2
   AND version_id = $3
";

/// The version a file's content actions are about.
///
/// `current_version_id` is nullable — a file whose first upload has not committed has no version,
/// and therefore no facts, which is *unscanned* rather than an error.
const CURRENT_VERSION_SQL: &str = "
SELECT current_version_id
  FROM files
 WHERE tenant_id = $1
   AND id        = $2
";

/// Which file a version belongs to, for an action that names the version directly.
const VERSION_OWNER_SQL: &str = "
SELECT file_id
  FROM file_versions
 WHERE tenant_id = $1
   AND id        = $2
";

/// Whether anything already reaches outside the tenant over this file.
///
/// `docs/06 §12.1`: the mandatory `FAIL_CLOSED` escalation for external sharing is two questions,
/// and the second — *is this share already external* — is a property of the resource. This is that
/// question.
///
/// Three things about the shape, each of which is the safe direction rather than the convenient
/// one:
///
///   * **The walk is ancestral.** A link on the containing folder or library exposes the file just
///     as a link on the file does, so the recursive term walks `parent_id` to the library root and
///     the `LIBRARY` case is checked against the library every ancestor names. Asking only about
///     the file itself would under-report exposure, and under-reporting is what makes the
///     escalation quietly not fire.
///   * **Everything but `INTERNAL` counts as external.** `SPECIFIC` names recipients who may well
///     be outside the tenant, and this predicate cannot tell. Over-reporting exposure makes an
///     unscanned share *harder* to change; under-reporting makes it easier. Only one of those two
///     mistakes is worth making.
///   * **Expiry and revocation are honoured.** A revoked or expired link reaches nobody, and
///     treating it as live would make the escalation permanent for any resource ever shared.
const EXPOSURE_SQL: &str = "
WITH RECURSIVE ancestry AS (
    SELECT f.id, f.parent_id, f.library_id
      FROM files f
     WHERE f.tenant_id = $1
       AND f.id        = $2
    UNION ALL
    SELECT p.id, p.parent_id, p.library_id
      FROM files p
      JOIN ancestry a ON a.parent_id = p.id
     WHERE p.tenant_id = $1
)
SELECT EXISTS (
    SELECT 1
      FROM share_links s
     WHERE s.tenant_id  = $1
       AND s.revoked_at IS NULL
       AND (s.expires_at IS NULL OR s.expires_at > now())
       AND s.audience <> 'INTERNAL'
       AND (
             (s.resource_type IN ('FILE','FOLDER')
              AND s.resource_id IN (SELECT id FROM ancestry))
          OR (s.resource_type = 'LIBRARY'
              AND s.resource_id IN (SELECT library_id FROM ancestry))
           )
) AS exposed
";

/// The upsert a completed scan performs.
///
/// `ON CONFLICT … DO UPDATE` rather than delete-then-insert, and that is not a style preference:
/// `enclave_app` holds no `DELETE` on this table (`migrations/0020`), so replacement *is* the
/// update. A rescan that could delete first would have a window in which the version is unscanned,
/// which under `FAIL_CLOSED` refuses live traffic for the duration of a maintenance job.
const RECORD_SQL: &str = "
INSERT INTO security_facts
    (tenant_id, file_id, version_id, pii_count, secret_count, financial_count, health_count,
     max_severity, risk_score, classification_rank, scan_version, detector_set_version, scanned_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (tenant_id, file_id, version_id) DO UPDATE
   SET pii_count            = EXCLUDED.pii_count,
       secret_count         = EXCLUDED.secret_count,
       financial_count      = EXCLUDED.financial_count,
       health_count         = EXCLUDED.health_count,
       max_severity         = EXCLUDED.max_severity,
       risk_score           = EXCLUDED.risk_score,
       classification_rank  = EXCLUDED.classification_rank,
       scan_version         = EXCLUDED.scan_version,
       detector_set_version = EXCLUDED.detector_set_version,
       scanned_at           = EXCLUDED.scanned_at
";

/// Reads the facts a completed scan left for one version.
///
/// `Ok(None)` means **unscanned**: no scan has run, or one is still running. It is not an error and
/// must not be turned into one — what an absence *means* is the tenant's `facts_unavailable` policy
/// to decide (`docs/06 §12`), and this module has no opinion about it.
///
/// A read failure is the opposite case and is propagated: returning `None` on a database error
/// would convert an outage into a policy answer, and under `FAIL_OPEN_AUDIT` that answer is allow.
///
/// # Errors
///
/// Query failures, and a row this crate cannot decode — a negative count or an unrecognised
/// severity. Both are refused rather than repaired; see the module header.
pub async fn load_facts(
    tx: &mut TenantScoped,
    file: FileId,
    version: VersionId,
) -> Result<Option<SecurityFacts>, DbError> {
    let tenant = tx.tenant_id();
    let row = sqlx::query(LOAD_SQL)
        .bind(sql(tenant))
        .bind(sql(file))
        .bind(sql(version))
        .fetch_optional(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let mut counts = DetectorCounts::none();
    for (column, category) in [
        ("pii_count", DetectorCategory::Pii),
        ("secret_count", DetectorCategory::Secret),
        ("financial_count", DetectorCategory::Financial),
        ("health_count", DetectorCategory::Health),
    ] {
        let stored: i32 = row.try_get(column).map_err(DbError::Query)?;
        let count = u32::try_from(stored).map_err(|_| decode_error(column, &stored.to_string()))?;
        counts.add(category, count);
    }

    let set: String = row.try_get("detector_set_version").map_err(DbError::Query)?;
    let scan_version: i32 = row.try_get("scan_version").map_err(DbError::Query)?;
    let scanned_at: DateTime<Utc> = row.try_get("scanned_at").map_err(DbError::Query)?;

    let mut facts = SecurityFacts::scanned(
        row.try_get_id("file_id").map_err(DbError::Query)?,
        row.try_get_id("version_id").map_err(DbError::Query)?,
        counts,
        DetectorSetVersion::new(set),
        ScanVersion::new(scan_version),
        scanned_at,
    );

    if let Some(severity) =
        row.try_get::<Option<String>, _>("max_severity").map_err(DbError::Query)?
    {
        let parsed: Severity =
            severity.parse().map_err(|_| decode_error("max_severity", &severity))?;
        facts = facts.with_max_severity(parsed);
    }

    if let Some(rank) =
        row.try_get::<Option<i32>, _>("classification_rank").map_err(DbError::Query)?
    {
        facts = facts.with_classification(enclave_core::ClassificationRank::new(rank));
    }

    let risk: i32 = row.try_get("risk_score").map_err(DbError::Query)?;
    // The migration bounds this to `0..=100`, so the conversion cannot fail on a row this schema
    // accepted. `RiskScore::new` clamps rather than rejecting for the same reason the column has a
    // `CHECK` rather than a trigger: an out-of-range score is a scorer defect, and discarding exact
    // counts to punish an inexact estimate would be the wrong trade.
    facts = facts.with_risk_score(RiskScore::new(u8::try_from(risk).unwrap_or(u8::MAX)));

    Ok(Some(facts))
}

/// Resolves the version whose facts describe this resource.
///
/// A file's content actions are about its *current* version, and a version reference is about
/// itself. `Ok(None)` covers three cases that are one case for this purpose — the resource is not
/// content, it does not exist in this tenant, or it has no committed version — and every one of
/// them means the same thing to the chain: there are no facts.
///
/// Note what makes the second case safe: the statements carry `tenant_id = $1` *and* run under
/// row-level security, so another tenant's file is not found here rather than resolved and then
/// filtered later.
///
/// # Errors
///
/// Query failures.
pub async fn resolve_content(
    tx: &mut TenantScoped,
    kind: ResourceKind,
    id: Uuid,
) -> Result<Option<(FileId, VersionId)>, DbError> {
    let tenant = tx.tenant_id();
    match kind {
        ResourceKind::File | ResourceKind::Folder => {
            let file = FileId::from_uuid(id);
            let row = sqlx::query(CURRENT_VERSION_SQL)
                .bind(sql(tenant))
                .bind(sql(file))
                .fetch_optional(&mut **tx)
                .await
                .map_err(DbError::Query)?;
            let Some(row) = row else { return Ok(None) };
            let version: Option<VersionId> =
                row.try_get_opt_id("current_version_id").map_err(DbError::Query)?;
            Ok(version.map(|version| (file, version)))
        }
        ResourceKind::Version => {
            let version = VersionId::from_uuid(id);
            let row = sqlx::query(VERSION_OWNER_SQL)
                .bind(sql(tenant))
                .bind(sql(version))
                .fetch_optional(&mut **tx)
                .await
                .map_err(DbError::Query)?;
            let Some(row) = row else { return Ok(None) };
            let file: FileId = row.try_get_id("file_id").map_err(DbError::Query)?;
            Ok(Some((file, version)))
        }
        // Everything else has no content to have facts about. Deliberately exhaustive rather than
        // a wildcard: a resource kind that gains content must be considered here, and a wildcard
        // would silently report it unscanned forever.
        ResourceKind::Tenant
        | ResourceKind::Workspace
        | ResourceKind::Library
        | ResourceKind::Chunk
        | ResourceKind::List
        | ResourceKind::ListItem
        | ResourceKind::Page
        | ResourceKind::Share
        | ResourceKind::User
        | ResourceKind::Group
        | ResourceKind::Device => Ok(None),
    }
}

/// Whether a live external share already reaches this file, or any container above it.
///
/// See [`EXPOSURE_SQL`] for what "external" means here and why the answer errs towards *yes*.
///
/// # Errors
///
/// Query failures. A failure is not `false`: `false` is the permissive answer, and returning it on
/// a database blip would disable the escalation exactly when nobody is watching.
pub async fn external_exposure(tx: &mut TenantScoped, file: FileId) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let row = sqlx::query(EXPOSURE_SQL)
        .bind(sql(tenant))
        .bind(sql(file))
        .fetch_one(&mut **tx)
        .await
        .map_err(DbError::Query)?;
    row.try_get("exposed").map_err(DbError::Query)
}

/// Writes the outcome of a completed scan, replacing any earlier row for the same version.
///
/// The counts are `u32` and the columns are `INT`; a count above `i32::MAX` is stored saturated
/// rather than refused, because the alternative is a scan result nobody can write down. Every
/// threshold a rule can express was crossed two billion findings earlier.
///
/// # Errors
///
/// Query failures, including the foreign keys — facts naming a version that does not exist in this
/// tenant are refused by PostgreSQL rather than stored where a decision would later read them.
pub async fn record_facts(tx: &mut TenantScoped, facts: &SecurityFacts) -> Result<(), DbError> {
    let tenant = tx.tenant_id();
    let counts = facts.counts();
    sqlx::query(RECORD_SQL)
        .bind(sql(tenant))
        .bind(sql(facts.file_id()))
        .bind(sql(facts.version_id()))
        .bind(stored_count(counts.get(DetectorCategory::Pii)))
        .bind(stored_count(counts.get(DetectorCategory::Secret)))
        .bind(stored_count(counts.get(DetectorCategory::Financial)))
        .bind(stored_count(counts.get(DetectorCategory::Health)))
        .bind(facts.max_severity().map(|severity| severity.as_str()))
        .bind(i32::from(facts.risk_score().get()))
        .bind(facts.classification().map(|rank| rank.get()))
        .bind(facts.scan_version().get())
        .bind(facts.detector_set().as_str())
        .bind(facts.scanned_at())
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// A `u32` count as the `INT` column can hold it.
fn stored_count(count: u32) -> i32 {
    i32::try_from(count).unwrap_or(i32::MAX)
}

/// A row this crate refuses to interpret, as the driver's own decode failure.
///
/// The column and the value are named because both are needed to fix it, and neither is content:
/// every column here is a count, a rank, a score or a version (`CLAUDE.md` rule 10, and the
/// migration's header for why the table has no column a match value could occupy).
fn decode_error(column: &'static str, value: &str) -> DbError {
    DbError::Query(sqlx::Error::Decode(
        format!(
            "security_facts.{column} holds `{value}`, which is not a value this schema defines"
        )
        .into(),
    ))
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Layer 1, asserted where it is written. Deleting a `tenant_id` predicate leaves row-level
    /// security holding the property alone — which is `docs/12 §4.1` `T5`'s designed property, and
    /// therefore something the behavioural test cannot catch. This is where it is caught.
    #[test]
    fn every_statement_is_scoped_to_one_tenant() {
        for statement in [LOAD_SQL, CURRENT_VERSION_SQL, VERSION_OWNER_SQL, EXPOSURE_SQL] {
            assert!(
                statement.contains("tenant_id = $1") || statement.contains("tenant_id  = $1"),
                "a statement reaching security facts without a tenant predicate: {statement}"
            );
        }
        // The write has no `WHERE`, so the same property takes a different form: the tenant is the
        // first column and the first bound parameter, which is what the `WITH CHECK` half of the
        // isolation policy then holds the row to.
        assert!(RECORD_SQL.contains("(tenant_id, file_id, version_id"));
        assert!(RECORD_SQL.contains("VALUES ($1,"));
    }

    /// The exposure walk is what makes `docs/06 §12.1`'s second escalation fire on a share hanging
    /// above the file rather than on it. Each clause is one line in one string, and the failure
    /// mode of deleting one is silent: fewer resources report as exposed, so an unscanned external
    /// share becomes editable and nothing errors.
    #[test]
    fn the_exposure_predicate_walks_upwards_and_ignores_dead_links() {
        assert!(EXPOSURE_SQL.contains("RECURSIVE"), "a link on a parent folder exposes the file");
        assert!(EXPOSURE_SQL.contains("LIBRARY"), "a library-wide link exposes the file");
        assert!(EXPOSURE_SQL.contains("revoked_at IS NULL"), "a revoked link reaches nobody");
        assert!(EXPOSURE_SQL.contains("expires_at IS NULL OR"), "an expired link reaches nobody");
        assert!(
            EXPOSURE_SQL.contains("audience <> 'INTERNAL'"),
            "everything but INTERNAL counts as external; over-reporting is the safe direction"
        );
    }

    /// A rescan replaces. `enclave_app` holds no `DELETE` on this table (`migrations/0020`), so a
    /// statement spelling one fails at runtime in whichever deployment ran it first rather than at
    /// compile time here.
    ///
    /// The needle is assembled rather than written, because a source-scanning assertion whose
    /// needle appears in its own file passes against itself — `docs/12 §1.2` records two tests in
    /// this repository that did exactly that.
    #[test]
    fn no_statement_here_deletes_a_fact_row() {
        let needle = format!("{} FROM security_facts", "DELETE");
        for statement in [LOAD_SQL, EXPOSURE_SQL, RECORD_SQL] {
            assert!(!statement.contains(&needle), "facts are replaced, never deleted");
        }
        // The positive control: the needle *would* be found if it were there.
        assert!(format!("{needle} WHERE 1=0").contains(&needle));
        // And the replacement it is the absence of.
        assert!(RECORD_SQL.contains("ON CONFLICT"), "a rescan must replace rather than fail");
    }

    /// A count above `i32::MAX` saturates rather than wrapping into a negative, which the column's
    /// `CHECK` would reject and which — if it ever reached a row — would read back as a decode
    /// error rather than as a small number.
    #[test]
    fn an_absurd_count_saturates_rather_than_wrapping_negative() {
        assert_eq!(stored_count(0), 0);
        assert_eq!(stored_count(7), 7);
        assert_eq!(stored_count(u32::MAX), i32::MAX);
        // The control: the conversion this avoids produces `-1`, which the column's `CHECK`
        // refuses — so the saturation above is doing something, rather than the two agreeing.
        assert_eq!(u32::MAX.cast_signed(), -1);
    }
}
