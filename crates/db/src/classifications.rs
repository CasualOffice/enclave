//! A resource's **effective** classification — `ENC-574`, closing `ENC-614`.
//!
//! `migrations/0022_classifications.sql` holds the argument for the table's shape and
//! `docs/04-DATA-MODEL.md §12.4` records how it differs from §12's model. This module is the walk
//! that turns a tree of nullable `classification_id` columns into the one number policy compares,
//! plus the two statements that put a label into the tree in the first place.
//!
//! # Why this sits in `enclave-db`
//!
//! The crate header names three argued exceptions to "no repositories here"; this is the fourth,
//! and it takes [`crate::security_facts`]' argument unchanged. `crates/classification` is the domain
//! crate, and it would have to reach past this one to read a table — which `CLAUDE.md`'s Rust
//! conventions forbid in the sentence that matters: all database access through
//! [`TenantScoped`], no `sqlx::query!` in a domain crate. So the statements live here and return
//! `enclave_core` types, which both this crate and every consumer can already name.
//!
//! # What "effective" means, and why it is a maximum
//!
//! The effective classification of a file is the **highest rank** carried by anything on its chain:
//! its own label, every folder above it, its library's default and its workspace's default.
//!
//! Maximum rather than nearest-wins, and the difference is a privilege question rather than a
//! preference. Nearest-wins means a `PUBLIC` folder created inside a `RESTRICTED` folder
//! declassifies everything filed under it — through an ordinary, supported operation, silently, in
//! the direction that leaks. That is `ENC-141`'s failure with the flag replaced by a label, and it
//! is the reason a rank on the chain is treated as a **floor** on sensitivity that nothing below can
//! lower. Lowering is then an explicit act on the ancestor that carries the rank, which is where an
//! administrator would look for it.
//!
//! The cost is stated rather than hidden: a tenant cannot file a genuinely public document inside a
//! restricted folder and have it read as public. Moving it out is the remedy, and it is a remedy
//! that is visible in the tree.
//!
//! # The walk is **not** the ACL walk, and that is deliberate (`ENC-141`)
//!
//! `enclave_authorization::repo::file_chains` already walks `files.parent_id` to the library root,
//! and `ENC-141` is this project's cautionary tale about a second walk drifting from the first. It
//! is not reused here, because the two walks answer questions with different stopping rules:
//!
//! * The ACL walk **stops at the first node whose `inherit_permissions` is `FALSE`**. That is
//!   correct for permissions, because breaking inheritance materialises the effective entries onto
//!   the node — the ancestors above it are redundant by construction rather than ignored
//!   (`docs/04 §9`).
//! * This walk **does not stop there, and must not.** `inherit_permissions` is a permissions flag;
//!   nothing materialises a label when it is flipped. A walk that honoured it would mean that
//!   breaking permission inheritance on a document silently dropped the `RESTRICTED` label it
//!   inherited from the folder above — the *same* escalation `ENC-141` fixed, gained through the
//!   same supported operation, one control over. `classification_inheritance_survives_a_permission_break`
//!   in `crates/classification/tests/effective_classification.rs` is that case, and it fails by name
//!   when `AND a.inherits` is added to the recursive term below.
//!
//! Reusing a walk whose stopping rule is wrong for the question is not reuse; it is the drift
//! `ENC-141` warns about, arriving pre-merged. What the two walks *do* share is the property that
//! matters — both carry `tenant_id = $1` on every join and both run under row-level security.
//!
//! # A truncated walk is an error, never a rank
//!
//! [`file_chains`](enclave_authorization) refuses a chain that hit its depth cap with more tree
//! above it, because the ancestors it did not reach are exactly the ones carrying organisation-wide
//! denials. The same is true here and one direction worse: the ancestors nearest the root are where
//! a tenant-wide `RESTRICTED` folder lives, so a truncated walk under-reports sensitivity. It
//! returns [`DbError::Query`] rather than `Ok(None)`, because `Ok(None)` is *unlabelled* and a
//! tenant on `Unlabelled::Assume` would proceed on the assumed rank as though the walk had
//! completed.
//!
//! # Withdrawn labels still resolve
//!
//! The joins to `classifications` carry no `deleted_at IS NULL` filter. See the migration header:
//! withdrawal governs whether a label may be *assigned*, not what it means for content already
//! carrying it, and a withdrawal that declassified in bulk would be the `DELETE` grant this schema
//! deliberately withholds, reached through the door that is granted.

use enclave_core::{
    ClassificationId, ClassificationRank, EffectiveClassification, FileId, LabelSource, TenantId,
};
use sqlx::{PgConnection, Row as _};

use crate::ids::sql;
use crate::tenant::TenantScoped;
use crate::DbError;

/// How far up the tree the walk goes before it refuses to answer.
///
/// `docs/04-DATA-MODEL.md §5` sets the ACL walk's cap by the same reasoning — a bound is what stops
/// a cycle introduced by a bad move from turning a request into an unbounded query. The value is
/// generous relative to any real folder tree; it is a safety bound, not a product limit.
pub const MAX_CHAIN_DEPTH: i32 = 64;

/// Every label on a file's chain, collapsed to the most sensitive one.
///
/// Four things about the shape, each of which is the safe direction rather than the convenient one:
///
///   * **`max(rank)`, not the nearest label.** See the module header: nearest-wins declassifies
///     through an ordinary move.
///   * **The recursive term is not gated on `inherit_permissions`.** Also the module header, and
///     `ENC-141`.
///   * **`truncated` is reported separately from the rank.** A walk that stopped at the cap with a
///     parent still above it has not seen the chain, and the caller turns that into an error rather
///     than into an answer.
///   * **`found` is reported separately from the rank.** "This file does not exist in this tenant"
///     and "this file has no label" are different facts that would otherwise both arrive as a
///     `NULL` rank, and the cross-tenant test needs to be able to tell them apart from the
///     positive control that resolves a real one.
///
/// `source` is chosen by `ORDER BY rank DESC, precedence ASC`: when two places on the chain carry
/// the same winning rank, the one nearest the resource is named, because that is the one an
/// administrator would edit to change it.
const EFFECTIVE_SQL: &str = "
WITH RECURSIVE ancestry AS (
    SELECT f.id, f.parent_id, f.library_id, f.classification_id, 0 AS depth
      FROM files f
     WHERE f.tenant_id = $1 AND f.id = $2 AND f.deleted_at IS NULL
    UNION ALL
    SELECT p.id, p.parent_id, p.library_id, p.classification_id, a.depth + 1
      FROM ancestry a
      JOIN files p
        ON p.tenant_id = $1 AND p.id = a.parent_id AND p.deleted_at IS NULL
     WHERE a.depth < $3
),
labels AS (
    SELECT c.rank,
           CASE WHEN a.depth = 0 THEN 'RESOURCE' ELSE 'ANCESTOR' END AS source,
           a.depth AS precedence
      FROM ancestry a
      JOIN classifications c
        ON c.tenant_id = $1 AND c.id = a.classification_id
    UNION ALL
    SELECT c.rank, 'LIBRARY', 1000000
      FROM ancestry a
      JOIN libraries l
        ON l.tenant_id = $1 AND l.id = a.library_id AND l.deleted_at IS NULL
      JOIN classifications c
        ON c.tenant_id = $1 AND c.id = l.default_classification_id
     WHERE a.parent_id IS NULL
    UNION ALL
    SELECT c.rank, 'WORKSPACE', 1000001
      FROM ancestry a
      JOIN libraries l
        ON l.tenant_id = $1 AND l.id = a.library_id AND l.deleted_at IS NULL
      JOIN workspaces w
        ON w.tenant_id = $1 AND w.id = l.workspace_id AND w.deleted_at IS NULL
      JOIN classifications c
        ON c.tenant_id = $1 AND c.id = w.default_classification_id
     WHERE a.parent_id IS NULL
)
SELECT (SELECT max(l.rank) FROM labels l) AS rank,
       (SELECT l.source FROM labels l ORDER BY l.rank DESC, l.precedence ASC LIMIT 1) AS source,
       EXISTS (SELECT 1 FROM ancestry) AS found,
       EXISTS (SELECT 1 FROM ancestry a WHERE a.depth = $3 AND a.parent_id IS NOT NULL)
           AS truncated
";

/// Defines a label in a tenant's set.
const DEFINE_SQL: &str = "
INSERT INTO classifications
    (tenant_id, id, key, label, rank, color, watermark_required, download_restricted,
     external_share_blocked, sync_blocked, embedding_policy)
VALUES ($1, $2, $3, $4, $5, NULL, FALSE, FALSE, FALSE, FALSE, 'ANY')
";

/// Withdraws a label. `UPDATE`, because `enclave_app` holds no `DELETE` on this table.
const WITHDRAW_SQL: &str = "
UPDATE classifications
   SET deleted_at = now(), updated_at = now()
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
";

/// Attaches a label to a file or folder.
///
/// `classification_source = 'MANUAL'`: this statement is somebody choosing, and the other three
/// sources in `docs/04 §8`'s `CHECK` belong to the paths that produce them — the resolver never
/// writes `INHERITED`, because inheritance here is *computed* from the chain rather than copied
/// down onto the row. A materialised `INHERITED` copy is the second representation `ENC-141` is
/// about, and there is deliberately not one.
const ASSIGN_SQL: &str = "
UPDATE files
   SET classification_id = $3,
       classification_source = 'MANUAL',
       modified_at = now()
 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
";

/// The rank of the most sensitive label on this file's chain, in the caller's transaction.
///
/// `Ok(None)` means **unlabelled**: nothing on the chain carries a label, or the file is not
/// visible to this transaction. It is not an error and must not be turned into one — what an
/// absence *means* is the tenant's `Unlabelled` policy to decide
/// ([`enclave_core::ClassificationResolution`]), and this module has no opinion about it.
///
/// # Errors
///
/// Query failures, a rank that is not an `i32`, a `source` string this crate does not define, and a
/// chain that hit [`MAX_CHAIN_DEPTH`] with more tree above it. None of them becomes "no label": a
/// read failure converted into an absence is a policy answer produced by an outage, and under
/// `Unlabelled::Assume` that answer is *proceed*.
pub async fn effective_classification_on(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
) -> Result<Option<EffectiveClassification>, DbError> {
    let row = sqlx::query(EFFECTIVE_SQL)
        .bind(sql(tenant))
        .bind(sql(file))
        .bind(MAX_CHAIN_DEPTH)
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    let truncated: bool = row.try_get("truncated").map_err(DbError::Query)?;
    if truncated {
        return Err(DbError::Query(sqlx::Error::Decode(
            format!(
                "the classification chain of file {file} is deeper than {MAX_CHAIN_DEPTH}; the \
                 ancestors nearest the root were not read, and they are where the most sensitive \
                 labels sit"
            )
            .into(),
        )));
    }

    // `found` is read even though nothing branches on it below, because reading it is what keeps
    // the column in the statement and the cross-tenant test able to distinguish "another tenant's
    // file" from "an unlabelled file". Both answer `Ok(None)` to the caller — deliberately, since
    // `CLAUDE.md` rule 7 makes a cross-tenant miss indistinguishable from absence everywhere else
    // too — and a test that could not tell them apart would be asserting an absence for free.
    let _found: bool = row.try_get("found").map_err(DbError::Query)?;

    let Some(rank): Option<i32> = row.try_get("rank").map_err(DbError::Query)? else {
        return Ok(None);
    };

    let source: String = row.try_get("source").map_err(DbError::Query)?;
    let source = match source.as_str() {
        "RESOURCE" => LabelSource::Resource,
        "ANCESTOR" => LabelSource::Ancestor,
        "LIBRARY" => LabelSource::Library,
        "WORKSPACE" => LabelSource::Workspace,
        other => {
            return Err(DbError::Query(sqlx::Error::Decode(
                format!(
                    "the classification walk produced the source `{other}`, which is not one \
                         this crate defines"
                )
                .into(),
            )))
        }
    };

    Ok(Some(EffectiveClassification::found(ClassificationRank::new(rank), source)))
}

/// [`effective_classification_on`], for a caller holding a [`TenantScoped`] transaction.
///
/// The tenant comes from the transaction rather than from an argument, so this form cannot be asked
/// about a tenant other than the one whose row-level-security context is established.
///
/// # Errors
///
/// As [`effective_classification_on`].
pub async fn effective_classification(
    tx: &mut TenantScoped,
    file: FileId,
) -> Result<Option<EffectiveClassification>, DbError> {
    let tenant = tx.tenant_id();
    effective_classification_on(&mut *tx, tenant, file).await
}

/// Defines one label in this tenant's set.
///
/// # Errors
///
/// Query failures, including the two live-uniqueness indexes: a second live label with the same key
/// or the same rank is refused by PostgreSQL rather than stored, which is the migration's argument
/// about two names for one policy outcome, enforced.
pub async fn define_classification(
    tx: &mut TenantScoped,
    id: ClassificationId,
    key: &str,
    label: &str,
    rank: ClassificationRank,
) -> Result<(), DbError> {
    let tenant = tx.tenant_id();
    sqlx::query(DEFINE_SQL)
        .bind(sql(tenant))
        .bind(sql(id))
        .bind(key)
        .bind(label)
        .bind(rank.get())
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Withdraws a label, so it can no longer be assigned.
///
/// Content already carrying it keeps resolving to its rank — see the module header. Returns whether
/// a live row was withdrawn, so a caller can tell "withdrawn" from "already withdrawn or not this
/// tenant's" without a second read.
///
/// # Errors
///
/// Query failures.
pub async fn withdraw_classification(
    tx: &mut TenantScoped,
    id: ClassificationId,
) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    sqlx::query(WITHDRAW_SQL)
        .bind(sql(tenant))
        .bind(sql(id))
        .execute(&mut **tx)
        .await
        .map(|done| done.rows_affected() == 1)
        .map_err(DbError::Query)
}

/// Attaches a label to a file or folder, or clears it with `None`.
///
/// Returns whether a row was updated. A label belonging to another tenant is refused by
/// `files_classification_fkey` rather than stored — the composite key of
/// `migrations/0022_classifications.sql`, which is the control, not a redundancy on top of one.
///
/// # Errors
///
/// Query failures, including that foreign key.
pub async fn assign_classification(
    tx: &mut TenantScoped,
    file: FileId,
    classification: Option<ClassificationId>,
) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    sqlx::query(ASSIGN_SQL)
        .bind(sql(tenant))
        .bind(sql(file))
        .bind(classification.map(sql))
        .execute(&mut **tx)
        .await
        .map(|done| done.rows_affected() == 1)
        .map_err(DbError::Query)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Layer 1, asserted where it is written. Deleting a `tenant_id` predicate leaves row-level
    /// security holding the property alone — `docs/12 §4.1` `T5`'s designed property, and therefore
    /// something the behavioural cross-tenant test cannot catch. This is where it is caught.
    /// The reading and updating statements carry the predicate; the insert carries the column.
    ///
    /// Written as two assertions rather than one because an `INSERT` has no `WHERE` and a single
    /// `contains("tenant_id = $1")` over all four is a test that cannot hold for the one statement
    /// that *writes* the tenant. Collapsing them was this file's first defect: the loop below was
    /// written over all four and failed on `DEFINE_SQL` the moment it was run, which is what
    /// `docs/12 §1.2`'s "watched to fail" catches and an unrun assertion does not.
    #[test]
    fn every_statement_is_scoped_to_one_tenant() {
        for statement in [EFFECTIVE_SQL, WITHDRAW_SQL, ASSIGN_SQL] {
            assert!(
                statement.contains("tenant_id = $1"),
                "a statement reaching classifications without a tenant predicate: {statement}"
            );
        }

        assert!(
            DEFINE_SQL.contains("(tenant_id, id,") && DEFINE_SQL.contains("VALUES ($1, $2,"),
            "the insert must write `tenant_id` from $1 as its first column, or a label can be \
             defined into a tenant the caller's transaction is not scoped to: {DEFINE_SQL}"
        );
    }

    /// Every join in the walk carries the tenant too, not just the anchor.
    ///
    /// The anchor's predicate is what the test above finds. A recursive term or a label join that
    /// dropped its own `tenant_id = $1` would still contain the string, so this counts them: five
    /// `files`/`libraries`/`workspaces` joins and three `classifications` joins, each scoped.
    #[test]
    fn the_walk_scopes_every_join_and_not_only_its_anchor() {
        let scoped = EFFECTIVE_SQL.matches("tenant_id = $1").count();
        assert!(
            scoped >= 8,
            "the walk has {scoped} tenant-scoped joins; every join to files, libraries, workspaces \
             and classifications must carry one, or a label from another tenant can be read \
             through a join row security is not asked about"
        );
    }

    /// `ENC-141`, as a property of the statement rather than of a fixture.
    ///
    /// The behavioural test lives in `crates/classification/tests`; this is the cheap, always-run
    /// half. `inherit_permissions` must appear nowhere in this walk: a permissions flag that
    /// truncated a label walk would drop an ancestor's `RESTRICTED` when somebody broke
    /// inheritance on the document, which is `ENC-141`'s escalation one control over.
    #[test]
    fn the_walk_never_consults_the_permission_break_flag() {
        assert!(
            !EFFECTIVE_SQL.contains("inherit"),
            "the classification walk must not stop at inherit_permissions: nothing materialises a \
             label when that flag is flipped, so honouring it would silently drop an inherited \
             RESTRICTED label (ENC-141)"
        );
    }

    /// The recursive **term**, not the `WITH RECURSIVE` keyword.
    ///
    /// `ENC-594` recorded a break that failed nothing for exactly this reason: deleting the whole
    /// recursive term left an assertion on `RECURSIVE` green, because the keyword survives in
    /// `WITH RECURSIVE`. **This test made the same mistake again before it was right.** Asserting
    /// `UNION ALL` and `FROM ancestry a` was also green with the recursive term deleted, because
    /// both survive in the `labels` CTE below it — three of its branches read `FROM ancestry a`,
    /// and they are joined by `UNION ALL`.
    ///
    /// What is unique to the recursive term is the **parent join**: it is the only place the walk
    /// climbs, so it is the only string whose absence means the walk reads the file's own label and
    /// calls it effective.
    #[test]
    fn the_walk_actually_recurses() {
        assert!(
            EFFECTIVE_SQL.contains("p.id = a.parent_id"),
            "the walk must climb from a node to its parent, or an inherited label is never seen \
             and every document in a RESTRICTED folder resolves as unlabelled"
        );
    }
}
