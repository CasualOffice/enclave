//! Stored conditional-access rules — `ENC-590`, `docs/04-DATA-MODEL.md §12.1`.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §7` is authoritative for what a rule *is*; this module is only
//! how one is written down and read back. `migrations/0019_conditional_access_rules.sql` holds the
//! argument for the table's shape.
//!
//! # Why this sits in `enclave-db` at all
//!
//! The crate header says there are no repositories here, and names [`crate::quota`] as the argued
//! exception. This is the second, and the argument is the reverse of the quota's: not that the rule
//! has no domain crate, but that `crates/conditional_access` **is** its domain crate and would have
//! to reach past this one to get at a table. `CLAUDE.md`'s Rust conventions forbid that in the
//! sentence that matters — *all database access through the `db` crate's `TenantScoped` wrapper, no
//! `sqlx::query!` in domain crates* — so the statement lives here and the meaning lives there.
//!
//! # This module holds no opinion about what a rule means
//!
//! [`RuleRow`] is strings. `audience`, `effect` and `mode` are the vocabularies the migration's
//! `CHECK` constraints define, and `conditions` is JSON **text**: this crate neither parses the
//! document nor knows the names in it. That is deliberate rather than lazy —
//! `crates/conditional_access/src/store.rs` owns the vocabulary because it owns the types the
//! vocabulary decodes into, and a second half-copy of it here is the drift this repository keeps
//! finding in other forms. Passing the document as text rather than as a `serde_json::Value` is the
//! same decision expressed in the dependency list: this crate has no reason to link a JSON parser.
//!
//! It follows that the *only* structural guarantees on the way in are PostgreSQL's — which is why
//! `effect`'s `CHECK` matters. A caller may hand [`insert_rule`] the string `ALLOW`; the database
//! refuses it, on every path, including the ones that never went through a Rust enum.

use enclave_core::id::UserId;
use sqlx::Row as _;
use uuid::Uuid;

use crate::ids::{sql, RowIdExt as _, SqlId};
use crate::tenant::TenantScoped;
use crate::DbError;

/// A stored rule's identifier.
///
/// A newtype rather than a bare `Uuid`, per `CLAUDE.md`'s Rust conventions — no bare `Uuid` on a
/// public boundary. It is declared here rather than in `enclave_core::id` because
/// `crates/conditional_access` depends on this crate and not the other way round, so a definition
/// in the domain crate could not be named by the row type it identifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(Uuid);

impl RuleId {
    /// A new, time-ordered identifier.
    #[must_use]
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl core::fmt::Display for RuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl SqlId for RuleId {
    const TYPE_NAME: &'static str = "RuleId";

    fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    fn to_uuid(self) -> Uuid {
        self.0
    }
}

/// One row of `conditional_access_rules`, exactly as stored.
///
/// Every field except [`RuleRow::id`] is the database's own spelling. Decoding them into rules is
/// `enclave_conditional_access::store`'s job, and the split is what keeps the Q19 type separation
/// from being re-decided here: this crate cannot accidentally read a `MACHINE` row as a human rule,
/// because it has no idea what either is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    /// The rule's identifier, unique within the tenant.
    pub id: RuleId,
    /// `HUMAN` or `MACHINE` — which rule set this row belongs to (Q19).
    pub audience: String,
    /// The administrator-facing name. Unique among a tenant's live rules.
    pub name: String,
    /// The conjunctive condition list, as JSON array text.
    pub conditions: String,
    /// The effect, in `effect`'s `CHECK` vocabulary. `ALLOW` is not in it.
    pub effect: String,
    /// `ENFORCE` or `SIMULATION`.
    pub mode: String,
}

/// Every live rule for the transaction's tenant.
///
/// `deleted_at IS NULL` is the withdrawal filter: `enclave_app` holds no `DELETE` on this table, so
/// removing a rule sets `deleted_at` and the row stays (`migrations/0019`). The ordering is by name
/// and is presentational only — the outcome of an evaluation is decided by `Effect`'s ordering, not
/// by the order rules arrive in (`docs/06 §7.4`), so this makes reports and logs stable without
/// making the decision depend on the query plan.
///
/// The `tenant_id = $1` predicate is written even though row-level security enforces the same
/// thing. That is the two-layer arrangement `docs/04 §3` describes and this crate exists for; see
/// `crates/db/src/lib.rs`.
const LOAD_SQL: &str = "
SELECT id, audience, name, conditions::text AS conditions, effect, mode
  FROM conditional_access_rules
 WHERE tenant_id = $1
   AND deleted_at IS NULL
 ORDER BY name
";

/// Writes a rule.
///
/// `$4::jsonb` casts the document on the way in, so a malformed one is refused by PostgreSQL's own
/// parser at the moment it is written rather than at the moment somebody's request is being
/// decided. The `CHECK` constraints on `audience`, `effect` and `mode` do the same for the three
/// vocabularies.
const INSERT_SQL: &str = "
INSERT INTO conditional_access_rules
    (tenant_id, id, audience, name, conditions, effect, mode, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, now(), now())
";

/// Withdrawal — the `UPDATE` this deployment has instead of a `DELETE`.
///
/// Idempotent by the `deleted_at IS NULL` predicate: withdrawing an already-withdrawn rule reports
/// `false` rather than moving the timestamp, so the record of *when* a rule stopped applying is
/// written once.
const WITHDRAW_SQL: &str = "
UPDATE conditional_access_rules
   SET deleted_at = now(),
       updated_at = now()
 WHERE tenant_id = $1
   AND id = $2
   AND deleted_at IS NULL
";

/// Moves a live rule between rehearsing and deciding.
///
/// The statement an administrator runs at the end of a rollout (`plans/M4-GOVERNANCE.md §2`), and
/// the one whose effect must not be delayed by a cache for an unbounded time — see
/// `enclave_conditional_access::TenantConditionalAccess`.
const SET_MODE_SQL: &str = "
UPDATE conditional_access_rules
   SET mode = $3,
       updated_at = now()
 WHERE tenant_id = $1
   AND id = $2
   AND deleted_at IS NULL
";

/// Loads every live rule for this transaction's tenant.
///
/// # Errors
///
/// Query failures. A tenant with no rules is an empty `Vec`, not an error: no rules configured is a
/// legitimate state and means this stage has nothing to object to.
pub async fn load_rules(tx: &mut TenantScoped) -> Result<Vec<RuleRow>, DbError> {
    let tenant = tx.tenant_id();
    let rows = sqlx::query(LOAD_SQL)
        .bind(sql(tenant))
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    rows.iter()
        .map(|row| {
            Ok(RuleRow {
                id: row.try_get_id("id").map_err(DbError::Query)?,
                audience: row.try_get("audience").map_err(DbError::Query)?,
                name: row.try_get("name").map_err(DbError::Query)?,
                conditions: row.try_get("conditions").map_err(DbError::Query)?,
                effect: row.try_get("effect").map_err(DbError::Query)?,
                mode: row.try_get("mode").map_err(DbError::Query)?,
            })
        })
        .collect()
}

/// Writes one rule, authored by `created_by`.
///
/// The author is `NOT NULL` and carries a composite foreign key onto `users (tenant_id, id)`, so a
/// rule cannot name another tenant's administrator as its author — PostgreSQL runs referential
/// integrity with row security not enforced, which is why the key is composite rather than a plain
/// `REFERENCES users (id)` (`docs/04 §3.3`).
///
/// # Errors
///
/// Query failures, including the `CHECK` violations that are the point of the vocabularies: an
/// `effect` of `ALLOW`, an `audience` that is neither `HUMAN` nor `MACHINE`, a `conditions`
/// document that is not a JSON array, or a name already taken by another live rule.
pub async fn insert_rule(
    tx: &mut TenantScoped,
    row: &RuleRow,
    created_by: UserId,
) -> Result<(), DbError> {
    let tenant = tx.tenant_id();
    sqlx::query(INSERT_SQL)
        .bind(sql(tenant))
        .bind(sql(row.id))
        .bind(&row.audience)
        .bind(&row.name)
        .bind(&row.conditions)
        .bind(&row.effect)
        .bind(&row.mode)
        .bind(sql(created_by))
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Withdraws a rule, leaving the row and its text in place.
///
/// Returns whether a live rule was withdrawn. `false` means it was already withdrawn or never
/// existed in this tenant — the two are indistinguishable here on purpose, for the same reason a
/// cross-tenant read is a `404`.
///
/// # Errors
///
/// Query failures.
pub async fn withdraw_rule(tx: &mut TenantScoped, id: RuleId) -> Result<bool, DbError> {
    affected(tx, WITHDRAW_SQL, id, None).await
}

/// Switches a live rule between `SIMULATION` and `ENFORCE`.
///
/// `mode` is a string rather than an enum for the same reason [`RuleRow`]'s fields are: the
/// vocabulary belongs to the domain crate and to the migration's `CHECK`, and a copy of it here
/// would be a copy that can drift. An unrecognised value is refused by PostgreSQL.
///
/// # Errors
///
/// Query failures, including the `CHECK` violation for an unrecognised mode.
pub async fn set_rule_mode(tx: &mut TenantScoped, id: RuleId, mode: &str) -> Result<bool, DbError> {
    affected(tx, SET_MODE_SQL, id, Some(mode)).await
}

/// Runs a tenant-and-id scoped `UPDATE` and reports whether it moved a row.
async fn affected(
    tx: &mut TenantScoped,
    statement: &'static str,
    id: RuleId,
    third: Option<&str>,
) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let mut query = sqlx::query(statement).bind(sql(tenant)).bind(sql(id));
    if let Some(value) = third {
        query = query.bind(value);
    }
    let result = query.execute(&mut **tx).await.map_err(DbError::Query)?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The withdrawal filter is the difference between "this rule was removed" and "this rule still
    /// refuses people", and it is one clause in one string. Asserting it here means deleting it is
    /// a failure in this crate as well as in the behavioural test one crate over.
    #[test]
    fn the_load_statement_reads_only_live_rules_of_one_tenant() {
        assert!(LOAD_SQL.contains("tenant_id = $1"), "the application predicate is layer 1");
        assert!(LOAD_SQL.contains("deleted_at IS NULL"), "a withdrawn rule must not be loaded");
    }

    /// Withdrawal must never be spelled `DELETE`, in this module or anywhere else that can reach
    /// the table: `enclave_app` holds no `DELETE` grant, so the statement would fail at runtime
    /// rather than at compile time, and it would fail in whichever deployment ran it first.
    ///
    /// The needle is assembled rather than written, because a source-scanning assertion whose
    /// needle appears in its own file passes against itself — `docs/12-TESTING.md §1.2` records two
    /// tests in this repository that did exactly that.
    #[test]
    fn no_statement_here_deletes_a_rule() {
        let needle = format!("{} FROM conditional_access_rules", "DELETE");
        for statement in [LOAD_SQL, INSERT_SQL, WITHDRAW_SQL, SET_MODE_SQL] {
            assert!(
                !statement.contains(&needle),
                "a rule is withdrawn with an UPDATE, never deleted (migrations/0019)"
            );
        }
        // The positive control: the needle *would* be found if it were there, so this test is
        // failing to find something it is capable of finding.
        assert!(format!("{needle} WHERE 1=0").contains(&needle));
    }

    #[test]
    fn a_rule_id_survives_the_round_trip_through_the_driver_transport() {
        let id = RuleId::new_v7();
        assert_eq!(RuleId::from_uuid(id.as_uuid()), id);
        assert_eq!(<RuleId as SqlId>::from_uuid(id.to_uuid()), id);
    }
}
