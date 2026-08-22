//! Stored DLP rules — `ENC-615`, `docs/04-DATA-MODEL.md §12.3`.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §8`–`§10` is authoritative for what a rule *is*; this module is
//! only how one is written down and read back. `migrations/0021_dlp_rules.sql` holds the argument
//! for the table's shape.
//!
//! # Why this sits in `enclave-db` at all
//!
//! The third argued exception to the crate header's "no repositories", and the same argument
//! [`crate::conditional_access`] makes: `crates/dlp` **is** the rule's domain crate and would have
//! to reach past this one to get at a table. `CLAUDE.md`'s Rust conventions forbid that in the
//! sentence that matters — *all database access through the `db` crate's `TenantScoped` wrapper, no
//! `sqlx::query!` in domain crates* — so the statement lives here and the meaning lives there.
//!
//! # This module holds no opinion about what a rule means
//!
//! [`DlpRuleRow`] is strings and numbers. `action` is the vocabulary the migration's `CHECK`
//! defines, and `scope`/`conditions` are JSON **text**: this crate neither parses the documents nor
//! knows the names in them. `crates/dlp/src/store.rs` owns the vocabulary because it owns the types
//! the vocabulary decodes into, and a second half-copy of it here is the drift this repository keeps
//! finding in other forms.
//!
//! It follows that the only structural guarantees on the way in are PostgreSQL's — which is why the
//! `CHECK` constraints matter. A caller may hand [`insert_dlp_rule`] the action `ALLOW`; the
//! database refuses it, on every path, including the ones that never went through a Rust enum.
//!
//! # Order is part of the answer here, unlike conditional access
//!
//! [`crate::conditional_access`]'s loader orders by name and says the ordering is presentational,
//! because that evaluator resolves by most-restrictive-effect-wins. This one does not:
//! `enclave_dlp::policy::Verdict::blocking_code` returns the **first** refusal in rule order, so the
//! order rows arrive in decides which reason code a refused caller is shown. [`LOAD_SQL`] therefore
//! sorts by `priority` and breaks ties on `name`, which is unique among a tenant's live rules — a
//! total order, so two replicas cannot disagree.

use enclave_core::id::UserId;
use sqlx::Row as _;
use uuid::Uuid;

use crate::ids::{sql, RowIdExt as _, SqlId};
use crate::tenant::TenantScoped;
use crate::DbError;

/// A stored DLP rule's identifier.
///
/// A newtype rather than a bare `Uuid`, per `CLAUDE.md`'s Rust conventions. Distinct from
/// [`crate::conditional_access::RuleId`] on purpose: the two tables are different tables, and one
/// shared "rule id" type would let a conditional-access identifier be passed to
/// [`withdraw_dlp_rule`] and vice versa — a mistake that compiles and then silently withdraws
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DlpRuleId(Uuid);

impl DlpRuleId {
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

impl core::fmt::Display for DlpRuleId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl SqlId for DlpRuleId {
    const TYPE_NAME: &'static str = "DlpRuleId";

    fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    fn to_uuid(self) -> Uuid {
        self.0
    }
}

/// One row of `dlp_rules`, exactly as stored.
///
/// Every field except [`DlpRuleRow::id`] is the database's own spelling. Decoding them into rules is
/// `enclave_dlp::store`'s job, and the split is what keeps Q16 from being re-decided here: this
/// crate cannot accidentally accept a condition vocabulary that includes a pattern, because it has
/// no idea what a condition is.
///
/// **There is no `mode` field**, and its absence is the milestone's structural guarantee rather than
/// an omission: `enclave_dlp::policy::RuleSet` holds no mode so that `evaluate` can take none, which
/// is what makes `SIMULATION` and `ENFORCE` unable to diverge (D28). A mode column would have to be
/// carried on the rule type to be read. See `migrations/0021_dlp_rules.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpRuleRow {
    /// The rule's identifier, unique within the tenant.
    pub id: DlpRuleId,
    /// The administrator-facing name. Unique among a tenant's live rules.
    pub name: String,
    /// Rule order, ascending. Decides which refusal a caller is shown when two rules refuse.
    pub priority: i32,
    /// Which actions the rule governs, as a JSON array of `ActionScope`. Never empty — the
    /// migration refuses an empty array, because an empty scope governs nothing.
    pub scope: String,
    /// The conjunctive condition list, as JSON array text. Empty is legitimate.
    pub conditions: String,
    /// The action, in `action`'s `CHECK` vocabulary. `ALLOW` is not in it.
    pub action: String,
    /// The rank `RECLASSIFY` raises the resource to, and `None` for every other action. The
    /// migration ties the two together in both directions.
    pub reclassify_to: Option<i32>,
}

/// Every live rule for the transaction's tenant, in evaluation order.
///
/// `deleted_at IS NULL` is the withdrawal filter: `enclave_app` holds no `DELETE` on this table, so
/// removing a rule sets `deleted_at` and the row stays (`migrations/0021`). The ordering is **not**
/// presentational — see the module header.
///
/// The `tenant_id = $1` predicate is written even though row-level security enforces the same
/// thing. That is the two-layer arrangement `docs/04 §3` describes and this crate exists for; see
/// `crates/db/src/lib.rs`.
const LOAD_SQL: &str = "
SELECT id,
       name,
       priority,
       scope::text      AS scope,
       conditions::text AS conditions,
       action,
       reclassify_to
  FROM dlp_rules
 WHERE tenant_id = $1
   AND deleted_at IS NULL
 ORDER BY priority, name
";

/// Writes a rule.
///
/// `$5::jsonb`/`$6::jsonb` cast the documents on the way in, so a malformed one is refused by
/// PostgreSQL's own parser at the moment it is written rather than at the moment somebody's request
/// is being decided. The `CHECK` constraints do the same for the action vocabulary, for the
/// scope's non-emptiness and for the `RECLASSIFY`/rank pairing.
const INSERT_SQL: &str = "
INSERT INTO dlp_rules
    (tenant_id, id, name, priority, scope, conditions, action, reclassify_to,
     created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, now(), now())
";

/// Withdrawal — the `UPDATE` this deployment has instead of a `DELETE`.
///
/// Idempotent by the `deleted_at IS NULL` predicate: withdrawing an already-withdrawn rule reports
/// `false` rather than moving the timestamp, so the record of *when* a rule stopped applying is
/// written once.
const WITHDRAW_SQL: &str = "
UPDATE dlp_rules
   SET deleted_at = now(),
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
/// legitimate state, and it is the state every deployment was in before this table existed. What
/// must **not** happen is the reverse — a query failure becoming an empty rule set, which is a DLP
/// stage that inspects nothing. That is the caller's obligation and
/// `enclave_dlp::tenant::TenantDlp` is where it is discharged.
pub async fn load_dlp_rules(tx: &mut TenantScoped) -> Result<Vec<DlpRuleRow>, DbError> {
    let tenant = tx.tenant_id();
    let rows = sqlx::query(LOAD_SQL)
        .bind(sql(tenant))
        .fetch_all(&mut **tx)
        .await
        .map_err(DbError::Query)?;

    rows.iter()
        .map(|row| {
            Ok(DlpRuleRow {
                id: row.try_get_id("id").map_err(DbError::Query)?,
                name: row.try_get("name").map_err(DbError::Query)?,
                priority: row.try_get("priority").map_err(DbError::Query)?,
                scope: row.try_get("scope").map_err(DbError::Query)?,
                conditions: row.try_get("conditions").map_err(DbError::Query)?,
                action: row.try_get("action").map_err(DbError::Query)?,
                reclassify_to: row.try_get("reclassify_to").map_err(DbError::Query)?,
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
/// Query failures, including the `CHECK` violations that are the point of the vocabulary: an
/// `action` of `ALLOW`, an empty `scope` array, a document that is not a JSON array, a
/// `RECLASSIFY` with no rank or a rank on any other action, or a name already taken by another
/// live rule.
pub async fn insert_dlp_rule(
    tx: &mut TenantScoped,
    row: &DlpRuleRow,
    created_by: UserId,
) -> Result<(), DbError> {
    let tenant = tx.tenant_id();
    sqlx::query(INSERT_SQL)
        .bind(sql(tenant))
        .bind(sql(row.id))
        .bind(&row.name)
        .bind(row.priority)
        .bind(&row.scope)
        .bind(&row.conditions)
        .bind(&row.action)
        .bind(row.reclassify_to)
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
pub async fn withdraw_dlp_rule(tx: &mut TenantScoped, id: DlpRuleId) -> Result<bool, DbError> {
    let tenant = tx.tenant_id();
    let result = sqlx::query(WITHDRAW_SQL)
        .bind(sql(tenant))
        .bind(sql(id))
        .execute(&mut **tx)
        .await
        .map_err(DbError::Query)?;
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

    /// The order rules come back in decides which reason code a refused caller sees
    /// (`Verdict::blocking_code` takes the first refusal), so an unordered load would make that
    /// answer depend on the query plan. `name` is the tie-break because it is unique among a
    /// tenant's live rules, which makes the ordering total.
    #[test]
    fn the_load_statement_returns_rules_in_a_total_order() {
        assert!(
            LOAD_SQL.contains("ORDER BY priority, name"),
            "rule order is precedence order here, not presentation"
        );
    }

    /// Withdrawal must never be spelled `DELETE`, in this module or anywhere else that can reach
    /// the table: `enclave_app` holds no `DELETE` grant, so the statement would fail at runtime
    /// rather than at compile time, and it would fail in whichever deployment ran it first.
    ///
    /// The needle is assembled rather than written, because a source-scanning assertion whose
    /// needle appears in its own file passes against itself — `docs/12-TESTING.md §1.2` records
    /// three tests in this repository that did exactly that.
    #[test]
    fn no_statement_here_deletes_a_rule() {
        let needle = format!("{} FROM dlp_rules", "DELETE");
        for statement in [LOAD_SQL, INSERT_SQL, WITHDRAW_SQL] {
            assert!(
                !statement.contains(&needle),
                "a rule is withdrawn with an UPDATE, never deleted (migrations/0021)"
            );
        }
        // The positive control: the needle *would* be found if it were there, so this test is
        // failing to find something it is capable of finding.
        assert!(format!("{needle} WHERE 1=0").contains(&needle));
    }

    #[test]
    fn a_rule_id_survives_the_round_trip_through_the_driver_transport() {
        let id = DlpRuleId::new_v7();
        assert_eq!(DlpRuleId::from_uuid(id.as_uuid()), id);
        assert_eq!(<DlpRuleId as SqlId>::from_uuid(id.to_uuid()), id);
    }
}
