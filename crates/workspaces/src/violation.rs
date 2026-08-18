//! Reading PostgreSQL's structured error fields, so a lost race becomes a domain answer.
//!
//! Matched on SQLSTATE and the relation/constraint name, never on the message text: messages are
//! localised and change between server releases, while `23505` and `23503` do not. This is the same
//! discipline `enclave_db::migrate` uses for the role-creation race, and the reason is the same —
//! a string match that silently stops matching turns a `400` into a `500` on a path nobody tests.
//!
//! The constraint name is checked *or* the table name, not both. The constraint is the precise
//! signal, and the table is the fallback for the case where an index is renamed by a later
//! migration: on `workspaces` the only unique index other than the primary key is
//! `uq_workspace_slug`, and the primary key holds a freshly minted UUIDv7 that cannot collide, so
//! a unique violation against that table is a slug collision in every reachable case. Falling back
//! to a *less* precise but still correct answer is better than falling back to `500`.

/// Whether the failure is a unique violation raised by `constraint`, or by anything on `table`.
pub(crate) fn is_unique_violation(error: &sqlx::Error, constraint: &str, table: &str) -> bool {
    is_violation(error, "23505", constraint, table)
}

/// Whether the failure is a foreign-key violation raised by `constraint`, or by anything on
/// `table`.
///
/// On `workspace_members` and `libraries` this means one thing: the composite key
/// `(tenant_id, workspace_id)` names no workspace in this tenant. Referential-integrity checks run
/// beneath row-level security, so this fires identically for a workspace that does not exist and
/// for one that belongs to another tenant — which is exactly the indistinguishability `CLAUDE.md`
/// rule 7 requires, obtained here for free rather than by remembering to collapse two cases.
pub(crate) fn is_foreign_key_violation(error: &sqlx::Error, constraint: &str, table: &str) -> bool {
    is_violation(error, "23503", constraint, table)
}

fn is_violation(error: &sqlx::Error, sqlstate: &str, constraint: &str, table: &str) -> bool {
    let Some(db) = error.as_database_error() else {
        return false;
    };
    if db.code().as_deref() != Some(sqlstate) {
        return false;
    }
    db.constraint() == Some(constraint) || db.table() == Some(table)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Constructing a `sqlx::DatabaseError` outside the driver is not possible, so the behaviour
    /// against real SQLSTATEs is asserted in `tests/repositories.rs` against a live PostgreSQL.
    /// What is checked here is the half that can be: a non-database failure must never be read as
    /// a constraint violation, because that would turn a dropped connection into "slug taken".
    #[test]
    fn a_transport_failure_is_never_mistaken_for_a_constraint_violation() {
        for error in [sqlx::Error::PoolTimedOut, sqlx::Error::RowNotFound, sqlx::Error::PoolClosed]
        {
            assert!(!is_unique_violation(&error, "uq_workspace_slug", "workspaces"));
            assert!(!is_foreign_key_violation(&error, "whatever_fkey", "workspace_members"));
        }
    }
}
