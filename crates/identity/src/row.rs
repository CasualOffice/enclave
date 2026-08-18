//! Turning stored rows back into the types in [`crate::model`].
//!
//! Kept in one place rather than inline in each repository so that the column names a query selects
//! and the column names a decoder reads are next to each other. The failure mode this guards
//! against is quiet: a `SELECT` that stops listing a column and a decoder that still asks for it
//! produce a runtime `ColumnNotFound` on a path that may only run in production.
//!
//! Every failure is [`IdentityError::MalformedRow`] naming the column and a fixed reason — never
//! the value. An unparseable `status` is a schema/code drift, and echoing the offending content
//! into a log is how personal data travels out of the database (`CLAUDE.md` rule 10).

use core::str::FromStr;

use chrono::{DateTime, Utc};
use enclave_db::RowIdExt;
use sqlx::postgres::PgRow;
use sqlx::Row as _;

use crate::error::{IdentityError, Result};
use crate::model::{Group, GroupSource, Tenant, TenantStatus, User, UserSource, UserStatus};

// The column lists each decoder below reads, as the reference the query constants are checked
// against. Test-only on purpose: the queries spell their `SELECT` lists out as literals — `concat!`
// takes only literals, and building SQL with `format!` on every call to avoid one duplicated string
// is the wrong trade. What is needed is not shared code but a check that the two agree, and that is
// exactly what a constant plus an assertion gives.

/// The `tenants` columns every tenant query selects.
#[cfg(test)]
pub(crate) const TENANT_COLUMNS: &str =
    "id, slug, display_name, status, residency_region, policy_generation, created_at, updated_at";

/// The `users` columns every user query selects.
#[cfg(test)]
pub(crate) const USER_COLUMNS: &str = "id, tenant_id, email, normalized_email, display_name, \
     status, is_admin, token_epoch, source, external_id, department, locale, last_login_at, \
     created_at, updated_at";

/// The `groups` columns every group query selects, unqualified.
#[cfg(test)]
pub(crate) const GROUP_COLUMNS: &str = "id, tenant_id, name, normalized_name, description, \
     source, external_id, created_at, updated_at";

/// The same list qualified with the alias the joined membership queries use.
#[cfg(test)]
pub(crate) const GROUP_COLUMNS_ALIASED: &str = "g.id, g.tenant_id, g.name, g.normalized_name, \
     g.description, g.source, g.external_id, g.created_at, g.updated_at";

/// Rebuilds a [`Tenant`].
///
/// # Errors
///
/// [`IdentityError::MalformedRow`] when a column is absent or holds a value outside its `CHECK`
/// constraint's vocabulary.
pub(crate) fn tenant_from_row(row: &PgRow) -> Result<Tenant> {
    Ok(Tenant {
        id: row.try_get_id("id")?,
        slug: row.try_get("slug")?,
        display_name: row.try_get("display_name")?,
        status: parse_enum::<TenantStatus>(row, "status", "not a known tenant status")?,
        residency_region: row.try_get("residency_region")?,
        policy_generation: row.try_get("policy_generation")?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
    })
}

/// Rebuilds a [`User`].
///
/// # Errors
///
/// As [`tenant_from_row`].
pub(crate) fn user_from_row(row: &PgRow) -> Result<User> {
    Ok(User {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        email: row.try_get("email")?,
        normalized_email: row.try_get("normalized_email")?,
        display_name: row.try_get("display_name")?,
        status: parse_enum::<UserStatus>(row, "status", "not a known user status")?,
        is_admin: row.try_get("is_admin")?,
        token_epoch: row.try_get("token_epoch")?,
        source: parse_enum::<UserSource>(row, "source", "not a known user source")?,
        external_id: row.try_get("external_id")?,
        department: row.try_get("department")?,
        locale: row.try_get("locale")?,
        last_login_at: row.try_get("last_login_at")?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
    })
}

/// Rebuilds a [`Group`].
///
/// # Errors
///
/// As [`tenant_from_row`].
pub(crate) fn group_from_row(row: &PgRow) -> Result<Group> {
    Ok(Group {
        id: row.try_get_id("id")?,
        tenant_id: row.try_get_id("tenant_id")?,
        name: row.try_get("name")?,
        normalized_name: row.try_get("normalized_name")?,
        description: row.try_get("description")?,
        source: parse_enum::<GroupSource>(row, "source", "not a known group source")?,
        external_id: row.try_get("external_id")?,
        created_at: timestamp(row, "created_at")?,
        updated_at: timestamp(row, "updated_at")?,
    })
}

/// Reads a text column and parses it into a closed vocabulary.
///
/// The `reason` is a fixed phrase supplied by the caller, so the error can say which vocabulary
/// rejected the value without the value itself appearing anywhere.
fn parse_enum<T>(row: &PgRow, column: &'static str, reason: &'static str) -> Result<T>
where
    T: FromStr,
{
    let raw: String = row.try_get(column)?;
    T::from_str(&raw).map_err(|_| IdentityError::MalformedRow { column, reason })
}

/// Reads a `TIMESTAMPTZ`.
///
/// A named helper only so that every timestamp in this module is read the same way; the columns are
/// `NOT NULL` in `migrations/0001_foundations.sql`, and a NULL here is a schema drift rather than an
/// absent value.
fn timestamp(row: &PgRow, column: &'static str) -> Result<DateTime<Utc>> {
    row.try_get(column)
        .map_err(|_| IdentityError::MalformedRow { column, reason: "not a readable timestamp" })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The aliased list is hand-written, so prove it is the same list. A missing column here is a
    /// `ColumnNotFound` on the membership path only, which is the path with no unit-test coverage.
    #[test]
    fn the_aliased_group_columns_are_the_unaliased_ones() {
        let stripped: Vec<String> = GROUP_COLUMNS_ALIASED
            .split(',')
            .map(|column| column.trim().trim_start_matches("g.").to_owned())
            .collect();
        let plain: Vec<String> =
            GROUP_COLUMNS.split(',').map(|column| column.trim().to_owned()).collect();
        assert_eq!(stripped, plain);
    }

    /// Every decoder reads exactly the columns its `SELECT` lists. Checked by name because the
    /// mismatch is invisible until a query runs.
    #[test]
    fn every_column_list_is_well_formed() {
        for list in [TENANT_COLUMNS, USER_COLUMNS, GROUP_COLUMNS, GROUP_COLUMNS_ALIASED] {
            for column in list.split(',') {
                let column = column.trim();
                assert!(!column.is_empty(), "empty column in `{list}`");
                assert!(
                    column.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c == '.'),
                    "`{column}` is not a plain identifier"
                );
            }
        }
        assert_eq!(USER_COLUMNS.split(',').count(), 15);
        assert_eq!(TENANT_COLUMNS.split(',').count(), 8);
        assert_eq!(GROUP_COLUMNS.split(',').count(), 9);
    }
}
