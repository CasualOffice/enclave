//! The SQL behind field definitions and values, and the half of validation that needs a database.
//!
//! Per `plans/M1-CONTENT-CORE.md` D10 every function takes a `&mut PgConnection` — never a pool —
//! so it cannot run outside the caller's `TenantScoped` transaction. Every statement also carries
//! an explicit `tenant_id = $1` predicate: layer 1 of `docs/04-DATA-MODEL.md §3`.
//!
//! # Why existence checking lives here and not in `validate`
//!
//! Four field types name something: `USER`, `GROUP`, `TAXONOMY` and `REFERENCE`.
//! [`crate::validate`] confirms the value is a well-formed UUID and stops, because resolving it
//! needs a connection and a validator that took one would run a query inside every loop over every
//! field of every row.
//!
//! It also needs a *tenant*, and that is the security half. A `REFERENCE` whose target is looked up
//! without a tenant predicate would resolve against another tenant's rows — and a field that
//! accepts one identifier and rejects another is an oracle for what exists over there. Every query
//! here is tenant-scoped and runs under forced RLS, so an unresolvable reference and a
//! cross-tenant one produce the same [`FieldViolation::UnresolvedReference`] by construction rather
//! than by remembering to flatten them.

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UserId};
use serde_json::Value;
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::error::{FieldViolation, MetadataError, Result};
use crate::model::{FieldConfig, FieldScope, FieldType, MetadataField, ValueResourceKind};

/// Reads a column, naming it and nothing else on failure.
fn column<'r, T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    name: &'static str,
) -> Result<T> {
    row.try_get(name).map_err(|_| MetadataError::MalformedRow {
        column: name,
        reason: "missing or of an unexpected type",
    })
}

/// Every field that applies to a resource in the given scopes.
///
/// Scopes are passed as a list rather than resolved here because the caller knows the resource's
/// workspace, library and content type and this crate does not — reconstructing that chain here
/// would be a second implementation of something `crates/files` already knows, and the two would
/// eventually disagree about which library a file is in.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn fields_for_scopes(
    conn: &mut PgConnection,
    tenant: TenantId,
    scopes: &[(FieldScope, Option<Uuid>)],
) -> Result<Vec<MetadataField>> {
    if scopes.is_empty() {
        return Ok(Vec::new());
    }

    let kinds: Vec<String> = scopes.iter().map(|(scope, _)| scope.as_str().to_owned()).collect();
    // A tenant-wide field has a NULL `scope_id`, and NULL never equals NULL in a join — so the
    // sentinel below stands in for it on both sides. Without this, tenant-wide fields would simply
    // never match, which reads as "this tenant has defined no fields" rather than as a bug.
    let ids: Vec<Uuid> = scopes.iter().map(|(_, id)| id.unwrap_or_else(Uuid::nil)).collect();

    let rows = sqlx::query(FIELDS_FOR_SCOPES_SQL)
        .bind(tenant.as_uuid())
        .bind(&kinds)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?;

    rows.iter().map(field_from_row).collect()
}

/// Confirms that every value naming something names something that exists in this tenant.
///
/// Pairs are `(field, value)`. Only the four naming types are checked; everything else is skipped,
/// so passing a whole row's worth of values is the intended use.
///
/// Returns one violation per unresolvable value, keyed by the field's `key`.
///
/// # Errors
///
/// Storage failures.
pub async fn validate_references(
    conn: &mut PgConnection,
    tenant: TenantId,
    values: &[(&MetadataField, &Value)],
) -> Result<Vec<(String, FieldViolation)>> {
    let mut unresolved = Vec::new();

    for (field, value) in values {
        let Some(id) = value.as_str().and_then(|raw| Uuid::parse_str(raw).ok()) else {
            // Shape is `validate`'s job; anything malformed has already been reported there, and
            // reporting it twice would show a caller the same problem under two names.
            continue;
        };

        let exists = match field.field_type {
            FieldType::User => scalar_exists(conn, USER_EXISTS_SQL, tenant, id).await?,
            FieldType::Group => scalar_exists(conn, GROUP_EXISTS_SQL, tenant, id).await?,
            FieldType::Taxonomy => {
                taxonomy_term_exists(conn, tenant, id, field.config.taxonomy_set.as_deref()).await?
            }
            FieldType::Reference => {
                reference_exists(conn, tenant, id, field.config.reference_kinds.as_deref()).await?
            }
            _ => continue,
        };

        if !exists {
            unresolved.push((field.key.clone(), FieldViolation::UnresolvedReference));
        }
    }

    Ok(unresolved)
}

/// Writes one value.
///
/// `value_text` is not written and cannot be: the column is `GENERATED ALWAYS ... STORED`, so
/// PostgreSQL refuses an insert that names it. That refusal is the guarantee — see
/// `crate`'s module documentation.
///
/// # Errors
///
/// Storage failures.
pub async fn set_value(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: ValueResourceKind,
    resource_id: Uuid,
    field_id: Uuid,
    value: &Value,
    updated_by: UserId,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(SET_VALUE_SQL)
        .bind(tenant.as_uuid())
        .bind(resource_type.as_str())
        .bind(resource_id)
        .bind(field_id)
        .bind(value)
        .bind(updated_by.as_uuid())
        .bind(now)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Every value set on one resource.
///
/// # Errors
///
/// Storage failures and unreadable rows.
pub async fn values_for(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: ValueResourceKind,
    resource_id: Uuid,
) -> Result<Vec<(Uuid, Value)>> {
    let rows = sqlx::query(VALUES_FOR_SQL)
        .bind(tenant.as_uuid())
        .bind(resource_type.as_str())
        .bind(resource_id)
        .fetch_all(&mut *conn)
        .await?;

    rows.iter().map(|row| Ok((column(row, "field_id")?, column(row, "value")?))).collect()
}

async fn scalar_exists(
    conn: &mut PgConnection,
    statement: &'static str,
    tenant: TenantId,
    id: Uuid,
) -> Result<bool> {
    let found: Option<i32> = sqlx::query_scalar(statement)
        .bind(tenant.as_uuid())
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(found.is_some())
}

async fn taxonomy_term_exists(
    conn: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    set_name: Option<&str>,
) -> Result<bool> {
    // The set is part of the check, not a hint. A `TAXONOMY` field configured for "Departments"
    // that accepts a term from "Product lines" is a field whose configuration says nothing, and the
    // facet it drives would quietly mix two vocabularies.
    let found: Option<i32> = sqlx::query_scalar(TAXONOMY_EXISTS_SQL)
        .bind(tenant.as_uuid())
        .bind(id)
        .bind(set_name)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(found.is_some())
}

async fn reference_exists(
    conn: &mut PgConnection,
    tenant: TenantId,
    id: Uuid,
    kinds: Option<&[String]>,
) -> Result<bool> {
    // Only `files` today, because files and folders are the only referenceable resources that
    // exist. When lists and pages land, this gains their tables — deliberately as separate
    // statements rather than a polymorphic lookup, so that each one keeps its own tenant predicate
    // and its own soft-delete condition instead of sharing a clever one that is wrong for one of
    // them.
    let wants_files = kinds.is_none_or(|k| {
        k.iter()
            .any(|kind| kind.eq_ignore_ascii_case("FILE") || kind.eq_ignore_ascii_case("FOLDER"))
    });
    if !wants_files {
        return Ok(false);
    }
    scalar_exists(conn, FILE_EXISTS_SQL, tenant, id).await
}

fn field_from_row(row: &sqlx::postgres::PgRow) -> Result<MetadataField> {
    fn parse<T: core::str::FromStr>(raw: &str, column: &'static str) -> Result<T> {
        raw.parse().map_err(|_| MetadataError::MalformedRow {
            column,
            reason: "not a value this crate knows",
        })
    }

    let scope: String = column(row, "scope")?;
    let field_type: String = column(row, "field_type")?;
    let config: Value = column(row, "config")?;

    Ok(MetadataField {
        id: column(row, "id")?,
        tenant_id: TenantId::from(column::<Uuid>(row, "tenant_id")?),
        scope: parse(&scope, "scope")?,
        scope_id: column(row, "scope_id")?,
        key: column(row, "key")?,
        label: column(row, "label")?,
        field_type: parse(&field_type, "field_type")?,
        required: column(row, "required")?,
        indexed: column(row, "indexed")?,
        // A config that will not deserialize is a defect in the definition, not in the value, and
        // it must not be silently defaulted: a field whose `max_length` failed to parse would
        // become an unbounded field that still claims to be bounded.
        config: serde_json::from_value::<FieldConfig>(config).map_err(|_| {
            MetadataError::MalformedRow { column: "config", reason: "not a field configuration" }
        })?,
        created_at: column(row, "created_at")?,
    })
}

const FIELDS_FOR_SCOPES_SQL: &str = "
SELECT f.id, f.tenant_id, f.scope, f.scope_id, f.key, f.label, f.field_type, f.required,
       f.indexed, f.config, f.created_at
  FROM metadata_fields f
  JOIN unnest($2::text[], $3::uuid[]) AS s(scope, scope_id)
    ON s.scope = f.scope
   AND coalesce(f.scope_id, '00000000-0000-0000-0000-000000000000'::uuid) = s.scope_id
 WHERE f.tenant_id = $1
 ORDER BY f.key
";

const SET_VALUE_SQL: &str = "
INSERT INTO metadata_values
    (tenant_id, resource_type, resource_id, field_id, value, updated_by, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
    ON CONFLICT (tenant_id, resource_type, resource_id, field_id)
    DO UPDATE SET value      = EXCLUDED.value,
                  updated_by = EXCLUDED.updated_by,
                  updated_at = EXCLUDED.updated_at
";

const VALUES_FOR_SQL: &str = "
SELECT field_id, value
  FROM metadata_values
 WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
";

// Each existence check selects a constant rather than the row: nothing needs the contents, and a
// `SELECT *` here would pull a user record into memory to answer a yes/no question.
const USER_EXISTS_SQL: &str = "SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2";
const GROUP_EXISTS_SQL: &str = "SELECT 1 FROM groups WHERE tenant_id = $1 AND id = $2";
const FILE_EXISTS_SQL: &str =
    "SELECT 1 FROM files WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";
const TAXONOMY_EXISTS_SQL: &str = "
SELECT 1 FROM taxonomy_terms
 WHERE tenant_id = $1 AND id = $2 AND ($3::text IS NULL OR set_name = $3)
";
