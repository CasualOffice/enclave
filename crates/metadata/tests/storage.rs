//! The half of metadata that needs a database: the generated projection, and reference resolution.
//!
//! Two properties are only answerable by PostgreSQL:
//!
//! 1. **`value_text` is generated, not written.** `docs/04-DATA-MODEL.md §10` calls it a projection
//!    for filtering and sorting, and a projection that could drift from its source is a wrong
//!    answer to a query. Generated in the database, it cannot drift — and the proof is that an
//!    insert naming the column is *refused*.
//! 2. **A reference cannot resolve across tenants.** Every lookup is tenant-scoped and runs under
//!    forced RLS, so another tenant's file and a file that never existed produce the same violation
//!    by construction. If they did not, a `REFERENCE` field would be an oracle for what exists over
//!    there.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_core::{TenantId, UserId};
use enclave_db::{DbPool, TenantScoped};
use enclave_metadata::{
    repo, FieldConfig, FieldScope, FieldType, FieldViolation, MetadataField, ValueResourceKind,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool().await.expect("application pool");
    (db, fixtures, pool)
}

async fn define_field(
    conn: &mut PgConnection,
    tenant: TenantId,
    key: &str,
    field_type: FieldType,
    config: &FieldConfig,
) -> MetadataField {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO metadata_fields
           (id, tenant_id, scope, scope_id, key, label, field_type, required, indexed, config,
            created_at)
         VALUES ($1, $2, 'TENANT', NULL, $3, $4, $5, FALSE, FALSE, $6, $7)",
    )
    .bind(id)
    .bind(tenant.as_uuid())
    .bind(key)
    .bind(key)
    .bind(field_type.as_str())
    .bind(serde_json::to_value(config).expect("config"))
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("define the field");

    MetadataField {
        id,
        tenant_id: tenant,
        scope: FieldScope::Tenant,
        scope_id: None,
        key: key.to_owned(),
        label: key.to_owned(),
        field_type,
        required: false,
        indexed: false,
        config: config.clone(),
        created_at: Utc::now(),
    }
}

/// The projection is maintained by PostgreSQL, and writing it is refused.
///
/// The refusal is the guarantee. If the column were merely *usually* written by this crate, the
/// first code path that inserted without it — a migration backfill, a bulk import, a fixture —
/// would leave rows whose filters and sorts silently disagree with their values.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0009; CI runs it with --include-ignored"]
async fn value_text_is_generated_by_the_database_and_cannot_be_written() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let field =
        define_field(&mut tx, alpha, "matter", FieldType::Text, &FieldConfig::default()).await;

    repo::set_value(
        &mut tx,
        alpha,
        ValueResourceKind::File,
        spine.file.as_uuid(),
        field.id,
        &json!("Acquisition of Northwind"),
        UserId::from(Uuid::nil()),
        now,
    )
    .await
    .expect("set the value");

    // The projection unwraps the JSON scalar to text — not `"Acquisition…"` with quotes, which is
    // what `::text` on a JSONB string would give and what a filter would then fail to match.
    let projected: String =
        sqlx::query_scalar("SELECT value_text FROM metadata_values WHERE field_id = $1")
            .bind(field.id)
            .fetch_one(&mut *tx)
            .await
            .expect("read the projection");
    assert_eq!(projected, "Acquisition of Northwind");

    // Updating the value moves the projection with it, without anything maintaining it.
    repo::set_value(
        &mut tx,
        alpha,
        ValueResourceKind::File,
        spine.file.as_uuid(),
        field.id,
        &json!("Disposal of Southgate"),
        UserId::from(Uuid::nil()),
        now,
    )
    .await
    .expect("update the value");
    let projected: String =
        sqlx::query_scalar("SELECT value_text FROM metadata_values WHERE field_id = $1")
            .bind(field.id)
            .fetch_one(&mut *tx)
            .await
            .expect("read the projection");
    assert_eq!(projected, "Disposal of Southgate");

    // And an insert that names the column is refused outright.
    let forced = sqlx::query(
        "INSERT INTO metadata_values
           (tenant_id, resource_type, resource_id, field_id, value, value_text, updated_by,
            updated_at)
         VALUES ($1, 'FILE', $2, $3, '\"a\"'::jsonb, 'something else', $4, $5)",
    )
    .bind(alpha.as_uuid())
    .bind(Uuid::now_v7())
    .bind(field.id)
    .bind(Uuid::nil())
    .bind(now)
    .execute(&mut *tx)
    .await;
    assert!(forced.is_err(), "value_text was writable, so the projection can be made to lie");

    tx.commit().await.expect("commit");
    drop(db);
}

/// A container has no single sortable projection, and inventing one would sort by whatever
/// `::text` happened to produce.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0009; CI runs it with --include-ignored"]
async fn a_container_value_projects_to_null_rather_than_to_its_rendering() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("spine");
    let field =
        define_field(&mut tx, alpha, "tags", FieldType::MultiChoice, &FieldConfig::default()).await;

    repo::set_value(
        &mut tx,
        alpha,
        ValueResourceKind::File,
        spine.file.as_uuid(),
        field.id,
        &json!(["a", "b"]),
        UserId::from(Uuid::nil()),
        now,
    )
    .await
    .expect("set the value");

    let projected: Option<String> =
        sqlx::query_scalar("SELECT value_text FROM metadata_values WHERE field_id = $1")
            .bind(field.id)
            .fetch_one(&mut *tx)
            .await
            .expect("read the projection");
    assert_eq!(projected, None);

    tx.commit().await.expect("commit");
    drop(db);
}

/// A reference to another tenant's file is unresolvable, and says nothing more than that.
///
/// # What this proves, and what it does not
///
/// It proves the *outcome*: alpha cannot resolve beta's file, and cannot tell that case apart from
/// an identifier that was never real. That is the property a `REFERENCE` field needs, and it is the
/// one worth asserting here.
///
/// It does **not** isolate which of the two isolation layers delivered it. Removing the
/// `tenant_id = $1` predicate from the lookup leaves this test passing, because forced RLS refuses
/// the row independently — which is the two-layer design of `docs/04-DATA-MODEL.md §3` behaving
/// exactly as intended, not a gap in the test. The layer-1 predicate is proven by T5 in
/// `docs/12-TESTING.md §4.1`, whose whole subject is that isolation survives the application
/// predicate being deliberately removed. Duplicating that here would test PostgreSQL twice and the
/// thing this file is about not at all.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0009; CI runs it with --include-ignored"]
async fn a_reference_cannot_resolve_across_tenants() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let now = Utc::now();

    // Beta has a file. Alpha will try to reference it.
    let beta_spine = Spine::new(beta);
    let mut tx = TenantScoped::begin(&pool, beta).await.expect("begin");
    beta_spine.insert(&mut tx, fixtures.beta.owner, now).await.expect("beta spine");
    tx.commit().await.expect("commit");

    let alpha_spine = Spine::new(alpha);
    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    alpha_spine.insert(&mut tx, fixtures.alpha.owner, now).await.expect("alpha spine");
    let field =
        define_field(&mut tx, alpha, "related", FieldType::Reference, &FieldConfig::default())
            .await;

    let own = Value::String(alpha_spine.file.as_uuid().to_string());
    let theirs = Value::String(beta_spine.file.as_uuid().to_string());
    let nobodys = Value::String(Uuid::now_v7().to_string());

    let resolved =
        repo::validate_references(&mut tx, alpha, &[(&field, &own)]).await.expect("resolve");
    assert!(resolved.is_empty(), "a file in the caller's own tenant did not resolve");

    let cross =
        repo::validate_references(&mut tx, alpha, &[(&field, &theirs)]).await.expect("resolve");
    let absent =
        repo::validate_references(&mut tx, alpha, &[(&field, &nobodys)]).await.expect("resolve");

    assert_eq!(cross, vec![("related".to_owned(), FieldViolation::UnresolvedReference)]);
    assert_eq!(
        cross, absent,
        "another tenant's file is distinguishable from one that never existed, which makes a \
         REFERENCE field an oracle for what exists over there"
    );

    tx.commit().await.expect("commit");
    drop(db);
}

/// A taxonomy value must come from the set its field names.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0009; CI runs it with --include-ignored"]
async fn a_taxonomy_value_must_come_from_the_configured_set() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let now = Utc::now();

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");

    let departments_id = Uuid::now_v7();
    let products_id = Uuid::now_v7();

    for (id, set, label) in
        [(departments_id, "Departments", "Legal"), (products_id, "Product lines", "Widgets")]
    {
        sqlx::query(
            "INSERT INTO taxonomy_terms (id, tenant_id, set_name, parent_id, label, path, created_at)
             VALUES ($1, $2, $3, NULL, $4, $4, $5)",
        )
        .bind(id)
        .bind(alpha.as_uuid())
        .bind(set)
        .bind(label)
        .bind(now)
        .execute(&mut *tx)
        .await
        .expect("insert term");
    }

    let config =
        FieldConfig { taxonomy_set: Some("Departments".to_owned()), ..FieldConfig::default() };
    let field = define_field(&mut tx, alpha, "department", FieldType::Taxonomy, &config).await;

    let right = Value::String(departments_id.to_string());
    let wrong = Value::String(products_id.to_string());

    assert!(repo::validate_references(&mut tx, alpha, &[(&field, &right)])
        .await
        .expect("resolve")
        .is_empty());
    assert_eq!(
        repo::validate_references(&mut tx, alpha, &[(&field, &wrong)]).await.expect("resolve"),
        vec![("department".to_owned(), FieldViolation::UnresolvedReference)],
        "a term from another set was accepted, so the facet this field drives mixes vocabularies"
    );

    tx.commit().await.expect("commit");
    drop(db);
}

/// Tenant-wide fields are found, which the NULL `scope_id` makes less obvious than it looks.
#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0001–0009; CI runs it with --include-ignored"]
async fn tenant_wide_fields_are_found_despite_their_null_scope() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;

    let mut tx = TenantScoped::begin(&pool, alpha).await.expect("begin");
    let field =
        define_field(&mut tx, alpha, "matter", FieldType::Text, &FieldConfig::default()).await;

    // NULL never equals NULL in a join, so a naive implementation returns nothing here — which
    // reads as "this tenant has defined no fields" rather than as a bug.
    let found = repo::fields_for_scopes(&mut tx, alpha, &[(FieldScope::Tenant, None)])
        .await
        .expect("read the fields");

    assert_eq!(found.len(), 1, "a tenant-wide field was invisible to a tenant-wide lookup");
    assert_eq!(found[0].id, field.id);
    assert_eq!(found[0].key, "matter");

    tx.commit().await.expect("commit");
    drop(db);
}
