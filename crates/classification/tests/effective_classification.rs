//! `ENC-574` — a file's effective classification, resolved from rows, in a deployment.
//!
//! Three things in this codebase took a `ClassificationRank` and none of them could be given one,
//! because `classifications` was created by no migration (`ENC-614`). These tests are about the
//! things that only exist once labels are rows.
//!
//! # What `docs/12-TESTING.md §1.2` demands of this file in particular
//!
//! *"An assertion about an absence passes for free."* Almost every property here is an absence —
//! one tenant's labels do not resolve for another's file, breaking permission inheritance does not
//! drop a label, a lower label below a higher one does not lower it. Each is therefore **paired in
//! the same test, over the same fixture, with a positive control** that resolves a real rank: if
//! the label set were unreachable, unwritable, or resolved to `None` for every input, the control
//! fails and the absence stops meaning anything.
//!
//! The most important pairing is `the_restricted_escalation_refuses_an_unscanned_document`. D27's
//! mandatory `FAIL_CLOSED` for `RESTRICTED` has been dead in every deployment since it was written,
//! and a test asserting "an unscanned `RESTRICTED` document is refused" proves nothing at all
//! unless something can actually label a file `RESTRICTED`. So that test labels one, through the
//! application role, and asserts the *identical* request over an *identical* unlabelled document is
//! permitted. One leg is the escalation; the other is the proof that the escalation, and not the
//! fixture, is what refused.
//!
//! Every assertion runs over the **application** role, never the harness superuser: a superuser
//! bypasses row-level security entirely, and a cross-tenant assertion run as one proves nothing
//! (PR #22, `ENC-124`).
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

// Assertions are the point of a test: a panic here is the failure signal, not a production hazard.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use enclave_classification::Classifications;
use enclave_core::ResourceKind;
use enclave_core::{
    Action, AuthorizationService, BarrierService, ClassificationId, ClassificationPolicy,
    ClassificationRank, ClassificationService, ConditionalAccessService, DetectorSetVersion, Error,
    Exposure, FactsPolicy, FactsSnapshot, FactsUnavailable, FileAction, FileId, LabelSource,
    Obligations, PolicyAuditSink, PolicyDecision, PolicyEngine, ReasonCode, RequestContext,
    ResourceRef, ResourceState, Result as CoreResult, RetentionService, SecurityFactsProvider,
    Stage, StageDecision, TenantId, Unlabelled, UserId, Utc, Uuid, VersionId,
};
use enclave_db::{
    assign_classification, define_classification, effective_classification, external_exposure,
    load_facts, resolve_content, withdraw_classification, DbPool, MAX_CHAIN_DEPTH,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

/// The shipped label set's ranks (`docs/01-PRD.md §17`). Named here rather than reached for as
/// constants so that every fixture's scale is visible in one place — the point of the table is that
/// they are the *tenant's* numbers, and a test that hid them would be asserting against a default.
const PUBLIC: i32 = 10;
const INTERNAL: i32 = 20;
const RESTRICTED: i32 = 50;

const DOWNLOAD: Action = Action::File(FileAction::Download);

// =================================================================================================
// Harness
// =================================================================================================

/// A migrated, seeded database and an application-role pool over it.
async fn harness() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(4).await.expect("application pool");
    (db, fixtures, pool)
}

/// Writes the workspace → library → folder → file spine.
async fn spine(conn: &mut PgConnection, tenant: TenantId, owner: UserId) -> Spine {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, Utc::now()).await.expect("write the content spine");
    spine
}

/// Commits one `AVAILABLE` version, so the file is content a scan could have facts about.
///
/// Without it `enclave_db::resolve_content` reports no version, which is *unscanned* — a legitimate
/// state, and one `a_labelled_file_with_no_committed_version_still_carries_its_label` covers on
/// purpose. The escalation tests want the ordinary case: a document with bytes that nobody has
/// scanned yet.
async fn commit_version(conn: &mut PgConnection, tenant: TenantId, spine: Spine, owner: UserId) {
    let version = VersionId::new_v7();
    sqlx::query(
        "INSERT INTO file_versions
           (id, tenant_id, file_id, object_key, storage_profile_id, size_bytes, checksum_sha256,
            mime_type, major, minor, status, created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 11, 'sha256-fixture', 'text/plain', 1, 0, 'AVAILABLE', $6, $7)",
    )
    .bind(version.as_uuid())
    .bind(tenant.as_uuid())
    .bind(spine.file.as_uuid())
    .bind(format!("fixture/{}", version.as_uuid()))
    .bind(Uuid::now_v7())
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("write the version");

    sqlx::query("UPDATE files SET current_version_id = $1 WHERE id = $2")
        .bind(version.as_uuid())
        .bind(spine.file.as_uuid())
        .execute(&mut *conn)
        .await
        .expect("point the file at its version");
}

/// Defines a label in a tenant's set, **through the application role**.
///
/// Through the role rather than through the harness connection deliberately: the whole of
/// `ENC-614` is that no deployment could produce a rank, and a fixture that wrote labels as
/// superuser would prove the resolver works while leaving the grant and the policy untested.
async fn define(pool: &DbPool, tenant: TenantId, key: &str, rank: i32) -> ClassificationId {
    let id = ClassificationId::new_v7();
    let mut tx = pool.begin(tenant).await.expect("begin");
    define_classification(&mut tx, id, key, key, ClassificationRank::new(rank))
        .await
        .expect("define the label");
    tx.commit().await.expect("commit");
    id
}

/// Attaches a label to a file or folder, through the application role.
async fn assign(pool: &DbPool, tenant: TenantId, file: FileId, label: ClassificationId) {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let applied =
        assign_classification(&mut tx, file, Some(label)).await.expect("assign the label");
    tx.commit().await.expect("commit");
    assert!(applied, "the label was not attached to {file}, so nothing below is being tested");
}

/// The rank the walk resolves for a file, under one tenant's row-level-security context.
async fn resolve(pool: &DbPool, tenant: TenantId, file: FileId) -> Option<(i32, LabelSource)> {
    let mut tx = pool.begin(tenant).await.expect("begin");
    let effective = effective_classification(&mut tx, file).await.expect("resolve");
    tx.commit().await.expect("commit");
    effective.map(|e| (e.rank().get(), e.source()))
}

// =================================================================================================
// The walk
// =================================================================================================

/// The positive control every absence in this file leans on: a label written through the
/// application role comes back as the rank it was written with.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_label_written_through_the_application_role_resolves_to_its_rank() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, content.file, restricted).await;

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Resource)),
        "a label written through the application role must resolve to its rank; if this fails, \
         every absence asserted in this file is passing for free (ENC-614)"
    );
}

/// A file with no label anywhere on its chain is **unresolved**, and unresolved is not a rank.
///
/// Both halves matter. The walk returns `None` — not `PUBLIC`, not the lowest defined label, not
/// the highest — and `ClassificationResolution` keeps it a state: `rank()` stays `None` under both
/// tenant policies, so nothing downstream can read an assumption as a reading.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_file_with_no_label_is_unresolved_and_is_not_public() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    // The label set exists and is reachable — the control. `PUBLIC` is defined and deliberately
    // attached to nothing, so "unresolved" cannot be confused with "there were no labels to find".
    let public = define(&pool, alpha, "PUBLIC", PUBLIC).await;
    let labelled = spine(&mut conn, alpha, fixtures.alpha.owner).await;
    assign(&pool, alpha, labelled.file, public).await;
    assert_eq!(resolve(&pool, alpha, labelled.file).await, Some((PUBLIC, LabelSource::Resource)));

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        None,
        "an unlabelled file must resolve to nothing at all. Returning the lowest defined rank is \
         the S8 breach arriving through a constant that looks reasonable (ENC-574)"
    );

    let resolver = Classifications::new(pool.clone(), ClassificationPolicy::fail_closed());
    let unlabelled = resolver.resolve(alpha, content.file).await.expect("resolve");
    assert_eq!(unlabelled.rank(), None, "fail-closed must not manufacture a rank");
    assert!(
        unlabelled.require(DOWNLOAD).into_denial().is_some(),
        "FAIL_CLOSED must refuse rather than proceed on a number nobody wrote"
    );

    let assuming = Classifications::new(
        pool.clone(),
        ClassificationPolicy::from_tenant_config(Unlabelled::Assume(ClassificationRank::new(
            INTERNAL,
        ))),
    );
    let assumed = assuming.resolve(alpha, content.file).await.expect("resolve");
    assert_eq!(
        assumed.rank(),
        None,
        "an assumed rank must never appear as a *read* rank: ResourceState's contract is that None \
         means the resource genuinely has no label, and an assumption laundered through it would \
         make the RESTRICTED escalation fire on a rank this codebase inferred"
    );
    match assumed.require_for_indexing() {
        enclave_core::ClassificationOutcome::Assumed(allow) => {
            assert_eq!(allow.rank().get(), INTERNAL, "the tenant's rank, not one we picked");
        }
        other => panic!("a tenant that configured Assume must get one: {other:?}"),
    }
}

/// A document in a labelled folder is labelled, whether or not anyone stamped the document.
///
/// This is the whole of the word *effective*. Paired with the file's own resolution beforehand, so
/// "the folder's label reached it" is distinguishable from "the walk returns 50 for everything".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_label_on_the_folder_reaches_the_file_below_it() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    assert_eq!(resolve(&pool, alpha, content.file).await, None, "nothing is labelled yet");

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, content.folder, restricted).await;

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Ancestor)),
        "a file inside a RESTRICTED folder is restricted; the source must say ANCESTOR so an \
         administrator is sent to the folder rather than to the document"
    );
}

/// `ENC-141`, transposed onto labels.
///
/// Breaking permission inheritance was privilege escalation once already: the flag flip truncated
/// the ACL resolver's walk, so an ancestor `DENY` stopped applying. The analogous mistake here is a
/// label walk that stops at `inherit_permissions = FALSE`, and it is worse in one respect —
/// breaking ACL inheritance at least *materialises* the effective entries onto the node, whereas
/// nothing materialises a label. A truncated label walk drops the ancestor's `RESTRICTED` outright.
///
/// The break is applied through the same column `enclave_authorization::break_file_inheritance`
/// flips, and the assertion is that the rank is unchanged by it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn breaking_permission_inheritance_does_not_drop_an_inherited_label() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, content.folder, restricted).await;

    // The control: it resolves before the break, so a failure afterwards is the break's doing.
    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Ancestor))
    );

    sqlx::query("UPDATE files SET inherit_permissions = FALSE WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.as_uuid())
        .bind(content.file.as_uuid())
        .execute(&mut conn)
        .await
        .expect("break permission inheritance on the file");

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Ancestor)),
        "breaking permission inheritance must not declassify. inherit_permissions is a permissions \
         flag and nothing materialises a label when it is flipped, so a walk that honoured it would \
         hand a RESTRICTED document a lower rank through a documented, supported operation — \
         ENC-141 one control over"
    );
}

/// A label below a more sensitive one does not lower it.
///
/// Nearest-wins would let a `PUBLIC` document filed inside a `RESTRICTED` folder read as public,
/// which is declassification through an ordinary move. The rank on the chain is a floor.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_lower_label_below_a_higher_one_does_not_lower_the_result() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let public = define(&pool, alpha, "PUBLIC", PUBLIC).await;
    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;

    // The control: `PUBLIC` on its own resolves as `PUBLIC`, so the assertion below is about
    // composition rather than about the label being unreachable.
    assign(&pool, alpha, content.file, public).await;
    assert_eq!(resolve(&pool, alpha, content.file).await, Some((PUBLIC, LabelSource::Resource)));

    assign(&pool, alpha, content.folder, restricted).await;

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Ancestor)),
        "the most sensitive label on the chain wins. Nearest-wins would declassify every document \
         somebody files in a public subfolder of a restricted tree"
    );
}

/// The library's default is part of the chain, and the workspace's is above it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_library_and_workspace_defaults_are_part_of_the_chain() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let internal = define(&pool, alpha, "INTERNAL", INTERNAL).await;
    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;

    assert_eq!(resolve(&pool, alpha, content.file).await, None, "nothing is labelled yet");

    sqlx::query(
        "UPDATE workspaces SET default_classification_id = $1 WHERE tenant_id = $2 AND id = $3",
    )
    .bind(internal.as_uuid())
    .bind(alpha.as_uuid())
    .bind(content.workspace.as_uuid())
    .execute(&mut conn)
    .await
    .expect("set the workspace default");

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((INTERNAL, LabelSource::Workspace)),
        "a workspace default is the tenant's expressed intent for everything under it"
    );

    sqlx::query(
        "UPDATE libraries SET default_classification_id = $1 WHERE tenant_id = $2 AND id = $3",
    )
    .bind(restricted.as_uuid())
    .bind(alpha.as_uuid())
    .bind(content.library.as_uuid())
    .execute(&mut conn)
    .await
    .expect("set the library default");

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Library)),
        "the more sensitive of the two defaults wins, and the source names the one to edit"
    );
}

/// Withdrawing a label does not declassify the content carrying it.
///
/// The migration withholds `DELETE` because deleting a label declassifies in bulk. Withdrawal is
/// the granted door, and if it declassified too the missing grant would be decoration.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn withdrawing_a_label_does_not_declassify_content_carrying_it() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, content.file, restricted).await;
    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Resource))
    );

    let mut tx = pool.begin(alpha).await.expect("begin");
    let withdrawn = withdraw_classification(&mut tx, restricted).await.expect("withdraw");
    tx.commit().await.expect("commit");
    assert!(withdrawn, "the label must actually have been withdrawn, or nothing below is tested");

    assert_eq!(
        resolve(&pool, alpha, content.file).await,
        Some((RESTRICTED, LabelSource::Resource)),
        "withdrawal governs whether a label may be assigned, not what it means for content already \
         carrying it. A withdrawal that declassified would be the bulk declassification the missing \
         DELETE grant exists to prevent, through the door that is granted"
    );
}

/// A chain deeper than the cap is **refused**, not answered.
///
/// `enclave_authorization` refuses a truncated ACL chain because the ancestors it did not reach are
/// the ones carrying organisation-wide denials. Here it is one direction worse: the nodes nearest
/// the root are where a tenant-wide `RESTRICTED` folder sits, so a truncated walk under-reports
/// sensitivity — and `Ok(None)` would mean *unlabelled*, which a tenant on
/// `Unlabelled::Assume` proceeds on as though the walk had finished.
///
/// Paired with a chain one node inside the cap that resolves the same label from the same place, so
/// the error is the depth and not the fixture.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_chain_deeper_than_the_cap_is_refused_rather_than_answered() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");
    let base = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, base.folder, restricted).await;

    // The control: a leaf exactly at the cap resolves the label at the top of its chain. `depth 0`
    // is the leaf itself and the walk may take `MAX_CHAIN_DEPTH` steps, so a stack of
    // `MAX_CHAIN_DEPTH - 1` folders above the labelled one is the deepest chain that fits.
    let inside =
        deep_chain(&mut conn, alpha, base, fixtures.alpha.owner, (MAX_CHAIN_DEPTH - 1) as usize)
            .await;
    assert_eq!(
        resolve(&pool, alpha, inside).await,
        Some((RESTRICTED, LabelSource::Ancestor)),
        "a chain within the cap must resolve, or the error below is about the fixture"
    );

    let outside =
        deep_chain(&mut conn, alpha, base, fixtures.alpha.owner, (MAX_CHAIN_DEPTH + 4) as usize)
            .await;
    let mut tx = pool.begin(alpha).await.expect("begin");
    let truncated = effective_classification(&mut tx, outside).await;
    tx.commit().await.expect("commit");

    assert!(
        truncated.is_err(),
        "a walk that hit the cap with more tree above it has not seen the chain. Answering `no \
         label` would hand the caller an unlabelled verdict for a document filed under a RESTRICTED \
         folder it never reached"
    );
}

/// Stacks `depth` folders above `base.folder`, and returns the leaf file at the bottom.
async fn deep_chain(
    conn: &mut PgConnection,
    tenant: TenantId,
    base: Spine,
    owner: UserId,
    depth: usize,
) -> FileId {
    let mut parent = base.folder;
    for _ in 0..depth {
        let node = FileId::new_v7();
        insert_node(conn, tenant, base, owner, node, Some(parent), "FOLDER").await;
        parent = node;
    }
    let leaf = FileId::new_v7();
    insert_node(conn, tenant, base, owner, leaf, Some(parent), "FILE").await;
    leaf
}

async fn insert_node(
    conn: &mut PgConnection,
    tenant: TenantId,
    base: Spine,
    owner: UserId,
    id: FileId,
    parent: Option<FileId>,
    node_type: &str,
) {
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, inherit_permissions, created_by, modified_by, created_at, modified_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 'application/octet-stream', TRUE, $8, $8, $9, $9)",
    )
    .bind(id.as_uuid())
    .bind(tenant.as_uuid())
    .bind(base.workspace.as_uuid())
    .bind(base.library.as_uuid())
    .bind(parent.map(|p| p.as_uuid()))
    .bind(node_type)
    .bind(id.as_uuid().to_string())
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("write a chain node");
}

/// `enclave_app` cannot delete a label, only withdraw one.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_cannot_delete_a_label() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;

    let mut tx = pool.begin(alpha).await.expect("begin");
    let refused = sqlx::query("DELETE FROM classifications WHERE tenant_id = $1 AND id = $2")
        .bind(alpha.as_uuid())
        .bind(restricted.as_uuid())
        .execute(&mut *tx)
        .await;

    assert!(
        refused.is_err(),
        "the application role holds no DELETE on classifications: one statement declassifies every \
         document carrying a label and orphans every rank already copied into security_facts and \
         the vector collection"
    );
}

/// One tenant's labels never resolve for another tenant's file, in either direction.
///
/// The absence is paired twice. `alpha` resolves its own file to a real rank in the same run, so
/// "beta sees nothing" is not "the walk sees nothing"; and the composite foreign key is asserted
/// directly, because the two mechanisms fail differently — row-level security makes the row
/// invisible, and the key makes the row unwritable.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_labels_never_resolve_for_another_tenants_file() {
    let (_db, fixtures, pool) = harness().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let mut conn = _db.connect().await.expect("harness connection");

    let alpha_content = spine(&mut conn, alpha, fixtures.alpha.owner).await;
    let beta_content = spine(&mut conn, beta, fixtures.beta.owner).await;

    // The same key and the same rank in both tenants — `docs/12 §3`: beta mirrors alpha's names so
    // a test cannot pass because the other tenant's rows were called something else.
    let alpha_restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    let beta_restricted = define(&pool, beta, "RESTRICTED", RESTRICTED).await;

    assign(&pool, alpha, alpha_content.file, alpha_restricted).await;

    // Control: within its own tenant, the label resolves.
    assert_eq!(
        resolve(&pool, alpha, alpha_content.file).await,
        Some((RESTRICTED, LabelSource::Resource))
    );

    // `beta` asking about `alpha`'s file gets nothing, which is what `CLAUDE.md` rule 7 requires
    // everywhere else too: a cross-tenant miss is indistinguishable from an absence.
    assert_eq!(
        resolve(&pool, beta, alpha_content.file).await,
        None,
        "one tenant's classification walk must not reach another tenant's file"
    );

    // Control for the line above: beta's own file, labelled with beta's own label, does resolve —
    // so the `None` is about the tenant boundary and not about beta's context being broken.
    assign(&pool, beta, beta_content.file, beta_restricted).await;
    assert_eq!(
        resolve(&pool, beta, beta_content.file).await,
        Some((RESTRICTED, LabelSource::Resource))
    );

    // The other mechanism: the composite key refuses the write outright. Attempted as the harness
    // superuser, deliberately — row-level security does not apply to it, so what refuses here can
    // only be `files_classification_fkey`, which is the constraint under test.
    let cross = sqlx::query("UPDATE files SET classification_id = $1 WHERE id = $2")
        .bind(beta_restricted.as_uuid())
        .bind(alpha_content.file.as_uuid())
        .execute(&mut conn)
        .await;
    assert!(
        cross.is_err(),
        "a composite foreign key must refuse another tenant's label on this tenant's file. \
         PostgreSQL runs referential-integrity checks with row security deliberately not enforced, \
         so a single-column REFERENCES classifications (id) would have accepted this"
    );
}

// =================================================================================================
// D27's `RESTRICTED` escalation, in a deployment
// =================================================================================================

/// The provider `enclave_dlp::PgSecurityFacts` becomes with `ENC-574` applied.
///
/// It is reproduced here rather than imported because `crates/dlp` belongs to another session. The
/// difference from the shipped type is **one line**: where `PgSecurityFacts::gather` writes
///
/// ```text
///     let state = ResourceState::new(exposure, None);   // ENC-614: no table to resolve a label
/// ```
///
/// this writes
///
/// ```text
///     let classification = effective_classification(&mut tx, file).await.map_err(Error::from)?;
///     let state = ResourceState::new(exposure, classification.map(|c| c.rank()));
/// ```
///
/// in the **same transaction** as the facts and the exposure, which is `ENC-614`'s own closing
/// requirement and D26's: *"the rank must be read in the same transaction as the facts, or two
/// stages can answer it differently."*
#[derive(Debug, Clone)]
struct FactsWithLabels {
    pool: DbPool,
    active_set: DetectorSetVersion,
    policy: FactsPolicy,
}

#[async_trait]
impl SecurityFactsProvider for FactsWithLabels {
    async fn gather(
        &self,
        ctx: &RequestContext,
        _action: Action,
        resource: &ResourceRef,
    ) -> CoreResult<FactsSnapshot> {
        let mut tx = self.pool.begin(ctx.tenant_id).await.map_err(Error::from)?;

        let resolved =
            resolve_content(&mut tx, resource.kind, resource.id).await.map_err(Error::from)?;

        // The label belongs to the **resource**, not to its content, so it is resolved before the
        // version lookup is allowed to bail out. A file whose first upload has not committed has no
        // version and therefore no facts — but it may sit in a `RESTRICTED` folder, and a `gather`
        // that returned early would hand the chain `None` for a document whose label is right there
        // in the database. That is `ENC-591`'s mistake with a different cause.
        let labelled = match resource.kind {
            ResourceKind::File | ResourceKind::Folder => Some(FileId::from_uuid(resource.id)),
            _ => resolved.map(|(file, _)| file),
        };
        let classification = match labelled {
            Some(file) => effective_classification(&mut tx, file).await.map_err(Error::from)?,
            None => None,
        };
        let rank = classification.map(|c| c.rank());

        let Some((file, version)) = resolved else {
            tx.commit().await.map_err(Error::from)?;
            return Ok(FactsSnapshot::missing(
                self.policy,
                ResourceState::new(Exposure::Internal, rank),
            ));
        };

        let facts = load_facts(&mut tx, file, version).await.map_err(Error::from)?;
        let exposure = if external_exposure(&mut tx, file).await.map_err(Error::from)? {
            Exposure::External
        } else {
            Exposure::Internal
        };
        tx.commit().await.map_err(Error::from)?;

        let state = ResourceState::new(exposure, rank);

        Ok(match facts {
            Some(facts) => FactsSnapshot::gathered(facts, &self.active_set, self.policy, state),
            None => FactsSnapshot::missing(self.policy, state),
        })
    }
}

/// Every stage but DLP allows, so a refusal can only have come from DLP.
#[derive(Debug, Clone, Copy)]
struct AllowAll;

#[async_trait]
impl ConditionalAccessService for AllowAll {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }
}

#[async_trait]
impl AuthorizationService for AllowAll {
    async fn authorize(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }

    async fn authorize_many(
        &self,
        _: &RequestContext,
        _: Action,
        resources: &[ResourceRef],
    ) -> CoreResult<Vec<StageDecision>> {
        Ok(resources.iter().map(|_| StageDecision::allow()).collect())
    }
}

#[async_trait]
impl BarrierService for AllowAll {
    async fn evaluate(&self, _: &RequestContext, _: &ResourceRef) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }

    async fn allowed_barrier_tokens(&self, _: &RequestContext) -> CoreResult<Vec<String>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl ClassificationService for AllowAll {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }
}

#[async_trait]
impl RetentionService for AllowAll {
    async fn evaluate(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
    ) -> CoreResult<StageDecision> {
        Ok(StageDecision::allow())
    }
}

/// A DLP stage that does nothing but ask the snapshot the question D27 is about.
///
/// It governs every action it is asked about — deliberately, because the subject here is the
/// mandatory escalation rather than a rule set. `FactsSnapshot::require` is the whole of the stage,
/// which is what makes a refusal attributable to `FactsPolicy::is_forced_closed` and nothing else.
#[derive(Debug, Clone, Copy)]
struct RequiresFacts;

#[async_trait]
impl enclave_core::DlpService for RequiresFacts {
    async fn evaluate(
        &self,
        _: &RequestContext,
        action: Action,
        _: &ResourceRef,
        facts: &FactsSnapshot,
    ) -> CoreResult<StageDecision> {
        match facts.require(action) {
            enclave_core::FactsOutcome::Facts(_) => Ok(StageDecision::allow()),
            enclave_core::FactsOutcome::Denied { code, remediation } => {
                Err(Error::denied_with(code, remediation))
            }
            enclave_core::FactsOutcome::Unscanned(allow) => {
                // Discharged: the audit event this stands for is `crates/dlp`'s, and dropping the
                // value silently would be the defect `#[must_use]` exists to prevent.
                let _staleness = allow.staleness();
                Ok(StageDecision::allow())
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct NoAudit;

#[async_trait]
impl PolicyAuditSink for NoAudit {
    async fn record_allow(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
        _: &Obligations,
    ) -> CoreResult<()> {
        Ok(())
    }

    async fn record_deny(
        &self,
        _: &RequestContext,
        _: Action,
        _: &ResourceRef,
        _: Stage,
        _: ReasonCode,
    ) -> CoreResult<()> {
        Ok(())
    }
}

/// The chain `crates/api` assembles, with every stage but DLP allowing, the tenant on
/// `FAIL_OPEN_AUDIT`, and the facts provider `ENC-574` makes possible.
///
/// `FAIL_OPEN_AUDIT` is the configuration in which the mandatory escalation is the **only** thing
/// that can refuse: without facts and without a label, this chain permits everything. That is what
/// makes each test's permitted leg a control rather than decoration.
///
/// `restricted_at` is passed as tenant configuration rather than assumed, honouring
/// `ClassificationRank`'s "ranks are tenant-defined": the fixture's `RESTRICTED` is 50 because this
/// tenant's label set says so, not because the constant does.
fn escalating_engine(pool: &DbPool) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(RequiresFacts),
        Arc::new(AllowAll),
        Arc::new(NoAudit),
    )
    .with_facts(Arc::new(FactsWithLabels {
        pool: pool.clone(),
        active_set: DetectorSetVersion::new("test-set".to_owned()),
        policy: FactsPolicy::from_tenant_config(
            FactsUnavailable::FailOpenAudit,
            ClassificationRank::new(RESTRICTED),
        ),
    }) as Arc<dyn SecurityFactsProvider>)
}

/// **`ENC-614` closed.** D27's mandatory `FAIL_CLOSED` for `RESTRICTED` fires on a document nobody
/// has scanned, because something can finally label one.
///
/// The tenant is on `FAIL_OPEN_AUDIT`, which is the configuration in which the escalation is the
/// *only* thing that can refuse: without facts and without a label, the chain permits. So the two
/// legs differ in exactly one fact about the world — whether a row in `classifications` is attached
/// to the file — and that difference is the whole assertion.
///
/// `restricted_at` is passed as tenant configuration rather than assumed, honouring
/// `ClassificationRank`'s "ranks are tenant-defined": the fixture's `RESTRICTED` is 50 because this
/// tenant's label set says so.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_restricted_escalation_refuses_an_unscanned_document() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");

    let labelled = spine(&mut conn, alpha, fixtures.alpha.owner).await;
    let unlabelled = spine(&mut conn, alpha, fixtures.alpha.owner).await;
    commit_version(&mut conn, alpha, labelled, fixtures.alpha.owner).await;
    commit_version(&mut conn, alpha, unlabelled, fixtures.alpha.owner).await;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, labelled.file, restricted).await;

    let engine = escalating_engine(&pool);

    // The control, and it is the leg that must pass for the other to mean anything: with no label
    // and no facts, `FAIL_OPEN_AUDIT` permits. If this refused, the test below would be asserting
    // that the chain refuses everything.
    assert!(
        !refused(&engine, alpha, DOWNLOAD, unlabelled.file_ref()).await,
        "FAIL_OPEN_AUDIT permits an unscanned, unlabelled document — otherwise the refusal below \
         is not the escalation"
    );

    assert!(
        refused(&engine, alpha, DOWNLOAD, labelled.file_ref()).await,
        "D27: FAIL_CLOSED is mandatory at and above the rank a tenant calls RESTRICTED, whatever \
         facts_unavailable says. This is the escalation ENC-591 built, ENC-582 fixed and ENC-614 \
         reported as dead in every deployment — it can only fire once a table resolves a label \
         into a rank"
    );
}

/// The escalation follows the **inherited** label too.
///
/// Otherwise `ENC-614` would be closed for documents somebody remembered to stamp and open for
/// every document in a restricted folder, which is the majority of them.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_restricted_escalation_follows_an_inherited_label() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");

    let content = spine(&mut conn, alpha, fixtures.alpha.owner).await;
    commit_version(&mut conn, alpha, content, fixtures.alpha.owner).await;

    let engine = escalating_engine(&pool);

    // Control: before the folder is labelled, the same request over the same file is permitted.
    assert!(!refused(&engine, alpha, DOWNLOAD, content.file_ref()).await);

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, content.folder, restricted).await;

    assert!(
        refused(&engine, alpha, DOWNLOAD, content.file_ref()).await,
        "a document inside a RESTRICTED folder is RESTRICTED, and the escalation must see the \
         effective rank rather than only the one stamped on the row"
    );
}

/// A file whose first upload has not committed still carries its label.
///
/// This is the case that makes the `PgSecurityFacts` change **more than one line**, and it is
/// recorded because the obvious patch gets it wrong. `resolve_content` reports no version for such
/// a file, and the shipped `gather` returns early on that — so a patch that resolved the label
/// *after* the early return would hand the chain `None` for a `RESTRICTED` document whose label is
/// sitting in the database. The label belongs to the resource, not to its content, so it is read
/// before the version lookup is allowed to bail out.
///
/// Paired, as everything here is: the same request over an unlabelled version-less file is
/// permitted, so the refusal is the label's doing rather than the missing version's.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_labelled_file_with_no_committed_version_still_carries_its_label() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = _db.connect().await.expect("harness connection");

    // Neither file gets a version — `Spine::insert` leaves `current_version_id` NULL.
    let labelled = spine(&mut conn, alpha, fixtures.alpha.owner).await;
    let unlabelled = spine(&mut conn, alpha, fixtures.alpha.owner).await;

    let restricted = define(&pool, alpha, "RESTRICTED", RESTRICTED).await;
    assign(&pool, alpha, labelled.file, restricted).await;

    let engine = escalating_engine(&pool);

    assert!(
        !refused(&engine, alpha, DOWNLOAD, unlabelled.file_ref()).await,
        "a version-less, unlabelled file is unscanned and unremarkable under FAIL_OPEN_AUDIT"
    );
    assert!(
        refused(&engine, alpha, DOWNLOAD, labelled.file_ref()).await,
        "the label is a property of the resource. A file with no committed version has no facts, \
         but it still has a classification, and the escalation must see it"
    );
}

/// Runs the chain, discharging the decision either way (`CLAUDE.md` rule 8).
///
/// Panics on any failure that is not a policy denial, so a test cannot read an internal error — a
/// broken statement, say — as a refusal.
async fn refused(engine: &PolicyEngine, tenant: TenantId, action: Action, on: ResourceRef) -> bool {
    let ctx = RequestContext::system(tenant);
    match engine.enforce(&ctx, action, &on).await.map(PolicyDecision::into_obligations) {
        Ok(obligations) => {
            let _count = obligations.len();
            false
        }
        Err(Error::PolicyDenied { .. }) => true,
        Err(other) => panic!("the chain failed rather than deciding: {other:?}"),
    }
}
