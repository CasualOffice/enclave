//! `ENC-594` — the DLP stage decides from **stored** facts, for one tenant at a time.
//!
//! `tests/modes.rs` proved the modes against a provider that hands the engine a prepared
//! `FactsSnapshot`. These tests are about the two things that only exist once the facts are rows:
//! that the stage `crates/api/src/main.rs` now wires refuses something a running deployment would
//! have permitted, and that one tenant's facts never decide another tenant's request.
//!
//! # Every test here would pass against `DisabledDlp` unless it refuses something
//!
//! That is the trap `ENC-590` had to avoid with `UnconfiguredConditionalAccess`, and it is
//! `docs/12-TESTING.md §1.2`'s shape again: "the request succeeded" holds against a stage that
//! decides nothing at all. So the *positive* leg comes first in every test — a refusal that could
//! only have come from a rule evaluated against a row read out of `security_facts` — and each
//! permitted leg is paired with it in the same run, over the same engine, so "allowed" means the
//! rule did not fire rather than the stage was never asked.
//!
//! Every assertion runs over the **application** role, never the harness superuser: a superuser
//! bypasses row-level security, and a cross-tenant assertion run as one proves nothing (PR #22,
//! `ENC-124`).
//!
//! # Which mechanism `one_tenants_facts_never_decide_another_tenants_request` proves
//!
//! Recorded because two deliberate breaks did **not** fail it, which `docs/12 §1.2` says is a
//! finding rather than a shrug. Removing `enclave_db::security_facts`'s `tenant_id = $1` predicate
//! leaves it green, and so does removing that predicate *and* weakening this table's row-level
//! security to `USING (true)` — because a fact row is reached through two lookups, not one. The
//! resource is resolved to a version first, through `files`, and that read is still scoped; the
//! keys it yields are globally unique, so a load that has lost its own tenant predicate is still
//! looking up identifiers that only exist in the tenant that asked.
//!
//! So this test proves *isolation of the path*, not any single predicate. It is not vacuous: with
//! the predicates removed from **both** statements and the `files` policy weakened as well, it
//! fails with *"alpha's fact row was readable from a tenant-beta request: left: Fresh, right:
//! Missing"*. The individual predicates are held by `enclave_db::security_facts`'s own
//! `every_statement_is_scoped_to_one_tenant`, which fails on the first break alone.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

// Assertions are the point of a test: a panic here is the failure signal, not a production hazard.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use async_trait::async_trait;
use enclave_core::{
    Action, AuthorizationService, BarrierService, ClassificationId, ClassificationRank,
    ClassificationService, ConditionalAccessService, DetectorCategory, DetectorCounts,
    DetectorSetVersion, DlpService, Error, Exposure, FactsPolicy, FactsSnapshot, FactsStaleness,
    FactsUnavailable, FileAction, FileId, Obligations, PolicyAuditSink, PolicyDecision,
    PolicyEngine, ReasonCode, RequestContext, ResourceRef, Result as CoreResult, RetentionService,
    ScanVersion, SecurityFacts, SecurityFactsProvider, ShareAction, Stage, StageDecision, TenantId,
    Utc, Uuid, VersionId,
};
use enclave_db::{assign_classification, define_classification, record_facts, DbPool};
use enclave_dlp::policy::{ActionScope, Condition, DlpAction, DlpRule, RuleId, RuleSet};
use enclave_dlp::{
    builtin_set, DisabledDlp, DlpMode, ModedDlp, ObservationSink, PgSecurityFacts,
    TracingObservations,
};
use enclave_testing::content::Spine;
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

const EXTERNAL_SHARE: Action = Action::File(FileAction::ShareExternal);
const DOWNLOAD: Action = Action::File(FileAction::Download);
const CHANGE_SHARE: Action = Action::Share(ShareAction::Update);

// =================================================================================================
// Harness — every stage but DLP allows, so a refusal can only have come from DLP.
// =================================================================================================

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

/// Audit is asserted by `crates/audit`'s own suite; here it must simply not fail the chain.
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

// =================================================================================================
// Fixtures
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

/// A spine with a committed version, which is what a fact row can hang off.
///
/// `Spine::insert` writes the workspace, library, folder and file; `file_versions` and the file's
/// `current_version_id` are written here, because a file with no committed version has no facts by
/// definition and every test below is about a file that does.
async fn content(
    conn: &mut PgConnection,
    tenant: TenantId,
    owner: enclave_core::UserId,
) -> Content {
    let spine = Spine::new(tenant);
    spine.insert(conn, owner, Utc::now()).await.expect("write the content spine");

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

    Content { spine, version }
}

/// A file with one committed version.
#[derive(Debug, Clone, Copy)]
struct Content {
    spine: Spine,
    version: VersionId,
}

impl Content {
    fn file_ref(&self) -> ResourceRef {
        self.spine.file_ref()
    }
}

/// Hangs a share link over a resource, so the exposure read has something to find.
async fn share_link(
    conn: &mut PgConnection,
    tenant: TenantId,
    resource_type: &str,
    resource_id: Uuid,
    audience: &str,
    owner: enclave_core::UserId,
) {
    sqlx::query(
        "INSERT INTO share_links
           (id, tenant_id, resource_type, resource_id, token_hash, permission, audience,
            created_by, created_at)
         VALUES ($1, $2, $3, $4, $5, 'VIEW', $6, $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(tenant.as_uuid())
    .bind(resource_type)
    .bind(resource_id)
    // A hash, never a token: `crates/sharing` mints the plaintext and hands it back once. This
    // fixture needs a unique string in the column and nothing else.
    .bind(format!("fixture-{}", Uuid::now_v7()))
    .bind(audience)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .execute(&mut *conn)
    .await
    .expect("write the share link");
}

/// Facts as a completed scan would have left them, stamped with `set`.
fn scanned(content: Content, financial: u32, set: &str) -> SecurityFacts {
    let mut counts = DetectorCounts::none();
    counts.add(DetectorCategory::Financial, financial);
    SecurityFacts::scanned(
        content.spine.file,
        content.version,
        counts,
        DetectorSetVersion::new(set),
        ScanVersion::new(1),
        Utc::now(),
    )
}

/// Writes facts through the application role, exactly as a scanner would.
async fn store(pool: &DbPool, tenant: TenantId, facts: &SecurityFacts) {
    let mut tx = pool.begin(tenant).await.expect("begin");
    record_facts(&mut tx, facts).await.expect("write the fact row");
    tx.commit().await.expect("commit");
}

/// The active detector set — the one `main.rs` passes, so these tests run the deployment's answer
/// rather than a value of their own.
fn active() -> DetectorSetVersion {
    builtin_set().version().clone()
}

/// **Block external sharing of anything carrying payment data** — `docs/12 §4.5` D1's rule.
///
/// Scoped to external sharing rather than to everything, which is what lets every test below tell
/// "the rule did not fire" from "the stage denied nothing": a download is never governed by it, so
/// a stage that refused everything would fail the download leg.
fn payment_data_rule() -> RuleSet {
    RuleSet::new(vec![DlpRule::new(
        RuleId::new("block-external-share-of-payment-data"),
        vec![ActionScope::ExternalSharing],
        vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }],
        DlpAction::Block,
    )])
}

/// **Block download of anything carrying payment data.**
///
/// The companion to [`payment_data_rule`], and the reason it exists is D27: external sharing is
/// forced closed *whatever* `facts_unavailable` says, so a rule scoped to external sharing cannot
/// be used to observe `FAIL_OPEN_AUDIT` at all. A download is a governed action that the mandatory
/// escalations have nothing to say about, which is the only place the configured policy is visible.
fn payment_download_rule() -> RuleSet {
    RuleSet::new(vec![DlpRule::new(
        RuleId::new("block-download-of-payment-data"),
        vec![ActionScope::Exactly(DOWNLOAD)],
        vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }],
        DlpAction::Block,
    )])
}

fn provider(pool: &DbPool, unavailable: FactsUnavailable) -> Arc<PgSecurityFacts> {
    Arc::new(PgSecurityFacts::new(
        pool.clone(),
        active(),
        FactsPolicy::from_tenant_config(unavailable, ClassificationRank::RESTRICTED),
    ))
}

/// The chain as `main.rs` assembles it: every other stage allows, DLP is `ModedDlp` in `mode`, and
/// the facts come from PostgreSQL.
fn engine(pool: &DbPool, mode: DlpMode, unavailable: FactsUnavailable) -> PolicyEngine {
    engine_running(pool, mode, unavailable, payment_data_rule())
}

/// The same, over a named rule set.
///
/// A separate entry point rather than a parameter on every call site, because the rule set is the
/// one thing most of these tests do *not* vary — and a test that quietly ran different rules from
/// its neighbours would be the hardest kind of green to interpret.
fn engine_running(
    pool: &DbPool,
    mode: DlpMode,
    unavailable: FactsUnavailable,
    rules: RuleSet,
) -> PolicyEngine {
    engine_with(
        Arc::new(ModedDlp::new(
            mode,
            rules,
            Arc::new(TracingObservations) as Arc<dyn ObservationSink>,
        )),
        provider(pool, unavailable),
    )
}

fn engine_with(dlp: Arc<dyn DlpService>, facts: Arc<PgSecurityFacts>) -> PolicyEngine {
    PolicyEngine::new(
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        Arc::new(AllowAll),
        dlp,
        Arc::new(AllowAll),
        Arc::new(NoAudit),
    )
    .with_facts(facts as Arc<dyn SecurityFactsProvider>)
}

/// Runs the chain, discharging the decision either way (`CLAUDE.md` rule 8).
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

// =================================================================================================
// The stage decides from rows
// =================================================================================================

/// The row this whole task exists for: a fact row in PostgreSQL becomes a refusal on the way out of
/// `PolicyEngine::enforce`.
///
/// Three legs, and the first is the one that fails against `DisabledDlp` — which is asserted
/// explicitly at the end, because "this test passes" is worth nothing if it would also pass against
/// the implementation the binary used to install.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn stored_facts_make_the_enforcing_stage_refuse_an_external_share() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let dirty = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let clean = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store(&pool, alpha, &scanned(dirty, 2, active().as_str())).await;
    store(&pool, alpha, &scanned(clean, 0, active().as_str())).await;

    let engine = engine(&pool, DlpMode::Enforce, FactsUnavailable::FailClosed);

    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "two payment identifiers were recorded for this version and the rule blocks external \
         sharing of them; the stage read the row or it did not"
    );

    // Control 1 — the same action over a version whose scan found nothing. The refusal above is
    // the *counts*, not the mere existence of a fact row or of a rule.
    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, clean.file_ref()).await,
        "a clean version was refused, so the stage is not deciding from the counts"
    );

    // Control 2 — an action no rule governs, over the dirty version. The refusal above is the rule
    // firing, not a stage that denies everything it is asked about.
    assert!(
        !refused(&engine, alpha, DOWNLOAD, dirty.file_ref()).await,
        "a download was refused by a rule scoped to external sharing"
    );

    // Control 3 — and the one that makes the first assertion mean something. `DisabledDlp` is what
    // `main.rs` installed before `ENC-594`, and it permits the identical request over the identical
    // row. A test that passed against it would prove that the chain runs, not that DLP is wired.
    let disabled =
        engine_with(Arc::new(DisabledDlp), provider(&pool, FactsUnavailable::FailClosed));
    assert!(
        !refused(&disabled, alpha, EXTERNAL_SHARE, dirty.file_ref()).await,
        "DisabledDlp refused something, so the assertion above does not distinguish the two \
         implementations"
    );
}

/// `docs/06 §12`, in a deployment rather than in a unit test: a version with no fact row is
/// **unscanned**, and what that means is the tenant's `facts_unavailable` policy's to say.
///
/// This is the state every deployment is in until a scanner writes rows (`ENC-613`), so both
/// directions have to be correct behaviour rather than an accident of the missing writer.
///
/// The **download** rule is what the two policies are observed through, and that is a correction
/// rather than a preference: the first draft used the external-sharing rule and failed here,
/// because D27 forces external sharing closed whatever `facts_unavailable` says — so that rule
/// cannot show `FAIL_OPEN_AUDIT` doing anything at all. The mandatory escalation is asserted as its
/// own leg below instead of standing in for the configured policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_version_with_no_fact_row_follows_the_configured_facts_unavailable_policy() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let unscanned = content(&mut conn, alpha, fixtures.alpha.owner).await;

    let closed = engine_running(
        &pool,
        DlpMode::Enforce,
        FactsUnavailable::FailClosed,
        payment_download_rule(),
    );
    assert!(
        refused(&closed, alpha, DOWNLOAD, unscanned.file_ref()).await,
        "no scan has run and a rule governs this action: FAIL_CLOSED must refuse"
    );

    // Control 1 — the same absence, the other policy. Without this leg the assertion above passes
    // against a stage that refuses everything.
    let open = engine_running(
        &pool,
        DlpMode::Enforce,
        FactsUnavailable::FailOpenAudit,
        payment_download_rule(),
    );
    assert!(
        !refused(&open, alpha, DOWNLOAD, unscanned.file_ref()).await,
        "FAIL_OPEN_AUDIT permits over unscanned content, and the evidence is the observation"
    );

    // Control 2 — `docs/06 §9.3`: an action no rule governs is never refused for facts it did not
    // need. Without this, a FAIL_CLOSED tenant refuses everything while a scan backlog drains,
    // which is the control nobody dares enable.
    assert!(
        !refused(&closed, alpha, EXTERNAL_SHARE, unscanned.file_ref()).await,
        "an ungoverned action was refused for a scan it never needed"
    );

    // D27's mandatory escalation, over a real absence rather than a constructed snapshot: with the
    // external-sharing rule in force, creating an external share of unscanned content is refused
    // under **either** configured policy. The `FAIL_OPEN_AUDIT` leg is the one worth having — the
    // tenant asked to be permitted and is refused anyway.
    for policy in [FactsUnavailable::FailClosed, FactsUnavailable::FailOpenAudit] {
        let engine = engine(&pool, DlpMode::Enforce, policy);
        assert!(
            refused(&engine, alpha, EXTERNAL_SHARE, unscanned.file_ref()).await,
            "external sharing of unscanned content must fail closed under {policy:?}"
        );
    }
}

/// `ENC-581` in a running deployment: freshness is **equality** with the active detector set, and
/// the two stale rows are chosen so that no ordering could have produced this result.
///
/// `builtin/0` sorts below the active set and `builtin/99` sorts above it. Under any ordering we
/// might have invented, one of the two would read as fresh — and the one that reads as fresh is the
/// dangerous one, because stale facts would then decide a request that believes it saw the current
/// rules. Both must be unusable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn facts_from_another_detector_set_are_unusable_however_the_version_string_sorts() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let older = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let newer = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let current = content(&mut conn, alpha, fixtures.alpha.owner).await;

    // Clean counts in every row, deliberately: if a stale row were used, its counts would fire
    // nothing and the request would be *permitted*. So a refusal below can only be the staleness.
    store(&pool, alpha, &scanned(older, 0, "builtin/0")).await;
    store(&pool, alpha, &scanned(newer, 0, "builtin/99")).await;
    store(&pool, alpha, &scanned(current, 0, active().as_str())).await;
    assert!(
        active().as_str() > "builtin/0" && active().as_str() < "builtin/99",
        "the two stale versions must straddle the active one, or this test is one comparison"
    );

    let engine = engine(&pool, DlpMode::Enforce, FactsUnavailable::FailClosed);

    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, older.file_ref()).await,
        "facts from an older detector set were used"
    );
    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, newer.file_ref()).await,
        "facts stamped with a version that sorts high read as fresh — the exact failure equality \
         exists to prevent"
    );
    // The control: the same clean counts, stamped with the active set, permit. The two refusals
    // above are the version comparison rather than a stage refusing every share.
    assert!(
        !refused(&engine, alpha, EXTERNAL_SHARE, current.file_ref()).await,
        "a clean, current scan was refused, so the refusals above prove nothing about staleness"
    );
}

// =================================================================================================
// Isolation
// =================================================================================================

/// One tenant's facts never decide another tenant's request.
///
/// The pairing is what makes it real (`docs/12 §1.2`, `§3`): `tenant-alpha` holds a version whose
/// scan found payment data, `tenant-beta` holds one whose scan found nothing, and the identical
/// request is run in both. Beta being permitted is not asserted alone — alpha is refused in the
/// same run, so "permitted" cannot mean "the stage never ran".
///
/// The second leg asks the provider directly what a beta request sees when it names **alpha's**
/// file. The chain would answer that with `NotFound` at stage 1 before DLP is reached, which is
/// correct and is also why the question has to be put to the provider: the guarantee under test is
/// that the read itself cannot cross the boundary, not that something upstream catches it first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_facts_never_decide_another_tenants_request() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);

    let alpha_file = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let beta_file = content(&mut conn, beta, fixtures.beta.owner).await;
    store(&pool, alpha, &scanned(alpha_file, 3, active().as_str())).await;
    store(&pool, beta, &scanned(beta_file, 0, active().as_str())).await;

    let engine = engine(&pool, DlpMode::Enforce, FactsUnavailable::FailClosed);

    assert!(
        refused(&engine, alpha, EXTERNAL_SHARE, alpha_file.file_ref()).await,
        "alpha's own findings must refuse alpha's share, or the test below proves nothing"
    );
    assert!(
        !refused(&engine, beta, EXTERNAL_SHARE, beta_file.file_ref()).await,
        "tenant-beta was decided against tenant-alpha's findings"
    );

    // The read itself, from beta's context, naming alpha's file.
    let reader = provider(&pool, FactsUnavailable::FailClosed);
    let beta_ctx = RequestContext::system(beta);
    let alphas_row_from_beta = reader
        .gather(&beta_ctx, EXTERNAL_SHARE, &ResourceRef::file(beta, alpha_file.spine.file))
        .await
        .expect("the read succeeds; it simply finds nothing");
    assert_eq!(
        alphas_row_from_beta.staleness(),
        FactsStaleness::Missing,
        "alpha's fact row was readable from a tenant-beta request"
    );

    // The positive control for that absence: the same identifier, read from alpha's context, does
    // find the row — so "missing" above is the tenant boundary and not a lookup that never works.
    let alpha_ctx = RequestContext::system(alpha);
    let alphas_row = reader
        .gather(&alpha_ctx, EXTERNAL_SHARE, &alpha_file.file_ref())
        .await
        .expect("alpha reads its own facts");
    assert_eq!(
        alphas_row.staleness(),
        FactsStaleness::Fresh,
        "alpha cannot read its own fact row, so the assertion above is a broken lookup"
    );
}

// =================================================================================================
// The resource's own state
// =================================================================================================

/// `docs/06 §12.1` / `ENC-588`: changing the terms of an **already external** share over unscanned
/// content is refused where creating one would have been — and in a deployment that means the
/// exposure has to be read from `share_links`, including links hanging above the file.
///
/// Run under `FAIL_OPEN_AUDIT`, deliberately. Under `FAIL_CLOSED` every leg would be refused and
/// the test would pass without the exposure read existing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_live_external_link_above_the_file_is_what_makes_the_escalation_fire() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let exposed = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let private = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let internal = content(&mut conn, alpha, fixtures.alpha.owner).await;

    // On the **folder**, not on the file: a link over a container exposes what is inside it, and
    // asking only about the file itself is how this escalation quietly stops firing.
    share_link(
        &mut conn,
        alpha,
        "FOLDER",
        exposed.spine.folder.as_uuid(),
        "ANYONE",
        fixtures.alpha.owner,
    )
    .await;
    // An internal link over the third file, so "external" is not simply "has any share link".
    share_link(
        &mut conn,
        alpha,
        "FILE",
        internal.spine.file.as_uuid(),
        "INTERNAL",
        fixtures.alpha.owner,
    )
    .await;

    let reader = provider(&pool, FactsUnavailable::FailOpenAudit);
    let ctx = RequestContext::system(alpha);
    let seen = |resource: ResourceRef| {
        let reader = Arc::clone(&reader);
        let ctx = ctx.clone();
        async move {
            reader.gather(&ctx, CHANGE_SHARE, &resource).await.expect("read the resource state")
        }
    };

    assert_eq!(
        seen(exposed.file_ref()).await.exposure(),
        Exposure::External,
        "a live ANYONE link on the containing folder exposes the file"
    );
    assert_eq!(
        seen(private.file_ref()).await.exposure(),
        Exposure::Internal,
        "a file with no link at all was reported as externally exposed"
    );
    assert_eq!(
        seen(internal.file_ref()).await.exposure(),
        Exposure::Internal,
        "an INTERNAL link is not external exposure"
    );

    // And what the exposure is *for*: under FAIL_OPEN_AUDIT, altering an already-external share
    // over unscanned content is refused, while altering an internal one is not.
    let engine = engine(&pool, DlpMode::Enforce, FactsUnavailable::FailOpenAudit);
    assert!(
        refused(&engine, alpha, CHANGE_SHARE, exposed.file_ref()).await,
        "changing the terms of an external share over unscanned content must fail closed"
    );
    assert!(
        !refused(&engine, alpha, CHANGE_SHARE, private.file_ref()).await,
        "the escalation fired on a file nothing has ever shared, so it is not the exposure that \
         fired it"
    );
}

/// A file with no committed version is unscanned rather than an error, and a resource with no
/// content at all never reaches the table.
///
/// The second half is what keeps `gather` off the critical path of every tenant-administration
/// call, and it is asserted through the same accessor so a resource kind that gains content and
/// is forgotten shows up as `Missing` here rather than as a silent permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_resource_with_no_content_has_no_facts_and_that_is_not_an_error() {
    let (db, fixtures, pool) = harness().await;
    let mut conn = db.connect().await.expect("administrative connection");
    let alpha = fixtures.alpha.id;

    let scanned_file = content(&mut conn, alpha, fixtures.alpha.owner).await;
    store(&pool, alpha, &scanned(scanned_file, 1, active().as_str())).await;

    let reader = provider(&pool, FactsUnavailable::FailClosed);
    let ctx = RequestContext::system(alpha);

    for resource in [
        ResourceRef::tenant(alpha),
        ResourceRef::user(alpha, fixtures.alpha.owner),
        // A file that does not exist in this tenant — or in any.
        ResourceRef::file(alpha, FileId::new_v7()),
    ] {
        let snapshot: FactsSnapshot =
            reader.gather(&ctx, DOWNLOAD, &resource).await.expect("no content is not a failure");
        assert_eq!(
            snapshot.staleness(),
            FactsStaleness::Missing,
            "{resource} reported facts it cannot have"
        );
        assert_eq!(snapshot.exposure(), Exposure::Internal, "{resource} reported exposure");
    }

    // The positive control: the same reader, over a resource that *does* have content, finds the
    // row — so the three `Missing` answers above are the absence of content rather than a provider
    // that finds nothing.
    let found = reader
        .gather(&ctx, DOWNLOAD, &scanned_file.file_ref())
        .await
        .expect("a scanned file has facts");
    assert_eq!(found.staleness(), FactsStaleness::Fresh);
}

/// A label the file inherits from its folder makes an unscanned document fail closed, and the
/// escalation reads that label even when the file has no committed content.
///
/// # Why this test exists at the seam rather than in `enclave-core`
///
/// `ENC-582` fixed `FactsPolicy::is_forced_closed` to take a rank, and `ENC-574` built the table,
/// the walk and the vocabulary that produce one. Between them sat `ENC-655`: this provider passed
/// `None`, so every unit test of the escalation passed and **no deployment could fire it**. A test
/// that constructs a `ResourceState` by hand proves the comparison; only this one proves the rank
/// arrives.
///
/// # The second half, which is the part that was actually wrong
///
/// The label is read *before* `gather` returns early on a file with no committed version. A label
/// belongs to the resource; facts belong to its content. Written the obvious way — resolve content,
/// return early, then read the label — a `RESTRICTED` document whose first upload has not finished
/// is unlabelled to the chain, which is precisely the moment its content is least known.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_inherited_label_reaches_the_escalation_with_or_without_committed_content() {
    let (db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("harness connection");

    let labelled = content(&mut conn, alpha, fixtures.alpha.owner).await;
    let plain = content(&mut conn, alpha, fixtures.alpha.owner).await;

    // A file with a label and *no committed version*: the early-return path.
    let empty = Spine::new(alpha);
    empty.insert(&mut conn, fixtures.alpha.owner, Utc::now()).await.expect("write a bare spine");

    let restricted = ClassificationId::new_v7();
    {
        let mut tx = pool.begin(alpha).await.expect("begin");
        define_classification(
            &mut tx,
            restricted,
            "RESTRICTED",
            "Restricted",
            ClassificationRank::RESTRICTED,
        )
        .await
        .expect("define the label");
        // On the **folders**, so the escalation is reached by inheritance rather than by a label
        // sitting on the file itself — the case a walk that stops early would drop.
        assign_classification(&mut tx, labelled.spine.folder, Some(restricted))
            .await
            .expect("label the folder");
        assign_classification(&mut tx, empty.folder, Some(restricted))
            .await
            .expect("label the empty file's folder");
        tx.commit().await.expect("commit the labels");
    }

    let reader = provider(&pool, FactsUnavailable::FailOpenAudit);
    let ctx = RequestContext::system(alpha);

    let rank_of = |resource: ResourceRef| {
        let reader = Arc::clone(&reader);
        let ctx = ctx.clone();
        async move {
            reader
                .gather(&ctx, DOWNLOAD, &resource)
                .await
                .expect("read the resource state")
                .classification()
        }
    };

    assert_eq!(
        rank_of(labelled.file_ref()).await,
        Some(ClassificationRank::RESTRICTED),
        "the file inherits RESTRICTED from its folder and the provider must carry it"
    );
    assert_eq!(
        rank_of(ResourceRef::file(alpha, empty.file)).await,
        Some(ClassificationRank::RESTRICTED),
        "a file whose first upload has not committed still carries its folder's label; reading the \
         label after the no-content early return is ENC-655"
    );

    // The control: the same provider, a file in the same tenant with no label anywhere above it.
    assert_eq!(
        rank_of(plain.file_ref()).await,
        None,
        "an unlabelled file was reported as carrying a rank, so the two answers above are not the \
         provider labelling everything"
    );

    // And what the rank is *for*. Under FAIL_OPEN_AUDIT the tenant has asked to proceed without
    // facts — D27 overrides that for RESTRICTED, and only a real rank can trigger it.
    //
    // `payment_download_rule` rather than the default: `RuleSet::evaluate` settles whether any rule
    // *governs* the action before it asks for facts (`docs/06 §9.3`), so an escalation cannot fire
    // for an action no rule governs. Written with the external-sharing rule this leg failed, and it
    // was the test that was wrong — an unlabelled *and* a RESTRICTED download were both permitted
    // because DLP was never consulted about downloads at all. Worth keeping as a comment because
    // the failure looked exactly like a dead escalation, which is the bug this test exists to catch.
    let engine = engine_running(
        &pool,
        DlpMode::Enforce,
        FactsUnavailable::FailOpenAudit,
        payment_download_rule(),
    );
    assert!(
        refused(&engine, alpha, DOWNLOAD, labelled.file_ref()).await,
        "an unscanned RESTRICTED document must fail closed even under FAIL_OPEN_AUDIT (D27)"
    );
    assert!(
        !refused(&engine, alpha, DOWNLOAD, plain.file_ref()).await,
        "the unlabelled file was refused too, so it is the tenant's policy refusing rather than \
         the RESTRICTED escalation"
    );
}
