//! The content scan, end to end against a real database — `ENC-613`.
//!
//! # What these tests are about, and what they are not
//!
//! `docs/12-TESTING.md §1.1`: whether Luhn recognises a card number is `enclave_dlp`'s problem and
//! is settled by its own suite. Ours is the wiring — that a document carrying a detectable
//! identifier becomes a **row** with the right count in it, that a document nobody could read
//! becomes **no row at all**, and that the row the scan wrote is the one the DLP stage then reads.
//!
//! # The absence that must not pass for free
//!
//! `docs/12 §1.2`, and it is the shape this file is arranged against. Every interesting assertion
//! here is an absence: *no fact row*, *no match value in any column*, *no cross-tenant row*. All of
//! them hold trivially against a scanner that writes nothing at all — which is precisely the
//! implementation that existed before this task. So every one of them is paired, in the same test
//! and over the same pass, with the positive control that a row *did* land and carries the counts.
//!
//! # Why the store is a fake and the database is not
//!
//! `tests/indexing.rs`'s reason, unchanged: only a real PostgreSQL can answer "what is in
//! `security_facts`", and the store is being asked "were you called", which a recording fake
//! answers better than MinIO does.
//!
//! `#[ignore]`d because they need PostgreSQL; CI runs them with `--include-ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use chrono::Utc;
use enclave_core::{
    Action, ClassificationRank, DetectorCategory, DetectorCounts, DetectorSetVersion, DlpService,
    FactsPolicy, FactsStaleness, FactsUnavailable, FileAction, FileId, ReasonCode, RequestContext,
    ResourceRef, ScanVersion, SecurityFacts, SecurityFactsProvider, StageOutcome, TenantId,
    VersionId,
};
use enclave_db::{record_facts, DbPool};
use enclave_dlp::detector::DetectorSet;
use enclave_dlp::policy::{ActionScope, Condition, DlpAction, DlpRule, RuleId, RuleSet};
use enclave_dlp::{
    builtin_set, DlpMode, ModedDlp, ObservationSink, PgSecurityFacts, TracingObservations,
};
use enclave_indexing::{ChunkBudget, Chunker, ChunkerVersion, Pipeline, PlainTextExtractor};
use enclave_preview::RenderBudget;
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::scan::{scan_pass, ScanCursor, ScanPass};
use enclave_worker::Stop;
use sqlx::{PgConnection, Row as _};

mod common;
use common::{a_file, a_file_on_a_spine, a_version, RecordingStore};

const CHUNKER: ChunkerVersion = ChunkerVersion::new("test/1");
const DOWNLOAD: Action = Action::File(FileAction::Download);

/// A Luhn-valid test card number. ISO/IEC 7812's own published example, and the one
/// `crates/dlp/src/builtin.rs` uses — a *test* PAN, issued by nobody, which is why it can be a
/// literal here at all.
const PAN: &str = "4111111111111111";

/// A second one, so a test about *counts* is not a test about one match.
const SECOND_PAN: &str = "5500005555555559";

fn pipeline() -> Pipeline<PlainTextExtractor> {
    Pipeline::new(PlainTextExtractor, Chunker::new(CHUNKER, ChunkBudget::default()))
}

async fn start() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect("start a test database");
    let fixtures = db.seed().await.expect("seed the fixtures");
    let pool = db.pool_with_connections(4).await.expect("pool");
    (db, fixtures, pool)
}

/// The shipped detector set, so these tests run the deployment's answer and not one of their own.
fn detectors() -> Arc<DetectorSet> {
    Arc::new(builtin_set())
}

/// One pass over `tenant`, from the start of the sweep.
async fn sweep(
    pool: &DbPool,
    tenant: TenantId,
    store: &RecordingStore,
    detectors: &Arc<DetectorSet>,
    batch: i64,
) -> ScanPass {
    scan_pass(
        pool,
        tenant,
        &pipeline(),
        None,
        detectors,
        store,
        RenderBudget::default(),
        batch,
        ScanCursor::start(),
        &Stop::new(),
    )
    .await
    .expect("the pass must not fail on a document it cannot read")
}

/// The whole fact row as text, or `None` when there is none.
///
/// Every column, deliberately: the rule-10 assertion below is "the match value is in none of them",
/// and a helper that read the four counts would prove it of the four columns somebody remembered.
async fn fact_row(conn: &mut PgConnection, version: VersionId) -> Option<String> {
    sqlx::query("SELECT security_facts::text AS row FROM security_facts WHERE version_id = $1")
        .bind(version.as_uuid())
        .fetch_optional(&mut *conn)
        .await
        .expect("read the fact row")
        .map(|row| row.try_get::<String, _>("row").expect("row as text"))
}

/// The financial count a scan recorded for `version`.
async fn financial_count(conn: &mut PgConnection, version: VersionId) -> Option<i32> {
    sqlx::query("SELECT financial_count FROM security_facts WHERE version_id = $1")
        .bind(version.as_uuid())
        .fetch_optional(&mut *conn)
        .await
        .expect("read the count")
        .map(|row| row.try_get::<i32, _>("financial_count").expect("financial_count"))
}

/// The detector set a stored row was stamped with.
async fn stamped_set(conn: &mut PgConnection, version: VersionId) -> Option<String> {
    sqlx::query("SELECT detector_set_version FROM security_facts WHERE version_id = $1")
        .bind(version.as_uuid())
        .fetch_optional(&mut *conn)
        .await
        .expect("read the stamp")
        .map(|row| row.try_get::<String, _>("detector_set_version").expect("detector_set_version"))
}

// =================================================================================================
// The row this whole task exists for
// =================================================================================================

/// A document carrying detectable identifiers is scanned, and the counts land.
///
/// Paired in one test with the rule-10 assertion, because that one is an absence: "the card number
/// is in no column" holds for free against a scanner that wrote nothing, and the count assertion is
/// what proves a scan happened at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_document_carrying_card_numbers_produces_facts_that_carry_counts_and_no_content() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (_file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;

    let store = RecordingStore::new(&format!(
        "Please charge {PAN} for the balance, and refund {SECOND_PAN} on the return."
    ));
    let pass = sweep(&pool, alpha, &store, &detectors(), 10).await;

    assert_eq!(pass.considered, 1);
    assert_eq!(pass.scanned, 1, "a readable text document was not scanned");
    assert_eq!(pass.unscannable(), 0);
    assert_eq!(store.reads().len(), 1, "the version's bytes were read exactly once");

    // The positive control. Two identifiers, so this is an assertion about the *count* rather than
    // about whether anything was found — a scanner that stopped at the first match answers every
    // is-it-there question correctly and this one wrongly.
    assert_eq!(
        financial_count(&mut conn, version).await,
        Some(2),
        "the counts the detectors produced did not reach `security_facts`"
    );

    // `CLAUDE.md` rule 10, over the whole row rather than the columns somebody thought of.
    let row = fact_row(&mut conn, version).await.expect("the row above exists");
    for needle in [PAN, SECOND_PAN, "4111", "Please charge"] {
        assert!(!row.contains(needle), "a matched value reached `security_facts`: {row}");
    }
    // And the control for *that*: the needles are findable in a rendering that does carry them, so
    // the four absences above are the schema working rather than the search being wrong.
    let carrying = format!("(2,{PAN},{SECOND_PAN},\"Please charge\")");
    for needle in [PAN, SECOND_PAN, "4111", "Please charge"] {
        assert!(carrying.contains(needle));
    }

    drop(db);
}

/// A document that yields no text produces **no row**, and a clean document that yields text does.
///
/// The decision this module is about, and the two halves have to be in one test: "no row" is an
/// absence that passes against a scanner that never writes, and "a row of zeroes" is the dangerous
/// outcome it must not be confused with.
///
/// The control runs in `tenant-beta` rather than beside the textless document in alpha, and that is
/// not decoration: an unscannable version stays in the queue, so a second pass over the *same*
/// tenant would re-attempt it against the control's store and scan it after all. Putting the two in
/// different tenants is what keeps each pass serving one document the bytes it is about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_document_that_yields_no_text_is_unscanned_while_a_clean_one_is_scanned() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let mut conn = db.connect().await.expect("connection");

    // Whitespace only: it parses perfectly and contains nothing. The same shape an encrypted
    // container or a scanned page on a deployment with no OCR presents.
    let (_file, textless) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;
    let blank = RecordingStore::new("   \n\n   \t  \n");
    let pass = sweep(&pool, alpha, &blank, &detectors(), 10).await;

    assert_eq!(pass.textless, 1, "a whitespace document was not reported textless");
    assert_eq!(pass.scanned, 0);
    assert!(!blank.reads().is_empty(), "the pass did read it — the absence below is a decision");
    assert_eq!(
        fact_row(&mut conn, textless).await,
        None,
        "a document nobody could read was recorded as scanned; every threshold rule would then \
         evaluate cleanly and permit"
    );

    // The positive control, and the reason the assertion above is not free: a document that *does*
    // yield text, and carries nothing sensitive, gets a row — with zeroes in it. That is a real
    // scan finding nothing, and it is what the absence above has to be distinguishable from.
    let (_file, clean) =
        a_file(&mut conn, beta, fixtures.beta.owner, "AVAILABLE", "CLEAN", "text/plain").await;
    let store = RecordingStore::new("The quarterly review is on Tuesday at 14:30 in room 4111.");
    let pass = sweep(&pool, beta, &store, &detectors(), 10).await;

    assert_eq!(pass.scanned, 1, "a clean document with text must still be scanned");
    assert_eq!(
        financial_count(&mut conn, clean).await,
        Some(0),
        "a clean document produces a row of zeroes, which is not the same fact as no row"
    );
    assert_eq!(fact_row(&mut conn, textless).await, None, "and the textless one still has none");

    drop(db);
}

/// A media type no extractor in this deployment handles produces no row either.
///
/// The second half of the same decision, and it is not the same code path: `Outcome::Unsupported`
/// is decided before a parser is entered, whereas `NoText` is decided after one has run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unsupported_media_type_is_unscanned_rather_than_recorded_clean() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    // No PDF extractor is registered in this pipeline, exactly as in a deployment with no PDFium.
    let (_file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "application/pdf")
            .await;

    let store = RecordingStore::new(&format!("charge {PAN}"));
    let pass = sweep(&pool, alpha, &store, &detectors(), 10).await;

    assert_eq!(pass.unsupported, 1);
    assert_eq!(pass.scanned, 0);
    assert_eq!(
        fact_row(&mut conn, version).await,
        None,
        "a type nothing can parse was recorded as a clean scan"
    );
    // The bytes *are* fetched first, exactly as `index_pass` fetches them: `Extractor::supports` is
    // consulted inside `Pipeline::prepare`, after the read. Written down rather than asserted as an
    // absence, because it is a cost and not a control — and asserting `reads().is_empty()` here
    // would be a claim about the wrong thing. It is also the positive control for the row above:
    // the pass reached this version rather than skipping it.
    assert_eq!(store.reads().len(), 1);

    drop(db);
}

// =================================================================================================
// Rule 9
// =================================================================================================

/// A version antivirus has not cleared is never read and never produces facts.
///
/// `CLAUDE.md` rule 9, and asserted on the **store** as well as on the table: an implementation that
/// fetched the bytes and then declined to record them would pass a table-only check while having
/// already read an unscanned upload into worker memory and handed it to a parser.
///
/// The clean version beside it is the positive control: the pass *is* reading and *is* writing, so
/// the two absences above are the readability gate rather than a pass that did nothing.
///
/// # Which mechanism this proves, and what it does not
///
/// Recorded because a deliberate break did not fail it (`docs/12 §1.2`). Deleting the queue's
/// `av_status = 'CLEAN'` predicate alone left this green, because the *first* fixture is
/// `SCANNING`/`PENDING` and `status = 'AVAILABLE'` still excluded it — two predicates covering one
/// document. The quarantined fixture below exists for that: it is `AVAILABLE` and `INFECTED`, so
/// each half of rule 9 is now the only thing excluding one of the two.
///
/// Even then, what fails is the `considered` count and nothing else. The row and store assertions
/// stay green with *both* predicates deleted, because `enclave_preview::repo::readable_version` is
/// the actual control: its query carries the same filter and it is the only constructor of the type
/// this pass needs to read an object. The queue predicate is pacing — without it every tick would
/// select an entire scanning backlog and discard it a row at a time — and `considered` is the
/// assertion that holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_version_still_being_scanned_is_never_read_and_produces_no_facts() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (_file, scanning) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "SCANNING", "PENDING", "text/plain").await;
    let (_file, quarantined) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "INFECTED", "text/plain").await;
    let (_file, clean) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;

    let store = RecordingStore::new(&format!("an unscanned upload carrying {PAN}"));
    let pass = sweep(&pool, alpha, &store, &detectors(), 10).await;

    assert_eq!(pass.considered, 1, "a version antivirus has not cleared reached the pass");
    assert_eq!(pass.scanned, 1);
    assert_eq!(fact_row(&mut conn, scanning).await, None, "unscanned content produced facts");
    assert_eq!(fact_row(&mut conn, quarantined).await, None, "infected content produced facts");
    assert!(fact_row(&mut conn, clean).await.is_some(), "the readable version was not scanned");
    assert_eq!(
        store.reads(),
        vec![format!("objects/{}", clean.as_uuid())],
        "the bytes of a version antivirus has not cleared were fetched"
    );

    drop(db);
}

// =================================================================================================
// Freshness, rescans and idempotence
// =================================================================================================

/// A version whose facts were produced by a different detector set is rescanned, and the row is
/// **replaced** rather than duplicated or left alone.
///
/// `ENC-581`'s equality rule is the rescan trigger, so this is the test that a detector-set change
/// actually re-enqueues. The second leg is the one that stops it being a treadmill: with the row
/// stamped by the *active* set, the version is not offered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn moving_the_detector_set_makes_a_scanned_version_due_again() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (file, version) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;

    // Facts as a *previous* set left them: a different version string, and a count that is wrong
    // for the document — so a rescan is visible in the counts as well as in the stamp.
    let mut counts = DetectorCounts::none();
    counts.add(DetectorCategory::Financial, 99);
    let stale = SecurityFacts::scanned(
        file,
        version,
        counts,
        DetectorSetVersion::new("builtin/0-superseded"),
        ScanVersion::new(1),
        Utc::now(),
    );
    let mut tx = pool.begin(alpha).await.expect("begin");
    record_facts(&mut tx, &stale).await.expect("write the stale row");
    tx.commit().await.expect("commit");

    let store = RecordingStore::new(&format!("charge {PAN}"));
    let detectors = detectors();
    let pass = sweep(&pool, alpha, &store, &detectors, 10).await;

    assert_eq!(pass.scanned, 1, "a row from a superseded detector set was not rescanned");
    assert_eq!(
        stamped_set(&mut conn, version).await.as_deref(),
        Some(detectors.version().as_str()),
        "the row must be stamped with the set that produced it"
    );
    assert_eq!(
        financial_count(&mut conn, version).await,
        Some(1),
        "the rescan replaced the row rather than leaving the superseded counts"
    );
    let rows: i64 = sqlx::query("SELECT count(*) AS n FROM security_facts WHERE version_id = $1")
        .bind(version.as_uuid())
        .fetch_one(&mut conn)
        .await
        .expect("count")
        .try_get("n")
        .expect("n");
    assert_eq!(rows, 1, "a rescan must replace, not accumulate");

    // And now it is fresh, so a second pass finds nothing to do. Without this the pass would
    // re-extract every version in the tenant on every tick forever.
    let pass = sweep(&pool, alpha, &store, &detectors, 10).await;
    assert_eq!(pass.considered, 0, "a version with fresh facts was offered to the pass again");

    drop(db);
}

/// Facts are per **version**: a second version of the same file is unscanned until it is scanned,
/// even though the file has been scanned before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_new_version_of_a_scanned_file_is_scanned_in_its_own_right() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (spine, first) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;

    let store = RecordingStore::new(&format!("charge {PAN}"));
    let detectors = detectors();
    assert_eq!(sweep(&pool, alpha, &store, &detectors, 10).await.scanned, 1);
    assert_eq!(financial_count(&mut conn, first).await, Some(1));

    let second = a_version(
        &mut conn,
        alpha,
        &spine,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;
    let pass = sweep(&pool, alpha, &store, &detectors, 10).await;

    assert_eq!(pass.considered, 1, "only the new version is due");
    assert_eq!(pass.scanned, 1);
    assert!(fact_row(&mut conn, second).await.is_some(), "the new version has its own facts");
    assert!(fact_row(&mut conn, first).await.is_some(), "and the old version keeps its own");

    drop(db);
}

// =================================================================================================
// Pacing
// =================================================================================================

/// A version that cannot be scanned does not starve the ones behind it.
///
/// The queue is a query with no claim column, so an unscannable version never leaves the result set
/// (`crate::scan::ScanCursor`). Without the cursor, a batch of them at the oldest end of the order
/// is re-selected every tick and nothing behind them is ever reached — which is silent, because the
/// pass reports success every time.
///
/// A batch of one makes that concrete: the first tick can only reach the textless document, and the
/// second must reach the one behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_unscannable_version_does_not_starve_the_one_behind_it() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");
    let (_file, blocker) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;
    let (_file, behind) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;

    // One store for both: the blocker is textless because the *first* pass serves whitespace, and
    // the second pass serves a card number. What differs between the ticks is only which version
    // is reached, which is the property under test.
    let blank = RecordingStore::new("    ");
    let detectors = detectors();

    let first = scan_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        &detectors,
        &blank,
        RenderBudget::default(),
        1,
        ScanCursor::start(),
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(first.considered, 1, "a batch of one reaches one version");
    assert_eq!(first.textless, 1);
    assert!(!first.resume.is_start(), "the cursor did not move past the version it could not scan");

    let content = RecordingStore::new(&format!("charge {PAN}"));
    let second = scan_pass(
        &pool,
        alpha,
        &pipeline(),
        None,
        &detectors,
        &content,
        RenderBudget::default(),
        1,
        first.resume,
        &Stop::new(),
    )
    .await
    .expect("pass");

    assert_eq!(second.scanned, 1, "the version behind an unscannable one was never reached");
    assert!(fact_row(&mut conn, behind).await.is_some(), "the second version has facts");
    assert_eq!(fact_row(&mut conn, blocker).await, None, "and the first still has none");

    drop(db);
}

// =================================================================================================
// Tenant isolation
// =================================================================================================

/// One tenant's pass never reads or writes another tenant's content.
///
/// `docs/12 §4.1`. The positive control is in the same run: alpha's version *is* scanned, so
/// "beta has no row" is the scoping rather than a pass that did nothing. The object read is
/// asserted too, because the damage here is not only a row in the wrong place — it is one tenant's
/// worker fetching another tenant's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_pass_for_one_tenant_never_reads_or_writes_another_tenants_versions() {
    let (db, fixtures, pool) = start().await;
    let (alpha, beta) = (fixtures.alpha.id, fixtures.beta.id);
    let mut conn = db.connect().await.expect("connection");
    let (_file, alphas) =
        a_file(&mut conn, alpha, fixtures.alpha.owner, "AVAILABLE", "CLEAN", "text/plain").await;
    let (_file, betas) =
        a_file(&mut conn, beta, fixtures.beta.owner, "AVAILABLE", "CLEAN", "text/plain").await;

    let store = RecordingStore::new(&format!("charge {PAN}"));
    let pass = sweep(&pool, alpha, &store, &detectors(), 10).await;

    assert_eq!(pass.considered, 1, "beta's version was offered to alpha's pass");
    assert!(fact_row(&mut conn, alphas).await.is_some(), "alpha's own version was not scanned");
    assert_eq!(fact_row(&mut conn, betas).await, None, "alpha's pass wrote facts for beta");
    assert_eq!(
        store.reads(),
        vec![format!("objects/{}", alphas.as_uuid())],
        "alpha's pass fetched another tenant's object"
    );

    drop(db);
}

// =================================================================================================
// The loop this closes
// =================================================================================================

/// **The end-to-end assertion.** A document with a card number in it is scanned, and the DLP stage
/// then refuses a governed action on the strength of what the scan wrote.
///
/// The three previous tasks each built one link — `ENC-581` the detectors, `ENC-582` the threading,
/// `ENC-594` the table and the reader — and none of them could run the chain over a row that
/// something in this repository had produced. This does: nothing here writes a `SecurityFacts` by
/// hand.
///
/// Two legs, and the second is what makes the first mean something. The identical rule, over an
/// identical file whose scan found nothing, permits — so the refusal is the *counts* rather than a
/// stage that refuses everything, and the pass's zero-count row is proved to be readable as a clean
/// bill of health rather than as an absence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn what_the_scan_wrote_is_what_the_dlp_stage_decides_from() {
    let (db, fixtures, pool) = start().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");

    let carrying = a_scanned_file(&mut conn, &pool, fixtures.alpha.owner, alpha, PAN).await;
    let clean =
        a_scanned_file(&mut conn, &pool, fixtures.alpha.owner, alpha, "nothing sensitive at all")
            .await;

    // The reader and the stage `crates/api/src/main.rs` installs, over the active detector set.
    let facts = PgSecurityFacts::new(
        pool.clone(),
        builtin_set().version().clone(),
        FactsPolicy::from_tenant_config(
            FactsUnavailable::FailClosed,
            ClassificationRank::RESTRICTED,
        ),
    );
    let dlp = ModedDlp::new(
        DlpMode::Enforce,
        RuleSet::new(vec![DlpRule::new(
            RuleId::new("block-download-of-payment-data"),
            vec![ActionScope::Exactly(DOWNLOAD)],
            vec![Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }],
            DlpAction::Block,
        )]),
        Arc::new(TracingObservations) as Arc<dyn ObservationSink>,
    );

    let ctx = RequestContext::system(alpha);

    // The row the scan wrote is *fresh* — the stamp it carries equals the active set. Asserted
    // first, because a stale reading would make the refusal below a facts-unavailable denial
    // wearing the same clothes.
    let snapshot = facts.gather(&ctx, DOWNLOAD, &carrying).await.expect("gather");
    assert_eq!(snapshot.staleness(), FactsStaleness::Fresh);
    let decision = dlp.evaluate(&ctx, DOWNLOAD, &carrying, &snapshot).await.expect("evaluated");
    assert_eq!(
        decision.outcome(),
        &StageOutcome::Deny(ReasonCode::DlpBlocked),
        "the DLP stage did not refuse a download of content the scan found a card number in"
    );

    // The control: the same rule, the same mode, a file the same pass scanned and found nothing in.
    let snapshot = facts.gather(&ctx, DOWNLOAD, &clean).await.expect("gather");
    assert_eq!(snapshot.staleness(), FactsStaleness::Fresh, "the clean file was scanned too");
    let decision = dlp.evaluate(&ctx, DOWNLOAD, &clean, &snapshot).await.expect("evaluated");
    assert!(
        decision.is_allowed(),
        "a document the scan found nothing in was refused, so the refusal above was not the counts"
    );

    drop(db);
}

/// A file whose current version has been through the scan pass, and a reference to it.
///
/// The version is made *current* because `resolve_content` answers a file action with
/// `files.current_version_id` — a file with no current version has no facts by definition, and the
/// end-to-end test would then be observing that rather than the scan.
async fn a_scanned_file(
    conn: &mut PgConnection,
    pool: &DbPool,
    owner: enclave_core::UserId,
    tenant: TenantId,
    body: &str,
) -> ResourceRef {
    let (spine, version) =
        a_file_on_a_spine(conn, tenant, owner, "AVAILABLE", "CLEAN", "text/plain").await;
    point_at(conn, spine.file, version).await;

    let store = RecordingStore::new(body);
    let pass = sweep(pool, tenant, &store, &detectors(), 10).await;
    assert_eq!(pass.scanned, 1, "the fixture's own scan did not run");

    spine.file_ref()
}

/// Points a file at the version whose facts describe it.
async fn point_at(conn: &mut PgConnection, file: FileId, version: VersionId) {
    sqlx::query("UPDATE files SET current_version_id = $1 WHERE id = $2")
        .bind(version.as_uuid())
        .bind(file.as_uuid())
        .execute(&mut *conn)
        .await
        .expect("point the file at its version");
}
