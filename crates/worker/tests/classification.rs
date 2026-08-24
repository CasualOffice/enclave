//! The indexing pass reads a real effective classification — `ENC-656`.
//!
//! # What this closes, and what it deliberately does not
//!
//! `UnclassifiedFiles` refuses every file, on the argument in its own documentation: a constant
//! rank is wrong in both directions and nothing downstream can detect it. `ENC-574` gave the
//! workspace a label set, a walk and a vocabulary; `PgClassification` is the source that connects
//! them, and these tests are the proof that the number arriving at `ClassifiedText` is the one in
//! the database rather than a plausible constant.
//!
//! They do **not** prove a deployment embeds. Three things stand between here and that, and only
//! the first is closed: the classification source (this file), a `VectorStage` in the worker binary
//! (`PipelineRunner` holds none), and an `EmbeddingProvider` implementation at all — the workspace
//! has `NoLocalModel` and `NoRemoteProvider`, both of which refuse by design. `ENC-661` carries the
//! rest, and this note is here so a reader of a green suite does not conclude otherwise.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use enclave_core::{
    ClassificationId, ClassificationOutcome, ClassificationPolicy, ClassificationRank, Unlabelled,
};
use enclave_db::{assign_classification, define_classification};
use enclave_testing::{Fixtures, TestDb};
use enclave_worker::indexing::{FileClassification, PgClassification, UnclassifiedFiles};

use common::a_file_on_a_spine;

/// A rank a tenant might assign `RESTRICTED`, distinct from the crate constant so a test that
/// accidentally compared against the default would still be comparing two different numbers.
const SECRET: ClassificationRank = ClassificationRank::new(70);

async fn harness() -> (TestDb, Fixtures) {
    let db = TestDb::start().await.expect(
        "these tests need a live PostgreSQL; CI provides a service container, locally use \
         deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    (db, fixtures)
}

/// The rank the walk finds is the rank the pass attaches.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_labelled_file_resolves_to_the_rank_in_the_database() {
    let (db, fixtures) = harness().await;
    let alpha = fixtures.alpha.id;
    let pool = db.pool().await.expect("pool");
    let mut conn = db.connect().await.expect("connection");

    let (spine, _) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;

    let secret = ClassificationId::new_v7();
    {
        let mut tx = pool.begin(alpha).await.expect("begin");
        define_classification(&mut tx, secret, "SECRET", "Secret", SECRET)
            .await
            .expect("define the label");
        // On the folder, so the rank arrives by inheritance — the case a source reading only
        // `files.classification_id` would answer `None` for while looking correct.
        assign_classification(&mut tx, spine.folder, Some(secret)).await.expect("assign");
        tx.commit().await.expect("commit");
    }

    let ranks =
        PgClassification::new(ClassificationPolicy::from_tenant_config(Unlabelled::FailClosed));

    let outcome =
        ranks.effective_rank(&mut conn, alpha, spine.file).await.expect("a labelled file resolves");
    match outcome {
        ClassificationOutcome::Labelled(effective) => assert_eq!(
            effective.rank(),
            SECRET,
            "the pass attached a rank the database does not hold"
        ),
        other => panic!("expected the stored label, got {other:?}"),
    }

    // The control, in the same tenant and the same transaction shape: with no label anywhere above
    // it, the identical call does *not* produce a rank. Without this the assertion above passes for
    // a source that answers SECRET to everything.
    let (bare, _) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;
    let unlabelled = ranks.effective_rank(&mut conn, alpha, bare.file).await;
    assert!(
        matches!(unlabelled, Ok(ClassificationOutcome::Denied { .. })),
        "an unlabelled file under FAIL_CLOSED must be denied, not given a rank: {unlabelled:?}"
    );
}

/// `Assume` is honoured and arrives as `Assumed`, never as a reading.
///
/// The distinction is the whole of `ENC-656`: a return type of `ClassificationRank` can express
/// *"the tenant nominated 20 for unlabelled content"* only by pretending 20 was read off the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn an_assumed_rank_is_not_reported_as_a_label() {
    let (db, fixtures) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");

    let (spine, _) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;

    let assumed_at = ClassificationRank::new(20);
    let ranks = PgClassification::new(ClassificationPolicy::from_tenant_config(
        Unlabelled::Assume(assumed_at),
    ));

    match ranks.effective_rank(&mut conn, alpha, spine.file).await.expect("assume answers") {
        ClassificationOutcome::Assumed(assumed) => {
            assert_eq!(assumed.rank(), assumed_at, "the assumed rank is the configured one");
        }
        ClassificationOutcome::Labelled(effective) => panic!(
            "an assumed rank was reported as a label read off the file: {effective:?}. That is the \
             collapse ENC-656 exists to prevent — nothing downstream can tell the two apart, and \
             the rank is written into the collection as though it had been read"
        ),
        other => panic!("expected an assumption, got {other:?}"),
    }
}

/// `UnclassifiedFiles` stays, and stays refusing.
///
/// It is not dead code once a real source exists: it is the deployment whose classification service
/// is unreachable, and its refusal is a different fact from the tenant's `FAIL_CLOSED` — an outage
/// rather than a policy. A test pins that so it is not deleted as redundant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_unconfigured_source_still_refuses_everything() {
    let (db, fixtures) = harness().await;
    let alpha = fixtures.alpha.id;
    let mut conn = db.connect().await.expect("connection");

    let (spine, _) = a_file_on_a_spine(
        &mut conn,
        alpha,
        fixtures.alpha.owner,
        "AVAILABLE",
        "CLEAN",
        "text/plain",
    )
    .await;

    let refused = UnclassifiedFiles.effective_rank(&mut conn, alpha, spine.file).await;
    assert!(
        refused.is_err(),
        "a deployment with no classification source must refuse rather than guess: {refused:?}"
    );
}
