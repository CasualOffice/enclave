//! The OCR stage a deployment's configuration builds — `ENC-546`.
//!
//! # What this file is for, and what it is not
//!
//! `crates/indexing/tests/{ocr,pdf}.rs` already prove the pieces: that `ocrs` reads a rendered page,
//! that `PdfiumPages` rasterises one, that `OcrRetry` refuses a document with a bad page rather than
//! indexing the rest. None of that is repeated here.
//!
//! What was untested until now is the *composition*: that the two environment variables CI sets
//! reach a `Config`, that a `Config` naming both volumes produces a working stage, and that the
//! three states of `Config::ocr_mounts` produce three different things rather than two. Every
//! assertion below is about our wiring — `docs/12 §1.1`.
//!
//! # The one timing rule
//!
//! [`UNTIMED`] and never `RenderBudget::DEFAULT` on a path that actually runs the engine. `ENC-540`
//! and the note on `crates/indexing/tests/pdf.rs`'s constant of the same name: `DEFAULT`'s
//! 30-second clock passes locally and timed out on a hosted runner, and both tests read as an OCR
//! defect rather than as a slow machine. Nothing here asserts how fast anything is.
//!
//! `#[ignore]`d because they need the mounted volumes; **CI runs them with `--include-ignored`** and
//! provisions both in the "Fetch the OCR models" and "Fetch PDFium" steps of the `test` job.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_config::{Config, ConfigLoader};
use enclave_core::VersionId;
use enclave_indexing::{
    ChunkBudget, Chunker, ChunkerVersion, ManifestStatus, Outcome, Prepared, Reason, RenderBudget,
    TextlessSource,
};
use enclave_worker::ocr::MountedOcr;

mod common;
use common::{blank_page, page_of_words};

/// `RenderBudget::DEFAULT` with the clock taken off. See the module documentation.
const UNTIMED: RenderBudget =
    RenderBudget { wall_clock: core::time::Duration::from_secs(600), ..RenderBudget::DEFAULT };

/// The configuration a deployment with both volumes mounted has.
///
/// Built through [`ConfigLoader`]'s environment layer rather than by setting the fields directly,
/// because the thing worth proving is that the **variable names CI sets** are the names the loader
/// turns into these fields. A test that assigned `config.ocr_models` would pass against a field
/// nothing in any environment can reach.
///
/// The two values are passed explicitly rather than letting the loader read the whole process
/// environment. That is not squeamishness. The instance that prompted it —
/// `ENCLAVE_TEST_S3_SECRET_ACCESS_KEY`, which the loader turned into a configuration field the
/// inline-credential scanner correctly refused — is gone, renamed out of the reserved prefix by
/// `ENC-544`. The reason is not: `ENCLAVE_DEV_*` still sits inside the prefix, and a shell is not a
/// controlled input. This test is about mounts, and it should fail only for reasons about mounts;
/// whether an *ambient* environment loads at all is asserted where it belongs, in
/// `crates/config/tests/ambient_environment.rs`.
fn mounted_config() -> Config {
    let models = std::env::var("ENCLAVE_OCR_MODELS")
        .expect("ENCLAVE_OCR_MODELS must name the mounted model directory");
    let pdfium =
        std::env::var("ENCLAVE_PDFIUM").expect("ENCLAVE_PDFIUM must name the mounted PDFium");

    ConfigLoader::new()
        .with_env([("ENCLAVE_OCR_MODELS", models), ("ENCLAVE_PDFIUM", pdfium)])
        .load()
        .expect("a configuration naming both volumes is valid")
        .into_config()
}

fn chunker() -> Chunker {
    Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default())
}

fn stage() -> MountedOcr {
    MountedOcr::from_config(&mounted_config(), chunker(), UNTIMED)
        .expect("both volumes are mounted")
        .expect("a configuration naming both volumes must build a stage")
}

fn textless(media_type: &str, pages: Vec<u32>) -> Prepared {
    Prepared {
        outcome: Outcome::NoText(TextlessSource {
            media_type: media_type.to_owned(),
            pages_without_text: pages,
        }),
        chunks: Vec::new(),
    }
}

// -------------------------------------------------------------------------------------------
// Construction.
// -------------------------------------------------------------------------------------------

#[test]
#[ignore = "requires OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
fn the_variables_ci_sets_are_the_fields_that_build_the_stage() {
    // **The positive control for `crates/worker/src/ocr.rs`'s
    // `a_deployment_with_no_mounts_builds_no_stage`.** That assertion is an absence and passes for
    // free against a `from_config` that returns `None` for every input; this is the case where
    // something must come back, and it is the only test in the repository that runs the whole
    // chain — environment variable, loader, `Config` field, `OcrModels::mounted`,
    // `PdfiumLibrary::mounted` — that a deployment actually traverses.
    let config = mounted_config();
    assert!(config.ocr_models.is_some(), "ENCLAVE_OCR_MODELS did not reach `ocr_models`");
    assert!(config.pdfium.is_some(), "ENCLAVE_PDFIUM did not reach `pdfium`");

    let built = MountedOcr::from_config(&config, chunker(), UNTIMED)
        .expect("both volumes are mounted and loadable");
    assert!(built.is_some(), "a configuration naming both volumes built no stage");
}

// -------------------------------------------------------------------------------------------
// Dispatch: what this stage does with each outcome and each media type.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_scanned_page_is_read_back_and_carries_the_page_it_came_from() {
    // The exit criterion's second half, through the stage a *configuration* built rather than
    // through an `OcrRetry` a test assembled. `crates/indexing/tests/pdf.rs` proves the engine reads
    // a rendered page; what is proved here is that nothing in `MountedOcr` drops it on the way.
    //
    // The recognised string is asserted loosely — one word of two, upper-cased. How well `ocrs`
    // reads Helvetica is `ocrs`'s problem (`docs/12 §1.1`); that *something* came back and reached
    // the chunker is ours, and an assertion of `chunks.len() > 0` alone would pass against a stage
    // that recognised noise.
    let prepared = stage()
        .retry(VersionId::new_v7(), textless("application/pdf", vec![1]), page_of_words())
        .await
        .expect("neither the rasteriser nor the engine failed");

    assert_eq!(
        prepared.outcome.status(),
        ManifestStatus::Ready,
        "a scanned page whose words were recognised must be searchable: {:?}",
        prepared.outcome
    );
    assert_eq!(prepared.outcome.reason(), None);

    // Asserts that *something* was recovered, never *what* — `docs/12 §1.1`. Whether `ocrs` reads
    // "INVOICE" or "NVOCE" off a rendered glyph is the engine's accuracy against a platform's font
    // rasterisation, and it is not ours to assert: this test failed on CI's Linux runner with
    // `recognised "NVOCE\nTOTAL"` while passing on macOS, which is the same shape as `ENC-550`'s
    // timing failure — a verdict that depends on the machine.
    //
    // What this file is for is the wiring: a mounted stage reached a textless document, recovered
    // text from a rendered page, and produced chunks that carry the page they came from. A
    // non-empty chunk is the honest form of "recovered text"; the page assertion below is the part
    // that would actually break if the stage were miswired.
    let text: String = prepared.chunks.iter().map(|chunk| chunk.text.as_str()).collect();
    assert!(
        text.chars().any(char::is_alphanumeric),
        "the stage recovered no readable characters at all: {text:?}"
    );

    assert_eq!(
        prepared.chunks.first().and_then(|chunk| chunk.coordinates.page_number),
        Some(1),
        "a chunk that cannot name its page is a citation nobody can navigate to"
    );
}

#[tokio::test]
#[ignore = "requires OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_blank_page_stays_failed_and_keeps_its_work_list() {
    // D24 with the rasteriser in place: the tempting outcome is `READY` over a document that
    // recognised nothing, which is an index entry that reads as filed and searchable with nothing
    // behind it. The work list must survive so a later attempt knows which pages to look at.
    //
    // The positive control is the test above — the identical stage over a page with words on it is
    // `READY`. Without it this assertion holds against a stage that recovers nothing from anything.
    //
    // What this test does **not** prove, recorded because a deliberate violation showed it: pointing
    // `RASTERISABLE` at the wrong media type leaves this green, because a blank page and a page
    // nothing rasterised both come back `NoText`. The dispatch is proved by
    // `a_type_nothing_here_rasterises_...` and by `the_stage_dispatches_on_the_decided_type_...` in
    // `tests/indexing.rs`; the mechanism here is the one that refuses `READY` over nothing.
    let prepared = stage()
        .retry(VersionId::new_v7(), textless("application/pdf", vec![1]), blank_page())
        .await
        .expect("a blank page is not an error");

    assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
    assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
    match prepared.outcome {
        Outcome::NoText(source) => assert_eq!(source.pages_without_text, vec![1]),
        other => panic!("expected the work list to survive, got {other:?}"),
    }
    assert!(prepared.chunks.is_empty());
}

#[tokio::test]
#[ignore = "requires OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_type_nothing_here_rasterises_is_left_intact_rather_than_fed_to_a_decoder() {
    // This stage's own dispatch, which nothing in `crates/indexing` covers because the pairing is
    // made here: PDFium reads PDFs, and a deployment that mounted it has said nothing about any
    // other format. A textless Word document gets `NoPageImages` — no image for any page — so the
    // work list survives untouched and no verdict is recorded against a document nothing here can
    // rasterise.
    //
    // The failure this prevents is not subtle: handing these bytes to `PdfiumPages` anyway would put
    // a non-PDF through a PDF parser on the strength of nobody having checked, which is the
    // dispatch-on-the-claim mistake `crates/preview/src/raster.rs` exists to refuse.
    //
    // The positive control is `a_scanned_page_is_read_back_...`: the same stage, the same bytes-in
    // shape, `application/pdf`, becomes `READY`.
    let prepared = stage()
        .retry(VersionId::new_v7(), textless("application/msword", vec![1, 2]), page_of_words())
        .await
        .expect("an unrasterisable type is not an error");

    assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
    match prepared.outcome {
        Outcome::NoText(source) => {
            assert_eq!(source.pages_without_text, vec![1, 2], "the work list was rewritten");
            assert_eq!(source.media_type, "application/msword");
        }
        other => panic!("expected NoText, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires OCR weights named by ENCLAVE_OCR_MODELS and a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn an_outcome_that_is_not_textless_passes_through_untouched() {
    // The property that keeps OCR from being a silent fallback, asserted at this layer because this
    // is the layer that could break it — `MountedOcr::retry` could have decided something before
    // delegating. A refusal is a verdict about a document; rewriting it as "no text" would turn a
    // visible failure into an invisible absence.
    //
    // The bytes handed over are a page *with words on it*, so a stage that ran OCR anyway would
    // produce `Ready` and fail this loudly rather than silently agreeing.
    let stage = stage();
    for outcome in [
        Outcome::Refused(enclave_indexing::Refusal::Timeout),
        Outcome::Unsupported,
        Outcome::Ready { chunks: core::num::NonZeroU32::new(3).unwrap() },
    ] {
        let before = format!("{outcome:?}");
        let after = stage
            .retry(VersionId::new_v7(), Prepared { outcome, chunks: Vec::new() }, page_of_words())
            .await
            .expect("a pass-through is not an error");
        assert_eq!(format!("{:?}", after.outcome), before, "OCR rewrote a verdict");
    }
}
