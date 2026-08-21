//! The OCR stage, built from what a deployment mounted — or not built at all.
//!
//! `ENC-546`. `crates/indexing` has had [`OcrExtractor`], [`OcrRetry`] and [`PdfiumPages`] since
//! `ENC-537`, and nothing outside its tests ever constructed one. This module is the constructor,
//! and [`index_pass`](crate::indexing::index_pass) is its only caller.
//!
//! # Three states, and the middle one is the point
//!
//! [`Config::ocr_mounts`] answers with three states rather than two, and this module honours all
//! three:
//!
//! | Configuration | What is built | What a scanned PDF does |
//! |---|---|---|
//! | Neither mount | nothing — [`None`] | `FAILED` / `no_text_extracted`, exactly as today |
//! | Both mounts | [`MountedOcr`] | OCR runs over the pages the work list names |
//! | One mount | **nothing is built; startup fails** | — |
//!
//! The third row is the one worth having. A deployment that staged the weights and forgot PDFium
//! would otherwise index every scanned PDF as empty while its configuration file said OCR was on —
//! `plans/M3-DISCOVERY.md` D24's failure mode arrived through configuration instead of through code.
//! `enclave_config::validate::check_mounts` refuses it at startup; [`MountedOcr::from_config`]
//! refuses it again, because a `Config` assembled in code never passes through the loader and the
//! guard that only exists on one of two paths is the guard that is missing on the day it matters.
//!
//! # What "absent" means here, and why it is not a degradation
//!
//! A deployment with no mounts is not a deployment with broken OCR. It is a deployment with no OCR,
//! and its scanned PDFs are recorded `FAILED` with `no_text_extracted` — a manifest state somebody
//! reads, a file visibly unsearchable rather than invisibly empty. That is the *documented absence*
//! D24 asks for, and it is why this module never silently substitutes something weaker.
//!
//! What it must never become is the tempting shortcut: no mount, so hand the OCR engine the PDF's
//! own bytes and let it try. That feeds an image decoder a file that is not an image, which is the
//! dispatch-on-the-claim mistake `crates/preview/src/raster.rs` exists to avoid. There is no code
//! path here that can express it.
//!
//! # A failed mount is an error, never an empty document
//!
//! [`OcrModels::mounted`] and [`PdfiumLibrary::mounted`] both fail rather than degrade, and both
//! failures propagate out of [`MountedOcr::from_config`] to whatever starts the worker. A volume
//! that failed to attach is an outage. Reporting it as a corpus of textless files would leave every
//! document it touched invisible to search long after the outage ended, with nothing saying so —
//! `crates/indexing/src/error.rs` states that as the indexing crate's property and this module does
//! not get to weaken it at the composition layer.
//!
//! # Threads
//!
//! `rten` pulls `rayon` unconditionally and there is no feature that removes it (`ENC-535`), so an
//! OCR worker runs a thread pool nested inside a parser on a `spawn_blocking` thread. Nothing in
//! library code sets `RTEN_NUM_THREADS`, deliberately — a library that mutates the process
//! environment does so to every other thread in the process without being asked. It is set beside
//! the worker's CPU limit by whoever deploys it, and `docs/11-OPERATIONS.md §3.2` is where that is
//! written down.

use std::sync::Arc;

use enclave_config::{Config, OcrMounts};
use enclave_core::VersionId;
use enclave_indexing::{
    BoundedExtractor, Chunker, NoPageImages, OcrExtractor, OcrModels, OcrRetry, Outcome,
    PdfiumLibrary, PdfiumPages, Prepared,
};
use enclave_preview::RenderBudget;

use crate::{Result, WorkerError};

/// The one media type this stage has a page rasteriser for.
///
/// A constant here rather than a question asked of `crates/indexing`, because the pairing is this
/// module's: PDFium reads PDFs, and a deployment that mounts it has said nothing about any other
/// format. Anything else textless gets [`NoPageImages`] — no image for any page, which is the honest
/// answer and leaves the manifest saying `FAILED` rather than claiming a verdict about a document
/// nothing here can rasterise.
const RASTERISABLE: &str = "application/pdf";

/// OCR over a scanned document, using the volumes a deployment mounted.
///
/// Holds the models and the library and nothing else — no store handle, no client, no key. The
/// no-egress property `crates/indexing/src/extract.rs` states for extractors applies with more force
/// here: this is the stage that has the whole of a document decoded in memory.
///
/// Cheap to clone conceptually but deliberately not [`Clone`]: one worker builds one of these and
/// lends it out by reference. `OcrModels` is tens of megabytes and `PdfiumLibrary` is a process
/// singleton, so both are already behind an [`Arc`] internally.
#[derive(Debug)]
pub struct MountedOcr {
    /// Wrapped in [`BoundedExtractor`] here rather than by the caller, because
    /// [`OcrRetry::new`]'s documentation says to and the caller is not in a position to notice if
    /// it were skipped: an unwrapped OCR extractor is correct-looking and unbounded, and the wall
    /// clock is the only thing standing between a hostile page and a stuck worker thread.
    extractor: BoundedExtractor<OcrExtractor>,
    library: Arc<PdfiumLibrary>,
    chunker: Chunker,
    /// The **per-page** budget, held here for the reason [`OcrRetry::new`] gives: OCR is seconds per
    /// page against milliseconds for text, so a nine-hundred-page scan under the text extractor's
    /// wall clock is a guaranteed timeout and the exit criterion could never be met.
    budget: RenderBudget,
}

impl MountedOcr {
    /// Builds the stage a deployment's configuration asks for, if it asks for one.
    ///
    /// `budget` is the per-page budget, not the extraction request's. See the field documentation.
    ///
    /// # Errors
    ///
    /// * [`WorkerError::IncompleteMount`] when one of the two volumes is configured and the other is
    ///   not. `enclave_config` refuses that at startup too; this is the second guard, for a `Config`
    ///   built in code.
    /// * [`WorkerError::Indexing`] when a configured volume cannot be loaded — missing, unreadable,
    ///   or an ABI that does not match this build. An outage, and reported as one.
    pub fn from_config(
        config: &Config,
        chunker: Chunker,
        budget: RenderBudget,
    ) -> Result<Option<Self>> {
        let (models, pdfium) = match config.ocr_mounts() {
            // The deny-by-default state, and the one almost every deployment is in.
            OcrMounts::Absent => return Ok(None),
            OcrMounts::Incomplete { present, missing } => {
                return Err(WorkerError::IncompleteMount { present, missing })
            }
            OcrMounts::Mounted { models, pdfium } => (models, pdfium),
        };

        // Both mounts before either is used, so a deployment with a bad PDFium volume finds out at
        // startup rather than on the first scanned upload. `?` and not a fallback: see the module
        // documentation on why a failed mount is an outage.
        let models = Arc::new(OcrModels::mounted(models)?);
        let library = PdfiumLibrary::mounted(pdfium)?;

        Ok(Some(Self {
            extractor: BoundedExtractor::new(OcrExtractor::new(models)),
            library,
            chunker,
            budget,
        }))
    }

    /// The mounted PDFium, so the composition root can build a [`PdfTextExtractor`] over the very
    /// same library this stage rasterises with.
    ///
    /// Handed out rather than mounted twice: `PdfiumLibrary` is a process singleton — `ENC-551`
    /// records that concurrent work across two PDFium *documents* crashes the process, and the
    /// `DOCUMENTS` lock that fixes it is per-library. Two libraries would be two locks, which is no
    /// lock at all.
    #[must_use]
    pub fn library(&self) -> Arc<PdfiumLibrary> {
        Arc::clone(&self.library)
    }

    /// Re-runs OCR over a textless document, reading its pages through PDFium.
    ///
    /// Anything that is not [`Outcome::NoText`] is returned untouched — that is
    /// [`OcrRetry::retry`]'s structural property, not a check repeated here, and it is what stops
    /// OCR turning *"this document failed"* into *"this document is empty"*.
    ///
    /// `source` is the document's bytes and `version` the version they belong to. Taken **by
    /// value**, because `PdfiumPages` needs an owned copy and a borrow here would mean a second one:
    /// a scanned document is tens of megabytes and the point of re-reading them (see
    /// `crate::indexing`) was to avoid holding two. Dispatch is on the
    /// **decided** media type carried by the textless outcome, not on what the uploader declared:
    /// the extractor established that type by reading the bytes, and the declared one is a hint
    /// (`Extractor::supports` says so in its own words).
    ///
    /// # Errors
    ///
    /// Whatever the rasteriser or the OCR extractor returns as an error, unchanged and
    /// un-downgraded.
    pub async fn retry(
        &self,
        version: VersionId,
        prepared: Prepared,
        source: Vec<u8>,
    ) -> Result<Prepared> {
        let Outcome::NoText(ref textless) = prepared.outcome else {
            return Ok(prepared);
        };

        if textless.media_type != RASTERISABLE {
            // Nothing here rasterises this source. `NoPageImages` yields no image for any page, so
            // the retry recovers nothing and the work list survives for a later attempt — an
            // absence, not a verdict about somebody's document.
            let retry =
                OcrRetry::new(self.extractor.clone(), NoPageImages, self.chunker, self.budget);
            return Ok(retry.retry(version, prepared).await?);
        }

        let pages = PdfiumPages::new(Arc::clone(&self.library), source, self.budget);
        let retry = OcrRetry::new(self.extractor.clone(), pages, self.chunker, self.budget);
        Ok(retry.retry(version, prepared).await?)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::path::PathBuf;

    use enclave_indexing::{ChunkBudget, ChunkerVersion};

    use super::*;

    fn chunker() -> Chunker {
        Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default())
    }

    fn build(config: &Config) -> Result<Option<MountedOcr>> {
        MountedOcr::from_config(config, chunker(), RenderBudget::DEFAULT)
    }

    #[test]
    fn a_deployment_with_no_mounts_builds_no_stage() {
        // Today's behaviour, kept. On its own this assertion passes for free against a
        // `from_config` that returns `None` for everything — the positive control is
        // `both_mounts_build_a_stage` in `tests/ocr_mounts.rs`, which needs the real volumes and so
        // cannot live here.
        assert!(build(&Config::default()).expect("no mounts is not an error").is_none());
    }

    #[test]
    fn half_a_mount_refuses_rather_than_building_half_a_stage() {
        // The second of the two guards. `enclave_config` refuses this through the loader; a `Config`
        // assembled in code — a test, an admin-API edit, a future embedded default — never goes
        // through the loader, and a guard on one of two paths is missing on the day it matters.
        //
        // Both directions, because the tempting implementation checks one.
        let models = Config { ocr_models: Some(PathBuf::from("/mnt/ocr")), ..Config::default() };
        match build(&models) {
            Err(WorkerError::IncompleteMount { present, missing }) => {
                assert_eq!(present, "ocr_models");
                assert_eq!(missing, "pdfium");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        let pdfium = Config { pdfium: Some(PathBuf::from("/mnt/pdfium")), ..Config::default() };
        match build(&pdfium) {
            Err(WorkerError::IncompleteMount { present, missing }) => {
                assert_eq!(present, "pdfium");
                assert_eq!(missing, "ocr_models");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_mount_that_does_not_exist_is_an_error_and_never_a_silent_absence() {
        // The distinction this whole module turns on: "no OCR configured" is `Ok(None)` and
        // "OCR configured against a volume that is not there" is `Err`. An implementation that
        // treated an unloadable mount as "no OCR" would give a deployment whose volume failed to
        // attach a corpus of textless files and no error anywhere.
        let config = Config {
            ocr_models: Some(PathBuf::from("/nonexistent/enclave/ocr-models")),
            pdfium: Some(PathBuf::from("/nonexistent/enclave/pdfium")),
            ..Config::default()
        };

        let error = build(&config).expect_err("a missing volume must not read as `no OCR`");
        assert!(matches!(error, WorkerError::Indexing(_)), "{error:?}");
    }

    #[test]
    fn the_refusal_message_can_carry_only_key_names() {
        // CLAUDE.md rule 10, and the reason both fields are `&'static str`. A message built from a
        // configured *value* would put a deployment's filesystem layout into a log pipeline; these
        // two can only ever name a key that appears in this source file.
        let error = WorkerError::IncompleteMount { present: "ocr_models", missing: "pdfium" };
        let shown = error.to_string();
        assert!(shown.contains("ocr_models"), "{shown}");
        assert!(shown.contains("pdfium"), "{shown}");
    }
}
