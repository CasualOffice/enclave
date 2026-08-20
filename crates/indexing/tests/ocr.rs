//! OCR against the real engine and the real model weights.
//!
//! # Why every test here is `#[ignore]`d
//!
//! `ocrs` ships no weights, and this repository does not either — `crates/indexing/src/ocr.rs`
//! explains why at length, and the short version is that the published models are **CC-BY-SA-4.0**
//! and `deny.toml`'s allowlist is permissive-only. Baking them into the image would put a
//! share-alike obligation inside a product image, past a gate that structurally cannot see it
//! because the weights are not a crate.
//!
//! So they are mounted, and a test that needs them needs the mount. That is the same shape the
//! PostgreSQL, Milvus and ClamAV suites already have: `#[ignore]`d with a reason naming what is
//! required, and run in CI with `--include-ignored` against an environment that has it.
//!
//! Point `ENCLAVE_OCR_MODELS` at a directory holding `text-detection.rten` and
//! `text-recognition.rten` — **the two files `ocrs`'s own `download-models.sh` fetches**, from
//! `ocrs-models.s3-accelerate.amazonaws.com` — and run:
//!
//! ```text
//! ENCLAVE_OCR_MODELS=/path/to/models cargo test --release -p enclave-indexing --test ocr \
//!     -- --include-ignored
//! ```
//!
//! **Not the `.rten` files on the Hugging Face model card**, even though that is where the licence
//! is stated and where a search lands you. Those are named `*-checkpoint-*` and are training
//! checkpoints: they load, they run, and they produce garbage. Staging them was tried here first,
//! and `a_page_of_text_with_no_text_layer_is_read_back_as_text` came back with
//! `2026 TOTAL / NVOICE / C / C / 1`, while `a_blank_page_is_textless_rather_than_an_empty_success`
//! **hallucinated eighteen lines of single characters onto a plain white page**. That is the dangerous
//! shape: wrong weights do not fail, they fill the index with noise that reads as content. Both
//! tests pass on the released models, which is the only reason this distinction is written down
//! rather than discovered by whoever stages the volume.
//!
//! **Run it in release.** `ocrs` and `rten` say so in their own documentation, and a debug build of
//! the inference kernels is slow enough to look like a hang rather than a slow test.
//!
//! # The image these tests read is drawn here, not committed
//!
//! A committed scan would be a binary fixture whose content nobody can review in a diff, and — worse
//! for a test that is meant to prove OCR works — one whose expected text is a claim about a file
//! rather than something the test constructed. So each test rasterises a known string with the font
//! `enclave-preview` already vendors, and asserts the engine reads that string back.
//!
//! What that does **not** prove is accuracy on a real scan: clean synthetic glyphs on white are the
//! easiest input an OCR engine ever sees, with none of the skew, noise, bleed-through or JPEG
//! artefacts of a document that went through a photocopier. These tests prove the wiring — models
//! load, an image reaches the engine, recognised text becomes a [`TextDocument`] inside its budget.
//! Accuracy on real scans is a measurement nobody has taken.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use ab_glyph::{Font as _, FontRef, PxScale, ScaleFont as _};
use enclave_indexing::{
    ExtractOutcome, ExtractRequest, Extractor, IndexingError, OcrExtractor, OcrModels, RenderBudget,
};
use image::{ImageFormat, Rgb, RgbImage};

/// Attached to every `#[ignore]` so the requirement is named at the test rather than in a comment
/// somebody has to go and find.
const NEEDS_MODELS: &str =
    "requires OCR model weights on a volume named by ENCLAVE_OCR_MODELS; CI runs it with \
     --include-ignored";

/// The font `enclave-preview` vendors for the watermark compositor.
///
/// Borrowed rather than vendored a second time. It is in this repository, it is compiled into the
/// preview crate already, and a second copy of a font file is a second thing to keep in step with
/// `crates/preview/assets/README.md`'s licensing note.
const FONT: &[u8] = include_bytes!("../../preview/assets/inter-latin.ttf");

/// The mounted model directory, or a skip.
///
/// Read from the environment rather than from a constant, because the whole point of mounting is
/// that the deployment chooses where the volume lands.
fn models_directory() -> PathBuf {
    PathBuf::from(
        std::env::var("ENCLAVE_OCR_MODELS")
            .expect("ENCLAVE_OCR_MODELS must name the mounted model directory"),
    )
}

fn models() -> Arc<OcrModels> {
    Arc::new(OcrModels::mounted(&models_directory()).expect("the mounted models load"))
}

/// Renders one line of black text on white, large, and encodes it as PNG.
///
/// Deliberately generous: 64px glyphs with wide margins. A test that also probes the engine's limits
/// would be measuring the model rather than this crate's wiring, and would fail on a model update
/// for reasons nobody here could act on.
fn png_of_text(text: &str) -> Vec<u8> {
    let font = FontRef::try_from_slice(FONT).expect("the vendored face parses");
    let scale = PxScale::from(64.0);
    let scaled = font.as_scaled(scale);

    let margin = 40_i32;
    let baseline = margin + scaled.ascent() as i32;
    let height = (margin * 2 + scaled.height() as i32) as u32;

    // Laid out first to size the canvas, so no glyph is clipped by a guess about the width.
    let mut caret = margin as f32;
    let mut placed = Vec::new();
    let mut previous = None;
    for character in text.chars() {
        let id = font.glyph_id(character);
        if let Some(last) = previous {
            caret += scaled.kern(last, id);
        }
        placed.push(id.with_scale_and_position(scale, ab_glyph::point(caret, baseline as f32)));
        caret += scaled.h_advance(id);
        previous = Some(id);
    }
    let width = (caret as i32 + margin) as u32;

    let mut canvas = RgbImage::from_pixel(width, height, Rgb([255, 255, 255]));
    for glyph in placed {
        if let Some(outline) = font.outline_glyph(glyph) {
            let bounds = outline.px_bounds();
            outline.draw(|x, y, coverage| {
                let px = bounds.min.x as i32 + x as i32;
                let py = bounds.min.y as i32 + y as i32;
                if px < 0 || py < 0 || px as u32 >= width || py as u32 >= height {
                    return;
                }
                // Straight to black at any coverage worth inking: anti-aliased grey is what a
                // scanner produces and what the engine is trained on, but a test that leaned on
                // subtle coverage would be measuring the rasteriser.
                let value = 255 - (coverage * 255.0) as u8;
                canvas.put_pixel(px as u32, py as u32, Rgb([value, value, value]));
            });
        }
    }

    let mut bytes = Vec::new();
    canvas
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
        .expect("encoding the test page");
    bytes
}

/// CRC-32/ISO-HDLC, the checksum every PNG chunk carries.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// A structurally valid PNG under a hundred bytes that declares `width × height`.
///
/// The decode bomb. `src/ocr.rs` has the same helper and the argument for why the checksums have to
/// be right — a malformed one makes the file *unreadable*, which is a different refusal reached
/// without the size ever being consulted.
fn png_declaring(width: u32, height: u32) -> Vec<u8> {
    let mut png = Vec::from(*b"\x89PNG\r\n\x1a\n");
    let mut chunk = |kind: &[u8; 4], payload: &[u8]| {
        let mut typed = Vec::from(*kind);
        typed.extend_from_slice(payload);
        png.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        png.extend_from_slice(&typed);
        png.extend_from_slice(&crc32(&typed).to_be_bytes());
    };

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    // 8-bit, colour type 6 (RGBA), deflate, adaptive filtering, no interlace.
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
    chunk(b"IEND", &[]);
    png
}

async fn extract(source: Vec<u8>, budget: RenderBudget) -> ExtractOutcome {
    OcrExtractor::new(models())
        .extract(ExtractRequest { declared_media_type: "image/png".to_owned(), source, budget })
        .await
        .expect("the extractor does not fail on our side")
}

#[tokio::test]
#[ignore = "requires OCR model weights on a volume named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_page_of_text_with_no_text_layer_is_read_back_as_text() {
    // `ENC-161`, at the smallest scale that means anything: an image carrying words and no character
    // data at all becomes a `TextDocument`. Every other test in this crate proves what happens
    // *around* that; this is the one that proves the engine is wired to something.
    let outcome = extract(png_of_text("INVOICE 2026 TOTAL"), RenderBudget::DEFAULT).await;

    let ExtractOutcome::Extracted(document) = outcome else {
        panic!("a page of plain words was not read: {outcome:?}");
    };

    let text = document.flatten().to_uppercase();
    assert!(text.contains("INVOICE"), "recognised {text:?}");
    assert!(text.contains("2026"), "recognised {text:?}");
    assert!(!document.is_empty());
    assert_eq!(document.media_type, "image/png");
    // Never the uploader's claim, and never a page number an image does not have.
    assert_eq!(document.page_count, None);
}

#[tokio::test]
#[ignore = "requires OCR model weights on a volume named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_blank_page_is_textless_rather_than_an_empty_success() {
    // D24's failure mode at the engine boundary. A scanned blank page must not come back as
    // `Extracted` with nothing in it, because that is what `READY`-with-no-content is made of.
    let mut bytes = Vec::new();
    RgbImage::from_pixel(1_200, 400, Rgb([255, 255, 255]))
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
        .expect("encoding a blank page");

    let outcome = extract(bytes, RenderBudget::DEFAULT).await;

    assert!(
        matches!(outcome, ExtractOutcome::NoText(_)),
        "a blank page produced {outcome:?} rather than a textless source"
    );
}

#[tokio::test]
#[ignore = "requires OCR model weights on a volume named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_source_that_is_not_an_image_never_reaches_the_engine() {
    // The declared media type is a hint, not a trust boundary. These bytes claim `image/png` and are
    // a PDF, and the sniff is what decides — an extractor that dispatched on the claim would hand an
    // image decoder a page tree.
    let outcome =
        extract(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n".to_vec(), RenderBudget::DEFAULT).await;

    assert!(
        matches!(outcome, ExtractOutcome::Refused(enclave_indexing::Refusal::UnsupportedFormat)),
        "{outcome:?}"
    );
}

#[tokio::test]
#[ignore = "requires OCR model weights on a volume named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_decode_bomb_is_refused_on_the_real_extraction_path() {
    // `src/ocr.rs` proves the ordering against `decode` directly. This proves it is still true with
    // the engine wired in and a `spawn_blocking` hop in the middle — the layer where an "optimisation"
    // that decoded before checking would actually land.
    //
    // The budget's output cap is what bounds the decoded buffer, so 1 MiB is well under the 1.6 GB
    // this header asks for and well over anything the check should refuse by accident.
    let budget = RenderBudget { max_output_bytes: 1024 * 1024, ..RenderBudget::DEFAULT };
    let outcome = extract(png_declaring(20_000, 20_000), budget).await;

    assert!(matches!(outcome, ExtractOutcome::Refused(_)), "{outcome:?}");
}

/// Runs without models on purpose — it is about the other tests, not about OCR.
#[test]
fn every_ignore_in_this_file_names_the_mount_and_how_to_run_it() {
    // `plans/M1-CONTENT-CORE.md §5` forbids an `#[ignore]` without a written reason naming where
    // the test *does* run. Read out of this file rather than asserted about the constant, because
    // the failure worth catching is a new test copying an `#[ignore]` with a vaguer reason — the
    // constant would still say the right thing and nothing would be checking the attribute.
    let source = include_str!("ocr.rs");
    let reasons: Vec<&str> =
        source.lines().filter(|line| line.trim_start().starts_with("#[ignore")).collect();

    assert!(reasons.len() >= 3, "expected the weight-dependent tests to be ignored");
    for reason in reasons {
        assert!(
            reason.contains(NEEDS_MODELS),
            "an #[ignore] here does not name the mount and the --include-ignored run: {reason}"
        );
    }
}

#[test]
fn a_missing_mount_is_our_failure_and_never_a_verdict_about_a_document() {
    // **Not `#[ignore]`d**: the absence of models is exactly what this asserts, so it is the one
    // test here that needs nothing staged.
    //
    // A deployment whose model volume failed to attach has an outage, not a corpus of textless
    // files. If this mapped to anything a manifest reads as "this document has no text", the mount
    // failure would be recorded against every file the worker touched.
    let error = OcrModels::mounted(&PathBuf::from("/nonexistent/enclave-ocr-models"))
        .expect_err("no models are mounted there");

    assert!(matches!(error, IndexingError::Worker(_)), "{error:?}");

    let rendered = error.to_string();
    assert_eq!(
        rendered, "the extraction worker failed",
        "the crate's own error text is a fixed phrase"
    );
}

#[test]
fn a_model_load_failure_never_carries_the_runtimes_message() {
    // `CLAUDE.md` rule 10, at the one place this module surfaces a string at all. The path is
    // operator configuration and is safe — and necessary — to name. The runtime's message is derived
    // from file contents, and a model file is the one thing on that volume an attacker who reached
    // it would control.
    let error = OcrModels::mounted(&PathBuf::from("/nonexistent/enclave-ocr-models"))
        .expect_err("no models are mounted there");
    // The `Debug` rendering, not `Display`: `IndexingError::Worker`'s own text is the fixed phrase
    // the test above asserts, and everything this test is about lives in the source it wraps.
    let chain = format!("{error:?}");

    assert!(
        chain.contains("/nonexistent/enclave-ocr-models"),
        "the mount path is what an operator needs to diagnose this: {chain}"
    );
    // `rten`'s `LoadError` renders as one of these; none of them may appear.
    for leaked in ["No such file", "os error", "ParseFailed", "InvalidHeader", "SchemaVersion"] {
        assert!(!chain.contains(leaked), "the runtime's message reached the error: {chain}");
    }
}
