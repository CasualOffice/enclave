//! PDF page rasterisation against the real PDFium, and the exit criterion it exists for.
//!
//! # Why most of this file is `#[ignore]`d
//!
//! PDFium is a 7 MB shared library per platform, mounted at run time rather than committed —
//! `crates/indexing/src/pdf.rs` says why, and the short version is that a binary artefact is content
//! nobody reviews in a diff and `cargo deny` structurally cannot audit. So a test that needs it needs
//! the mount, which is the shape the PostgreSQL, Milvus, ClamAV and OCR suites already have:
//! `#[ignore]`d with a reason naming what is required, and run in CI with `--include-ignored` against
//! an environment that has it.
//!
//! **An `#[ignore]` is not insulation from CI.** `.github/workflows/ci.yml` fetches the library in a
//! step of its own, exactly as it fetches the OCR models, because a test that is ignored locally and
//! run in CI without its dependency is a red build that says nothing about the code.
//!
//! Stage a directory holding `libpdfium.so` (Linux) or `libpdfium.dylib` (macOS) — the **non-V8,
//! non-XFA** build from `bblanchon/pdfium-binaries`, matching the `pdfium_7881` feature the workspace
//! manifest pins — point `ENCLAVE_PDFIUM` at it, and run:
//!
//! ```text
//! ENCLAVE_PDFIUM=/path/to/pdfium/lib ENCLAVE_OCR_MODELS=/path/to/models \
//!     cargo test --release -p enclave-indexing --test pdf -- --include-ignored
//! ```
//!
//! **Run it in release** for the same reason `tests/ocr.rs` says so: the recognition kernels in a
//! debug build are slow enough to look like a hang.
//!
//! # The documents are built here, not committed
//!
//! Every PDF in this file is assembled byte by byte below, for the reason `tests/ocr.rs` gives about
//! its page images: a committed fixture is a binary whose content nobody can review in a diff, and —
//! worse for a test meant to prove OCR reads a scan — one whose expected text is a claim about a file
//! rather than something the test constructed.
//!
//! [`scanned_pdf`] builds the thing the exit criterion names: a page whose entire content stream is
//! one JPEG, with no font resource and no text-showing operator anywhere in the file. [`typed_pdf`]
//! builds its opposite and exists as the positive control for
//! [`the_scanned_documents_here_really_have_no_text_layer`] — without it, a scanner asserting the
//! absence of `BT` would pass against a scanner that never finds anything. [`pdf_of`] mixes the two,
//! which is `ENC-545`'s hardest case and a document neither of the previous two builders could
//! produce.
//!
//! # `ENC-545`: the front half, and what the criterion now runs through
//!
//! That source-level check does **not** ask PDFium whether the text layer is empty, which is the
//! stronger statement. It could not, until `ENC-545`: reaching PDFium's text API means a PDF *text*
//! extractor, `NoExtractor` answered for `application/pdf`, and every scanned document was `SKIPPED`
//! before a page was ever rasterised.
//!
//! [`PdfTextExtractor`] is that extractor, so the criterion test below no longer hands `OcrRetry` a
//! work list somebody typed. It runs `Pipeline::prepare` over the real bytes, takes whatever the text
//! extractor decided, and hands *that* to the retry — which is the wiring the criterion is about, and
//! the part no previous test in this file covered.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use ab_glyph::{Font as _, FontRef, PxScale, ScaleFont as _};
use enclave_core::VersionId;
use enclave_indexing::{
    BoundedExtractor, ChunkBudget, Chunker, ChunkerVersion, ExtractOutcome, ExtractRequest,
    Extractor as _, ManifestStatus, OcrExtractor, OcrModels, OcrRetry, Outcome, PageImage,
    PageImages, PdfTextExtractor, PdfiumLibrary, PdfiumPages, Pipeline, Prepared, Reason, Refusal,
    RenderBudget, SegmentKind,
};
use image::{ExtendedColorType, ImageEncoder as _, ImageFormat, ImageReader, Rgb, RgbImage};

/// Attached to every `#[ignore]` that needs only the library.
const NEEDS_PDFIUM: &str = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with \
                            --include-ignored";

/// Attached to every `#[ignore]` that needs the library *and* the OCR weights.
const NEEDS_PDFIUM_AND_MODELS: &str =
    "requires a mounted PDFium named by ENCLAVE_PDFIUM and OCR weights named by \
     ENCLAVE_OCR_MODELS; CI runs it with --include-ignored";

/// The longest edge `crates/indexing/src/pdf.rs` clamps a rendered page to.
///
/// Restated here rather than exported, because a test that read the constant out of the module would
/// pass against any value of it — including a value large enough that the clamp bounds nothing. This
/// number is the assertion.
const MAX_EDGE: u32 = 2_400;

/// The font `enclave-preview` vendors for the watermark compositor, borrowed rather than copied.
const FONT: &[u8] = include_bytes!("../../preview/assets/inter-latin.ttf");

fn library() -> Arc<PdfiumLibrary> {
    let directory = PathBuf::from(
        std::env::var("ENCLAVE_PDFIUM").expect("ENCLAVE_PDFIUM must name the mounted PDFium"),
    );
    PdfiumLibrary::mounted(&directory).expect("the mounted library loads")
}

fn models() -> Arc<OcrModels> {
    let directory = PathBuf::from(
        std::env::var("ENCLAVE_OCR_MODELS")
            .expect("ENCLAVE_OCR_MODELS must name the mounted model directory"),
    );
    Arc::new(OcrModels::mounted(&directory).expect("the mounted models load"))
}

/// `RenderBudget::DEFAULT` with the clock taken off.
///
/// The end-to-end OCR tests below rasterise pages and then recognise text on them, and the *only*
/// thing they assert is our wiring: that a scanned PDF reaches `READY` with its page recorded, and
/// that a blank one does not. How long `ocrs` takes to do that is the engine's business, and on a
/// machine slower than the one a test was written on it is nobody's.
///
/// It was not hypothetical. `DEFAULT`'s 30-second clock passes here — this suite runs in about 22
/// seconds locally — and **timed out on CI's runner**, where both tests failed with
/// `Refused(Timeout)` and read as an OCR defect. A test whose verdict depends on how fast the
/// machine is will keep doing that, intermittently, and each occurrence teaches somebody that the
/// OCR path is flaky.
///
/// `docs/12 §1.1`: we test our integration, not a third party's speed. The tests that assert the
/// budget *itself* — input cap, page cap, output cap, the clamp — keep `DEFAULT` and tightened
/// values, because there the bound is the thing under test.
const UNTIMED: RenderBudget =
    RenderBudget { wall_clock: core::time::Duration::from_secs(600), ..RenderBudget::DEFAULT };

fn pages_of(pdf: Vec<u8>, budget: RenderBudget) -> PdfiumPages {
    PdfiumPages::new(library(), pdf, budget)
}

fn chunker() -> Chunker {
    Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default())
}

/// Runs the text extractor **unwrapped**, which is the only way to see its own bounds answer.
///
/// [`BoundedExtractor`] applies the input cap, the page cap and the output cap from outside, and it
/// applies them *first* — so a budget test run through the wrapper proves the wrapper. That is the
/// same shadowing `crates/indexing/src/ocr.rs` documents between its size check and `image`'s
/// `max_alloc`, and it is dodged here the same way: by asking the inner extractor directly.
///
/// The pipeline tests below use the wrapped extractor, because there the wrapper is part of the
/// wiring under test.
async fn extract(pdf: Vec<u8>, budget: RenderBudget) -> ExtractOutcome {
    PdfTextExtractor::new(library())
        .extract(ExtractRequest {
            declared_media_type: "application/pdf".to_owned(),
            source: pdf,
            budget,
        })
        .await
        .expect("no worker failure")
}

/// The pages a document reported having no text on, or a panic naming what it said instead.
fn work_list(outcome: &ExtractOutcome) -> Vec<u32> {
    match outcome {
        ExtractOutcome::NoText(source) => {
            assert_eq!(source.media_type, "application/pdf", "the source's type, not the pages'");
            source.pages_without_text.clone()
        }
        other => panic!("expected a textless document, got {other:?}"),
    }
}

// -------------------------------------------------------------------------------------------
// Building the documents.
// -------------------------------------------------------------------------------------------

/// One page: the JPEG that fills it, and the page box in points.
struct Page {
    jpeg: Vec<u8>,
    pixels: (u32, u32),
    /// The `/MediaBox`, in points. Usually the image at 72 dpi; deliberately not, for the clamp test.
    points: (u32, u32),
}

/// Renders one line of black text on white and encodes it as a JPEG.
///
/// JPEG rather than PNG because `/DCTDecode` lets the encoded bytes go into the PDF stream verbatim,
/// so the document below needs no filter of its own — the file says what it is made of.
fn jpeg_of_text(text: &str) -> (Vec<u8>, u32, u32) {
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
                let value = 255 - (coverage * 255.0) as u8;
                canvas.put_pixel(px as u32, py as u32, Rgb([value, value, value]));
            });
        }
    }

    (encode_jpeg(&canvas), width, height)
}

/// A blank white page image — the back of a sheet, or a section divider.
fn blank_jpeg(width: u32, height: u32) -> (Vec<u8>, u32, u32) {
    (encode_jpeg(&RgbImage::from_pixel(width, height, Rgb([255, 255, 255]))), width, height)
}

fn encode_jpeg(canvas: &RgbImage) -> Vec<u8> {
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 95)
        .write_image(canvas.as_raw(), canvas.width(), canvas.height(), ExtendedColorType::Rgb8)
        .expect("encoding the page image");
    bytes
}

fn page_of_text(text: &str) -> Page {
    let (jpeg, width, height) = jpeg_of_text(text);
    Page { jpeg, pixels: (width, height), points: (width, height) }
}

fn blank_page() -> Page {
    let (jpeg, width, height) = blank_jpeg(1_200, 400);
    Page { jpeg, pixels: (width, height), points: (width, height) }
}

/// What one sheet of a built document carries.
///
/// The two arms are the two things a page of a real PDF can be, and `ENC-545` needs a document that
/// is **both**: a report whose exhibits were scanned in. Before that, the two lived in two builders
/// that could not be mixed, which is exactly the document neither of them could produce.
enum Sheet<'a> {
    /// An image and nothing else. No `/Font`, no `BT`, no `Tj`.
    Scan(&'a Page),
    /// Real characters in a base-14 font.
    Typed(&'a str),
}

/// A PDF of the given sheets, with a real cross-reference table.
///
/// Written with a real table rather than relying on PDFium's tolerance for a broken one, so that a
/// test asserting `SourceUnreadable` for a *truncated* file is asserting something about the
/// truncation.
///
/// Three objects per page whichever kind it is — page, content, resource — so the numbering does not
/// depend on the mixture.
fn pdf_of(sheets: &[Sheet<'_>]) -> Vec<u8> {
    let mut out = Vec::from(*b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<usize> = Vec::new();

    fn object(out: &mut Vec<u8>, offsets: &mut Vec<usize>, number: usize, body: &[u8]) {
        offsets.push(out.len());
        out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    let kids: Vec<String> =
        (0..sheets.len()).map(|index| format!("{} 0 R", 3 + index * 3)).collect();
    object(&mut out, &mut offsets, 1, b"<< /Type /Catalog /Pages 2 0 R >>");
    object(
        &mut out,
        &mut offsets,
        2,
        format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.join(" "), sheets.len()).as_bytes(),
    );

    for (index, sheet) in sheets.iter().enumerate() {
        let (page_object, content_object, resource_object) =
            (3 + index * 3, 4 + index * 3, 5 + index * 3);

        let (media_box, resources, content) = match sheet {
            Sheet::Scan(page) => {
                let (points_width, points_height) = page.points;
                (
                    format!("[0 0 {points_width} {points_height}]"),
                    format!("<< /XObject << /Im0 {resource_object} 0 R >> >>"),
                    // The whole content stream: place the image over the page box. No text operator
                    // exists.
                    format!("q\n{points_width} 0 0 {points_height} 0 0 cm\n/Im0 Do\nQ\n"),
                )
            }
            Sheet::Typed(text) => (
                "[0 0 595 842]".to_owned(),
                format!("<< /Font << /F1 {resource_object} 0 R >> >>"),
                format!("BT\n/F1 24 Tf\n72 700 Td\n({text}) Tj\nET\n"),
            ),
        };

        object(
            &mut out,
            &mut offsets,
            page_object,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox {media_box} /Resources {resources} \
                 /Contents {content_object} 0 R >>"
            )
            .as_bytes(),
        );
        object(
            &mut out,
            &mut offsets,
            content_object,
            format!("<< /Length {} >>\nstream\n{content}endstream", content.len()).as_bytes(),
        );

        match sheet {
            Sheet::Scan(page) => {
                let (pixels_width, pixels_height) = page.pixels;
                let mut image = format!(
                    "<< /Type /XObject /Subtype /Image /Width {pixels_width} \
                     /Height {pixels_height} /ColorSpace /DeviceRGB /BitsPerComponent 8 \
                     /Filter /DCTDecode /Length {} >>\nstream\n",
                    page.jpeg.len()
                )
                .into_bytes();
                image.extend_from_slice(&page.jpeg);
                image.extend_from_slice(b"\nendstream");
                object(&mut out, &mut offsets, resource_object, &image);
            }
            Sheet::Typed(_) => object(
                &mut out,
                &mut offsets,
                resource_object,
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            ),
        }
    }

    trailer(out, &offsets)
}

/// A PDF whose pages are images and nothing else: a scan.
fn scanned_pdf(pages: &[Page]) -> Vec<u8> {
    pdf_of(&pages.iter().map(Sheet::Scan).collect::<Vec<_>>())
}

/// The opposite document: pages carrying real characters in a base-14 font.
fn typed_pdf(pages: &[&str]) -> Vec<u8> {
    pdf_of(&pages.iter().copied().map(Sheet::Typed).collect::<Vec<_>>())
}

fn trailer(mut out: Vec<u8>, offsets: &[usize]) -> Vec<u8> {
    let start = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n",
            offsets.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// The dimensions of a rendered page image, read from the PNG header alone.
fn dimensions_of(png: &[u8]) -> (u32, u32) {
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"), "a page image must be a PNG");
    ImageReader::with_format(std::io::Cursor::new(png), ImageFormat::Png)
        .into_dimensions()
        .expect("the rendered page's header parses")
}

// -------------------------------------------------------------------------------------------
// What the documents are, provable without the library.
// -------------------------------------------------------------------------------------------

#[test]
fn the_scanned_documents_here_really_have_no_text_layer() {
    // The premise the whole suite rests on. If `scanned_pdf` ever grew a font resource, the exit
    // criterion test below would still pass and would be proving that a *text* extractor works.
    //
    // The positive control is `typed_pdf`, scanned by the same function: without it, every assertion
    // here holds against a scanner that finds nothing in anything.
    let scanned = scanned_pdf(&[page_of_text("INVOICE 2026 TOTAL")]);
    let typed = typed_pdf(&["INVOICE 2026 TOTAL"]);

    // The JPEG payload is arbitrary bytes and can contain any two-character sequence by chance, so
    // the operators are looked for in the parts of the file that are not image data: everything
    // before the first image stream.
    let head = |pdf: &[u8]| -> String {
        let end = pdf
            .windows(11)
            .position(|window| window == b"/DCTDecode ".as_slice())
            .unwrap_or(pdf.len());
        String::from_utf8_lossy(&pdf[..end]).into_owned()
    };

    let scanned_head = head(&scanned);
    for operator in ["/Font", "BT\n", "Tj", "TJ"] {
        assert!(
            !scanned_head.contains(operator),
            "a document this suite calls a scan carries `{operator}`"
        );
    }

    let typed_head = head(&typed);
    for operator in ["/Font", "BT\n", "Tj"] {
        assert!(
            typed_head.contains(operator),
            "the control document does not carry `{operator}`, so the scan above proved nothing"
        );
    }
}

#[test]
fn every_ignore_in_this_file_names_the_mount_and_how_to_run_it() {
    // `plans/M1-CONTENT-CORE.md §5` forbids an `#[ignore]` without a written reason naming where the
    // test *does* run. Read out of this file rather than asserted about the constants, because the
    // failure worth catching is a new test copying an `#[ignore]` with a vaguer reason.
    let source = include_str!("pdf.rs");
    let reasons: Vec<&str> =
        source.lines().filter(|line| line.trim_start().starts_with("#[ignore")).collect();

    assert!(reasons.len() >= 8, "expected the mount-dependent tests to be ignored");
    for reason in reasons {
        assert!(
            reason.contains(NEEDS_PDFIUM) || reason.contains(NEEDS_PDFIUM_AND_MODELS),
            "an #[ignore] here does not name the mount and the --include-ignored run: {reason}"
        );
    }
}

// -------------------------------------------------------------------------------------------
// The rasteriser, against the real library.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_scanned_pdf_page_becomes_pixels() {
    // `ENC-537` at the smallest scale that means anything, and the positive control every refusal
    // test below depends on: without it, a rasteriser that refused everything would satisfy all of
    // them.
    let page = page_of_text("INVOICE 2026 TOTAL");
    let (points_width, points_height) = page.points;
    let pages = pages_of(scanned_pdf(&[page]), RenderBudget::DEFAULT);

    let PageImage::Rendered(png) = pages.page_image(1).await.expect("no worker failure") else {
        panic!("page 1 of a one-page document produced no image");
    };

    // 200 dpi: the page box is in points, and a point is 1/72 inch.
    let (width, height) = dimensions_of(&png);
    let expected = |points: u32| (f64::from(points) * 200.0 / 72.0).round() as u32;
    assert_eq!((width, height), (expected(points_width), expected(points_height)));
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_page_the_document_does_not_have_is_absent_and_not_a_verdict() {
    // `Absent` and `Refused` are the two arms `ENC-537` widened the port to distinguish, and this is
    // the half that must *not* fail a document: asking for a page that is not there is an ordinary
    // thing for a work list to do, and turning it into a refusal would fail every document whose
    // pagination the text stage guessed at.
    let pages = pages_of(scanned_pdf(&[page_of_text("ONE")]), RenderBudget::DEFAULT);

    for page in [0, 2, 9_999] {
        assert_eq!(
            pages.page_image(page).await.expect("no worker failure"),
            PageImage::Absent,
            "page {page} of a one-page document"
        );
    }
    // The positive control, in the same test: page 1 exists.
    assert!(matches!(
        pages.page_image(1).await.expect("no worker failure"),
        PageImage::Rendered(_)
    ));
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn bytes_that_are_not_a_pdf_never_reach_the_page_tree() {
    // The sniff. A PNG declared as a PDF is refused as a PNG rather than handed to a page-tree
    // parser, which is `raster.rs`'s dispatch-on-content rule applied at the other end.
    let mut png = Vec::new();
    RgbImage::from_pixel(4, 4, Rgb([255, 255, 255]))
        .write_to(&mut std::io::Cursor::new(&mut png), ImageFormat::Png)
        .expect("encoding");

    let pages = pages_of(png, RenderBudget::DEFAULT);

    assert_eq!(
        pages.page_image(1).await.expect("no worker failure"),
        PageImage::Refused(Refusal::UnsupportedFormat)
    );
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_source_over_the_input_cap_is_refused_before_the_parser_is_entered() {
    // Nothing wraps a `PageImages` in `Bounded`, so this cap is applied inside `pdf.rs` or nowhere.
    // The refusal is asserted exactly: `SourceUnreadable` would mean the parser ran and disliked
    // what it found, which is the parse this cap exists to prevent.
    let pdf = scanned_pdf(&[page_of_text("INVOICE")]);
    let budget = RenderBudget { max_input_bytes: 64, ..RenderBudget::DEFAULT };
    assert!(pdf.len() > 64, "the fixture must exceed the cap for this to assert anything");

    let pages = pages_of(pdf, budget);

    assert_eq!(
        pages.page_image(1).await.expect("no worker failure"),
        PageImage::Refused(Refusal::InputTooLarge)
    );
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_render_larger_than_the_output_cap_is_refused_from_the_declared_page_size() {
    // The bomb check, at the point `raster.rs` puts `decoder.total_bytes()`: the page box has been
    // read and no pixel buffer exists. The budget is tightened deliberately — see `pdf.rs` on why
    // `MAX_EDGE` and not this check is what bounds the default budget, and why the check is kept
    // and tested anyway.
    let page = page_of_text("INVOICE 2026 TOTAL");
    let pdf = scanned_pdf(&[page]);

    let tight = RenderBudget { max_output_bytes: 4_096, ..RenderBudget::DEFAULT };
    assert_eq!(
        pages_of(pdf.clone(), tight).page_image(1).await.expect("no worker failure"),
        PageImage::Refused(Refusal::OutputTooLarge)
    );

    // The positive control. The identical page under the default budget renders, so the assertion
    // above is about the cap and not about the document.
    assert!(matches!(
        pages_of(pdf, RenderBudget::DEFAULT).page_image(1).await.expect("no worker failure"),
        PageImage::Rendered(_)
    ));
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_document_with_more_pages_than_the_budget_allows_renders_none_of_them() {
    // The cap that bounds the *document* rather than the page. `OcrRetry` applies the same number to
    // its work list; this one catches the case that list cannot see — a short work list naming three
    // pages of a million-page file.
    let pdf = scanned_pdf(&[page_of_text("ONE"), blank_page(), page_of_text("THREE")]);

    let tight = RenderBudget { max_pages: 2, ..RenderBudget::DEFAULT };
    assert_eq!(
        pages_of(pdf.clone(), tight).page_image(1).await.expect("no worker failure"),
        PageImage::Refused(Refusal::TooManyPages)
    );

    // The positive control: the same document one page inside the cap renders.
    let permissive = RenderBudget { max_pages: 3, ..RenderBudget::DEFAULT };
    assert!(matches!(
        pages_of(pdf, permissive).page_image(1).await.expect("no worker failure"),
        PageImage::Rendered(_)
    ));
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn an_enormous_page_box_is_clamped_rather_than_allocated() {
    // The amplification a PDF has that an image does not: the page declares its size in points and
    // *we* choose the pixels, so a file of a few kilobytes can ask for an arbitrarily large buffer.
    //
    // 1440 points is 20 inches. At 200 dpi that is 4000 pixels a side — 64 MB of RGBA, which is
    // inside the default budget, so nothing but the clamp refuses it. That is the point: this test
    // fails by name when the clamp is removed, and it does so without asking the machine running it
    // to allocate the 6.4 GB a maximal 200-inch page would.
    let (jpeg, pixels_width, pixels_height) = jpeg_of_text("LARGE");
    let page = Page { jpeg, pixels: (pixels_width, pixels_height), points: (1_440, 1_440) };
    let pages = pages_of(scanned_pdf(&[page]), RenderBudget::DEFAULT);

    let PageImage::Rendered(png) = pages.page_image(1).await.expect("no worker failure") else {
        panic!("a 20-inch page was refused rather than scaled");
    };

    let (width, height) = dimensions_of(&png);
    assert_eq!(
        (width, height),
        (MAX_EDGE, MAX_EDGE),
        "a 20-inch square page rendered at {width}×{height}; the clamp is {MAX_EDGE}"
    );
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_truncated_document_is_a_verdict_and_never_an_error() {
    // D17: a document that will not parse is an answer about the document. If this came back as
    // `IndexingError` the scheduler would retry it, and a file that reliably fails is a
    // denial-of-service primitive the moment something is willing to run it again.
    let pdf = scanned_pdf(&[page_of_text("INVOICE")]);
    let truncated = pdf[..pdf.len() / 2].to_vec();
    assert!(truncated.starts_with(b"%PDF-"), "it must still pass the sniff to reach the parser");

    let pages = pages_of(truncated, RenderBudget::DEFAULT);

    assert_eq!(
        pages.page_image(1).await.expect("a broken document must not be an error"),
        PageImage::Refused(Refusal::SourceUnreadable)
    );
}

// -------------------------------------------------------------------------------------------
// The text extractor, against the real library. `ENC-545`.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_typed_pdf_yields_one_segment_per_page_that_names_its_page() {
    // The positive control the whole section rests on: without it, an extractor that found nothing
    // in anything would satisfy every "this document is textless" assertion below.
    let outcome = extract(typed_pdf(&["FIRST PAGE", "SECOND PAGE"]), RenderBudget::DEFAULT).await;

    let ExtractOutcome::Extracted(document) = outcome else {
        panic!("a document with characters in it was reported as {outcome:?}");
    };

    assert_eq!(document.page_count, Some(2));
    assert_eq!(document.media_type, "application/pdf");
    assert_eq!(document.segments.len(), 2, "`docs/07 §2.1`: per-page text");
    for (index, expected) in ["FIRST PAGE", "SECOND PAGE"].iter().enumerate() {
        let segment = &document.segments[index];
        assert_eq!(segment.kind, SegmentKind::Page);
        assert!(segment.text.contains(expected), "page {} read as {:?}", index + 1, segment.text);
        assert_eq!(
            segment.coordinates.page_number,
            Some(u32::try_from(index).expect("small") + 1),
            "a segment that cannot name its page is a citation nobody can navigate to"
        );
    }
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_scanned_pdf_is_textless_and_hands_ocr_every_page() {
    // **`ENC-545`.** This is the hand-off the exit criterion was missing: a scan has to come back as
    // a *textless source naming its pages*, because `OcrRetry` fires on nothing else and rasterises
    // nothing but what the list names.
    //
    // The document is the same one `the_scanned_documents_here_really_have_no_text_layer` proves has
    // no text layer at the source level; this asks PDFium, which is the stronger statement that file
    // could not make before.
    let scanned = scanned_pdf(&[page_of_text("INVOICE"), blank_page(), page_of_text("TOTAL")]);

    let outcome = extract(scanned, RenderBudget::DEFAULT).await;

    assert_eq!(work_list(&outcome), vec![1, 2, 3], "OCR would be asked for the wrong pages");
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_document_with_some_scanned_pages_is_extracted_and_still_names_them() {
    // The case that is neither of the other two, against the real parser: a report whose exhibit was
    // scanned in. It is not `NoText` — reporting that would throw the typed pages away, because
    // `OcrRetry` builds its document from what it recognised and nothing else — and it is not a
    // refusal, because the document parsed.
    //
    // The blank page keeps its number inside the extracted document, which is the information the
    // outcome cannot carry today and the thing that makes the gap closable. See
    // `crates/indexing/src/pdf_text.rs` for what is still missing and why it is not smuggled in here.
    let exhibit = page_of_text("SCANNED EXHIBIT");
    let mixed = pdf_of(&[
        Sheet::Typed("QUARTERLY REPORT"),
        Sheet::Scan(&exhibit),
        Sheet::Typed("APPENDIX"),
    ]);

    let outcome = extract(mixed, RenderBudget::DEFAULT).await;

    let ExtractOutcome::Extracted(document) = outcome else {
        panic!("a document with text on two of three pages was reported as {outcome:?}");
    };
    assert!(!document.is_empty());

    let blank: Vec<u32> = document
        .segments
        .iter()
        .filter(|segment| segment.text.is_empty())
        .filter_map(|segment| segment.coordinates.page_number)
        .collect();
    assert_eq!(blank, vec![2], "the scanned page is not identifiable from the extracted document");
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn two_pages_never_merge_into_one_chunk() {
    // `SegmentKind::Page` is structural, and this is why. `Coordinates` carries **one** page number
    // and a chunk takes its coordinates from the first segment that went into it, so a chunker that
    // merged these two short pages would emit one chunk citing page 1 for text that is on page 2 —
    // a citation that deep-links to the wrong place, which `crates/indexing/src/model.rs` calls worse
    // than one that does not deep-link because the reader believes it.
    //
    // Both pages are far inside `ChunkBudget::DEFAULT`'s 2 400-character window, so nothing but the
    // boundary claim keeps them apart.
    let pipeline =
        Pipeline::new(BoundedExtractor::new(PdfTextExtractor::new(library())), chunker());

    let prepared = pipeline
        .prepare(
            VersionId::new_v7(),
            ExtractRequest {
                declared_media_type: "application/pdf".to_owned(),
                source: typed_pdf(&["FIRST PAGE", "SECOND PAGE"]),
                budget: RenderBudget::DEFAULT,
            },
        )
        .await
        .expect("no worker failure");

    assert_eq!(prepared.outcome.status(), ManifestStatus::Ready);
    assert_eq!(prepared.outcome.chunk_count(), 2, "two pages became {:?}", prepared.chunks);
    let pages: Vec<Option<u32>> =
        prepared.chunks.iter().map(|chunk| chunk.coordinates.page_number).collect();
    assert_eq!(pages, vec![Some(1), Some(2)]);
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn bytes_that_are_not_a_pdf_are_never_parsed_for_text() {
    // The sniff, at the other parser. A PNG declared `application/pdf` is refused on its signature
    // rather than handed to a page tree — `supports` is a routing hint and the content decides.
    let mut png = Vec::new();
    RgbImage::from_pixel(4, 4, Rgb([255, 255, 255]))
        .write_to(&mut std::io::Cursor::new(&mut png), ImageFormat::Png)
        .expect("encoding");

    assert_eq!(
        extract(png, RenderBudget::DEFAULT).await,
        ExtractOutcome::Refused(Refusal::UnsupportedFormat)
    );
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_source_over_the_input_cap_is_refused_before_the_text_parser_is_entered() {
    // Asserted against the *unwrapped* extractor, because `BoundedExtractor` applies the same cap
    // first and a test run through it would prove the wrapper. The refusal is asserted exactly:
    // `SourceUnreadable` would mean the parser ran and disliked what it found, which is the parse
    // this cap exists to prevent.
    let pdf = typed_pdf(&["INVOICE"]);
    assert!(pdf.len() > 64, "the fixture must exceed the cap for this to assert anything");

    assert_eq!(
        extract(pdf.clone(), RenderBudget { max_input_bytes: 64, ..RenderBudget::DEFAULT }).await,
        ExtractOutcome::Refused(Refusal::InputTooLarge)
    );

    // The positive control: the identical document under the default budget extracts.
    assert!(matches!(extract(pdf, RenderBudget::DEFAULT).await, ExtractOutcome::Extracted(_)));
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_document_with_more_pages_than_the_budget_allows_extracts_none_of_them() {
    // The cap that bounds the *document* rather than the page, applied from the page tree's own
    // count before a single page's text is fetched.
    let pdf = typed_pdf(&["ONE", "TWO", "THREE"]);

    assert_eq!(
        extract(pdf.clone(), RenderBudget { max_pages: 2, ..RenderBudget::DEFAULT }).await,
        ExtractOutcome::Refused(Refusal::TooManyPages)
    );

    // The positive control: the same document one page inside the cap extracts.
    assert!(matches!(
        extract(pdf, RenderBudget { max_pages: 3, ..RenderBudget::DEFAULT }).await,
        ExtractOutcome::Extracted(_)
    ));
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM; CI runs it with --include-ignored"]
async fn a_truncated_document_is_a_text_verdict_and_never_an_error() {
    // D17: a document that will not parse is an answer about the document. As an `IndexingError` the
    // scheduler would retry it, and a file that reliably fails is a denial-of-service primitive the
    // moment something is willing to run it again.
    //
    // And specifically not `NoText`: a malformed file reported as a scan would spend a rasterisation
    // and a recognition on every page of something that never parsed.
    let pdf = typed_pdf(&["INVOICE"]);
    let truncated = pdf[..pdf.len() / 2].to_vec();
    assert!(truncated.starts_with(b"%PDF-"), "it must still pass the sniff to reach the parser");

    assert_eq!(
        extract(truncated, RenderBudget::DEFAULT).await,
        ExtractOutcome::Refused(Refusal::SourceUnreadable)
    );
}

// -------------------------------------------------------------------------------------------
// The exit criterion.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM and OCR weights named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_scanned_text_free_pdf_is_read_back_as_text() {
    // **The M3 exit criterion**, end to end from a PDF that carries no characters at all:
    // text extractor → work list → page tree → pixels → recognition → chunks, with the page number
    // that makes a citation navigable.
    //
    // `ENC-545` is what lets this start at the beginning. Until it landed the work list was typed
    // into this test, because `NoExtractor` answered for `application/pdf` and the real pipeline
    // never reached the rasteriser at all — so the test proved the two halves and not the join.
    // Nothing below is constructed by hand: `Pipeline::prepare` decides, and whatever it decided is
    // what the retry is given.
    let version = VersionId::new_v7();
    let pdf = scanned_pdf(&[page_of_text("INVOICE 2026 TOTAL"), blank_page()]);

    let pipeline =
        Pipeline::new(BoundedExtractor::new(PdfTextExtractor::new(library())), chunker());
    let prepared = pipeline
        .prepare(
            version,
            ExtractRequest {
                declared_media_type: "application/pdf".to_owned(),
                source: pdf.clone(),
                budget: UNTIMED,
            },
        )
        .await
        .expect("the text extractor did not fail");

    // The join, asserted rather than assumed: before `ENC-545` this was `SKIPPED` /
    // `unsupported_media_type`, which `OcrRetry` passes straight through — so the rest of this test
    // would have run against an outcome OCR is structurally forbidden to touch.
    //
    // **Which mechanism this proves, established by breaking it.** Making the extractor report
    // `Extracted` over its all-blank document leaves this test green, because `BoundedExtractor`
    // converts an empty `TextDocument` into `NoText` from outside and derives `1..=page_count` — the
    // same list, for this document. So what is asserted here is the *wrapped* pipeline's answer.
    // `a_scanned_pdf_is_textless_and_hands_ocr_every_page` runs the extractor unwrapped and is the
    // test that fails when the extractor itself stops naming its pages.
    assert_eq!(
        prepared.outcome.status(),
        ManifestStatus::Failed,
        "a scan that reaches OCR must arrive as NoText: {:?}",
        prepared.outcome
    );
    assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
    assert!(
        matches!(&prepared.outcome, Outcome::NoText(source)
            if source.pages_without_text == vec![1, 2]),
        "the work list OCR will rasterise: {:?}",
        prepared.outcome
    );

    let retry = OcrRetry::new(
        BoundedExtractor::new(OcrExtractor::new(models())),
        pages_of(pdf, UNTIMED),
        chunker(),
        UNTIMED,
    );

    let prepared =
        retry.retry(version, prepared).await.expect("neither the rasteriser nor the engine failed");

    assert_eq!(
        prepared.outcome.status(),
        ManifestStatus::Ready,
        "a scanned PDF whose words were recognised must be searchable: {:?}",
        prepared.outcome
    );
    assert_eq!(prepared.outcome.reason(), None);

    let text: String = prepared.chunks.iter().map(|chunk| chunk.text.to_uppercase()).collect();
    assert!(text.contains("INVOICE"), "recognised {text:?}");
    assert!(text.contains("2026"), "recognised {text:?}");

    // The blank second page contributed nothing and did not fail the document, and the text that was
    // recovered is attributed to the page it came from.
    assert_eq!(
        prepared.chunks.first().and_then(|chunk| chunk.coordinates.page_number),
        Some(1),
        "a chunk that cannot name its page is a citation nobody can navigate to"
    );
}

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM and OCR weights named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_scanned_pdf_of_blank_pages_fails_rather_than_indexing_as_empty() {
    // D24's failure mode with the rasteriser in place. Now that pixels exist, the tempting outcome
    // is `READY` over a document that recognised nothing — an index entry that reads as filed and
    // searchable with nothing behind it. The work list must survive too, so a later attempt with
    // better models knows which pages to look at.
    //
    // The positive control is the test above: the identical machinery over a page with words on it
    // is `READY`.
    let version = VersionId::new_v7();
    let pdf = scanned_pdf(&[blank_page(), blank_page()]);

    let pipeline =
        Pipeline::new(BoundedExtractor::new(PdfTextExtractor::new(library())), chunker());
    let prepared: Prepared = pipeline
        .prepare(
            version,
            ExtractRequest {
                declared_media_type: "application/pdf".to_owned(),
                source: pdf.clone(),
                budget: UNTIMED,
            },
        )
        .await
        .expect("the text extractor did not fail");

    let retry = OcrRetry::new(
        BoundedExtractor::new(OcrExtractor::new(models())),
        pages_of(pdf, UNTIMED),
        chunker(),
        UNTIMED,
    );

    let prepared =
        retry.retry(version, prepared).await.expect("neither the rasteriser nor the engine failed");

    assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
    match prepared.outcome {
        Outcome::NoText(source) => assert_eq!(source.pages_without_text, vec![1, 2]),
        other => panic!("expected the work list to survive, got {other:?}"),
    }
    assert!(prepared.chunks.is_empty());
}
