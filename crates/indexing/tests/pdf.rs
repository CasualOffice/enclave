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
//! absence of `BT` would pass against a scanner that never finds anything.
//!
//! What that check does **not** do is ask PDFium whether the text layer is empty, which would be the
//! stronger statement. Reaching PDFium's text API from here means a PDF *text* extractor, and this
//! change deliberately does not add one — see the report on `ENC-537` and the note in
//! `crates/indexing/src/pdf.rs` about what still stands between this and the criterion.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use ab_glyph::{Font as _, FontRef, PxScale, ScaleFont as _};
use enclave_core::VersionId;
use enclave_indexing::{
    BoundedExtractor, ChunkBudget, Chunker, ChunkerVersion, ManifestStatus, OcrExtractor,
    OcrModels, OcrRetry, Outcome, PageImage, PageImages, PdfiumLibrary, PdfiumPages, Prepared,
    Refusal, RenderBudget, TextlessSource,
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

fn pages_of(pdf: Vec<u8>, budget: RenderBudget) -> PdfiumPages {
    PdfiumPages::new(library(), pdf, budget)
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

/// A PDF whose pages are images and nothing else. No `/Font`, no `BT`, no `Tj`: a scan.
///
/// Written with a real cross-reference table rather than relying on PDFium's tolerance for a broken
/// one, so that a test asserting `SourceUnreadable` for a *truncated* file is asserting something
/// about the truncation.
fn scanned_pdf(pages: &[Page]) -> Vec<u8> {
    let mut out = Vec::from(*b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<usize> = Vec::new();

    fn object(out: &mut Vec<u8>, offsets: &mut Vec<usize>, number: usize, body: &[u8]) {
        offsets.push(out.len());
        out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    let kids: Vec<String> =
        (0..pages.len()).map(|index| format!("{} 0 R", 3 + index * 3)).collect();
    object(&mut out, &mut offsets, 1, b"<< /Type /Catalog /Pages 2 0 R >>");
    object(
        &mut out,
        &mut offsets,
        2,
        format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.join(" "), pages.len()).as_bytes(),
    );

    for (index, page) in pages.iter().enumerate() {
        let (page_object, content_object, image_object) =
            (3 + index * 3, 4 + index * 3, 5 + index * 3);
        let (points_width, points_height) = page.points;

        object(
            &mut out,
            &mut offsets,
            page_object,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {points_width} {points_height}] \
                 /Resources << /XObject << /Im0 {image_object} 0 R >> >> \
                 /Contents {content_object} 0 R >>"
            )
            .as_bytes(),
        );

        // The whole content stream: place the image over the page box. No text operator exists.
        let content = format!("q\n{points_width} 0 0 {points_height} 0 0 cm\n/Im0 Do\nQ\n");
        object(
            &mut out,
            &mut offsets,
            content_object,
            format!("<< /Length {} >>\nstream\n{content}endstream", content.len()).as_bytes(),
        );

        let (pixels_width, pixels_height) = page.pixels;
        let mut image = format!(
            "<< /Type /XObject /Subtype /Image /Width {pixels_width} /Height {pixels_height} \
             /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream\n",
            page.jpeg.len()
        )
        .into_bytes();
        image.extend_from_slice(&page.jpeg);
        image.extend_from_slice(b"\nendstream");
        object(&mut out, &mut offsets, image_object, &image);
    }

    trailer(out, &offsets)
}

/// The opposite document: one page carrying real characters in a base-14 font.
///
/// Exists only as the positive control for [`the_scanned_documents_here_really_have_no_text_layer`].
fn typed_pdf(text: &str) -> Vec<u8> {
    let mut out = Vec::from(*b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
    let mut offsets: Vec<usize> = Vec::new();

    fn object(out: &mut Vec<u8>, offsets: &mut Vec<usize>, number: usize, body: &[u8]) {
        offsets.push(out.len());
        out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    object(&mut out, &mut offsets, 1, b"<< /Type /Catalog /Pages 2 0 R >>");
    object(&mut out, &mut offsets, 2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    object(
        &mut out,
        &mut offsets,
        3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] \
          /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
    );
    let content = format!("BT\n/F1 24 Tf\n72 700 Td\n({text}) Tj\nET\n");
    object(
        &mut out,
        &mut offsets,
        4,
        format!("<< /Length {} >>\nstream\n{content}endstream", content.len()).as_bytes(),
    );
    object(&mut out, &mut offsets, 5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

    trailer(out, &offsets)
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
    let typed = typed_pdf("INVOICE 2026 TOTAL");

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
// The exit criterion.
// -------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a mounted PDFium named by ENCLAVE_PDFIUM and OCR weights named by ENCLAVE_OCR_MODELS; CI runs it with --include-ignored"]
async fn a_scanned_text_free_pdf_is_read_back_as_text() {
    // **The M3 exit criterion**, end to end from a PDF that carries no characters at all:
    // page tree → pixels → recognition → chunks, with the page number that makes a citation
    // navigable.
    //
    // What it does not cover, stated at the test rather than in a summary: the work list is
    // constructed here, and in a running system it would come from a PDF *text* extractor reporting
    // which pages yielded nothing. No such extractor exists — `NoExtractor` answers for
    // `application/pdf` — so this proves the rasteriser and the OCR stage, and the wiring in front of
    // them is still absent. `crates/indexing/src/pdf.rs` and the `ENC-537` report say so too.
    let pdf = scanned_pdf(&[page_of_text("INVOICE 2026 TOTAL"), blank_page()]);

    let retry = OcrRetry::new(
        BoundedExtractor::new(OcrExtractor::new(models())),
        pages_of(pdf, RenderBudget::DEFAULT),
        Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default()),
        RenderBudget::DEFAULT,
    );

    // Exactly what a PDF text extractor would hand over: this document yielded no text, and these
    // are the pages an image pipeline should look at.
    let prepared = retry
        .retry(
            VersionId::new_v7(),
            Prepared {
                outcome: Outcome::NoText(TextlessSource {
                    media_type: "application/pdf".to_owned(),
                    pages_without_text: vec![1, 2],
                }),
                chunks: Vec::new(),
            },
        )
        .await
        .expect("neither the rasteriser nor the engine failed");

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
    let pdf = scanned_pdf(&[blank_page(), blank_page()]);

    let retry = OcrRetry::new(
        BoundedExtractor::new(OcrExtractor::new(models())),
        pages_of(pdf, RenderBudget::DEFAULT),
        Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default()),
        RenderBudget::DEFAULT,
    );

    let prepared = retry
        .retry(
            VersionId::new_v7(),
            Prepared {
                outcome: Outcome::NoText(TextlessSource {
                    media_type: "application/pdf".to_owned(),
                    pages_without_text: vec![1, 2],
                }),
                chunks: Vec::new(),
            },
        )
        .await
        .expect("neither the rasteriser nor the engine failed");

    assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
    match prepared.outcome {
        Outcome::NoText(source) => assert_eq!(source.pages_without_text, vec![1, 2]),
        other => panic!("expected the work list to survive, got {other:?}"),
    }
    assert!(prepared.chunks.is_empty());
}
