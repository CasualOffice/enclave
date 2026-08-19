//! The watermark, burned into pixels.
//!
//! The properties here are what make the mark a *control* rather than a decoration. An overlay a
//! client is asked to draw is one a client can decline to draw; these tests are about the bytes
//! that actually leave.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_preview::{
    composite_watermark as composite, CompositeRefusal, WatermarkFacts, WatermarkStyle,
};
use image::{ImageFormat, Rgba, RgbaImage};

/// A blank white page, so any non-white pixel afterwards is ink this module put there.
fn blank(width: u32, height: u32) -> Vec<u8> {
    let canvas = RgbaImage::from_pixel(width, height, Rgba([255, 255, 255, 255]));
    let mut out = Vec::new();
    image::DynamicImage::ImageRgba8(canvas)
        .write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .expect("encode");
    out
}

fn facts(name: &str, email: &str) -> WatermarkFacts {
    WatermarkFacts {
        viewer_name: name.to_owned(),
        viewer_email: email.to_owned(),
        issued_at: "19 August 2026 at 14:07 GMT+1".to_owned(),
        file_reference: "Q3-forecast.xlsx".to_owned(),
        session_reference: "sess-4417".to_owned(),
        classification: Some("Confidential".to_owned()),
    }
}

/// How many pixels the compositor changed.
fn inked(png: &[u8]) -> usize {
    let image = image::load_from_memory_with_format(png, ImageFormat::Png).expect("decode");
    image.to_rgba8().pixels().filter(|p| p.0[0] != 255 || p.0[1] != 255 || p.0[2] != 255).count()
}

/// The mark reaches the pixels, and is spread across the page rather than stamped once.
///
/// The count matters as much as the presence: a compositor that drew one line in a corner would
/// satisfy "some ink" while leaving a crop that names nobody, which is the failure `docs/06 §5.2`
/// is honest about not being able to prevent any other way.
#[test]
fn the_mark_is_burned_into_the_bytes_and_tiled_across_them() {
    let base = blank(800, 600);
    let marked =
        composite(&base, &facts("Ada Lovelace", "ada@example.test"), WatermarkStyle::DEFAULT)
            .expect("composite");

    assert_ne!(marked, base, "the returned bytes are the base, unmarked");
    let painted = inked(&marked);
    assert!(painted > 2_000, "only {painted} pixels were inked — the mark is not legible");

    // Present in every quadrant: a crop of any corner still carries it.
    let image = image::load_from_memory_with_format(&marked, ImageFormat::Png).expect("decode");
    let rgba = image.to_rgba8();
    for (label, x0, y0) in [
        ("top-left", 0, 0),
        ("top-right", 400, 0),
        ("bottom-left", 0, 300),
        ("bottom-right", 400, 300),
    ] {
        let mut found = false;
        for y in y0..y0 + 300 {
            for x in x0..x0 + 400 {
                let p = rgba.get_pixel(x, y);
                if p.0[0] != 255 || p.0[1] != 255 || p.0[2] != 255 {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        assert!(found, "the {label} quadrant carries no mark, so a crop of it names nobody");
    }
}

/// Two viewers of the same page get different bytes.
///
/// If they did not, the mark would identify nobody and every other assertion here would be about a
/// control that does not do anything.
#[test]
fn two_viewers_receive_different_bytes_for_the_same_page() {
    let base = blank(600, 400);
    let one = composite(&base, &facts("Ada Lovelace", "ada@example.test"), WatermarkStyle::DEFAULT)
        .expect("composite");
    let two = composite(&base, &facts("Alan Turing", "alan@example.test"), WatermarkStyle::DEFAULT)
        .expect("composite");

    assert_ne!(one, two);
}

/// The same viewer and the same page composite identically.
///
/// Not a caching claim — nothing caches this. It is what makes the two-viewer assertion above mean
/// something: if output varied run to run, that test would pass for a compositor that emitted noise.
#[test]
fn the_same_viewer_and_page_composite_identically() {
    let base = blank(400, 300);
    let facts = facts("Ada Lovelace", "ada@example.test");
    let first = composite(&base, &facts, WatermarkStyle::DEFAULT).expect("composite");
    let second = composite(&base, &facts, WatermarkStyle::DEFAULT).expect("composite");
    assert_eq!(first, second);
}

/// A name the bundled face cannot draw is omitted — exactly as if it had not been supplied.
///
/// "Omitted" is asserted as *byte equality with the same facts carrying no name at all*, which is
/// the precise claim. An earlier version of this test compared ink against the Latin case and was
/// wrong for an instructive reason: dropping a line makes the tile shorter, so more tiles fit and
/// the total ink goes **up**. Counting pixels measures the layout, not the glyphs.
///
/// Tofu would be worse than absence — it says a name existed and refuses to say which — and this
/// assertion excludes it: a `.notdef` box would be ink the nameless render does not have.
#[test]
fn a_name_the_font_cannot_draw_is_omitted_rather_than_rendered_as_boxes() {
    let base = blank(600, 400);

    let cjk = composite(&base, &facts("陳大文", "chan@example.test"), WatermarkStyle::DEFAULT)
        .expect("a name it cannot draw must not stop the mark");
    let nameless = composite(&base, &facts("", "chan@example.test"), WatermarkStyle::DEFAULT)
        .expect("composite");

    assert_eq!(
        cjk, nameless,
        "an unrenderable name changed the output, so something was drawn for it — and the only \
         thing it could have drawn is boxes"
    );

    // And the mark is still there, still naming the viewer by the parts that survive.
    assert!(inked(&cjk) > 1_000, "the CJK-named viewer received no mark at all");

    // A renderable name *does* change the output, or the check above would pass for a compositor
    // that ignored the name field entirely.
    let latin =
        composite(&base, &facts("Ada Lovelace", "chan@example.test"), WatermarkStyle::DEFAULT)
            .expect("composite");
    assert_ne!(latin, nameless, "the name field is not being drawn at all");
}

/// If the email cannot be drawn, the mark names nobody, so it refuses.
///
/// `CLAUDE.md` rule 8: an obligation is satisfied or the operation fails. "We drew a blank stripe"
/// is not satisfaction, and the caller must turn this into a refused preview.
#[test]
fn an_identity_the_font_cannot_draw_at_all_is_a_refusal() {
    let base = blank(400, 300);

    let unrenderable =
        composite(&base, &facts("Someone", "陳@example.test"), WatermarkStyle::DEFAULT);
    assert_eq!(unrenderable, Err(CompositeRefusal::Unrenderable));

    let absent = composite(&base, &facts("Someone", ""), WatermarkStyle::DEFAULT);
    assert_eq!(absent, Err(CompositeRefusal::Unrenderable));
}

/// A base that is not a decodable rendition is refused rather than served.
///
/// It is our own artefact, so this means the cache holds something the renderer would not produce.
#[test]
fn an_undecodable_base_is_refused() {
    let outcome =
        composite(b"not a png", &facts("Ada", "ada@example.test"), WatermarkStyle::DEFAULT);
    assert_eq!(outcome, Err(CompositeRefusal::UndecodableBase));
}

/// The page underneath is still readable through the mark.
///
/// A watermark that obliterates the document defeats the permission it accompanies: the whole point
/// of `preview=ALLOW, download=DENY` is that the user can *read* the thing.
#[test]
fn the_document_is_still_visible_through_the_mark() {
    let base = blank(800, 600);
    let marked =
        composite(&base, &facts("Ada Lovelace", "ada@example.test"), WatermarkStyle::DEFAULT)
            .expect("composite");

    let total = 800 * 600;
    let painted = inked(&marked);
    assert!(
        painted * 100 / total < 25,
        "the mark covers {}% of the page; at that density the document is not readable",
        painted * 100 / total
    );
}

/// An artefact too small to carry a legible mark is refused, not returned unmarked.
///
/// This is the defect the delivery tests found rather than inspection did: an 8×8 rendition came
/// back byte-identical to its input. Every glyph fell outside the canvas, each was discarded by the
/// per-pixel bounds check, and the function returned `Ok` having marked nothing — an obligation
/// reported as discharged and silently dropped.
///
/// There is no size of image for which "the mark did not fit" makes serving it unmarked acceptable,
/// so the answer is a refusal and the caller must refuse the preview.
#[test]
fn an_artefact_too_small_to_mark_is_refused_rather_than_returned_untouched() {
    let facts = facts("Ada Lovelace", "ada@example.test");

    let tiny = blank(8, 8);
    let outcome = composite(&tiny, &facts, WatermarkStyle::DEFAULT);
    assert_eq!(
        outcome,
        Err(CompositeRefusal::NoRoom),
        "a canvas too small for the mark returned success; the bytes would have gone out unmarked"
    );

    // And the boundary is not arbitrary: a page-sized rendition marks fine, so this is a refusal
    // about *room*, not a compositor that only works on one size.
    assert!(composite(&blank(400, 300), &facts, WatermarkStyle::DEFAULT).is_ok());
}
