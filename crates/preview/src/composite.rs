//! Burning the watermark into the rendition, at delivery, per request.
//!
//! [`crate::watermark`] composes the identity layer as SVG, which is right for an HTML rendition —
//! the markup goes into the response and the browser draws it. For a **raster** rendition it is not
//! enough, and the reason is the whole point of the obligation: an overlay the client is asked to
//! draw is an overlay a client can decline to draw. `Obligation::Watermark` exists because the page
//! must identify whoever is looking at it; a mark that a hostile viewer can omit identifies nobody.
//!
//! So for `Thumb` and the page profiles the mark is composited into the pixels here, and the bytes
//! that leave are the bytes the viewer sees.
//!
//! # This does not break the cache split
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §5.1` keeps the base rendition identity-free and cached, and the
//! watermark per-request and uncached. That still holds: this function takes base bytes and returns
//! new bytes, and nothing in this crate will store them — [`crate::RenditionKey`] has three fields
//! and none of them can hold a principal, so a composited artefact has no key it could be written
//! under. See [`crate::model`].
//!
//! # Why glyphs and not an SVG renderer
//!
//! `resvg` is MPL-2.0 and this workspace's licence allowlist is deliberate, so adopting it is a
//! decision about licensing rather than about rendering. It is also a great deal of machinery: a
//! full SVG engine is a large new parser, and parsers are the widest attack-surface class in this
//! product (`plans/M2-ACCESS-DELIVERY.md` D17). A watermark is six lines of text. `ab_glyph`
//! rasterises glyphs and nothing else.
//!
//! # The font, and the case it cannot render
//!
//! The face is the Inter subset already vendored for the web client (`ENC-135`, OFL — see
//! `web/public/fonts/LICENSE`), converted from its `woff2` rather than downloaded again so that the
//! bytes in this repository have one provenance. It covers Latin and Latin-Extended: 230
//! codepoints, no CJK, no Arabic, no Cyrillic.
//!
//! That is a real limit and it is handled explicitly rather than by rendering `.notdef` boxes:
//!
//! * A **display name** the font cannot draw is **omitted**, and the mark still carries the email,
//!   the session and the timestamp — which is what makes a leaked screenshot attributable to a
//!   person and a sign-in. Tofu would be worse than absence: it says a name existed and refuses to
//!   say which.
//! * If the **email** cannot be drawn, the mark names nobody, so this refuses
//!   ([`CompositeRefusal::Unrenderable`]) and the caller must refuse the preview. `CLAUDE.md`
//!   rule 8 — an obligation is satisfied or the operation fails, and "we drew a blank stripe" is
//!   not satisfaction.
//!
//! Broader script coverage is a font-shipping decision, not a code one; `ENC-173` records it.

use ab_glyph::{Font as _, FontRef, Glyph, PxScale, ScaleFont as _};
use image::{ImageFormat, Rgba, RgbaImage};

use crate::watermark::{WatermarkFacts, WatermarkStyle};

/// The face, converted from the `woff2` this repository already ships for the web client.
static FONT: &[u8] = include_bytes!("../assets/inter-latin.ttf");

/// Why no composited artefact was produced.
///
/// A refusal, not an error: nothing went wrong, and re-running changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompositeRefusal {
    /// The base rendition could not be decoded.
    ///
    /// It is our own artefact, so this means the cache holds something the renderer would not
    /// produce — worth refusing rather than serving.
    UndecodableBase,
    /// The identity the mark exists to carry cannot be drawn with the bundled face.
    ///
    /// See the module documentation: a mark that names nobody is not a mark.
    Unrenderable,

    /// The artefact is too small to carry a legible mark.
    ///
    /// Found by a test, not by inspection: an 8×8 rendition produced bytes **identical** to its
    /// input. Every glyph fell outside the canvas, each was discarded by the per-pixel bounds
    /// check, and the function returned `Ok` having marked nothing — an obligation reported as
    /// discharged and silently dropped, which is exactly what `CLAUDE.md` rule 8 forbids.
    ///
    /// So the compositor now counts what it inks and refuses if the answer is zero. A caller must
    /// turn this into a refused preview: there is no size of image for which "we could not fit the
    /// mark" makes serving it unmarked acceptable.
    NoRoom,
}

/// Draws the watermark into a base rendition and returns the result as PNG.
///
/// # Errors
///
/// Never. A refusal is a value — see [`CompositeRefusal`].
pub fn composite(
    base_png: &[u8],
    facts: &WatermarkFacts,
    style: WatermarkStyle,
) -> Result<Vec<u8>, CompositeRefusal> {
    let font = FontRef::try_from_slice(FONT).map_err(|_| CompositeRefusal::UndecodableBase)?;

    // The lines, in the order `docs/06 §5.1` names them. The email is required; the rest are
    // dropped individually if the face cannot draw them.
    let renderable = |text: &str| text.chars().all(|c| c == ' ' || font.glyph_id(c).0 != 0);

    if facts.viewer_email.is_empty() || !renderable(&facts.viewer_email) {
        return Err(CompositeRefusal::Unrenderable);
    }

    let mut lines: Vec<&str> = Vec::with_capacity(6);
    for candidate in [
        facts.viewer_name.as_str(),
        facts.viewer_email.as_str(),
        facts.issued_at.as_str(),
        facts.file_reference.as_str(),
        facts.session_reference.as_str(),
        facts.classification.as_deref().unwrap_or_default(),
    ] {
        if !candidate.is_empty() && renderable(candidate) {
            lines.push(candidate);
        }
    }

    let image = image::load_from_memory_with_format(base_png, ImageFormat::Png)
        .map_err(|_| CompositeRefusal::UndecodableBase)?;
    let mut canvas: RgbaImage = image.to_rgba8();
    let (width, height) = canvas.dimensions();

    // Scaled to the artefact rather than fixed: a 16px mark on a 4000px page is unreadable, and an
    // unreadable mark is a decoration.
    let size = (width.min(height) as f32 / 48.0).clamp(11.0, 28.0);
    let scaled = font.as_scaled(PxScale::from(size));
    let line_height = scaled.height() * 1.25;
    let block_height = line_height * lines.len() as f32;

    // Tiled, not one centred stamp. `docs/06 §5.2` is honest that screenshots cannot be prevented;
    // what a tile buys is that a *cropped* fragment still names someone.
    let widest = lines.iter().map(|line| text_width(&font, line, size)).fold(0.0_f32, f32::max);
    let step_x = (widest + size * 4.0).max(1.0);
    let step_y = (block_height + size * 3.0).max(1.0);

    let alpha = (f32::from(style.opacity_percent.min(100)) / 100.0 * 255.0) as u8;
    let ink = Rgba([64, 64, 64, alpha]);

    // Counted, not assumed. See `CompositeRefusal::NoRoom`.
    let mut inked = 0_u64;
    let mut row = 0_usize;
    let mut origin_y = step_y * 0.25;
    while origin_y < height as f32 {
        // Staggered: aligned columns would let a crop between them miss every tile.
        let offset = if row.is_multiple_of(2) { 0.0 } else { step_x / 2.0 };
        let mut origin_x = offset - step_x * 0.25;
        while origin_x < width as f32 {
            for (index, line) in lines.iter().enumerate() {
                inked += draw_line(
                    &mut canvas,
                    &font,
                    line,
                    size,
                    origin_x,
                    origin_y + line_height * index as f32,
                    ink,
                );
            }
            origin_x += step_x;
        }
        origin_y += step_y;
        row += 1;
    }

    // The assertion this function owes its caller: bytes came back *changed*. Returning `Ok` here
    // with nothing drawn would report an obligation as discharged when it was dropped.
    if inked == 0 {
        return Err(CompositeRefusal::NoRoom);
    }

    let mut out = Vec::with_capacity(base_png.len());
    image::DynamicImage::ImageRgba8(canvas)
        .write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .map_err(|_| CompositeRefusal::UndecodableBase)?;
    Ok(out)
}

/// Advance width of a string at a scale, for tile spacing.
fn text_width(font: &FontRef<'_>, text: &str, size: f32) -> f32 {
    let scaled = font.as_scaled(PxScale::from(size));
    text.chars().map(|c| scaled.h_advance(font.glyph_id(c))).sum()
}

/// Draws one line, alpha-blending each glyph's coverage into the canvas.
///
/// Returns how many pixels it actually touched, which is what lets the caller tell "marked" from
/// "drew every glyph off the edge of a tiny image and returned successfully".
fn draw_line(
    canvas: &mut RgbaImage,
    font: &FontRef<'_>,
    text: &str,
    size: f32,
    origin_x: f32,
    origin_y: f32,
    ink: Rgba<u8>,
) -> u64 {
    let scaled = font.as_scaled(PxScale::from(size));
    let (width, height) = canvas.dimensions();
    let mut caret = origin_x;
    let mut painted = 0_u64;

    for character in text.chars() {
        let id = font.glyph_id(character);
        let glyph: Glyph =
            id.with_scale_and_position(PxScale::from(size), ab_glyph::point(caret, origin_y));
        caret += scaled.h_advance(id);

        let Some(outline) = font.outline_glyph(glyph) else { continue };
        let bounds = outline.px_bounds();

        outline.draw(|dx, dy, coverage| {
            let x = bounds.min.x as i64 + i64::from(dx);
            let y = bounds.min.y as i64 + i64::from(dy);
            if x < 0 || y < 0 || x >= i64::from(width) || y >= i64::from(height) {
                return;
            }
            // `as` conversions are checked by the bounds test above.
            let pixel = canvas.get_pixel_mut(x as u32, y as u32);
            blend(pixel, ink, coverage);
            painted += 1;
        });
    }
    painted
}

/// Source-over blend of one ink pixel at `coverage` into the canvas.
///
/// Written out rather than reached for from a library because it is four lines and because the
/// alternative — `imageproc` — is a large dependency for this one operation.
fn blend(under: &mut Rgba<u8>, ink: Rgba<u8>, coverage: f32) {
    let a = (f32::from(ink.0[3]) / 255.0 * coverage.clamp(0.0, 1.0)).clamp(0.0, 1.0);
    for channel in 0..3 {
        let src = f32::from(ink.0[channel]);
        let dst = f32::from(under.0[channel]);
        under.0[channel] = (src * a + dst * (1.0 - a)) as u8;
    }
}
