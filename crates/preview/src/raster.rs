//! The first renderer in this crate that produces bytes: raster images in, PNG renditions out.
//!
//! # What it renders, and what it deliberately leaves to [`NoRenderer`](crate::NoRenderer)
//!
//! PNG, JPEG and WebP sources; the [`Thumb`](RenditionProfile::Thumb) and
//! [`PagePng1x`](RenditionProfile::PagePng1x) profiles. Nothing else.
//!
//! `PdfSanitized`, `HtmlSanitized` and the office formats behind them are **not** here and are not
//! half-here. They need a parser rather than a decoder, running out of process under the limits
//! `plans/M2-ACCESS-DELIVERY.md` D17 specifies, and a partial implementation would be worse than a
//! refusal: it would report "preview available" for a format whose sanitization nobody has written
//! yet. [`NoRenderer`](crate::NoRenderer) still answers for those, which is the deny-by-default this
//! crate already relies on.
//!
//! `PagePng2x` is refused too, and that is a decision rather than an omission. The 2x profile exists
//! so a high-density display gets real detail; a raster source has none to give above its own pixel
//! grid, so serving it would mean upscaling — double the cache footprint for pixels that were
//! interpolated rather than read. A source that genuinely has more detail at 2x is a vector one, and
//! that arrives with the D17 worker.
//!
//! # The decode bomb, and the exact point it is stopped
//!
//! A 70-byte PNG may declare itself 65535×65535. Nothing about the file is large; the allocation it
//! asks for is 17 GiB, and a decoder whose only verb is "give me the pixels" performs that
//! allocation before anyone can object. That is the single failure mode this module is arranged
//! around.
//!
//! So the order is fixed, and it is the order rather than the check that matters:
//!
//! 1. **Sniff.** Magic bytes decide the format, from a closed allowlist. An unrecognised or
//!    non-allowlisted signature is [`Refusal::UnsupportedFormat`] and no decoder is constructed.
//! 2. **Inspect the header.** [`ImageReader::into_decoder`] parses the header and nothing else,
//!    yielding a decoder that already knows its dimensions and its `total_bytes()` — the exact size
//!    of the buffer the decode would need, from the decoder rather than from arithmetic of ours
//!    that could disagree with it about bit depth or channel count.
//! 3. **Decide.** `total_bytes()` over [`RenderBudget::max_output_bytes`] is
//!    [`Refusal::OutputTooLarge`], returned here, with no pixel buffer in existence.
//! 4. **Only then decode**, on the same decoder object the header check was made against. Checking
//!    with one parse and decoding with another is a parser differential in miniature: two readings
//!    of hostile bytes that are allowed to disagree, where the second one is the one that allocates.
//!
//! `max_output_bytes` bounds the intermediate as well as the artefact deliberately. A second knob
//! for the same direction is a knob someone sets inconsistently, and the bomb's whole property —
//! small going in, enormous coming out — is the one this number already exists to bound.
//!
//! The decoder's own [`Limits::max_alloc`] is set to the same number as a second layer, because it
//! is enforced *inside* the decode where this module cannot reach. It is not the guarantee: WebP
//! carries its dimensions in a chunk rather than a fixed header, and a bound that only holds where
//! we happened to look is one format away from not holding.
//!
//! # The declared media type is not consulted at all
//!
//! Not "consulted and then verified" — not read. [`RenderRequest::declared_media_type`] is whatever
//! the uploader claimed, and with a magic-byte sniff over a three-entry allowlist there is nothing
//! for a hint to usefully select: the sniff is cheaper than the branch that would use it, and a
//! renderer that dispatches on the claim feeds a PNG decoder a file that is not a PNG. A source
//! declared `application/pdf` that is really a JPEG renders as a JPEG; a GIF declared `image/png` is
//! refused as a GIF.
//!
//! # Re-encoding is a sanitizer, not a formality
//!
//! The rendition is built from decoded pixels and encoded fresh, so EXIF, ICC, XMP, thumbnails
//! embedded inside the source's own metadata, and anything appended after the format's end marker
//! do not survive. That is load-bearing: a phone photo's EXIF carries the GPS coordinates of where
//! it was taken, and a preview that passed the container through would publish them to everyone who
//! can see the file — a disclosure the uploader never made and `docs/06 §5` never permits.
//!
//! Output is always 8-bit RGBA PNG. One output colour type means an artefact's size is a function
//! of its dimensions alone, and there is no path where a 16-bit source yields a 16-bit rendition
//! that quietly doubles what the cache holds for it.
//!
//! # Why every byte of this runs on `spawn_blocking`
//!
//! `CLAUDE.md` forbids blocking calls in async contexts, and here the reason is sharper than
//! throughput. [`Bounded`](crate::Bounded)'s wall clock is `tokio::time::timeout`, which stops
//! polling a future — it cannot interrupt a thread already inside synchronous parser code. Decoding
//! on the runtime's poll thread would mean a hostile image stalls the executor and the budget
//! expires with nobody able to act on it. On a blocking thread the caller is released on time, which
//! is the promise the wrapper actually makes. It is not the process isolation D17 asks for, and
//! this module does not pretend otherwise.

use std::io::Cursor;

use async_trait::async_trait;
use image::codecs::png::{CompressionType, FilterType as PngFilter, PngEncoder};
use image::imageops::FilterType;
use image::{
    DynamicImage, ExtendedColorType, ImageDecoder as _, ImageEncoder as _, ImageFormat,
    ImageReader, Limits,
};

use crate::budget::{Refusal, RenderBudget};
use crate::error::{PreviewError, Result};
use crate::model::{GeneratorVersion, RenditionProfile};
use crate::render::{RenderOutcome, RenderRequest, RenderedArtifact, Renderer};

/// Which build produced an artefact, in the form [`Renderer::generator_version`] requires.
///
/// Two components, and both must move when they change. `raster/N` covers this module's own output
/// decisions — the edge lengths, the resampling filter, the encoder settings, the RGBA
/// normalisation. The suffix pins the decoder, down to the patch release, because a patch release of
/// a decoder is exactly the kind of change that alters output while looking like it could not:
/// `tests` reads the resolved version out of `Cargo.lock` and fails if the two have drifted, so an
/// upgrade cannot silently leave the cache serving artefacts from the build it replaced.
const GENERATOR: &str = "raster/1+image-0.25.10";

/// The formats this renderer will hand to a decoder.
///
/// A closed allowlist rather than "whatever the decoder can read". The `image` dependency is built
/// with these three formats and no others, so this list and the enabled parsers are the same set —
/// asserted in `tests`, because a feature added to the manifest for one crate's benefit would
/// otherwise silently widen what every uploader can get parsed.
const SUPPORTED_FORMATS: &[ImageFormat] = &[ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::WebP];

/// The longest edge of a thumbnail, in pixels.
///
/// Sized for a listing row or a card at 2x device density, not for reading. A thumbnail large
/// enough to read is a download with extra steps, which is the collapse `CLAUDE.md` rule 6 exists to
/// prevent.
const THUMB_EDGE: u32 = 320;

/// The longest edge of a nominal-resolution page image, in pixels.
///
/// Roughly an A4 page at 135 dpi: legible full-screen, and small enough that the RGBA buffer behind
/// it is single-digit megabytes however large the source was.
const PAGE_1X_EDGE: u32 = 1_600;

/// Renders raster images, in process, on a blocking thread.
///
/// Holds no configuration, no client and no handle to anything. That is not minimalism — a renderer
/// with a field could have a store in it, and the no-egress property of [`crate::render`] is worth
/// more than the flexibility.
#[derive(Debug, Clone, Copy, Default)]
pub struct RasterRenderer;

#[async_trait]
impl Renderer for RasterRenderer {
    fn generator_version(&self) -> GeneratorVersion {
        GeneratorVersion::new(GENERATOR)
    }

    fn supports(&self, profile: RenditionProfile) -> bool {
        longest_edge(profile).is_some()
    }

    async fn render(&self, request: RenderRequest) -> Result<RenderOutcome> {
        // Destructured rather than read field by field, so that a field added to `RenderRequest`
        // later — an identity, say — fails this build instead of being quietly ignored by it.
        let RenderRequest { profile, declared_media_type: _, source, budget } = request;

        let Some(edge) = longest_edge(profile) else {
            return Ok(RenderOutcome::Refused(Refusal::UnsupportedFormat));
        };

        match tokio::task::spawn_blocking(move || rasterize(&source, profile, edge, budget)).await {
            Ok(outcome) => outcome,
            // A parser that panics has made a statement about the document: the same bytes panic
            // the same way every time, so this is a verdict and caching it is correct. Reporting it
            // as ours would invite the retry, and a file that reliably kills a worker thread is a
            // denial-of-service primitive the moment a scheduler is willing to run it again.
            Err(join) if join.is_panic() => Ok(RenderOutcome::Refused(Refusal::SourceUnreadable)),
            // Cancellation is not about the document. The runtime is shutting down or the task was
            // aborted, and answering "this file has no preview" would cache an outage.
            Err(join) => Err(PreviewError::Worker(anyhow::Error::new(join))),
        }
    }
}

/// The whole synchronous pipeline, in the order the module documentation fixes.
///
/// Returns `Err` only for failures on our side of the line — an encoder that could not write pixels
/// this function produced itself. Everything the source is responsible for is a [`Refusal`].
fn rasterize(
    source: &[u8],
    profile: RenditionProfile,
    edge: u32,
    budget: RenderBudget,
) -> Result<RenderOutcome> {
    let Some(format) = sniff(source) else {
        return Ok(RenderOutcome::Refused(Refusal::UnsupportedFormat));
    };

    let mut limits = Limits::no_limits();
    limits.max_alloc = Some(budget.max_output_bytes);

    let mut reader = ImageReader::with_format(Cursor::new(source), format);
    reader.limits(limits);

    // Header only. A failure here is a source that carries the right magic bytes and then does not
    // parse — truncated, or a signature bolted onto something else.
    let Ok(decoder) = reader.into_decoder() else {
        return Ok(RenderOutcome::Refused(Refusal::SourceUnreadable));
    };

    let (width, height) = decoder.dimensions();
    if width == 0 || height == 0 {
        // Zero-extent images are legal in some containers and useless in all of them, and they are
        // the input that turns every ratio below into a division by zero.
        return Ok(RenderOutcome::Refused(Refusal::SourceUnreadable));
    }

    // The bomb check, and the last statement before any pixel buffer could exist.
    if decoder.total_bytes() > budget.max_output_bytes {
        return Ok(RenderOutcome::Refused(Refusal::OutputTooLarge));
    }

    let Ok(image) = DynamicImage::from_decoder(decoder) else {
        return Ok(RenderOutcome::Refused(Refusal::SourceUnreadable));
    };

    let (target_width, target_height) = fit_within(width, height, edge);
    // Downscale first, convert second. The other order would build an RGBA copy of the full-size
    // image — up to four times the decoded buffer for a greyscale source — after the one check that
    // bounds it has already been made.
    let scaled = if (target_width, target_height) == (width, height) {
        image
    } else {
        // `resize_exact` against dimensions computed here, rather than `resize`, so the geometry is
        // this module's and is unit-testable. `resize`'s own rounding is a detail of a dependency,
        // and a detail of a dependency that decides output dimensions is one that can change under
        // a generator version that did not move.
        image.resize_exact(target_width, target_height, FilterType::Triangle)
    };
    let rgba = scaled.into_rgba8();

    let mut bytes = Vec::new();
    let encoder =
        PngEncoder::new_with_quality(&mut bytes, CompressionType::Default, PngFilter::Adaptive);
    encoder
        .write_image(rgba.as_raw(), target_width, target_height, ExtendedColorType::Rgba8)
        .map_err(|_| {
            // A fixed phrase, not the encoder's message: this is the one error path that has run
            // with the document's pixels in hand, and `CLAUDE.md` rule 10 does not want any of them
            // in a log line.
            PreviewError::Worker(anyhow::anyhow!("the rendition could not be encoded"))
        })?;

    Ok(RenderOutcome::Rendered(RenderedArtifact {
        bytes,
        // From the profile, never echoed from the input — the input's claim about itself is the
        // thing this whole module declines to believe.
        media_type: "image/png".to_owned(),
        // A raster source is one page. `None` for the unpaginated profile rather than `Some(1)`,
        // so `Bounded` has nothing to apply the page cap to; see `RenditionProfile::is_paginated`.
        page_count: profile.is_paginated().then_some(1),
    }))
}

/// Decides the format from content, or refuses.
///
/// [`image::guess_format`] recognises signatures for formats this build cannot decode, which is what
/// makes the allowlist meaningful: a GIF is identified as a GIF and refused as one, rather than
/// reaching a decoder that would fail on it for the incidental reason that the feature is off.
fn sniff(source: &[u8]) -> Option<ImageFormat> {
    let format = image::guess_format(source).ok()?;
    SUPPORTED_FORMATS.contains(&format).then_some(format)
}

/// The longest output edge for a profile, or `None` if this renderer does not serve it.
///
/// One function behind both [`Renderer::supports`] and the render path, so the two cannot come to
/// different conclusions — a renderer that claims a profile and then refuses every source under it
/// reads to an operator as a broken worker rather than as an unsupported profile.
const fn longest_edge(profile: RenditionProfile) -> Option<u32> {
    match profile {
        RenditionProfile::Thumb => Some(THUMB_EDGE),
        RenditionProfile::PagePng1x => Some(PAGE_1X_EDGE),
        RenditionProfile::PagePng2x
        | RenditionProfile::PdfSanitized
        | RenditionProfile::HtmlSanitized => None,
    }
}

/// Scales dimensions to fit a square box, preserving aspect ratio and never enlarging.
///
/// Never enlarging is the point: upscaling costs cache and bandwidth to deliver pixels that were
/// invented, and it turns a 40×30 icon into a megabyte of interpolation.
///
/// The arithmetic is `u64` because `width * edge` overflows `u32` at dimensions well inside what a
/// header may declare, and an overflowing multiply here would produce a *smaller* number — a
/// silently mis-sized rendition rather than a crash.
fn fit_within(width: u32, height: u32, edge: u32) -> (u32, u32) {
    let longest = width.max(height);
    if longest <= edge {
        return (width, height);
    }

    let scale = |value: u32| -> u32 {
        let scaled = u64::from(value) * u64::from(edge) / u64::from(longest);
        // Never zero: an extreme aspect ratio scales the short edge below one, and a zero-width
        // image is not something to hand an encoder.
        u32::try_from(scaled).unwrap_or(edge).max(1)
    };

    (scale(width), scale(height))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_generator_version_names_the_decoder_the_lockfile_resolved() {
        // The check the trait's doc comment asks for, made mechanical. A decoder bump changes what
        // this renderer emits; if the generator string does not move with it, every cached artefact
        // stays reachable under a key that no longer describes what produced it.
        let lock = include_str!("../../../Cargo.lock");
        let resolved = lock
            .split_once("\nname = \"image\"\nversion = \"")
            .expect("`image` in the lockfile")
            .1
            .split_once('"')
            .expect("the version's closing quote")
            .0;

        assert!(
            GENERATOR.ends_with(&format!("image-{resolved}")),
            "`{GENERATOR}` does not name image-{resolved}: bump it, or the cache serves artefacts \
             from the build this one replaced"
        );
    }

    #[test]
    fn the_allowlist_and_the_enabled_parsers_are_the_same_set() {
        // The manifest is read rather than restated. A test carrying its own copy of the list
        // passes when both copies are wrong together, and the failure that matters here is a
        // feature switched on in the manifest for some other reason — every enabled format is a
        // parser any uploader can reach.
        let manifest = include_str!("../../../Cargo.toml");
        let line = manifest
            .lines()
            .find(|line| line.starts_with("image "))
            .expect("the `image` dependency line");
        let features = line
            .split_once("features = [")
            .expect("the feature list")
            .1
            .split_once(']')
            .expect("the feature list's closing bracket")
            .0;

        for (format, feature) in
            [(ImageFormat::Png, "png"), (ImageFormat::Jpeg, "jpeg"), (ImageFormat::WebP, "webp")]
        {
            assert_eq!(
                SUPPORTED_FORMATS.contains(&format),
                features.contains(&format!("\"{feature}\"")),
                "`{feature}` is enabled in one place and not the other"
            );
        }
        assert_eq!(
            features.matches('"').count() / 2,
            SUPPORTED_FORMATS.len(),
            "a format is compiled in that the allowlist does not name, so it is a parser reachable \
             by upload that nobody decided to ship"
        );
    }

    #[test]
    fn only_the_two_raster_profiles_are_claimed() {
        assert!(RasterRenderer.supports(RenditionProfile::Thumb));
        assert!(RasterRenderer.supports(RenditionProfile::PagePng1x));
        // Not omissions. See the module documentation: 2x of a raster source is upscaling, and the
        // document profiles need the out-of-process worker rather than a decoder.
        assert!(!RasterRenderer.supports(RenditionProfile::PagePng2x));
        assert!(!RasterRenderer.supports(RenditionProfile::PdfSanitized));
        assert!(!RasterRenderer.supports(RenditionProfile::HtmlSanitized));
    }

    #[test]
    fn fitting_preserves_the_ratio_and_never_enlarges() {
        assert_eq!(fit_within(2000, 1200, 320), (320, 192));
        assert_eq!(fit_within(1200, 2000, 320), (192, 320));
        // Already inside the box: returned untouched rather than stretched up to it.
        assert_eq!(fit_within(64, 96, 320), (64, 96));
        assert_eq!(fit_within(320, 320, 320), (320, 320));
    }

    #[test]
    fn an_extreme_aspect_ratio_never_scales_an_edge_to_zero() {
        // A 20000×1 banner scales its short edge to 0.016 pixels. Rounded down that is a zero-width
        // rendition, which is an encoder panic or an empty artefact depending on which encoder.
        let (width, height) = fit_within(20_000, 1, 320);
        assert_eq!(width, 320);
        assert_eq!(height, 1);
    }

    #[test]
    fn fitting_the_largest_declarable_dimensions_does_not_overflow() {
        // Not reachable through `rasterize` — the bomb check refuses these long before here — but
        // the arithmetic is the kind that is correct until someone reorders the two.
        let (width, height) = fit_within(u32::MAX, u32::MAX, 1_600);
        assert_eq!((width, height), (1_600, 1_600));
    }

    #[test]
    fn a_signature_outside_the_allowlist_is_not_a_format_this_renderer_knows() {
        assert_eq!(sniff(b"GIF89a\x01\x00\x01\x00\x00\x00\x00"), None);
        assert_eq!(sniff(b"not an image at all"), None);
        assert_eq!(sniff(b""), None);
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n"), Some(ImageFormat::Png));
    }
}
