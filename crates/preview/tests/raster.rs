//! `RasterRenderer` against real files, hostile files, and files that lie about themselves.
//!
//! Three properties are worth more than the rest, and each has its own section below.
//!
//! **The decode bomb is stopped on the header.** A file of a few kilobytes may declare itself
//! 65535×65535, and a decoder that allocates before it checks turns that into a 17 GiB request.
//! Proving "it did not allocate" without a counting allocator — which `unsafe_code = "forbid"` puts
//! out of reach — needs an assertion that only the correct ordering can satisfy, so these tests
//! assert the *specific* refusal. A renderer that decoded first would answer `SourceUnreadable`,
//! because the fixture's pixel stream describes a far smaller image; `OutputTooLarge` is reachable
//! only from the header check that runs before any buffer exists.
//!
//! **A refusal is never an error and never a panic.** Every assertion here goes through `expect`
//! on the outer `Result`, so an implementation that reported a corrupt file as `Err` fails the test
//! rather than passing a weaker one.
//!
//! **The rendition is really an image.** Dimensions and colour type are read out of the emitted
//! PNG's IHDR by hand rather than through the library that wrote it, and the pixels are checked to
//! still carry the source's gradient — a renderer that returned a blank canvas of the right size
//! would satisfy every structural assertion and none of these.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use enclave_preview::{
    Bounded, RasterRenderer, Refusal, RenderBudget, RenderOutcome, RenderRequest, RenderedArtifact,
    Renderer, RenditionProfile,
};

/// 2000×1200, 8-bit RGB, a gradient: red rises left to right, green top to bottom, blue constant.
/// Larger than every target box, so both profiles must scale it down.
const LANDSCAPE_PNG: &[u8] = include_bytes!("fixtures/landscape-2000x1200.png");

/// 64×96 baseline JPEG. Smaller than every target box, so it is what proves the no-upscale rule.
const PORTRAIT_JPEG: &[u8] = include_bytes!("fixtures/portrait-64x96.jpg");

/// 48×32 lossless WebP — the third enabled parser, present so support for it is asserted rather
/// than assumed from the feature flag.
const SWATCH_WEBP: &[u8] = include_bytes!("fixtures/swatch-48x32.webp");

/// The first bytes of a GIF. A format `image` recognises and this build cannot decode, which is the
/// case that distinguishes "refused by the allowlist" from "failed for lack of a feature".
const GIF_HEADER: &[u8] = b"GIF89a\x10\x00\x10\x00\x80\x00\x00";

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Renders through the bare renderer, so the bounds asserted are the renderer's own.
///
/// `Bounded` would also refuse an oversized artefact, and a test that ran through it could not tell
/// which of the two had done the refusing. Exactly one test below goes through the wrapper, to show
/// the two compose.
async fn render(profile: RenditionProfile, declared: &str, source: &[u8]) -> RenderOutcome {
    render_within(profile, declared, source, RenderBudget::DEFAULT).await
}

async fn render_within(
    profile: RenditionProfile,
    declared: &str,
    source: &[u8],
    budget: RenderBudget,
) -> RenderOutcome {
    RasterRenderer
        .render(RenderRequest {
            profile,
            declared_media_type: declared.to_owned(),
            source: source.to_vec(),
            budget,
        })
        .await
        .expect("a verdict about a document is never an error")
}

fn rendered(outcome: RenderOutcome) -> RenderedArtifact {
    match outcome {
        RenderOutcome::Rendered(artifact) => artifact,
        RenderOutcome::Refused(refusal) => panic!("expected a rendition, got {refusal}"),
    }
}

/// The emitted PNG's IHDR, parsed by hand: width, height, bit depth, colour type.
///
/// Deliberately not `image::load_from_memory`. Reading the output back with the library that wrote
/// it proves the two agree, which they would even if both were wrong about what the profile asked
/// for.
fn ihdr(png: &[u8]) -> (u32, u32, u8, u8) {
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "the artefact is not a PNG");
    assert_eq!(&png[12..16], b"IHDR", "the first chunk of a PNG is IHDR");
    let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(png[20..24].try_into().unwrap());
    assert_eq!(&png[png.len() - 12..png.len() - 4], b"\0\0\0\0IEND", "the artefact is truncated");
    (width, height, png[24], png[25])
}

/// CRC-32 as PNG specifies it, so a patched IHDR is still a chunk a decoder will accept.
///
/// Without this the dimension-bomb fixtures would be rejected as corrupt, and the test would pass
/// for the wrong reason — the strongest way to get a security test to prove nothing.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A real PNG with its IHDR rewritten to declare enormous dimensions.
///
/// A synthesised header would test the header parser; this tests the pipeline, because every byte
/// after the IHDR is a genuine, complete, decodable image. The file stays 9 KB and claims 17 GiB.
fn png_declaring(width: u32, height: u32) -> Vec<u8> {
    let mut out = LANDSCAPE_PNG.to_vec();
    out[16..20].copy_from_slice(&width.to_be_bytes());
    out[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = crc32(&out[12..29]);
    out[29..33].copy_from_slice(&crc.to_be_bytes());
    out
}

/// The same trick for JPEG, which needs no checksum fixed up — the dimensions live in SOF0 and
/// nothing in the format cross-checks them against the scan that follows.
fn jpeg_declaring(width: u16, height: u16) -> Vec<u8> {
    let mut out = PORTRAIT_JPEG.to_vec();
    let sof = out
        .windows(2)
        .position(|pair| pair == [0xFF, 0xC0])
        .expect("a baseline JPEG has an SOF0 marker");
    out[sof + 5..sof + 7].copy_from_slice(&height.to_be_bytes());
    out[sof + 7..sof + 9].copy_from_slice(&width.to_be_bytes());
    out
}

/// And for lossless WebP, whose dimensions are 14-bit fields packed into the VP8L header.
///
/// 14 bits caps a side at 16383, so this bomb declares 16383×16383 — three quarters of a gigabyte
/// of pixels out of a 62-byte file. The same attack with a smaller number, which is the point: a
/// bound that only catches the 17 GiB case is a bound tuned to one fixture.
fn webp_declaring_max() -> Vec<u8> {
    let mut out = SWATCH_WEBP.to_vec();
    let signature = out.iter().position(|byte| *byte == 0x2F).expect("the VP8L signature byte");
    // Width-1 in the low 14 bits, height-1 in the next 14, then the alpha and version bits, which
    // stay clear — a non-zero version is rejected before the dimensions are ever read.
    let header: u32 = 0x3FFE | (0x3FFE << 14);
    out[signature + 1..signature + 5].copy_from_slice(&header.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------------------------
// It really renders
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_png_renders_a_thumbnail_at_the_profile_s_geometry() {
    let artifact = rendered(render(RenditionProfile::Thumb, "image/png", LANDSCAPE_PNG).await);

    let (width, height, depth, colour) = ihdr(&artifact.bytes);
    assert_eq!((width, height), (320, 192), "2000×1200 fitted to a 320 box, ratio preserved");
    assert_eq!((depth, colour), (8, 6), "renditions are 8-bit RGBA whatever the source was");
    assert_eq!(artifact.media_type, "image/png");
    // `None`, not `Some(1)`: an unpaginated profile gives `Bounded` nothing to apply a page cap to,
    // which is what keeps a 5,000-page document's thumbnail from being refused for its length.
    assert_eq!(artifact.page_count, None);
}

#[tokio::test]
async fn a_png_renders_a_page_image_at_the_nominal_edge() {
    let artifact = rendered(render(RenditionProfile::PagePng1x, "image/png", LANDSCAPE_PNG).await);

    let (width, height, _, _) = ihdr(&artifact.bytes);
    assert_eq!((width, height), (1_600, 960));
    // A raster source is exactly one page, and the profile is paginated, so it says so.
    assert_eq!(artifact.page_count, Some(1));
}

#[tokio::test]
async fn the_rendition_carries_the_source_s_pixels_and_not_a_blank_canvas() {
    // The assertion the structural ones cannot make. Every check above is satisfied by a renderer
    // that emits a correctly-sized field of zeroes, so this one reads the gradient back: red rises
    // left to right, green top to bottom, blue is constant. Sampled well inside the edges so the
    // resampling filter's treatment of the border is not what is being tested.
    let artifact = rendered(render(RenditionProfile::Thumb, "image/png", LANDSCAPE_PNG).await);
    let image = image::load_from_memory(&artifact.bytes).expect("a decodable PNG").to_rgb8();

    let top_left = image.get_pixel(8, 8);
    let top_right = image.get_pixel(311, 8);
    let bottom_left = image.get_pixel(8, 183);

    assert!(
        top_right[0] > top_left[0] + 200,
        "the horizontal red ramp did not survive: {top_right:?} vs {top_left:?}"
    );
    assert!(
        bottom_left[1] > top_left[1] + 200,
        "the vertical green ramp did not survive: {bottom_left:?} vs {top_left:?}"
    );
    for sample in [top_left, top_right, bottom_left] {
        assert!((90..=102).contains(&sample[2]), "the constant blue channel drifted: {sample:?}");
    }
}

#[tokio::test]
async fn a_jpeg_renders_and_a_source_smaller_than_the_box_is_never_enlarged() {
    let artifact = rendered(render(RenditionProfile::PagePng1x, "image/jpeg", PORTRAIT_JPEG).await);

    let (width, height, _, colour) = ihdr(&artifact.bytes);
    // 64×96 stays 64×96. Upscaling would spend cache and bandwidth on interpolated pixels, and the
    // profile's edge is a ceiling rather than a target.
    assert_eq!((width, height), (64, 96));
    assert_eq!(colour, 6, "a JPEG has no alpha channel; the rendition is RGBA regardless");
}

#[tokio::test]
async fn a_webp_source_renders() {
    let artifact = rendered(render(RenditionProfile::Thumb, "image/webp", SWATCH_WEBP).await);

    let (width, height, _, _) = ihdr(&artifact.bytes);
    assert_eq!((width, height), (48, 32));
}

#[tokio::test]
async fn a_rendition_survives_the_wrapper_the_service_puts_around_it() {
    // The one test through `Bounded`, because that is how `RenditionService` constructs it and a
    // renderer whose output the wrapper immediately refuses would still pass every test above.
    let renderer = Bounded::new(RasterRenderer);
    let outcome = renderer
        .render(RenderRequest {
            profile: RenditionProfile::Thumb,
            declared_media_type: "image/png".to_owned(),
            source: LANDSCAPE_PNG.to_vec(),
            budget: RenderBudget::DEFAULT,
        })
        .await
        .expect("a rendition is not an error");

    let artifact = rendered(outcome);
    assert_eq!(ihdr(&artifact.bytes).0, 320);
}

// ---------------------------------------------------------------------------------------------
// The decode bomb
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_png_declaring_impossible_dimensions_is_refused_on_its_header() {
    let bomb = png_declaring(65_535, 65_535);
    assert!(bomb.len() < 16 * 1024, "the fixture must stay small; the declaration is the attack");

    let started = std::time::Instant::now();
    let outcome = render(RenditionProfile::Thumb, "image/png", &bomb).await;

    // The ordering proof. Every byte after the IHDR describes a 2000×1200 image, so a decode that
    // ran first would exhaust the pixel stream and answer `SourceUnreadable` — or, with the limit
    // absent, ask the allocator for 65535 × 65535 × 3 bytes. `OutputTooLarge` is reachable only
    // from the header check, which runs before a buffer exists.
    assert_eq!(
        outcome.refusal(),
        Some(Refusal::OutputTooLarge),
        "the bomb was not refused on its header"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a header check is microseconds; anything near a wall clock means pixels were touched"
    );
}

#[tokio::test]
async fn a_jpeg_declaring_impossible_dimensions_is_refused_on_its_header() {
    // The same attack in a format with no checksum to fix up, so the bound cannot be something that
    // only PNG's header layout happens to make easy.
    let outcome =
        render(RenditionProfile::Thumb, "image/jpeg", &jpeg_declaring(65_535, 65_535)).await;

    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

#[tokio::test]
async fn a_webp_declaring_its_maximum_dimensions_is_refused_on_its_header() {
    // WebP carries its dimensions in a chunk rather than at a fixed offset, which is exactly the
    // shape of format that a bound written against one header layout silently fails to cover.
    let outcome = render(RenditionProfile::Thumb, "image/webp", &webp_declaring_max()).await;

    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

#[tokio::test]
async fn the_bound_is_the_budget_s_and_not_a_constant() {
    // A deployment that lowers `max_output_bytes` lowers what may be decoded, in one place. If this
    // bound were a private constant, a tightened budget would be a setting with no effect —
    // reassuring in a manifest and absent from the code path it names.
    let budget = RenderBudget { max_output_bytes: 1024 * 1024, ..RenderBudget::DEFAULT };
    let outcome = render_within(RenditionProfile::Thumb, "image/png", LANDSCAPE_PNG, budget).await;

    // 2000 × 1200 × 3 is 6.9 MiB decoded, from a 9 KB file that renders fine under the default.
    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
    assert!(matches!(
        render(RenditionProfile::Thumb, "image/png", LANDSCAPE_PNG).await,
        RenderOutcome::Rendered(_)
    ));
}

// ---------------------------------------------------------------------------------------------
// Refusals are verdicts
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_truncated_source_is_refused_rather_than_failing() {
    // Cut mid-IDAT: the header parses, the dimensions are honest, and the pixel stream stops.
    let half = &LANDSCAPE_PNG[..LANDSCAPE_PNG.len() / 2];
    assert_eq!(
        render(RenditionProfile::Thumb, "image/png", half).await.refusal(),
        Some(Refusal::SourceUnreadable)
    );

    // Cut before the header is complete: the magic bytes still say PNG, so this reaches the
    // decoder and must come back as a verdict too rather than as a parser error escaping upwards.
    assert_eq!(
        render(RenditionProfile::Thumb, "image/png", &LANDSCAPE_PNG[..20]).await.refusal(),
        Some(Refusal::SourceUnreadable)
    );
}

#[tokio::test]
async fn a_corrupt_source_is_refused_rather_than_failing() {
    // A valid header over scrambled compressed data — the case a fuzzer finds first, and the one
    // most likely to reach a `panic!` inside a decoder. A panic is caught and answered as a verdict
    // too, so neither outcome escapes as an error.
    let mut corrupt = LANDSCAPE_PNG.to_vec();
    for (index, byte) in corrupt.iter_mut().enumerate().skip(64) {
        *byte ^= u8::try_from(index % 251).unwrap_or(0);
    }

    assert_eq!(
        render(RenditionProfile::Thumb, "image/png", &corrupt).await.refusal(),
        Some(Refusal::SourceUnreadable)
    );
}

#[tokio::test]
async fn a_format_this_build_does_not_decode_is_refused_as_unsupported() {
    // A GIF is a format, not a failure: `docs/06 §5`'s vocabulary distinguishes "nothing renders
    // this" from "this is broken", and an installer or a video must not fill the logs as an error.
    assert_eq!(
        render(RenditionProfile::Thumb, "image/gif", GIF_HEADER).await.refusal(),
        Some(Refusal::UnsupportedFormat)
    );
    assert_eq!(
        render(RenditionProfile::Thumb, "text/plain", b"this is not an image").await.refusal(),
        Some(Refusal::UnsupportedFormat)
    );
    assert_eq!(
        render(RenditionProfile::Thumb, "image/png", b"").await.refusal(),
        Some(Refusal::UnsupportedFormat)
    );
}

#[tokio::test]
async fn a_profile_this_renderer_does_not_serve_is_refused_without_a_parse() {
    for profile in [
        RenditionProfile::PagePng2x,
        RenditionProfile::PdfSanitized,
        RenditionProfile::HtmlSanitized,
    ] {
        assert!(!RasterRenderer.supports(profile), "`{profile}` was claimed");
        assert_eq!(
            render(profile, "image/png", LANDSCAPE_PNG).await.refusal(),
            Some(Refusal::UnsupportedFormat),
            "`{profile}` reached a decoder"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The declared media type is not believed
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_source_is_rendered_as_what_it_is_and_not_as_what_it_claims() {
    // The uploader controls `declared_media_type`. A renderer that dispatched on it would hand a
    // PNG decoder a JPEG, which is how a parser meets input it was never written for.
    let lying = rendered(render(RenditionProfile::Thumb, "image/png", PORTRAIT_JPEG).await);
    let honest = rendered(render(RenditionProfile::Thumb, "image/jpeg", PORTRAIT_JPEG).await);
    assert_eq!(lying.bytes, honest.bytes, "the claim changed the rendition");

    // And the claim cannot make an unsupported format supported.
    assert_eq!(
        render(RenditionProfile::Thumb, "image/png", GIF_HEADER).await.refusal(),
        Some(Refusal::UnsupportedFormat)
    );
}

#[tokio::test]
async fn a_media_type_from_a_different_universe_does_not_stop_a_real_image_rendering() {
    // The other direction, and the one a "trust the hint, fall back to sniffing" design gets wrong:
    // a version row whose media type is stale or wrong must not cost the file its preview.
    let artifact =
        rendered(render(RenditionProfile::Thumb, "application/pdf", LANDSCAPE_PNG).await);
    assert_eq!(ihdr(&artifact.bytes).0, 320);
}

// ---------------------------------------------------------------------------------------------
// Identity and generation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_same_source_renders_to_the_same_bytes_every_time() {
    // A base rendition is cached under a key with no request in it, so two renders of one source
    // must be interchangeable. Non-determinism here — a timestamp in the PNG, a filter chosen by
    // wall clock — would mean the cached artefact and a regenerated one differ for no reason a
    // viewer could see, and would make any future integrity check on the cache meaningless.
    let first = rendered(render(RenditionProfile::Thumb, "image/png", LANDSCAPE_PNG).await);
    let second = rendered(render(RenditionProfile::Thumb, "image/png", LANDSCAPE_PNG).await);
    assert_eq!(first.bytes, second.bytes);
}

#[tokio::test]
async fn the_rendition_carries_none_of_the_source_s_metadata() {
    // Re-encoding from decoded pixels is what strips EXIF, and EXIF on a phone photo carries the
    // coordinates of where it was taken. The fixture has none to lose, so this asserts the
    // structural consequence instead: the artefact holds only the chunks a PNG needs, and nothing
    // was carried across from the container it came from.
    let artifact = rendered(render(RenditionProfile::Thumb, "image/jpeg", PORTRAIT_JPEG).await);
    for marker in [&b"Exif"[..], b"JFIF", b"http://ns.adobe.com/xap", b"iCCP", b"eXIf", b"tEXt"] {
        assert!(
            !artifact.bytes.windows(marker.len()).any(|window| window == marker),
            "`{}` survived re-encoding",
            String::from_utf8_lossy(marker)
        );
    }
}

#[test]
fn the_generator_version_is_not_the_one_that_renders_nothing() {
    // Cheap, and it catches the copy-paste that would make every artefact this renderer produces
    // indistinguishable in the cache from one produced by the stub that refuses everything.
    assert_ne!(RasterRenderer.generator_version(), enclave_preview::NoRenderer.generator_version());
}
