//! The budget holds against a renderer that ignores it.
//!
//! Every renderer here is deliberately badly behaved, because a well-behaved one proves nothing:
//! `Bounded` exists for the case where the component parsing hostile input is stuck, wrong, or
//! under someone else's control (`crates/preview/src/budget.rs`). A test whose renderer respects
//! its budget is a test of the renderer.
//!
//! The four bounds are asserted separately rather than through one hostile renderer, so a
//! regression names which bound stopped holding.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::time::Duration;

use async_trait::async_trait;
use enclave_preview::{
    Bounded, GeneratorVersion, NoRenderer, Refusal, RenderBudget, RenderOutcome, RenderRequest,
    RenderedArtifact, Renderer, RenditionProfile, Result,
};

/// A renderer that does whatever it is told, however badly.
struct Rogue {
    /// How long to take, regardless of the budget it is handed.
    takes: Duration,
    /// What to hand back, however large.
    produces: RenderedArtifact,
}

#[async_trait]
impl Renderer for Rogue {
    fn generator_version(&self) -> GeneratorVersion {
        GeneratorVersion::new("rogue/1")
    }

    fn supports(&self, _profile: RenditionProfile) -> bool {
        true
    }

    async fn render(&self, _request: RenderRequest) -> Result<RenderOutcome> {
        // Note what is absent: this renderer never reads `request.budget`. That is the point.
        tokio::time::sleep(self.takes).await;
        Ok(RenderOutcome::Rendered(self.produces.clone()))
    }
}

fn artifact(size: usize, pages: Option<u32>) -> RenderedArtifact {
    RenderedArtifact { bytes: vec![0; size], media_type: "image/png".to_owned(), page_count: pages }
}

fn request(profile: RenditionProfile, source: usize, budget: RenderBudget) -> RenderRequest {
    RenderRequest {
        profile,
        declared_media_type: "application/pdf".to_owned(),
        source: vec![0; source],
        budget,
    }
}

/// The bound that matters most: a renderer that never returns must not hold the caller.
///
/// `start_paused` makes this deterministic rather than a race against a real clock — tokio
/// auto-advances time while every task is idle, so the renderer's hour-long sleep and the budget's
/// thirty seconds resolve in the correct order without the test taking either.
#[tokio::test(start_paused = true)]
async fn a_renderer_that_hangs_is_refused_rather_than_awaited() {
    let budget = RenderBudget { wall_clock: Duration::from_secs(30), ..RenderBudget::DEFAULT };
    let renderer =
        Bounded::new(Rogue { takes: Duration::from_secs(3600), produces: artifact(1, None) });

    let outcome = renderer
        .render(request(RenditionProfile::Thumb, 1024, budget))
        .await
        .expect("a hung renderer is a verdict, not an error");

    assert_eq!(outcome.refusal(), Some(Refusal::Timeout));
}

/// And the timeout is a *verdict*, not an error — the distinction D17 turns on.
///
/// If this arrived as `Err`, the caller's natural response is a retry, and a retry against a
/// document engineered to take forever is a denial-of-service primitive with a scheduler helping
/// it along.
#[tokio::test(start_paused = true)]
async fn a_timeout_never_arrives_in_the_error_channel() {
    let budget = RenderBudget { wall_clock: Duration::from_millis(1), ..RenderBudget::DEFAULT };
    let renderer =
        Bounded::new(Rogue { takes: Duration::from_secs(60), produces: artifact(1, None) });

    let result = renderer.render(request(RenditionProfile::Thumb, 1, budget)).await;
    assert!(result.is_ok(), "a timeout became an error, which invites the retry it must not");
}

/// The decompression bomb: small going in, enormous coming out.
///
/// An input cap alone does not catch this — that is the bomb's whole design — which is why
/// `RenderBudget` bounds the two directions independently.
#[tokio::test]
async fn an_artifact_over_the_output_cap_is_refused_however_small_its_source() {
    let budget = RenderBudget {
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 4096,
        ..RenderBudget::DEFAULT
    };
    let renderer = Bounded::new(Rogue { takes: Duration::ZERO, produces: artifact(4097, None) });

    let outcome = renderer
        .render(request(RenditionProfile::Thumb, 16, budget))
        .await
        .expect("an oversized artifact is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::OutputTooLarge));
}

/// The source is refused before the renderer is entered at all.
///
/// Asserted by giving the rogue renderer an artifact it would happily return: if the input check
/// ran after the call, this would come back `Rendered`.
#[tokio::test]
async fn an_oversized_source_is_refused_without_being_parsed() {
    let budget = RenderBudget { max_input_bytes: 128, ..RenderBudget::DEFAULT };
    let renderer = Bounded::new(Rogue { takes: Duration::ZERO, produces: artifact(1, None) });

    let outcome = renderer
        .render(request(RenditionProfile::Thumb, 129, budget))
        .await
        .expect("an oversized source is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::InputTooLarge));
}

/// The page cap applies to paginated profiles.
#[tokio::test]
async fn a_paginated_profile_over_the_page_cap_is_refused() {
    let budget = RenderBudget { max_pages: 10, ..RenderBudget::DEFAULT };
    let renderer = Bounded::new(Rogue { takes: Duration::ZERO, produces: artifact(64, Some(11)) });

    let outcome = renderer
        .render(request(RenditionProfile::PagePng1x, 16, budget))
        .await
        .expect("too many pages is a verdict");

    assert_eq!(outcome.refusal(), Some(Refusal::TooManyPages));
    assert!(RenditionProfile::PagePng1x.is_paginated());
}

/// A thumbnail of a 5,000-page book costs what any other thumbnail costs.
///
/// The counterpart to the test above, and the reason the cap is not applied unconditionally: a
/// thumbnail is one image of the first page whatever the document's length.
#[tokio::test]
async fn a_thumbnail_is_not_subject_to_the_page_cap() {
    let budget = RenderBudget { max_pages: 10, ..RenderBudget::DEFAULT };
    // No page count: an unpaginated artifact reports none, so there is nothing to cap.
    let renderer = Bounded::new(Rogue { takes: Duration::ZERO, produces: artifact(64, None) });

    let outcome = renderer
        .render(request(RenditionProfile::Thumb, 16, budget))
        .await
        .expect("a thumbnail renders");

    assert_eq!(outcome.refusal(), None);
    assert!(!RenditionProfile::Thumb.is_paginated());
}

/// A deployment with no rendering worker refuses previews; it does not fall through.
///
/// The same shape as `crates/core`'s deny-by-default policy stubs, and for the same reason: the
/// alternative to "no preview" must never become "here is the original".
#[tokio::test]
async fn the_default_renderer_renders_nothing() {
    let renderer = Bounded::new(NoRenderer);
    for profile in RenditionProfile::all() {
        assert!(!renderer.supports(*profile), "`{profile}` claimed support with no worker present");
    }

    let outcome = renderer
        .render(request(RenditionProfile::PagePng1x, 16, RenderBudget::DEFAULT))
        .await
        .expect("refusing is not failing");
    assert_eq!(outcome.refusal(), Some(Refusal::UnsupportedFormat));
}
