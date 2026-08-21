//! Which extractor is asked, when a deployment has more than one.
//!
//! `ENC-552`. [`Pipeline`](crate::Pipeline) holds **one** [`Extractor`], so until this module existed
//! a deployment got plain text *or* PDF and never both: `ENC-545`'s [`PdfTextExtractor`] was proven
//! by its own tests and unreachable in any worker that also wanted `text/plain`. This is the table
//! that picks between them.
//!
//! It lives in this crate rather than in a binary's `main.rs` deliberately. A router written at a
//! composition root puts extraction routing outside the crate that owns extraction, where it has no
//! tests of its own, no argument attached to it, and nothing stopping the next binary from writing a
//! second one that disagrees.
//!
//! # It dispatches on the hook that was already there
//!
//! [`Extractor::supports`] is consulted **before any bytes reach a parser**, and
//! [`Pipeline::prepare`](crate::Pipeline::prepare) already answers
//! [`Outcome::Unsupported`](crate::Outcome::Unsupported) when it says no. That is this module's whole
//! dispatch mechanism: [`MediaTypeRouter::supports`] is a lookup in the routing table, and
//! [`MediaTypeRouter::extract`] delegates to whatever the same lookup found. There is no second
//! mechanism, so there is no second place a media type can be decided.
//!
//! What the router selects is **which extractor is asked**, and nothing more. It is not the thing
//! that decides what the bytes are. `crates/preview/src/raster.rs` fixes this crate's stance and
//! [`ExtractRequest::declared_media_type`] restates it: a declared type is a *hint*, never a trust
//! boundary, and every extractor here sniffs the content and refuses bytes that are not what they
//! were claimed to be. A text file misdeclared `application/pdf` is routed to
//! [`PdfTextExtractor`], which refuses it on the `%PDF-` signature before a parser is constructed,
//! so routing a source to the wrong parser costs a refusal rather than a parse of something that
//! parser was never written for.
//!
//! The converse is weaker and is named here rather than implied, because a router is where somebody
//! will look for the check. A **PDF misdeclared `text/plain`** is routed to [`PlainTextExtractor`],
//! which has no signature to match — *plain* text has none — and refuses only what its NUL scan and
//! its strict UTF-8 decode catch. A PDF whose objects are all ASCII decodes, and its syntax is
//! indexed as prose. That is bounded (`text.rs` charges every segment against the output cap) and it
//! is ugly, and it is **exactly what happened before this module existed** in a text-only
//! deployment: the router changes which extractor a *correctly* declared source reaches and changes
//! nothing about a misdeclared one. Closing it means a negative sniff in `text.rs` — refusing bytes
//! that carry another format's signature — which is a change to an extractor's own verdicts and is
//! logged separately rather than folded in here.
//!
//! # The three decisions, and why each went the way it did
//!
//! ## 1. Two extractors claiming one type is refused at construction, not resolved
//!
//! The obvious design walks a list and takes the first extractor whose `supports` answers true.
//! Its failure is that **the resolution is invisible**: a deployment where two extractors both claim
//! `application/pdf` works, and somebody who later reorders the list — alphabetising it, moving the
//! PDF registration up next to a related one — changes which parser reads every PDF in the corpus
//! without knowing they changed anything, and nothing in a diff or a manifest says so.
//!
//! So [`MediaTypeRouter::route`] refuses the registration: a table with an ambiguous type is a
//! [`RouteError::Ambiguous`] and a process built on one does not start. That is `ENC-554`'s
//! conclusion applied to a different table — *a process that starts on the wrong value is worse than
//! one that refuses to start* — and it makes the ordering of the registrations carry no meaning at
//! all, which is the property that keeps a reorder from being a behaviour change.
//!
//! The registration also states its media types explicitly rather than asking the extractor which
//! ones it wants, because `supports` is a predicate and cannot be enumerated. The claim is
//! cross-checked in the direction that matters: an extractor registered for a type its own
//! `supports` rejects is [`RouteError::NotClaimed`], so the router can never route bytes to a parser
//! that was not written for them. The other direction — an extractor that claims a type nobody
//! registered — is not detectable and is deny-by-default: the type is unrouted, which is `SKIPPED`,
//! which is visible. An extractor registered for *nothing* is [`RouteError::NothingRouted`], because
//! that is a mistake rather than a policy: a deployment that mounted PDFium and then reached no PDF
//! would look exactly like one that had not.
//!
//! ## 2. No extractor claiming a type stays `SKIPPED`
//!
//! Unchanged, and structurally rather than by agreement. [`MediaTypeRouter::supports`] is false for
//! an unrouted type, `Pipeline::prepare` returns [`Outcome::Unsupported`](crate::Outcome), and the
//! manifest records `SKIPPED` / `unsupported_media_type` exactly as it did when
//! [`NoExtractor`](crate::NoExtractor) answered for everything. A deployment that registers nothing
//! is a router with an empty table, which is `NoExtractor` with a version marker.
//!
//! [`MediaTypeRouter::extract`] answers [`Refusal::UnsupportedFormat`] for an unrouted type, which is
//! what [`NoExtractor`] answers and is a *different* manifest state — `FAILED`, not `SKIPPED`. That
//! difference is only reachable by a caller that called `extract` without asking `supports` first,
//! which `Pipeline` does not do; the arm exists so an unwrapped router is still correct, in the shape
//! `text.rs` and `pdf_text.rs` both use for their own internal blank-page checks. Asserted in both
//! directions in this module's tests, because "the router is deny-by-default" is an assertion about
//! an absence and would otherwise pass for free.
//!
//! ## 3. The router is itself an `Extractor`, and its version marker is *checked*, not composed
//!
//! Being an [`Extractor`] is what makes `Pipeline` need no change: `Pipeline<MediaTypeRouter>` is an
//! ordinary pipeline, every existing test keeps working, and `crates/worker`'s
//! `Pipeline<E>` type parameter takes a router the same way it takes a bare extractor.
//!
//! The price is [`Extractor::extractor_version`], which now has to mean something for a *set* of
//! extractors — and `docs/07 §3` compares that string to decide what gets reindexed. Three answers
//! were possible and two of them are wrong:
//!
//! - **A marker for the router alone** (`router/1`) is the dangerous one. Bumping `pdf-text/1` to
//!   `pdf-text/2` would leave the recorded marker unchanged, so nothing reindexes and the index keeps
//!   serving text produced by the build that was replaced. A reindex trigger that silently stops
//!   triggering is worse than no trigger, because the dashboard says the corpus is current.
//! - **A marker composed at run time** from the members' versions gets the semantics right and
//!   breaks [`ExtractorVersion`]'s own rule: it is `&'static str` precisely so a marker cannot be
//!   assembled from a runtime value, because a marker that differs between two replicas of one
//!   deployment triggers a reindex that never converges. Composing one needs a leak, and a leak per
//!   router is a leak per test.
//! - **A marker the deployment declares, and the router verifies.** [`MediaTypeRouter::new`] takes
//!   an `ExtractorVersion` — a literal, at the composition root — and every registration checks that
//!   the router's marker names every `+`-separated component of that extractor's own. Registering
//!   `pdf-text/1+pdfium-render-0.9.3` under a marker that does not name both components is
//!   [`RouteError::UnnamedBuild`], and the process does not start.
//!
//! The third is what this module does. It turns "remember to bump the router when you bump an
//! extractor" from a convention into a build that refuses to run, which is the same move
//! `pdf_text.rs` makes when it asserts its own marker against `Cargo.lock` rather than trusting it.
//! The comparison is per component and not `contains`, and that is load-bearing: `text/1` is a
//! substring of `pdf-text/1`, so a containment check would accept a marker that had dropped the text
//! extractor entirely. This module's tests use exactly that pair as the positive control.
//!
//! ### What this marker costs, stated rather than discovered
//!
//! **It over-reindexes.** One marker covers every routed type, so bumping the PDF extractor changes
//! the marker recorded against text files too, and `docs/07 §3` reindexes them. That is work rather
//! than silence, which is the direction to err in; the alternative is the first bullet above.
//!
//! **The manifest no longer names the extractor that ran.** `index_manifests.extractor_version`
//! records the router's marker for every file, so a reader cannot tell from the row whether a
//! document was read by the text extractor or by PDFium. The information is not lost —
//! [`TextDocument::extractor_version`](crate::TextDocument::extractor_version) carries the truth out
//! of the extractor that produced it — but [`Prepared`](crate::Prepared) drops it and `crates/worker`
//! builds its `BuildVersions` once per pass rather than per document. Recorded as a gap; closing it
//! is a change to `Prepared` and to the worker's recording, not something to smuggle in behind a
//! router.
//!
//! **The mounted-PDFium gap is unchanged.** `ENC-545` already records it: a different `libpdfium`
//! can lay out a page's text differently under a marker that did not move, because the library is
//! `dlopen`ed at run time and [`ExtractorVersion`] is deliberately not computable from one. A router
//! marker inherits that gap exactly — it names `pdf-text/1+pdfium-render-0.9.3` and still cannot name
//! the `.so` — and does not widen it.
//!
//! # What this module does not touch
//!
//! **D24's gate.** [`Pipeline::prepare`](crate::Pipeline::prepare)'s `NonZeroU32` is the only
//! constructor of [`Outcome::Ready`](crate::Outcome::Ready) and this module has no path to it: the
//! router returns an [`ExtractOutcome`] like any other extractor and the pipeline decides. A document
//! that yields no text cannot become `READY` through a route.
//!
//! **Concurrency.** The router delegates one call and spawns nothing, so it adds no parallelism of
//! its own. What it does change is *reach*: PDF extraction stops being a thing only a PDF-only
//! deployment could run, so `ENC-551`'s hazard — two threads interleaving two PDFium documents kills
//! the process — is now live in ordinary deployments rather than latent. `crates/indexing/src/pdf.rs`
//! holds the `DOCUMENTS` lock for a document's whole life and both PDF modules take it, so the
//! hazard stays closed; the cost is that PDFium work in one process is serial per document, which is
//! a throughput bound the D17 sandbox would remove.
//!
//! **The error vocabulary.** [`RouteError`] carries `&'static str` and [`ExtractorVersion`], never a
//! `String` from anywhere near a document (`CLAUDE.md` rule 10). A routing table is written in code,
//! so its media types are literals — the same reason `ExtractorVersion` is `&'static str` — and there
//! is no way for a byte an uploader chose to reach one of these messages.
//!
//! [`PdfTextExtractor`]: crate::PdfTextExtractor
//! [`PlainTextExtractor`]: crate::PlainTextExtractor
//! [`NoExtractor`]: crate::NoExtractor
//! [`Pipeline`]: crate::Pipeline

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use enclave_preview::Refusal;

use crate::error::Result;
use crate::extract::{ExtractOutcome, ExtractRequest, Extractor};
use crate::model::ExtractorVersion;

/// The separator an [`ExtractorVersion`] uses between the builds it names.
///
/// `pdf-text/1+pdfium-render-0.9.3` is two components. The router's marker must name each of them
/// separately — see [`MediaTypeRouter::route`] for why a substring test is not good enough.
const COMPONENT: char = '+';

/// Why a routing table was refused.
///
/// Every variant is a startup failure. A deployment that hits one does not have a router with a
/// smaller table; it has no router, and the process does not start — see this module's
/// documentation for why that is the right direction for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteError {
    /// Two extractors were registered for one media type.
    ///
    /// Refused rather than resolved by declaration order, because an order that decides behaviour is
    /// one somebody changes by tidying a list.
    #[error("two extractors are registered for `{media_type}`")]
    Ambiguous {
        /// The colliding type, as the registration spelled it.
        media_type: &'static str,
    },

    /// An extractor was registered for a media type its own [`Extractor::supports`] rejects.
    ///
    /// The router would otherwise hand that extractor bytes it was not written for, which is the
    /// dispatch-on-the-claim mistake `crates/preview/src/raster.rs` exists to avoid.
    #[error("the extractor registered for `{media_type}` does not claim it")]
    NotClaimed {
        /// The type that was registered, as the registration spelled it.
        media_type: &'static str,
    },

    /// An extractor was registered for no media types at all.
    ///
    /// Unreachable rather than deny-by-default: a deployment that mounted PDFium and then routed
    /// nothing to it looks exactly like one that never mounted it.
    #[error("`{extractor}` was registered for no media type")]
    NothingRouted {
        /// The build that would never have been asked for anything.
        extractor: ExtractorVersion,
    },

    /// The router's version marker does not name a build it routes to.
    ///
    /// `docs/07 §3` compares that marker to decide what needs reindexing, so a marker that does not
    /// move when an extractor does leaves the index holding text from the build it replaced.
    #[error("the router's version does not name `{component}`")]
    UnnamedBuild {
        /// The component of the extractor's own version that the router's marker omits.
        component: &'static str,
    },
}

/// Sends a source to the one extractor registered for its declared media type.
///
/// An [`Extractor`] itself, so `Pipeline<MediaTypeRouter>` is an ordinary pipeline. Build it at the
/// composition root, wrap it in [`BoundedExtractor`](crate::BoundedExtractor), and hand it to
/// [`Pipeline::new`](crate::Pipeline::new):
///
/// ```
/// # use std::sync::Arc;
/// # use enclave_indexing::{ExtractorVersion, MediaTypeRouter, PlainTextExtractor};
/// let router = MediaTypeRouter::new(ExtractorVersion::new("router/1+text/1"))
///     .route(&["text/plain", "text/markdown"], Arc::new(PlainTextExtractor))?;
/// # Ok::<(), enclave_indexing::RouteError>(())
/// ```
///
/// Wrapping the *router* rather than each member is enough and is what this crate expects: one
/// attempt runs per request, and [`BoundedExtractor`](crate::BoundedExtractor) forwards
/// [`Extractor::supports`] and [`Extractor::extractor_version`], so a member that is itself wrapped
/// changes nothing about routing or about the version check below.
#[derive(Clone)]
pub struct MediaTypeRouter {
    version: ExtractorVersion,
    /// Keyed by the *essence* of a media type — lower-cased, parameters stripped — so that
    /// `TEXT/PLAIN; charset=utf-8` and `text/plain` cannot route differently.
    routes: BTreeMap<String, Arc<dyn Extractor>>,
}

impl MediaTypeRouter {
    /// An empty routing table, under the marker the deployment declares for it.
    ///
    /// An empty router is [`NoExtractor`](crate::NoExtractor) with a version: it claims nothing, so
    /// every source is `SKIPPED`. That is the deny-by-default state and not a broken one.
    ///
    /// `version` is a literal at the composition root, and [`route`](Self::route) refuses any
    /// extractor whose own version it does not name. See this module's documentation for why the
    /// marker is declared and checked rather than composed.
    #[must_use]
    pub const fn new(version: ExtractorVersion) -> Self {
        Self { version, routes: BTreeMap::new() }
    }

    /// Registers one extractor for the media types it is to be asked about.
    ///
    /// `media_types` is `&'static str` because a routing table is written in code — the same reason
    /// [`ExtractorVersion`] is — so nothing an uploader chose can enter a table or a [`RouteError`].
    ///
    /// # Errors
    ///
    /// - [`RouteError::UnnamedBuild`] when the router's marker does not name every `+`-separated
    ///   component of this extractor's version. Compared component by component and **not** with
    ///   `contains`: `text/1` is a substring of `pdf-text/1`, so a containment test would accept a
    ///   marker that had dropped the text extractor entirely.
    /// - [`RouteError::NotClaimed`] when the extractor's own `supports` rejects a type it is being
    ///   registered for.
    /// - [`RouteError::Ambiguous`] when another extractor already holds one of these types.
    /// - [`RouteError::NothingRouted`] when `media_types` is empty.
    pub fn route(
        mut self,
        media_types: &[&'static str],
        extractor: Arc<dyn Extractor>,
    ) -> core::result::Result<Self, RouteError> {
        let version = extractor.extractor_version();
        if media_types.is_empty() {
            return Err(RouteError::NothingRouted { extractor: version });
        }

        for component in version.as_str().split(COMPONENT) {
            if !self.version.as_str().split(COMPONENT).any(|named| named == component) {
                return Err(RouteError::UnnamedBuild { component });
            }
        }

        for &media_type in media_types {
            // The extractor's own claim, asked before anything is inserted. A router that registered
            // a type its extractor rejects would hand a parser bytes it was never written for, and
            // would do it on the strength of a line in a composition root.
            if !extractor.supports(media_type) {
                return Err(RouteError::NotClaimed { media_type });
            }
            let key = essence(media_type);
            if self.routes.contains_key(&key) {
                return Err(RouteError::Ambiguous { media_type });
            }
            self.routes.insert(key, Arc::clone(&extractor));
        }

        Ok(self)
    }

    /// The media types this router will hand to an extractor, normalised and in order.
    ///
    /// For a deployment's startup log and for tests. A router's whole configuration being readable
    /// is what makes "this deployment serves PDFs" a thing an operator can check rather than infer
    /// from a file that failed to index.
    pub fn routed(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }
}

#[async_trait]
impl Extractor for MediaTypeRouter {
    fn extractor_version(&self) -> ExtractorVersion {
        self.version
    }

    fn supports(&self, declared_media_type: &str) -> bool {
        self.routes.contains_key(&essence(declared_media_type))
    }

    async fn extract(&self, request: ExtractRequest) -> Result<ExtractOutcome> {
        let Some(extractor) = self.routes.get(&essence(&request.declared_media_type)) else {
            // Unreachable through `Pipeline`, which asks `supports` first and answers
            // `Outcome::Unsupported` — `SKIPPED` — for a type nothing claims. This is what an
            // *unwrapped* router answers, and it is `NoExtractor`'s answer rather than a second
            // one: an extractor that is only correct inside its caller is one somebody will call
            // directly.
            return Ok(ExtractOutcome::Refused(Refusal::UnsupportedFormat));
        };

        extractor.extract(request).await
    }
}

impl fmt::Debug for MediaTypeRouter {
    /// Names the marker and the table, because `dyn Extractor` has nothing to print.
    ///
    /// Everything here is code-supplied configuration — no document, no source, no bytes — so it is
    /// safe on any surface a `Debug` reaches (`CLAUDE.md` rule 10).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MediaTypeRouter")
            .field("version", &self.version)
            .field("routes", &self.routes.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The routing key for a declared media type: the essence, lower-cased.
///
/// The same normalisation `text.rs` and `pdf_text.rs` apply inside their own `supports` — parameters
/// stripped, ASCII case ignored — done once here so that the router and its members cannot disagree
/// about whether `TEXT/PLAIN; charset=utf-8` is `text/plain`. A disagreement in that direction is a
/// type the router accepts and the extractor then refuses, reported as a verdict about a document.
fn essence(declared_media_type: &str) -> String {
    declared_media_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use core::num::NonZeroU32;

    use enclave_preview::RenderBudget;

    use enclave_core::VersionId;

    use super::*;
    use crate::chunk::{ChunkBudget, Chunker, ChunkerVersion};
    use crate::model::{Coordinates, Segment, SegmentKind, TextDocument};
    use crate::pipeline::{ManifestStatus, Outcome, Pipeline, Reason};

    /// An extractor that claims a fixed set of types and reports which one of it ran.
    ///
    /// It produces a document whose only segment is its own name, so a test can assert **which**
    /// extractor a source reached rather than that some extraction happened — the difference between
    /// proving a route and proving that a router returns something.
    struct Named {
        version: &'static str,
        claims: &'static [&'static str],
    }

    impl Named {
        fn arc(version: &'static str, claims: &'static [&'static str]) -> Arc<dyn Extractor> {
            Arc::new(Self { version, claims })
        }
    }

    #[async_trait]
    impl Extractor for Named {
        fn extractor_version(&self) -> ExtractorVersion {
            ExtractorVersion::new(self.version)
        }

        fn supports(&self, declared_media_type: &str) -> bool {
            let essence = essence(declared_media_type);
            self.claims.iter().any(|claimed| essence == claimed.to_ascii_lowercase())
        }

        async fn extract(&self, _request: ExtractRequest) -> Result<ExtractOutcome> {
            Ok(ExtractOutcome::Extracted(TextDocument {
                segments: vec![Segment {
                    kind: SegmentKind::Document,
                    text: self.version.to_owned(),
                    coordinates: Coordinates::none(),
                }],
                media_type: "application/octet-stream".to_owned(),
                page_count: None,
                extractor_version: ExtractorVersion::new(self.version),
            }))
        }
    }

    /// An extractor that fails the test if it is ever handed bytes.
    ///
    /// `supports` is honest; `extract` is the trap. It is what turns "an unrouted type is skipped"
    /// from an assertion about an absence into one about a parser that was never entered.
    struct NeverExtracts;

    #[async_trait]
    impl Extractor for NeverExtracts {
        fn extractor_version(&self) -> ExtractorVersion {
            ExtractorVersion::new("never/1")
        }

        fn supports(&self, declared_media_type: &str) -> bool {
            essence(declared_media_type) == "text/plain"
        }

        async fn extract(&self, request: ExtractRequest) -> Result<ExtractOutcome> {
            panic!("bytes reached a parser for `{}`", request.declared_media_type)
        }
    }

    /// An extractor that parses happily and produces a document with no characters in it.
    ///
    /// The D24 shape: a scanned page, from the pipeline's point of view. It answers `Extracted`
    /// rather than `NoText` on purpose, because that is what an extractor that believes it succeeded
    /// returns and it is the case the `NonZeroU32` gate exists to catch.
    struct Blank;

    #[async_trait]
    impl Extractor for Blank {
        fn extractor_version(&self) -> ExtractorVersion {
            ExtractorVersion::new("blank/1")
        }

        fn supports(&self, declared_media_type: &str) -> bool {
            essence(declared_media_type) == "text/plain"
        }

        async fn extract(&self, _request: ExtractRequest) -> Result<ExtractOutcome> {
            Ok(ExtractOutcome::Extracted(TextDocument {
                segments: vec![Segment {
                    kind: SegmentKind::Page,
                    text: "   ".to_owned(),
                    coordinates: Coordinates { page_number: Some(1), ..Coordinates::none() },
                }],
                media_type: "application/pdf".to_owned(),
                page_count: Some(1),
                extractor_version: ExtractorVersion::new("blank/1"),
            }))
        }
    }

    fn request(declared: &str) -> ExtractRequest {
        ExtractRequest {
            declared_media_type: declared.to_owned(),
            source: b"irrelevant".to_vec(),
            budget: RenderBudget::DEFAULT,
        }
    }

    /// The name of the extractor a source reached, or a panic naming what came back instead.
    async fn reached(router: &MediaTypeRouter, declared: &str) -> String {
        match router.extract(request(declared)).await.expect("the fakes never error") {
            ExtractOutcome::Extracted(document) => document.flatten(),
            other => panic!("expected `{declared}` to reach an extractor, got {other:?}"),
        }
    }

    fn two_format_router() -> MediaTypeRouter {
        MediaTypeRouter::new(ExtractorVersion::new("router/1+text/1+pdf-text/1"))
            .route(
                &["text/plain", "text/markdown"],
                Named::arc("text/1", &["text/plain", "text/markdown"]),
            )
            .expect("the marker names text/1")
            .route(&["application/pdf"], Named::arc("pdf-text/1", &["application/pdf"]))
            .expect("the marker names pdf-text/1")
    }

    #[tokio::test]
    async fn each_source_reaches_the_extractor_registered_for_it() {
        // The positive control for everything below: without it, every "was not routed" assertion in
        // this module passes against a router that routes nothing anywhere.
        let router = two_format_router();

        assert_eq!(reached(&router, "text/plain").await, "text/1");
        assert_eq!(reached(&router, "text/markdown").await, "text/1");
        assert_eq!(reached(&router, "application/pdf").await, "pdf-text/1");
    }

    #[tokio::test]
    async fn parameters_and_case_do_not_change_the_route() {
        // The members normalise inside their own `supports`; if the router did not, a source
        // declared `TEXT/PLAIN; charset=utf-8` would be unrouted here and claimed there — `SKIPPED`
        // for a file the deployment can read perfectly well.
        let router = two_format_router();

        assert_eq!(reached(&router, "TEXT/PLAIN").await, "text/1");
        assert_eq!(reached(&router, "text/plain; charset=utf-8").await, "text/1");
        assert_eq!(reached(&router, "  application/PDF ; version=1.7").await, "pdf-text/1");
    }

    #[test]
    fn two_extractors_claiming_one_type_is_refused_at_construction() {
        // Not resolved by declaration order. An order that decides which parser reads every PDF in
        // the corpus is one somebody changes while alphabetising a list.
        let error = MediaTypeRouter::new(ExtractorVersion::new("router/1+one/1+two/1"))
            .route(&["application/pdf"], Named::arc("one/1", &["application/pdf"]))
            .expect("the first registration is fine")
            .route(&["application/pdf"], Named::arc("two/1", &["application/pdf"]))
            .expect_err("a second claim on application/pdf must not be resolved silently");

        assert_eq!(error, RouteError::Ambiguous { media_type: "application/pdf" });

        // The positive control: the same two extractors over disjoint types build a router. Without
        // it, this test passes against a `route` that refuses every second registration.
        MediaTypeRouter::new(ExtractorVersion::new("router/1+one/1+two/1"))
            .route(&["application/pdf"], Named::arc("one/1", &["application/pdf"]))
            .expect("the first registration is fine")
            .route(&["text/plain"], Named::arc("two/1", &["text/plain"]))
            .expect("disjoint types are not a conflict");
    }

    #[test]
    fn an_extractor_registered_for_a_type_it_does_not_claim_is_refused() {
        // Otherwise the router hands a parser bytes it was never written for, on the strength of a
        // line in a composition root — the dispatch-on-the-claim mistake, one level up.
        let error = MediaTypeRouter::new(ExtractorVersion::new("router/1+text/1"))
            .route(&["application/pdf"], Named::arc("text/1", &["text/plain"]))
            .expect_err("an extractor that does not claim application/pdf must not be routed it");

        assert_eq!(error, RouteError::NotClaimed { media_type: "application/pdf" });
    }

    #[test]
    fn an_extractor_routed_nothing_is_refused_rather_than_left_unreachable() {
        // A mounted PDFium that nothing routes to looks exactly like a PDFium that was never
        // mounted, and the file it silently does not read is `SKIPPED` on a surface nobody
        // correlates with a deployment change.
        let error = MediaTypeRouter::new(ExtractorVersion::new("router/1+pdf-text/1"))
            .route(&[], Named::arc("pdf-text/1", &["application/pdf"]))
            .expect_err("an extractor registered for nothing is a mistake, not a policy");

        assert_eq!(
            error,
            RouteError::NothingRouted { extractor: ExtractorVersion::new("pdf-text/1") }
        );
    }

    #[test]
    fn the_router_version_must_name_every_build_it_routes_to() {
        // `docs/07 §3` compares this string to decide what needs reindexing. A router marker that
        // does not move when a member's does leaves the index holding text produced by the build
        // that was replaced — and unlike a stale rendition, nothing regenerates it on demand.
        let error = MediaTypeRouter::new(ExtractorVersion::new("router/1+text/1"))
            .route(
                &["application/pdf"],
                Named::arc("pdf-text/1+pdfium-render-0.9.3", &["application/pdf"]),
            )
            .expect_err("a marker that names neither component of the PDF build must be refused");

        assert_eq!(error, RouteError::UnnamedBuild { component: "pdf-text/1" });

        // Every component, not just the first. A marker naming `pdf-text/1` and not the parser it
        // pins would leave a `pdfium-render` upgrade invisible to the reindex trigger, which is the
        // exact failure `pdf_text.rs` asserts its own marker against `Cargo.lock` to prevent.
        let error = MediaTypeRouter::new(ExtractorVersion::new("router/1+pdf-text/1"))
            .route(
                &["application/pdf"],
                Named::arc("pdf-text/1+pdfium-render-0.9.3", &["application/pdf"]),
            )
            .expect_err("a marker that omits the pinned parser must be refused");

        assert_eq!(error, RouteError::UnnamedBuild { component: "pdfium-render-0.9.3" });

        // The positive control: a marker naming both components builds.
        MediaTypeRouter::new(ExtractorVersion::new("router/1+pdf-text/1+pdfium-render-0.9.3"))
            .route(
                &["application/pdf"],
                Named::arc("pdf-text/1+pdfium-render-0.9.3", &["application/pdf"]),
            )
            .expect("a marker naming every component is what a deployment ships");
    }

    #[test]
    fn a_component_is_not_named_by_a_marker_that_merely_contains_it() {
        // The substring trap, and the reason the check splits on `+` rather than calling `contains`:
        // `text/1` is a substring of `pdf-text/1`. A containment test would accept a router that had
        // dropped the text extractor from its marker entirely, and every text file in the corpus
        // would then stop reindexing when the text extractor was bumped.
        assert!("router/1+pdf-text/1".contains("text/1"), "the trap this test exists for");

        let error = MediaTypeRouter::new(ExtractorVersion::new("router/1+pdf-text/1"))
            .route(&["text/plain"], Named::arc("text/1", &["text/plain"]))
            .expect_err("`pdf-text/1` does not name the build `text/1`");

        assert_eq!(error, RouteError::UnnamedBuild { component: "text/1" });
    }

    #[test]
    fn the_router_reports_the_marker_the_deployment_declared() {
        // What `crates/worker` records in `index_manifests.extractor_version`, and what `docs/07 §3`
        // compares. A router that reported a member's version would record one build's marker
        // against documents another build extracted.
        let router = two_format_router();

        assert_eq!(router.extractor_version().as_str(), "router/1+text/1+pdf-text/1");
        assert_eq!(
            router.routed().collect::<Vec<_>>(),
            vec!["application/pdf", "text/markdown", "text/plain"]
        );
    }

    #[tokio::test]
    async fn a_type_no_route_claims_is_skipped_and_never_reaches_a_parser() {
        // Decision 2, unchanged: `SKIPPED` / `unsupported_media_type`, not `FAILED`, and no bytes
        // handed to anything. `NeverExtracts` panics if it is entered, so this asserts the second
        // half rather than assuming it — an assertion about an absence otherwise passes for free.
        let router = MediaTypeRouter::new(ExtractorVersion::new("router/1+never/1"))
            .route(&["text/plain"], Arc::new(NeverExtracts))
            .expect("the marker names never/1");

        assert!(!router.supports("application/vnd.ms-excel"));

        let chunker = Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default());
        let prepared = Pipeline::new(router, chunker)
            .prepare(VersionId::new_v7(), request("application/vnd.ms-excel"))
            .await
            .expect("an unrouted type is not an error");

        assert_eq!(prepared.outcome.status(), ManifestStatus::Skipped);
        assert_eq!(prepared.outcome.reason(), Some(Reason::Unsupported));
        assert!(prepared.chunks.is_empty());
    }

    #[tokio::test]
    async fn an_empty_router_claims_nothing_and_skips_everything() {
        // The deny-by-default state: a deployment that registered no extractor is `NoExtractor` with
        // a version marker, not a router that falls through to something which indexes raw bytes.
        let router = MediaTypeRouter::new(ExtractorVersion::new("router/1"));

        assert!(!router.supports("text/plain"));
        assert!(router.routed().next().is_none());

        let chunker = Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default());
        let prepared = Pipeline::new(router, chunker)
            .prepare(VersionId::new_v7(), request("text/plain"))
            .await
            .expect("an empty table is not an error");

        assert_eq!(prepared.outcome, Outcome::Unsupported);
    }

    #[tokio::test]
    async fn an_unrouted_type_handed_straight_to_extract_is_refused_as_no_extractor_would() {
        // The arm `Pipeline` never reaches, kept correct for a caller that skipped `supports`. It is
        // `NoExtractor`'s answer rather than a second one, and it is deliberately *not* the same
        // manifest state: `Refused` is `FAILED`, and only a caller that dispatched without asking
        // can get there.
        let router = two_format_router();
        let outcome = router.extract(request("text/csv")).await.expect("not an error");

        assert_eq!(outcome, ExtractOutcome::Refused(Refusal::UnsupportedFormat));
    }

    #[tokio::test]
    async fn the_verdict_on_a_misdeclared_source_is_the_extractor_s_and_not_the_router_s() {
        // The router selects which extractor is asked; the extractor decides what the bytes are.
        // Run against the real `PlainTextExtractor` rather than a fake, because the property is that
        // the router does **not** pre-empt an extractor's sniff.
        //
        // `SourceUnreadable` is the assertion and the choice is deliberate: it is a code the router
        // cannot produce. Asserting `UnsupportedFormat` here would pass identically against a router
        // that had refused the source itself and never called anything — the "an absence passes for
        // free" shape `docs/12 §1.2` names.
        let router = MediaTypeRouter::new(ExtractorVersion::new("router/1+text/1"))
            .route(&["text/plain"], Arc::new(crate::text::PlainTextExtractor))
            .expect("the marker names text/1");

        let mut invalid = ExtractRequest {
            declared_media_type: "text/plain".to_owned(),
            source: vec![0xC3, 0x28],
            budget: RenderBudget::DEFAULT,
        };
        let outcome = router.extract(invalid).await.expect("not an error");
        assert_eq!(outcome, ExtractOutcome::Refused(Refusal::SourceUnreadable));

        // The positive control: the same route over bytes that *are* text extracts them.
        invalid = ExtractRequest {
            declared_media_type: "text/plain".to_owned(),
            source: b"a real paragraph".to_vec(),
            budget: RenderBudget::DEFAULT,
        };
        let outcome = router.extract(invalid).await.expect("not an error");
        assert_eq!(
            outcome.document().map(TextDocument::flatten).as_deref(),
            Some("a real paragraph")
        );
    }

    #[tokio::test]
    async fn a_routed_document_with_no_text_still_cannot_reach_ready() {
        // D24 through a route. The router returns an `ExtractOutcome` like any other extractor and
        // the pipeline decides, so `Pipeline::prepare`'s `NonZeroU32` is still the only constructor
        // of `Outcome::Ready` — the routing table adds no path around it.
        let chunker = || Chunker::new(ChunkerVersion::new("test/1"), ChunkBudget::default());

        let blank = MediaTypeRouter::new(ExtractorVersion::new("router/1+blank/1"))
            .route(&["text/plain"], Arc::new(Blank))
            .expect("the marker names blank/1");
        let prepared = Pipeline::new(blank, chunker())
            .prepare(VersionId::new_v7(), request("text/plain"))
            .await
            .expect("a document without text is not an error");

        assert_eq!(prepared.outcome.status(), ManifestStatus::Failed);
        assert_eq!(prepared.outcome.reason(), Some(Reason::NoText));
        assert!(prepared.chunks.is_empty());

        // The positive control, and the thing this whole item is for: the identical wiring over an
        // extractor that *does* produce text reaches `READY`. Without it, every assertion above
        // passes against a router that returns nothing for everything.
        let router = two_format_router();
        let prepared = Pipeline::new(router, chunker())
            .prepare(VersionId::new_v7(), request("text/plain"))
            .await
            .expect("not an error");

        assert_eq!(prepared.outcome, Outcome::Ready { chunks: NonZeroU32::new(1).expect("one") });
    }
}
