//! `enclave-preview` — base renditions: generation, caching, and the bounds they run inside.
//!
//! Preview is the product's central claim. `docs/01-PRD.md §18`: a user may hold
//! `FILE_PREVIEW=ALLOW` with `FILE_DOWNLOAD=DENY`, and the system honours both. That is only true
//! if there is something to serve that is *not the original bytes* — which is what this crate
//! produces.
//!
//! # The three properties, and where each is enforced
//!
//! **1. A base rendition can never carry an identity.** `docs/06-SECURITY-DLP-ACCESS.md §5.1`
//! splits a preview into an identity-free base, which is cached, and a watermark naming the viewer,
//! which is composed per request and never stored. [`RenditionKey`] has three fields and none of
//! them can hold a principal; `RenderRequest` likewise. The guarantee is not that the code avoids
//! writing an identity — it is that there is nowhere to put one. See [`model`].
//!
//! **2. Nothing unscanned is ever parsed.** `CLAUDE.md` rule 9. Rendering is the read path that
//! hands bytes to a parser, so it is the one where serving `SCANNING` content matters most.
//! [`ReadableVersion`] has private fields and one constructor, whose query filters on
//! [`repo::READABLE_PREDICATE`]. A caller cannot express a request to render
//! something unscanned. See [`repo`].
//!
//! **3. A renderer cannot exceed its budget.** Document parsers are the widest attack surface in
//! the product. The budget is enforced *around* the renderer by [`Bounded`], not inside it, because
//! the component parsing hostile input is the one least able to promise it will stop. See
//! [`budget`].
//!
//! # A refusal is an answer, not an error
//!
//! A document that will not render — too large, too many pages, unsupported, engineered to hang —
//! produces [`PreviewOutcome::Unavailable`], a value in the success channel. Only *our* failures
//! are [`PreviewError`]. `plans/M2-ACCESS-DELIVERY.md` D17: a timeout is a verdict. Treated as an
//! error it becomes a retry, and a retry against a document engineered to take forever is a
//! denial-of-service primitive with a scheduler helping it along.
//!
//! # What renders today
//!
//! [`RasterRenderer`] — PNG, JPEG and WebP sources, producing the `thumb`, `page-png-1x` and
//! `page-png-2x` profiles. It runs in process on a blocking thread rather than in D17's sandboxed
//! worker, which is why its scope stops where it does: a decoder that inspects a header before
//! allocating can be bounded from here, and a document parser cannot. See [`raster`].
//!
//! # The composition a deployment runs (`ENC-798`)
//!
//! ```text
//! RenditionService<RasterRenderer, BlobSource, NoRenditionSink>
//!                  └ bounded ────┘ └ read ───┘ └ write ───────┘
//! ```
//!
//! [`BlobSource`] is the only holder of a `BlobStore` on the delivery path, and it has one method
//! that reads one key it was handed. [`NoRenditionSink`] keeps nothing, so every request renders —
//! see its documentation for why that is what `enclave_storage`'s seven-member trait can honestly
//! support, and `ENC-802` for the verb that would change it.
//!
//! # What is deliberately not here yet
//!
//! **No document formats.** PDF and OOXML need the out-of-process worker of
//! `plans/M2-ACCESS-DELIVERY.md` D17, with the process limits that make a memory bound real, so
//! `pdf-sanitized` and `html-sanitized` are still answered by [`NoRenderer`]. That is the
//! deny-by-default shape `crates/core`'s policy stages use: a deployment with no worker for a
//! format refuses that preview rather than falling through to something that serves originals. A
//! `.pdf` asked for as a thumbnail is refused for the same reason one layer down — the sniffer's
//! allowlist has three entries and none of them is a document.

pub mod blob;
pub mod budget;
pub mod composite;
pub mod error;
pub mod model;
pub mod print;
pub mod raster;
pub mod render;
pub mod repo;
pub mod service;
pub mod watermark;

pub use blob::BlobSource;
pub use budget::{Refusal, RenderBudget};
pub use composite::{composite as composite_watermark, CompositeRefusal};
pub use error::{PreviewError, Result};
pub use model::{GeneratorVersion, Rendition, RenditionKey, RenditionObject, RenditionProfile};
pub use print::{PrintGrant, PrintToken, PrintTokenDigest, RedeemedPrint};
pub use raster::RasterRenderer;
pub use render::{Bounded, NoRenderer, RenderOutcome, RenderRequest, RenderedArtifact, Renderer};
pub use repo::ReadableVersion;
pub use service::{
    BaseRendition, Delivery, Kept, NoRenditionSink, PreviewOutcome, PreviewPipeline,
    RenditionService, RenditionSink, SourceReader, UnconfiguredPipeline,
};
pub use watermark::{compose, escape_text, WatermarkFacts, WatermarkStyle, Watermarked};
