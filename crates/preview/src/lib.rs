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
//! `status = 'AVAILABLE' AND av_status = 'CLEAN'`. A caller cannot express a request to render
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
//! # What is deliberately not here yet
//!
//! **No real renderer.** [`NoRenderer`] refuses everything, in the shape `crates/core`'s policy
//! stages already use: a deployment with no rendering worker configured refuses every preview
//! rather than falling through to something that serves originals. The codecs live in a separate
//! sandboxed process (`plans/M2-ACCESS-DELIVERY.md` D17) and land in `ENC-146a`; this crate is the
//! pipeline they plug into, and the bounds they will run inside.
//!
//! **No watermark composition** (`ENC-147`) and **no API surface** (`ENC-148`).
//! `crates/api/src/preview.rs` still returns `501`, and it should keep doing so until there is a
//! rendition to serve — the shortcut of streaming originals in the meantime would collapse
//! `preview` and `download` into one permission on exactly the path where the collapse is least
//! visible.

pub mod budget;
pub mod error;
pub mod model;
pub mod render;
pub mod repo;
pub mod service;

pub use budget::{Refusal, RenderBudget};
pub use error::{PreviewError, Result};
pub use model::{GeneratorVersion, Rendition, RenditionKey, RenditionProfile};
pub use render::{Bounded, NoRenderer, RenderOutcome, RenderRequest, RenderedArtifact, Renderer};
pub use repo::ReadableVersion;
pub use service::{PreviewOutcome, RenditionService, SourceReader};
