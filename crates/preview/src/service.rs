//! Cache lookup, generation, and recording — the pipeline `docs/06 §5.1` describes.
//!
//! # What this is not
//!
//! **It makes no authorization decision.** The policy chain is called from the handler, before a
//! domain service is reached (`plans/M1-CONTENT-CORE.md` D11), so everything here is unauthorized
//! by construction and assumes the caller already ran `PolicyEngine::enforce` for
//! [`FileAction::Preview`](enclave_core::FileAction::Preview). What this crate contributes is
//! narrower and separate: even a fully authorized caller cannot cause an unscanned version to be
//! parsed, because [`ReadableVersion`] cannot be constructed from one.
//!
//! **It does not compose watermarks.** The artefact this returns is the identity-free base
//! rendition. The watermark is composed over it in the response stream (`ENC-147`), never here and
//! never before the cache — see [`crate::model`].
//!
//! # The three ports, and why the store is two of them
//!
//! [`SourceReader`] fetches a version's bytes so they can be rendered. [`RenditionSink`] keeps the
//! artefact that comes out, and reads one back. They are separate traits over what will usually be
//! one object store, because the two capabilities are not the same: the source port names a key it
//! is *given* by a `ReadableVersion`, while the sink port accepts only a [`RenditionObject`] — a
//! key that cannot name an original. A single read/write port would have let a rendition write take
//! any key the pipeline could build, which is one bug away from overwriting a version.
//!
//! # A deployment that cannot keep a rendition still serves one
//!
//! [`NoRenditionSink`] is what a deployment gets today, and it keeps nothing: `enclave_storage`'s
//! `BlobStore` has no server-side write verb at all — every write in the product goes to a
//! pre-signed URL that a *client* PUTs to (`ENC-802`). So `base_rendition` renders on every
//! request, and records no row, because a row is a claim that bytes exist at a key and there would
//! be none. The alternative — record the row anyway — is worse than no cache: the next request
//! hits, fetches an object that was never written, and the file becomes permanently unpreviewable
//! under that generator.

use chrono::{DateTime, Utc};
use enclave_core::TenantId;
use sqlx::PgConnection;

use crate::budget::{Refusal, RenderBudget};
use crate::error::{PreviewError, Result};
use crate::model::{Rendition, RenditionKey, RenditionObject, RenditionProfile};
use crate::render::{Bounded, RenderOutcome, RenderRequest, Renderer};
use crate::repo::{self, ReadableVersion};

/// Where object bytes come from.
///
/// A port rather than a [`BlobStore`](enclave_storage::BlobStore) handle threaded through, so that
/// [`RenditionService`] can be tested against a source that is a `Vec<u8>` and so that the renderer
/// still never sees a store — see [`crate::render`]. [`crate::BlobSource`] is the implementation a
/// deployment runs.
#[async_trait::async_trait]
pub trait SourceReader: Send + Sync {
    /// Fetches an object's bytes.
    ///
    /// # Errors
    ///
    /// Transport failures. A missing object is an error here rather than `None`: the version row
    /// says the bytes exist, so their absence is a broken invariant and not an ordinary outcome.
    async fn read(&self, object_key: &str) -> Result<Vec<u8>>;
}

/// Where a generated base rendition is kept, when a deployment can keep one.
///
/// The write half of `docs/06 §5.1`'s cache. It takes a [`RenditionObject`] rather than a string
/// for the reason that type documents: the capability this port grants is "write a rendition", and
/// a `&str` would have made it "write anything the pipeline can name".
#[async_trait::async_trait]
pub trait RenditionSink: Send + Sync {
    /// Writes a freshly generated artefact, or reports that this deployment keeps none.
    ///
    /// # Errors
    ///
    /// Transport failures. "This deployment keeps nothing" is [`Kept::Discarded`] in the success
    /// channel and not an error — it is a property of the deployment, permanent, and identical on
    /// every request, so reporting it as a failure would turn every successful preview into a
    /// logged error.
    async fn keep(&self, object: &RenditionObject, bytes: &[u8]) -> Result<Kept>;

    /// Reads a kept artefact back.
    ///
    /// `None` means the object is gone — which is a **miss**, not a failure: an artefact evicted by
    /// a lifecycle rule, or lost with the deployment that wrote it, must regenerate rather than
    /// make the file permanently unpreviewable.
    ///
    /// # Errors
    ///
    /// Transport failures.
    async fn load(&self, object: &RenditionObject) -> Result<Option<Vec<u8>>>;
}

/// What a sink did with an artefact.
///
/// Two named values rather than a `bool`, because the caller's decision — whether to write a
/// `renditions` row — is not obviously "the same as" the answer to `stored?` at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// The bytes are at the key. A row may be recorded, and a later request may be served from it.
    Stored,
    /// The bytes were served and dropped. **No row may be recorded**: a row pointing at an object
    /// nobody wrote is a cache entry that fails forever.
    Discarded,
}

/// What a preview request produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewOutcome {
    /// A base rendition is available — freshly generated or served from cache.
    Available(Box<BaseRendition>),
    /// This version has no preview under this profile, and re-asking will not change that.
    Unavailable(Refusal),
}

/// A base rendition, its bytes, and whether anything kept it.
///
/// Carries the bytes rather than only the row, which the row-only shape could not: with no
/// server-side write verb there is not always a row, and a caller handed one would have no way to
/// tell a cache entry it can read from one it cannot. The bytes are already bounded — by
/// [`RenderBudget::max_output_bytes`], enforced around the renderer by [`Bounded`] — so this is not
/// an unbounded buffer per viewer, and the delivery path had to hold them in memory anyway to
/// composite a watermark over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRendition {
    /// The artefact. Identity-free: the watermark is composed over it at delivery, never baked in
    /// here, or it would be cacheable (`docs/06 §5.1`).
    pub bytes: Vec<u8>,
    /// Which derived form this is.
    pub profile: RenditionProfile,
    /// Pages represented, for paginated profiles.
    pub page_count: Option<i32>,
    /// The `renditions` row describing it, or `None` when this deployment kept nothing.
    ///
    /// `Some` is the claim that the bytes are also at [`Rendition::object_key`]; nothing writes a
    /// row without having written the object first.
    pub cached: Option<Rendition>,
}

/// Generates and caches base renditions.
#[derive(Debug, Clone)]
pub struct RenditionService<R, S, K> {
    renderer: Bounded<R>,
    source: S,
    sink: K,
    budget: RenderBudget,
}

impl<R: Renderer, S: SourceReader, K: RenditionSink> RenditionService<R, S, K> {
    /// Assembles the pipeline.
    ///
    /// The renderer is wrapped in [`Bounded`] here rather than by the caller, so that there is no
    /// way to construct this service around an unbounded renderer. A budget that can be omitted at
    /// the call site is a budget that will be.
    pub const fn new(renderer: R, source: S, sink: K, budget: RenderBudget) -> Self {
        Self { renderer: Bounded::new(renderer), source, sink, budget }
    }

    /// Returns the base rendition for a version, generating it if nothing has one cached.
    ///
    /// The `ReadableVersion` argument is the guarantee that this never parses unscanned content —
    /// see [`crate::repo`].
    ///
    /// # Errors
    ///
    /// Storage failures, a dead rendering worker, a source that could not be fetched, or a
    /// `renditions` row whose object key does not name a rendition of this tenant. Never for a
    /// document that simply will not render: that is [`PreviewOutcome::Unavailable`].
    pub async fn base_rendition(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        version: &ReadableVersion,
        profile: RenditionProfile,
        now: DateTime<Utc>,
    ) -> Result<PreviewOutcome> {
        let key = RenditionKey::new(version.id(), profile, self.renderer.generator_version());

        if let Some(hit) = repo::find(conn, tenant, key).await? {
            // The row's key is re-validated before a byte is fetched. A `renditions` row is data,
            // and data can be wrong; a key naming a *version* would turn this line into the
            // download path with a `Content-Type` of `image/png` (`CLAUDE.md` rule 6).
            let object = RenditionObject::parse(&hit.object_key, tenant).map_err(|_error| {
                PreviewError::MalformedRow {
                    column: "object_key",
                    reason: "does not name a rendition of this tenant",
                }
            })?;

            if let Some(bytes) = self.sink.load(&object).await? {
                repo::touch(conn, tenant, key, now).await?;
                return Ok(PreviewOutcome::Available(Box::new(BaseRendition {
                    bytes,
                    profile,
                    page_count: hit.page_count,
                    cached: Some(hit),
                })));
            }
            // The row outlived its object — evicted, or written by a deployment whose store this
            // one is not. Regenerating is the only answer that does not make the file permanently
            // unpreviewable; the row is overwritten below if this attempt is kept.
        }

        // Asked before the source is fetched, so an unsupported profile costs no object-storage
        // read and no allocation.
        if !self.renderer.supports(profile) {
            return Ok(PreviewOutcome::Unavailable(Refusal::UnsupportedFormat));
        }

        // The input cap, applied against the row's recorded size *before* the bytes are fetched.
        // `Bounded` checks it again on the buffer it is handed — that is not redundant, it is the
        // difference between trusting `size_bytes` and verifying it. This first check is what stops
        // a half-gigabyte read from happening at all.
        if u64::try_from(version.size_bytes()).unwrap_or(u64::MAX) > self.budget.max_input_bytes {
            return Ok(PreviewOutcome::Unavailable(Refusal::InputTooLarge));
        }

        let source = self.source.read(version.object_key()).await?;
        let request = RenderRequest {
            profile,
            declared_media_type: version.media_type().to_owned(),
            source,
            budget: self.budget,
        };

        match self.renderer.render(request).await? {
            RenderOutcome::Refused(refusal) => Ok(PreviewOutcome::Unavailable(refusal)),
            RenderOutcome::Rendered(artifact) => {
                let object = RenditionObject::new(tenant, version.id(), profile)
                    .map_err(|error| PreviewError::Source(anyhow::Error::new(error)))?;

                let size = i64::try_from(artifact.size_bytes()).unwrap_or(i64::MAX);
                let pages = artifact.page_count.and_then(|p| i32::try_from(p).ok());

                // The row is written only after the object is, and only if it was. See the module
                // header: the inverse order is a cache that serves 404s for the lifetime of a
                // generator.
                let cached = match self.sink.keep(&object, &artifact.bytes).await? {
                    Kept::Stored => {
                        repo::record(conn, tenant, key, object.as_str(), size, pages, now).await?;
                        Some(Rendition {
                            version_id: version.id(),
                            profile,
                            object_key: object.as_str().to_owned(),
                            size_bytes: size,
                            page_count: pages,
                            generator_version: key.generator.as_str().to_owned(),
                            created_at: now,
                            last_access_at: None,
                        })
                    }
                    Kept::Discarded => None,
                };

                Ok(PreviewOutcome::Available(Box::new(BaseRendition {
                    bytes: artifact.bytes,
                    profile,
                    page_count: pages,
                    cached,
                })))
            }
        }
    }
}

/// What the delivery path may ask of the pipeline.
///
/// # Why this is a trait and not the concrete service
///
/// `crates/api/src/preview.rs` holds no [`BlobStore`](enclave_storage::BlobStore) — deliberately,
/// and the module says so at length: a handler that could reach object storage is one edit away
/// from serving an original on the view-only path, which collapses `preview` and `download` into
/// one permission (`CLAUDE.md` rule 6).
///
/// Serving a rendition needs *some* storage read, so the question is what shape to give it. This
/// trait is the answer: one method, which takes a [`ReadableVersion`] and a profile and returns
/// bytes. There is no way to name an object key, and no method that mints a URL. The handler cannot
/// ask for the original because the vocabulary it is given cannot express the request — the same
/// technique the handler already uses against `BlobStore`, applied one level in.
#[async_trait::async_trait]
pub trait PreviewPipeline: Send + Sync {
    /// The bytes to serve for this version and profile.
    ///
    /// # Errors
    ///
    /// Storage failures, a dead rendering worker, or a source that could not be fetched. Never for
    /// a document that will not render — that is [`Delivery::Unavailable`].
    async fn deliver(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        version: &ReadableVersion,
        profile: RenditionProfile,
        now: DateTime<Utc>,
    ) -> Result<Delivery>;
}

/// What the delivery path got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// Bytes, ready to stream.
    Available {
        /// The base rendition. Identity-free — the watermark is composed over it at delivery, never
        /// baked in here, or it would be cacheable (`docs/06 §5.1`).
        bytes: Vec<u8>,
        /// What the bytes are. Determined by the profile, never echoed from the source.
        media_type: String,
        /// Pages represented, for paginated profiles.
        page_count: Option<i32>,
    },
    /// No preview for this version under this profile, and re-asking will not change that.
    Unavailable(Refusal),
}

#[async_trait::async_trait]
impl<R: Renderer, S: SourceReader, K: RenditionSink> PreviewPipeline for RenditionService<R, S, K> {
    async fn deliver(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        version: &ReadableVersion,
        profile: RenditionProfile,
        now: DateTime<Utc>,
    ) -> Result<Delivery> {
        match self.base_rendition(conn, tenant, version, profile, now).await? {
            PreviewOutcome::Unavailable(refusal) => Ok(Delivery::Unavailable(refusal)),
            PreviewOutcome::Available(base) => Ok(Delivery::Available {
                // The bytes this call produced or loaded, never a second fetch by a key from
                // anywhere else. That is what keeps the trait's promise: the pipeline serves the
                // object it decided on.
                bytes: base.bytes,
                media_type: media_type_for(base.profile).to_owned(),
                page_count: base.page_count,
            }),
        }
    }
}

/// What a profile's artefact is, as a media type.
///
/// Derived from the profile rather than stored beside it: a media type recorded at generation time
/// is one that can disagree with the bytes after a generator change, and the profile is what
/// decides the format in the first place.
const fn media_type_for(profile: RenditionProfile) -> &'static str {
    match profile {
        RenditionProfile::Thumb | RenditionProfile::PagePng1x | RenditionProfile::PagePng2x => {
            "image/png"
        }
        RenditionProfile::PdfSanitized => "application/pdf",
        // `charset` is not optional here. Without it a browser sniffs the encoding, and sniffing is
        // how a document controls its own interpretation.
        RenditionProfile::HtmlSanitized => "text/html; charset=utf-8",
    }
}

/// The sink a deployment has when nothing can keep a rendition.
///
/// Not a placeholder: it is what every deployment runs today, because `enclave_storage`'s
/// `BlobStore` has no method that writes bytes from this process. Its seven members put objects
/// into the bucket exactly one way — a pre-signed URL that the *client* PUTs to — which is what
/// keeps a 5 GB upload out of the API's memory, and which a server-side rendition write cannot use
/// without the API becoming its own S3 client (`ENC-802`).
///
/// So renditions are regenerated per request. That is a cost, not a hole: every attempt runs inside
/// the same [`RenderBudget`], and the artefact that comes out is the same identity-free base a
/// cached one would have been.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRenditionSink;

#[async_trait::async_trait]
impl RenditionSink for NoRenditionSink {
    async fn keep(&self, _object: &RenditionObject, _bytes: &[u8]) -> Result<Kept> {
        Ok(Kept::Discarded)
    }

    async fn load(&self, _object: &RenditionObject) -> Result<Option<Vec<u8>>> {
        // Nothing was ever kept, so nothing can be loaded. Reachable only for a row written by a
        // deployment that had a sink — which is a miss and regenerates, not a failure.
        Ok(None)
    }
}

/// The pipeline a deployment has when it has no rendering worker configured.
///
/// The counterpart to [`crate::NoRenderer`], one level up, and it exists for the reason `ENC-170`
/// found: `crates/api`'s router registered a preview route whose dependency the binary never
/// supplied, so it answered `500` while every integration test passed. The fix is not an `Option`
/// somebody has to remember to check — it is a value with defined behaviour, in the shape
/// `crates/core`'s policy stages already use.
///
/// # Why this errors rather than returning `Unavailable`
///
/// [`Delivery::Unavailable`] means *this document has no preview and re-asking will not change
/// that* — the caller sees a `404`, and the answer is cached as final. "Nobody configured a
/// renderer" is neither: it is an operator's problem, it is temporary, and reporting it as a
/// property of the document would have the product tell every user that none of their files can be
/// previewed. So it is [`PreviewError::Source`], which renders as a `503` naming object storage.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredPipeline;

#[async_trait::async_trait]
impl PreviewPipeline for UnconfiguredPipeline {
    async fn deliver(
        &self,
        _conn: &mut PgConnection,
        _tenant: TenantId,
        _version: &ReadableVersion,
        _profile: RenditionProfile,
        _now: DateTime<Utc>,
    ) -> Result<Delivery> {
        Err(PreviewError::Source(anyhow::anyhow!(
            "no rendition pipeline is configured in this deployment"
        )))
    }
}
