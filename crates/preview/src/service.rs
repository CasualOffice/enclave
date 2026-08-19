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

use chrono::{DateTime, Utc};
use enclave_core::TenantId;
use enclave_storage::ObjectKey;
use sqlx::PgConnection;

use crate::budget::{Refusal, RenderBudget};
use crate::error::{PreviewError, Result};
use crate::model::{Rendition, RenditionKey, RenditionProfile};
use crate::render::{Bounded, RenderOutcome, RenderRequest, Renderer};
use crate::repo::{self, ReadableVersion};

/// Where the source bytes come from.
///
/// A port rather than a [`BlobStore`](enclave_storage::BlobStore) handle threaded through, so that
/// [`RenditionService`] can be tested against a source that is a `Vec<u8>` and so that the renderer
/// still never sees a store — see [`crate::render`].
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

/// What a preview request produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewOutcome {
    /// A base rendition is available — freshly generated or served from cache.
    ///
    /// Carries the row, not the bytes. The caller streams from `object_key` and composes the
    /// watermark over it; handing back bytes here would mean holding a whole rendition in memory
    /// for every concurrent viewer.
    Available(Box<Rendition>),
    /// This version has no preview under this profile, and re-asking will not change that.
    Unavailable(Refusal),
}

/// Generates and caches base renditions.
#[derive(Debug, Clone)]
pub struct RenditionService<R, S> {
    renderer: Bounded<R>,
    source: S,
    budget: RenderBudget,
}

impl<R: Renderer, S: SourceReader> RenditionService<R, S> {
    /// Assembles the pipeline.
    ///
    /// The renderer is wrapped in [`Bounded`] here rather than by the caller, so that there is no
    /// way to construct this service around an unbounded renderer. A budget that can be omitted at
    /// the call site is a budget that will be.
    pub const fn new(renderer: R, source: S, budget: RenderBudget) -> Self {
        Self { renderer: Bounded::new(renderer), source, budget }
    }

    /// Returns the base rendition for a version, generating it if the cache does not hold one.
    ///
    /// The `ReadableVersion` argument is the guarantee that this never parses unscanned content —
    /// see [`crate::repo`].
    ///
    /// # Errors
    ///
    /// Storage failures, a dead rendering worker, or a source that could not be fetched. Never for
    /// a document that simply will not render: that is [`PreviewOutcome::Unavailable`].
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
            repo::touch(conn, tenant, key, now).await?;
            return Ok(PreviewOutcome::Available(Box::new(hit)));
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
                let object_key =
                    ObjectKey::rendition(tenant, version.id(), profile.as_str(), ARTIFACT_NAME)
                        .map_err(|error| PreviewError::Source(anyhow::Error::new(error)))?;

                let size = i64::try_from(artifact.size_bytes()).unwrap_or(i64::MAX);
                let pages = artifact.page_count.and_then(|p| i32::try_from(p).ok());

                repo::record(conn, tenant, key, object_key.as_str(), size, pages, now).await?;

                Ok(PreviewOutcome::Available(Box::new(Rendition {
                    version_id: version.id(),
                    profile,
                    object_key: object_key.as_str().to_owned(),
                    size_bytes: size,
                    page_count: pages,
                    generator_version: key.generator.as_str().to_owned(),
                    created_at: now,
                    last_access_at: None,
                })))
            }
        }
    }
}

/// The single artefact name under a rendition's profile prefix.
///
/// Fixed rather than derived from anything about the request, because `ObjectKey::rendition` treats
/// this segment as the one place a `../` could reach the key space, and a constant cannot carry
/// one. Multi-artefact profiles — a page-per-file pyramid — will name pages by index here, which
/// is still not caller-controlled.
const ARTIFACT_NAME: &str = "base";
