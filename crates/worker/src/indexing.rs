//! The indexing pass — the thing that makes `chunk_text` non-empty in a real deployment.
//!
//! `ENC-527`'s last piece. Extraction, chunking, the chunk store and the manifest writer all
//! existed; nothing drove them, so degraded search behaved exactly as it had before `ENC-515`
//! landed. This drives them.
//!
//! # Rule 9 is why this reads versions through `readable_version`
//!
//! Indexing reads file *content*, and `CLAUDE.md` rule 9 says nothing serves content before
//! antivirus completes. [`enclave_preview::repo::readable_version`] already answers "may this
//! version's bytes be read" with a query carrying `status = 'AVAILABLE' AND av_status = 'CLEAN'`,
//! and returns `None` otherwise.
//!
//! This uses it rather than asking the question again. A second query deciding what is readable is
//! the one that drifts, and the drift is silent: an indexer reading a `SCANNING` version puts the
//! contents of an unscanned upload into the search index, where a permission check on the *file*
//! looks perfectly normal and the content is served as an excerpt.
//!
//! A version that is not readable is **deferred**, not failed — see
//! [`enclave_indexing::defer`]. "Not scanned yet" is not a verdict about the document.
//!
//! # One transaction per file, and what is inside it
//!
//! The chunk write and the manifest write share a transaction. Either order of a split would be
//! wrong in a way nothing reports: a manifest saying `READY` over text that was never committed is
//! a file that search believes it can find and cannot, and committed text with no manifest is text
//! the coverage check does not count, so the store reads as depleted while holding the right data.
//!
//! Files are separate transactions from each other. One document that fails to parse must not roll
//! back the twenty indexed before it, and each is independently retryable because the manifest
//! records where it got to.

use enclave_core::TenantId;
use enclave_db::DbPool;
use enclave_indexing::{
    claim, defer, record, write_chunks, BuildVersions, ExtractRequest, Extractor, Outcome, Pipeline,
};
use enclave_preview::repo::readable_version;
use enclave_preview::RenderBudget;
use enclave_storage::{BlobStore, ByteRange};
use tracing::debug;

use crate::{Result, Stop, WorkerError};

/// What one pass over a tenant's queue did.
///
/// Counted separately rather than summed into "processed", because the four mean different things
/// to an operator. `indexed` climbing is the system working; `failed` climbing is documents that
/// need looking at; `skipped` is types nobody has an extractor for; and `deferred` climbing while
/// the others stay flat means antivirus is behind, not that indexing is broken. A single total
/// would make those indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexPass {
    /// Files claimed this pass.
    pub claimed: usize,
    /// Files whose text is now searchable.
    pub indexed: usize,
    /// Files that produced no searchable text and were recorded `FAILED`.
    pub failed: usize,
    /// Files no extractor handles, recorded `SKIPPED`.
    pub skipped: usize,
    /// Files returned to the queue because their bytes are not readable yet.
    pub deferred: usize,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
}

/// Indexes up to `batch` of one tenant's queued files.
///
/// Returns rather than only logging, so a scheduler, a health check or a test can assert on the
/// outcome — the same reason `invalidation::sweep` does.
///
/// # Errors
///
/// [`WorkerError`] from the first file whose *storage or database* fails. Files already indexed in
/// this pass stay indexed: each was its own transaction. A document that fails to **parse** is not
/// an error — it is an [`Outcome`], recorded and counted, because a hostile or broken document is
/// the ordinary case here and must not stop the queue.
pub async fn index_pass<E: Extractor, S: BlobStore + ?Sized>(
    pool: &DbPool,
    tenant: TenantId,
    pipeline: &Pipeline<E>,
    store: &S,
    versions: BuildVersions<'_>,
    budget: RenderBudget,
    batch: i64,
    stop: &Stop,
) -> Result<IndexPass> {
    let mut outcome = IndexPass::default();

    let claimed = {
        let mut tx = pool.begin(tenant).await?;
        let claimed = claim(&mut tx, tenant, batch).await?;
        tx.commit().await?;
        claimed
    };
    outcome.claimed = claimed.len();

    for file in claimed {
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        let mut tx = pool.begin(tenant).await?;

        let Some(readable) = readable_version(&mut tx, tenant, file.version_id).await? else {
            // Not readable *yet*: scanning, quarantined, or superseded. Not a verdict.
            defer(&mut tx, tenant, file.file_id).await?;
            tx.commit().await?;
            outcome.deferred += 1;
            continue;
        };

        // Read before the extractor sees anything. The budget bounds what is read as well as what
        // is parsed — an extractor that is handed the whole of a 40 GB object has already lost,
        // whatever it then decides to do with it.
        let source = read_bounded(store, readable.object_key(), &budget).await?;

        let request = ExtractRequest {
            declared_media_type: readable.media_type().to_owned(),
            source,
            budget,
        };

        let prepared = pipeline.prepare(file.version_id, request).await?;

        if let Outcome::Ready { .. } = prepared.outcome {
            write_chunks(
                &mut tx,
                tenant,
                file.file_id,
                file.version_id,
                versions.chunker,
                &prepared.chunks,
            )
            .await?;
        }

        record(&mut tx, tenant, file.file_id, file.version_id, versions, &prepared.outcome).await?;
        tx.commit().await?;

        match prepared.outcome {
            Outcome::Ready { .. } => outcome.indexed += 1,
            Outcome::NoText(_) | Outcome::Refused(_) => outcome.failed += 1,
            Outcome::Unsupported => outcome.skipped += 1,
        }
    }

    debug!(
        claimed = outcome.claimed,
        indexed = outcome.indexed,
        failed = outcome.failed,
        skipped = outcome.skipped,
        deferred = outcome.deferred,
        stopped = outcome.stopped,
        "indexing pass complete"
    );
    Ok(outcome)
}

/// Reads the object, refusing rather than truncating if it exceeds the budget.
///
/// [`ByteStream::collect_bounded`] is the whole of it: it stops fetching the moment the accumulated
/// length would exceed the limit and returns [`enclave_storage::StorageError::TooLarge`]. That
/// distinction matters more here than it looks. A read that truncated at the cap would hand the
/// extractor a *prefix* of the document, which parses cleanly, chunks cleanly and indexes as though
/// complete — text that differs from the document, searchable, with nothing anywhere reporting a
/// problem. `ENC-511` refuses exactly that on the encoding side; this is the same refusal on the
/// size side.
///
/// The budget's `max_output_bytes` is the limit because it already bounds what the extractor may
/// produce: reading more than it could ever emit buys nothing and costs memory per worker.
async fn read_bounded<S: BlobStore + ?Sized>(
    store: &S,
    key: &str,
    budget: &RenderBudget,
) -> Result<Vec<u8>> {
    let limit =
        usize::try_from(budget.max_output_bytes).map_err(|_| WorkerError::MalformedRow {
            column: "render_budget.max_output_bytes",
            reason: "larger than this platform's addressable memory",
        })?;

    let stream = store.read_range(key, ByteRange::from(0)).await?;
    stream.collect_bounded(limit).await.map_err(WorkerError::from)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The counters must not be collapsed into a total.
    ///
    /// `deferred` climbing while `indexed` stays flat means antivirus is behind; `failed` climbing
    /// means documents need looking at. A single "processed" number makes an operator unable to
    /// tell a stalled scanner from a broken extractor, and both look like "indexing is slow".
    #[test]
    fn a_pass_reports_each_reason_separately() {
        let pass = IndexPass {
            claimed: 4,
            indexed: 1,
            failed: 1,
            skipped: 1,
            deferred: 1,
            stopped: false,
        };
        assert_eq!(pass.indexed + pass.failed + pass.skipped + pass.deferred, pass.claimed);
    }
}
