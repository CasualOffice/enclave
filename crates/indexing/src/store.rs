//! Persisting chunk text to PostgreSQL, so the degraded path can find a document by what it says.
//!
//! # Why the text is written here as well as to the vector store
//!
//! `docs/07 §4` gives Milvus a `text` field, and for retrieval that is where chunk text belongs.
//! It is the wrong copy for one caller: the lexical fallback (`crates/search/src/lexical.rs`) runs
//! precisely when the vector store cannot be reached, so the copy it needs has to be somewhere else.
//! Before this module existed, degraded search matched file names and scalar metadata only, and a
//! contract whose body says *indemnity* was invisible unless that word was in its filename
//! (`ENC-515`).
//!
//! # One statement, because the prune is not optional
//!
//! [`write_chunks`] does two things — upsert the chunks this run produced, and delete the chunks of
//! this file that it did not — and they are one SQL statement rather than two, so no crash, no
//! cancelled task and no caller who forgot to open a transaction can leave the first done and the
//! second not.
//!
//! The state that would leave behind is worth naming, because it is not merely untidy. Chunks from
//! the *previous* version stay matchable: a clause deleted in v3 is still findable by its wording,
//! attributed to a file whose current text does not contain it. The post-filter cannot help — the
//! caller is fully authorised on the file, and the file genuinely exists. That is a disclosure of
//! removed content through a store nobody would think to check, and it is the same shape as the
//! orphan problem `ENC-513` solved for chunk *ids*: nothing knows the row is there, so nothing ever
//! corrects it.
//!
//! A run that produced no chunks — a scanned PDF, an [`ExtractOutcome::NoText`](crate::ExtractOutcome)
//! — therefore removes the file's text rather than leaving it alone. "This version has no text" is
//! a fact about the version, and answering it with the previous version's text is the same lie in a
//! quieter form.
//!
//! # What this module does not do
//!
//! It does not decide *whether* a file's text may be stored. A `NO_INDEX` classification means
//! content never leaves the database (`docs/07 §2.3`), and this table is inside the database — but
//! "may this text be indexed at all" is a classification question, answered by the pipeline stage
//! that has a classification in hand, before it calls this. A store that consulted policy would be
//! a second place where indexing eligibility is decided, and the second place is the one that ends
//! up disagreeing.
//!
//! It also holds no opinion about permissions, and has nowhere to put one. `chunk_text` carries no
//! ACL tokens, no classification rank and no barrier tokens: retrieval over it produces candidates,
//! and `crates/search`'s post-filter is what decides who sees them (`CLAUDE.md` rule 5).

use enclave_core::{FileId, TenantId, VersionId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::chunk::{Chunk, ChunkerVersion};
use crate::error::{IndexingError, Result};

/// What one call to [`write_chunks`] changed.
///
/// Both numbers, rather than a bare success. `pruned` is how an operator sees a reindex actually
/// replacing text instead of accumulating it, and a sweep that pruned nothing is distinguishable
/// from one that did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChunkWrite {
    /// Rows inserted or updated — the chunks this run produced.
    pub written: u64,
    /// Rows removed: text of this file that this run did not produce, which is every chunk of every
    /// earlier version and any chunk a re-chunk no longer yields.
    pub pruned: u64,
}

/// Replaces one file's stored chunk text with `chunks`.
///
/// Idempotent, and that is load-bearing rather than convenient: indexing runs off an at-least-once
/// outbox, so a retry is the ordinary case (`ENC-513`). Chunk ids are deterministic
/// ([`chunk_id`](crate::chunk_id)), so the second run updates the same rows the first wrote and the
/// prune finds nothing to do.
///
/// `version` is the version the chunks were extracted from, and every row is written against it.
/// Chunks belonging to any *other* version of the same file are removed in the same statement — see
/// the module documentation for why that cannot be a separate step.
///
/// Takes a `&mut PgConnection` rather than a pool so a caller may run it inside the transaction that
/// updates `index_manifests`, which is where it belongs: a manifest that says `READY` over text that
/// was never committed is the same confident wrong answer from the other side.
///
/// # Errors
///
/// Storage failures. Never a partial write reported as success: the single statement either applies
/// or it does not.
pub async fn write_chunks(
    conn: &mut PgConnection,
    tenant: TenantId,
    file: FileId,
    version: VersionId,
    chunker: ChunkerVersion,
    chunks: &[Chunk],
) -> Result<ChunkWrite> {
    let ids: Vec<Uuid> = chunks.iter().map(|chunk| chunk.id).collect();
    // `i64::from` rather than a narrowing cast: `chunk_text.ordinal` is `BIGINT` precisely so this
    // conversion cannot fail, and so no fallback has to invent an ordinal.
    let ordinals: Vec<i64> = chunks.iter().map(|chunk| i64::from(chunk.ordinal)).collect();
    let texts: Vec<&str> = chunks.iter().map(|chunk| chunk.text.as_str()).collect();

    let row = sqlx::query(WRITE_SQL)
        .bind(tenant.as_uuid())
        .bind(file.as_uuid())
        .bind(version.as_uuid())
        .bind(chunker.as_str())
        .bind(&ids)
        .bind(&ordinals)
        .bind(&texts)
        .fetch_one(&mut *conn)
        .await?;

    Ok(ChunkWrite { written: count(&row, "written")?, pruned: count(&row, "pruned")? })
}

/// Reads one `count(*)` back as a `u64`.
///
/// `count(*)` is `BIGINT` and is never negative, so the conversion cannot lose anything; it is
/// written fallibly anyway rather than cast, because a column that failed to decode must be an
/// error and not a zero that reads as "nothing was written".
fn count(row: &sqlx::postgres::PgRow, column: &'static str) -> Result<u64> {
    let value: i64 = row.try_get(column).map_err(IndexingError::Storage)?;
    u64::try_from(value).map_err(|_| {
        IndexingError::Worker(anyhow::anyhow!("chunk write reported a negative {column} count"))
    })
}

/// Upsert and prune, as one statement.
///
/// The two data-modifying CTEs see the same snapshot, which is exactly what makes this safe to write
/// in either order: `pruned` cannot see the rows `written` is inserting, and it does not need to,
/// because it excludes their ids explicitly. The two therefore act on disjoint rows and cannot
/// collide inside the statement.
///
/// `chunk_id <> ALL($5)` with an empty array is true for every row, so a run that produced no chunks
/// removes the file's text. That is the intended reading — see the module documentation.
///
/// The upsert rewrites `file_id` and `version_id` on conflict rather than leaving them, so a row
/// whose id somehow already existed under another version is corrected rather than left holding text
/// attributed to the wrong version. The ids are derived from the version, so this is unreachable
/// today; it is written this way because "unreachable" and "silently wrong if reached" is a bad pair.
const WRITE_SQL: &str = "
WITH incoming AS (
    SELECT * FROM unnest($5::uuid[], $6::bigint[], $7::text[]) AS t(chunk_id, ordinal, text)
), written AS (
    INSERT INTO chunk_text
        (tenant_id, chunk_id, file_id, version_id, ordinal, chunker_version, text, written_at)
    SELECT $1, i.chunk_id, $2, $3, i.ordinal, $4, i.text, now()
      FROM incoming i
        ON CONFLICT (tenant_id, chunk_id)
        DO UPDATE SET file_id         = EXCLUDED.file_id,
                      version_id      = EXCLUDED.version_id,
                      ordinal         = EXCLUDED.ordinal,
                      chunker_version = EXCLUDED.chunker_version,
                      text            = EXCLUDED.text,
                      written_at      = EXCLUDED.written_at
    RETURNING chunk_id
), pruned AS (
    DELETE FROM chunk_text c
     WHERE c.tenant_id = $1
       AND c.file_id   = $2
       AND c.chunk_id <> ALL($5::uuid[])
    RETURNING c.chunk_id
)
SELECT (SELECT count(*) FROM written) AS written,
       (SELECT count(*) FROM pruned)  AS pruned
";
