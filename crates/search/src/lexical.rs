//! Lexical retrieval over PostgreSQL — the candidate generator degraded search falls back to.
//!
//! # What this is, and what it is not
//!
//! It is a *candidate generator*, exactly as Milvus is. It produces [`Candidate`] values and its
//! output goes through [`crate::PostFilter::confirm`] before anybody sees it, so it inherits the
//! same contract: it is allowed to be wrong in the permissive direction and it is never consulted
//! about permissions. `plans/M3-DISCOVERY.md` D25 states the rule this module is built to obey —
//! degraded mode is a worse **recall** guarantee, never a worse **authorization** guarantee.
//!
//! That is why [`candidates`] hands back a [`LexicalCandidates`] rather than a `Vec<Candidate>`.
//! There is no accessor that unwraps it and no `From` impl that flattens it: the only thing in this
//! crate that consumes one is [`crate::SearchResults::confirm_degraded`], which post-filters it and
//! marks the result degraded. A path from this module to a caller that skips either step does not
//! exist to be taken by accident.
//!
//! # What it can find
//!
//! - A file by a **whole word in its name**. `budget` finds `Q3 budget-forecast.xlsx`.
//! - A file by a **whole word in one of its scalar metadata values** — `metadata_values.value_text`,
//!   the generated projection migration 0009 maintains.
//! - A file by a **whole word in its extracted text** — `chunk_text`, which
//!   `enclave_indexing::store` writes as documents are indexed (migration 0013, `ENC-515`). A
//!   300-page agreement whose body says *indemnity* is findable by that word without it appearing
//!   anywhere in the filename.
//!
//! # What the content half depends on, and what it therefore misses
//!
//! `chunk_text` holds the text of the version that was **last indexed**, which is not always the
//! current one. A file uploaded a moment ago, or one whose extraction failed or refused
//! (`enclave_indexing`'s `ExtractOutcome`), has no rows there and is findable by name and metadata
//! only — the pre-`ENC-515` behaviour, now the exception rather than the rule. That is ordinary
//! index staleness rather than a hole in the fallback: nothing here is a statement about
//! permissions, and every candidate is post-filtered whatever produced it.
//!
//! Formats matter more than freshness in practice. Only what an `enclave_indexing::Extractor`
//! handles has text at all, and today that is UTF-8 plain text and Markdown — PDF and OOXML wait on
//! D17's out-of-process worker. So *most* of a real tenant's content is still name-and-metadata only
//! on this path, and saying otherwise would misdescribe what a caller is getting during an incident.
//!
//! # What it cannot find, and this list is the honest part
//!
//! - **Prefixes and substrings.** `budg` finds nothing. Prefix matching means building a `tsquery`
//!   from user input rather than letting `plainto_tsquery` do it, and a query-syntax parser over
//!   untrusted input is not a thing to introduce on the path that only runs during an incident.
//! - **Inflections, stems and synonyms.** The text search configuration is `simple`, so `invoices`
//!   does not find `invoice`. A stemming configuration has to name a language, the tenant's
//!   documents are not all in it (`docs/14-I18N-L10N.md`), and a wrong guess changes recall
//!   silently in both directions. `simple` is wrong in one direction only, which is the direction
//!   a caller can understand from the results they got.
//! - **Multi-valued metadata.** `value_text` is NULL for arrays and objects by construction —
//!   migration 0009 says why — so a tag field holding `["legal","urgent"]` is not searchable here.
//! - **Folders, trashed files, and anything not `AVAILABLE`.** The last is `CLAUDE.md` rule 9: a
//!   file still being scanned is not served by any read path, and a fallback that forgot this would
//!   be a read path that serves unscanned content precisely when nobody is watching closely.
//!
//! # Why the text is normalized before it is tokenized
//!
//! PostgreSQL's default parser classifies `budget-forecast.xlsx` as a single `file` token, so
//! `to_tsvector('simple', …)` yields `'budget-forecast.xlsx'` and a search for `budget` misses it
//! entirely. Filenames and metadata values are short structured strings — codes, paths, ticket
//! ids — not prose, and the parser's compound token types are the wrong reading of every one of
//! them.
//!
//! So both sides are folded through `regexp_replace(…, '[^[:alnum:]]+', ' ', 'g')` first. **Both**
//! is the load-bearing word: normalizing the stored text but not the query, or the reverse, makes
//! the two disagree, and a search for `budget.xlsx` that cannot find `budget.xlsx` is the shape of
//! that bug. `[[:alnum:]]` is Unicode-aware in a UTF-8 database, so `Größe` survives as one token.
//!
//! # Cost, and the indexes these expressions must match
//!
//! Every `to_tsvector` expression below has a GIN index behind it: `files.name` and
//! `metadata_values.value_text` in migration 0012, `chunk_text.text` in 0013.
//!
//! An expression index is used **only** when the query's expression is identical, so the copies here
//! and the copies there are not redundancy to be tidied away — they are the same string twice on
//! purpose. A difference of one character does not make this query slower; it makes it a sequential
//! scan while the index sits unused, which reads as "full-text search is slow" rather than as a
//! typo. That mattered least on `files.name`, where the scan was bounded by a tenant's file count,
//! and matters most on `chunk_text`, which holds tens of rows per document and is the largest table
//! this schema has.

use enclave_core::{FileId, TenantId};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::degraded::DegradedReason;
use crate::error::SearchError;
use crate::postfilter::Candidate;

/// Candidates the lexical fallback produced, with the reason it was running at all.
///
/// Deliberately opaque. It carries a `Vec<Candidate>` and offers no way to read it, so the only
/// thing that can be done with one is hand it to [`crate::SearchResults::confirm_degraded`] — which
/// post-filters it and sets `degraded`. That is how D25's "a caller cannot mistake degraded results
/// for complete ones" is enforced by the compiler rather than by everyone remembering.
///
/// It carries no length or emptiness accessor either. The count of *unconfirmed* candidates is a
/// number about files the caller may not be allowed to know exist; the post-filter reports the same
/// figure as [`crate::DropCounts::proposed`] once it is safe to.
#[derive(Debug)]
pub struct LexicalCandidates {
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) reason: DegradedReason,
}

impl LexicalCandidates {
    /// Why retrieval was degraded when these were generated.
    #[must_use]
    pub const fn reason(&self) -> DegradedReason {
        self.reason
    }
}

/// Generates lexical candidates for `query` within `tenant`.
///
/// Requires a [`DegradedReason`], which is only obtainable from
/// [`crate::Retrieval::decide`](crate::degraded::Retrieval::decide). Lexical retrieval is not a
/// thing to reach for because it is convenient — it finds a fraction of what the vector path finds
/// (see the module documentation) — so the type system asks for the decision to have been made
/// before the query is written.
///
/// `limit` is a candidate budget, not a page size. The post-filter drops what the caller may not
/// see, so a page of 20 results needs materially more than 20 candidates (`plans/M3-DISCOVERY.md`
/// D21); a caller that passes its page size here gets short pages during an incident and reads them
/// as absence.
///
/// A query with no alphanumeric characters returns nothing without touching the database: an empty
/// `tsquery` matches no row anyway, and the scan to discover that is not worth running.
///
/// # Errors
///
/// Storage failures, and a row whose columns do not parse. Never an empty result standing in for a
/// failure — `crate::error` explains why that distinction is the one that matters here.
pub async fn candidates(
    conn: &mut PgConnection,
    tenant: TenantId,
    query: &str,
    limit: u32,
    reason: DegradedReason,
) -> Result<LexicalCandidates, SearchError> {
    if !query.chars().any(char::is_alphanumeric) {
        return Ok(LexicalCandidates { candidates: Vec::new(), reason });
    }

    let rows = sqlx::query(CANDIDATES_SQL)
        .bind(tenant.as_uuid())
        .bind(query)
        .bind(i64::from(limit))
        .fetch_all(&mut *conn)
        .await?;

    let candidates = rows
        .iter()
        .map(|row| {
            let file_id = row.try_get::<Uuid, _>("file_id").map(FileId::from).map_err(|_| {
                SearchError::MalformedRow { column: "file_id", reason: "missing or not a uuid" }
            })?;
            let score = row.try_get::<f32, _>("score").map_err(|_| SearchError::MalformedRow {
                column: "score",
                reason: "missing or not a rank",
            })?;
            // Still no excerpt, and it is still a decision. There is text to cut one from now, and
            // that makes the choice sharper rather than settling it: a headline over the
            // *normalized* expression returns the punctuation-stripped form, which is not the
            // sentence the document contains, and a headline over the raw text is a second
            // tokenization that can highlight a different span than the one that matched. Both are
            // decisions about what a quotation from a document is allowed to look like, and they
            // belong to a row of their own rather than to the change that made text searchable. An
            // empty snippet is a visible gap; a snippet assembled from the wrong source is an
            // invisible one.
            //
            // Note where the gate would be if this changes: the excerpt field is disclosed only
            // when the post-filter resolves `ContentRead`, and chunk text is document content, so
            // the machinery is already the right shape. Nothing here may disclose it directly.
            Ok(Candidate { file_id, score, excerpt: None })
        })
        .collect::<Result<Vec<_>, SearchError>>()?;

    Ok(LexicalCandidates { candidates, reason })
}

/// Matching files, ranked, for one tenant.
///
/// The tenant predicate is stated explicitly as well as enforced by row-level security. Redundant
/// by design: RLS is the control, and the predicate is what makes the index usable and what makes
/// the statement readable as tenant-scoped without knowing the session's settings.
///
/// `GROUP BY f.id` collapses the metadata join — a file with eight fields must not appear eight
/// times — and is legal against the other `f.` columns because `id` is the primary key.
///
/// # Why content is aggregated in a CTE and not joined like metadata
///
/// A document has tens of chunks and can have tens of metadata values, and joining both into the
/// same row set multiplies them: sixty chunks by eight fields is 480 rows for one file, every one of
/// them carrying the chunk's text through a `to_tsvector` the planner has no reason to compute once.
/// `GROUP BY f.id` would still give the right *answer*, at a cost that grows with the product of two
/// unrelated numbers.
///
/// So `content` reduces chunk matches to at most one row per file **before** the join, and the file
/// list is then left-joined against it. The predicate `k.file_id IS NOT NULL` is what admits a file
/// matched only by its body.
///
/// The tenant predicate appears in the CTE as well as in the outer query. `chunk_text` has its own
/// row-level security, so this is the same belt-and-braces the outer query already uses — and the
/// CTE is evaluated on its own, so leaving it out would mean scanning every tenant's chunks and
/// discarding the others at the join, which is both slower and a shape nobody should have to
/// re-derive as safe.
///
/// # Ranking
///
/// A name match outranks the other two by a factor of two: a filename is evidence about the
/// document, where a field value is evidence about one attribute of it and a chunk match is evidence
/// about one passage. Content and metadata are level with each other, deliberately unweighted —
/// `ts_rank` over a 2,400-character chunk and over a short field value are not comparable
/// quantities, and inventing a coefficient between them would look like a decision when it is a
/// guess. The exact factors are Q15's to settle (`plans/M3-DISCOVERY.md §7` asks whether degraded
/// mode should rank at all). What is not open is that the order is **total and deterministic** —
/// `file_id` breaks every remaining tie — because an order that varies between two identical queries
/// makes a paginating caller skip rows and repeat others, and "search dropped a result" is a report
/// nobody can reproduce.
///
/// The boost is written `2.0::real` rather than `2.0`, and the content default `0.0::real` for the
/// same reason. An unsuffixed literal is `numeric`, which makes the product `numeric`, which makes
/// the whole column `numeric` — and the decode below then fails with `MalformedRow` at runtime
/// rather than anywhere a type checker would have caught it. It did, on the first run.
const CANDIDATES_SQL: &str = "
WITH q AS (
    SELECT plainto_tsquery('simple', regexp_replace($2, '[^[:alnum:]]+', ' ', 'g')) AS tsq
), content AS (
    SELECT c.file_id, max(ts_rank(t.text_tsv, q.tsq)) AS score
      FROM chunk_text c
      CROSS JOIN q
      CROSS JOIN LATERAL (
          SELECT to_tsvector('simple', regexp_replace(c.text, '[^[:alnum:]]+', ' ', 'g'))
                 AS text_tsv
      ) t
     WHERE c.tenant_id = $1
       AND t.text_tsv @@ q.tsq
     GROUP BY c.file_id
)
SELECT f.id AS file_id,
       max(GREATEST(ts_rank(v.name_tsv, q.tsq) * 2.0::real,
                    ts_rank(v.meta_tsv, q.tsq),
                    coalesce(k.score, 0.0::real))) AS score
  FROM files f
  CROSS JOIN q
  LEFT JOIN metadata_values m
         ON m.tenant_id = f.tenant_id
        AND m.resource_type = 'FILE'
        AND m.resource_id = f.id
  LEFT JOIN content k
         ON k.file_id = f.id
  CROSS JOIN LATERAL (
      SELECT to_tsvector('simple', regexp_replace(f.name, '[^[:alnum:]]+', ' ', 'g')) AS name_tsv,
             to_tsvector('simple', regexp_replace(coalesce(m.value_text, ''),
                                                  '[^[:alnum:]]+', ' ', 'g')) AS meta_tsv
  ) v
 WHERE f.tenant_id = $1
   AND f.deleted_at IS NULL
   AND f.node_type = 'FILE'
   AND f.status = 'AVAILABLE'
   AND (v.name_tsv @@ q.tsq OR v.meta_tsv @@ q.tsq OR k.file_id IS NOT NULL)
 GROUP BY f.id
 ORDER BY score DESC, f.modified_at DESC, f.id
 LIMIT $3
";
