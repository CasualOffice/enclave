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
//!
//! # What it cannot find, and this list is the honest part
//!
//! - **Anything by document content.** There is no extracted-text table yet; D24's extraction lands
//!   in the sandboxed worker. A 300-page agreement whose text says *indemnity* is invisible here
//!   unless that word is in its filename or a metadata field. This is the largest gap between
//!   degraded and complete retrieval and the main reason the `degraded` flag has to reach the
//!   caller: without it, "not found" reads as "not there".
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
//! # Cost, and the index that is missing
//!
//! There is no expression index for these `to_tsvector` calls, so this is a sequential scan of the
//! tenant's files. It is acceptable *because of when it runs*: the vector store is already down, the
//! alternative is answering nothing, and a scan bounded by one tenant's file count is a cost paid
//! during an incident rather than continuously. It is not acceptable as a permanent state — a GIN
//! index on the normalized name expression belongs in a migration, and this module is written so
//! that adding one changes the plan and not the SQL.

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
            // No excerpt, and that is a decision rather than an omission. There is no extracted
            // text to excerpt from; a headline cut from the filename tells the caller nothing the
            // hit does not already carry; and a headline cut from a metadata value would push a
            // field value behind the post-filter's `ContentRead` gate, which answers a different
            // disclosure question than the one metadata values are governed by. An empty snippet is
            // a visible gap. A snippet assembled from the wrong source is an invisible one.
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
/// A name match outranks a metadata match by a factor of two: a filename is evidence about the
/// document, a field value is evidence about one attribute of it. The exact factor is Q15's to
/// settle (`plans/M3-DISCOVERY.md §7` asks whether degraded mode should rank at all). What is not
/// open is that the order is **total and deterministic** — `file_id` breaks every remaining tie —
/// because an order that varies between two identical queries makes a paginating caller skip rows
/// and repeat others, and "search dropped a result" is a report nobody can reproduce.
///
/// The boost is written `2.0::real` rather than `2.0`. An unsuffixed literal is `numeric`, which
/// makes the product `numeric`, which makes the whole column `numeric` — and the decode below then
/// fails with `MalformedRow` at runtime rather than anywhere a type checker would have caught it.
/// It did, on the first run.
const CANDIDATES_SQL: &str = "
WITH q AS (
    SELECT plainto_tsquery('simple', regexp_replace($2, '[^[:alnum:]]+', ' ', 'g')) AS tsq
)
SELECT f.id AS file_id,
       max(GREATEST(ts_rank(v.name_tsv, q.tsq) * 2.0::real, ts_rank(v.meta_tsv, q.tsq))) AS score
  FROM files f
  CROSS JOIN q
  LEFT JOIN metadata_values m
         ON m.tenant_id = f.tenant_id
        AND m.resource_type = 'FILE'
        AND m.resource_id = f.id
  CROSS JOIN LATERAL (
      SELECT to_tsvector('simple', regexp_replace(f.name, '[^[:alnum:]]+', ' ', 'g')) AS name_tsv,
             to_tsvector('simple', regexp_replace(coalesce(m.value_text, ''),
                                                  '[^[:alnum:]]+', ' ', 'g')) AS meta_tsv
  ) v
 WHERE f.tenant_id = $1
   AND f.deleted_at IS NULL
   AND f.node_type = 'FILE'
   AND f.status = 'AVAILABLE'
   AND (v.name_tsv @@ q.tsq OR v.meta_tsv @@ q.tsq)
 GROUP BY f.id
 ORDER BY score DESC, f.modified_at DESC, f.id
 LIMIT $3
";
