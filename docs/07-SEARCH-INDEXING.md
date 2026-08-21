# 07 — Search & Indexing

> **Status:** Draft · **Version:** 1.8 · **Owner:** Search Engineering · **Last updated:** 2026-08-22
> **Authoritative for:** the indexing pipeline, Milvus schema, permission-aware retrieval, ACL invalidation, rebuild.

## 1. Position of the index

Milvus is a **projection**. PostgreSQL and object storage are authoritative. Three consequences run
through this entire document:

1. Losing Milvus loses no data — only time (`§9`).
2. A Milvus result is a *candidate*, never a decision. Every candidate is confirmed against
   PostgreSQL before a caller sees it (`§6.2`).
3. When the index and the database disagree about permissions, the database wins and the index is
   repaired.

## 2. Indexing pipeline

```text
file.version.created
 -> Malware Scan          blocking; INFECTED terminates the pipeline
 -> DLP Pre-Scan          produces SecurityFacts
 -> Extract               text + structure per format
 -> Structure Parse       headings, tables, sheets, slides, code blocks
 -> Semantic Chunk        bounded, overlapping, structure-aware
 -> Metadata Enrichment   title, path, owner, dates, custom fields
 -> Classification        detected label, may raise the file's classification
 -> Embed                 provider routed by classification
 -> chunk_text upsert     chunk text into PostgreSQL, replacing the file's previous text
 -> Milvus upsert         chunk rows with security metadata
 -> index_manifests.status = READY
```

The `chunk_text` write (`04-DATA-MODEL.md §15`) is what makes degraded retrieval able to match on
document *content*: the lexical fallback runs when Milvus cannot be reached, so the copy it searches
cannot be Milvus's. It replaces the file's stored text rather than adding to it — wording removed by
a new version must stop being matchable through that file.

Every stage is idempotent on `(file_id, version_id, index_version)`. A retried event re-runs stages
without duplicating chunks: chunk IDs are deterministic,
`chunk_id = uuid_v5(version_id, chunker_version || ordinal)`.

### 2.1 Extraction

| Format | Extractor | Notes |
|---|---|---|
| PDF | `pdfium`/`pdf-extract` | Per-page text with coordinates. **OCR is a stage, not a fallback** — `plans/M3-DISCOVERY.md` D24 overrode the wording that stood here: a page yielding no text hands `pages_without_text` to OCR as a work list, and if OCR recovers nothing the version is recorded `FAILED`, never `READY` with nothing in it. A scanned PDF that indexes as empty is invisible to search while appearing correctly filed, which is worse than one that visibly failed to ingest |
| DOCX/PPTX/XLSX | OOXML parser | Headings, slide titles, sheet and range coordinates |
| TXT/Markdown/HTML | Native | HTML sanitized before extraction |
| CSV/JSON | Structured reader | Row groups and key paths as chunk boundaries |

Extraction runs sandboxed: no network egress, bounded CPU/memory/wall-clock, hard page and cell
limits. Extractor failures mark the manifest `FAILED` with a reason; the file stays fully usable and
lexically searchable by name and metadata.

### 2.2 Chunking

Structure-aware, not fixed-size-only. Target 400–800 tokens with ~15% overlap, never crossing a
table row group, slide, page or sheet-range boundary. Each chunk keeps its source coordinates
(`page_number`, `sheet_name`, `section_path`) so results can deep-link and so RAG answers can cite a
location a person can actually navigate to.

Chunk types: `document`, `section`, `paragraph`, `table`, `row_group`, `sheet_range`, `slide`,
`page`, `code_block`, `list`.

`page` is the paginated analogue of `slide` and carries the same boundary claim: a chunk keeps one
`page_number`, so a chunk merged across a page boundary cites one page for text that is on two.

### 2.3 Embedding

The embedding provider is chosen by classification (`classifications.embedding_policy`):

```text
RESTRICTED            -> LOCAL_ONLY      local/in-cluster model only
HIGHLY_CONFIDENTIAL   -> APPROVED_ONLY   named enterprise endpoint
CONFIDENTIAL          -> APPROVED_ONLY
INTERNAL / PUBLIC     -> ANY             any configured provider
any label may set     -> NO_INDEX        content never leaves the database
```

Routing is enforced in the `embeddings` crate, not in configuration alone: a request to embed
`RESTRICTED` text through a non-local provider is a hard error, and it is covered by a permanent test
(`12-TESTING.md §4`).

## 3. Reindexing triggers

| Trigger | Action | Re-embed? |
|---|---|---|
| New version | Full pipeline | Yes |
| Extractor / chunker / model version change | Full pipeline | Yes |
| Content unchanged, ACL changed | Metadata-only update (`§6.3`) | No |
| Classification changed | Metadata-only update; may drop chunks if the new label is `NO_INDEX` | No |
| File moved | Metadata-only update (path, workspace, library) | No |
| File deleted / purged | Delete by `version_id` filter | — |
| Library `ai_indexing_enabled` turned off | Delete all chunks for the library | — |
| Barrier assignment changed | Metadata-only update of `barrier_tokens` | No |

## 4. Milvus schema

Collection `workspace_chunks`, one Milvus partition key per tenant.

| Field | Type | Purpose |
|---|---|---|
| `chunk_id` | VARCHAR (PK) | Deterministic per `(version, chunker, ordinal)` |
| `tenant_id` | VARCHAR (partition key) | Hard tenant separation |
| `workspace_id`, `library_id` | VARCHAR | Scope filters |
| `file_id`, `version_id` | VARCHAR | Join back to PostgreSQL |
| `chunk_type` | VARCHAR | Result presentation and boosting |
| `title` | VARCHAR | Boosted lexical field |
| `text` | VARCHAR | Chunk body (BM25 source) |
| `dense_vector` | FLOAT_VECTOR | Semantic retrieval |
| `sparse_vector` | SPARSE_FLOAT_VECTOR | Learned sparse / BM25 hybrid |
| `classification_rank` | INT | Ceiling filtering |
| `acl_tokens` | ARRAY[VARCHAR] | **Optimization only** — see `§6` |
| `barrier_tokens` | ARRAY[VARCHAR] | Mandatory segmentation |
| `acl_epoch` | INT64 | `files.acl_revision` at index time |
| `mime_type`, `language` | VARCHAR | Filters |
| `page_number`, `sheet_name`, `section_path` | INT / VARCHAR | Deep links and citations |
| `modified_timestamp` | INT64 | Recency filters and boosting |

Index configuration: `HNSW` (M=32, efConstruction=256) for dense, `SPARSE_INVERTED_INDEX` for sparse,
scalar indexes on `tenant_id`, `workspace_id`, `library_id`, `file_id`, `classification_rank`.

Chunk `text` in Milvus is a copy of sensitive content. It is therefore treated as sensitive storage:
encrypted volumes, restricted network reach, no direct client access, and `NO_INDEX` classifications
never reach it at all.

## 5. Query pipeline

```text
Query
 -> Authenticate, resolve tenant / groups / barrier tokens / classification ceiling
 -> Conditional access (search may be permitted while download is not)
 -> Resolve accessible scope set from PostgreSQL (workspaces + libraries), cached
 -> Milvus hybrid query, over-fetched (limit x OVERFETCH), with server-built filters
 -> Fusion + rerank
 -> Authoritative permission recheck against PostgreSQL (batch)
 -> Drop or redact, then trim to the requested limit
 -> Audit, return
```

Server-built filter, always — never a client-supplied expression:

```text
tenant_id == "{tid}"
  and library_id in {accessible_library_ids}
  and classification_rank <= {ceiling}
  and barrier_tokens subset_of {allowed_barriers}
  and file_id not in {denylist}
```

`OVERFETCH` defaults to 3× (capped at 200 candidates) so that post-filter drops rarely leave a short
page. If post-filtering removes more than 50% of a page, the query is re-issued once with a deeper
fetch, and the ratio is recorded as a metric — a persistently high drop rate means index metadata has
drifted and repair is needed.

## 6. Permission correctness (the ACL invalidation problem)

**The problem.** `acl_tokens` are written at index time. Between indexing and querying, permissions
change. Milvus cannot participate in the PostgreSQL transaction that changes an ACL, so there is
always a window in which the index believes a user may read a chunk that the database says they may
not. In a naive design that window is a silent data leak through semantic search — precisely what
acceptance criterion #3 forbids.

**The design.** Correctness never depends on index freshness. Four layers:

### 6.1 Layer 1 — coarse, slow-changing pre-filter

The Milvus filter uses attributes that change rarely and are cheap to keep correct: `tenant_id`,
`library_id`, `classification_rank`, `barrier_tokens`. The caller's accessible library set is resolved
from PostgreSQL at query time — **not** from the index — and cached for 60 seconds under the
workspace/library membership revision.

This alone bounds the blast radius: a user can never receive candidates from a library they cannot
access, regardless of how stale per-file ACL tokens are.

### 6.2 Layer 2 — authoritative post-filter (the guarantee)

Every candidate is confirmed before it reaches the caller:

Two levels of disclosure are checked, not one:

- `MetadataRead` — required to see the hit at all (title, path, location);
- `ContentRead` — required to see the `excerpt`. A user who may see that a document exists but not
  read it gets the title and no snippet.

Both are resolved in **one** call, not two passes:

```rust
const DISCLOSURE_ACTIONS: [Action; 2] =
    [Action::File(FileAction::MetadataRead), Action::File(FileAction::ContentRead)];

let candidates = vector_store.search(&sec_ctx, request).await?;
let resources: Vec<_> = candidates
    .iter()
    .map(|c| ResourceRef::file(ctx.tenant_id, c.file_id))
    .collect();

// One batched query against PostgreSQL, for both actions at once — not a loop, and not
// two passes. The result is a grid, index-aligned with DISCLOSURE_ACTIONS.
let grid = authorization
    .authorize_many_actions(ctx, &DISCLOSURE_ACTIONS, &resources)
    .await?;

let metadata = grid.first();
let content = grid.get(1);
```

**Why one call and not two.** `ENC-145` measured resolution as roughly **80% fixed cost** — 1.4 ms
for a single candidate, 7.0 ms for two hundred. A second pass therefore very nearly doubles the
post-filter's price, while asking for more candidates in the same pass is close to free. `ENC-167`
made the batched multi-action form available and `plans/M3-DISCOVERY.md` D20 locks it. Measured
end to end, the two forms were **8.1 ms against 68.5 ms** for a page of results.

**Read the `get`/`first` shape above as load-bearing, not defensive.** The grid is index-aligned
with the actions, and a short outer vector leaves an action unanswered while a short inner one
leaves a candidate unanswered. Both must *drop* the candidate. An absent verdict is never a grant,
and code that unwraps here would turn a truncated response into a disclosure — which is why the
implementation in `crates/search/src/postfilter.rs` treats a missing entry as a denial rather than
indexing into the grid directly.

This layer is **mandatory and unconditional**. It is what makes the guarantee, and it is the reason
`acl_tokens` may be treated as an optimization. It costs one indexed batch query per search — a
`WHERE (tenant_id, file_id) IN (...)` against the effective-permission path, typically under 10 ms
for 200 candidates.

**An absent excerpt and a withheld one are the same value.** A caller who may know a document exists
but not read it receives `excerpt: null` — exactly what a document with no quotable passage yields.
Distinguishing them would tell the caller *there is content here you may not see*, which is a fact
about a document they may not read. The distinction exists once, in the operator-facing
`enclave_search_postfilter_excerpts_withheld_total` counter, and nowhere in a response.

#### 6.2.1 What an excerpt is

An excerpt is a **verbatim, contiguous substring of the indexed text of one chunk**, cut at word
boundaries, bounded in length — **240 characters on both retrieval paths** — and marked with `…` at
whichever end text was elided. No excerpt is ever assembled, reworded or normalized; the body
between the marks is the document's own bytes.

Which window is quoted is the one thing the two paths do not share, and they cannot:

- **Lexical.** The window contains at least one term the query matched on. If the matched term
  cannot be located in that chunk by the same rule the index matched on, **there is no excerpt**.
- **Dense.** A chunk retrieved by embedding similarity has **no matched span** — the caller may not
  have typed a word occurring in it, and finding documents that do not contain the words you typed
  is what the dense path is for. The window is therefore the **head** of the chunk.

The lexical path's last clause is the design, not a caveat. Both obvious implementations are wrong:

- `ts_headline` over the **indexed expression** — the `regexp_replace(…, '[^[:alnum:]]+', ' ', 'g')`
  form that `migrations/0012` and `migrations/0013` index and that `crates/search/src/lexical.rs`
  queries — highlights the right span and returns `Clause 7 2 b`. That is not a sentence any
  document contains, and a clause number is *made of* its punctuation.
- `ts_headline` over the **raw text** returns real sentences and is a second tokenization. The
  default parser reads `clause-7.2(b)` as one indivisible token, which is why the index normalizes
  first; a `tsquery` term of `clause` therefore matches nothing in the raw text, and `ts_headline`
  responds by returning **the opening words of the document** — handed to the caller as the passage
  that answered their query, with no error anywhere.

So the span is located by restating the indexed rule (a term is the lowercase of a maximal
alphanumeric run; `simple` neither stems nor drops stopwords) and the excerpt is cut from the raw
text at the located offsets. Where that restatement and PostgreSQL's tokenizer could disagree, the
result is `null` — the same value the `ContentRead` gate already produces, so the disagreement can
never become a disclosure.

The window is **not** snapped to sentence boundaries: a sentence end requires knowing the language,
and `14-I18N-L10N.md` has tenants in many. That is the same argument `migrations/0012` makes for
choosing `simple` over a stemmer, and it lands the same way — a wrong guess fails silently.

A head cut is **not** the raw-text `ts_headline` failure above wearing a different name, and the
difference decides whether it may be shown at all. `ts_headline` returns the opening of the
*document* when the match was elsewhere in it — a window outside the matched span, presented as the
matched span. On the dense path the matched unit **is the chunk**: the embedding was computed over
the whole of it and the whole of it is what scored, so there is no narrower true span for a head cut
to miss. What a dense excerpt cannot say is *which sentence*, and it does not claim to.

Three alternatives were weighed and rejected (`ENC-538`). Looking for the query's words in the chunk
and falling back to the head makes the meaning of the field depend on an accident, with nothing in
the response saying which rule produced a given string — and it is backwards, since dense retrieval
earns its keep precisely where those words are absent. Returning the whole chunk keeps the size of a
result dependent on which path answered and relabels that a contract; it is also 64 KB of document
body in a page of twenty results where 5 KB says the same. Returning nothing on the dense path makes
a **healthy** search disclose strictly less than a degraded one, inverting the relationship
`degraded: true` exists to describe.

No markup is produced by retrieval. `05-API.md §11`'s `<em>` is the API layer's, applied from
offsets — interpolating document content into a markup string in the retrieval crate is how stored
XSS gets delivered. Retrieval **carries** those offsets rather than leaving the API layer to
re-locate the terms, which would be a third tokenization of document content in the crate that also
builds the markup string. They exist only on the lexical path: nothing matched *at a position* on the
dense one, so a dense excerpt arrives unmarked, and the type says which of those two it is holding
rather than reporting both as an empty list.

The offsets travel **inside** the excerpt value, never beside it. A response carrying `excerpt: null`
with offsets next to it would say *there is a passage here you may not see*, which is exactly the
distinction `§6.2` withholds and `12-TESTING.md §4.3` S6 tests; there is no arrangement of the type
that can disclose one without the other, and the post-filter withholds both with one decision.

An excerpt is a **fragment**, so bidirectional state balanced across a whole document can be
unbalanced in the quotation: a U+202E opened before the passage and closed after it leaves the
excerpt with an override that is never terminated, reversing the surrounding interface of a result
list and not merely the snippet. The remedy is isolation at render (`14-I18N-L10N.md §7`) and **not**
stripping the characters here, which would break the verbatimness every clause above is built on.

`crates/search/src/excerpt.rs` is the implementation and carries the same argument at length.

### 6.3 Layer 3 — active invalidation

On `permission.changed`, `classification.changed`, barrier changes and moves, the indexing worker
performs a **metadata-only update**:

1. Read the affected `file_id`s (a folder-level ACL change expands to its subtree; the expansion is
   chunked and processed incrementally, never as one giant transaction).
2. For each affected version, recompute `acl_tokens`, `barrier_tokens`, `classification_rank` and
   `acl_epoch = files.acl_revision`.
3. Apply the update to Milvus.

Milvus `upsert` replaces a whole entity, so a metadata-only update still needs the vectors. Rather
than re-embedding — which is the expensive thing this path exists to avoid — the worker:

- **queries** the existing entities by `file_id` to retrieve `dense_vector` and `sparse_vector`
  (Milvus can return vectors as output fields), then upserts the same vectors with new scalars; or
- reads them from the **vector cache**, an object-storage-backed store keyed by `chunk_id` written
  during the original indexing run. The cache makes repair independent of the index's own health and
  is what allows a fast rebuild in `§9`.

Cost note: this is O(chunks of affected files), not O(tenant). A subtree ACL change on 50k files is a
background job with progress reporting, not a synchronous operation.

### 6.4 Layer 4 — the denylist (the fallback that closes the gap)

Layer 3 can fail or lag: Milvus is down, the update job is backed up, the vector cache is
incomplete. During that window Layer 2 still guarantees correctness — but Layer 2 only runs when a
candidate is returned, and a stale-but-permissive index wastes over-fetch budget and can crowd out
legitimate results.

So any invalidation that **reduces** access takes effect immediately:

1. In the same transaction as the ACL change, insert the affected `file_id`s into
   `retrieval_denylist` (`04-DATA-MODEL.md §15`) and mirror them into Redis.
2. Every query filter includes `file_id not in {denylist}`, sourced from the Redis mirror with a
   PostgreSQL fallback. The set is per-tenant and small; entries are removed as soon as the
   corresponding metadata update completes.
3. If the denylist exceeds a configured size (default 10 000 files) — meaning invalidation is badly
   backed up — semantic search for that tenant **degrades to lexical-only over authoritative
   PostgreSQL data** and reports `diagnostics.degraded: true`, rather than serving from an index that
   is known to be wrong at scale.
4. If Redis is unavailable, the denylist is read from PostgreSQL; if that also fails, vector search
   fails closed for that tenant.

Denylist entries carry `clears_at` as a backstop deadline, and the scheduler reconciles by comparing
`index_manifests.acl_epoch` against `files.acl_revision`: any manifest whose epoch is behind is
re-queued.

**A suppression is lifted by `clears_at` alone, and by nothing else.** The temptation is to lift it
when the index has caught up, and until `04-DATA-MODEL.md §15`'s `suppression_seq` / `indexed_seq`
pair existed, nothing could even express that. Now that something can, the rule still holds and is
now a deliberate refusal rather than a limitation: making a lift conditional on a worker reporting
back would make S4 (`12-TESTING.md §4.3` — a stopped invalidation worker changes nothing a caller
can observe) pass because the worker ran, rather than because the denylist write sits inside the ACL
transaction. The catch-up columns are an operator's signal and a rebuild's input. The query path
reads neither, and there is deliberately no per-file "is this file's index current?" accessor, for
the reason `crates/worker/src/lib.rs` gives: that predicate is the one a search eventually calls to
skip work.

### 6.4.1 A store that is up and *wrong*

Everything above assumes an index that is stale. The failure it does not cover is an index that is
**absent** — a collection dropped and recreated empty, a restore that missed a volume, a rebuild
that stopped halfway, a tenant nothing ever indexed. Reachability cannot see it: the server answers,
the collection exists, the circuit stays closed. Search returns two hits out of forty thousand
documents and reports `degraded: false`. That is worse than an outage, because an outage is visible.

So coverage is a third degradation trigger, alongside unreachability and denylist overflow:

1. A background probe, per tenant, sums `chunk_count` over that tenant's `READY` manifests — what
   PostgreSQL says the store holds — and asks the store for its own count of that tenant's chunks.
2. Below a configured share of the expectation (default 50%), the tenant degrades to lexical search
   with `degraded: true`, exactly as the other two triggers do.
3. **A background probe, never a per-request measurement.** A trigger sampled inside a request makes
   the same query answer completely at 10:00:01 and degraded at 10:00:02 with no state change, which
   is why latency is not a trigger either.

Two limits, stated rather than discovered:

- **It detects absence, not wrongness.** The right number of wrong chunks reads as healthy. Nothing
  about content, embeddings or `acl_tokens` is inspected — the post-filter is what makes a wrong
  candidate harmless, and what it cannot do is notice a candidate that was never offered.
- **It is blind where `chunk_count` is not recorded.** That column defaults to `0`, so a pipeline
  that never populates it produces tenants that expect nothing and can never be found depleted. That
  reading is reported as *unknown* rather than folded into "healthy", exported as
  `enclave_search_index_coverage_unknown`, and alerted on — because the difference between a quiet
  signal and a blind one is invisible otherwise.

### 6.5 Why not rely on `acl_tokens` alone

Per-principal tokens in the index are attractive because they push filtering down to Milvus. They are
kept — but only as an optimization — because on their own they have three defects:

1. they are stale by construction between an ACL write and an index write;
2. group membership changes multiply into token changes across every file the group can reach, so
   "just reindex" is unbounded work at exactly the moment correctness matters;
3. a token set large enough to express real enterprise ACLs (nested groups, deny entries) does not
   fit a simple `subset_of` filter — deny semantics in particular cannot be expressed as token
   overlap.

Layers 1, 2 and 4 hold the guarantee. Layer 3 makes it fast.

### 6.6 Summary of guarantees

| Failure | Result |
|---|---|
| Index metadata stale | Post-filter drops the hit; user sees nothing they shouldn't |
| Invalidation job backed up | Denylist blocks the file at query time |
| Milvus returns unauthorized candidates | Post-filter drops them; drop-ratio metric fires |
| Redis denylist unavailable | PostgreSQL fallback; then fail closed for vector search |
| Milvus entirely down | Lexical search over PostgreSQL — file names, scalar metadata and `chunk_text` — post-filtered as usual; `degraded: true` |
| Milvus up but the tenant's chunks are missing | Coverage probe finds the store below its floor; lexical search, `degraded: true` (`§6.4.1`) |
| Milvus up, chunks present, contents wrong | **Not detected by coverage.** The post-filter keeps it correct; the drop-ratio metric is what shows it |
| `chunk_count` never recorded by the indexer | Coverage is *unknown* for that tenant and says so; the depletion trigger cannot fire and an alert names that |
| Vector cache incomplete | Repair falls back to re-embedding for the affected files |

## 7. Ranking

Hybrid fusion of dense and sparse/BM25 scores via reciprocal rank fusion, then reranking with:

- exact filename and title matches boosted;
- recency boost with a configurable half-life;
- authority signals (workspace membership, prior access by the caller, favorite status);
- chunk-type weighting (a `section` heading match outranks a `row_group` match for the same score);
- classification is **never** a ranking signal — it is a filter, so ranking cannot leak the existence
  of restricted content through result ordering.

## 8. RAG-safe answering

`POST /search/answer` composes an answer from retrieved chunks. Rules:

- retrieval runs the full pipeline in `§5`, including the post-filter — the LLM only ever sees
  chunks the caller may read;
- every answer cites its source chunks with file, version and location; an answer with no citations
  is not returned;
- the classification of the answer is the maximum classification of its sources, and the answer
  inherits the strictest applicable obligations (watermark, no-download);
- prompts and completions are audited by reference (chunk IDs), not by content;
- the answering model is chosen by the same classification routing as embeddings — `RESTRICTED`
  content is answered by a local model or not at all.

## 9. Rebuild and disaster recovery

The index is rebuildable from authoritative state. Three tiers, fastest first:

| Tier | Source | Speed | When |
|---|---|---|---|
| **Metadata repair** | PostgreSQL scalars + Milvus vectors | Minutes | Drift detected by the epoch reconciler |
| **Vector-cache rebuild** | Vector cache in object storage + PostgreSQL | Hours | Milvus data loss, collection recreation, schema migration |
| **Full reindex** | Original files in object storage | Hours to days; costs embedding spend | Model change, extractor change, cache loss |

Rebuild is incremental, resumable and rate-limited so it cannot starve live traffic:

```text
1. Create the new collection with the target schema and an alias pointing at the old one.
2. Enumerate index_manifests ordered by (tenant_id, modified_at DESC) — recent content first.
3. Process in batches with a concurrency cap and a token/spend budget.
4. Track progress in index_manifests.status; failures retry with backoff, then park as FAILED.
5. Flip the alias when coverage passes the configured threshold (default 99% of READY manifests).
6. Drop the old collection after a soak period.
```

During rebuild, search continues against the old collection. Files whose manifests are not yet
`READY` remain findable lexically. Operator runbook: `11-OPERATIONS.md §5`.

## 10. Observability

Per-tenant metrics: index lag (`file.version.created` → `READY`), manifest status distribution,
embedding spend, query latency by mode, post-filter drop ratio, denylist size, epoch-drift count,
degraded-query rate, rebuild progress, and index coverage — expected chunks, observed chunks, the
floor they are compared against, and whether the reading could be established at all (`§6.4.1`).

Alert thresholds worth naming: post-filter drop ratio > 20% sustained, denylist size > 1 000,
epoch-drift count > 0 for more than 15 minutes, index lag P95 > 10 minutes, observed chunks below
the coverage floor for more than 10 minutes, and coverage *unknown* for more than two hours — the
last one because a signal that cannot see is indistinguishable from a signal that sees nothing
wrong. Rules: `deploy/monitoring/alerts/search.yml`.

## 11. Multi-tenancy and residency

Milvus partition key is `tenant_id`. High-security tenants may be pinned to a dedicated collection,
database or cluster (`08-BYO-INFRA.md §10`). Residency policy applies to the index exactly as it does
to primary storage: a tenant restricted to a region must not have its chunks — or the embeddings
derived from them — leave it.
