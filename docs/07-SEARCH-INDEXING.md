# 07 — Search & Indexing

> **Status:** Draft · **Version:** 1.3 · **Owner:** Search Engineering · **Last updated:** 2026-08-21
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
| PDF | `pdfium`/`pdf-extract` | Per-page text with coordinates; OCR fallback when a page yields no text |
| DOCX/PPTX/XLSX | OOXML parser | Headings, slide titles, sheet and range coordinates |
| TXT/Markdown/HTML | Native | HTML sanitized before extraction |
| CSV/JSON | Structured reader | Row groups and key paths as chunk boundaries |

Extraction runs sandboxed: no network egress, bounded CPU/memory/wall-clock, hard page and cell
limits. Extractor failures mark the manifest `FAILED` with a reason; the file stays fully usable and
lexically searchable by name and metadata.

### 2.2 Chunking

Structure-aware, not fixed-size-only. Target 400–800 tokens with ~15% overlap, never crossing a
table row group, slide or sheet-range boundary. Each chunk keeps its source coordinates
(`page_number`, `sheet_name`, `section_path`) so results can deep-link and so RAG answers can cite a
location a person can actually navigate to.

Chunk types: `document`, `section`, `paragraph`, `table`, `row_group`, `sheet_range`, `slide`,
`code_block`, `list`.

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
