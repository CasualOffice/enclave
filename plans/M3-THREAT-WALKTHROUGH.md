# M3 — a threat walkthrough of the search path

> **Status:** Draft · **Version:** 1.0 · **Owner:** Search Engineering · **Last updated:** 2026-08-21

`plans/M3-DISCOVERY.md §6` requires this specifically, and says why: search is *"the one milestone
where tests alone are not the bar."* The reason is in `§2` of that plan — every other read path
answers one question about one resource the caller named. Search answers a question the caller did
not phrase, about resources they did not name, by consulting a second store that holds a copy of the
content and its own idea of who may see it.

This document walks the path an attacker's input actually takes, states what stops them at each
step, and — the part that matters — names what is **not** stopped.

It is written against the code, not the design. Where a control is weaker than the design implies,
that is recorded here rather than smoothed over.

---

## 1. What the caller controls

A search request carries: query text, optional filters (library, type, date), pagination, and a
bearer token. Of these, the **token is the only thing that decides identity**, and the tenant comes
from the verified token or from custom-domain routing — never a body field, query parameter or
header (`CLAUDE.md` rule 3).

Everything else is attacker-controlled and must be treated as such. Notably the query text reaches
three different parsers: a tokenizer for lexical search, an embedding model, and — as a *filter
expression* — the vector index.

---

## 2. Step by step

### 2.1 The request reaches `PolicyEngine::enforce` before it reaches anything else

No search-specific reasoning happens first. The chain's order is fixed (`CLAUDE.md` rule 2) and
`xtask policy-routing` fails the build if a handler is registered that cannot reach `enforce`.

**Residual:** the search handler itself does not exist yet — the API surface for search is not
wired. The gate that would catch a bypass is live and has been verified by deliberate violation
(#44), so the failure mode here is "not yet built", not "built unsafely".

### 2.2 The query text becomes a filter expression — and is never concatenated into one

`crates/search/src/milvus.rs` binds every value as a **template parameter**. Nothing is `format!`-ed
into the expression.

This is the injection surface. A filter built by string concatenation from a caller-supplied library
id would let a crafted value close the clause and append its own — the vector-store equivalent of
SQL injection, against a store where the tenant partition is expressed *in the filter*. Bound
parameters make the expression's shape fixed and its values inert.

**Verified:** `every_filter_constrains_the_partition_key` asserts the emitted expression is exactly
`tenant_id == {tenant}` with the value in the bindings, not the text.

### 2.3 The pre-filter narrows, and is allowed to be wrong

Three clause shapes only: `tenant_id`, `library_id in (…)`, `classification_rank <= …`. It emits
**no `acl_tokens` and no `barrier_tokens`**, asserted over the expression *and* the bindings across
every `Prefilter` shape.

The tenant clause is there so Milvus can route to one partition. **It is not the isolation control.**
Delete it and the post-filter still drops the foreign candidates; what is lost is performance, not
safety. Stating that plainly matters, because a reader who believes the prefilter isolates tenants
will eventually "optimise" the post-filter away.

Wrong permissively costs nothing — the post-filter drops what was wrongly offered (S5). Wrong
restrictively costs recall only.

### 2.4 The denylist drops revoked files before anything is resolved

Revocation writes `retrieval_denylist` in the **same transaction** as the ACL change (D22). Every
search consults it.

This is what makes S3 and S4 both hold. The design everybody reaches for first — enqueue a job, let
a worker remove the document from the index — cannot satisfy both: a stopped worker leaves a revoked
file findable *and the search still answers*, which is not an outage but a wrong answer delivered
confidently.

**Known weakness in our own tests, recorded rather than hidden:** S3 and S4 originally stayed green
with the denylist removed, because a revocation also deletes the ACL and the post-filter refuses the
file anyway. A test isolating the denylist was added
(`the_denylist_suppresses_what_the_acl_alone_would_still_admit`), and `docs/12` now records which
mechanism each row proves.

### 2.5 The post-filter is the guarantee

Every surviving candidate is resolved against PostgreSQL. Both disclosure levels —
`MetadataRead` and `ContentRead` — come from a single `authorize_many_actions` (D20).

Three properties are load-bearing:

1. **It is unconditional.** There is no parameter that disables it and no path around it. The
   tempting optimisation is to skip it when some other signal looks confident — the index was rebuilt
   recently, the `acl_epoch` matches, a cache is warm. Each of those is a claim *about* the thing
   being checked, made by the thing being checked, and a post-filter skipped when a signal looks
   confident is absent exactly when that signal is wrong.
2. **A missing verdict is a denial.** The result is a grid index-aligned with the actions. A short
   outer vector leaves an action unanswered; a short inner one leaves a candidate unanswered. Both
   drop the candidate. Code that indexed into the grid directly would turn a truncated response into
   a disclosure.
3. **An absent excerpt is indistinguishable from a withheld one.** A caller who may know a document
   exists but not read it gets `excerpt: None` — the same value a document with no excerpt yields.
   Distinguishing them would say *there is content here you may not see*, which is a fact about a
   document they cannot read.

   This became a live property rather than a cheap one at `ENC-529`, when the degraded path started
   producing excerpts: before that, `None` for everything honoured it by accident. `S6` now asserts
   it against a running degraded query, with a third file that *does* receive its quotation so the
   assertion cannot pass against a generator that returns nothing. The distinction is required to
   exist exactly once, in the operator-facing `excerpt_withheld` counter.

   It holds in `Debug` too (`S11`). `Candidate` and `Confirmed` hand-write theirs and print
   `Some(<content withheld>)`, because an excerpt is file content (`CLAUDE.md` rule 10) and because a
   `Debug` that distinguishes withheld from absent reintroduces at the log line what the response
   refuses to say.

### 2.6 Degraded mode is a worse recall guarantee, never a worse authorization one

Lexical retrieval over PostgreSQL still goes through `PostFilter::confirm`. `SearchResults.degraded`
is unconstructible except through `confirm` (never degraded) or `confirm_degraded` (always), and
`LexicalCandidates` is opaque — so the only thing that can be done with lexical output is hand it to
the function that post-filters **and** marks it.

Degraded mode is deliberately **not** latency-triggered (ENC-514): a per-request trigger engages
under load, which is when the vector path is most valuable, and makes the same query answer
completely at 10:00:01 and degraded at 10:00:02 with no state change.

### 2.7 The index is only ever fed content antivirus has cleared

The indexing pass reads versions through `readable_version`, the same query the preview path uses
(`status = 'AVAILABLE' AND av_status = 'CLEAN'`). A version that is not readable is **deferred**,
not failed.

This is the quietest failure on the whole path, which is why it has its own leakage row (**G7**). An
indexer that read a `SCANNING` version would put an unscanned upload's contents into the search
index — and every later permission check on the *file* would pass legitimately, because the caller
genuinely may read that file. What leaks is content the scanner had not cleared, disclosed as an
excerpt, with no error anywhere. G7 asserts on the **store**, not the manifest, because an
implementation that fetched the bytes and then declined to record them would pass a manifest-only
check having already read the upload into worker memory.

### 2.8 `RESTRICTED` text cannot reach a remote embedding provider

S8, and it is enforced by the compiler rather than by a test (ENC-508). `ClassifiedText` exposes no
method returning its chunks; only `TextBatch::<Local>::admit` and `TextBatch::<Remote>::admit` can
read it, and the routing lives in the type carrying the text. Writing the 3am fallback fails to
compile rather than failing a test.

### 2.9 Errors and telemetry do not carry what the query touched

A Milvus error's `Display` can echo the filter expression, which holds tenant and library ids. The
error type therefore carries a **fixed vocabulary** — `VectorIndex { operation: &'static str }` —
and the provider's message is dropped.

The Prometheus exposition carries `tenant_id` labels, so it is served on a **separate socket**, off
by default and loopback-bound; `xtask policy-routing` refuses a `/metrics` registration on the API
router and explains why an allowlist entry is the wrong answer.

---

## 3. What is not stopped

Named here because a threat walkthrough that lists only successes is a marketing document.

| # | Residual risk | Why it is acceptable *today*, and what closes it |
|---|---|---|
| R1 | **Coverage detects absence, not wrongness.** The index-health check compares the store's chunk count against `READY` manifests. An index holding the *right number of wrong chunks* — stale ACL tokens, content from a superseded version — reads as healthy | The post-filter is what makes this harmless: wrong chunks are dropped on resolution. The health signal is a recall and cost signal, not a safety one, and `crates/search/src/health.rs` says so in its own documentation rather than leaving it to be assumed |
| R2 | **Nothing writes `indexed_seq`.** The schema can express "the index has caught up"; no producer sets it, so every row reads *unasserted* | Correct by construction — the tri-state exists so that "unknown" is representable rather than being read as "no". Nothing depends on the column. `ENC-528` |
| R3 | **A scanned PDF is not searchable by its content.** The two stages now exist — OCR (`ENC-535`) and PDF page rasterisation (`ENC-537`) — and nothing joins them to a document: `NoExtractor` answers for `application/pdf`, so extraction returns `Unsupported`, `OcrRetry` passes that through untouched, and no work list of textless pages is ever produced. No worker constructs an `OcrRetry` either | Still an **unmet M3 exit criterion**, not an accepted risk, and recorded as such in `§4` below. What remains is named rather than open-ended: a PDF text extractor that reports which pages yielded nothing, and the wiring in the indexing worker |
| R10 | **PDFium runs in the indexing process.** `ENC-537` mounts a C++ PDF engine and calls it on `spawn_blocking`. It is the first memory-unsafe parser in this workspace's graph, so unlike `image`, `ocrs` and `rten` its worst case is not a wrong answer but corruption of the whole worker. `pdfium-render`'s `thread_safe` mutex serialises every call in the process, so a page engineered to take an hour blocks *every* document's rasterisation for that hour, and the wall clock around it releases the caller without releasing the mutex | Bounded, not isolated, and `crates/indexing/src/pdf.rs` says so in those words rather than implying otherwise. What is available today is applied: deny-by-default (a deployment that mounts no library gets `NoPageImages` and no rasteriser exists), a build with `pdf_enable_v8 = false` and `pdf_enable_xfa = false` so there is no JavaScript engine or XML forms parser behind the page tree, the input/page/output caps, and an edge clamp that makes the pixel amplification finite. **D17's out-of-process worker is what closes this**, and it is the same blocker `crates/preview/src/raster.rs` names for `PdfSanitized` — which this change does not touch: the preview path still refuses PDFs |
| R4 | **The quotation rule mirrors PostgreSQL's tokenizer rather than calling it.** `crates/search/src/excerpt.rs` locates the matched span by restating the indexed rule — a term is the lowercase of a maximal alphanumeric run — because both `ts_headline` forms are wrong (`docs/07 §6.2.1`). `char::is_alphanumeric` is Unicode's answer where `[[:alnum:]]` is the collation's, and the default parser may subdivide a run this module keeps whole | `ENC-529`. Acceptable because the disagreement fails to `None` — the caller gets the hit with no quotation, which is already indistinguishable from an excerpt withheld for want of `ContentRead`, so it costs recall of *context* and can never become a disclosure. It cannot quote an unmatched span either: the chunk was selected by `@@`, and the window must contain a run equal to one of the query's. What would close it is a Postgres-side locator that returns offsets rather than marked-up text, which `ts_headline` does not offer |
| R8 | **No excerpt is highlighted.** `docs/05 §11` shows the matched term wrapped in `<em>`; retrieval returns plain text | Deliberate. Emitting markup means interpolating untrusted document content into a markup string in the crate furthest from any renderer, which is `docs/12 §4.2` A9's defect on a new path. Closed by carrying the matched offsets alongside the text so the API layer marks up without parsing content — `ENC-529`'s follow-up |
| R9 | **An excerpt is a fragment, so bidi state balanced in the whole document can be unbalanced in the quotation.** An unterminated U+202E in a result list reverses the rendering of surrounding UI text | Not fixed here, and named rather than half-fixed: stripping the character would make the excerpt no longer verbatim, and refusing to quote chunks containing explicit bidi marks would cost excerpts across every right-to-left tenant. The remedy is at render — isolating each excerpt (`unicode-bidi: isolate`, or FSI…PDI) — which is where the same problem is already solved for filenames |
| R5 | **Degraded ordering is undecided** (Q15). Ranking badly may be worse than not ranking | Open question, owned by Product. Not a safety property: order does not change which documents a caller may see |
| R6 | **The vector index has never run against a Milvus under load**, only against a single-node standalone in CI | A performance and correctness-at-scale gap, not a disclosure one. The post-filter's cost is measured (7.0 ms for 200 candidates); the index's is not |
| R7 | **No search API endpoint exists yet**, so none of this has been exercised through the policy chain end to end | The chain is enforced structurally by `xtask policy-routing`, which fails the build on a handler that cannot reach `enforce`. Verified by deliberate violation, so the guarantee does not depend on the endpoint existing |

---

## 4. Exit criteria, honestly

From `plans/M3-DISCOVERY.md`:

| Criterion | State |
|---|---|
| **S3** — a revoked file vanishes immediately, before any index update | **Met.** Verified by deliberate violation, including a test that isolates the denylist from the ACL |
| **S4** — S3 holds with the invalidation worker stopped | **Met.** The denylist write is in the ACL transaction, so a stopped worker costs index size, never correctness |
| **S5** — over-permissive index candidates are dropped | **Met.** Now against a real Milvus holding deliberately wrong `acl_tokens`; stubbing the post-filter fails it by name |
| **S8** — `RESTRICTED` text never reaches a non-local provider | **Met**, and enforced by the compiler rather than a test |
| Drop ratio and denylist size exported, alerts wired | **Met.** Including the listener that serves them — the metrics existed for a while with nothing scraping them, which is a metric that reads as zero forever |
| A scanned, text-free PDF is searchable by its content | **NOT MET**, and closer than it was. The two stages exist and are each proved against real dependencies: OCR reads a page image (`ENC-535`), and a PDF page becomes one (`ENC-537` — `crates/indexing/tests/pdf.rs` renders a hand-built scan and recognises `INVOICE 2026 TOTAL` out of it, end to end through `OcrRetry`). **What is missing is the join.** Nothing extracts `application/pdf` at all, so a scanned PDF is `SKIPPED` / `unsupported_media_type` and the OCR stage — which only ever runs on `NoText` — is never reached. Nothing wires `OcrRetry` into the indexing worker either. Both are `R3` above |

**M3 is therefore not complete.** The gap is one criterion, and it is now a gap in *wiring* rather than
in capability: every part it needs has been built and watched to work, and no part of it is joined to a
document that arrives through the pipeline. The
definition of done also requires every M3 P1 to be `DONE`; `ENC-527` is `REVIEW` pending CI, and the
remaining P1s are tracked.

The honest summary: **the authorization properties of the search path are met and were each verified
by breaking them on purpose. The retrieval-completeness properties are not** — OCR is absent, and
the index-health signal can see absence but not wrongness.

Those are different kinds of gap, and conflating them is how a milestone gets called done. A search
that cannot find a scanned contract is visibly incomplete; a search that returns a document the
caller may not read is not visible at all. This milestone closed the second kind first, deliberately
(`ENC-506`: the guarantee before the thing it guards).
