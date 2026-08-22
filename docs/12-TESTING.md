# 12 — Testing & Quality Gates

> **Status:** Draft · **Version:** 1.13 · **Owner:** Engineering · **Last updated:** 2026-08-22
> **Authoritative for:** test strategy, the security leakage matrix, CI gates, release criteria.

## 1. Philosophy

Two rules shape everything below.

**Security tests are permanent.** Every leak class in `§4` has a test that runs on every commit,
forever. They are not a one-time audit; they are the executable form of the acceptance criteria in
`01-PRD.md §38`.

**Test the policy chain, not the endpoint.** A test that a download endpoint honors an ACL proves
little if preview, search, sync, MCP and the editor each re-implement the check. The chain is
implemented once (`03-LLD.md §12`), and the matrix in `§4` asserts that every surface routes through
it.

### 1.1 Test our integration, not somebody else's correctness

Whether ClamAV detects EICAR, whether an OCR model reads a page accurately, whether PDFium renders
a glyph correctly and whether Milvus ranks well are **their** problems, settled by their own test
suites. Ours is the wiring: that an `INFECTED` verdict quarantines the version and no read path
serves it, that a page yielding no text becomes a `FAILED` manifest rather than an empty `READY`,
that a candidate the index offers is dropped when the caller may not read it.

This matters for what gets built as well as what gets asserted. A test that measures a vendor's
accuracy fails when they improve their model, on a line nobody here can act on — and it tempts the
kind of infrastructure (emulating an amd64 antivirus daemon on an arm64 laptop) that buys a slower
copy of a check CI already runs.

The line is drawn at the boundary: **assert everything about what we hand them and what we do with
what they return.** Bounds we impose, refusals we make, states we record, and what reaches a caller.

### 1.2 A test is not believed until it has been watched to fail

Write the test, then **break the thing it tests on purpose** and confirm it fails *by name*. Restore,
and confirm it passes. A test that has never failed is a claim, not a check.

This is not a counsel of perfection — it has caught roughly eight of this project's own tests being
vacuous, and each one had been read and reviewed first:

- a concurrency test passed 3/3 against a naive implementation, because the pool was capped at two
  connections and the race could not occur;
- `S3`/`S4` stayed green with the denylist deleted, because a revocation also removes the ACL and the
  post-filter refused the file anyway — so the tests proved a different mechanism than they named;
- a `D24` test passed with the empty-document guard removed, because the chunker drops whitespace
  segments and a *different* guard caught it — the comment claimed the wrong one was load-bearing;
- an image-bomb test passed twice for two different wrong reasons: first a bad CRC made the file
  unreadable, then the decoder's own allocation limit refused it before our check was reached.

**The recurring shape: an assertion about an absence passes for free.** `excerpt == None`,
"no cross-tenant row", "no `set_status` in this module", "these bytes were never read" — all of them
hold trivially against an implementation that does nothing at all. Two habits close it:

1. **Include a positive control.** Assert that the thing *does* appear in the case where it should.
   Without a third document that receives its excerpt, every assertion in an excerpt test passes
   against code that returns `None` for everything.
2. **Say which mechanism the test proves.** When a deliberate violation does *not* fail a test, that
   is a finding: the test is proving something other than what its name says. Record which control
   actually holds the property rather than deleting the test or quietly rewording it.

A source-scanning test — one that asserts some string does *not* appear in a file — deserves special
care, because the needle it searches for appears in its own source. Two such tests here failed
against themselves on first run. Assemble the needle at run time, exactly as `CLAUDE.md` rule 11
prescribes for PEM banners.

## 2. Test pyramid

| Layer | Scope | Runtime | Where |
|---|---|---|---|
| Unit | Pure functions, policy evaluation, chunking, parsing | < 30 s | Every crate |
| Property | ACL resolution, cursor encoding, conflict handling, chunk boundaries | < 2 min | `proptest` |
| Integration | Real PostgreSQL + Redis + MinIO + NATS via testcontainers | < 10 min | `tests/` |
| Contract | OpenAPI schema conformance, event schema compatibility | < 2 min | CI |
| Security | The leakage matrix (`§4`) | < 10 min | `tests/security/` |
| E2E | Browser flows against a seeded stack | < 20 min | Playwright |
| Load | Search, upload, browse at target concurrency | Nightly | k6 |
| Chaos | Dependency failure injection | Weekly | Staging |

## 3. Fixtures

A deterministic seeded tenant set that every integration and security test shares:

```text
tenant-alpha
  users:      owner, member, viewer, guest, auditor, admin
  groups:     engineering, finance, external-partners (nested: finance > finance-leads)
  workspaces: engineering (MEMBERS_ONLY), board (RESTRICTED)
  libraries:  specs (sync on), contracts (sync off, CONFIDENTIAL default)
  files:      public.md, internal.docx, confidential.pdf, restricted.xlsx,
              pii-sample.csv, secret-key.txt, infected.eicar, huge.bin
  barriers:   segment-a, segment-b (incompatible)
tenant-beta
  mirror structure with identical file names and colliding fixture IDs
```

`tenant-beta` exists solely so every cross-tenant assertion has a realistic counterpart with the same
names — a test that passes only because the other tenant's file was called something else proves
nothing.

## 4. Security leakage matrix

Each row is at minimum one permanent test. A surface is not "shipped" until its column is filled.

### 4.1 Cross-tenant isolation

| # | Assertion |
|---|---|
| T1 | A `tenant-beta` file ID requested by a `tenant-alpha` user returns `404`, never `403` |
| T2 | Search never returns a chunk whose `tenant_id` differs from the caller's |
| T3 | A cursor issued in one tenant is rejected in another |
| T4 | A signed URL issued for one tenant's object cannot be minted from another tenant's context |
| T5 | RLS blocks a cross-tenant read even when the application predicate is deliberately removed |
| T6 | An access token with a mismatched `tid` against the routed custom domain is rejected |

T5 is the important one: it is run with a deliberately broken query builder, and it must still pass.

### 4.2 Authorization

| # | Assertion |
|---|---|
| A1 | `preview=ALLOW, download=DENY` yields a rendition and **no** signed original URL. Both halves asserted in one test: the preview returns `200 image/png` carrying the pipeline's bytes, and the *store* reports zero `signed_download` calls — not generated and withheld, never asked for. The handler holds no `BlobStore` and its `PreviewPipeline` has no method that could mint a URL. `crates/api/tests/delivery.rs` (`ENC-148`) |
| A2 | Export, print and copy are each independently deniable |
| A3 | A `DENY` entry overrides an inherited `ALLOW` at every level |
| A4 | Breaking inheritance materializes the effective set with no privilege gain. `enclave_authorization::break_file_inheritance` and `break_library_inheritance` collapse the whole chain — the resource's own entries included — by deny-wins and write the result onto the resource in the same transaction as the flag flip. Both flags carry the escalation, so both are covered: `a4_breaking_inheritance_materialises_and_gains_no_privilege` asserts the file case and sweeps five probes across principal, action and node for an unchanged verdict, `a4_breaking_library_inheritance_gains_no_privilege` asserts the library case, and `a_settings_update_cannot_break_inheritance` proves a settings replacement cannot flip the flag without the copy (`ENC-141`) |
| A5 | Direct object-key access without a signed URL fails at the storage layer. Asserted against the provider, not against our own refusal to build such a URL: the object is uploaded, confirmed readable *with* a signature, and then fetched anonymously by its real key — so a `403` cannot be a missing object in disguise. The startup self-check does not cover this; its anonymous probe uses a key chosen so it cannot exist, which answers "is the bucket open?" and not "is this stored object reachable by whoever learns its key?". A second leg repoints a valid signed URL at a different key and requires the same refusal, so one authorized download is not a key to the bucket. `crates/storage/tests/minio.rs` (`ENC-153`) |
| A6 | A signed URL cannot be replayed after expiry, or after single use where supported. Expiry is asserted end to end against MinIO: a short-TTL URL is fetched successfully, then again after the TTL elapses, and the second fetch must be refused. **Single use is not covered and cannot be**: SigV4 pre-signed URLs have no server-side use counter, so no S3-compatible backend supports it. Rather than leave that implicit, the test pins the true behaviour — a second fetch *inside* the TTL succeeds — and requires the store to report `single_use_signed_urls` as `false`, so the short TTL (`plans/M1-CONTENT-CORE.md` D14) stays visibly the only control on a captured URL and no caller can rely on a property the backend lacks. `crates/storage/tests/minio.rs` (`ENC-153`) |
| A7 | Version-level reads respect the current file ACL, not the ACL at version creation |
| A8 | A watermarked artifact is never written to the rendition cache, and two viewers of one page share a base object keyed by neither of them. Structural rather than asserted at the write site: `RenditionKey` has three fields — version, profile, generator — and no constructor accepting a principal, so there is no key a watermarked artifact could be stored under. `crates/preview/tests/watermark.rs` (`ENC-147`) |
| A11 | A listing row's `capabilities` are identical to what the single-file endpoint returns for the same file and caller. Not cosmetic: `CLAUDE.md` requires the UI to render actions from this object and never re-derive permissions client-side, so if the two can disagree the product changes its mind about what a user may do purely because they clicked into a file. Both are built by one function from one action table and the same resolved decision, and the test asserts field-by-field equality across a page whose rows deliberately differ. `crates/api/tests/content.rs` (`ENC-152`) |
| A10 | A `REFERENCE`, `USER`, `GROUP` or `TAXONOMY` metadata value cannot resolve to another tenant's resource, and an unresolvable one is indistinguishable from a cross-tenant one. Otherwise a metadata field is an oracle for what exists elsewhere: set the value, see whether it is accepted. Shape is checked without a database and existence only inside a tenant-scoped transaction, so the two cases collapse by construction. `crates/metadata/tests/storage.rs` (`ENC-151`) |
| A9 | No field interpolated into a watermark can become markup. The layer is SVG carrying a display name and an email — fields the viewer sets on their own profile — so an unescaped `<script>` is stored XSS delivered on the preview path to every viewer of the document. Every interpolated field is attacked, and the payload must survive *escaped* rather than be dropped: silently discarding a hostile name would let an attacker blank their own watermark by choosing one. `crates/preview/tests/watermark.rs` (`ENC-147`) |
| A12 | A watermark obligation is discharged in the *bytes*, not delegated to the client. An overlay a client is asked to draw is one a client can decline to draw, and the obligation exists because the page must identify whoever is looking at it — so for raster renditions the mark is composited into the pixels before the response leaves. Two viewers of one page receive different bytes; a name the bundled face cannot draw is omitted rather than rendered as boxes, and if the *email* cannot be drawn the mark names nobody and the preview is refused. An artefact too small to carry a legible mark is refused rather than returned untouched — found by a test whose output came back byte-identical to its input. `crates/preview/tests/composite.rs`, `crates/api/tests/delivery.rs` (`ENC-169`) |

### 4.3 Search and AI

| # | Assertion |
|---|---|
| S1 | Keyword search returns nothing from an inaccessible library |
| S2 | Semantic search returns nothing from an inaccessible library |
| S3 | **After a permission revocation, the revoked file disappears from search results immediately**, before any index update completes. The candidate generator is unchanged across the revocation — it still proposes the file, as a real index would until a worker catches up — and the post-filter drops it. `crates/search/tests/postfilter.rs` (`ENC-506`) |
| S4 | With the invalidation worker deliberately stopped, S3 still holds. There is no worker in the test at all, which is the assertion. Note what it does **not** isolate: because a revocation removes the ACL *and* writes the denylist, the post-filter alone is sufficient here — removing the denylist consultation leaves S3 and S4 green, which was checked. The denylist is necessary for staleness an ACL does not capture, and `the_denylist_suppresses_what_the_acl_alone_would_still_admit` is the row that isolates it. `crates/search/tests/postfilter.rs` (`ENC-506`) |
| S5 | With the candidate generator returning deliberately over-permissive candidates, the post-filter drops them. Asserted against a **fake** generator rather than Milvus, and that is the stronger test: a fake can propose another tenant's file, a file that does not exist and a file never granted — things a real index would only offer by accident. The permitted file sits in the middle of the set, so a post-filter that refused everything fails too. `crates/search/tests/postfilter.rs` (`ENC-506`). Asserted a second time against the **real** generator that matches document text, because chunk text is content rather than a filename and a new candidate source is where an exception gets carved: three files whose bodies all contain the query word, one of them in `tenant-beta`, one ungranted — exactly one survives, and the beta file never becomes a candidate. `crates/search/tests/lexical_content.rs` (`ENC-515`) |
| S6 | A `MetadataRead`-only user receives titles but never excerpts, **and cannot tell that from a document that had none**. The second clause is the one worth testing: `Confirmed::excerpt` is `Option<String>` and `None` deliberately carries both meanings, because distinguishing them would say *there is content here you may not see* — a fact about a document the caller may not read. Asserted on the degraded path, where the excerpt is now cut from real chunk text (`ENC-529`): three files, all hits for one caller. The first matched on its **body** and the caller holds `MetadataRead` alone — there is a quotation and they do not get it. The second matched on its **name**, so there is no matched passage to quote even though the caller holds both actions. The third matched on its body with both actions granted. The third is load-bearing — without it every assertion passes against the pre-`ENC-529` code, which returned `None` for everything. The two `None`s are asserted equal, and the distinction between them is required to appear exactly once, in the operator-facing `excerpt_withheld` counter. `crates/search/tests/lexical_content.rs` (`ENC-529`). Asserted a second time on the **dense** path against live Milvus, because `ENC-538` made that path produce excerpts that are *new objects* — cut from the chunk by `excerpt::preview` rather than passed through — so the assertion is run against candidates a real index produced rather than inferred from the lexical case. Same shape, with the dense analogue of a name-only match: a chunk indexed with an **empty** `text`, which `milvus::decode` documents as legitimate because a metadata-only update writes scalars and vectors and leaves the body alone. The generator's half is asserted first — the candidate must *carry* an excerpt — so "withheld" cannot be satisfied by "never produced". `crates/search/tests/milvus.rs` (`ENC-541`) |
| S7 | RAG answers cite only chunks the caller may read; an uncitable answer is not returned |
| S8 | `RESTRICTED` text never reaches a non-local embedding provider. Structural, not checked: `ClassifiedText` has no method returning its chunks, so the only way to obtain a `TextBatch<Remote>` is through an admission that refuses at and above the ceiling — holding one *is* the proof. Verified by writing the fallback a tired engineer would write, which fails to **compile**. The remote double panics rather than erroring, so "never reached" cannot be confused with "reached and recovered". `crates/embeddings/tests/routing.rs` (`ENC-508`). **The input is now covered too** (`ENC-557`): the guarantee is only as good as the rank attached at `ClassifiedText::new`, so the indexing worker resolves it through `FileClassification` and the shipped implementation *refuses* rather than defaulting — a fabricated `PUBLIC` would send every document off-network while the ceiling comparison worked perfectly. Watched to fail exactly that way: making `UnclassifiedFiles` answer `0` trips the panicking remote double in `a_deployment_that_cannot_classify_a_file_refuses_rather_than_guessing_a_rank`. `crates/worker/tests/indexing.rs` |
| S9 | A `NO_INDEX` classification produces no chunks in the vector store at all |
| S10 | Barrier-segmented content is excluded at query time, not merely at result time |
| S11 | **No search type prints an excerpt through `Debug`.** `CLAUDE.md` rule 10: an excerpt is file content, and it may be returned to an authorized caller but must never reach a log line. The realistic failure is not somebody logging a snippet deliberately — it is `tracing::debug!(?candidates)` added during an incident, reaching `Candidate` and `Confirmed` through the derived `Debug` on the envelopes that hold them (`LexicalCandidates`, `SearchResults`), and writing document bodies into an aggregator whose audience is far broader than the documents it quotes. Both types therefore hand-write `Debug` and render the field as `Some(<content withheld>)`. A third assertion requires an *absent* excerpt to still render as `None`: a `Debug` that distinguishes withheld from absent reintroduces at the log line exactly the distinction `S6` refuses to make in the response. `crates/search/src/postfilter.rs` (`ENC-529`). Extended by `ENC-542` to the **highlighting offsets**, which are derived from the content — a span says a matched term of this length occurs at this position, and how many there are says how often the query's words occur in the passage — so printing them beside a redacted body hands back part of what the redaction removed. Two independent defences, both asserted: `Excerpt` and `Highlights` hand-write their own `Debug`, and `postfilter`'s field-level redaction does not consult them. The **variant** is still printed, because which retrieval path answered is a fact about the search and not about the document. `crates/search/src/excerpt.rs`, `crates/search/src/postfilter.rs` (`ENC-542`) |

S3 and S4 are the tests that make acceptance criterion #3 real. They are the highest-value tests in
the suite.

### 4.4 Sharing and guests

| # | Assertion |
|---|---|
| H1 | A share token is unguessable and stored only as a hash. 256 bits of OS entropy; the row holds SHA-256 and the assertion dumps *every* column looking for the plaintext, because a token that leaked into a label would be just as usable. `crates/sharing/tests/redemption.rs` (`ENC-149`) |
| H2 | Password and OTP requirements are enforced server-side, not just prompted |
| H3 | `max_downloads` holds under 50 concurrent redemptions (exactly N succeed). Two tests, deliberately: the fifty-task one is realistic, and on its own it **passed against a naive implementation** — the harness pool caps at two connections, so it ran two at a time. The second holds the read-to-write window open on a barrier until every contender is inside it, and fails 3/3 without the limit in the `WHERE` clause. `crates/sharing/tests/redemption.rs` (`ENC-150`) |
| H4 | An expired or revoked link fails closed. The link is made *usable first* and revoked afterwards, because a link that was never usable proves nothing about revocation; liveness is re-checked inside the spending `UPDATE`, so a revocation lands on a redemption already in flight. The *already-open session* clause needs the preview path and stays open until `ENC-148`. `crates/sharing/tests/redemption.rs` (`ENC-149`) |
| H5 | A guest cannot enumerate siblings, parents or other resources from a share context |
| H6 | Domain-restricted links reject non-matching authenticated domains |

### 4.5 DLP, classification, retention

| # | Assertion |
|---|---|
| D1 | `ENFORCE` blocks a sensitive external share synchronously. Driven through the real `PolicyEngine` with every other stage allowing, so a refusal can only have come from DLP. Asserted in the *same test* as D2, deliberately — see that row. `crates/dlp/tests/modes.rs` (`ENC-582`). **Extended to a running deployment by `ENC-594`**: the same refusal, taken against a row read out of `security_facts` through the `TenantScoped` wrapper rather than a snapshot the test handed the engine, with the identical request over the identical row asserted to be *permitted* by `DisabledDlp` — which is what `main.rs` installed before the wiring, so a test that would have passed against the old binary cannot pass here. `crates/dlp/tests/stored_facts.rs` |
| D2 | `SIMULATION` records the decision and takes no action. **Not a test on its own**, because "takes no action" is an assertion about an absence and holds for free against a simulation that never evaluates — `§1.2`'s exact shape. `d1_and_d2_one_policy_both_ways_records_the_same_decision` runs one policy over one set of facts in both modes and asserts three things: `ENFORCE` refuses (the positive control, and D1), `SIMULATION` does not, and the **recorded decision is identical** — the mode-independent verdict and the "what would `ENFORCE` have done" answer, which is D28. A fourth assertion requires the facts to have been read in both, so a simulation cannot be cheap by skipping the work it exists to measure. Two further tests widen it: the same equality across six policy outcomes including the clean one, and a mode-by-mode ladder over `DISABLED`/`MONITOR`/`SIMULATION`/`WARN`/`ENFORCE`, because the interesting failure is a mode doing one step more than its rung allows. The observation also carries **which mode produced it** — `MONITOR` and `SIMULATION` differ in nothing else, and `docs/06 §9`'s "the admin UI refuses to enable enforcement on a policy that has never been simulated" reads that field; stamping every record `MONITOR` failed no test until an assertion was added for it. `crates/dlp/tests/modes.rs` (`ENC-582`) |
| D3 | Missing security facts follow `facts_unavailable` — `FAIL_CLOSED` denies. Three legs, the last two being the controls: `FAIL_OPEN_AUDIT` over the *same* absent facts permits and leaves the high-visibility evidence that is the whole difference between the modes, and `FAIL_CLOSED` with *fresh* facts that fire nothing permits — so the refusal is the absence of facts rather than a mode that refuses everything. Beside it, D27's mandatory escalations are asserted through the chain: external sharing of unscanned content is refused under **either** configured mode, an unscanned `RESTRICTED` document is refused under `FAIL_OPEN_AUDIT` (`ENC-591` — the rank comes from the resource, not from the scan that has not run), and changing the terms of an already-external share is refused where creating one would have been (`ENC-588`). An action **no rule governs** is never refused for facts it did not need, which is the row that stops a `FAIL_CLOSED` tenant refusing everything while a scanning backlog drains. `crates/dlp/tests/modes.rs`, `crates/core/src/policy.rs` (`ENC-582`). **Extended by `ENC-594`** to the absence a deployment actually has — a version with no row at all, which is every version until a scanner writes one — with both policies observed through a *download* rule, because external sharing is forced closed whatever `facts_unavailable` says and cannot show `FAIL_OPEN_AUDIT` doing anything. Staleness is asserted the same way, over rows stamped with versions that sort both **below and above** the active set, since under any invented ordering exactly one of the two would read as fresh. `crates/dlp/tests/stored_facts.rs` |
| D4 | An unhandled obligation (watermark, justification) fails the operation rather than proceeding. Two halves. On the delivery path, a `NO_DOWNLOAD` obligation refuses before any signed URL is generated and a `WATERMARK` one cannot be satisfied by original bytes — `crates/api/tests/delivery.rs`, `crates/api/src/download.rs` (`ENC-148`). On every *other* surface, `Obligations::require_none` is what a path with nothing to satisfy an obligation with calls, and it refuses with the code that tells the caller what to do next. Three handlers — `me`, container browse and version history — asserted this with `debug_assert!`, which is compiled out of a release build: the shipping binary dropped the obligation and served the response. That is D29's third outcome, and `ENC-544` was the same defect in the audit crate's field-count guard. `crates/dlp/tests/modes.rs`, `crates/core/src/policy.rs` (`ENC-582`) |
| D5 | Legal hold blocks deletion for owners, admins and the retention scheduler alike |
| D6 | A declared record rejects modification and deletion until `immutable_until` |
| D7 | Classification ceilings block MCP retrieval above the client's limit |
| D8 | Incident records contain detector types and counts, never matched values |

### 4.6 Authentication and tokens

| # | Assertion |
|---|---|
| K1 | An expired access token is rejected; clock skew tolerance is bounded (60 s) |
| K2 | A token signed by a retired key is rejected after the overlap window |
| K3 | Refresh rotation invalidates the presented token |
| K4 | Reuse of a consumed refresh token revokes the family and raises `SESSION_REPLAY` |
| K5 | `token_epoch` bump invalidates every outstanding access token for that user |
| K6 | A refresh from a now-blocked network zone is rejected |
| K7 | A sync/editor token without a matching `dev` claim is rejected |
| K8 | `alg: none`, algorithm confusion and unsigned tokens are rejected |
| K9 | Privileged scopes fail closed when the denylist store is unavailable |
| K10 | The refresh cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, path-scoped |

### 4.7 Sync and editing

| # | Assertion |
|---|---|
| Y1 | A no-download file never appears as `syncEligible`, and its bytes are refused |
| Y2 | Eligibility is re-checked at byte-fetch time, not only at delta time |
| Y3 | Revoked access produces a `TOMBSTONE` with a reason, not a silent omission |
| Y4 | A conflicting upload creates a conflicted copy; no content is discarded |
| Y5 | An editor session token grants access to exactly one file version and nothing else |
| Y6 | A client-side editor is refused for no-download content |
| Y7 | A revoked device's tokens stop working immediately |

### 4.8 Ingestion safety

| # | Assertion |
|---|---|
| G1 | An EICAR upload is quarantined and never becomes readable, previewable or searchable. `crates/antivirus/tests/eicar.rs` asserts the verdict and the incident against a real clamd, with a `Clean` control so an `Infected` verdict is evidence of detection rather than of a broken client. The *previewable* clause is now enforced rather than inferred: rendering is a read path, and `enclave_preview::ReadableVersion` cannot be constructed except from a row matching `status = 'AVAILABLE' AND av_status = 'CLEAN'`, so a quarantined version cannot be handed to a parser — `crates/preview/tests/cache.rs` (`ENC-146`) |
| G2 | A decompression bomb is rejected by depth/size caps. `RenderBudget` bounds input and output independently — an input cap alone does not catch a bomb, since being small going in is its whole design — and `enclave_preview::Bounded` enforces both from *outside* the renderer, so a renderer that ignores its budget still cannot exceed it. `crates/preview/tests/bounds.rs`, whose renderers are all deliberately badly behaved (`ENC-146`) |
| G3 | A malformed document fails extraction without crashing the worker or leaking a temp file. For raster sources this now holds and is asserted: truncated and corrupt inputs are `Refused(SourceUnreadable)` — in the *success* channel, never `Err` — and a decoder panic is mapped to the same verdict rather than reported as our failure, because the same bytes panic identically and calling it ours would invite a retry loop. A decode bomb is refused on its header before any pixel buffer exists; removing that check leaves the test grinding for minutes instead of refusing. `crates/preview/tests/raster.rs` (`ENC-146a`). Document formats still need D17's out-of-process worker, and `NoRenderer` answers for them until then |
| G4 | An SVG/HTML upload cannot execute script in a preview — **still blocked on the sanitizer**, which the raster renderer does not provide and does not pretend to: it decodes PNG/JPEG/WebP and re-encodes pixels, so an SVG is `Refused(UnsupportedFormat)` rather than rendered unsafely. `HtmlSanitized` remains `NoRenderer`'s. Distinct from A9, which covers markup injected through the *watermark's* fields |
| G5 | A file exceeding the library size limit is rejected before bytes are transferred |
| G6 | With the AV engine down and `HOLD` policy, the version stays in `SCANNING` and unreadable |
| G7 | **The indexer never reads a version antivirus has not cleared.** `crates/worker/tests/indexing.rs` asserts it on the *store*, not only on the manifest: a `SCANNING` or `INFECTED` version is deferred and its bytes are never fetched. Distinct from `G1`, which covers the read paths a user drives — this is the one path that reads content with no user present, and getting it wrong is quieter than anywhere else. An indexer that read an unscanned upload would put its contents in the search index, where every later permission check on the *file* passes legitimately and the content is disclosed as an excerpt, with nothing reporting an error. Enforced by reading versions through `enclave_preview::repo::readable_version` — the same query the preview path uses — rather than asking the question a second time |

| G8 | **A PDF page rendered for OCR cannot amplify into an unbounded allocation, and a page that will not render is a verdict rather than an absence.** A PDF declares its page size in *points* and the renderer chooses the pixels, so a sub-kilobyte file may ask for a 40000×40000 buffer — 6.4 GB — which no input cap can see. `crates/indexing/src/pdf.rs` clamps the longest edge before rendering and checks `width × height × 4` against `RenderBudget::max_output_bytes` with no buffer in existence, after sniffing `%PDF-` at offset zero and applying the input and page caps. `crates/indexing/tests/pdf.rs` proves each against the real PDFium, every refusal with a positive control beside it. The second half is `PageImage::Refused` versus `PageImage::Absent`: a rasteriser that reported a timeout as "no image for this page" would leave the page *skipped* and the rest of the document `READY`, which is D24's failure mode — a document that reads as correctly filed with part of its content silently missing (`ENC-537`). Distinct from `G2`, which bounds a renderer whose output size the *source* declares |
| G9 | **A PDF's *text* layer is bounded by the same budget as its pixels, and a page that yielded nothing is named rather than dropped.** `crates/indexing/src/pdf_text.rs` runs `sniff → input cap → page cap → output cap`, charging each page's segment (text plus `SEGMENT_OVERHEAD_BYTES`) against `RenderBudget::max_output_bytes` *before* it is pushed — a nine-hundred-page file of blank pages is a few kilobytes in and nine hundred structs out, which no input cap can see, and without the per-segment charge its accounted size is zero. Every page that yielded no text goes into `TextlessSource::pages_without_text`, and a document where *every* page did is `NoText` → `FAILED` / `no_text_extracted`, never `READY` over an empty index (D24). A document with **some** scanned pages is `Extracted`, which is argued at the module and leaves a named gap: those pages are not OCR'd, because `OcrRetry` fires only on `NoText`. `crates/indexing/tests/pdf.rs` proves each bound against the real PDFium with a positive control beside it, and runs the exit criterion end to end — `Pipeline::prepare` decides, and whatever it decided is what the retry is handed (`ENC-545`) |
| G10 | **Two PDFs cannot be parsed concurrently in one process.** `pdfium-render`'s `thread_safe` feature locks each FFI *call*, which still lets two threads interleave two documents; PDFium's globals are not re-entrant across that, and two threads reading text off two documents carrying fonts killed the test binary with `SIGTRAP`, `SIGABRT` or `SIGSEGV` in seven runs of eight. The rasteriser had the same hazard latently — image-only pages never touch the font machinery, so `ENC-537` never fired it, and four concurrent rasterisations of a font-carrying PDF crash 5/6 without the fix. `crates/indexing/src/pdf.rs`'s `DOCUMENTS` lock is held for the whole life of a document and both modules take it. Not a row with its own test: what asserts it is that `crates/indexing/tests/pdf.rs` runs in parallel at all, which it did not before (`ENC-545`) |

### 4.9 Workflows and signing

Full rows in `15-WORKFLOWS-AND-SIGNING.md §12`; they run in this suite.

| # | Assertion |
|---|---|
| W1 | A workflow cannot grant an actor access they do not independently hold |
| W2 | Self-approval is rejected unless explicitly enabled |
| W3 | A new version invalidates in-flight approvals by default |
| W5 | `AUTOMATION` steps cannot invoke anything outside the allowlist |
| N1 | The bytes presented to the signer hash to `sealed_sha256`; a mismatch aborts |
| N2 | A signing token is single-use, single-document and expires |
| N4 | Post-signature modification makes verification report `DOCUMENT_MODIFIED` |
| N5 | A private key is never transmitted to the server in `DIGITAL_SIGNER_CERT` mode |
| N6 | A `RESTRICTED` document is not sent to a non-permitted external provider |
| N7 | Verification succeeds offline from embedded LTV material |

### 4.10 Audit

| # | Assertion |
|---|---|
| U1 | **Every allow and every deny in the matrix produces an audit event, and the row can explain the denial.** Counting rows is not enough — `ENC-585`'s walkthrough found a request that returned `403 PREVIEW_ONLY` and left exactly one row saying `ALLOW`, which satisfies a count. So the assertion is on the row's *contents*: `outcome`, the `reason_code` the caller was given, and the stage in `policy_refs`, which is inside the hashed bytes. Driven through the real `PolicyEngine` into the real record format, in a loop over `Stage::ORDER`, so a stage added to the chain without an audit call fails by name — and adding one changes `PolicyEngine::new`'s arity, so the loop cannot silently skip it. `the_sink_is_actually_written_to` is the liveness half: every other assertion here is about a row's contents and would pass for free against a chain that wrote none. Verified by deleting `record_deny` from the chain (four tests fail, naming the stage) and by dropping `policy_refs.push(stage)` from the sink — which leaves `enclave-core`'s 81 unit tests green, because they assert against a mock that *receives* a `Stage` rather than against a record that carries one. `crates/audit/tests/policy_audit_coverage.rs` (`ENC-585`) |
| U2 | The application role cannot `UPDATE` or `DELETE` `audit_events` |
| U3 | Hash-chain verification detects a tampered row and reports the first divergence |
| U4 | Audit records never contain passwords, tokens, refresh cookies or file content |
| U5 | **Every site in the workspace that constructs a refusal does so where the policy engine records it.** `CLAUDE.md` rule 10 for denials, enumerated rather than sampled: an enforcement point is a call site of `StageDecision::deny`, `Error::denied` or `Error::denied_with` — nothing else can refuse on policy grounds, because `Error::PolicyDenied`'s fields are private and `StageOutcome::Deny` is only reachable through `StageDecision::deny`. A site inside a function returning `StageDecision` hands its refusal to `PolicyEngine::enforce`, which records it before returning `Err`; anything else must be in `ACKNOWLEDGED` with a reason and the tracker row that owns the gap, printed on every run, and a **stale** entry fails the gate too. The `ensure_allowed()` enumeration is what keeps 'audited by construction' true: it is the public conversion from a stage's decision into the caller's error, and a `StageDecision` consumed by anything but the engine is a denial with no row behind it. Liveness is not optional here and earned itself on the first run — it failed, because `enforce` takes every denial inside a `macro_rules!` body an AST walk never enters. `xtask/src/audit_coverage.rs` (`ENC-585`) |
| U6 | **An audit write failure fails the operation it describes.** Rule 10's other half: an unaudited action must not be treated as having happened. Asserted on both paths, because a chain that propagated the failure for allows and swallowed it for denials would pass a one-sided test — and the denial path is the one an incident depends on. `crates/audit/tests/policy_audit_coverage.rs` (`ENC-585`) |

### 4.11 Conditional access

| # | Assertion |
|---|---|
| C1 | **A forged `X-Forwarded-For` from an untrusted peer is ignored.** M4's exit criterion, and an assertion about an absence — so it is never asserted alone. Both halves of `a_forged_forwarded_for_is_ignored_from_an_untrusted_peer_and_honoured_from_a_trusted_one` call the *same* resolver on the *same* header with the *same* configuration and differ only in the peer address: from `198.51.100.66` the header is not read at all, from `10.0.0.7` it is honoured. Without the second half the first passes against a resolver that ignores the header unconditionally and against one that never runs. Asserted a second time through the code the HTTP path runs — `edge::tests::a_forged_forwarded_for_reaches_the_context_only_from_a_trusted_peer` builds the `Parts` an extractor sees, with axum's `ConnectInfo`, and checks the `NetworkContext` that reaches the chain, including that the forged address bought no trusted **zone**. `crates/conditional_access/tests/forwarded_for.rs`, `crates/api/src/edge.rs` (`ENC-583`) |
| C2 | **Neither "leftmost" nor "first public address" can be the resolved client.** Both shortcuts let a client claim any source IP by sending enough entries (`06 §7.3`, D30), so each has a test named for it, and the fixture `10.9.9.9, 203.0.113.9, 192.0.2.44` makes leftmost, first-public and correct three *different* addresses — a table where any two coincided would let a wrong implementation pass. The walk is table-driven across nineteen cases: more entries than hops, fewer, none, malformed and obfuscated entries, `hops: 0`, IPv6 bare and bracketed, IPv4-mapped peers, and `X-Forwarded-For` arriving as several header lines. `crates/conditional_access/tests/forwarded_for.rs` (`ENC-583`) |
| C3 | **A hop is believed only while the address being stepped past is itself in a trusted network.** The budget is the peer's configured `hops`, and the walk stops early when an intermediate is not trusted — so a client one hop behind a real proxy cannot buy extra hops by lengthening the chain, and a forwarded entry that *names* a trusted network does not grant one. `via_trusted_proxy` reports what happened rather than whether the peer was on a list: a trusted proxy that forwards nothing yields `false`, because the address in hand was observed rather than relayed. `crates/conditional_access/tests/forwarded_for.rs` (`ENC-583`) |
| C4 | **Zones are resolved against the client address and never against the proxy.** `06 §7.3` requires geo and ASN lookups to run on the resolved address; the same holds for zone membership, and getting it wrong is *permissive* — the load balancer is nearly always inside a trusted zone, so every request through it would arrive trusted. Asserted with the proxy inside the zone and the client outside it, and a positive control where the client really is inside. `crates/api/src/edge.rs` (`ENC-583`) |
| C5 | **A rule written for people decides nothing about a service account, and vice versa** (`plans/M4-GOVERNANCE.md` Q19). The separation is by type — `HumanCondition` has no posture-free machine vocabulary and `MachineCondition` has no `PostureBelow` or `AuthStrengthBelow` — so a posture rule against a machine is not skipped, it cannot be written, and needs no escape clause. Each half carries its control in the same test: the same policy set holds a machine rule that *does* refuse the same request, so "the human rule did not fire" cannot be satisfied by an evaluator that fires nothing. `system` is in the machine set and is asserted there, because a token can assert `typ: "system"`. `crates/conditional_access/tests/rules.rs` (`ENC-583`) |
| C6 | **Break-glass is exempt from IP and zone policy and from nothing else** (`11-OPERATIONS.md §5.6`). Conditional access is a stage break-glass *traverses*: skipping it would waive every effect and could not be audited. Three claims, each asserted with its control — a zone rule that locks an ordinary administrator out is waived for a break-glass session; a posture rule refuses the same session; and a break-glass token that authenticated with one factor gets no exemption at all, because §5.6 does not exempt it from MFA. A machine principal holding the same scope gets nothing. `crates/conditional_access/tests/rules.rs` (`ENC-583`) |
| C7 | **A caller whose location cannot be resolved is outside every geo-fence and inside none.** `NetworkContext::country` is `None` until a geolocation provider is wired, so this is the shape every fence configured today meets: `country NOT IN [IN]` matches an unplaceable caller and blocks them; `country IN [IN]` does not match. Both directions asserted, each against a placed caller as the control. An empty machine allowlist likewise admits nobody rather than everybody. `crates/conditional_access/tests/rules.rs` (`ENC-583`) |
| C8 | **A stored rule cannot express what the rule types cannot** (Q19, `ENC-590`). The separation between the two rule sets is a *type* separation, and a JSONB column would dissolve it silently. Three refusals, each with its positive control in the same test: `{"posture_below":"MANAGED"}` under `MACHINE` is refused **and names the offending clause**, while the identical document under `HUMAN` decodes into the condition it names; `{"actor_kind_is":[…]}` under `HUMAN` is refused and decodes under `MACHINE`; and `{"client_is":[…]}` — legitimately in both vocabularies — decodes into *different* rules under the two audiences, which is why the audience is a column and can never be inferred from the document. Every condition of both enums round-trips, with an exhaustive `match` naming each variant so a new one fails to compile rather than going untested. `crates/conditional_access/tests/rule_storage.rs` |
| C9 | **An undecodable rule fails the request; it never quietly leaves the rule set.** Skipping it is the permissive failure and it is silent — the deployment carries on with one refusal fewer than the administrator wrote. Asserted at both levels: `decode_rules` over a good row and a bad one returns `Err` (control: the same call over two good rows returns both), and end to end, a hostile row written through the repository — a `MACHINE` rule carrying a person's posture condition, which PostgreSQL cannot type-check and does not pretend to — makes the stage return an error rather than an allow. The control is asserted **first**, in the same fixture: the tenant's valid rule refuses a download and permits a preview, so the failure afterwards is distinguishable from a stage that never decided anything. `crates/conditional_access/tests/{rule_storage,stored_rules}.rs` |
| C10 | **`ALLOW` cannot be stored, and neither can an invented audience, mode or non-array condition list.** `06 §7.4` has no allow because under most-restrictive-wins it could never change an outcome — an exception that appears to exist. The decoder refuses the string and `migrations/0019`'s `CHECK` refuses the row, which is the half that holds for a repair script that never went through the enum; both are asserted, the second against a live database with a well-formed insert beside it as the control. An unrecognised mode is refused rather than demoted to `SIMULATION`, because a control that reports itself as on and refuses nothing is the failure `plans/M4-GOVERNANCE.md §2` is written against. `crates/conditional_access/tests/{rule_storage,stored_rules}.rs`, `crates/conditional_access/src/store.rs` |
| C11 | **One tenant's rules never decide another tenant's request.** The assertion that matters most here and an assertion about an absence, so it is never made alone: `tenant-alpha` stores a rule, and in the same run, over the same application-role pool, alpha's request is **denied** by it while beta's identical request is allowed — then the mirror, with beta storing a rule of the same name and alpha still not being refused by it. A leak in one direction only is still a leak. Repeated one layer down, where a leak would happen: the repository returns beta zero rules and alpha exactly one. Run over `enclave_app`, never the harness superuser, because a superuser bypasses row-level security and would prove nothing (`ENC-124`). `crates/conditional_access/tests/stored_rules.rs` |
| C12 | **A rule cannot be authored by another tenant's administrator.** PostgreSQL runs referential-integrity checks with row security deliberately not enforced, so `REFERENCES users (id)` would accept `tenant-beta`'s admin as the author of a `tenant-alpha` rule — two well-formed rows, and RLS refuses neither (`04 §3.3`, `ENC-543`). The composite `(tenant_id, created_by)` key closes it; asserted by attempting the cross-tenant insert and requiring it to fail, with the same row and this tenant's own administrator as the control. `crates/conditional_access/tests/stored_rules.rs` |
| C13 | **The application role may withdraw a rule and may never delete one.** One `DELETE` lifts every network restriction a tenant has and leaves nothing to say it existed, so `enclave_app` does not hold it (`migrations/0019`, the same argument `0018` makes for quotas). Asserted as the grant *and* as the statement — the `DELETE` is actually attempted over the application role and must fail — with `SELECT`/`INSERT`/`UPDATE` asserted present first, since a role with no privileges at all would satisfy the `DELETE` leg on its own. Withdrawal is idempotent, keeps the row and its text, and stops the rule deciding: the same request is refused before the withdrawal and allowed after it. `crates/conditional_access/tests/stored_rules.rs` |
| C14 | **A tightened rule is applied within the cache TTL, and the cache is genuinely there.** A stale rule set is *permissive* — there is no `ALLOW` effect, so every rule this stage holds denies — which makes unbounded staleness a security defect rather than a performance nuance. Both halves are each other's control: immediately after a rule is moved from `SIMULATION` to `ENFORCE` the request is still allowed, which is what proves a cache exists; after the TTL elapses the identical request is denied, which is what proves the staleness is bounded. Dropping either half leaves a test that passes against a stage with no cache, or against one whose cache never expires. Invalidation is asserted separately as the immediate route on the replica that made the change, against an hour-long TTL so it cannot pass by expiry. `crates/conditional_access/tests/stored_rules.rs` |
| C15 | **The stage decides from stored rules in the running binary, not `UnconfiguredConditionalAccess`.** The evaluator existed for a milestone and was wired to nothing, which is the state `plans/M4-GOVERNANCE.md §2` is entirely about. Two halves, because neither is sufficient: a tenant with no rules is allowed and the *same* tenant with one rule is denied, through the `dyn ConditionalAccessService` the policy engine holds — a test that only asserted the allow would have passed against the stub — and `crates/api/src/main.rs`'s own unit test asserts the start-up banner no longer announces the stage as unconfigured, with the entry proved present before filtering, exactly one entry removed, and the genuinely-unconfigured stages still announced. `crates/conditional_access/tests/stored_rules.rs`, `crates/api/src/main.rs` |

### 4.12 Quotas and capacity

`plans/M4-GOVERNANCE.md` D31. The same shape as `H3` — the limit in the `WHERE` clause of the
statement that spends the resource, a zero-row result as the refusal — applied to stored bytes
instead of share-link downloads.

`Q1`–`Q6` are the statement (`crates/db/tests/storage_quota.rs`, `ENC-584`). `Q7`–`Q11` are the
*wiring* (`ENC-589`), and they exist because the two are separable in exactly the way §2 of the
plan is about: `ENC-584` shipped a correct charge that nothing called, and a control that is
switched off is indistinguishable from an absent one except in the compliance answer. So the
question `Q7`–`Q11` ask is not "does the statement refuse" but "does the real write path reach it,
in the real transaction, before the row it pays for" (`§1.1`).

| # | Assertion |
|---|---|
| Q1 | **Sixteen concurrent charges against a quota with room for one admit exactly one**, and the counter ends *at* the limit rather than above it. Enforced by a single `UPDATE` carrying the limit in its `WHERE` clause; under `READ COMMITTED` a contender whose row moved while it waited re-evaluates that predicate against the new row. Has a **positive control beside it**: the check-then-write shape, written out in the same file and run on the same pool, the same barrier and the same row, must over-issue. `docs/12 §4.4` H3 passed for a milestone against a naive implementation because the harness could only run two transactions at a time, and a concurrency test that has never been shown to *catch* anything is a claim about the harness as much as about the code — if the control ever admits exactly one, `Q1` is proving nothing |
| Q2 | **Quota exhaustion blocks writes while reads, deletes and exports keep working.** The refusal is asserted **first**, in the same fixture, so the three "not blocked" legs are statements about a demonstrably exhausted quota rather than about one that never engaged (`§1.2`: an assertion about an absence passes for free). The loop closes at the end: after the delete frees room, the charge that was refused three statements earlier is admitted. Structurally reinforced — `Released` has no refusal variant, so "this delete was refused for quota" is not a constructible value, and `release_storage`'s statement is bounded by the tenant and by nothing else. The strictly-over-limit case is covered separately in `Q6`, because under `BLOCK` no charge can take a tenant *past* its limit — only reconciliation can — so a release guarded by `used_bytes <= limit_bytes` passes here and fails there |
| Q3 | **A charging statement that lost its bound aborts the transaction rather than exceeding the quota.** D31's backstop: `CHECK (enforcement <> 'BLOCK' OR used_bytes <= limit_bytes + overshoot_bytes)`. Asserted by running the mistake — the charge with its `WHERE` clause stripped to the tenant — and requiring SQLSTATE `23514` naming `storage_quotas_within_budget`, with a control charge inside the limit beside it so a constraint that refused every update would not satisfy it |
| Q4 | **One tenant's exhaustion never refuses another, and neither transaction can see the other's quota row.** Run over `tenant-alpha` and `tenant-beta` with identical limits and identical charges, over the application role rather than the harness superuser. The RLS leg's zero has the same query for the caller's own row beside it as its positive control |
| Q5 | **The soft limit is announced once, and before anything is refused.** The crossing is decided inside the charging statement, under the row lock, and stamped on the row — so it fires once rather than once per replica and does not fire again after a restart. Asserted at 79%, 80% and 90% with the first refusal after all three, and re-armed by a release back under the threshold. `plans/M4-GOVERNANCE.md §2`: quotas notify before they refuse, which is also why `MONITOR` and `WARN` count without refusing while `BLOCK` refuses the identical charge |
| Q6 | **Nightly reconciliation corrects drift without a window in which writes are refused on a stale figure.** Two halves. The counter is corrected *relatively* — a charge that commits between the observation and the correction keeps its full effect, and the test names the figure an absolute assignment would have produced. And the observation takes no lock: a charge issued while it is open must complete, with the **control** being the same charge against a reconciler that took `SELECT … FOR UPDATE`, which must time out. Also covers what a genuinely over-limit tenant may still do: record its true figure, and delete its way back under |
| Q7 | **A version commit over the quota is refused and stores nothing; the identical commit under a quota with room stores everything.** The row, the `file.version.created` outbox row, the audit row, the file's `revision` bump and the counter are counted together as one `Footprint`, and the refusal leg asserts that value is *unchanged*. That is five assertions about an absence, so **the control runs first and is asserted in full** — without it the whole test passes against a commit path that writes none of them (`§1.2`). The refusal itself is `VersionsError::StorageQuotaExceeded`, rendering `403` `QUOTA_EXCEEDED` with the limit: quota exhaustion is not a server error. `crates/versions/tests/versions.rs` (`ENC-589`) |
| Q8 | **The charge and the write it pays for share one transaction, proved from both sides.** The charge is read back *inside* the commit's own transaction — that read is the positive control, and without it "the counter did not move" is satisfied by a path that never charges — and the transaction is then rolled back, after which the counter is zero and no version survives. Beside it, a real post-charge failure: a duplicate `object_key` refused by `uq_version_object`, the statement immediately after the charge, must leave the counter exactly where the preceding successful commit left it. A counter that kept that charge is drift the nightly job would spend the night undoing, and `ENC-584`'s reconciliation would be correcting a divergence the write path manufactured. `crates/versions/tests/versions.rs` (`ENC-589`) |
| Q9 | **The reserve-time preflight refuses before a URL is issued, and admits nothing.** `docs/05-API.md §8` and `10-SYNC-AND-EDITING.md §5` require a quota answer before the client spends bandwidth; `UploadService::create` gives one, and the store is asserted never to have been called — with the control, an upload that fits, issued and reaching the store once, in the same fixture. The **second** test is the one that makes the design visible rather than documented: two sessions that each fit the same headroom are *both* issued, because a pass is not a reservation. `Preflight` has no admitting variant, so "the quota admitted this upload" is not a constructible value and the binding decision stays the single statement at commit. `crates/uploads/tests/sessions.rs` (`ENC-589`) |
| Q10 | **An exhausted tenant can still delete, and deleting frees nothing it should not.** The refusal is asserted first against the same tenant, then `FileRepository::trash` and `FileRepository::restore` both succeed under it — a tenant over quota that cannot delete cannot get back under it. And the counter is asserted **unchanged** by the trash: a soft delete destroys nothing, the bytes are still stored, and releasing there would make the recycle bin an unmetered tier that reconciliation would then report as drift. The loop closes with a real release admitting the charge that exhaustion refused. `crates/files/tests/tree.rs` (`ENC-589`) |
| Q11 | **Rollout modes and unmetered tenants reach the same wiring.** `MONITOR` counts a commit it will not refuse while `BLOCK` refuses the identical one; a tenant with no quota row commits unmetered while `tenant-beta`, configured, is refused under the same fixture; one tenant's exhaustion never refuses the other's commit; a restore is charged for its *copy* of the bytes and refused when they do not fit, because `uq_version_object` makes sharing the source's key unrepresentable and the deployment is storing both. Each "not refused" leg carries a refusal beside it. `crates/versions/tests/versions.rs` (`ENC-589`) |

**Not yet covered, and named rather than implied:** `release_storage` has **no caller outside its own
tests**, because no path in this workspace destroys stored bytes. `FileRepository::trash` is a soft
delete whose bytes are still held (`Q10` asserts it must not release), and
`enclave_files::purge_permanently` refuses by construction until retention and legal hold exist.
`ENC-597` owns the release, and `crates/files/src/purge.rs` names where it goes.

## 5. Structural CI gates

Assertions about the codebase itself, not its behavior:

| Gate | Rule |
|---|---|
| RLS coverage | Every table with a `tenant_id` column has RLS enabled **and** forced, with a policy |
| Grant coverage | `enclave_app` can reach every tenant-scoped table, still cannot `UPDATE`/`DELETE` `audit_events` or its partitions, and holds neither `SUPERUSER` nor `BYPASSRLS`. The RLS gate cannot see any of this: it checks the policy, not whether the role it applies to can use the table — the gap that let a cross-tenant read return `200` in PR #22 |
| Composite FKs | Every FK between tenant-scoped tables includes `tenant_id` |
| Policy routing | Every Axum route handler reaches `PolicyEngine::enforce` (verified by a call-graph lint) |
| Audit coverage | Every site that constructs a refusal does so where `PolicyEngine::enforce` records it, and the row it writes names the stage that refused. Two halves in one job, because they fail differently: deleting `record_deny` from the chain leaves the lint green, and dropping the stage attribution leaves both the lint and `enclave-core`'s own tests green |
| No raw pool | No `sqlx::query*` outside the `db` crate bypasses `TenantScoped` |
| Obligations | `PolicyDecision` is `#[must_use]`; no `let _ =` discards it |
| Secrets | No literal credential patterns in configuration files or fixtures |
| Migrations | Numbered, checksummed, no gaps; contract-phase migrations flagged for review |
| Dependencies | `cargo audit` and `cargo deny` clean; SBOM generated |
| API contract | Generated OpenAPI matches the committed snapshot, or the diff is explicitly approved |
| Accessibility | axe passes on every primary route |
| Bundle size | Main bundle ≤ 250 KB gzipped |
| i18n | No untranslated user-facing string literals in `web/src` (`14-I18N-L10N.md §8`) |

## 6. Performance tests

Nightly k6 against staging, asserting the budgets in `03-LLD.md §23` and `09-UX-WHITE-LABELING.md §2`:

- browse a 100 000-item folder — first page P95 < 400 ms;
- search at 50 RPS — P95 < 500 ms, post-filter drop ratio < 5%;
- 100 concurrent 1 GB uploads — no API memory growth beyond the configured buffer;
- 500 concurrent preview requests — rendition queue drains within SLO;
- policy decision under cold cache — P95 < 300 ms.

A regression greater than 20% against the previous week fails the build.

## 7. Chaos tests

Weekly in staging, each asserting the row in `02-HLD.md §24`:

kill PostgreSQL primary (failover, no data loss) · kill Redis (degrade, no authoritative loss) ·
kill Milvus (search degrades, files work) · kill NATS (outbox retains) · block the embedding provider
(indexing pends) · block AV (uploads hold) · block SMTP (retries then DLQ) · block Vault (leases
continue, new fetches fail closed) · partition object storage (metadata browsing continues).

## 8. Manual and external testing

- **Screen-reader pass** (NVDA + VoiceOver) on primary flows each release.
- **Localization pass** in one RTL and one long-string locale each release (`14-I18N-L10N.md §9`).
- **Penetration test** at least annually and before any major release, scoped explicitly to the
  matrix in `§4` plus standard web application testing.
- **Restore drill** monthly (`11-OPERATIONS.md §4`).
- **Upgrade drill** from the previous two minor versions before each release.

## 9. Release criteria

A release ships only when all of the following hold:

1. every test in `§4` passes — no skips, no quarantined security tests;
2. structural gates in `§5` pass;
3. no open SEV1/SEV2 defects;
4. performance within 20% of the previous release;
5. migrations verified forward **and** with the previous release running against the new schema;
6. accessibility and localization passes complete;
7. the changelog, upgrade notes and any new runbook sections are written;
8. the error budget is not exhausted (`11-OPERATIONS.md §1`).

## 10. Coverage expectations

Line coverage is a weak signal and is not a gate. What is gated:

- 100% of the matrix in `§4`;
- 100% of policy-engine branches (every effect, every obligation, every fail-closed path);
- every state transition in the upload, incident, index-manifest and sync state machines;
- every error variant in `03-LLD.md §22` reachable from at least one test.
