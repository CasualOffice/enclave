# M3 — Discovery · Implementation Plan

> Enclave · Phase 1 · 5 weeks planned · Tracker: `ENC-505` onwards
> Roadmap: [`ROADMAP.md §5`](../ROADMAP.md) · Preceded by [`M2-CLOSEOUT.md`](M2-CLOSEOUT.md)

---

## 1. Objective

**Search that cannot leak, and that degrades honestly when its index is unavailable.**

The roadmap says this milestone "contains the highest-severity design risk in the product", and that
is not a figure of speech. Every other surface answers one question about one resource, with the
policy chain in front of it. Search answers a question the caller did not phrase about resources
they did not name, by consulting a *second* store that holds a copy of the content and its own idea
of who may see it. Both of those — the second copy, and the second idea — are new failure modes.

### Exit criteria (from the roadmap — may not be weakened here)

- [x] **S3**: a revoked file vanishes from results **immediately**, before any index update.
- [x] **S4**: S3 still holds with the invalidation worker stopped.
- [x] **S5**: deliberately over-permissive index candidates are dropped by the post-filter.
- [x] **S8**: `RESTRICTED` text never reaches a non-local embedding provider.
- [x] Post-filter drop ratio and denylist size exported as metrics, with alerts wired.
- [ ] A scanned, text-free PDF is searchable by its content (`ENC-161`). **Not met** — no OCR;
      blocked on model files and the language decision in `Q12`.

Assessed in [`M3-THREAT-WALKTHROUGH.md`](M3-THREAT-WALKTHROUGH.md `§4`), which also records the
residual risks the ticks above do not cover. The short version: the **authorization** properties are
met and were each verified by breaking them on purpose; the **retrieval-completeness** properties are
not. Conflating those two is how a milestone gets called done — a search that cannot find a scanned
contract is visibly incomplete, and a search that returns a document the caller may not read is not
visible at all.

---

## 2. The one sentence this milestone is built on

**The vector index is a candidate generator. PostgreSQL is the authority.** (`CLAUDE.md` rule 5.)

Everything below follows from refusing to soften that. In particular, no design in this milestone
may make the post-filter *conditional* — not on a cache being warm, not on `acl_tokens` agreeing,
not on the index being recent. A post-filter that is skipped when some other signal looks confident
is a post-filter that is absent exactly when that signal is wrong.

---

## 3. Decisions to lock before the design sets

### D20 — Both disclosure levels are resolved in **one** call

`docs/07 §6.2` checks two levels: `MetadataRead` to see a hit at all, and `ContentRead` to see its
excerpt. Written when `authorize_many` batched resources only, that meant two resolutions per
search.

`ENC-145` measured what a resolution costs, and the answer inverts the obvious reading: **~80% of it
is fixed**. One candidate takes 1.4 ms; two hundred take 7.0 ms. So a second pass is not "a bit more
work proportional to the hits" — it very nearly doubles the price of the whole post-filter, while
raising the over-fetch factor is close to free.

`ENC-167` made that avoidable: `authorize_many_actions` resolves several actions in one pass, and a
ten-action page measured 8.1 ms against 68.5 ms for ten separate calls. **M3 uses it for both
levels in one call.** This is written down as a decision rather than left as an optimisation
because the shape of the post-filter is the hardest thing here to change later.

`docs/07 §6.2`'s example must be updated to match, or it will be copied.

### D21 — Over-fetch generously; it is the cheap side of the trade

Follows directly from D20's measurement. The post-filter drops candidates, so a page of 20 results
needs more than 20 candidates, and how many more depends on how over-permissive the index is. Since
resolution cost barely moves with batch size, the ratio should be set by *result quality* — how
often a page comes back short — and not by a fear of resolution cost that the numbers do not
support.

The drop ratio is exported as a metric (an exit criterion) precisely so this can be tuned from
evidence rather than guessed twice.

### D22 — The denylist is written in the same transaction as the ACL change

S3 asks that a revoked file vanish **immediately**, before any index update, and S4 asks that this
hold with the invalidation worker stopped. Those two together forbid the natural design — enqueue a
job, let a worker remove the document — because a stopped worker then means a revoked file stays
findable, and *the search still answers* rather than failing.

So revocation writes a `retrieval_denylist` row in the same transaction that changes the ACL. The
worker's job is to clean up afterwards, and its absence must cost only index size, never
correctness. S4 is the test that a stopped worker changes nothing a caller can observe.

### D23 — Classification routes embeddings, and the routing is enforced in code

S8: `RESTRICTED` text never reaches a non-local embedding provider. The failure mode is not that
somebody chooses the wrong provider; it is that a *fallback* does. A provider that is unreachable,
rate-limited or slow invites a retry against another one, and that is the moment the routing rule is
quietly violated by code that is trying to be helpful.

The routing therefore lives in the type that carries the text, not in the caller's choice of client:
text above the ceiling must be unable to reach a remote provider at all, in the way
`crates/api/src/preview.rs` cannot reach a `BlobStore`. **If the local model is unavailable,
indexing waits.** It does not fall back, and it does not index without embedding.

### D24 — Extraction runs in the D17 worker, and OCR is not a fallback

The sandboxed worker M2 deferred (`ENC-146a`) arrives here, because extraction is the same problem
as rendering: a parser eating hostile input. Its bounds are already written and tested
(`crates/preview/src/budget.rs`); this milestone reuses them rather than inventing a second set.

`ENC-161`: OCR is a first-class path, not the `docs/07` fallback "when a page yields no text". A
scanned PDF that indexes as empty is invisible to search while *appearing* correctly filed, which is
worse than one that failed to ingest — a failure is visible and a silent absence is not.

### D25 — Degraded search says so, in the response

Milvus down means lexical search over PostgreSQL with `degraded: true` in the response. The flag is
part of the contract, not an internal detail: a caller that cannot tell degraded results from
complete ones will report "the document isn't there" to a user, and the user will conclude it was
deleted.

Degraded mode is still post-filtered. It is a worse *recall* guarantee, never a worse *authorization*
guarantee.

---

## 4. Sequencing, by uncertainty

M2 opened with its only genuine unknown and that worked, so M3 does the same.

| Order | Work | Why here |
|---|---|---|
| 1 | The post-filter and the denylist, against a **fake** candidate generator | The guarantee, built before the thing it guards. A fake generator can be made deliberately over-permissive, which is exactly what S5 needs and what a real index makes hard to arrange. |
| 2 | Extraction + OCR in the sandboxed worker | The second unknown, and the one with an attack surface |
| 3 | Chunking with deterministic chunk IDs | Needed by both the index and invalidation |
| 4 | Embedding provider trait + local model, with D23's routing | Must precede anything that sends text anywhere |
| 5 | Milvus `VectorStore`, collection and hybrid query | The candidate generator the post-filter already has a fake of |
| 6 | Invalidation worker and epoch reconciler | Cleanup, after correctness does not depend on it |
| 7 | Degraded mode | Needs both paths to exist to fall between them |
| 8 | Metrics, alerts, and the matrix rows | Same PR as each surface |

**Building the post-filter first, against a fake, is the important part of this order.** It means the
guarantee exists before there is a real index to be tempted by, and it makes S5 a test that can be
written honestly: a generator that returns files the caller cannot see is a two-line fake and a
research project to arrange in Milvus.

---

## 5. Risks specific to M3

| Risk | Mitigation |
|---|---|
| The post-filter becomes conditional under latency pressure | It is built first, against a fake, with S5 asserting it drops what the generator wrongly offered. Any later change that makes it skippable fails that test. |
| A stopped invalidation worker becomes a correctness bug | D22: the denylist write is in the ACL transaction. S4 is the test. |
| An embedding fallback violates classification routing | D23: unreachable local model means indexing waits. The routing is structural, not a call-site choice. |
| Extraction is the widest attack surface in the product | D24 reuses M2's bounds and its out-of-process design rather than inventing a second set |
| Degraded results are mistaken for complete ones | D25 puts the flag in the response contract, and the matrix asserts it |
| OCR cost or language coverage is discovered late | `ENC-161` decides engine, languages and cost *before* extraction ships, not after |

---

## 6. Definition of done

- [ ] Every M3 P1 is `DONE`.
- [ ] All six exit criteria demonstrated, each by a test that has been watched to fail.
- [x] Leakage matrix §4.3 (S1–S10) complete and green. `§4.8` also gained **G7** — the indexer
      never reads a version antivirus has not cleared, which is rule 9 on the one path with no user
      present.
- [x] The post-filter's drop ratio and the denylist size are exported, with alerts wired to a runbook
      — and, since `ENC-521`, a listener that serves them. They existed for a while with nothing
      scraping them, which is a metric that reads as zero forever.
- [x] `docs/07 §6.2`'s example updated to the single-call form of D20, so it is not copied wrongly
      (`ENC-505`).
- [x] A written threat walkthrough of the search path, reviewed before merge — the roadmap asks for
      this specifically, and it is the one milestone where tests alone are not the bar.
      [`M3-THREAT-WALKTHROUGH.md`](M3-THREAT-WALKTHROUGH.md).

---

## 7. Open questions

| # | Question | Needs deciding by | Owner |
|---|---|---|---|
| Q12 | OCR engine, and which languages ship by default. Cost and image size both scale with it | Before extraction | Product + Platform |
| Q13 | Chunk size and overlap — a retrieval-quality decision that also sets index size and embedding spend | Before chunking | Backend |
| Q14 | Which local embedding model, and does it ship in the image or mount at runtime? Bears on air-gapped installs (`docs/08 §18`) | Before D23's routing | Platform |
| Q15 | Does degraded mode rank at all, or return in a fixed order? Ranking badly may be worse than not ranking | Before degraded mode | Product |
