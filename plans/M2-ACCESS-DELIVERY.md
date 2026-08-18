# M2 — Access & Delivery · Implementation Plan

> Enclave · Phase 1 · 5 weeks planned · Tracker: `ENC-145` … `ENC-154`
> Roadmap: [`ROADMAP.md §5`](../ROADMAP.md) · Preceded by [`M1-CONTENT-CORE.md`](M1-CONTENT-CORE.md)

---

## 1. Objective

**Granular permissions actually work, and preview is genuinely separable from download.**

M1 proved content can be stored safely. M2 is where the product's central claim stops being an
architecture diagram: that a user may hold `FILE_PREVIEW=ALLOW` with `FILE_DOWNLOAD=DENY` and the
system can honour both at once. Today the preview endpoint returns `501` rather than lie about it
(`crates/api/src/preview.rs`). Closing that honestly is the milestone.

### Exit criteria (from the roadmap — may not be weakened here)

- [ ] `preview=ALLOW, download=DENY` produces a rendition and **no** signed original URL (A1).
- [ ] A `DENY` beats an inherited `ALLOW` at every level (A3).
- [ ] `max_downloads` holds under 50 concurrent redemptions — exactly N succeed (H3).
- [ ] Watermarked output is never written to the rendition cache.
- [ ] Cursor from one tenant rejected in another (T3).

---

## 2. What M1 already delivered against this milestone

Stated first because it changes the sequencing, and because a plan that re-plans finished work is a
plan nobody trusts.

| Roadmap step | State | Evidence |
|---|---|---|
| ACL resolution: inheritance, group closure, deny-wins | **Done** | `crates/authorization`, `tests/acl_resolution.rs`. Landed early as `ENC-126`: containers could not be built before the thing that decides who sees them. |
| Break-inheritance | **Done** | `enclave_authorization::materialise` (`ENC-141`). It was a privilege escalation when found, not a missing feature — see `§6`. |
| `authorize_many` batch path | **Implemented, unmeasured** | `service.rs:333`. Three round trips for a batch of any size. Never benchmarked; see `ENC-145`. |
| Cursor pagination | **Done** | `enclave_db::cursor`, signed and tenant-bound. T3 is already green in the leakage matrix. |
| `capabilities` on file responses | **Partial** | Present on `FileMetadata`, absent from listings by deliberate choice (`crates/api/src/content.rs:130`). Views do not exist. |

So exit criteria A3 and T3 are **already met** and are re-run rather than built. The milestone's real
content is renditions, share links, metadata and views — and the two criteria nothing yet touches,
A1 and H3.

---

## 3. Sequencing, and why it opens this way

### 3.1 First: the rendition pipeline (`ENC-146`)

Everything else in M2 is smaller and better understood. The pipeline is the milestone's only genuine
unknown — a sandboxed process that parses hostile input — and the exit criterion that depends on it
(A1) is the one the product is sold on. It goes first so that discovering it is harder than expected
happens in week 1 rather than week 4.

It also has the longest tail of decisions that other work must not pre-empt: where a rendition is
stored, what the cache key is, and what a watermark composition costs per request. Building share
links first would mean guessing at all three.

### 3.2 Then, in dependency order

| Order | Tracker | Work | Why here |
|---|---|---|---|
| 1 | `ENC-146` | `crates/preview` — sandboxed rendition generation, base cache | The unknown, and A1 depends on it |
| 2 | `ENC-147` | Watermark composition per request, never cached | Second half of A1; separable only once a base rendition exists |
| 3 | `ENC-148` | Replace the preview `501` with the rendition response | The policy code above it does not change — that is the point |
| 4 | `ENC-149` | `crates/sharing` — token hashing, password/OTP, expiry | Independent of renditions; can run alongside 1–3 |
| 5 | `ENC-150` | Atomic download budget — `max_downloads` under concurrency | H3, and the reason sharing is not one task |
| 6 | `ENC-151` | `crates/metadata` — fields, values, validation, content types | Needed by views, needed by search in M3 |
| 7 | `ENC-152` | Views + `capabilities` on every file response | Consumes metadata; closes the listing gap noted in `§2` |
| 8 | `ENC-145` | Benchmark `authorize_many` at 200 candidates | Must precede M3's post-filter design, not follow it |
| 9 | `ENC-153` | Leakage matrix rows for everything above | Same PR as each surface, as in M1 |

`ENC-150` is separated from `ENC-149` deliberately. A share link with an expiry is a feature; a
download budget that holds under 50 concurrent redemptions is a distributed-systems problem with a
specific wrong answer (read-modify-write) that looks correct in every single-threaded test.

---

## 4. Design decisions to lock in M2

### D15 — A rendition is derived content with its own lifecycle, not a cached response

It gets a row, a state machine and an object key of its own, in the same shape as a version. The
alternative — treating it as an HTTP cache concern — puts its lifetime in a header and makes
"invalidate every rendition of this file because its classification changed" unexpressible.

It follows that renditions are subject to the same rule as versions: nothing is readable before it
is scanned, and a rendition derived from a quarantined version is never generated at all.

### D16 — The base rendition is identity-free; the watermark is composed per request and never stored

`docs/06 §5.1`. Two consequences that must be enforced structurally rather than remembered:

1. The cache key cannot contain a user identifier, because if it could, a watermarked artefact would
   be cacheable and the fourth exit criterion becomes a matter of discipline.
2. The compositor writes to the response body, and has no handle to the store that holds base
   renditions. Same technique as `crates/api/src/preview.rs` uses today: the capability is absent
   from scope, not merely unused, so re-introducing it is a diff a reviewer notices.

### D17 — Extraction and rendering run in a sandbox with no network egress

`docs/03 §17`. Document parsers are the widest attack surface in the product (roadmap risk register:
likelihood High, impact High). Bounded CPU, bounded memory, bounded wall-clock, no egress, no
filesystem beyond a scratch directory, and the worker is not in the API process.

A timeout is a *verdict*, not an error: a document that cannot be rendered inside the budget yields
"no preview available", never a retry loop that pins a core.

### D18 — The download budget is decremented by the database, in the same transaction as the grant

`UPDATE share_links SET used = used + 1 WHERE id = $1 AND used < max_downloads RETURNING used`, and
zero rows means refused. Not a read, a check and a write — that is the shape that lets 50 concurrent
redemptions all observe `used = 49`.

H3 is asserted with real concurrency against a real database, because it cannot fail any other way.

### D19 — A share link's token is never stored

Store `hash(token)` with a per-tenant pepper; the token exists only in the URL the creator receives.
A leaked database backup then yields no working links. This mirrors how refresh tokens are already
handled in `crates/auth`, and the two should not diverge.

---

## 5. Risks specific to M2

| Risk | Mitigation |
|---|---|
| Rendition generation is the widest attack surface in the product | D17's sandbox is a task in its own right, not a flag on the worker; fuzzing lands in M3 as the roadmap says |
| A watermarked artefact reaches the cache | D16 makes the cache key structurally incapable of carrying an identity; asserted directly, not inferred |
| `max_downloads` passes tests and fails in production | D18 plus a genuinely concurrent test — 50 redemptions, exactly N succeed |
| Preview quietly becomes download under delivery pressure | The `501` is replaced by a rendition or not at all. Streaming originals "temporarily" is the one shortcut this milestone may not take |
| `authorize_many` is too slow for M3's post-filter | Benchmarked in `ENC-145` inside M2, so M3 designs against a measured number |

---

## 6. What M1 taught that changes how M2 is run

Recorded because `ROADMAP.md §6` step 5 asks for it, and because two of these cost real time.

1. **A gate that reports is not a gate that blocks.** Every structural gate is now verified by
   deliberate violation before it is trusted. M2 adds no gate without that step.
2. **A test that never runs is worse than no test**, because it reads as coverage. `ENC-118` found 27
   ignored tests including every proof of tenant isolation.
3. **A characterisation test is a good way to record a defect and a bad way to leave one.** A4 was
   documented as unsatisfied, with a test asserting the escalation *passed* — visible, but it sat
   there through four PRs. `ENC-141` should have been fixed when found. In M2, a discovered
   escalation stops the queue rather than joining it.
4. **Parallel batches need one shared `CARGO_TARGET_DIR`.** Per-agent target directories filled the
   disk and took the Docker daemon down mid-integration.

---

## 7. Definition of done

- [ ] Every M2 P1 is `DONE`.
- [ ] All five roadmap exit criteria demonstrated, each by a test that has been watched to fail.
- [ ] Leakage matrix rows A1, A5, A6, H1–H3 complete and green; A3 and T3 still green.
- [ ] `authorize_many` has a measured p99 at 200 candidates, recorded in the tracker.
- [ ] The preview endpoint no longer returns `501`, and still cannot reach object storage.

**No gate is held at the end of M2.** `ROADMAP.md §6` places G1 at the end of **M5**, not here —
M2, M3 and M4 all precede it. This plan is where that is written down, because
`M1-CONTENT-CORE.md §5` got it wrong and the tracker repeated the error.

---

## 8. Open questions

| # | Question | Needs deciding by | Owner |
|---|---|---|---|
| Q8 | Rendition formats: PDF-only, or PDF plus a raster tile pyramid for large documents? | Before `ENC-146` | Product |
| Q9 | Does a rendition inherit its source version's retention, or expire on its own schedule? | Before `ENC-146` | Governance |
| Q10 | Share-link OTP delivery — email only for MVP, or SMS too? `docs/13` assumes an email provider exists | Before `ENC-149` | Product |
| Q11 | Do views live in `metadata` or in `libraries`? They are library-scoped but metadata-defined | Before `ENC-152` | Backend |
