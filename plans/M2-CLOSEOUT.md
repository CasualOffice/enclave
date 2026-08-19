# M2 — Access & Delivery · Close-out

> Enclave · Closed 2026-08-20 · **Complete**
> Plan: [`M2-ACCESS-DELIVERY.md`](M2-ACCESS-DELIVERY.md) · Roadmap: [`ROADMAP.md §5`](../ROADMAP.md)

**No gate is held here.** `ROADMAP.md §6` places G1 at the end of **M5**; M3 and M4 come first. This
document exists because a milestone that closes without anyone writing down what it cost is a
milestone whose lessons are lost — not because a decision is due.

---

## 1. Exit criteria

From the roadmap, unchanged and not weakened.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | `preview=ALLOW, download=DENY` produces a rendition and **no** signed original URL (A1) | **Met** | `crates/api/tests/delivery.rs`. Both halves in one test: the response is `200 image/png` carrying the pipeline's bytes, and the *store* reports zero `signed_download` calls — never asked for, not asked and withheld. |
| 2 | A `DENY` beats an inherited `ALLOW` at every level (A3) | **Met** | `crates/testing/tests/leakage.rs`, from M1, re-run. Strengthened during M2 by `ENC-141`. |
| 3 | `max_downloads` holds under 50 concurrent redemptions (H3) | **Met** | `crates/sharing/tests/redemption.rs`, two tests — see `§3.1`, which is the most useful thing in this document. |
| 4 | Watermarked output is never written to the rendition cache | **Met** | Structural: `RenditionKey` has three fields and no constructor accepting a principal, so a composited artefact has no key it could be stored under. `crates/preview/tests/composite.rs`, matrix rows A8 and A12. |
| 5 | Cursor from one tenant rejected in another (T3) | **Met** | `crates/testing/tests/leakage.rs`, from M1, re-run. |

Definition of done, from the plan:

- [x] Every M2 P1 is `DONE`.
- [x] All five criteria demonstrated, each by a test watched to fail.
- [x] Leakage matrix A1, A5, A6, H1–H3 complete; A3 and T3 still green.
- [x] `authorize_many` measured at 200 candidates — p50 **7.0 ms**, recorded in `ENC-145`.
- [x] The preview endpoint no longer returns `501`, and still cannot reach object storage.

---

## 2. What the numbers say

| | End of M1 | End of M2 |
|---|---|---|
| Tests passing | 922 | **946** |
| Migrations | 6 | 10 |
| Tenant-scoped tables under RLS *and* grants | 30 | **38** |
| Leakage-matrix rows carrying a test | ~14 | ~24 |
| CI checks | 21 | 21 |

The row that moved most is the third: eight new tables, each with RLS enabled and forced, a policy
reading `app.tenant_id`, and a grant to `enclave_app` — every one added by a migration that the
gates then checked rather than by a migration anybody remembered to check.

---

## 3. What the milestone actually taught

Four things, kept because each cost something to learn and none was visible by reading.

### 3.1 A concurrency test on a small pool is a sequential test

`H3` asks that `max_downloads` hold under fifty concurrent redemptions. The obvious test — fifty
`tokio::spawn`s — **passed against a deliberately naive implementation, three times out of three**.
`TestDb::pool` caps connections at two, on purpose, because the D3 pool-exhaustion proof depends on
it. Fifty tasks two at a time is a sequential test wearing `tokio::spawn`.

Widening the pool was not enough either: the window between a stale read and the increment is real
but too narrow to hit by luck, and a concurrency test that fails only *sometimes* gets marked flaky
and then deleted. The property is now proven by holding the window open on a barrier until every
contender is inside it — which fails 3/3 without the `WHERE` clause and asserts its own precondition,
so a green result cannot mean "the contention never happened".

**The general form:** a test of a race must be shown to fail against the wrong implementation, and
the harness it runs on is part of the test.

### 3.2 Removing a stub can turn a satisfied obligation into a dropped one

`satisfy` treated `Obligation::Watermark` as satisfied on the honest grounds that nothing was
rendered at all, so nothing could be served unwatermarked. That was true for as long as the preview
endpoint returned `501`. The moment it returned a rendition, the same unchanged arm became a silent
obligation drop — rule 8, violated *by the endpoint starting to work*.

**The general form:** an invariant that holds because a feature is missing is an invariant with an
expiry date, and nothing warns you when it passes. The arm's comment said exactly why it was safe;
the comment was still true and no longer sufficient.

### 3.3 A gate can report green against a schema nobody is running

`sqlx::migrate!` reads `migrations/` at compile time, and Cargo had no reason to rebuild when a
`.sql` changed. Every schema gate applies migrations through that crate and then inspects the result,
so after an edit they reported on the *previous* schema. Found by a deliberate violation **failing
to fail** — the RLS gate stayed green with `FORCE` removed, and reported one table fewer than the
schema actually had.

CI builds from scratch and never saw it. The only place it bites is a person iterating locally, at
the moment they are trusting a gate.

**The general form:** verify a gate by breaking something, and be suspicious when the break is
invisible rather than relieved.

### 3.4 Cost is where you have not measured, not where you assume

`authorize_many` was assumed to scale with candidates. Measured, it is ~80% fixed: 1.4 ms for one
candidate, 7.0 ms for two hundred. That inverted two design intuitions at once — over-fetch is nearly
free, and a *second* resolution pass costs more than tripling the batch — and `docs/07 §6.2` had
already described exactly such a second pass for excerpt disclosure. Batching actions rather than
resources then took a listing page from 68.5 ms to 8.1 ms.

**The general form:** a performance argument that has not been measured is a design constraint
somebody invented. This one had been in a specification for two milestones.

---

## 4. What is deliberately not proven

Stated plainly, so nobody mistakes silence for assurance.

- **Only raster renditions exist.** PDF and OOXML need the out-of-process worker of D17;
  `NoRenderer` answers for them, so a preview of a Word document is a `404` today. Leakage row G4
  (an SVG/HTML upload cannot execute script in a preview) is blocked on the sanitizer that arrives
  with it.
- **The watermark's font covers Latin only.** A display name it cannot draw is omitted — the mark
  still carries email, session, file and timestamp — but a viewer whose *email* is non-Latin has
  their preview refused outright (`ENC-173`). Safe, and a poor experience for a large part of the
  world.
- **Share links check no password, OTP, domain or MFA yet.** The requirements are carried and
  returned; enforcing them is `H2` and belongs beside the rest of authentication.
- **Nothing has run under load.** The `authorize_many` figures are a single debug-build machine, not
  a budget verified at scale.
- **The API binary still serves almost nothing.** `router()` now refuses to compile without its
  dependencies (`ENC-170`), and what a deployment gets without them is a documented `503` — but that
  is honesty about absence, not presence.

---

## 5. Estimate check

Planned at 5 weeks; delivered in one session, as M0 and M1 were. The roadmap's calendar dates assume
a 7-person team at 70% capacity and are left unchanged, for the reason `G0-GATE.md` gave:
re-baselining from this would produce a schedule nobody could meet.

What *is* carried forward is the shape. The plan opened with the rendition pipeline on the grounds
that it was the milestone's only genuine unknown, and that held — it produced the decode-bomb
ordering, the compositor's silent no-op, and the font-coverage limit, none of which were foreseen.
The items the plan treated as routine were routine. Sequencing by uncertainty rather than by
dependency worked, and M3 is planned the same way.

---

## 6. Scope added during the milestone

Recorded because `ROADMAP.md §8` requires promoted scope to carry its cost, and because a milestone
that quietly absorbs work teaches nothing about estimating the next one.

| Added | Why | Cost |
|---|---|---|
| `ENC-141` — break-inheritance materialisation | A privilege escalation found while writing the A4 matrix row | Fixed before M2 began |
| `ENC-146a` — a real renderer | Split from `ENC-146`; the pipeline is not testable end to end without one | Within M2 |
| `ENC-159`…`ENC-162` — DMS gaps | Raised as a question; four genuine gaps found, one an adoption blocker | **M8b, +2 weeks to Enterprise V1 GA** |
| `ENC-170`, `ENC-171` | Two routes returning `500` in the binary, and every dependency outage rendering as `500` | Within M2 |
| `ENC-167`, `ENC-175` | The post-filter measurement, and acting on it | Within M2 |

Only the third changed a date, and `ROADMAP.md §2` states it.
