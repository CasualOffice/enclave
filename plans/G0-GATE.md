# Gate G0 — Are the foundations sound enough to build on?

> Enclave · Held 2026-08-18 · Decision: **PASS, with two conditions carried into M1**
> Roadmap: [`ROADMAP.md §6`](../ROADMAP.md) · Plan: [`M0-FOUNDATIONS.md`](M0-FOUNDATIONS.md)

The roadmap places this gate at the end of M0 deliberately: it is the cheapest moment to discover
the foundation is wrong. Everything in M1 assumes the answers below.

---

## 1. Exit criteria

From `ROADMAP.md §5`, unchanged and not weakened.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | One end-to-end request: login → JWT → `enforce` → tenant-scoped query → audit row | **Partial** | Every component exists and is tested in isolation. Nothing composes them, because `crates/api` has no handlers — that is M1's first task. See `§4.1`. |
| 2 | Cross-tenant read fails with the application predicate deliberately removed (T5) | **Met** | `rls_coverage.rs` asserts RLS enabled **and forced** on all 20 tenant-scoped tables, and that every policy reads `app.tenant_id`. Proven to fail on an unprotected table and on a `USING (true)` policy. |
| 3 | Refresh rotation works; replaying a consumed token revokes the family (K3, K4) | **Met** | `crates/auth`, tests named for their K numbers. K8 includes the algorithm-confusion attack. |
| 4 | All four structural CI gates fail correctly when deliberately violated | **Met** | Each proven by deliberate violation — see `§3`. |
| 5 | `docker compose up` → healthy stack on a clean machine | **Met** | `deploy/compose/dev.yml`, health-checked, images from registries that do not require authentication. |

---

## 2. What the numbers say

| | At the start of M0 | Now |
|---|---|---|
| Crates | 0 | 46 |
| Tests passing | 0 | **403** |
| Tests ignored | — | **0** |
| CI checks | 0 | 20 |
| Structural gates enforcing | 0 | 10 |

The second row is the one that changed meaning during this gate. It read "380 passing, 27 ignored"
until `ENC-118`, and the 27 included every proof of tenant isolation the foundation rests on.

---

## 3. Do the controls actually work?

A control nobody has watched fail is a control nobody should trust. Each was verified by breaking
something on purpose.

| Gate | Proven by |
|---|---|
| RLS coverage | Creating a `tenant_id` table with no policy — failed by name. Rewriting a policy as `USING (true)` — failed, quoting both clauses. |
| Policy routing | Registering an unprotected handler beside a compliant one — flagged the first, passed the second, exit 1. |
| No raw pool | Reinstating the audit-sink bug — failed at `sink.rs:185`. |
| Secrets | Two real PEM literals caught, in PR #11 and PR #16. |
| Forward-only migrations | Rejected my own amendment to `0001` in PR #15. |
| `#[must_use]` on `PolicyDecision` | Clippy failed the policy-engine branch because a *test* dropped a decision. |

That last one is worth keeping: the attribute caught the exact mistake it exists for, in the first
code to use it, written by the person who added the attribute.

### 3.1 What the gates found that review did not

Six defects reached `main` or a PR and were caught by automation rather than by reading:

1. **Audit sink read on a raw pool** — under forced RLS it would have reported *"chain valid, 0
   events checked"* against a full chain. Failure that looks like success.
2. **A flaky security test** — 0.8% failure rate, measured at 15/2000. Rare enough to be waved
   through, frequent enough to eventually be `#[ignore]`d, at which point the redaction it guards
   stops being checked.
3. **A migration role race** — 10/10 reproduction, and my first fix caught the wrong SQLSTATE.
4. **Five self-deadlocking tests** — would have hung CI indefinitely rather than failing.
5. **A split test database variable** — made a whole crate's tests unreachable even where a
   database was available.
6. **Two tests interfering** through the deliberately cross-tenant outbox publisher.

None of these were visible by inspection. All were visible to a machine that ran the code.

---

## 4. Conditions carried into M1

The gate passes, but not unconditionally. Two things are true and should not be forgotten.

### 4.1 Nothing composes yet

Criterion 1 is partial, and honestly so. `PolicyEngine::enforce` is implemented and tested with
instrumented stubs; `TenantScoped` is implemented and proven under pool contention; `auth` issues
and rotates tokens. **No request has ever traversed all of them together**, because there is no HTTP
handler to originate one.

M1's first task is therefore not a feature. It is one real endpoint — `GET /api/v1/me` — wired
end to end, so criterion 1 becomes fully met before any content feature is built on the assumption
that it already is.

### 4.2 Five dependency majors are outstanding

`jsonwebtoken 9→11`, `ed25519-dalek 2→3`, `rand 0.8→0.10`, `sqlx 0.8→0.9`, `ipnetwork 0.20→0.21`.
All five fail CI on their Dependabot branches; all are genuine breaking changes, concentrated in
`auth` and `db`.

They should land **before** M1 adds content code, not after. Three of the five are cryptographic or
data-layer dependencies; the amount of code depending on them only ever increases, and `sqlx 0.9`
in particular touches every query in the workspace. Tracked as `ENC-119` … `ENC-123`.

---

## 5. What is deliberately not proven

Stated plainly, so nobody mistakes silence for assurance:

- **The policy chain has no real stage implementations.** All six services are deny-by-default
  stubs. The chain's *order*, short-circuiting, obligation accumulation and audit coverage are
  tested; what any individual stage decides is not, because none of them decide anything yet.
- **The leakage matrix is mostly unwritten.** `docs/12-TESTING.md §4` lists ~60 assertions across
  ten sections. Perhaps a dozen exist. The rest are M1 and M2 work and the matrix should be filled
  as each surface lands, not in a batch at the end.
- **Nothing has run under load.** The performance budgets in `docs/03 §23` are unmeasured.
- **No object storage, no search, no antivirus** has been exercised beyond a trait definition.

---

## 6. Decision

**PASS.** The foundation is sound enough to build on, on the evidence in `§1`–`§3` and with the two
conditions in `§4` scheduled rather than assumed.

The specific thing that makes this defensible rather than optimistic: the isolation proofs are no
longer aspirational. `no_transaction_ever_observes_another_tenants_context` — the pool-exhaustion
test that decision D3 was scheduled against, and around which this whole milestone was sequenced —
runs on every commit and passes. A week ago it had never executed.

### Estimate check

M0 was planned at 5 weeks and delivered in one session, which says more about the mode of work than
about the estimate. The roadmap's calendar dates assume a 7-person team at 70% capacity and are left
unchanged; re-baselining them from this would produce a schedule nobody could meet. What *is*
carried forward is the shape: the sequencing held, the day-10 checkpoint was the right checkpoint,
and it did surface the highest-risk decision exactly as intended.
