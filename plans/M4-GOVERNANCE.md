# M4 — Governance baseline

> **Status:** Draft · **Version:** 1.2 · **Owner:** Engineering · **Last updated:** 2026-08-22

`ROADMAP.md`: *"A tenant can be told no, for the right reasons, with an audit trail."*

---

## 1. Objective

M3 made content findable. M4 makes it refusable — and makes the refusal explainable afterwards.

Four of the six policy stages are still `Unconfigured` stubs that permit everything. `crates/dlp`
and `crates/conditional_access` each export exactly one public item. The chain runs, the order is
enforced, and three of its stages currently decide nothing.

### Exit criteria (from the roadmap — may not be weakened here)

- [ ] **D1–D4** green: `ENFORCE` blocks, `SIMULATION` records only, missing facts fail closed, a
      dropped obligation fails the operation.
- [ ] A forged `X-Forwarded-For` from an untrusted peer is ignored.
- [ ] Quota exhaustion blocks writes while reads, deletes and exports keep working.
- [ ] Every row in the audit table maps to a real enforcement point; no silent successes.

---

## 2. The one sentence this milestone is built on

**A control that cannot be turned on gradually will be turned on carelessly, or not at all.**

M3's sentence was about the index never being the authority. M4's is about *rollout*. Every control
here is one an administrator must be able to enable against real traffic without breaking it —
which is why `SIMULATION` is a mode and not a flag, why `facts_unavailable` is a policy rather than
a constant, and why quotas notify before they refuse.

The failure this milestone is arranged against is not a control that blocks wrongly. It is a control
nobody dares enable, which is indistinguishable from one that does not exist — and which, unlike an
absent control, appears in the compliance answer.

---

## 3. Decisions to lock before the design sets

### D26 — `SecurityFacts` are gathered once per request and passed down

**Q16 is answered and constrains this section: structured detectors only, no regex on the
synchronous path.** Luhn-checked card numbers, IBANs, national IDs and API-key shapes — validated by
structure and checksum. A `SecurityFacts` shape built around "detector counts" therefore counts
*matches of structured detectors*, and nothing in it should assume a pattern or capture groups.

Every stage that needs facts receives the *same* value. No stage re-fetches.

Two reasons, and the second is the one that matters. The obvious one is cost: facts are a read per
resource, and the chain has ten stages. The real one is that a stage re-fetching can observe
*different* facts from the stage before it — a scan completing mid-chain flips `facts_unavailable`
between DLP and retention, and the request is then decided against two different views of the same
document. That is not a race that produces a wrong answer occasionally; it is a race that produces a
decision nobody can reconstruct from the audit row, because the row records one of the two.

Consequence to accept: facts are as of the start of the request. A scan finishing during a request
does not affect that request.

### D27 — `facts_unavailable` is tenant policy, never a per-request choice

`docs/06 §12` gives two modes. Neither may be selected by a caller, a header, or an operation —
only by tenant configuration, with `FAIL_CLOSED` the default for `RESTRICTED` and for external
sharing at any classification.

A per-request override is the shape that gets added for "just this bulk import" and stays.

### D28 — `SIMULATION` must be indistinguishable from `ENFORCE` except in its effect

Same detectors, same facts, same evaluation, same audit row shape, same latency budget. The *only*
difference is that the action is recorded rather than taken.

If simulation takes a cheaper path, it measures something other than what enforcement will do — and
its whole purpose is to answer "what would this policy have done to last week's traffic". A
simulation that is fast because it skips work is a rehearsal of a different play.

`docs/06 §9` already requires simulation before enforcement for any `BLOCK` or `QUARANTINE` policy.
That requirement is worth nothing if the two run different code.

### D29 — An obligation is satisfied or the operation fails; there is no third outcome

`PolicyDecision` is already `#[must_use]` and `let_underscore_must_use` is denied at the workspace
level (`crates/core`). M4 adds obligations that *cost something to satisfy* — a watermark to burn, a
justification to collect — and the temptation is a path that proceeds when satisfying one fails.

There is no such path. An unsatisfiable obligation is a denial, and `D4` is the row that proves it.

### D30 — A forwarding header is believed only from a configured network, hop by hop

`ServerConfig::trusted_proxies` already exists and defaults to empty. M4 makes conditional access
*use* client IP, which is the point at which an empty list stops being cautious and starts being
load-bearing.

The rule: the peer address is the client address unless the peer is in a trusted network, in which
case exactly the configured number of hops is stripped. Never "take the leftmost", never "take the
first public address" — both let a client claim any source IP by sending enough headers.

### D31 — A quota is enforced in the same statement as the write it bounds

The share-link download counter already does this (`migrations/0008`): the limit is in the `WHERE`
clause and a zero-row result means exhausted. Quotas follow it.

A check-then-write is a race whose losing side is an over-issued resource, and a
`CHECK (used <= limit)` constraint is the backstop that turns a mistake in the statement into a
failed transaction rather than an exceeded quota.

**Reads, deletes and exports are never quota-blocked.** A tenant over quota that cannot delete
anything cannot get back under it, and one that cannot export cannot leave — which turns a billing
control into a hostage situation.

### D32 — Every enforcement point emits an audit row, and the sweep is a gate rather than a review

`CLAUDE.md` rule 10 already says audit happens inside the policy engine, for denials as well as
allows. The exit criterion asks that *every row map to a real enforcement point, with no silent
successes* — which is a statement about coverage, and coverage claims decay.

So the sweep lands as a check that can fail, in the shape of `crates/db/tests/rls_coverage.rs`:
enumerate the enforcement points, enumerate what audits, and fail on the difference. `ENC-543` is
why this is not a review item — the composite-FK gate was a review item for a milestone and printed
`pass` in green the whole time.

---

## 4. Sequencing, by uncertainty

Most-uncertain first, so the expensive discovery happens while there is room to react.

1. **`SecurityFacts` and the shape of a detector.** Everything else consumes this. If the shape is
   wrong, every stage that reads it changes.
2. **Conditional access**, because the trusted-proxy handling is the one piece with a *published*
   correct answer and a long history of implementations getting it wrong.
3. **DLP modes and obligations**, which are mostly plumbing once D28 is honoured.
4. **Quotas**, whose hard part is the reconciliation job rather than the enforcement.
5. **The audit coverage sweep**, last, because it enumerates what the four above built.

---

## 5. Risks specific to M4

| Risk | Why it is specific to this milestone |
|---|---|
| A detector that is expensive on a large document turns every write into a timeout | DLP is the first stage that reads *content* synchronously. `RenderBudget`'s bounds exist for the extraction path; this needs its own answer, and "reuse the budget" may not be it |
| Simulation diverging from enforcement | D28 forbids it in code, but nothing structurally prevents a second code path appearing. Worth a test that runs one policy both ways and asserts the recorded decision is identical |
| Conditional access locking out an administrator | A zone rule that denies the network the admin is on is a control that cannot be undone through the product. Break-glass (`docs/11 §5.6`) already exists; M4 must not add a stage that break-glass itself traverses |
| Quota reconciliation disagreeing with the counter | Two numbers for one fact. The nightly job must be able to *correct* without a window in which writes are refused on a stale figure |

---

## 6. Definition of done

- [ ] Every M4 P1 is `DONE`.
- [ ] All four exit criteria demonstrated, each by a test that has been watched to fail.
- [ ] Leakage matrix `§4` D-rows complete and green, and the H-rows quotas touch.
- [x] The audit coverage sweep exists as a **gate**, not a document (D32). `ENC-585`:
      `xtask audit-coverage` enumerates every refusal-constructing site and fails on the unaudited
      ones; `crates/audit/tests/policy_audit_coverage.rs` asserts the row can explain the denial.
- [ ] `docs/06` updated where implementation taught something the design did not say — and *only*
      there; it is authoritative and this plan is not.
- [x] A written walkthrough of one denial end to end: request in, stage that refused, obligation
      raised, audit row out. The roadmap asks M3 for a threat walkthrough; the equivalent here is a
      *provenance* walkthrough, because "for the right reasons, with an audit trail" is a claim
      about explainability rather than about leakage.
      `plans/M4-PROVENANCE-WALKTHROUGH.md` — two denials, both executed against a live database.
      The obligation one is the finding: it returns `403 PREVIEW_ONLY` and the audit row says
      `ALLOW` (`ENC-606`).

---

## 7. Open questions

| # | Question | Needs deciding by | Owner |
|---|---|---|---|
| ~~Q16~~ | **Answered 2026-08-22: structured detectors only, no regex on the synchronous path.** Credit-card numbers (Luhn), IBANs, national IDs, API-key shapes — validated by *structure and checksum* rather than by a pattern. A regex engine reading attacker-supplied content synchronously is a denial-of-service surface with a long CVE history, and the failure mode is the bad one: one crafted document stalls every write, arriving as load rather than as a refusal, which is far harder to attribute during an incident. Custom patterns are what enterprise buyers ask for first, so expect the pressure — the answer is a linear-time engine on an *asynchronous* path, never a backtracking one on this path | — | Closed |
| ~~Q17~~ | **Answered 2026-08-22: rate limits yes, quotas no — and the feared doubling does not arise.** The question conflates two controls with opposite subjects. A **rate limit** protects the *system* from load, and a simulated evaluation is real load — detectors run, facts are read, the same latency is spent. Exempting it means the limiter under-reports actual consumption precisely during a rollout, which is when load is highest and when an operator is least able to tell a capacity problem from a policy problem. A **quota** bounds a *stored resource* (Q18: storage bytes). `SIMULATION` records rather than acts, so the write never reaches `execute` and no bytes are stored; charging for them would bill a tenant for a document that does not exist. The premise that identical simulation doubles cost is **false under D26**: the rollout pattern is a candidate policy simulated beside the enforcing one, and because facts are gathered once per request and passed down, the expensive half — detection — is shared. Only policy *evaluation* duplicates, which is a comparison against already-computed counts. D26 was taken for correctness; that it makes simulation affordable is the reason this question has a cheap answer rather than a trade-off. Noted for whoever implements it: rate limiting is currently **documented but not built** — `docs/05 §…` specifies the `RateLimit-*` headers and no code emits them, so this answer is a constraint on a control that does not yet exist | — | Closed |
| ~~Q18~~ | **Answered 2026-08-22: storage bytes, per tenant.** Matches what `docs/04` already models and what a customer is billed for — one number per tenant, reconciled nightly against actual object storage. Named limitation, so it is not rediscovered: a byte quota does not bound the metadata and index load a million 1 KB files create, and a file-count limit is the additive fix if that becomes real | — | Closed |
| ~~Q19~~ | **Answered 2026-08-22: yes, with a separate rule set.** Conditional access evaluates for **every** principal; service accounts and MCP tokens are matched by rules written for them — network allowlists and token binding rather than device posture or MFA. The rejected option is the one that looks simpler: a single rule set means every posture rule needs an escape clause for non-human principals, which is the exemption again, written once per rule instead of once. And an exemption is precisely the gap an attacker looks for — compromise a service token and the zone rules simply do not apply | — | Closed |
