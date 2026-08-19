# ROADMAP

> **Milestones, sequencing and exit criteria for Enclave.**
> Owner: Casual Office · Last updated: 2026-08-18 · Baseline: 2026-09-01

This is the plan we follow. [`TRACKER.md`](TRACKER.md) is what we work from day to day; this document
says **why the work is in that order, when each milestone completes, and what "complete" means**.

Where the two disagree, the tracker is authoritative for status and this document is authoritative for
sequencing and exit criteria.

---

## 1. Planning assumptions

Every date below depends on these. If an assumption changes, the schedule changes — say so rather
than absorbing it silently.

| Assumption | Value |
|---|---|
| Team | 4 backend (Rust), 2 frontend (React/TS), 1 platform/SRE. Design and product shared, not dedicated. |
| Baseline start | 2026-09-01 |
| Sprint cadence | 2 weeks |
| Effective capacity | 70% of nominal — the rest goes to review, support, interviews, holidays |
| Estimate basis | Engineer-weeks, then divided by the parallel tracks that can genuinely run at once |
| Confidence | **High** through M2, **Medium** M3–M5, **Low** beyond M5 — replan at each phase gate |

**Estimates are planning instruments, not commitments.** The exit criteria are the commitment; the
dates are the current best model of when they will be met.

---

## 2. Milestone map

```text
Phase 0 ──── M0 Foundations
                │
Phase 1 ──── M1 Content core ──── M2 Access & delivery ──┐
                                                         ├── M4 Governance baseline ── M5 MVP GA
                              M3 Discovery ──────────────┘
                                                              │
Phase 2 ──── M6 Enterprise identity ──┐                       │
             M7 AI & BYO infra ───────┼── M10 Enterprise V1 GA
             M8 Delivery surfaces ────┤
             M8b Content migration ───┤
             M9 Workflows & signing ──┘
```

| # | Milestone | Phase | Duration | Cumulative | Target |
|---|---|---|---|---|---|
| M0 | Foundations | 0 | 5 weeks | 5 w | 2026-10-03 |
| M1 | Content core | 1 | 6 weeks | 11 w | 2026-11-14 |
| M2 | Access & delivery | 1 | 5 weeks | 16 w | 2026-12-19 |
| M3 | Discovery | 1 | 5 weeks | 19 w¹ | 2027-01-16 |
| M4 | Governance baseline | 1 | 4 weeks | 23 w | 2027-02-13 |
| M5 | **MVP GA** | 1 | 4 weeks | 27 w | 2027-03-13 |
| M6 | Enterprise identity & governance | 2 | 8 weeks | 35 w | 2027-05-08 |
| M7 | AI & BYO infrastructure | 2 | 7 weeks | 40 w¹ | 2027-06-12 |
| M8 | Delivery surfaces | 2 | 8 weeks | 46 w¹ | 2027-07-24 |
| M8b | Content migration | 2 | 5 weeks | 48 w¹ | 2027-08-07 |
| M9 | Workflows & signing | 2 | 7 weeks | 52 w¹ | 2027-09-04 |
| M10 | **Enterprise V1 GA** | 2 | 5 weeks | 57 w | 2027-10-09 |

¹ Cumulative is less than the sum because M3 runs partly parallel to M2, and M7–M9 run partly
parallel to M6. See `§4`.

**M8b moved Enterprise V1 GA by two weeks, from 2027-09-25 to 2027-10-09.** Stated here rather than
absorbed, because `§8` requires promoted scope to carry its knock-on effect. Content migration
partly parallelises with M9 — different people, different subsystems — so five weeks of work costs
two weeks of schedule. It is not optional work: an enterprise does not replace a document system
without a path off the old one, so the alternative to the two weeks is a product nobody can adopt.

**Two dates matter to the business: MVP GA around 2027-03-13, Enterprise V1 GA around 2027-10-09.**
Everything else is internal sequencing.

---

## 3. The critical path

Seven items gate everything downstream. Delay in any of these delays the release; delay elsewhere
usually does not.

```text
ENC-104 db + TenantScoped
   └─ ENC-105 migration 001 + RLS
        └─ ENC-109 PolicyEngine::enforce
             └─ ENC-208 ACL resolution
                  └─ ENC-215 search post-filter
                       └─ ENC-224 leakage matrix green
                            └─ M5 MVP GA
```

Consequences of that shape, which drove the ordering below:

- **The policy engine is built before any feature that uses it.** Retrofitting a chain into handlers
  that already query the database directly is the single most expensive mistake available here.
- **The search post-filter is built with the first search, not after it.** It is the mechanism that
  makes index staleness a performance problem instead of a data leak (`docs/07 §6`).
- **RLS lands in migration 001.** Adding it to fifty existing tables later means auditing fifty
  tables; adding it first means the CI gate keeps it true for free.

---

## 4. Parallel tracks

Three tracks run concurrently once M0 completes. This is what turns ~90 engineer-weeks of scope into
~55 calendar weeks.

| Track | Owns | Runs |
|---|---|---|
| **Core** (2 backend) | Policy chain, content, ACL, governance | Continuous, on the critical path |
| **Platform** (1 backend + 1 SRE) | Storage, AV, indexing, search, BYO providers, deploy | From M1; feeds Core |
| **Experience** (2 frontend) | Web app, i18n, accessibility, admin UX | From M1, one milestone behind Core |

Frontend deliberately trails backend by one milestone. Building UI against an unstable API produces
rework, and the API stabilizes at the end of each milestone, not the start.

The fourth backend engineer floats to whatever is on the critical path — this is the schedule's
shock absorber, and it is the first thing consumed when an estimate is wrong.

---

## 5. Milestones in detail

### M0 — Foundations · 5 weeks · Phase 0

**Goal.** A request can traverse the full policy chain against a real database, and CI enforces the
structural rules that keep it that way.

**Tracker:** ENC-100 … ENC-115 · **Plan:** [`plans/M0-FOUNDATIONS.md`](plans/M0-FOUNDATIONS.md)

**Steps, in order**

1. Cargo workspace and crate skeletons per `docs/02 §4`; every crate compiles empty (ENC-100).
2. CI: `fmt`, `clippy -D warnings`, `test`, plus the structural gate harness (ENC-101).
3. `config` — layered precedence, secret references, startup validation (ENC-102).
4. `core` — typed IDs, `RequestContext`, `Actor`, the `Error` enum (ENC-103).
5. `db` — pool, migration runner, `TenantScoped` query guard (ENC-104).
6. Migration 001 — tenants, users, groups, credentials, refresh tokens, audit, outbox — **with RLS
   enabled and forced on every tenant-scoped table** (ENC-105).
7. RLS coverage CI gate: fails the build on any `tenant_id` table without a forced policy (ENC-106).
8. `audit` — append-only writes, hash chain, `INSERT`/`SELECT`-only role (ENC-107).
9. `events` — transactional outbox, JetStream publisher, idempotent consumer helper (ENC-108).
10. `PolicyEngine::enforce` with all six stages wired to stub services that deny by default (ENC-109).
11. Policy-routing CI gate: every route handler provably reaches the engine (ENC-110).
12. `auth` — Argon2id, JWT issue/verify, refresh rotation with reuse detection (ENC-111).
13. Test harness: testcontainers, `tenant-alpha` / `tenant-beta` fixtures (ENC-112).
14. Dev Compose stack (ENC-113); OTel wiring (ENC-114); `enclave-cli seed` (ENC-115).

**Exit criteria**

- [ ] One end-to-end request: login → JWT → `enforce` → tenant-scoped query → audit row.
- [ ] Cross-tenant read fails **with the application predicate deliberately removed** (T5).
- [ ] Refresh rotation works; replaying a consumed token revokes the family (K3, K4).
- [ ] All four structural CI gates fail correctly when deliberately violated.
- [ ] `docker compose up` → healthy stack on a clean machine, documented in `CONTRIBUTING.md`.

**Risks.** RLS interacts badly with connection pooling if `SET LOCAL` is misused — prove it in week 1
with a pool-exhaustion test, not in month 6. Stub services that default to *allow* would quietly
disable the chain; they default to deny.

---

### M1 — Content core · 6 weeks · Phase 1

**Goal.** Content can be stored and versioned safely. Nothing is readable before it is scanned.

**Tracker:** ENC-200 … ENC-207

**Steps**

1. Tenancy, users, groups, memberships, invitations (ENC-200).
2. Local auth end-to-end; OIDC; LDAP bind (ENC-201).
3. Workspaces and libraries with settings and inheritance flags (ENC-202).
4. Files and folders: create, rename, reparent, trash, restore, move/copy (ENC-203).
5. `storage` — S3-compatible `BlobStore`, capability probing, public-access self-check (ENC-204).
6. Upload: session state machine, multipart, signed URLs, checksum verification (ENC-205).
7. Versions: immutable rows, atomic commit with outbox and audit, restore (ENC-206).
8. `antivirus` + ClamAV; **no version reaches `AVAILABLE` without a clean verdict** (ENC-207).

**Exit criteria**

- [ ] 5 GB resumable upload with flat API memory.
- [ ] Version rows reject mutation of `object_key`, `checksum`, `size`, `major`, `minor`.
- [ ] EICAR upload → `QUARANTINED`, unreadable through every path, incident raised (G1).
- [ ] AV down with `HOLD` → uploads wait in `SCANNING`, existing content unaffected (G6).
- [ ] Sibling name collision rejected by constraint, not by application check alone.

---

### M2 — Access & delivery · 5 weeks · Phase 1

**Goal.** Granular permissions actually work, and preview is genuinely separable from download.

**Tracker:** ENC-208 … ENC-212

**Steps**

1. ACL resolution: inheritance chain, transitive group closure, deny-wins, break-inheritance
   (ENC-208).
2. `authorize_many` batch path — required later by search; built now (ENC-208).
3. Rendition pipeline: sandboxed generation, base cache, per-request watermark composition (ENC-209).
4. Preview API with no original URL on the view-only path; download API as `POST` with audit before
   URL issuance (ENC-209).
5. Share links: token hashing, password/OTP, expiry, atomic download budget (ENC-210).
6. Metadata fields, values, content types (ENC-211).
7. Views + cursor pagination + `capabilities` on every file response (ENC-212).

**Exit criteria**

- [ ] `preview=ALLOW, download=DENY` produces a rendition and **no** signed original URL (A1).
- [ ] A `DENY` beats an inherited `ALLOW` at every level (A3).
- [ ] `max_downloads` holds under 50 concurrent redemptions — exactly N succeed (H3).
- [ ] Watermarked output is never written to the rendition cache.
- [ ] Cursor from one tenant rejected in another (T3).

---

### M3 — Discovery · 5 weeks · Phase 1 · *starts in M2 week 3*

**Goal.** Search that cannot leak, and that degrades honestly when its index is unavailable.

**Tracker:** ENC-213 … ENC-216

**Steps**

1. Extraction (PDF, OOXML, text) in a sandboxed worker; structure parsing (ENC-213).
2. **OCR for scanned pages** — engine, language coverage and cost decided rather than assumed
   (ENC-161). Not a fallback bolted to the end of extraction: scanned PDFs are a large share
   of what enterprises actually store, and a scanned document that indexes as empty is
   invisible to search while appearing correctly filed, which is worse than one that failed
   to ingest.
3. Structure-aware chunking with deterministic chunk IDs (ENC-213).
4. Embedding provider trait + local model; classification routing enforced in code (ENC-213).
5. Milvus `VectorStore`; collection, indexes, hybrid query (ENC-214).
6. **Authoritative post-filter with batch authorization and over-fetch** (ENC-215).
7. Denylist written in the same transaction as the ACL change; invalidation worker; epoch
   reconciler (ENC-216).
8. Degraded mode: Milvus down → lexical over PostgreSQL with `degraded: true` (ENC-214).

**Exit criteria**

- [ ] S3: revoked file vanishes from results **immediately**, before any index update.
- [ ] S4: S3 still holds with the invalidation worker stopped.
- [ ] S5: deliberately over-permissive index candidates are dropped by the post-filter.
- [ ] S8: `RESTRICTED` text never reaches a non-local embedding provider.
- [ ] Post-filter drop ratio and denylist size exported as metrics with alerts wired.
- [ ] A scanned, text-free PDF is searchable by its content (ENC-161).

**Measured before this milestone starts (`ENC-145`).** `authorize_many` resolves 200 candidates in **p50 7.0 ms** (debug build), and one candidate in 1.4 ms — so the post-filter's cost is ~80% fixed: transaction setup plus three round trips, not candidate count. That inverts the obvious intuition twice over. Raising over-fetch is nearly free; adding a *second* resolution pass costs more than tripling the batch. Whether result disclosure and excerpt disclosure can be answered in one call is therefore a design decision to take before the search path sets, not after (`ENC-167`).

**Risks.** This milestone contains the highest-severity design risk in the product. It gets the most
senior reviewer and a written threat walkthrough before merge, not just tests.

---

### M4 — Governance baseline · 4 weeks · Phase 1

**Goal.** A tenant can be told no, for the right reasons, with an audit trail.

**Tracker:** ENC-217 … ENC-220

**Steps**

1. DLP detectors, `SecurityFacts`, sync evaluation with `facts_unavailable` handling (ENC-217).
2. DLP modes incl. simulation; obligations returned and enforced as `#[must_use]` (ENC-217).
3. Conditional access: zones, geo/ASN, trusted-proxy hop handling, effects (ENC-218).
4. Quotas: transactional enforcement, soft-limit notification, nightly reconciliation (ENC-219).
5. Audit coverage sweep — every enforcement point, allow and deny (ENC-220).

**Exit criteria**

- [ ] D1–D4 green: enforce blocks, simulation records only, missing facts fail closed, dropped
      obligation fails the operation.
- [ ] Forged `X-Forwarded-For` from an untrusted peer is ignored.
- [ ] Quota exhaustion blocks writes while reads, deletes and exports keep working.
- [ ] Every row in the audit table maps to a real enforcement point; no silent successes.

---

### M5 — MVP GA · 4 weeks · Phase 1

**Goal.** A real team could use this daily. Ship it.

**Tracker:** ENC-221 … ENC-226

**Steps**

1. Web shell: navigation, command bar, `⌘K` palette, details panel (ENC-221).
2. Virtualized file views; upload UX with true states through to `Ready` (ENC-222).
3. i18n scaffolding, `en-US` catalog, `en-XA`/`en-XB` pseudo-locales in CI (ENC-223).
4. Leakage matrix §4.1–4.6 implemented and green (ENC-224).
5. `community` deployment profile, install docs, upgrade path (ENC-225).
6. Accessibility: axe gate, keyboard flows, screen-reader pass (ENC-226).
7. Release hardening: load test at budget, chaos pass, restore drill, docs review.

**Exit criteria — the MVP gate**

- [ ] Every P1 in Phase 1 `DONE`.
- [ ] Leakage matrix §4.1–4.6 green, zero skips.
- [ ] Performance budgets met: metadata P95 < 300 ms, search P95 < 500 ms, 100k-item folder
      first paint < 400 ms.
- [ ] Restore drill executed end to end and documented.
- [ ] axe clean on every primary route; keyboard-only walkthrough completed.
- [ ] A new operator can install from `README` on a clean machine without asking a question.
- [ ] External penetration test scoped to `docs/12 §4` — no unresolved high findings.

---

### M6 — Enterprise identity & governance · 8 weeks · Phase 2

**Tracker:** ENC-300 … ENC-306

Federation and the compliance controls enterprises buy for. SAML with XSW/XXE hardening; SCIM with
the mass-deactivation guard; WebAuthn and step-up; advanced DLP; information barriers; retention,
records and legal hold; incidents and SIEM forwarding.

**Exit criteria**

- [ ] SAML rejects XSW1–XSW8, XXE and assertion replay.
- [ ] A deliberately broken LDAP filter trips the mass-deactivation guard and applies nothing.
- [ ] Legal hold blocks deletion for owners, admins **and** the retention scheduler (D5).
- [ ] A declared record refuses modification until `immutable_until` (D6).
- [ ] Barrier-segmented content is excluded at query time, not result time (S10).
- [ ] SIEM outage buffers locally and drops nothing.

---

### M7 — AI & BYO infrastructure · 7 weeks · Phase 2 · *overlaps M6*

**Tracker:** ENC-307 … ENC-309, ENC-316

MCP gateway with scopes and classification ceilings; RAG answers with mandatory citations; `LlmProvider`
with classification routing; BYO storage profiles, Vault, KMS, SMTP, AV; Milvus HA and an exercised
rebuild runbook.

**Exit criteria**

- [ ] D7: MCP cannot return content above its ceiling even when the acting user could read it.
- [ ] S7: an answer without citable, readable sources is not returned.
- [ ] S8 extended: `RESTRICTED` content never reaches a non-local LLM.
- [ ] A tenant configures BYO storage + Vault + SMTP + AV entirely through the admin UI, with working
      "test connection" for each.
- [ ] Index rebuild executed against a populated tenant, with search live throughout.

---

### M8 — Delivery surfaces · 8 weeks · Phase 2 · *overlaps M6/M7*

**Tracker:** ENC-310 … ENC-312

White-labeling, custom domains with certificate automation, desktop/mobile sync, external editor
brokering, and the two document surfaces a DMS is expected to have:

- **Annotations and markup** (ENC-160). Not a viewer feature bolted on: an annotation is user
  content stored against an immutable version, it must respect `PREVIEW_ONLY`, and it is
  discoverable — so it carries a classification and an ACL of its own.
- **Version compare** (ENC-162). `docs/02` has listed "compare hooks" on the `versions` crate since
  the beginning without any document saying what compare does. Immutable versions make it tractable,
  and it is one of the two reasons anyone opens a version history.

**Exit criteria**

- [ ] Y1: a no-download file is never `syncEligible` and its bytes are refused.
- [ ] Y3: revoked access produces a reasoned tombstone, never a silent omission.
- [ ] Y4: a conflicting upload produces a conflicted copy; nothing is discarded.
- [ ] Y5/Y6: editor tokens are single-version; client-side editors refused for no-download content.
- [ ] A custom domain is verified, issued a certificate and routed to the right tenant end to end.
- [ ] An annotation on a `PREVIEW_ONLY` version is readable by its author and by nobody the
      file's ACL excludes (ENC-160).

---

### M8b — Content migration · 5 weeks · Phase 2 · *overlaps M9*

**Goal.** An enterprise can bring its existing document estate in, with its history intact.

**Tracker:** ENC-159

Added 2026-08-20 rather than planned from the start, and worth saying why: the spec pack described
a product that stores documents beautifully and had no answer to *"we have four terabytes in
SharePoint."* That is not a missing feature, it is a missing adoption path, and it was invisible
because every document was written from the inside out.

**Steps**

1. A migration specification, before any code. The shape of the importer constrains the ingest API,
   so getting it wrong is expensive in a way the other milestones' unknowns are not.
2. Source connectors: SharePoint/OneDrive, NetDocuments, iManage, and a plain file share — the last
   because it is what most of the long tail actually is.
3. Fidelity: version history, metadata, and permissions. A migration that flattens history destroys
   the record it was supposed to preserve, and one that drops permissions silently opens everything
   it touches.
4. Resumability and reconciliation. A four-terabyte migration will be interrupted; it must resume
   without duplicating and must be able to prove what did and did not arrive.
5. Dry-run mode with a per-item report, so a customer sees what will happen before it does.

**Exit criteria**

- [ ] A source item with ten versions arrives as ten versions, in order, with their timestamps and
      authors — not as one file with the latest bytes.
- [ ] Permissions map to `acl_entries` or the item is **refused**, never imported wide open. An
      unmappable ACL is a failure with a reason, not a default.
- [ ] An interrupted migration resumes without duplicating, and reconciliation reports the
      difference between source and destination by count and by checksum.
- [ ] Nothing imported is readable before antivirus completes — the same rule as any other ingest
      path (`CLAUDE.md` rule 9), which is why this is a milestone and not a script.
- [ ] Dry run produces a report a customer can read and a rollback that leaves nothing behind.

---

### M9 — Workflows & signing · 7 weeks · Phase 2 · *overlaps M8*

**Tracker:** ENC-313 … ENC-315

Workflow engine, approvals, and the signing pipeline through PAdES with TSA and LTV; external
signature providers.

**Exit criteria**

- [ ] W1: a workflow grants no access the actor does not independently hold.
- [ ] N1: presented bytes hash to the seal; a mismatch aborts.
- [ ] N4: post-signature modification is reported as `DOCUMENT_MODIFIED`.
- [ ] N5: no private key reaches the server in `DIGITAL_SIGNER_CERT` mode.
- [ ] N7: verification succeeds with the provider unreachable, from embedded LTV material.

---

### M10 — Enterprise V1 GA · 5 weeks · Phase 2

**Tracker:** ENC-317 … ENC-319

**Steps.** Full leakage matrix green; HA deployment profile; DR drill; Tier 1 + Tier 2 locales;
performance at enterprise scale; documentation and runbook completeness; external penetration test;
release engineering — signed artifacts, SBOM, upgrade path from MVP.

**Exit criteria — the Enterprise gate**

- [ ] Every P1 in Phase 2 `DONE`.
- [ ] Leakage matrix §4.1–4.10 green, zero skips.
- [ ] DR drill: RPO ≤ 5 min, RTO ≤ 4 h, demonstrated not asserted.
- [ ] Chaos suite passes for every row in `docs/02 §24`.
- [ ] Upgrade from the MVP release verified with real data.
- [ ] Penetration test complete, no unresolved high or critical findings.
- [ ] Every alert in `docs/11 §10` links to a runbook that resolves it.

---

## 6. Phase gates

A gate is a decision point, not a formality. At each one:

1. Confirm every P1 in the phase is `DONE` — not "effectively done".
2. Run the full leakage matrix and record the result in `TRACKER.md §6`.
3. Re-assess priorities for the next phase; promote or drop P3s.
4. Re-estimate the next phase using actual velocity, and update `§2` if it moved by more than 15%.
5. Write down what the estimates got wrong and why. This is the only mechanism that makes the next
   estimate better.

| Gate | When | Decision |
|---|---|---|
| G0 | End of M0 | Are the foundations sound enough to build on? If the policy chain or RLS is shaky, fix before proceeding — this is the cheapest moment. |
| G1 | End of M5 | Ship the MVP? |
| G2 | End of M10 | Ship Enterprise V1? |

---

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Search post-filter is slower than budget at scale | Medium | High | Batch authorization built in M2, benchmarked in M3 against 200-candidate pages before the design sets |
| RLS + pooling interaction causes leaks or churn | Low | Critical | Proven in M0 week 1 with a pool-exhaustion test; CI gate keeps coverage total |
| Milvus operational burden underestimated | Medium | Medium | HA and rebuild runbook exercised in M7, not deferred to M10 |
| Document extraction is a wide attack surface | High | High | Sandboxed workers, no egress, bounded resources, fuzzing in M3 |
| Embedding cost at enterprise volume | Medium | Medium | Cost model measured in M3 on real corpora; local model is the default path |
| Frontend blocked by unstable API | Medium | Medium | Experience track runs one milestone behind; API frozen at each milestone end |
| Signing legal requirements vary by jurisdiction | Medium | Medium | Modes are separated and labelled (`docs/15 §6.2`); the product states evidence, counsel judges validity |
| Scope creep from mid-flight requests | **High** | High | `TRACKER.md §2` — logged, prioritized, queued. No pivoting. |
| Estimates beyond M5 drift | High | Medium | Low confidence declared up front; re-estimated at every gate |

The last two are the ones that actually kill schedules like this one. Both are process problems with
process answers, and both answers are written down.

---

## 8. Explicitly deferred

Not in the plan before Enterprise V1 GA, by decision rather than omission
(`docs/01-PRD.md §3`): offline sync merge, in-house real-time co-authoring, Azure Blob and GCS
adapters, additional vector stores, advanced eDiscovery export, Tier 3 locales, and a Power
Automate/Power Apps equivalent.

Anything here that becomes necessary is promoted through `TRACKER.md §2.2` like any other request —
with its cost and its knock-on effect on the dates in `§2` stated at the time.

**Promoted on 2026-08-20**, all four raised as one question — *"are we handling DMS?"* — against a
spec pack that turned out to answer most of it and be silent on the rest:

| Was | Now | Why it was not visible |
|---|---|---|
| Migration from an existing DMS — unmentioned | **M8b** (`ENC-159`) | Every document was written from the inside out. Nothing asked how content *gets here*. |
| Annotations — unmentioned | M8 (`ENC-160`) | Reads as a viewer feature; is actually versioned, classified, ACL'd user content. |
| OCR — one line in `docs/07`, as a fallback | M3 (`ENC-161`) | "Fallback when a page yields no text" quietly assumes scanned documents are the exception. |
| Version compare — a crate-list entry | M8 (`ENC-162`) | `docs/02` has listed "compare hooks" since the start; no document ever said what compare does. |

Check-in/check-out, content types, records management, legal hold, retention and templates were
already specified — the gaps were the four above and no others.

---

## 9. First two weeks

Concrete, so M0 starts on a Monday rather than in a planning meeting.

| Day | Work |
|---|---|
| 1–2 | Repo scaffolding, Cargo workspace, empty crates compiling, `main` protected |
| 3–4 | CI skeleton: fmt, clippy, test on every PR |
| 5 | Compose stack up; every dependency reachable from a smoke test |
| 6–7 | `core` types; `Error`; `RequestContext` |
| 8–9 | `db` crate, `TenantScoped`, migration runner |
| 10 | **Migration 001 with RLS — and the pool/`SET LOCAL` proof test** |
| 11–12 | RLS coverage gate; cross-tenant test T5 with the predicate removed |
| 13–14 | `audit` append-only + hash chain; first audited request end to end |

If day 10 goes badly, the schedule moves. That is why it is on day 10 and not in month three.
