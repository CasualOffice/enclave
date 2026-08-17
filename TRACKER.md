# TRACKER

> **The single source of truth for what is being worked on, in what order.**
> Enclave · Casual Office · Last updated: 2026-08-18
> Roadmap and exit criteria: [`ROADMAP.md`](ROADMAP.md)

Every piece of work — feature, bug, doc, chore, and every new request from anyone — exists as a row
in this file before it is started. If it is not here, it is not being worked on.

---

## 1. Priority grading

Priority is assigned at intake, by the person or agent logging the item, using this rubric. It is not
a vote and not negotiable by enthusiasm — it is a question of what breaks if the item is not done.

| Grade | Meaning | Response |
|---|---|---|
| **P0** | Stop everything. Security vulnerability, data loss or corruption risk, `main` build broken, CI red, production incident, or a regression in work that just landed. | Preempts the in-flight item immediately. Fix, verify, then resume. |
| **P1** | Phase blocker. The current phase cannot be declared complete without it. | Next up. Worked in listed order. |
| **P2** | Planned. Belongs to a later phase, or is quality/DX/hardening work that is scheduled but not blocking. | Queued behind all P1s of the current phase. |
| **P3** | Deferred. Worth doing, not scheduled. Revisited at each phase boundary. | Not started without an explicit decision to promote it. |

**Automatic P0s**, no judgement call required: any failing CI job on `main`; any test in the security
leakage matrix (`docs/12-TESTING.md §4`) failing or skipped; any finding in scope of `SECURITY.md`;
any migration that has left an environment un-bootable.

**Priority is re-assessed only at phase boundaries**, or when a P0 arrives. Mid-phase reshuffling is
how a backlog stops meaning anything.

---

## 2. Working rules

### 2.1 One thing at a time — no pivoting

1. **Exactly one item may be `IN PROGRESS`.** Not two, not "a small one alongside".
2. **Do not start a new item while one is in progress.** A new request is logged with a priority and
   waits its turn.
3. **Only three things interrupt in-flight work:**
   - an explicit instruction from the repo owner to switch;
   - a **P0**;
   - a bug or CI failure in work that just landed (which is a P0 by definition).
4. **On interruption**, the in-flight item moves to `PAUSED` with a one-line note recording exactly
   where it stopped and what remains. It is resumed the moment the interrupt clears — before anything
   else is started.
5. **Scope discovered mid-task becomes a new row, not a bigger current task.** If while doing
   `ENC-101` you find that `ENC-101` also needs X, log X as its own item and finish what was scoped.
   The only exception is when the current item is genuinely broken without X, in which case say so
   explicitly in the row's note rather than expanding silently.
6. **Finish means finished**: code, tests, docs updated in the authoritative place, CI green. A row
   does not move to `DONE` with "just the tests left".

### 2.2 Intake — every new request lands here

When a new request arrives, before any work starts:

1. Add a row to the correct phase section in `§4`.
2. Assign an ID (`ENC-nnn`, next free number in the item's phase block, never reused).
3. Assign a priority using the `§1` rubric, and state the reasoning in the note if it is not obvious.
4. Assign a phase. A request that does not fit the current phase goes to the phase where it belongs —
   it does not jump the queue because it is new.
5. Record the date and the requester.
6. **Then say what was logged, at what priority, and when it will be picked up** — do not silently
   absorb a request into whatever is currently in flight.

Requests that arrive mid-task are logged immediately and worked in priority order afterwards. The
only request that changes what happens *right now* is an explicit "do this instead" or a P0.

### 2.3 ID scheme

IDs are `ENC-nnn`, blocked by phase so a number tells you where the work belongs:

| Block | Phase |
|---|---|
| `ENC-001`–`ENC-099` | D — Specification |
| `ENC-100`–`ENC-199` | 0 — Foundations |
| `ENC-200`–`ENC-299` | 1 — MVP |
| `ENC-300`–`ENC-399` | 2 — Enterprise V1 |
| `ENC-400`–`ENC-499` | 3 — Beyond V1 |

Numbers are never reused, including after a row is dropped.

### 2.4 Status values

| Status | Meaning |
|---|---|
| `TODO` | Logged, prioritized, not started |
| `WIP` | In progress — **at most one row in the whole file** |
| `PAUSED` | Started, interrupted, with a note on where it stopped |
| `BLOCKED` | Cannot proceed; the blocker is named in the note |
| `REVIEW` | Complete, awaiting review or verification |
| `DONE` | Merged, tests green, docs updated |

### 2.5 Phase discipline

A phase is complete when **every P1 in it is `DONE`**. P2 and P3 items do not block a phase boundary;
they roll forward. At each boundary: re-assess remaining priorities, promote or drop P3s, and record
the boundary in `§6`.

Work does not start on the next phase's items while the current phase has open P1s — unless an item
is a prerequisite that turned out to be needed earlier, in which case it is *moved* into the current
phase, not worked out of band.

---

## 3. Active board

**In progress:** `ENC-109` — policy engine (branch `feat/enc-109-policy-engine`)

**Plan for the current milestone:** [`plans/M0-FOUNDATIONS.md`](plans/M0-FOUNDATIONS.md)

**Next three, in order:** `ENC-110` (routing gate), `ENC-112` (test harness — unblocks the 18
ignored database tests), `ENC-113` (Compose stack). Then the two P2s close Phase 0.

> **Deviation from §2.1, recorded deliberately.** The repo owner directed parallel execution of the
> M0 foundation crates on 2026-08-18. Seven items are in flight at once rather than one. This is
> sound here only because the tasks touch disjoint directories and share no files, and because an
> integration step (`cargo check`/`clippy`/`test` across the workspace, by one person) follows before
> anything is marked `DONE`. It is not the new default: the rule resumes at `ENC-106`.

**Paused / blocked:** none.

**Open P0s:** none.

---

## 4. Phase trackers

Rows here are authoritative. `§3` and `§5` are views over them and must not disagree.

### Phase D — Specification *(complete)*

Design pack. Exit criterion: every subsystem specified, no contradictions between documents.

| ID | Item | Pri | Status | Note |
|---|---|---|---|---|
| ENC-001 | Reorganize docs into an ordered, single-source pack | P1 | DONE | 17 docs, cross-refs verified |
| ENC-002 | Reconcile crate list and enforcement chain contradictions | P0 | DONE | Two docs disagreed on both |
| ENC-003 | Complete data model — all DDL, RLS, quotas | P1 | DONE | `docs/04` |
| ENC-004 | API surface, error model, pagination, idempotency | P1 | DONE | `docs/05` |
| ENC-005 | Search/indexing spec incl. ACL invalidation | P0 | DONE | Highest-risk gap in the original pack |
| ENC-006 | Sync clients + external editor design | P1 | DONE | `docs/10` |
| ENC-007 | Operations: SLOs, runbooks, backup/DR, rotation | P1 | DONE | `docs/11` |
| ENC-008 | Test strategy + security leakage matrix | P1 | DONE | `docs/12` |
| ENC-009 | JWT access tokens + rotating refresh tokens | P1 | DONE | Requested 2026-08-18; replaced opaque sessions |
| ENC-010 | Identity: OIDC, SAML, LDAP, SCIM, JIT, guests | P1 | DONE | Requested 2026-08-18 · `docs/13` |
| ENC-011 | i18n / l10n specification | P1 | DONE | Requested 2026-08-18 · `docs/14` |
| ENC-012 | BYO LLM provider + classification routing | P1 | DONE | Requested 2026-08-18 · `docs/08 §12` |
| ENC-013 | Workflows, approvals and document signing | P1 | DONE | Requested 2026-08-18 · `docs/15` |
| ENC-014 | Repo files: README, CLAUDE, SKILLS, CONTRIBUTING, SECURITY, LICENSE | P1 | DONE | Apache-2.0 |
| ENC-015 | Apply `casualoffice` org and `casualoffice.org` domain | P2 | DONE | Requested 2026-08-18 |
| ENC-016 | This tracker + working rules | P1 | DONE | Requested 2026-08-18 |
| ENC-017 | `security.txt` + PGP key published at casualoffice.org | P2 | TODO | `SECURITY.md` points at it; must exist before public release |
| ENC-018 | Confirm legal entity name on the LICENSE copyright line | P2 | TODO | Currently "Casual Office" |
| ENC-019 | Development roadmap: milestones, gates, sequencing, risks | P1 | DONE | Requested 2026-08-18 · `ROADMAP.md` |
| ENC-020 | Product rename Vault → Enclave; ID prefix `VLT-` → `ENC-` | P1 | DONE | Requested 2026-08-18. HashiCorp Vault references deliberately preserved |
| ENC-021 | Rename the working directory `services/vault` → `services/enclave` | P2 | TODO | Filesystem-level; left to the repo owner to avoid breaking active paths |
| ENC-022 | Initialize git repository, initial history, remote on `CasualOffice/enclave` | P1 | DONE | Requested 2026-08-18 · branch `main`, private |
| ENC-023 | M0 implementation plan (`plans/M0-FOUNDATIONS.md`) | P1 | DONE | Requested 2026-08-18 · task-level breakdown for Phase 0 |

### Phase 0 — Foundations

Nothing ships without these. Exit criterion: a request can traverse the full policy chain against a
real database, with CI enforcing the structural gates.

| ID | Item | Pri | Status | Depends on |
|---|---|---|---|---|
| ENC-100 | Cargo workspace, crate skeletons per `docs/02 §4` | P1 | DONE | 43 crates; check/clippy/fmt clean |
| ENC-101 | CI: fmt, clippy, test, structural gates (`docs/12 §5`) | P1 | DONE | ENC-100 |
| ENC-102 | `config` crate — layered config + secret references | P1 | DONE | ENC-100 |
| ENC-103 | `core` crate — typed IDs, `RequestContext`, `Error` | P1 | TODO | ENC-100 |
| ENC-104 | `db` crate — pool, migrations, `TenantScoped` guard | P1 | DONE | ENC-103 |
| ENC-105 | Migration 001: tenancy, identity, RLS policies | P1 | DONE | ENC-104 |
| ENC-106 | RLS coverage CI gate — fails on any unprotected table | P0 | DONE | ENC-105 |
| ENC-107 | `audit` crate — append-only writes, hash chain | P1 | DONE | ENC-104 |
| ENC-108 | `events` crate — outbox, JetStream publish, idempotency | P1 | DONE | ENC-104 |
| ENC-109 | `PolicyEngine::enforce` skeleton, all six stages wired | P1 | DONE | ENC-103, ENC-107 |
| ENC-110 | Policy-routing CI gate — every handler reaches the engine | P1 | TODO | ENC-109 |
| ENC-111 | `auth` crate — Argon2id, JWT issue/verify, refresh rotation | P1 | DONE | ENC-105 |
| ENC-112 | Test harness: testcontainers + `tenant-alpha`/`tenant-beta` fixtures | P1 | TODO | ENC-105 |
| ENC-113 | Dev Compose stack: PG, Redis, NATS, MinIO, Milvus, ClamAV | P1 | TODO | — |
| ENC-114 | OpenTelemetry wiring + span attribute conventions | P2 | TODO | ENC-103 |
| ENC-115 | `enclave-cli seed` for dev tenants | P2 | TODO | ENC-112 |

### Phase 1 — MVP

Per `docs/01-PRD.md §37`. Exit criterion: a tenant can store, find, share and govern content, with
the leakage matrix green.

| ID | Item | Pri | Status | Depends on |
|---|---|---|---|---|
| ENC-200 | Tenancy, users, groups, memberships | P1 | TODO | Phase 0 |
| ENC-201 | Local auth + OIDC + LDAP bind | P1 | TODO | ENC-111 |
| ENC-202 | Workspaces and libraries | P1 | TODO | ENC-200 |
| ENC-203 | Files, folders, trash, move/copy | P1 | TODO | ENC-202 |
| ENC-204 | `storage` crate — S3-compatible `BlobStore` | P1 | TODO | ENC-102 |
| ENC-205 | Upload state machine + multipart + signed URLs | P1 | TODO | ENC-204 |
| ENC-206 | Immutable versions + restore | P1 | TODO | ENC-203 |
| ENC-207 | `antivirus` crate + ClamAV; nothing `AVAILABLE` before clean | P0 | TODO | ENC-205 |
| ENC-208 | ACL resolution: inheritance, group closure, deny-wins | P1 | TODO | ENC-200 |
| ENC-209 | Preview/download split + rendition pipeline | P1 | TODO | ENC-206, ENC-208 |
| ENC-210 | Share links: hashing, password, expiry, download budget | P1 | TODO | ENC-208 |
| ENC-211 | Metadata fields, values, content types | P1 | TODO | ENC-202 |
| ENC-212 | Library views (list, grid, details, tree) + cursor pagination | P1 | TODO | ENC-211 |
| ENC-213 | Extraction + chunking pipeline | P1 | TODO | ENC-207 |
| ENC-214 | Milvus `VectorStore` + hybrid retrieval | P1 | TODO | ENC-213 |
| ENC-215 | **Authoritative search post-filter** (`docs/07 §6.2`) | P0 | TODO | ENC-214, ENC-208 |
| ENC-216 | Retrieval denylist + invalidation worker | P1 | TODO | ENC-215 |
| ENC-217 | Basic DLP: detectors, security facts, monitor/enforce | P1 | TODO | ENC-213 |
| ENC-218 | Geo/IP conditional access + trusted proxy handling | P1 | TODO | ENC-109 |
| ENC-219 | Quotas: enforcement at write, nightly reconciliation | P1 | TODO | ENC-205 |
| ENC-220 | Audit coverage for every enforcement point | P1 | TODO | ENC-107 |
| ENC-221 | Web shell: nav, command bar, details panel | P1 | TODO | ENC-202 |
| ENC-222 | Web: virtualized file views + upload UX with true states | P1 | TODO | ENC-221 |
| ENC-223 | i18n scaffolding + `en-US` catalog + pseudo-locales | P1 | TODO | ENC-221 |
| ENC-224 | Security leakage matrix §4.1–4.6 implemented and green | P0 | TODO | ENC-215, ENC-210 |
| ENC-225 | Docker deployment profile `community` | P1 | TODO | ENC-113 |
| ENC-226 | Accessibility pass: axe gate + keyboard flows | P2 | TODO | ENC-222 |

### Phase 2 — Enterprise V1

| ID | Item | Pri | Status | Depends on |
|---|---|---|---|---|
| ENC-300 | SAML 2.0 (incl. XSW/XXE hardening) | P1 | TODO | Phase 1 |
| ENC-301 | SCIM 2.0 service provider + mass-deactivation guard | P1 | TODO | ENC-200 |
| ENC-302 | WebAuthn / passkeys + step-up | P1 | TODO | ENC-111 |
| ENC-303 | Advanced DLP: full detector set, simulation, obligations | P1 | TODO | ENC-217 |
| ENC-304 | Information barriers | P1 | TODO | ENC-208 |
| ENC-305 | Retention, records, legal hold | P1 | TODO | ENC-203 |
| ENC-306 | Incidents + SIEM forwarding | P1 | TODO | ENC-220 |
| ENC-307 | MCP gateway: tools, scopes, classification ceilings | P1 | TODO | ENC-215 |
| ENC-308 | RAG answers with citations + BYO LLM routing | P1 | TODO | ENC-307 |
| ENC-309 | BYO infra: storage profiles, Vault, KMS, SMTP, AV | P1 | TODO | ENC-102 |
| ENC-310 | White-labeling + custom domains + certificate automation | P1 | TODO | ENC-221 |
| ENC-311 | Sync: device registry, delta protocol, eligibility, wipe | P1 | TODO | ENC-208 |
| ENC-312 | External editor session brokering | P1 | TODO | ENC-206 |
| ENC-313 | Workflow engine: definitions, stages, approvals | P1 | TODO | ENC-203 |
| ENC-314 | Document signing: ceremony, PAdES, TSA, LTV, verification | P1 | TODO | ENC-313 |
| ENC-315 | External signature providers (DocuSign, Adobe, eSign) | P2 | TODO | ENC-314 |
| ENC-316 | Milvus HA + rebuild runbook exercised | P1 | TODO | ENC-214 |
| ENC-317 | Leakage matrix §4.7–4.10 green | P0 | TODO | ENC-311, ENC-314 |
| ENC-318 | Tier 1 + Tier 2 locales translated | P2 | TODO | ENC-223 |
| ENC-319 | HA deployment profile + DR drill executed | P1 | TODO | ENC-316 |

### Phase 3 — Beyond V1

| ID | Item | Pri | Status | Note |
|---|---|---|---|---|
| ENC-400 | Offline sync merge | P3 | TODO | Explicit V1 non-goal |
| ENC-401 | Azure Blob + GCS storage adapters | P3 | TODO | — |
| ENC-402 | Additional vector-store providers | P3 | TODO | Trait is deliberately narrow |
| ENC-403 | Maker/checker across all privileged surfaces | P2 | TODO | Partial in V1 |
| ENC-404 | Advanced eDiscovery export | P3 | TODO | — |
| ENC-405 | Tier 3 locales | P3 | TODO | — |

---

## 5. Rollup

| Phase | P0 | P1 | P2 | P3 | Done | Open |
|---|---|---|---|---|---|---|
| D — Specification | 2 | 17 | 4 | 0 | 20 | 3 |
| 0 — Foundations | 1 | 12 | 3 | 0 | 0 | 16 |
| 1 — MVP | 3 | 22 | 2 | 0 | 0 | 27 |
| 2 — Enterprise V1 | 1 | 16 | 3 | 0 | 0 | 20 |
| 3 — Beyond V1 | 0 | 0 | 1 | 5 | 0 | 6 |
| **Total** | **7** | **67** | **13** | **5** | **20** | **72** |

Counts include completed items in their priority column. Update this table whenever a row's status or
priority changes; a stale rollup is worse than none.

---

## 6. Log

| Date | Event |
|---|---|
| 2026-08-18 | Phase D opened and closed. Spec pack reorganized to 17 documents; ACL invalidation, tenant isolation, quotas, antivirus, sync, signing, identity, i18n and BYO LLM specified. |
| 2026-08-18 | Mid-flight requests ENC-009 through ENC-015 logged and completed within Phase D. |
| 2026-08-18 | Tracker and working rules established (ENC-016). |
| 2026-08-18 | Roadmap published (ENC-019): 11 milestones, MVP GA target 2027-03-13, Enterprise V1 GA target 2027-09-25. |
| 2026-08-18 | Product renamed Vault → Enclave; tracker IDs renumbered to `ENC-` phase blocks (ENC-020). |
| 2026-08-18 | Git repository initialized on `main`; specification pack, guidance, tracker and roadmap committed; remote set to `CasualOffice/enclave` (ENC-022). |
| 2026-08-18 | M0 implementation plan published (ENC-023): eight locked design decisions, 16 tasks, day-10 RLS/pooling checkpoint. |
| 2026-08-18 | **Phase D closed.** Phase 0 open. Gate G0 applies at the end of M0. |
| 2026-08-18 | `ENC-100` workspace scaffolded: 43 crates, check/clippy/fmt clean. |
| 2026-08-18 | PR #1 merged. Two structural gates failed on it and were right to: the audit sink read on a raw pool (would have reported "chain valid, 0 events" under RLS), and a test literal tripped the secrets gate. Both fixed; the no-raw-pool gate was rewritten to check execution rather than type names. |
| 2026-08-18 | `ENC-109` policy engine implemented in `enclave-core::engine`: six stage traits, deny-by-default stubs, obligation accumulation, audit on allow and deny. Design decision D9 recorded; `docs/02 §4` and `docs/03 §12` updated. |
| 2026-08-18 | `ENC-106` RLS coverage gate written and run against PostgreSQL 16: 20 tenant-scoped tables all enabled, forced and policied. Proven to fail on an unprotected table and on a `USING (true)` policy. |
| 2026-08-18 | M0 foundation batch landed: ENC-101/102/103/104/105/107/108/111. Workspace green — 279 tests pass, 18 ignored pending the ENC-112 database harness. Verified independently of the implementing agents: JWT algorithm pinned (K8 attack test present), `SET LOCAL` semantics via `set_config`, RLS forced by catalog-driven loop, audit UPDATE/DELETE revoked. |

---

## 7. If you are an agent working in this repo

- Read `§2` before doing anything. The no-pivoting rule is the one most likely to be broken by
  helpfulness.
- Check `§3` for what is in flight. If something is `WIP` and you were asked for something else, log
  the new request per `§2.2`, report what you logged and its priority, and continue the in-flight
  item.
- Assign priority yourself using `§1` — do not ask which priority unless the rubric genuinely does not
  decide it.
- Update the row's status when you start and when you finish, and update `§5` and `§6` in the same
  edit. The tracker being current *is* part of the task.
- If the work you were asked for is already a row, say so and use that ID rather than opening a
  duplicate.
