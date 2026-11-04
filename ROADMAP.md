# ROADMAP

> **Milestones, sequencing and exit criteria for Enclave.**
> Owner: Casual Office · Last updated: 2026-09-10 · Baseline: 2026-08-18

This is the plan we follow. [`TRACKER.md`](TRACKER.md) is what we work from day to day; this document
says **why the work is in that order, when each milestone completes, and what "complete" means**.

Where the two disagree, the tracker is authoritative for status and this document is authoritative for
sequencing and exit criteria.

**On the `ENC-nnn` numbers below.** `TRACKER.md §2.3` is authoritative for the ID scheme; this
document only cites IDs, and cites none that does not exist. Until 2026-08-21 it did: it handed out
`ENC-200`–`ENC-226` from a phase-blocked scheme that `ENC-154` retired, so a reader following a
number from a milestone into the tracker found nothing and could not tell whether the work was
unlogged or already done under a different ID. Nothing was renumbered to fix it — sixty completed
rows carry their numbers in branch names, commits and merged PRs. Where the real row exists it is
named; where the step is real and nobody has logged it, it says **_(no row yet)_**, which is a
checkable statement rather than a number that resolves to nothing (`ENC-500`).

---

## 1. Planning assumptions

Every date below depends on these. If an assumption changes, the schedule changes — say so rather
than absorbing it silently.

**Rebased 2026-09-09 (`ENC-981`), and the previous version of this table was fiction.** It assumed
*4 backend, 2 frontend, 1 platform/SRE* at 70% capacity and a baseline start of `2026-09-01`. The
repository was initialised on `2026-08-18`, has one human author, and had delivered M0 through M4 by
`2026-09-09` — so the table's week two was the project's month six, and every date derived from it
was wrong in the same direction. The numbers below are measured rather than estimated.

| Assumption | Value |
|---|---|
| Team | **1 engineer, AI-assisted.** The seven-person team this table named for three weeks never existed |
| Baseline start | **2026-08-18** — the first commit, not the `2026-09-01` carried here until the rebase |
| Cadence | Continuous. No sprints: 335 commits in the first three weeks, 224 of them in one |
| Effective capacity | **Not modelled.** Headcount × utilisation predicts nothing here; throughput is measured per milestone instead |
| Estimate basis | **Measured duration**, split into work that compresses and work that does not — see below, because the split is the whole of this plan now |
| Confidence | **High** for M5's remaining build work · **Low** for every calendar-bound criterion · **Low** beyond M5 |

**Estimates are planning instruments, not commitments.** The exit criteria are the commitment; the
dates are the current best model of when they will be met. Both GA dates are internal targets, and
the rebase moves them.

### 1.1 The measured record

| | Budgeted | Actual | Ratio |
|---|---|---|---|
| M0 Foundations → M4 Governance baseline | 23 weeks cumulative | **3.0 weeks** (2026-08-18 → 2026-09-09) | **≈ 7.7×** |

Reported as one figure and not five because the milestones were not dated as they closed — that is
`ENC-991`, and it is the reason a per-milestone ratio would be invented rather than measured.

### 1.2 What compresses and what does not

**This is the load-bearing distinction, and the old plan did not make it.** A 7.7× ratio over
M0–M4 is real, and it says nothing about the work M5 has left, because that work is a different
kind. M0–M4 were self-contained: code, tests and documents, where the only dependency was the
author. What remains is not.

| Compresses at the measured rate | Does not compress |
|---|---|
| The leakage-matrix sweep (`ENC-987`) | **External penetration test** — scheduling lead time, execution, remediation, retest |
| API completion — metadata, fields, views (`ENC-984`) | **A restore drill** — needs a deployment target (`ENC-993`) |
| A k6 harness, and the budgets it measures | **Screen-reader pass** on NVDA and VoiceOver — a person on real assistive technology |
| Release documentation and upgrade notes | **An operator who has never seen the repo** installing from `README` |
| Anything else that is source in this tree | **A chaos pass** — needs an environment to break |

Four of M5's seven exit criteria sit in the right-hand column, and a fifth — the performance
budgets — is blocked on `ENC-993` before it is blocked on k6. **MVP GA stopped being a velocity
question somewhere around M4 and nobody said so.** Writing code faster does not move any of them.

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

### 2.1 Delivered

| # | Milestone | Phase | State | Evidence |
|---|---|---|---|---|
| M0 | Foundations | 0 | **Delivered** | Gate G0 passed — [`plans/G0-GATE.md`](plans/G0-GATE.md) |
| M1 | Content core | 1 | **Delivered, two gaps carried** | [`plans/M1-CONTENT-CORE.md`](plans/M1-CONTENT-CORE.md). `ENC-144` demonstrated the *flat-memory* half of the 5 GB criterion and no deployment can accept such an upload (`ENC-829`); the EICAR criterion's *incident* clause is a log line (`ENC-645`) — `§5` records both |
| M2 | Access & delivery | 1 | **Delivered** | [`plans/M2-CLOSEOUT.md`](plans/M2-CLOSEOUT.md); all five exit criteria evidenced in `§5` |
| M3 | Discovery | 1 | **Delivered, one gap carried — and it is not the one this row named** | The scanned-PDF criterion **is** met: `ENC-545`, `ENC-546`, `ENC-577` and `ENC-578` closed it on 2026-08-22, `plans/M3-DISCOVERY.md §1` has carried the tick since, and `§5` names the tests. `TRACKER.md`'s `ENC-161` row is stale. What is carried instead is the **denylist-size gauge, which nothing publishes** — two of its alerts are structurally incapable of firing, and no row covers it (`§5`) |
| M4 | Governance baseline | 1 | **Delivered** | `ENC-580`–`ENC-585`; DLP, conditional access, retention and the audit sweep are wired in `crates/api/src/main.rs`; all four exit criteria evidenced in `§5` |

**The exit criteria for M0–M4 were evidenced one by one on 2026-09-10 (`ENC-991`), and until then no
checkbox in `§5` had ever been ticked for any of them.** "Delivered" above had meant only that the
milestone's rows were `DONE` and its plan closed. Of the twenty-five criteria, **twenty-two are met
and ticked with the test, migration or gate that proves each**; three are not, and each names what
is missing rather than being left blank. Every claim comes from a file that was opened — the three
that changed the picture are the two M1 gaps above and the M3 correction, none of which was visible
from the tracker.

### 2.2 Remaining

| # | Milestone | Phase | Basis | Target | Confidence |
|---|---|---|---|---|---|
| M5 | **MVP GA** | 1 | build ~2 w, then calendar-bound | **2026-11-20** ± 3 w | Low — see below |
| M6 | Enterprise identity & governance | 2 | external IdPs (SAML, SCIM, LDAP) | 2027-01 | Low |
| M7 | AI & BYO infrastructure | 2 | `enclave-ai` and `enclave-mcp` are five-line stubs | 2027-02 | Low |
| M8 | Delivery surfaces | 2 | sync is largely built (`ENC-731`–`ENC-734`) | 2027-02 | Low |
| M8b | Content migration | 2 | needs SharePoint / NetDocuments / iManage to test against | 2027-04 | **Very low** |
| M9 | Workflows & signing | 2 | `enclave-signing` is a five-line stub; PAdES needs a real TSA and CA | 2027-04 | **Very low** |
| M10 | **Enterprise V1 GA** | 2 | second penetration test, second set of drills | **2027-05** ± 8 w | **Very low** |

**MVP GA moves from 2027-03-13 to approximately 2026-11-20 — roughly sixteen weeks earlier.** The
shape of that estimate matters more than the date: about two weeks of build work, and then eight to
ten weeks in which the schedule is set by a penetration testing firm's calendar, a deployment target
that does not exist yet (`ENC-993`), and three passes that need a human who is not the author. The
±3 weeks is almost entirely the pen test's booking lead time, which nobody has started.

**Enterprise V1 GA moves from 2027-10-09 to approximately 2027-05, and that number is weak.** M8b
and M9 both depend on systems outside this repository — three commercial DMS products to migrate
from, and a timestamping authority and certificate chain to sign against. The 7.7× ratio has no
evidence behind it for work of that kind, and pretending otherwise is how the old table got here.
Replan at the M5 gate rather than trusting this row.

### 2.3 What would move these dates

Named explicitly, because `§1` requires a changed assumption to be stated rather than absorbed:

1. **Booking the penetration test.** It is the longest pole in MVP GA and has no row, no vendor and
   no date. Every week it is not booked moves MVP GA by a week.
2. **`ENC-993` — a deployment target.** The restore drill, the performance budgets and the chaos
   pass are all downstream of it.
3. **A second person, or a first non-author reader.** Two M5 criteria — the screen-reader pass and
   the clean-machine install — cannot be satisfied by the person who wrote the thing being tested.
4. **`ENC-987` — the leakage-matrix sweep.** The last link of the critical path in `§3`, 214 rows,
   and it had no ID at all until 2026-09-09.

---

## 3. The critical path

Seven items gate everything downstream. Delay in any of these delays the release; delay elsewhere
usually does not.

```text
ENC-104 db + TenantScoped
   └─ ENC-105 migration 0001 + RLS
        └─ ENC-109 PolicyEngine::enforce
             └─ ENC-126 ACL resolution
                  └─ ENC-506 search post-filter + retrieval denylist
                       └─ M5 leakage matrix §4.1–4.6 green  (ENC-987)
                            └─ M5 MVP GA
```

The last link had no ID for the whole of M0–M4 because nothing had been logged for it; it is `ENC-987`, raised 2026-09-09. `ENC-134` and `ENC-153` filled in
individual matrix rows as the surfaces they cover landed; **the sweep that takes §4.1–4.6 green as a
whole is M5 work nobody has written down yet**, and giving it a number here would be inventing one.

Consequences of that shape, which drove the ordering below:

- **The policy engine is built before any feature that uses it.** Retrofitting a chain into handlers
  that already query the database directly is the single most expensive mistake available here.
- **The search post-filter is built with the first search, not after it.** It is the mechanism that
  makes index staleness a performance problem instead of a data leak (`docs/07 §6`).
- **RLS lands in migration 0001.** Adding it to fifty existing tables later means auditing fifty
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

**The design system already exists**, so the web shell does not start from a blank page. The client
design system, layout and prototype are built in Claude Design and reachable through the Claude
Design MCP:

    https://claude.ai/design/p/c02388c5-f47e-443e-adc4-4020470148b1?file=Enclave+Client.dc.html

Read it before writing any UI. The visual language and component structure are decided; the work is
to implement them against `docs/09-UX-WHITE-LABELING.md` and `docs/14-I18N-L10N.md`, not to invent a
second one. Recorded here rather than in a chat because the milestone that needs it is months out
(noted 2026-08-21).

The fourth backend engineer floats to whatever is on the critical path — this is the schedule's
shock absorber, and it is the first thing consumed when an estimate is wrong.

---

## 5. Milestones in detail

### M0 — Foundations · 5 weeks · Phase 0

**Goal.** A request can traverse the full policy chain against a real database, and CI enforces the
structural rules that keep it that way.

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 0 — Foundations* (ENC-100 … ENC-118; the last
three were found during the milestone and are not in the step list below) ·
**Plan:** [`plans/M0-FOUNDATIONS.md`](plans/M0-FOUNDATIONS.md)

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

- [x] One end-to-end request: login → JWT → `enforce` → tenant-scoped query → audit row —
      `the_issued_token_is_accepted_by_another_endpoint` (`crates/api/tests/auth.rs`) drives
      `POST /auth/login` → `GET /me`, and `a_request_traverses_authentication_the_chain_the_database_and_audit`
      (`crates/api/tests/me.rs`) asserts exactly one `ALLOW` row in `audit_events`. G0 recorded this
      **Partial**; `ENC-124` closed it.
- [x] Cross-tenant read fails **with the application predicate deliberately removed** (T5) —
      `t5_row_level_security_alone_blocks_a_cross_tenant_read`, `crates/testing/tests/leakage.rs`:
      every query is `SELECT … FROM <table>` with no `tenant_id` clause, checked in both directions
      per table, over a table list read from the catalog rather than a literal.
- [x] Refresh rotation works; replaying a consumed token revokes the family (K3, K4) —
      `k3_rotation_consumes_the_presented_token` (`crates/auth/src/refresh.rs`) and
      `k4_a_replayed_token_revokes_every_row_in_the_family` (`crates/api/tests/auth_postgres.rs`),
      which asserts `SESSION_REPLAY` and zero usable rows left in the family.
- [x] All four structural CI gates fail correctly when deliberately violated —
      [`plans/G0-GATE.md §3`](plans/G0-GATE.md) records **six** proven that way, each naming what was
      broken; all are live jobs or steps in `.github/workflows/structural-gates.yml`
      (`rls-coverage`, `policy-routing`, no-raw-pool, the secrets scan).
- [x] `docker compose up` → healthy stack on a clean machine, documented in `CONTRIBUTING.md` —
      `deploy/compose/dev.yml` health-checks all eight services and `CONTRIBUTING.md §Development setup`
      documents `up -d --wait`, which returns on *healthy* rather than on *created*.

**Risks.** RLS interacts badly with connection pooling if `SET LOCAL` is misused — prove it in week 1
with a pool-exhaustion test, not in month 6. Stub services that default to *allow* would quietly
disable the chain; they default to deny.

---

### M1 — Content core · 6 weeks · Phase 1

**Goal.** Content can be stored and versioned safely. Nothing is readable before it is scanned.

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 1 — MVP*, the **Carried from gate G0** and
**Content** tables (ENC-119 … ENC-136) · **Plan:** [`plans/M1-CONTENT-CORE.md`](plans/M1-CONTENT-CORE.md)

**Steps**

1. Tenancy, users, groups, memberships (ENC-125). Invitations were not part of it — *(no row yet)*.
2. Local auth end-to-end (ENC-111, ENC-124). **OIDC and LDAP bind slipped** — `docs/13` specifies
   them (ENC-010) and no implementation row exists; the earliest logged federation work is SAML in
   M6 (ENC-300) — *(no row yet)*.
3. Workspaces and libraries with settings and inheritance flags (ENC-136 for the DDL, ENC-127 for
   the crate; break-inheritance was reopened by ENC-141).
4. Files and folders: create, rename, reparent, trash, restore, move/copy (ENC-130), with the read
   paths and cursor pagination in ENC-133.
5. `storage` — S3-compatible `BlobStore`, capability probing, public-access self-check (ENC-128).
6. Upload: session state machine, multipart, signed URLs, checksum verification (ENC-129).
7. Versions: immutable rows, atomic commit with outbox and audit, restore (ENC-131).
8. `antivirus` + ClamAV; **no version reaches `AVAILABLE` without a clean verdict** (ENC-132).

**Exit criteria**

- [ ] 5 GB resumable upload with flat API memory. **Half met, and the half that is missing is the
      one a user meets.** Flat memory is demonstrated — `a_five_gigabyte_upload_is_completed_without_the_api_touching_a_byte`
      (`crates/uploads/tests/sessions.rs`, `ENC-144`) drives a session declared at the full size
      through create, resume, complete and hand-off against a store whose two byte-bearing methods
      abort the test. But **no deployment can accept such an upload**: `declared_sha256` is a
      mandatory `String`, and `crates/storage/src/s3/store.rs` returns `ChecksumUnverifiable` for
      *every* multipart request because S3's composite checksum is not the whole-object digest — so
      anything above the 16 MiB threshold is refused before a URL exists. `ENC-829` (P1) is the row,
      and it names this criterion itself.
- [x] Version rows reject mutation of `object_key`, `checksum`, `size`, `major`, `minor` —
      `an_available_version_refuses_every_change_to_its_content_identity`,
      `crates/versions/tests/versions.rs`, against the `file_versions_immutable` `BEFORE UPDATE`
      trigger in `migrations/0006`; all five refused one at a time and each named by the column the
      trigger reports, with `an_available_version_still_accepts_its_governance_columns` as the
      control that the trigger is not simply freezing the row.
- [ ] EICAR upload → `QUARANTINED`, unreadable through every path, incident raised (G1). **Two of
      the three.** Quarantine is proved with its positive control —
      `an_infected_version_is_quarantined_while_a_clean_one_beside_it_becomes_readable`
      (`crates/worker/tests/antivirus.rs`) — and *unreadable through every path* is `G16`'s
      `status` × `av_status` cross-product against a real database and the live preview route
      (`the_two_spellings_of_readable_agree_against_a_real_database`,
      `the_file_response_and_the_preview_route_agree_about_every_version_state`). **No incident is
      raised**: `crates/worker/src/antivirus.rs::raise` is a `tracing::error!` line, there is no
      incident table and `crates/incidents` is a five-line stub, so nothing notifies security and
      nothing survives a log rotation — `ENC-645` (P2).
- [x] AV down with `HOLD` → uploads wait in `SCANNING`, existing content unaffected (G6) —
      `an_engine_that_is_down_holds_the_version_and_an_engine_that_answers_releases_it`,
      `crates/worker/tests/antivirus.rs`: the pass writes nothing (`held: 1`, `written: 0`), the row
      stays `SCANNING`/`PENDING`, and the same fixture becomes readable once an engine answers —
      which is the control that stops "still `SCANNING`" passing against a pass nobody called.
- [x] Sibling name collision rejected by constraint, not by application check alone —
      `a_second_sibling_with_the_same_folded_name_is_refused_by_the_index`,
      `crates/files/tests/tree.rs`, against `uq_files_sibling_name` (`migrations/0005`);
      `crates/files/src/repo.rs` documents and takes no preceding `SELECT`, so there is no
      read-then-write window for a concurrent create to slip through.

---

### M2 — Access & delivery · 5 weeks · Phase 1

**Goal.** Granular permissions actually work, and preview is genuinely separable from download.

**Tracker:** [`TRACKER.md §3`](TRACKER.md) — M2's rows sit on the active board rather than in a `§4`
phase table · **Plan:** [`plans/M2-ACCESS-DELIVERY.md`](plans/M2-ACCESS-DELIVERY.md)

**Steps**

1. ACL resolution: inheritance chain, transitive group closure, deny-wins, break-inheritance
   (ENC-126; break-inheritance was found to escalate privilege and fixed in ENC-141).
2. `authorize_many` batch path — required later by search; built now (ENC-126), benchmarked at 200
   candidates before M3 set its design (ENC-145), and extended to batch *actions* as well as
   resources once that benchmark inverted the assumption (ENC-167, ENC-175).
3. Rendition pipeline: sandboxed generation, base cache, per-request watermark composition
   (ENC-146, ENC-146a; watermark-never-cached is ENC-147).
4. Preview API with no original URL on the view-only path; download API as `POST` with audit before
   URL issuance (ENC-148, ENC-169).
5. Share links: token hashing, password/OTP, expiry, atomic download budget (ENC-149, ENC-150).
6. Metadata fields, values, content types (ENC-151; `content_types` was already in migration 0004 —
   ENC-165).
7. Views + cursor pagination + `capabilities` on every file response (saved views ENC-501,
   `capabilities` ENC-152; cursor pagination landed in M1 with ENC-133).

**Exit criteria**

- [x] `preview=ALLOW, download=DENY` produces a rendition and **no** signed original URL (A1) —
      `preview_allowed_and_download_denied_yields_a_rendition_path_and_no_signed_url`,
      `crates/api/tests/delivery.rs`: the preview is `200 image/png` carrying the pipeline's bytes,
      the download is `403 ACCESS_DENIED`, and `store.touched()` is **empty** — the URL was never
      asked for rather than generated and withheld.
- [x] A `DENY` beats an inherited `ALLOW` at every level (A3) —
      `a3_a_deny_overrides_an_inherited_allow_at_every_level`, `crates/testing/tests/leakage.rs`:
      four arrangements over workspace, library, folder and file, each flipped back afterwards so
      the refusal cannot be something unrelated refusing everything.
- [x] `max_downloads` holds under 50 concurrent redemptions — exactly N succeed (H3) —
      `h3_the_download_budget_holds_under_fifty_concurrent_redemptions`,
      `crates/sharing/tests/redemption.rs`, on a **sixteen-connection** pool because the harness
      default of two made the first version of this test pass against a read-then-write
      implementation; asserted on the successes and on their distinct counts `1..=N`, not on the
      final counter. `h3_the_limit_lives_in_the_where_clause_and_holds_when_every_reader_is_stale`
      is the deterministic half.
- [x] Watermarked output is never written to the rendition cache — structural, and the structure is
      the guarantee: `RenditionKey::new` takes version, profile and generator and **no principal**
      (`the_base_object_both_viewers_share_is_keyed_without_them`,
      `crates/preview/tests/watermark.rs`), and `RenditionSink::keep` has exactly one caller in the
      workspace — `crates/preview/src/service.rs`, handed the renderer's identity-free artefact.
      The mark is composited downstream in `crates/api/src/preview.rs`, after the cache.
- [x] Cursor from one tenant rejected in another (T3) —
      `t3_a_cursor_issued_in_one_tenant_is_rejected_in_another`, `crates/testing/tests/leakage.rs`,
      through a real listing rather than the codec, with both controls: beta pages perfectly well
      without the cursor, and the cursor still works in the tenant that issued it.

---

### M3 — Discovery · 5 weeks · Phase 1 · *starts in M2 week 3*

**Goal.** Search that cannot leak, and that degrades honestly when its index is unavailable.

**Tracker:** [`TRACKER.md §3`](TRACKER.md) — M3's rows sit on the active board rather than in a `§4`
phase table · **Plan:** [`plans/M3-DISCOVERY.md`](plans/M3-DISCOVERY.md)

**Steps**

1. Extraction (PDF, OOXML, text) in a sandboxed worker; structure parsing (ENC-510, ENC-511).
2. **OCR for scanned pages** — engine, language coverage and cost decided rather than assumed
   (ENC-161, answered by ENC-534 and built as ENC-535; ENC-536 is why the weights matter).
   Not a fallback bolted to the end of extraction: scanned PDFs are a large share
   of what enterprises actually store, and a scanned document that indexes as empty is
   invisible to search while appearing correctly filed, which is worse than one that failed
   to ingest.
3. Structure-aware chunking with deterministic chunk IDs (ENC-513).
4. Embedding provider trait + local model; classification routing enforced in code (ENC-508;
   the model and how it ships are ENC-509 and ENC-534).
5. Milvus `VectorStore`; collection, indexes, hybrid query (ENC-523, ENC-524).
6. **Authoritative post-filter with batch authorization and over-fetch** (ENC-506; `docs/07 §6.2`
   was corrected to match the measurement in ENC-505).
7. Denylist written in the same transaction as the ACL change (ENC-506); invalidation worker and
   epoch reconciler (ENC-518, ENC-519).
8. Degraded mode: Milvus down → lexical over PostgreSQL with `degraded: true` (ENC-514, with
   document content in ENC-515 and the up-but-wrong trigger in ENC-516).

**Exit criteria**

- [x] S3: revoked file vanishes from results **immediately**, before any index update —
      `s3_a_revoked_file_leaves_the_results_before_the_index_is_touched`,
      `crates/search/tests/postfilter.rs`: the candidate generator is unchanged across the
      revocation and still proposes the file, and the pre-revocation confirmation is the control.
- [x] S4: S3 still holds with the invalidation worker stopped —
      `s4_the_answer_is_right_with_no_worker_running_at_all`, same file: there is no worker in the
      test at all, and nothing calls `lift_expired`. Recorded as the *weaker* half —
      `the_denylist_suppresses_what_the_acl_alone_would_still_admit` is what isolates the denylist,
      because a revocation removes the ACL too.
- [x] S5: deliberately over-permissive index candidates are dropped by the post-filter —
      `s5_over_permissive_candidates_are_dropped_however_confident_the_index_is`, same file: an
      ungranted file, a beta-tenant file and a file that does not exist, with the permitted one in
      the middle so a post-filter that refused everything fails too (`confirmed == 1` is asserted).
- [x] S8: `RESTRICTED` text never reaches a non-local embedding provider —
      `restricted_text_never_reaches_a_remote_provider`, `crates/embeddings/tests/routing.rs`,
      against a remote double that **panics** on contact, sweeping `RESTRICTED` itself and the ranks
      above it; the fallback a tired engineer would write does not compile. The *input* half is
      `a_deployment_that_cannot_classify_a_file_refuses_rather_than_guessing_a_rank`,
      `crates/worker/tests/indexing.rs` (`ENC-557`).
- [x] Post-filter drop ratio and denylist size exported as metrics with alerts wired. **Both halves
      now, and the second was found by `ENC-991` reading this criterion against the tree.** The drop
      ratio was always real: `PostFilter::confirm` publishes every pass
      (`crates/search/src/postfilter.rs::publish` at the `confirm` call site →
      `enclave_observability::metrics::search::PostFilterPass`). **Nothing set the denylist gauges**
      — `record_denylist_size` had no caller outside `metrics.rs`'s own unit tests, so
      `enclave_search_denylist_entries` was never exported, `SearchDenylistBacklogGrowing` and
      `SearchDenylistOverflowedAndTenantIsDegraded` were structurally incapable of firing, and the
      file's own `SearchDenylistSizeUnreported` described the deployment exactly. `ENC-1005` wired
      it at the one place holding both numbers, `routes::search::plan`, and
      `a_search_publishes_the_denylist_gauge_the_alerts_read` drives a real search and scrapes the
      rendered exposition — it fails when the recorder call is removed.
- [x] A scanned, text-free PDF is searchable by its content (ENC-161). **Met 2026-08-22, and the
      note that stood here was three rows out of date.** `ENC-545` added `PdfTextExtractor`, which
      returns `NoText` carrying the pages that yielded nothing; `ENC-546` wired
      `MountedOcr::retry` into `crates/worker/src/indexing.rs`, which recovers text from exactly
      those pages and commits it; `ENC-577` made `crates/worker/src/main.rs` register
      `application/pdf` — only when PDFium is mounted; and `ENC-578` crossed the last join,
      `text_an_indexing_pass_committed_is_text_lexical_search_finds`
      (`crates/worker/tests/indexing.rs`), where a pass writes rows and a search reads them back in
      one process. [`plans/M3-DISCOVERY.md §1`](plans/M3-DISCOVERY.md) has carried this tick and its
      link-by-link evidence since; **this document did not, which is `ENC-991` in one line.**
      Two honest qualifications, both stated there: **no single test spans all four boundaries** —
      they are joined pairwise, each with real components on both sides — and OCR is a deployment
      option, since a worker without the two mounted volumes routes PDFs nowhere and records
      `SKIPPED` rather than failing. `TRACKER.md`'s `ENC-161` row still reads `BLOCKED` on the
      model-file question `ENC-535` answered; that row is stale.

**Measured before this milestone starts (`ENC-145`).** `authorize_many` resolves 200 candidates in **p50 7.0 ms** (debug build), and one candidate in 1.4 ms — so the post-filter's cost is ~80% fixed: transaction setup plus three round trips, not candidate count. That inverts the obvious intuition twice over. Raising over-fetch is nearly free; adding a *second* resolution pass costs more than tripling the batch. Whether result disclosure and excerpt disclosure can be answered in one call is therefore a design decision to take before the search path sets, not after (`ENC-167`).

**Risks.** This milestone contains the highest-severity design risk in the product. It gets the most
senior reviewer and a written threat walkthrough before merge, not just tests.

---

### M4 — Governance baseline · 4 weeks · Phase 1

**Goal.** A tenant can be told no, for the right reasons, with an audit trail.

**Tracker:** `TRACKER.md §3`, `ENC-580`–`ENC-585`, and the plan is
[`plans/M4-GOVERNANCE.md`](plans/M4-GOVERNANCE.md). Two Phase 2 items depend on this milestone by
name — `ENC-303` on DLP detectors, `ENC-306` on the audit coverage sweep.

**Steps**

1. DLP detectors, `SecurityFacts`, sync evaluation with `facts_unavailable` handling — `ENC-581`.
2. DLP modes incl. simulation; obligations returned and enforced as `#[must_use]` — `ENC-582`.
3. Conditional access: zones, geo/ASN, trusted-proxy hop handling, effects — `ENC-583`.
4. Quotas: transactional enforcement, soft-limit notification, nightly reconciliation — `ENC-584`.
5. Audit coverage sweep — every enforcement point, allow and deny — `ENC-585`.

**Exit criteria**

- [x] D1–D4 green: enforce blocks, simulation records only, missing facts fail closed, dropped
      obligation fails the operation — `crates/dlp/tests/modes.rs`.
      `d1_and_d2_one_policy_both_ways_records_the_same_decision` runs one policy over one set of
      facts in both modes and asserts `ENFORCE` refuses *first*, so D2's absence means something;
      `d3_missing_facts_follow_the_tenants_policy` carries both controls (`FAIL_OPEN_AUDIT` over the
      same absent facts permits and leaves the evidence, `FAIL_CLOSED` with fresh clean facts
      permits); `d4_an_obligation_that_cannot_be_satisfied_fails_the_operation` refuses through
      `Obligations::require_none` with the clean document as its control. Extended to a running
      deployment reading `security_facts` through `TenantScoped` by `crates/dlp/tests/stored_facts.rs`
      (`ENC-594`).
- [x] Forged `X-Forwarded-For` from an untrusted peer is ignored —
      `a_forged_forwarded_for_is_ignored_from_an_untrusted_peer_and_honoured_from_a_trusted_one`,
      `crates/conditional_access/tests/forwarded_for.rs`: the same header and the same configuration,
      differing only in the peer address, so a resolver that ignored the header unconditionally
      fails the control. `crates/api/src/edge.rs`'s
      `a_forged_forwarded_for_reaches_the_context_only_from_a_trusted_peer` is the HTTP layer.
- [x] Quota exhaustion blocks writes while reads, deletes and exports keep working —
      `quota_exhaustion_blocks_writes_while_reads_deletes_and_exports_keep_working`,
      `crates/db/tests/storage_quota.rs`, in one fixture with the refusal asserted **first** so the
      three "still works" legs are statements about a demonstrably exhausted quota, and closing the
      loop: after the delete frees room, the charge refused in step 1 is admitted.
- [x] Every row in the audit table maps to a real enforcement point; no silent successes — two
      halves that fail differently, both wired as the `audit-coverage` job. `xtask audit-coverage`
      enumerates every site that can *construct* a refusal and classifies it by the enclosing
      function's return type, with an acknowledgement list that fails on a **stale** entry as well
      as on a new unaudited one; `crates/audit/tests/policy_audit_coverage.rs` drives the real
      engine once per `Stage::ORDER` and asserts the row carries outcome, reason code and the stage
      in `policy_refs` — deleting `record_deny` leaves the static gate green, which is why both
      exist. The cascade hole this left is closed: `ENC-923`/`A46`, one audit row per resource
      through `PolicyEngine::enforce_many`.

---

### M5 — MVP GA · 4 weeks · Phase 1

**Goal.** A real team could use this daily. Ship it.

**Plan:** [`plans/M5-MVP-GA.md`](plans/M5-MVP-GA.md) — D33–D38 locked, Q20–Q23 open.

**Tracker:** ENC-671 … ENC-676. Two Phase 2 items depend on this milestone by name (ENC-310 on the
web shell, ENC-318 on i18n scaffolding), and it is the milestone gate G1 decides at.

**Steps**

**Corrected 2026-09-09 (`ENC-986`).** Six of these seven read *(no row yet)* while five of them
were built — the opposite of `§1`'s old error, and read as a project further behind than it is.

1. Web shell: navigation, command bar, `⌘K` palette, details panel — **done**. `ENC-702` gave it a
   keyboard model from one table the handlers and the `?` reference both read; `ENC-853`–`ENC-868`
   made `shared/ui` a component library. The self-hosted typefaces landed early as ENC-135.
2. Virtualized file views; upload UX with true states through to `Ready` — **done**. The
   virtualization is hand-rolled in `web/src/features/libraries/list/grouped-file-list.tsx` rather
   than a dependency, which is why `web/package.json` names no windowing library; upload is
   `ENC-972` and paging past the first fifty rows is `ENC-973`.
3. i18n scaffolding and the `en-US` catalog — **done** (`web/src/shared/i18n/catalog.ts`, enforced
   by the `lint:i18n` gate). **The `en-XA`/`en-XB` pseudo-locales are not built** — `ENC-994`.
   `web/tools/lint-web.mjs` still refers to them in the future tense, and `en-XB` is what would
   prove the logical-property rule that lint enforces statically.
4. Leakage matrix §4.1–4.6 implemented and green — **swept by `ENC-987`, and the criterion is
   unmeetable as written.** Nineteen rows had a passing test and did not say so —
   including the two this sweep first reported as gaps and then corrected (`ENC-998`) — and **ten
   cannot be tested at all in M5**, because each
   needs a subsystem that is a five-line stub and belongs to M6 or M7 — AI, MCP, classification
   ceilings, barriers, legal hold, records, incidents, and share redemption. The criterion acquired
   a Phase 2 dependency as rows were added to it, and nobody noticed because nobody had read the
   set as a whole. It needs a rescope or a decision to pull those subsystems forward: `ENC-999`,
   and it is the repo owner's. `docs/12 §4.0` carries the evidence row by row.
   Rows have been filled in as their surfaces landed (ENC-134 for §4.1/§4.2/§4.8, ENC-153 for A1,
   A5, A6 and H1–H3); the sweep that takes the whole set green is this step and had no ID until
   2026-09-09.
5. `community` deployment profile, install docs, upgrade path — **profile done**
   (`DeploymentProfile::Community`, and a test pins that its generated key is unreachable outside a
   loopback community deployment); `README.md` and `CONTRIBUTING.md` exist. The **upgrade path** is
   unevidenced, and exit criterion 5 in `docs/12 §9` asks for a migration verified against the
   previous release running — which needs a previous release.
6. Accessibility: axe gate **done** (real Chromium, every primary route, both themes), keyboard
   flows **done** (`ENC-702`, `ENC-900`). **The screen-reader pass is not done** and cannot be by
   the author — see `§1.2`.
7. Release hardening: load test at budget, chaos pass, restore drill, docs review — **not started,
   and blocked on `ENC-993`**: there is no deployment target above `deploy/compose/dev.yml`, and no
   k6 harness. This is the step that sets the date.

**Exit criteria — the MVP gate**

- [ ] Every P1 in Phase 1 `DONE`.
- [ ] Leakage matrix §4.1–4.6 green, **except the ten rows named in
      `.github/scripts/matrix_coverage.py`'s `DEFERRED` list, each with the milestone that closes
      it** — `S7`, `S9`, `S10`, `H2`, `H5`, `H6`, `D5`, `D6`, `D7`, `D8`. No other skips, and no
      quarantined test.

      **Rescoped 2026-09-10 by the repo owner (`ENC-999`); it read *zero skips* and was
      unmeetable.** Each of the ten needs a subsystem that is a five-line stub scheduled for M6 or
      M7 — AI, MCP, classification ceilings, barriers, legal hold, records, incidents, and a share
      redemption that is deliberately unregistered. The criterion acquired that dependency one row
      at a time, and nobody noticed until `ENC-987` read the set as a whole.

      **The exception is enforced rather than waived**, which is the difference between this and
      dropping the criterion: `matrix_coverage.py` fails if an eleventh row is marked untestable,
      and fails again if one of the ten becomes testable and nobody retires it. An exception nobody
      can grow and nobody can forget is a scope decision; one written in prose is an erosion.
- [ ] Performance budgets met: metadata P95 < 300 ms, search P95 < 500 ms, 100k-item folder
      first paint < 400 ms.
- [ ] Restore drill executed end to end and documented.
- [ ] axe clean on every primary route; keyboard-only walkthrough completed.
- [ ] A new operator can install from `README` on a clean machine without asking a question.
- [ ] External penetration test scoped to `docs/12 §4` — no unresolved high findings.

---

### M6 — Enterprise identity & governance · 8 weeks · Phase 2

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 2 — Enterprise V1*: ENC-300 … ENC-306

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

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 2 — Enterprise V1*: ENC-307 … ENC-309, ENC-316

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

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 2 — Enterprise V1*: ENC-310 … ENC-312, plus ENC-160 and ENC-162 on the active board (`§3`)

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

**Tracker:** [`TRACKER.md §3`](TRACKER.md) — ENC-159, on the active board

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

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 2 — Enterprise V1*: ENC-313 … ENC-315

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

**Tracker:** [`TRACKER.md §4`](TRACKER.md) → *Phase 2 — Enterprise V1*: ENC-317 … ENC-319

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
