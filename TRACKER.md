# TRACKER

> **The single source of truth for what is being worked on, in what order.**
> Enclave · Casual Office · Last updated: 2026-08-20
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

IDs are `ENC-nnn`, drawn from one sequence and never reused — including after a row is dropped.
**A number does not tell you the phase**; the section the row sits in does. New rows take the next
free number at or above `ENC-500`.

Numbers were originally blocked by phase, and the blocking did not survive contact with the work.
Phase 1 ran straight on from Phase 0 at `ENC-119` instead of restarting at `ENC-200`, because the
two were continuous and nobody stopped to re-block; by the time it was noticed (`ENC-154`) some
sixty rows carried those numbers into branch names, commit messages and merged PR titles. The
`ENC-200`–`ENC-299` block was never instantiated at all. Renumbering to restore the scheme would
have rewritten references that live outside this file, and it would have renumbered completed work,
to recover a property nothing was actually reading — so the scheme was dropped instead of the
history. What already exists is left exactly where it is:

| Range | Phase | Note |
|---|---|---|
| `ENC-001`–`ENC-023` | D — Specification | — |
| `ENC-100`–`ENC-118` | 0 — Foundations | — |
| `ENC-119`–`ENC-176` | 1 — MVP | Continued in the 100 block; `ENC-127a` is a suffixed insert |
| `ENC-200`–`ENC-299` | — | Reserved by the old scheme, never allocated |
| `ENC-300`–`ENC-319` | 2 — Enterprise V1 | — |
| `ENC-400`–`ENC-405` | 3 — Beyond V1 | — |
| `ENC-500`+ | Any | Every new row, whatever phase it belongs to |

New IDs start at `ENC-500` rather than at `ENC-406`, which is the next free number, so that a new
row cannot be read as one of the Phase 3 items it would otherwise sit among. Gaps in a sequence cost
nothing; a number that quietly implies the wrong phase costs the reader's trust in the whole column.

A **`Depends on`** entry names either an ID that exists in this file or a milestone in
`ROADMAP.md` — never a number reserved for work nobody has logged, which is what `ENC-154` found.

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

**In progress:** *(none)*

**Gate G0: PASSED** — see [`plans/G0-GATE.md`](plans/G0-GATE.md). Both conditions carried into M1 are closed: the five dependency majors landed (`ENC-119`–`ENC-123`) and `GET /api/v1/me` made criterion 1 fully met (`ENC-124`).

**Gate G1 is not due here.** `ROADMAP.md §6` places it at the end of **M5** — see the correction under `ENC-142` below.

**Phase 0 is complete.** Phase 1 is in progress: M0 and M1 are delivered, M2 is open.

**Plan for the current milestone:** [`plans/M3-DISCOVERY.md`](plans/M3-DISCOVERY.md)

| ENC-139 | CI `test` job had no object storage, so the new BlobStore tests failed on `main` | P0 | DONE | Same shape as ENC-118: `--include-ignored` runs tests needing infrastructure the job does not provide |

| ENC-137 | Promote `Cursor`/`PageSize`/`FilterFingerprint`/`normalize_slug` below the domain layer | P1 | DONE | Finished in integration: `crates/files` repointed and the compatibility shim deleted, so no crate reaches sideways for pagination |
| ENC-140 | ClamAV has no non-Docker-Hub mirror, so the dev stack's `av` profile needs `docker login` | P3 | DONE | Re-probed 2026-08-20 and half of it is no longer true: an **anonymous** Docker Hub token for `clamav/clamav` is issued and `1.4_base` resolves, with the budget stated in the token itself (100 pulls / 6 h / source IP), so no `docker login` is required for `av` or `search`. The mirror is still absent — `quay.io/clamav/clamav`, `ghcr.io/clamav/clamav` and `ghcr.io/cisco-talos/clamav` all 401 (no public repository), `public.ecr.aws` 404s because ClamAV is not a Docker official image — and the same probe resolved `quay.io/coreos/etcd`, `ghcr.io/astral-sh/uv` and `public.ecr.aws/docker/library/postgres`, so those are absences and not a broken check. The row also named the wrong profile: it is `av`, not `security`. Closed as a standing constraint rather than an open task, recorded in `deploy/README.md` where a contributor meets it — including the part nobody had written down, that **CI** pulls this image anonymously in the `test` job and a Hub refusal would surface as leakage row G1 failing rather than as a registry problem |

| ENC-141 | **Breaking inheritance gains privilege.** `inherit_permissions = FALSE` truncated the ACL walk instead of materialising the effective set, so a `DENY` above the break stopped applying | P1 | DONE | Found by ENC-134 while writing matrix row A4. Break-inheritance is a documented feature (`docs/01 §17`), so this was privilege escalation through a supported operation, not an unreachable edge. Fixed in three parts: `enclave_authorization::break_file_inheritance` and `break_library_inheritance` collapse the whole chain — the resource's own entries included — by deny-wins and write the result onto the resource in the same transaction as the flag flip; and `enclave-libraries` no longer lets a settings update touch the column, since fixing one door and leaving the other open moves a bug rather than closing it. The harness's parallel reference implementation is deleted — a second copy of this operation is the divergence that would quietly restore the bug. Both new tests verified by neutering the copy and watching them name the escalation. A4 is one row again in `docs/12 §4.2` |
| ENC-142 | **Gate G1 recorded at the wrong milestone.** `plans/M1-CONTENT-CORE.md §5` and `TRACKER.md §3` both placed G1 at the end of M1; `ROADMAP.md §6` places it at the end of M5 | P2 | DONE | A documentation defect with a scheduling consequence: it would have had the MVP ship decision taken four milestones early, against criteria that assume M2–M4 exist. Found while acting on the tracker's own "Next". Both documents now defer to the roadmap rather than restate it |
| ENC-143 | M2 implementation plan — access & delivery | P1 | DONE | `plans/M2-ACCESS-DELIVERY.md`. Five design decisions locked (D15–D19); opens with the rendition pipeline because it is the milestone's only genuine unknown and the exit criterion the product is sold on depends on it |
| ENC-144 | M1 exit criterion 1 — 5 GB resumable upload with flat API memory — is argued, not demonstrated | P2 | DONE | Now exercised. A session declared at the criterion's full size is driven through create, resume, complete and antivirus hand-off against a store whose two byte-bearing methods **abort the test** rather than erroring — an error is something the service could plausibly handle and move past, and the claim is not "it copes" but "it never asks". It moves no data deliberately: a volume test would pass just as well against an implementation that streamed 5 GB through this process in pieces, because the criterion is about who touches the bytes |
| ENC-145 | Benchmark `authorize_many` at 200 candidates | P1 | DONE | **p50 7.0 ms, p95 7.6 ms** for 200 candidates through 5-deep chains with 6-level group nesting, in a *debug* build — the build CI runs. `docs/07 §6.2`'s "typically under 10 ms" holds. The fixture is the point: 200 files across 20 chains, denials only a full walk reaches, grants only a full group closure reaches, expired entries, and 400 noise rows — plus an assertion that exactly 150 of 200 are allowed, so a resolver that got fast by answering a different question fails rather than posting a good number. The binding assertion is a **ratio** ceiling (200 candidates < 25× one candidate; measured 4.8×), because an absolute bound can be satisfied by a fast runner while an N+1 shows up as ~200× on any hardware |
| ENC-146 | `crates/preview` — the rendition pipeline, its cache, and the bounds it runs inside | P1 | DONE | Three properties made structural rather than remembered: a base rendition **cannot** carry an identity (`RenditionKey` and `RenderRequest` have nowhere to put one, and `ObjectKey::rendition` already had the same shape); nothing unscanned is ever parsed (`ReadableVersion` has private fields and one constructor, whose query filters `AVAILABLE`+`CLEAN`); and a renderer cannot exceed its budget, because `Bounded` enforces the wall clock and the output cap from *outside* it — the component parsing hostile input is the one least able to promise it will stop. Migration 0007. A refusal is a value in the success channel, never an error: a timeout treated as an error is a retry, and a retry against a document engineered to hang is a DoS primitive with a scheduler helping it. Satisfies leakage rows G2 and the *previewable* clause of G1. Both database controls verified by deliberate violation |
| ENC-146a | A real renderer behind the `Renderer` trait | P1 | DONE | `RasterRenderer` — PNG/JPEG/WebP in, 8-bit RGBA PNG out, for `Thumb` and `PagePng1x`. The whole module is arranged around one failure: a 70-byte PNG can declare itself 65535×65535, and a decoder whose only verb is *give me the pixels* performs the 17 GiB allocation before anyone can object. So the order is fixed — sniff by magic bytes, build the decoder from the header, check `total_bytes()` against the budget, and only then decode **on the same decoder object**, because checking with one parse and decoding with another is a parser differential where the second reading is the one that allocates. Verified by removing those four lines: the bomb test then ran for over ten minutes instead of refusing instantly. PDF/OOXML remain `NoRenderer`'s, needing D17's out-of-process worker; `PagePng2x` is refused as a decision — upscaling a raster source doubles the cache for interpolated pixels. A decoder *panic* maps to `Refused(SourceUnreadable)`, not `Err`: the same bytes panic identically, so it is a verdict, and calling it ours would invite the retry loop D17 warns about |
| ENC-168 | `GENERATOR` must name the decoder the lockfile actually resolved | P2 | DONE | Fell out of ENC-146a. The rendition cache treats a `generator_version` mismatch as a miss, which is what makes a codec upgrade take effect without a purge — but only if the string moves when the codec does. A test now reads the resolved `image` version out of `Cargo.lock` and fails if `raster/1+image-0.25.10` has drifted, so a dependency bump cannot silently leave the cache serving artefacts from the build it replaced |
| ENC-155 | `sqlx::migrate!` embeds migrations at compile time, so a schema gate can pass against a stale build | P1 | DONE | Closed by a build script on `enclave-db` declaring `rerun-if-changed` on `migrations/` — the macro's input is a directory no `.rs` file mentions, so Cargo had no reason to rebuild and every schema gate applied a schema nobody was running. CI never saw it (it builds from scratch), which is exactly why it survived: it bites only a person iterating locally, at the moment they are trusting a gate. Verified by the original scenario — remove `FORCE ROW LEVEL SECURITY` from a migration, touch no `.rs` file, and the RLS gate now fails naming the table, where before it passed and reported one table fewer than the schema had |
| ENC-172 | Editing an unmerged migration leaves a persistent dev database unusable | P3 | DONE | `VersionMismatch(n)` — a variant name and an integer — now becomes `MigrationModified`, naming the migration and giving the remedy. Nothing is weakened: it still fails, and the checksum comparison behind it *is* the forward-only gate; a test asserts the message sends someone with a **merged** migration forward to a new one rather than backward, so a legible error does not become a documented way round the gate. It bit three more times the same day while building `ENC-501`, which says the message was the smaller half of the problem — `.expect()` prints `Debug`, so the remedy stays invisible where it is needed, and the harness still touches the shared database at all. Both are `ENC-504` |
| ENC-156 | CI `test` job ran the runner out of disk; the linker died with `SIGBUS` | P1 | DONE | Surfaced on PR #30, whose two new test binaries tipped an already-tight budget: this workspace links one statically-linked binary per test target, each carrying the whole dependency graph. There is no `ENOSPC` in the log because `ld` writes its output through an mmap, and a full filesystem raises `SIGBUS` rather than returning an error — which is why it reads as a compiler crash rather than as the capacity problem it is. Fixed by reclaiming the ~25 GB of unused toolchains the hosted image ships and by dropping CI debug info to `line-tables-only`, which keeps file and line in backtraces and drops what only a debugger reads. `df` is now reported either side of the build so a recurrence names itself |
| ENC-147 | Watermark composed per request, never cached | P1 | DONE | D16 made structural rather than asserted: a watermarked artefact has **no cache key it could be stored under**, because `RenditionKey` has three fields and no constructor taking a principal. Caching one would require widening that type first — a diff whose purpose is legible in review. The second control is escaping: the layer is SVG carrying a display name and an email, fields the viewer sets on their own profile, so an unescaped `<script>` is stored XSS delivered on the preview path to every viewer of the document. Every interpolated field is attacked, and the payload must survive *escaped* rather than be dropped — silently discarding a hostile name would let an attacker blank their own watermark by choosing one. Leakage rows A8 and A9 added; G4 clarified as a different vector. Verified by neutering the escaper |
| ENC-157 | `docs/08` offered `preview.watermark_cache` as a deployment setting | P2 | DONE | Found while implementing ENC-147. A control expressed as a default is a control somebody can turn off, and there is no deployment for which caching a watermarked artefact is correct — it either serves one viewer's identity to another or serves a stale identity to its owner. Removed from `docs/08` with the reasoning left where a reader would look for the key, and the guarantee moved into the type system instead. `crates/config` never parsed it, so nothing depended on it |
| ENC-159 | **DMS migration/import path** — no way to bring content in from SharePoint, NetDocuments, iManage or a file share | P1 | TODO | Raised 2026-08-20. Zero coverage in `docs/`: searched for bulk import and migration and found nothing. This is an adoption blocker rather than a feature gap — no enterprise replaces a document system without a path off the old one, and the path has to carry version history, metadata and permissions or the migration loses the record. Needs a spec before it needs code; the shape of it constrains the ingest API. **Now `ROADMAP.md` M8b**, five weeks, which moves Enterprise V1 GA from 2027-09-25 to 2027-10-09 — stated rather than absorbed |
| ENC-160 | Annotations and markup on documents | P2 | TODO | Raised 2026-08-20. Zero coverage in `docs/`. Standard in every DMS this competes with, and it interacts with things already specified rather than sitting beside them: an annotation on a preview is user content stored against an immutable version, it must respect `PREVIEW_ONLY`, and it is discoverable — so it needs a classification and an ACL of its own. **Now `ROADMAP.md` M8**, with an exit criterion |
| ENC-161 | OCR is one line of `docs/07` | P2 | TODO | Raised 2026-08-20. `docs/07 §…` names it only as a fallback *"when a page yields no text"*. For a document system that is backwards — scanned PDFs are a large share of what enterprises actually store, and if they index as empty they are invisible to search while appearing to be filed correctly, which is worse than being absent. Wants a real decision on engine, language coverage and cost. **Now `ROADMAP.md` M3 step 2**, beside extraction rather than after it, with an exit criterion |
| ENC-162 | Version compare / redline is a crate-list entry and nothing more | P2 | TODO | Raised 2026-08-20. `docs/02` lists `versions — version lifecycle, restore, compare hooks`; no document specifies what compare does. Immutable versions make it tractable, and it is one of the two things people open a version history for. **Now `ROADMAP.md` M8** |
| ENC-148 | Replace the preview `501` with the rendition response | P1 | DONE | Closes M2 exit criterion **A1** — `preview=ALLOW, download=DENY` now produces a rendition and still no signed original URL, asserted from the store's side as zero `signed_download` calls. The handler still holds no `BlobStore`; it holds `PreviewPipeline`, one method taking a version and a profile, with no way to name an object key and no method that mints a URL — the same technique the module already used, one level in. **Removing the 501 exposed an obligation drop**: `satisfy` treated `Obligation::Watermark` as satisfied on the honest grounds that nothing was rendered, which stopped being true the moment something was. It now refuses (rule 8), and the delivery test that asserted `501` asserts `403` with the reasoning |
| ENC-169 | Composite the watermark server-side so previews of marked content work | P1 | DONE | The mark is now burned into the pixels before the response leaves, so a preview carrying `Obligation::Watermark` succeeds instead of being refused — which mattered because the content policy watermarks is exactly the content worth previewing. Glyphs rather than SVG: `resvg` is MPL-2.0 against a deliberate allowlist, and a full SVG engine would be a large new parser — the widest attack-surface class here — to draw six lines of text. The face is the Inter subset already vendored for the web client, converted from its `woff2` so the bytes have one provenance rather than a second download. Two defects found while building it, both by tests rather than inspection: a compositor that returned `Ok` having marked nothing on a small canvas (now `CompositeRefusal::NoRoom`), and a stub rendition of eight bytes that made the delivery test pass for the wrong reason |
| ENC-173 | The watermark face covers Latin only, so a non-Latin name is omitted | P2 | TODO | The vendored Inter subset is 230 codepoints: no CJK, Arabic or Cyrillic. A display name it cannot draw is dropped and the mark still carries the email, session, file and timestamp — which keeps a leaked screenshot attributable — but a viewer whose name is in another script sees a mark that does not name them, and if their *email* is non-Latin the preview is refused outright. That is the safe direction and a poor experience for a large part of the world. A font-shipping decision rather than a code one: broader coverage costs megabytes, and per-script subsetting costs a lookup |
| ENC-174 | Watermark timestamps are UTC, not the viewer's locale and time zone | P3 | TODO | `docs/14-I18N-L10N.md` says a watermark renders in the viewer's locale with the timestamp in their time zone. The handler knows neither yet, so it stamps UTC and labels it UTC — honest, and not what the document asks for. Wants the locale on `RequestContext`, which is a wider change than this path |
| ENC-170 | The binary registers two routes whose dependencies it never provides | P1 | DONE | `router()` now **takes** a `Delivery { store, preview }`, so a route whose extension nobody supplies is a compile error rather than a `500` somebody finds in production — adding two `.layer()` calls to `main.rs` would have fixed those two routes and left the shape that produced them. Neither field is optional: a deployment without either passes `UnconfiguredBlobStore` / `UnconfiguredPipeline`, which refuse with a reason and are warned about at start-up beside the unconfigured policy stages, because a deployment missing a capability must look different from one that has it. The unconfigured store's `verify_not_public` returns `Inconclusive`, never a pass — a stub reporting "not public" would turn the absence of a bucket into evidence about one |
| ENC-171 | **Every dependency outage in the API rendered as `500`, not `503`** | P1 | DONE | Found by ENC-170's own test, which asserted an unconfigured deployment answers something other than `500` and did not. `ApiError::into_response` re-derived the status in its own `match`, and had no arm for `Error::Upstream` or `Error::QuotaExceeded` — both fell into the catch-all. So PostgreSQL down, object storage down, Milvus down all reported as our own defect inside our own error budget, and a capacity-quota refusal told the caller to retry something that could never succeed. `enclave_core::Error::status_code` documents itself as living there so that *"two handlers [do not answer] the same failure with different statuses"*, and the renderer ignored it. It now renders that value directly, so the arms choose only the body and there is nowhere for a second opinion to live. A test asserts the two agree for every variant |
| ENC-149 | `crates/sharing` — share links, token hashing, expiry, revocation | P1 | DONE | Migration 0008. The token is 256 bits of OS entropy and the database holds only SHA-256 of it, so a backup yields no working link — mirroring `enclave_auth::RefreshToken` down to the method names, because two token primitives making different choices about the same problem is how one ends up wrong. Every refusal — unknown, malformed, expired, revoked, exhausted — is one answer to a redeemer; separate answers would tell an attacker whether a guessed token ever existed, turning a 256-bit search into an oracle. `share_link_events` is granted INSERT and SELECT only, so the evidence that somebody probed a link cannot be edited away. Password/OTP/domain/MFA enforcement is H2 and stays in `crates/auth` |
| ENC-150 | Atomic download budget — `max_downloads` under concurrency | P1 | DONE | H3. The limit is in the `WHERE` clause of the `UPDATE` that spends it, so the read and the write are one statement; a zero-row result is the refusal. **The first test of this was vacuous and that is the finding**: fifty tasks against the harness pool passed with a deliberately naive implementation three times out of three, because `TestDb::pool` caps connections at two for the D3 proof — fifty tasks two at a time is a sequential test wearing `tokio::spawn`. Widening the pool was not enough either; the stale-read window is real but too narrow to hit by luck. Now proven by a second test that holds the window open on a barrier until every contender is inside it, which fails 3/3 without the clause. `TestDb::pool_with_connections` exists because of this |
| ENC-163 | A concurrency test on a two-connection pool proves nothing | P2 | DONE | Found by ENC-150's negative control failing to fail. `TestDb::pool` caps at two connections deliberately — the D3 pool-exhaustion proof depends on it — but every future test whose subject is a race will inherit that cap and quietly become sequential. `TestDb::pool_with_connections` added beside it, with the reason written where the next person will read it. The general lesson is the one the gates already taught: a green concurrency test is worth nothing until the wrong implementation has been watched to fail |
| ENC-151 | `crates/metadata` — fields, values, validation | P1 | DONE | Migration 0009. The crate's rule is **reject, never coerce**: a `NUMBER` that accepts `"42"` has decided a client sending strings is fine, and the next one sends `"1e999"`. Validation is in two halves — shape is pure and total so it can run over every field of every row; existence needs a tenant-scoped transaction, and a reference resolved without one would be an oracle for what exists in another tenant. `value_text` is `GENERATED ALWAYS` rather than written, so the projection filters and sorts read cannot drift from its source — proven by the insert that names it being refused |
| ENC-164 | Dates must be stored in canonical form, or `value_text` sorts wrong | P2 | DONE | Found writing ENC-151's tests. `chrono` parses `2026-8-2` happily and it is an unambiguous date — but as *text* it sorts after `2026-12-01`, and `value_text` is what a library orders by. Same for timestamps, worse: `Z` and `+00:00` and `.000Z` are the same instant and three sort positions, so a column holding a mixture cannot be ordered at all. Both now require the canonical form, checked by round trip — parse it, format it, require equality — which refuses the non-canonical spelling without rewriting it |
| ENC-165 | I recreated a table migration 0004 already had | P2 | DONE | `content_types` is listed in `docs/04 §10` beside the metadata tables, so 0009's first draft created it. `CREATE TABLE IF NOT EXISTS` silently did nothing and the `CREATE POLICY` after it failed — which is the *useful* shape of the mistake, because a policy is exactly what a silently-skipped duplicate would have been missing. Straight violation of `CLAUDE.md`'s "check before assuming: read the file rather than trusting a doc that describes an intention", by the session that quotes that rule at other people. Recorded rather than quietly fixed |
| ENC-166 | `serde_json::Value`'s `Drop` is recursive; its parser caps at 128 levels | P3 | DONE | The JSON depth check has to run *before* the size check, because `serde_json`'s serializer recurses and measuring an over-deep value overflows the stack — the defence dying on the input it exists to reject. The first test of this crashed the binary while *constructing* its input, which is how the ordering got found. The parser's 128-level limit is now asserted in a test rather than assumed in a comment, because the ordering is only sufficient while that limit holds |
| ENC-152 | `capabilities` on every file response | P1 | DONE | Batch-resolved: a 200-row page costs the same 10 `authorize_many` calls as a 1-row page — the per-row loop it replaces would have been 1,800. The contract that matters is that a listing row and `GET /files/{id}` are the *same object*, so the UI cannot change its mind about what a user may do purely because they clicked in; asserted directly, and mutation-checked by dropping one action from the batch path. `From<&FileNode>` was removed so a row can only be built by someone holding a resolved answer — a conversion from the node alone could only invent nine `false`s. Views (`ROADMAP.md` M2 step 7, no row yet) deliberately not included |
| ENC-167 | `authorize_many`'s cost is ~80% fixed, which inverts an M3 design assumption | P1 | DONE | Resolution now batches **actions** as well as resources: `action = ANY($2)`, and the resolver keys answers by `(action, resource)` through an `EffectiveGrid` rather than nested vectors — the only interesting bug here is a transposition, and nested vectors leave the axis order as a convention in a doc comment. Measured: ten actions over 200 candidates in **one pass, p50 8.1 ms**, against **68.5 ms** for ten passes — 8.48× cheaper, 60 ms per listing page. Mutation-checked three ways (rows filed into every bucket, bucket shifted by one, resource axis reversed), each caught. The M3 consequence stands and is now cheaper to act on: one resolution answering both disclosure levels is a single call |
| ENC-175 | The API cannot reach multi-action resolution yet | P1 | DONE | `AuthorizationService` gained a **defaulted** `authorize_many_actions` whose body loops the existing method — so every stub, test double and unconfigured stage keeps working and answers identically, only slower — overridden by `PgAclAuthorization` with the real one pass. Making it a required method would have turned a performance improvement into a breaking change for six deny-by-default stages with no use for it. `capabilities_for_many` now makes one call where it made nine, which is the 60 ms `ENC-167` measured. The unit test counting resolutions was corrected rather than left: it counts a stub that uses the default body, so it proves the count does not scale with the *page* and cannot prove it does not scale with the *actions* — that belongs to the override, and is measured where it can be |
| ENC-153 | Leakage matrix rows A1, A5, A6, H1–H3 | P0 | DONE | A5 and A6 now assert against a real MinIO. A5 proves a stored object is unreachable unsigned — with the object provably present and the unsigned path asserted identical to the signed one, so the `403` is neither a missing object nor a mistyped bucket — and that a signature is bound to the key it names, so one leaked URL is not a key to the bucket. A6 pins expiry, and is explicit about what it **cannot** prove: single use does not exist on any S3 backend, so rather than fake it the test asserts the store *reports the capability absent*, leaving the short TTL visibly the only control on a captured URL |
| ENC-176 | `ttf-parser` is unmaintained, reached through `ab_glyph` | P2 | TODO | Accepted with the reasoning rather than waved through. An unmaintained *parser* is normally a serious finding here — D17 exists because parsers are the widest attack surface in this product — and this one differs in the way that decides it: it never sees attacker-controlled input. The only font it parses is vendored in this repository and compiled in with `include_bytes!`; what a viewer controls is the text, which our own code bounds. Ends when `ab_glyph` moves to a maintained parser **or when the watermark needs a font we do not ship**, because that is when the argument stops holding. Revisit 2026-11-20. Recorded in **both** `deny.toml` and `.cargo/audit.toml` — the first attempt updated only one, and CI caught it: two advisory gates with separate configs is a trap worth knowing about |
| ENC-154 | Planned tracker IDs `ENC-200`–`ENC-2xx` were never instantiated as rows | P3 | DONE | Twelve dangling `Depends on` entries in `§4` Phase 2, not the two the row named, plus one inside `ENC-152`'s note — all pointing into the empty `ENC-200` block. Fixed by dropping the phase-blocked ID scheme rather than by renumbering — `§2.3` now says a number carries no phase, records where each existing block came from, and starts new rows at `ENC-500`. Renumbering was the other option and was rejected on the rule the scheme itself states: numbers are never reused, and sixty completed rows have their IDs in branch names, commits and merged PRs, so restoring the blocks would have broken references outside this file to recover a property nothing reads. Each Phase 2 dependency now names either a row that exists or the `ROADMAP.md` milestone the prerequisite belongs to, because six of them were prerequisites nobody has logged yet and an ID would have been a guess. `ROADMAP.md` hands out the same phantom numbers in `§3` and `§5` and is out of scope here — logged as `ENC-500` |
| ENC-500 | `ROADMAP.md` still allocates the `ENC-200`–`ENC-226` IDs that `ENC-154` retired | P3 | TODO | Raised 2026-08-20 by `ENC-154`, and scoped out of it rather than absorbed (`§2.1` rule 5): `ROADMAP.md §3` draws its critical path through `ENC-208`/`ENC-215`/`ENC-224` and every `§5` milestone opens with a **Tracker:** line naming a range of numbers no row ever used, so a reader who follows one from the roadmap into this file finds nothing and cannot tell whether the work is unlogged or already done under another number. Mostly transcription rather than investigation — M1's `ENC-200` is `ENC-125` and its `ENC-203` is `ENC-130`, M2's `ENC-208` is `ENC-126`, M3–M5's are prerequisites nobody has logged — but the mapping is not one-to-one and the roadmap's ordering is not this file's, so it wants reading line by line rather than substituting. First new ID under the `§2.3` scheme |
| ENC-501 | Saved views — `library_views`, migration 0010 | P1 | DONE | M2's last substantive item. A view is an **arrangement, never a permission**: it decides what is displayed, and the policy chain decides what exists, so the two compose in one direction only — a view can hide a row a caller may see and can never reveal one they may not. Made structural rather than stated: the module takes no `RequestContext`, resolves no ACL and reads no content table, asserted by a test over the statements themselves. Migration 0010 carries three invariants `docs/04 §10` leaves as prose — one container, an owner exactly when personal, a personal view never a library's default — because an assumption a database does not enforce is one that holds until the first bulk import. A test caught a real bug in `set_default`: a *refused* promotion still demoted the existing default, leaving the library opening to nothing while the caller was told `false` |
| ENC-502 | `library_views.list_id` has no foreign key | P3 | TODO | Not a decision: `lists` has no migration yet, and a key cannot reference a table that does not exist. The `CHECK` insisting on exactly one container keeps a row naming a list at least well-formed until the milestone that creates `lists` adds the key. Noted where the column is declared so whoever writes that migration finds it |
| ENC-503 | CI pulls ClamAV anonymously, so a registry change reads as a security-test failure | P2 | DONE | Found while closing `ENC-140`. Anonymous Docker Hub pulls work today — 100 per six hours per source IP, stated inside the token — so the dev stack needs no login. The exposure is CI: `.github/workflows/ci.yml` pulls `clamav/clamav:1.4` anonymously and runs the EICAR tests, so if Hub closes anonymous pulls or a busy runner IP exhausts the budget, **leakage row G1 fails and looks like a security defect rather than a registry one**. No mirror exists — quay, ghcr and ECR all checked. Fixed by the second option, a failure that names its cause: the pull is now its own step, retried three times with backoff, and `docker run --pull never` below it so the start step cannot quietly re-pull and re-blur the boundary. An exhausted pull says *"ClamAV image pull failed — REGISTRY, not a security failure"*, states the 100-per-six-hours-per-IP budget and that hosted runners share addresses, and says outright that G1 was **not evaluated** — nothing asserted, nothing failed. The readiness timeout was reworded the same way. The retry is honest about its own limits: it covers a 5xx or a dropped handshake, and a 429 resets in *hours*, so it burns all three attempts and lands on the message, which was always the deliverable. The cached-image option was rejected rather than skipped — a warm cache still needs a pull to fill it, and pinning what gets cached would freeze the signature database that the floating `1.4` tag exists to keep moving |
| ENC-504 | The migration checksum papercut is half-fixed | P2 | TODO | `ENC-172` made the error name its migration, and it still cost three interruptions in one afternoon. Two things remain. The remedy is on `Display` and every call site uses `.expect()`, which prints `Debug` — so `MigrationModified { version: 10 }` is what a person actually sees, better than before and not the sentence that was written for them. And the harness applies migrations to the `DATABASE_URL` database as well as its throwaway one, which is why an unmerged edit poisons a developer's database at all; option (b) from the original row — stop touching the shared database — is the fix that removes the class rather than labelling it. **2026-08-20: the visible half landed; the row stays open for option (b).** `HarnessError` now implements `Debug` by hand — its `Display` plus the source chain beneath it — because `expect` formats with `Debug` and follows no `source()`, so the remedy written on `DbError` was one link further down than anything a panic ever printed. `NoDatabaseUrl` had the same disease and is fixed by the same impl: a variant whose entire value is the compose command it names was printing as the thirteen characters of its own identifier. Chosen over giving the variant a hand-written `Debug`, which would have meant editing `DbError` — a type every crate handles — to fix a rendering problem that only exists where tests panic, and would have left the harness's other messages just as invisible. **Nothing was weakened**: the checksum comparison, the forward-only gate and `is_retryable() == false` are untouched (`ENC-116`), and the test asserts on `{:?}` rather than `{}` precisely because asserting `Display` is what let the visible half stay broken through `ENC-172`. A third test pins the redaction, since printing `Display` prints whatever a message interpolates |
| ENC-505 | `docs/07 §6.2` describes a two-pass post-filter that the measurement contradicts | P1 | TODO | The section resolves `MetadataRead` and `ContentRead` separately, which was right when `authorize_many` batched resources only. `ENC-145` then measured resolution as ~80% fixed cost — 1.4 ms for one candidate, 7.0 ms for two hundred — so a second pass very nearly doubles the post-filter's price, while over-fetching more is close to free. `ENC-167` made one call possible. The document still shows the old form in a code example, and a code example in a specification is a thing people copy. `plans/M3-DISCOVERY.md` D20 locks the decision; this row is the document catching up |
| ENC-506 | The authoritative post-filter and the retrieval denylist | P0 | DONE | M3's first task by design — the guarantee before the thing it guards. Migration 0011. Built against a **fake** candidate generator, which is the stronger test rather than the weaker one: a fake proposes another tenant's file, a nonexistent file and an ungranted file, which a real index would offer only by accident, so S5 states the contract in full. Both disclosure levels resolve in one `authorize_many_actions` (D20). Verified by deliberate violation — trusting the index leaves all four candidates surviving. **The second control found a real weakness in my own tests**: S3 and S4 stayed green with the denylist consultation removed, because a revocation deletes the ACL and the post-filter refuses the file anyway. The denylist is defence in depth there and *necessary* only for staleness an ACL does not capture, so a test that isolates it was added and `docs/12 §4.3` now says so |
| ENC-508 | Embedding provider port with classification routing (S8) | P0 | DONE | D23. The routing lives in the **carrier**, not the caller: `ClassifiedText` holds the chunks and the rank and has no method returning the chunks, so the only way to obtain a `TextBatch<Remote>` is through an admission that refuses at and above the ceiling — **holding one is the proof its text was below it**. Verified the way that matters: writing the 3am fallback (`Err(timeout) => self.remote.embed(..)`) does not compile — `expected TextBatch<Remote>, found ClassifiedText`. The helpful edit is rejected by the compiler rather than by a test. The remote double *panics* rather than erroring, because an `Err` is something a router could plausibly handle and move past, and then the double cannot tell "never reached" from "reached, refused, recovered" — the second being the bug. Three routes to a document that *looks* indexed and is not are closed as well: an unavailable local model returns `LocalUnavailable` rather than the tempting `Ok(vec![])`, and a short batch is refused |
| ENC-509 | Q14 — which local embedding model, and how it ships | P1 | TODO | Blocks a real embedder; both stubs report `dimensions() == 0` deliberately rather than a plausible 384 or 768, because the number is not guessable and a guess would look decided. Four decisions, the first two expensive to reverse: **which model** (it fixes the Milvus collection width and `index_manifests.embedding_model`, so changing it later is a full reindex); **in-image or mounted** (decides whether an absent model is a startup failure or the wait state the crate models, decides image size, and decides the air-gapped story — a mounted model means a customer volume plus a checksum we verify); **in-process or sidecar**; and **max input length**, which interacts with Q13's chunk size. A width check at construction was left out on purpose and said so: with both stubs at `0`, a constructor refusing disagreement would refuse nothing while looking like it checked |
| ENC-510 | Text extraction in the sandboxed worker | P1 | DONE | D24. Depends on `enclave-preview` rather than copying its bounds — extraction runs in the *same* D17 worker as rendering, so they share one memory limit, wall clock and input cap, and two names for one budget is how two sets of numbers appear behind them. Three genuine differences, each named rather than forked: the output cap is charged per *segment* because a `TextDocument` is a `Vec` whose size is not a function of text length (10 MB of blank lines is 10 M structs); `ExtractorVersion` is not `GeneratorVersion`, because a stale rendition self-heals as a cache miss and a stale index is wrong until somebody pays for a reindex; and a textless source is a third outcome, `NoText`, so a future PDF extractor cannot reach `READY` with nothing behind it. PDF/OOXML deliberately absent — `NoExtractor` answers, on raster's own argument that a partial implementation is worse than a refusal, and worse here: a half-rendered preview looks wrong, a half-extracted index looks like the document |
| ENC-511 | Extraction refuses anything that is not UTF-8, rather than decoding it lossily | P2 | DONE | The reasoning is worth keeping because it looks like fussiness and is not. Preview and download hand a browser the **original** bytes, decoded by the browser's rules; a second decoder here means indexed text ≠ displayed text, and every DLP match, classification label and excerpt downstream becomes a statement about a document nobody can see. `from_utf8_lossy` gives the concrete form — Latin-1 `café` indexes as `caf<FFFD>` and a word-boundary DLP pattern stops matching text a viewer reads plainly. So: UTF-16/32 BOM is `UnsupportedFormat` (known, no decoder); invalid UTF-8 without a BOM is `SourceUnreadable` (declared itself text, did not decode); a NUL anywhere is refused on a whole-input scan, because PostgreSQL `text` cannot store `U+0000` however it decodes |
| ENC-512 | Parallel sessions clobbered each other through a shared `/tmp` scratch name | P2 | TODO | Two sessions independently chose `/tmp/<module>.rs.bak` for a backup during a deliberate violation, and one overwrote the other's — a `text.rs` from one crate was restored into another. Caught by `cargo fmt --check` and repaired, and both trees verified undamaged. I made it worse mid-flight by deleting `/tmp/*.bak` during a disk cleanup while sessions were running. Two lessons, and the second is the general one: scratch belongs in a per-session directory, and a cleanup that runs while other work is in flight is a change to that work |
| ENC-513 | Structure-aware chunking with deterministic ids | P1 | DONE | `chunk_id = uuid_v5(version_id, chunker_version || ordinal)`, per `docs/07 §2`. Indexing runs off an at-least-once outbox, so a retry is the *ordinary* case — and with random ids a worker that crashed halfway inserts a second copy of every chunk that nothing ever removes. The quiet part is worse than the duplication: an orphaned copy keeps the `acl_tokens` of the run that wrote it **forever**, because nothing knows it exists to update. The post-filter still refuses it, so it is not a leak — it is permanent over-fetch that worsens with every retry and shows up as a drop ratio climbing for a reason nobody can find. Verified by deliberate violation twice: dropping the separator makes chunker `v1`/ordinal `23` collide with `v12`/ordinal `3`, and disabling the boundary check merges five segments into one chunk. The window is in **characters, not tokens** — tokenisation is a property of a model `ENC-509` has not chosen, and a guess would size chunks for a model the deployment may not run |
| ENC-514 | Degraded search: lexical retrieval over PostgreSQL | P1 | DONE | D25, and still post-filtered — a worse *recall* guarantee, never a worse *authorization* one. An unmarked degraded result is unconstructible rather than merely unwritten: `SearchResults.degraded` is private with no setter, the type is built only by `confirm` (never degraded) or `confirm_degraded` (always), and `LexicalCandidates` is opaque so the only thing you can do with lexical output is hand it to the function that post-filters **and** marks it. Deliberately **not** latency-triggered — a latency trigger engages under load, which is when the vector path is most valuable, and it engages per request so the same query answers completely at 10:00:01 and degraded at 10:00:02 with no state change, which nobody can reproduce |
| ENC-515 | Lexical search cannot find document *content* | P2 | TODO | Named by `ENC-514` rather than glossed. There is no extracted-text table yet, so degraded mode searches file names and scalar metadata only: a contract whose body says "indemnity" is invisible unless that word is in the filename. Also no prefixes (building a `tsquery` from untrusted input is not a parser to introduce on the incident path) and no stemming (a stemmer must assume a language, and assuming wrongly fails silently). Lands with the chunk store |
| ENC-516 | A vector store that is up but *wrong* does not trigger degraded mode | P1 | TODO | The gap `ENC-514` named in its own design. The trigger covers loud failures — unreachable, circuit open, denylist over its limit — and a store that is reachable but empty (collection recreated, botched rebuild) keeps the circuit closed and returns `degraded: false` with very few hits. That is the worst shape available: confidently complete, and wrong. Closing it needs an index-health signal — `index_manifests` READY count against what the store actually holds |
| ENC-517 | `CREATE INDEX CONCURRENTLY` deadlocks against the test harness's setup lock | P1 | DONE | Two findings, and the second one is the lesson. First: PostgreSQL wraps multiple statements in one round trip in an implicit transaction, so two `CONCURRENTLY` builds in one file fail with `25001` from a file that had carefully opted out of a transaction. Second, and worse: `CONCURRENTLY` waits for every concurrent transaction holding an older snapshot, while `TestDb` serialises setup behind a **session-level advisory lock held across the whole migration run** — so one binary blocks inside `CONCURRENTLY` waiting for transactions belonging to binaries that are waiting for the lock it holds. `40P01`, every database-backed test failing, and the failure naming the RLS gate rather than the migration. **I saw this locally, called it an unrelated race, re-ran it green, and shipped it** — which is exactly the reasoning that lets a flaky test survive. Now plain `CREATE INDEX IF NOT EXISTS`, with the zero-downtime path documented as an operator step that makes the migration a no-op. Verified both directions: the old form reproduces 8 deadlocks, the new form zero across two full runs |
| ENC-518 | The invalidation sweep and the epoch reconciler | P1 | DONE | D22's cleanup half. The safety argument for lifting a suppression is exactly one sentence: the search path already treats an expired row as lifted, so deleting it is unobservable before, during and after — which is also why the sweep needs no crash recovery. The reconciler is kept from becoming load-bearing by three structural refusals rather than a plea: no freshness oracle on its public surface (that is the function a search would eventually call to skip work), it never writes `retrieval_denylist` (that would make S4 pass because the reconciler ran rather than because the write is in the ACL transaction), and it writes one column of one table. Concurrency: the sweep takes `pg_try_advisory_xact_lock` per tenant and the loser reports `Contended` rather than queueing behind row locks it could deadlock against; the reconciler uses `SKIP LOCKED` so two workers partition rather than contend. **Its racy concurrency tests passed under lock removal**, so each has a deterministic counterpart — the `ENC-150` lesson, applied by the session that read it |
| ENC-519 | `lift_expired` compared a caller's clock against the database's | P1 | DONE | Found by the session building the sweep on top of it, in code I had written the same day. `suppressed` judges expiry against PostgreSQL's `now()` because it runs in the search's transaction; `lift_expired` took a `now` from its caller. Two clocks: a worker running a few seconds fast deletes rows the database still considers in force, and the suppressed file becomes findable early — briefly, on one node, for reasons nothing logs. The session worked around it correctly at its call site; I removed the parameter instead, so the hazard is not available to the next caller. The `DELETE` now compares against `now()` in the same statement, and the sweep reads no clock at all — the strongest form, because there is nothing left to pass wrongly |
| ENC-520 | Nothing can express "the index has caught up" | P2 | TODO | Named rather than proxied. `migrations/0011` says `clears_at` means the index has caught up, and no column can answer it: a denylist row carries no reference to an index write; `acl_epoch` is about a *rewrite* of ACL tokens, not a *removal* from the vector store; a suppressed file may have no manifest row at all, so a manifest join reads "caught up" and "never indexed" identically; and a NULL `clears_at` is exactly the case where nobody has asserted it. The sweep lifts on expiry alone and says so. A proxy here would be the kind of almost-right signal that makes S4 pass for the wrong reason |
| ENC-507 | A crates.io outage fails whichever gate happens to be running, under that gate's name | P2 | DONE | Raised and worked 2026-08-20 with `ENC-503`, logged as its own row rather than absorbed (`§2.1` rule 5): same disease, different registry. `main` went red on `failed to get successful HTTP response from https://index.crates.io/... got 503` and it arrived as **`RULE: every tenant_id table is granted to enclave_app, which cannot bypass RLS`** — the sentence for a tenant-isolation defect, printed for a CDN having a bad minute. A check whose red state can mean either is one people re-run instead of read, and the run that gets waved through as flaky is eventually the real finding. Fixed by separating the fetch from the verdict: every cargo job in `structural-gates.yml`, `security.yml` and CI's two security-asserting jobs now runs `cargo fetch --locked` in a step of its own, retried four times with quadratic backoff (~70 s), which says *"Dependency registry unavailable — NOT a gate failure"* and *"nothing was asserted and no rule was broken"* when it gives up. It works because that fetch is the only crates.io traffic in these jobs — afterwards the assertion resolves from `Cargo.lock` and the local cache and touches no network, so an outage can only fail the step that names the registry. **Only the fetch is retried, and the comment at each site says so**: three attempts at "is EICAR quarantined" passes on the run where the answer was no, once. Two `Explain on failure` steps were re-conditioned on the gate step rather than on the job, because a fetch failure was otherwise printing a full page about which security rule had been broken; the pending gates skip the fetch entirely via `hashFiles`; and the scheduled-scan P0 issue template now says to read which step failed before triaging an advisory that may not exist |

**Accepted risk, `ENC-138`:** `RUSTSEC-2026-0253` — unsoundness in `lru`, reached transitively
through `aws-sdk-s3`. `LruCache::pop()` is not panic-safe. Accepted because there is nowhere to
move to: `lru 0.16.4` is the latest release, the advisory names no patched version, and the SDK pins
it. Suppressed in `.cargo/audit.toml` with its reason and its expiry condition — it ends when
`aws-sdk-s3` bumps past the fix, and `cargo audit` will say so on the first build after that. An
acceptance, not a resolution.

**Phase 1 (MVP) is feature-complete.** Content enters through a scanned, versioned, immutable path
and leaves through a policy-gated one. 922 tests, 8 routes, every handler proven to reach the chain.

**Next:** **M3 — Discovery**, plan at [`plans/M3-DISCOVERY.md`](plans/M3-DISCOVERY.md). **M2 is closed** — all five exit criteria demonstrated, definition of done met, assessment in [`plans/M2-CLOSEOUT.md`](plans/M2-CLOSEOUT.md). No gate falls here: `ROADMAP.md §6` puts G1 at the end of M5.

M3 carries the highest-severity design risk in the product, and the plan is arranged around one sentence — the vector index is a candidate generator, PostgreSQL is the authority. Two decisions in it exist because of what M2 measured: both disclosure levels resolve in **one** call (D20), and over-fetch is the cheap side of the trade (D21). `docs/07 §6.2` describes a two-pass design that predates the measurement and needs correcting before it is copied.

**Correction (`ENC-142`).** This line previously read *"Next: gate G1 — ship the MVP?"*, and
`plans/M1-CONTENT-CORE.md §5` said the same. Both were wrong: `ROADMAP.md §6` places **G1 at the end
of M5**, with M2, M3 and M4 in between. The error originated in the M1 plan and was copied here, which
is exactly the failure mode `plans/README.md` warns about — a plan restating a roadmap commitment
instead of referring to it. Had it stood, M1 would have been assessed against the MVP's ship criteria
four milestones early, and the four milestones of work those criteria assume would have been read as
missing rather than as not yet due. Both documents now point at the roadmap.

**Follow-up worth doing first (`ENC-137`):** `Cursor`, `PageSize`, `FilterFingerprint` and
`normalize_slug` live in `enclave-identity` and are now used by four crates. They are a security
primitive — a cursor is signed and bound to a tenant and filter set — and they belong below the
domain layer, not inside one domain crate that others reach sideways into. Flagged by the
implementing session rather than found in review.

**M0 is now fully closed.** Exit criterion 1 — one request traversing login → JWT → `enforce` →
tenant-scoped query → audit row — is demonstrated by `crates/api/tests/me.rs`, not asserted.

> **ENC-116 — decided 2026-08-18 by the repo owner: option (c), accept.** The racy `CREATE ROLE`
> stays in migration 0001. It is not amended, so the forward-only rule and the gate that enforces it
> remain intact with no exception carved into either.
>
> The risk is accepted on the basis that role provisioning is a deployment concern: roles are created
> before any migration runs — `deploy/compose/init/01-roles.sql` locally, the credential provisioning
> step in production (`docs/11-OPERATIONS.md §12`) — which makes 0001's guard a no-op. Verified at
> 0 failures in 10 stress runs where it previously failed 10 out of 10.
>
> **The residual risk, stated plainly so it is not rediscovered as a surprise:** anyone who migrates
> into a cluster where the roles were never provisioned can still hit the race, and the symptom is an
> opaque `unique_violation` on `pg_authid_rolname_index` during startup. `docs/11-OPERATIONS.md §12`
> documents the provisioning step as a requirement rather than a suggestion, which is what makes this
> acceptance defensible rather than merely convenient. Revisit if migrations ever create another
> cluster-wide object.

> **The original framing, kept for the decision record.** The clean fix is to catch `duplicate_object` **and**
> `unique_violation` in migration 0001 — but 0001 is merged, and migrations are forward-only
> (`CLAUDE.md`), which the structural gate enforces with no escape hatch. A later migration cannot
> repair it: 0001 runs first and fails before anything else executes. So the options are (a) amend
> 0001 and grant the gate a narrow, reviewable pre-release exception, (b) move role creation out of
> migrations entirely into deployment provisioning — which is where 0001's own comments say
> credentials come from — or (c) accept it, since production role provisioning is a deployment
> concern anyway. My recommendation is (b): migrations arguably should not be creating cluster-wide
> roles at all. Not decided unilaterally, because it touches a control.

> **Branch protection is unavailable on this plan — closed, not deferred.** Both
> `repos/CasualOffice/enclave/branches/main/protection` and `/rulesets` return
> `403 Upgrade to GitHub Pro or make this repository public`. The repository is private under an
> organization account, so required status checks cannot be enforced server-side without either
> paying for Pro or making the code public. Neither is mine to decide.
>
> This matters because it was the mitigation proposed twice after `main` went red: PR #10 and PR #12
> were both merged while their checks were still running, and both landed a known failure. Until the
> plan changes, that remains a process control rather than a technical one — **wait for green before
> merging**. Every gate is wired to block *in CI* (`structural-gates-status` requires all eleven);
> what is missing is GitHub refusing the merge button, not the signal.

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
| ENC-017 | `security.txt` + PGP key published at casualoffice.org | P2 | TODO | Drafted at [`.well-known/security.txt`](.well-known/security.txt) and deliberately left unparseable: `Expires` and `Encryption` are `<REPLACE_ME>`, so an RFC 9116 reader rejects the file outright rather than half-trusting it if it is ever deployed unfinished. Confirmed still open — `https://casualoffice.org/.well-known/security.txt` 404s today while `SECURITY.md` tells reporters to fetch a PGP key from it. **Needs from the repo owner:** (1) confirmation that `security@casualoffice.org` reaches a monitored mailbox — the domain has Cloudflare Email Routing MX records so mail reaches *something*, but routing is per-address and not visible from here, and the address was transcribed from `SECURITY.md`/`README.md`, not chosen; (2) a PGP key, generated and published at a stable URL — no key material belongs in this repository (rule 11), which is why the field takes a URL; (3) an `Expires` date and the person who renews it. The GitHub advisory URL is on the file already because it is the one contact that can be verified from here. Publication is a step on whatever serves the apex domain — it is not this repository |
| ENC-018 | Confirm legal entity name on the LICENSE copyright line | P2 | TODO | Left untouched on purpose. A placeholder is the right answer in a draft `security.txt` and the wrong one in a copyright notice: "Copyright 2026 REPLACE_ME" is a defective grant, worse than the trade name already there, and Apache-2.0 §4 obliges downstream redistributors to carry whatever this line says. **Needs from the repo owner:** the registered entity name and its jurisdiction, or a decision that copyright is held personally. Two files carry the string and must move together — `LICENSE` line 189 and `README.md` §License |
| ENC-019 | Development roadmap: milestones, gates, sequencing, risks | P1 | DONE | Requested 2026-08-18 · `ROADMAP.md` |
| ENC-020 | Product rename Vault → Enclave; ID prefix `VLT-` → `ENC-` | P1 | DONE | Requested 2026-08-18. HashiCorp Vault references deliberately preserved |
| ENC-021 | Rename the working directory `services/vault` → `services/enclave` | P2 | BLOCKED | Assessed 2026-08-20 and the caution in the original note is aimed at the wrong risk. **Nothing in the repository depends on the path:** `git grep services/vault` matches this row and nothing else, the directory being renamed *is* the repository root so git tracks no name for it, the remote is `git@github.com:CasualOffice/enclave.git` and is unaffected by what the checkout is called locally, and CI runs from `$GITHUB_WORKSPACE` and never names it. What a rename does break is untracked local state: the 29 GB `target/` tree, whose artefacts and `.d` files carry absolute paths, forcing a full rebuild, and the working directory of every editor, shell and agent session currently open on the old path — including, if an agent were to run it, its own. **Blocked on the repo owner**, because it cannot be done from inside the tree and must be done with nothing running: `mv services/vault services/enclave` from `melp/`, with no repository change of any kind |
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
| ENC-103 | `core` crate — typed IDs, `RequestContext`, `Error` | P1 | DONE | ENC-100 |
| ENC-104 | `db` crate — pool, migrations, `TenantScoped` guard | P1 | DONE | ENC-103 |
| ENC-105 | Migration 001: tenancy, identity, RLS policies | P1 | DONE | ENC-104 |
| ENC-106 | RLS coverage CI gate — fails on any unprotected table | P0 | DONE | ENC-105 |
| ENC-107 | `audit` crate — append-only writes, hash chain | P1 | DONE | ENC-104 |
| ENC-108 | `events` crate — outbox, JetStream publish, idempotency | P1 | DONE | ENC-104 |
| ENC-109 | `PolicyEngine::enforce` skeleton, all six stages wired | P1 | DONE | ENC-103, ENC-107 |
| ENC-110 | Policy-routing CI gate — every handler reaches the engine | P1 | DONE | ENC-109 |
| ENC-111 | `auth` crate — Argon2id, JWT issue/verify, refresh rotation | P1 | DONE | ENC-105 |
| ENC-112 | Test harness: disposable databases + `tenant-alpha`/`tenant-beta` fixtures | P1 | DONE | ENC-105 |
| ENC-113 | Dev Compose stack: PG, Redis, NATS, MinIO, Milvus, ClamAV | P1 | DONE | — |
| ENC-114 | OpenTelemetry wiring + span attribute conventions | P2 | DONE | ENC-103 |
| ENC-115 | `enclave-cli seed` for dev tenants | P2 | DONE | ENC-112 |
| ENC-116 | Migration 0001 `CREATE ROLE` is check-then-act; concurrent first-migration across databases in one cluster fails | P2 | DONE |
| ENC-117 | Make the accepted ENC-116 race legible when it fires | P2 | DONE |
| ENC-118 | Run the database tests in CI — 24 of 27 ran nowhere | P0 | DONE | Gate G0 finding. Hid five self-deadlocks, an env-var split, cross-test interference and three prose blocks masquerading as doc-tests. | Researched, decided and implemented rather than escalated. sqlx locks per **database**, so same-database replicas are already safe; only multi-database-per-cluster races. The defect worth fixing was the opaque error, not the race. | Found by ENC-112. Reproduced 10/10. Worked around in the harness with an advisory lock; the defect itself remains. Two API replicas starting together against different databases in one cluster would hit it. **Needs a decision** — see the note below. |

### Phase 1 — MVP

Per `docs/01-PRD.md §37`. Plan: [`plans/M1-CONTENT-CORE.md`](plans/M1-CONTENT-CORE.md).
Exit criterion: a tenant can store, find, share and govern content, with the leakage matrix green.

**Carried from gate G0 — these land before any content work:**

| ID | Item | Pri | Status | Depends on |
|---|---|---|---|---|
| ENC-119 | Bump `ipnetwork` 0.20 → 0.21 | P1 | DONE | — |
| ENC-120 | Bump `rand` 0.8 → 0.10 | P1 | DONE | — |
| ENC-121 | Bump `ed25519-dalek` 2 → 3 | P1 | DONE | ENC-120 |
| ENC-122 | Bump `jsonwebtoken` 9 → 11 | P1 | DONE | ENC-121 |
| ENC-123 | Bump `sqlx` 0.8 → 0.9 — touches every query, so it lands alone and early | P1 | DONE | ENC-119 |
| ENC-124 | `GET /api/v1/me` end to end — closes M0 exit criterion 1 | P0 | DONE | ENC-123 |

**Content:**

| ID | Item | Pri | Status | Depends on |
|---|---|---|---|---|
| ENC-125 | Tenancy, users, groups, membership | P1 | DONE | ENC-124 |
| ENC-127a | Grant-coverage gate — every tenant-scoped table must be reachable by `enclave_app` | P1 | DONE | Found by ENC-124. The RLS gate structurally cannot see this: it checks policies, not whether the role they apply to can reach the table |
| ENC-135 | Self-host Inter and JetBrains Mono | P1 | DONE | Leaks every user's IP to a third party, breaks air-gapped installs, undercuts `docs/08 §18` residency |
| ENC-136 | Migrations 0004 and 0005 — workspaces, libraries, `acl_entries`, roles, `files` | P1 | DONE | DDL from `docs/04 §7` and `§9` |
| ENC-126 | Real `AuthorizationService` — ACL resolution, inheritance, group closure, deny-wins | P1 | DONE | ENC-125 |
| ENC-127 | Workspaces and libraries | P1 | DONE | ENC-126 |
| ENC-128 | `BlobStore` — S3-compatible, public-access self-check | P1 | DONE | ENC-124 |
| ENC-129 | Upload state machine, multipart, signed URLs | P1 | DONE | ENC-128 |
| ENC-130 | Files and folders, trash, move/copy | P1 | DONE | ENC-127 |
| ENC-131 | Immutable versions, atomic commit, restore | P1 | DONE | ENC-129, ENC-130 |
| ENC-132 | `AntivirusScanner` + ClamAV; nothing `AVAILABLE` before clean | P0 | DONE | ENC-131 |
| ENC-133 | Read paths: metadata, listing, cursor pagination | P1 | DONE | ENC-132 |
| ENC-134 | Leakage matrix §4.1, §4.2, §4.8 | P0 | DONE | ENC-133 |

### Phase 2 — Enterprise V1

Every `Depends on` here pointed into the `ENC-200` block until `ENC-154`; twelve of the twenty named
a number no row ever used. They now name a row in this file, or — where the prerequisite is real but
nobody has logged it — the `ROADMAP.md` milestone that will. A milestone is a checkable answer; an ID
for work that does not exist is not.

| ID | Item | Pri | Status | Depends on |
|---|---|---|---|---|
| ENC-300 | SAML 2.0 (incl. XSW/XXE hardening) | P1 | TODO | Phase 1 |
| ENC-301 | SCIM 2.0 service provider + mass-deactivation guard | P1 | TODO | ENC-125 |
| ENC-302 | WebAuthn / passkeys + step-up | P1 | TODO | ENC-111 |
| ENC-303 | Advanced DLP: full detector set, simulation, obligations | P1 | TODO | M4 — DLP detectors *(no row yet)* |
| ENC-304 | Information barriers | P1 | TODO | ENC-126 |
| ENC-305 | Retention, records, legal hold | P1 | TODO | ENC-131 |
| ENC-306 | Incidents + SIEM forwarding | P1 | TODO | M4 — audit coverage sweep *(no row yet)* |
| ENC-307 | MCP gateway: tools, scopes, classification ceilings | P1 | TODO | M3 — search post-filter *(no row yet)* |
| ENC-308 | RAG answers with citations + BYO LLM routing | P1 | TODO | ENC-307 |
| ENC-309 | BYO infra: storage profiles, Vault, KMS, SMTP, AV | P1 | TODO | ENC-102 |
| ENC-310 | White-labeling + custom domains + certificate automation | P1 | TODO | M5 — web shell *(no row yet)* |
| ENC-311 | Sync: device registry, delta protocol, eligibility, wipe | P1 | TODO | ENC-126 |
| ENC-312 | External editor session brokering | P1 | TODO | ENC-131 |
| ENC-313 | Workflow engine: definitions, stages, approvals | P1 | TODO | ENC-130 |
| ENC-314 | Document signing: ceremony, PAdES, TSA, LTV, verification | P1 | TODO | ENC-313 |
| ENC-315 | External signature providers (DocuSign, Adobe, eSign) | P2 | TODO | ENC-314 |
| ENC-316 | Milvus HA + rebuild runbook exercised | P1 | TODO | M3 — Milvus `VectorStore` *(no row yet)* |
| ENC-317 | Leakage matrix §4.7–4.10 green | P0 | TODO | ENC-311, ENC-314 |
| ENC-318 | Tier 1 + Tier 2 locales translated | P2 | TODO | M5 — i18n scaffolding *(no row yet)* |
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
| 0 — Foundations | 2 | 13 | 4 | 0 | 19 | 0 |
| 1 — MVP | 7 | 40 | 17 | 7 | 58 | 13 |
| 2 — Enterprise V1 | 1 | 17 | 2 | 0 | 0 | 20 |
| 3 — Beyond V1 | 0 | 0 | 1 | 5 | 0 | 6 |
| **Total** | **12** | **87** | **28** | **12** | **97** | **42** |

Counts include completed items in their priority column. Update this table whenever a row's status or
priority changes; a stale rollup is worse than none — this one read "Phase 1: 0 done" while
twenty-four of its rows were merged, which is how it was noticed. It had drifted again by 2026-08-20,
nine rows behind, for the ordinary reason: the rows that get added in a hurry are the ones found
mid-task, and the table is a second edit. Recounted from the rows.

Derived from the rows themselves, not maintained by hand: every `ENC-` row in `§3` and `§4`,
deduplicated by ID with `§3` winning on status because it is the fresher of the two. A row that
appears only in `§3` belongs to the phase in flight when it was raised — Phase 0 below `ENC-119`,
Phase 1 from there up, and that is where `§2.3`'s ranges come from rather than the other way round.

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
| 2026-08-19 | M1 storage and content batch (four parallel sessions): workspaces and libraries repositories, `BlobStore` over S3/MinIO with a public-bucket self-check, the files and folders tree, and self-hosted fonts. 689 tests pass, up from 512, with MinIO and PostgreSQL both live. |
| 2026-08-19 | Disk filled at 99% mid-integration and took the Docker daemon with it. Cause was mine: every parallel agent got its own `CARGO_TARGET_DIR` to avoid cargo lock contention, and ten batches of those were never cleaned up — ~24 GB of scratch plus a 13.8 GB workspace target. Reclaimed 38 GB. Worth a cleanup step in the batch pattern rather than remembering. |
| 2026-08-19 | Branch protection closed as **unavailable**, not deferred: both the protection and rulesets APIs return `403 Upgrade to GitHub Pro` for a private org repo. Remains a process control — wait for green before merging. |
| 2026-08-19 | M1 foundations batch (four parallel sessions, one cumulative PR): identity repositories, real ACL resolution with inheritance and deny-wins, the grant-coverage gate, migrations 0004/0005, and the v2 design system. 512 tests pass, up from 409. Integration found one real coupling the parallel split could not: the ACL resolver's inheritance walk is a recursive CTE over `files`, which was scheduled for ENC-130 — so `files` moved forward into migration 0005 rather than shipping a resolver that fails on its only real use case. |
| 2026-08-19 | `ENC-124` closed M0's last exit criterion — and found a cross-tenant read. The first real end-to-end request with a beta-tenant token for an alpha-tenant subject returned **200 with alpha's row**. Cause: the harness connects as the cluster superuser, and superusers bypass RLS unconditionally, so every test that believed it demonstrated tenant isolation ran with isolation switched off. Compounded by migration 0002 never granting `enclave_app` on any table but `audit_events`, so nothing had ever run as the application role. Fixed by migration 0003 (grants) and the harness taking `SET ROLE enclave_app`. The policies in 0002 were correct throughout; nothing had exercised them. 409 tests pass. |
| 2026-08-19 | `ENC-141` fixed: breaking ACL inheritance no longer gains privilege. The flag flip alone truncated the resolver's walk, so a `DENY` written above the break stopped applying — an operation whose purpose is to narrow access was widening it. `enclave_authorization::materialise` now collapses the whole chain by deny-wins and writes it onto the resource in the same transaction as the flip, for files and libraries both, and `enclave-libraries` refuses a settings update that would touch the column. Three details were load-bearing and none were obvious: the resource's *own* entries have to be in the collapse, or an ancestor `DENY` loses to a direct `ALLOW` that `uq_acl_entry` cannot store beside it; the walk is borrowed from the resolver rather than rewritten, because a second walk that drifts copies a different set from the one being enforced; and the harness's parallel reference implementation is deleted for the same reason. Both new tests verified by neutering the copy and watching them name the escalation. 922 tests. |
| 2026-08-19 | M1 closed and M2 planned. Acting on the tracker's own "Next" surfaced that it was wrong: both it and `plans/M1-CONTENT-CORE.md §5` placed gate **G1** at the end of M1, while `ROADMAP.md §6` places it at the end of **M5**. The MVP ship decision would have been taken four milestones early, against criteria that assume M2–M4 exist — and the work those criteria describe would have read as missing rather than as not yet due. The error started in the plan and was copied into the tracker, which is precisely what `plans/README.md` warns about. Both now defer to the roadmap (`ENC-142`). M1's five exit criteria: four demonstrated by tests that have been watched to fail; the fifth — 5 GB upload with flat API memory — is structurally true but never exercised end to end, logged honestly as `ENC-144` rather than ticked. `plans/M2-ACCESS-DELIVERY.md` published (`ENC-143`): D15–D19 locked, opening with the rendition pipeline because it is the milestone's only genuine unknown and the criterion the product is sold on (A1) depends on it. Two M2 steps were already delivered early by M1 — ACL resolution and break-inheritance — so A3 and T3 are re-run, not built. |
| 2026-08-19 | M2 opened with `ENC-146`, the rendition pipeline — `crates/preview` and migration 0007. The milestone's only genuine unknown goes first by design, and writing it turned three security properties from things the code must remember into things the types make unrepresentable: a base rendition cannot carry an identity, an unscanned version cannot be handed to a parser, and a renderer cannot exceed its budget because the budget is enforced around it rather than by it. The real codecs are split out as `ENC-146a` — they are where the attack surface is, they run out-of-process, and none of the pipeline's guarantees depend on which one is plugged in. Proving the RLS gate covered the new table found `ENC-155`: `sqlx::migrate!` embeds migrations at compile time, so editing a `.sql` and re-running the gate locally reports green against a schema nobody is running. It was only visible because the deliberate violation *failed to fail*. 942 tests. |
| 2026-08-19 | CI went red on PR #30 with `ld terminated with signal 7 [Bus error]` — the runner had filled its disk, and `ld` writing through an mmap turns that into `SIGBUS` instead of `ENOSPC`, so a capacity problem arrived looking like a toolchain crash. The workspace links one static test binary per test target and `ENC-146` added two more. Reclaimed the hosted image's unused toolchains and dropped CI debug info to `line-tables-only`; `df` is now printed either side of the build, because the fix that matters more than the space is that the next occurrence says what it is (`ENC-156`). |
| 2026-08-20 | `ENC-147`, the watermark layer. The property M2's fourth exit criterion asks for — watermarked output is never written to the rendition cache — is now true because there is no key such an artefact could be stored under, not because the write site remembers not to. Implementing it found `ENC-157`: `docs/08` offered `preview.watermark_cache` as a deployment setting, defaulted to `false`. A control expressed as a default is a control somebody can turn off, and no deployment wants this one off — removed, and the guarantee moved into the type system. The other half of the work is escaping: the layer interpolates a display name and an email into SVG, both attacker-settable, so every field is attacked in test and the payload must survive escaped rather than dropped — a watermark that silently discards a hostile name is one an attacker can blank by choosing one. |
| 2026-08-20 | *"Can we also add DMS, or are we already handling these?"* — checked rather than answered from memory. Most of it was already specified: check-in/check-out, content types, records management, legal hold, retention and templates all appear across the pack. Four things were not, and the pattern in how they were missed is worth keeping: every document was written from the inside out, so nothing asked how content *gets here* (`ENC-159`, migration — the one that is an adoption blocker rather than a feature gap), annotations read as a viewer feature rather than as versioned classified user content (`ENC-160`), OCR was written as a fallback *"when a page yields no text"* which quietly assumes scanned documents are the exception (`ENC-161`), and version compare has been a crate-list entry since the beginning with no document saying what it does (`ENC-162`). All four placed in `ROADMAP.md`; migration became **M8b** and moved Enterprise V1 GA two weeks to 2027-10-09, stated rather than absorbed. |
| 2026-08-20 | `ENC-149`/`ENC-150`, share links and the download budget — and a lesson about testing concurrency. H3 asks that `max_downloads` hold under fifty concurrent redemptions. The obvious test — fifty `tokio::spawn`s — **passed against a deliberately naive implementation, three times out of three**, because the harness pool caps at two connections for the D3 proof, so fifty tasks ran two at a time. Widening the pool did not fix it: the window between a stale read and the increment is real but too narrow to hit by luck, and a test that only fails sometimes gets marked flaky and then deleted. The property is now proven by holding the window open on a barrier until all twenty contenders are inside it, which fails 3/3 without the `WHERE` clause. Both tests are kept: one is realistic, the other is decisive. |
| 2026-08-20 | Four M2 items in parallel, one cumulative PR: `crates/metadata` (`ENC-151`), the `authorize_many` measurement (`ENC-145`), capabilities on listings (`ENC-152`) and the first real renderer (`ENC-146a`). Two results outlast their tasks. **The post-filter's cost is ~80% fixed** — 1.4 ms for one candidate, 7.0 ms for two hundred — so raising over-fetch is nearly free while a second resolution pass costs more than tripling the batch, which is the opposite of how `docs/07 §6.2` currently describes excerpt disclosure (`ENC-167`, written into M3 before the design sets). And **the decode bomb is stopped by ordering, not by a check**: removing four lines from the renderer left the bomb test grinding for over ten minutes instead of refusing instantly. Along the way I recreated a table migration 0004 already had (`ENC-165`) and was caught by `ENC-155` a second time — the compile-time migration embedding is a trap that catches the person who logged it. |
| 2026-08-20 | `ENC-170`: `router()` now takes the dependencies its routes need, so the missing-extension `500` becomes a compile error. Writing the regression test for it found something larger — **`ENC-171`, every `Error::Upstream` in the product rendering as `500` instead of `503`**, because `ApiError::into_response` re-derived the status and had no arm for it. `Error::status_code` exists precisely to stop that and the renderer was ignoring it. Both are now one value. Also worth recording: CI was red on PR #34 for a reason that was not the code at all — GitHub had stopped allocating runners over account billing, so fourteen jobs never started and reported as failures. Making the repository public restored it. |
| 2026-08-20 | `ENC-155` closed — a build script on `enclave-db` now watches `migrations/`, so an edited `.sql` reaches the binary that embeds it. Worth recording why it lasted: CI builds from scratch and never saw it, so the one place it could bite was a person iterating locally *at the moment they were trusting a gate*. It was found by a deliberate violation failing to fail, and it then caught the session that logged it two tasks later. Verified by the original scenario, untouched: remove `FORCE ROW LEVEL SECURITY` from a migration, touch no Rust, and the RLS gate now fails naming the table. |
| 2026-08-20 | Six items in parallel. `ENC-169` made the watermark real — burned into the pixels, because an overlay a client is asked to draw is one a client can decline to draw — and two defects fell out of building it, both found by tests rather than reading: a compositor that returned success having marked **nothing** on a small canvas, and one of my own tests passing for the wrong reason because its stub rendition was eight bytes. `ENC-167`/`ENC-175` collapsed a listing page's capability probe from nine resolutions to one — measured at **8.1 ms against 68.5 ms**, 60 ms a page — with the trait method defaulted so six deny-by-default stages were not broken by a performance change. `ENC-153` filled A5/A6 against a real MinIO and was explicit about the half of A6 that **cannot** be proven. `ENC-144` and `ENC-172` closed an M1 criterion and a papercut that had cost three verification attempts. One session stalled immediately before restoring a dependency it had commented out to iterate — caught at integration, which is the reason integration is not a formality. |
| 2026-08-20 | Backlog sweep across five long-open items, batched on the repo owner's explicit instruction — the first of `§2.1`'s three exceptions, recorded rather than assumed. Two closed on evidence, three stay open with the missing input named. `ENC-140` was re-probed rather than re-read: anonymous Docker Hub pulls work again (the token states its own budget, 100 per six hours), so `docker login` is no longer needed, while the mirror is still absent from quay.io, ghcr.io under both plausible orgs, and public.ecr.aws — with controls run through the same code path so the absences are absences. It also surfaced the part nobody had written down: **CI** pulls that image anonymously and runs the `eicar` tests with `--include-ignored`, so a Hub refusal would arrive looking like leakage row G1 failing. `ENC-154` retired the phase-blocked ID scheme instead of renumbering — twelve of Phase 2's twenty dependencies pointed into a block that was never allocated, and sixty completed rows carry their numbers in branches, commits and merged PRs, so the blocks were the thing to give up. New IDs start at `ENC-500` so a new row cannot be misread as Phase 3 work. `ENC-017` is drafted but deliberately unparseable, `ENC-018` untouched because a placeholder in a copyright line is worse than the trade name already there, and `ENC-021` turns out to be blocked on nothing in the repository at all — `git grep` finds the path only in its own tracker row; what a rename breaks is 29 GB of `target/` and every open session's working directory. The rollup had drifted nine rows behind and was recounted. |
| 2026-08-20 | **M2 closed.** All five exit criteria demonstrated, every P1 done, 946 tests, 38 tenant-scoped tables under RLS and grants. `plans/M2-CLOSEOUT.md` records what the milestone taught, and the four lessons are all the same shape: a control that looks green because it is not actually running. A concurrency test on a two-connection pool; an obligation satisfied only because the feature was missing; a schema gate reporting on the previous build; and a cost assumption that had been in a specification for two milestones without anyone measuring it. `plans/M3-DISCOVERY.md` opens the next milestone with the post-filter built **first, against a deliberately over-permissive fake** — the guarantee before the thing it guards, because S5 is easy to assert against a two-line fake and a research project to arrange in Milvus. |
| 2026-08-18 | All five dependency majors landed (`ENC-119`–`ENC-123`). Two were more than version bumps: `jsonwebtoken` 11 compiled cleanly and then panicked at runtime on every verification because 11 made the crypto backend pluggable — chose `rust_crypto`, reasoning recorded in the manifest. `rand` 0.10 made OS entropy fallible, so key generation and refresh minting now propagate `EntropyUnavailable` rather than unwrapping. 403 tests green throughout. |
| 2026-08-18 | **Gate G0 held: PASS**, with two conditions carried into M1. The controls were each verified by deliberate violation, and six defects were caught by automation that review had missed. Recorded in `plans/G0-GATE.md`; M1 planned in `plans/M1-CONTENT-CORE.md`. |
| 2026-08-18 | `ENC-118`: the CI `test` job had no database, so 24 of 27 tests ran nowhere — including the D3 pool-exhaustion proof this milestone was sequenced around. Wiring one in surfaced five self-deadlocking tests (`pool.close()` awaited while a handle was still held — they would have hung CI indefinitely, not failed), a split between `DATABASE_URL` and `ENCLAVE_TEST_DATABASE_URL` that made a whole crate's tests unreachable, two tests interfering through the deliberately cross-tenant outbox publisher, and three prose blocks fenced as ```ignore doc-tests. Now 403 passing, 0 ignored. |
| 2026-08-18 | Phase 0 batch two landed: `ENC-110` policy-routing lint now enforcing (was warning "not enforced yet"), `ENC-113` dev Compose stack, `ENC-114` observability with structural secret redaction, `ENC-115` CLI seed/migrate/doctor. 380 tests pass. Verified independently: the routing lint flags a deliberately unprotected handler and exits 1. |
| 2026-08-18 | `ENC-112` harness landed and immediately earned itself: it exposed a race in migration 0001. Concurrent `CREATE ROLE` across databases in one cluster failed 10/10 runs — the `IF NOT EXISTS` guard is check-then-act, and losing the race raises `unique_violation` (23505) from `pg_authid_rolname_index`, not `duplicate_object` (42710). First attempt amended 0001; the forward-only migrations gate correctly rejected that. Reverted, worked around with an advisory lock in the harness (0/10 failures), and logged the real defect as `ENC-116` for a decision. |
| 2026-08-18 | Two P0s: `main` went red twice, both because a PR was merged while its checks were still running. (1) fmt on the ENC-106 test — my error, I did not re-run fmt after writing it. (2) A flaky key-redaction test in `auth`, failing 0.8% of runs because it searched Debug output for a single DER byte rendered as "48"; the `kid` contains "48" by chance. Both fixed. **Branch protection requiring green checks before merge would have prevented both** — pending a decision. |
| 2026-08-18 | `ENC-109` policy engine implemented in `enclave-core::engine`: six stage traits, deny-by-default stubs, obligation accumulation, audit on allow and deny. Design decision D9 recorded; `docs/02 §4` and `docs/03 §12` updated. |
| 2026-08-18 | `ENC-106` RLS coverage gate written and run against PostgreSQL 16: 20 tenant-scoped tables all enabled, forced and policied. Proven to fail on an unprotected table and on a `USING (true)` policy. |
| 2026-08-18 | M0 foundation batch landed: ENC-101/102/103/104/105/107/108/111. Workspace green — 279 tests pass, 18 ignored pending the ENC-112 database harness. Verified independently of the implementing agents: JWT algorithm pinned (K8 attack test present), `SET LOCAL` semantics via `set_config`, RLS forced by catalog-driven loop, audit UPDATE/DELETE revoked. |
| 2026-08-20 | `ENC-503`, `ENC-507` and half of `ENC-504`, worked together because they are one failure mode: **a gate whose red state can mean "infrastructure" but says "security" trains people to distrust the gate**, and the run that gets waved through as probably-flaky is eventually the real finding. Both halves had already happened for real — a Docker Hub budget that CI spends anonymously and cannot refill, and a crates.io 503 that reported as the tenant-isolation grant rule failing. The fix in both cases is to separate the fetch from the verdict so they fail in different steps with different words, and to retry only the fetch: an assertion that gets three attempts is a machine for turning an intermittent security failure into a green build, and each retry site says so in a comment so nobody widens it later. `ENC-504`'s visible half is the same idea one layer in — the remedy `ENC-172` wrote was correct, on `Display`, and invisible, because `.expect()` prints `Debug`. `HarnessError` now renders its message and source chain; the checksum gate itself is untouched, and the test asserts `{:?}` rather than `{}` because asserting `Display` is exactly what let it stay broken. Option (b) of `ENC-504` — the harness not touching the shared database at all — is still open. |
| 2026-08-20 | **M3 opened** with the post-filter built first, against a fake candidate generator — the guarantee before the thing it guards (`ENC-506`). Migration 0011. S3, S4 and S5 pass, and verifying them by deliberate violation found a weakness in my own tests: S3 and S4 stayed green with the denylist removed, because a revocation deletes the ACL and the post-filter refuses the file anyway — so a test that *isolates* the denylist was added and `docs/12` now says which mechanism each row proves. **S8 is enforced by the compiler** (`ENC-508`): the routing lives in the type carrying the text, so writing the 3am fallback fails to compile rather than failing a test. Extraction reuses the rendering budget by depending on it rather than copying it (`ENC-510`), and refuses non-UTF-8 rather than decoding it lossily, because indexed text that differs from displayed text makes every DLP match downstream a statement about a document nobody can see (`ENC-511`). Also: gate failures now say *registry* rather than naming a security rule (`ENC-503`, `ENC-507`), and 21 GB of Docker cache was reclaimed with the disk at 1.6 GiB free. |
| 2026-08-20 | M3's second batch: chunking with deterministic ids (`ENC-513`), degraded lexical search (`ENC-514`), and the invalidation sweep and reconciler (`ENC-518`). The best result is one session finding a latent bug in another's code: `lift_expired` compared a *caller's* clock against the database's, so a worker running seconds fast would lift a suppression the database still considered in force. It worked around that at its call site; the parameter is now gone entirely, so the sweep reads no clock at all. Two gaps were named rather than proxied — nothing can express "the index has caught up" (`ENC-520`), and a vector store that is *up but wrong* keeps the circuit closed and answers `degraded: false` with very few hits (`ENC-516`), which is the worst shape available: confidently complete, and wrong. |

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
