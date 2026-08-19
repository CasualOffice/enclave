# 12 — Testing & Quality Gates

> **Status:** Draft · **Version:** 1.0 · **Owner:** Engineering · **Last updated:** 2026-08-18
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
| A1 | `preview=ALLOW, download=DENY` yields a rendition and **no** signed original URL |
| A2 | Export, print and copy are each independently deniable |
| A3 | A `DENY` entry overrides an inherited `ALLOW` at every level |
| A4 | Breaking inheritance materializes the effective set with no privilege gain. `enclave_authorization::break_file_inheritance` and `break_library_inheritance` collapse the whole chain — the resource's own entries included — by deny-wins and write the result onto the resource in the same transaction as the flag flip. Both flags carry the escalation, so both are covered: `a4_breaking_inheritance_materialises_and_gains_no_privilege` asserts the file case and sweeps five probes across principal, action and node for an unchanged verdict, `a4_breaking_library_inheritance_gains_no_privilege` asserts the library case, and `a_settings_update_cannot_break_inheritance` proves a settings replacement cannot flip the flag without the copy (`ENC-141`) |
| A5 | Direct object-key access without a signed URL fails at the storage layer |
| A6 | A signed URL cannot be replayed after expiry, or after single use where supported |
| A7 | Version-level reads respect the current file ACL, not the ACL at version creation |
| A8 | A watermarked artifact is never written to the rendition cache, and two viewers of one page share a base object keyed by neither of them. Structural rather than asserted at the write site: `RenditionKey` has three fields — version, profile, generator — and no constructor accepting a principal, so there is no key a watermarked artifact could be stored under. `crates/preview/tests/watermark.rs` (`ENC-147`) |
| A11 | A listing row's `capabilities` are identical to what the single-file endpoint returns for the same file and caller. Not cosmetic: `CLAUDE.md` requires the UI to render actions from this object and never re-derive permissions client-side, so if the two can disagree the product changes its mind about what a user may do purely because they clicked into a file. Both are built by one function from one action table and the same resolved decision, and the test asserts field-by-field equality across a page whose rows deliberately differ. `crates/api/tests/content.rs` (`ENC-152`) |
| A10 | A `REFERENCE`, `USER`, `GROUP` or `TAXONOMY` metadata value cannot resolve to another tenant's resource, and an unresolvable one is indistinguishable from a cross-tenant one. Otherwise a metadata field is an oracle for what exists elsewhere: set the value, see whether it is accepted. Shape is checked without a database and existence only inside a tenant-scoped transaction, so the two cases collapse by construction. `crates/metadata/tests/storage.rs` (`ENC-151`) |
| A9 | No field interpolated into a watermark can become markup. The layer is SVG carrying a display name and an email — fields the viewer sets on their own profile — so an unescaped `<script>` is stored XSS delivered on the preview path to every viewer of the document. Every interpolated field is attacked, and the payload must survive *escaped* rather than be dropped: silently discarding a hostile name would let an attacker blank their own watermark by choosing one. `crates/preview/tests/watermark.rs` (`ENC-147`) |

### 4.3 Search and AI

| # | Assertion |
|---|---|
| S1 | Keyword search returns nothing from an inaccessible library |
| S2 | Semantic search returns nothing from an inaccessible library |
| S3 | **After a permission revocation, the revoked file disappears from search results immediately**, before any index update completes |
| S4 | With the invalidation worker deliberately stopped, S3 still holds (post-filter + denylist) |
| S5 | With Milvus returning deliberately over-permissive candidates, the post-filter drops them |
| S6 | A `MetadataRead`-only user receives titles but never excerpts |
| S7 | RAG answers cite only chunks the caller may read; an uncitable answer is not returned |
| S8 | `RESTRICTED` content is never sent to a non-local embedding or LLM provider |
| S9 | A `NO_INDEX` classification produces no chunks in the vector store at all |
| S10 | Barrier-segmented content is excluded at query time, not merely at result time |

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
| D1 | `ENFORCE` blocks a sensitive external share synchronously |
| D2 | `SIMULATION` records the decision and takes no action |
| D3 | Missing security facts follow `facts_unavailable` — `FAIL_CLOSED` denies |
| D4 | An unhandled obligation (watermark, justification) fails the operation rather than proceeding |
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
| U1 | Every allow and every deny in the matrix produces an audit event |
| U2 | The application role cannot `UPDATE` or `DELETE` `audit_events` |
| U3 | Hash-chain verification detects a tampered row and reports the first divergence |
| U4 | Audit records never contain passwords, tokens, refresh cookies or file content |

## 5. Structural CI gates

Assertions about the codebase itself, not its behavior:

| Gate | Rule |
|---|---|
| RLS coverage | Every table with a `tenant_id` column has RLS enabled **and** forced, with a policy |
| Grant coverage | `enclave_app` can reach every tenant-scoped table, still cannot `UPDATE`/`DELETE` `audit_events` or its partitions, and holds neither `SUPERUSER` nor `BYPASSRLS`. The RLS gate cannot see any of this: it checks the policy, not whether the role it applies to can use the table — the gap that let a cross-tenant read return `200` in PR #22 |
| Composite FKs | Every FK between tenant-scoped tables includes `tenant_id` |
| Policy routing | Every Axum route handler reaches `PolicyEngine::enforce` (verified by a call-graph lint) |
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
