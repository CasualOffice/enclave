# SKILLS.md

Repository-specific skills for AI assistants working in Enclave.

A **skill** is a packaged procedure for a recurring task in this codebase — the steps, the files to
touch, the checks that must pass. Each one below lives in `.claude/skills/<name>/SKILL.md` and is
invocable as `/<name>` in Claude Code. This file is the index and the contract: if a procedure here
disagrees with a skill file, the skill file is the executable version and this file should be
corrected.

General rules and conventions live in [`CLAUDE.md`](CLAUDE.md). Skills are for *how to do a specific
job*; `CLAUDE.md` is for *how to behave anywhere in the repo*.

## Available skills

| Skill | Use when |
|---|---|
| [`add-endpoint`](#add-endpoint) | Adding or changing a REST endpoint |
| [`add-migration`](#add-migration) | Any schema change |
| [`add-enforcement-point`](#add-enforcement-point) | Exposing a new surface that touches content |
| [`add-provider`](#add-provider) | Implementing a `BlobStore`, `LlmProvider`, `AntivirusScanner`, etc. |
| [`add-mcp-tool`](#add-mcp-tool) | Adding a tool to the MCP gateway |
| [`add-ui-surface`](#add-ui-surface) | Building a new screen, panel or view |
| [`add-i18n-string`](#add-i18n-string) | Any user-facing text |
| [`add-workflow-or-signing`](#add-workflow-or-signing) | Touching the workflow engine or a signing flow |
| [`reindex`](#reindex) | Reasoning about or triggering a search rebuild |
| [`security-review`](#security-review) | Before merging anything touching policy, auth or retrieval |
| [`doc-sync`](#doc-sync) | After a behavior change, to keep the spec pack honest |

---

## add-endpoint

**Read:** `docs/05-API.md`, `docs/03-LLD.md §12`.

1. Define the contract in `docs/05-API.md` first — path, method, request, response, error codes.
   The docs are the design review; write them before the handler.
2. Add the Axum route in `crates/api`. The handler does three things and no more: parse and validate
   input, call `PolicyEngine::enforce`, delegate to a domain service.
3. **Never** query the database directly from a handler, and never re-derive a permission decision.
4. Mutations: accept `If-Match` where the resource is versioned, `Idempotency-Key` where the
   operation creates or transfers.
5. Errors map to the envelope in `docs/05-API.md §5`. Policy denials carry a stable code and a
   user-safe remediation — never internal policy detail.
6. Add the endpoint to the rate-limit table if it needs a bucket of its own.
7. Tests: happy path, unauthorized (`403`), cross-tenant (`404`), stale `If-Match` (`409`), and the
   relevant rows from `docs/12-TESTING.md §4`.
8. Regenerate the OpenAPI snapshot; an unexplained diff fails CI.

**Done when:** doc updated, handler thin, policy enforced, OpenAPI snapshot current, tests green.

---

## add-migration

**Read:** `docs/04-DATA-MODEL.md`, `docs/11-OPERATIONS.md §8`.

1. Add the DDL to `docs/04-DATA-MODEL.md` — it is the only place schema is defined.
2. Create a numbered migration in `migrations/`. Forward-only; never edit an applied migration.
3. Tenant-scoped table? Then in the **same** migration: `tenant_id` as the first column, RLS enabled
   and forced with a policy, composite foreign keys including `tenant_id`, and `tenant_id` leading
   every composite index.
4. Expand-then-contract: this release adds; a later release removes. The previous release must run
   against the new schema.
5. `CREATE INDEX CONCURRENTLY`. Add `NOT NULL` via a validated `CHECK` first. A large table rewrite
   is a background job, not a deploy step.
6. Update the retention table in `docs/04-DATA-MODEL.md §18` if the new data needs a lifecycle.
7. Verify: migration up on a seeded database, previous release's binary still healthy, RLS coverage
   gate passes.

**Done when:** DDL documented, RLS in place, rollback-safe, CI structural gates green.

---

## add-enforcement-point

**Read:** `docs/06-SECURITY-DLP-ACCESS.md §11`, `docs/12-TESTING.md §4`.

Any new way for content to leave the system — a new client, export format, integration, bulk
operation — is an enforcement point.

1. Route it through `PolicyEngine::enforce`. No exceptions, no fast path.
2. Choose the right `Action`. If none fits, add one rather than reusing a near-miss — this is how
   preview/download splits get quietly lost.
3. Add the surface to the enforcement-point list in `docs/06-SECURITY-DLP-ACCESS.md §11`.
4. Add rows to the leakage matrix in `docs/12-TESTING.md §4` and write the tests.
5. Add audit coverage: the action, the decision and the reason code.
6. Check the obligations: does this surface need to honor watermark, no-download, justification? If
   it cannot honor one, it must refuse rather than proceed unprotected.

**Done when:** the surface appears in the enforcement list, the matrix, and the audit trail.

---

## add-provider

**Read:** `docs/08-BYO-INFRA.md §2`.

1. Implement the existing trait. Do not widen a trait to fit one vendor — adapt in the
   implementation.
2. Configuration is a named profile with `secret_ref` values. Never a literal credential, never in a
   fixture.
3. Implement the health/verify method so the admin "test connection" is real.
4. Declare residency truthfully (`EmbeddingProvider`/`LlmProvider`). Classification routing is
   enforced against it in code.
5. Handle failure explicitly and map it to the documented behavior in `docs/02-HLD.md §24`.
6. Tests: contract tests against the trait, plus a failure-injection test proving the documented
   degradation.

**Done when:** the provider is configurable, verifiable, honest about residency, and degrades as
documented.

---

## add-mcp-tool

**Read:** `docs/05-API.md §15`, `docs/02-HLD.md §13`.

1. The tool calls the same domain service the HTTP API calls. It never touches PostgreSQL, Milvus or
   object storage directly.
2. Assign it to an existing scope, or add one and document it. Write tools default to disabled.
3. Enforce the client's classification ceiling — a tool result must never exceed it, even when the
   acting user could read the content directly.
4. Audit every call with the MCP client identity.
5. Tests: scope enforcement, ceiling enforcement, cross-tenant `404`, audit emission.

**Done when:** the tool is indistinguishable from the HTTP path in what it will and will not reveal.

---

## add-ui-surface

**Read:** `docs/09-UX-WHITE-LABELING.md`, `docs/14-I18N-L10N.md`.

1. Define all four states before building: empty (new), empty (filtered), loading, error.
2. Skeletons that match the final layout — no layout shift, no full-screen spinners on navigation.
3. Render actions from the server's `capabilities` object. Never re-derive permissions client-side.
4. Virtualize anything that can exceed 100 rows; cursor-paginate the query.
5. Keyboard first: every action reachable without a mouse, visible focus, correct ARIA roles.
6. All text through the i18n catalog; logical CSS properties only; verify at +40% text expansion and
   in RTL using the `en-XA`/`en-XB` pseudo-locales.
7. Check contrast in both light and dark themes.
8. Tests: Playwright flow, axe pass, pseudo-locale pass.

**Done when:** it works keyboard-only, in RTL, in dark mode, at 100k rows, and offline of nothing it
claims to have.

---

## add-i18n-string

**Read:** `docs/14-I18N-L10N.md §4`.

1. Add a namespaced key (`files.actions.download`) to the `en-US` catalog — never derive a key from
   the English text.
2. Write the full ICU message with plural and select categories. Never concatenate.
3. Add a translator `description` explaining where it appears and what each placeholder means.
   "Share" the verb and "Share" the noun are different keys.
4. Format dates, numbers and currency through `Intl` wrappers only.
5. Security-critical text (denials, deletion confirmations, legal-hold notices) is flagged for human
   review — never machine translation.

**Done when:** the key exists with a description, the lint passes, and the pseudo-locale renders it
translated.

---

## add-workflow-or-signing

**Read:** `docs/15-WORKFLOWS-AND-SIGNING.md`.

1. A workflow **requires** action from someone who already has access. It never grants access. If a
   step seems to need an escalation, that is an ACL change, made explicitly and audited.
2. Bind to an immutable version, never to a file. A new version invalidates in-flight approvals
   unless the definition explicitly says otherwise.
3. `AUTOMATION` steps call allowlisted platform actions only. There is no scripting host; do not add
   one.
4. Signing: seal the byte hash before presenting, present exactly those bytes, re-verify the hash
   before applying the signature. Presented ≠ hashed is the failure this ordering exists to prevent.
5. The signed artifact is a **new version**. Never mutate the original.
6. Private keys never reach the server in `DIGITAL_SIGNER_CERT` mode — send a digest, receive a
   signature.
7. External providers are classification-gated and default to deny. Always store the signed artifact
   and the provider's audit certificate locally; verification must work with the provider offline.
8. Embed LTV material and a TSA timestamp for anything externally consequential.
9. Tests: rows W1–W5 and N1–N10 in `docs/15-WORKFLOWS-AND-SIGNING.md §12`.

**Done when:** the flow grants nothing, signs exactly what was shown, produces a new version, and
verifies without the vendor.

---

## reindex

**Read:** `docs/07-SEARCH-INDEXING.md §9`, `docs/11-OPERATIONS.md §5.1`.

1. Pick the cheapest sufficient tier: `metadata_repair` → `vector_cache` → `full`. A full reindex
   costs embedding spend; do not reach for it by default.
2. Never flip the collection alias before coverage passes threshold.
3. During a rebuild, search must report `degraded: true` if it is serving less than normal — say so
   rather than letting users infer it from missing results.
4. Correctness is not at risk during drift; the post-filter guarantees it. Result *quality* is.
   Frame the incident that way.

**Done when:** coverage threshold met, alias flipped, old collection soaked then dropped, drop-ratio
and epoch-drift metrics back to normal.

---

## security-review

**Read:** `docs/12-TESTING.md §4`, `docs/06-SECURITY-DLP-ACCESS.md`.

Run this before merging anything that touches auth, tokens, permissions, sharing, search retrieval,
sync, MCP or providers. Check, concretely:

- Does every new path call `PolicyEngine::enforce`, in the canonical order?
- Cross-tenant access returns `404`, not `403`?
- Is the search post-filter intact and unconditional?
- Are obligations satisfied rather than dropped?
- Are new tables RLS-enforced with composite FKs?
- Does anything new log a token, password, cookie, DLP match value or file content?
- Do denials avoid leaking policy internals to the client while still auditing them?
- Are new leakage-matrix rows added and passing?
- Does anything fail *open* that should fail closed?

**Done when:** every question above has an explicit answer, and any "no" is either fixed or written
down as an accepted, dated risk.

---

## doc-sync

**Read:** `docs/README.md §1`.

After a behavior change:

1. Update the **authoritative** document for that concern, not a convenient nearby one.
2. Check for contradictions introduced elsewhere — the pack's value is that it does not disagree with
   itself.
3. Bump the doc's version line; add a change-log row for substantive changes.
4. Keep cross-references in the `04-DATA-MODEL.md §7` form.
5. If the change adds a new surface, confirm it appears in: the enforcement-point list, the leakage
   matrix, the audit table and the failure-behavior table.

**Done when:** a reader following only the docs would build what the code actually does.

---

## Adding a skill

Create `.claude/skills/<name>/SKILL.md` with YAML frontmatter (`name`, `description`), keep it to the
steps and the checks — not background theory, which belongs in `docs/` — and add a row to the table
at the top of this file.

A skill earns its place when the same procedure has been explained more than twice.
