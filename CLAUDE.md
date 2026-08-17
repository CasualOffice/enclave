# CLAUDE.md

Guidance for Claude Code and other AI assistants working in this repository.

## What this repository is

Enclave — an enterprise shared workspace (SharePoint-class): Rust backend, React frontend, PostgreSQL
authoritative, Milvus for hybrid search, MCP for AI access, all behind a single enforced policy
chain.

**Current state: design phase.** `docs/` holds the complete specification; code lands per the phasing
in `docs/01-PRD.md §37`. Do not assume a file exists because a doc describes it — check.

## Before anything: the tracker

[`TRACKER.md`](TRACKER.md) is the single source of truth for what is being worked on. Read `§2` of it
before acting. Three rules matter most:

1. **One item `WIP` at a time. No pivoting.** If something is in flight and a new request arrives,
   log the request, state its priority and where it sits in the queue, and continue what you were
   doing. Only an explicit "do this instead", a P0, or a CI failure interrupts.
2. **Every new request gets a row before work starts** — ID, priority (you assign it, per the rubric),
   phase, date. Never absorb a request silently into the current task.
3. **Update the row, the rollup and the log in the same edit as the work.** Keeping the tracker
   current is part of the task, not admin afterwards.

[`ROADMAP.md`](ROADMAP.md) says why the order is what it is, and what each milestone must satisfy to
be called complete.

## Read before you write

| If you are touching… | Read first |
|---|---|
| Anything at all | `docs/README.md` (the invariant and the single-source rules) |
| Database schema | `docs/04-DATA-MODEL.md` — **the only** place DDL is defined |
| An HTTP endpoint | `docs/05-API.md` — error model, pagination, idempotency |
| Auth or tokens | `docs/03-LLD.md §5`, `docs/13-IDENTITY-SSO-SCIM.md` |
| Permissions or policy | `docs/03-LLD.md §12`, `docs/06-SECURITY-DLP-ACCESS.md` |
| Search or indexing | `docs/07-SEARCH-INDEXING.md` — especially §6, ACL invalidation |
| A provider integration | `docs/08-BYO-INFRA.md` |
| UI | `docs/09-UX-WHITE-LABELING.md`, `docs/14-I18N-L10N.md` |
| Workflows or signing | `docs/15-WORKFLOWS-AND-SIGNING.md` |
| Tests | `docs/12-TESTING.md` |

## Non-negotiable rules

These are not style preferences. Violating one is a security defect, and each has a permanent test.

1. **Never bypass the policy chain.** Every entry point calls `PolicyEngine::enforce`
   (`docs/03-LLD.md §12`). Do not hand-roll an ACL check, do not "just this once" query a file
   directly in a handler, do not add a fast path that skips DLP.
2. **The chain's order is fixed.** Tenant isolation → auth → conditional access → authorization →
   barriers → classification → DLP → retention → execute → audit.
3. **Never trust the client for tenant identity.** It comes from the verified token or custom-domain
   routing. Never from a body field, query param or header.
4. **Every tenant-scoped table gets `tenant_id` first, RLS enabled and forced, and composite foreign
   keys that include `tenant_id`.** CI fails otherwise.
5. **Search results are confirmed against PostgreSQL before returning.** The vector index is a
   candidate generator, never an authority. Never remove or weaken the post-filter.
6. **Preview ≠ download ≠ print ≠ export ≠ sync.** Never collapse them into one permission, and never
   issue an original object-storage URL on a preview path.
7. **Cross-tenant and barrier denials return `404`, not `403`.** A `403` confirms existence.
8. **Obligations must be satisfied, not dropped.** `PolicyDecision` is `#[must_use]`.
9. **Nothing is `AVAILABLE` before antivirus completes.** No read path serves `SCANNING` content.
10. **Audit happens inside the policy engine**, for denials as well as allows. Never log passwords,
    tokens, refresh cookies, DLP match values or file content.
11. **Secrets are references, never literals** (`vault://…`, `env://…`). Never a value in YAML, a
    fixture or a test. This includes **PEM banners in test fixtures**: the secrets gate refuses
    `-----BEGIN … PRIVATE KEY-----` in any tracked file and has no test exemption, because a gate
    with exceptions is one people learn to route around. Assemble such strings at runtime —
    `format!("-----{} PRIVATE KEY-----", "BEGIN")` — so the assertion still holds and the literal
    never enters the tree. Two tests have already tripped this.
12. **User-facing strings go in the i18n catalog.** No string literals in `web/src`, no manual date
    or number formatting, no physical `left`/`right` CSS.

## Conventions

**Rust**
- Edition 2021. `cargo fmt`, `cargo clippy -- -D warnings` clean.
- Newtype every ID (`FileId`, not `Uuid`). No bare `Uuid` on a public boundary.
- `thiserror` for library errors, `anyhow` only at binary boundaries. Map to `Error`
  (`docs/03-LLD.md §22`) at the API edge.
- All database access through the `db` crate's `TenantScoped` wrapper. No `sqlx::query!` in domain
  crates.
- Async everywhere; no blocking calls in async contexts — `spawn_blocking` for CPU work.
- Public items get doc comments explaining *why*, not restating the signature.

**SQL**
- Migrations are forward-only, numbered, checksummed, expand-then-contract across releases.
- `CREATE INDEX CONCURRENTLY`; no long `ACCESS EXCLUSIVE` locks on populated tables.
- New tenant-scoped table ⇒ RLS policy in the same migration.

**TypeScript / React**
- Strict mode. No `any`. Zod at every API boundary.
- TanStack Query for server state; Zustand only for genuinely local UI state.
- Virtualize any list that can exceed 100 rows.
- Render actions from the server-provided `capabilities` object — never re-derive permissions client
  side.
- Every surface defines empty, loading, error and success states.

**Commits and PRs**
- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- One logical change per PR. Security-relevant changes say so in the description and name the tests
  that cover them.

## Testing expectations

- New enforcement point ⇒ add a row to the leakage matrix in `docs/12-TESTING.md §4` **and** the test
  that proves it.
- Integration tests use the seeded `tenant-alpha` / `tenant-beta` fixtures. `tenant-beta` exists so
  cross-tenant assertions are realistic — use it.
- Never skip, `#[ignore]` or quarantine a security test to get a build green. Fix the code.
- Run before pushing: `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo fmt --check`,
  and `npm run test && npm run lint` in `web/`.

## Documentation discipline

Each document is authoritative for exactly one thing (`docs/README.md §1`). When you change behavior:

- update the authoritative document, not a convenient nearby one;
- never restate DDL outside `04`, endpoint contracts outside `05`, or the crate list outside `02`;
- bump the doc's version line and add a change-log row when the change is substantive;
- keep cross-references in the `04-DATA-MODEL.md §7` form so they stay checkable.

## Working style

- **Check before assuming.** This repo is mid-build; read the file rather than trusting a doc that
  describes an intention.
- **Prefer the narrow fix.** Do not refactor adjacent code opportunistically inside a feature PR.
- **Ask when a change would weaken a control.** If the straightforward implementation requires
  skipping a policy step, that is a design conversation, not a judgement call to make silently.
- **Report honestly.** If tests fail, say so with the output. If part of a task is incomplete, say
  which part and why.
