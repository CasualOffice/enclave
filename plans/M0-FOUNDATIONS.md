# M0 — Foundations · Implementation Plan

> Enclave · Phase 0 · 5 weeks · Baseline 2026-09-01 → 2026-10-03
> Tracker: `ENC-100` … `ENC-115` · Roadmap: [`ROADMAP.md §5`](../ROADMAP.md)

---

## 1. Objective

**A request can traverse the full policy chain against a real database, and CI enforces the
structural rules that keep it that way.**

M0 ships no user-facing feature. It ships the constraints that every later feature is built inside.
Everything here is expensive to retrofit and cheap to establish now — that is the entire selection
criterion for what is in this milestone.

### Exit criteria (from the roadmap — may not be weakened here)

- [ ] One end-to-end request: login → JWT → `enforce` → tenant-scoped query → audit row.
- [ ] Cross-tenant read fails **with the application predicate deliberately removed** (test T5).
- [ ] Refresh rotation works; replaying a consumed token revokes the family (K3, K4).
- [ ] All four structural CI gates fail correctly when deliberately violated.
- [ ] `docker compose up` → healthy stack on a clean machine, documented in `CONTRIBUTING.md`.

---

## 2. Design decisions to lock in M0

These are the choices that are painful to reverse. Each is decided here, with the reasoning, and
written back into `docs/` if it changes the specification.

### D1 — Crate graph and dependency direction

Dependencies point **inward**, never outward or sideways between domains:

```text
api / worker / scheduler        (binaries — compose everything)
        ↓
domain crates                   (files, sharing, dlp, search, …)
        ↓
authorization · conditional_access · dlp · … (policy services)
        ↓
db · events · audit             (infrastructure)
        ↓
core · config                   (no dependencies on anything above)
```

A domain crate never depends on another domain crate. Where two need to cooperate, the binary wires
them, or the interaction is expressed as an event. This is what keeps `PolicyEngine` callable from
`api`, `worker` and `mcp` without a cycle.

`core` depends on nothing in the workspace. If something needs to go into `core` to break a cycle,
that is a signal the boundary is wrong — raise it rather than widening `core`.

### D2 — Error strategy

`thiserror` in libraries, `anyhow` only in binaries. Every crate defines its own error type; the
`core::Error` enum (`docs/03 §22`) is the single type the API layer maps to HTTP.

**Policy denials are a distinct variant, not a string.** `Error::PolicyDenied { code, remediation }`
carries only what the client may see; the reasoning goes to audit. This split exists in the type
system from day one because "we'll sanitize it later" reliably leaks policy internals.

### D3 — RLS and connection pooling — *the highest-risk decision in M0*

Row-level security depends on `app.tenant_id` being set correctly for the duration of a transaction
and never leaking to the next checkout from the pool.

Decision: **`SET LOCAL app.tenant_id` inside an explicit transaction, issued by the `TenantScoped`
wrapper, never by a caller.** `SET LOCAL` is transaction-scoped, so a returned connection cannot
carry tenant context forward. The application connects as a non-owner role with `FORCE ROW LEVEL
SECURITY` so the policy applies to it.

Rejected alternatives, recorded so they are not re-litigated:

- *Session-level `SET`* — survives the transaction and therefore the pool checkout. One misuse is a
  cross-tenant leak. Rejected.
- *A connection pool per tenant* — does not scale to thousands of tenants, and moves the failure to
  connection exhaustion.
- *Application filtering alone* — one missing predicate is a leak, and no test can prove the absence
  of a missing predicate across a whole codebase. This is why there are two layers, not one.

**This is proven on day 10 with a pool-exhaustion test**, not assumed. If it does not hold, the
schedule moves and we solve it before anything is built on top.

### D4 — Migration and RLS discipline

Migration `001` creates every table it creates *with* RLS enabled, forced, and a policy — in the same
migration. The CI gate (`ENC-106`) then keeps it true for every future table. Adding RLS to fifty
existing tables later means auditing fifty tables; this is the one moment where it is free.

### D5 — JWT signing keys in development

`KeyProvider` is a trait from day one, with a local file-backed implementation for development and
Vault/KMS implementations later. Development keys live in `deploy/config/dev-keys/` and are
git-ignored; the dev stack generates them on first run. No key material is ever committed, even a
throwaway one — because throwaway keys get copied into production more often than anyone admits.

### D6 — Outbox before any event consumer exists

The outbox table and publisher land in M0 even though nothing consumes events until M1. Writing a
state change and its event in one transaction is a property of *how writes are done*; adding it after
the first twenty write paths exist means editing twenty write paths.

### D7 — Test harness shape

Integration tests get a real PostgreSQL, Redis, NATS and MinIO via testcontainers — not mocks. The
seeded `tenant-alpha` / `tenant-beta` fixtures (`docs/12 §3`) exist from M0 so that every subsequent
test can assert cross-tenant behavior without inventing its own fixtures.

Mocks are used for *external* providers only (SMTP, AV engines, embedding endpoints), never for the
database, because the properties being tested — RLS, transactional outbox, constraint enforcement —
are properties of the database.

**Amended at ENC-112.** The harness takes a `DATABASE_URL` and creates a disposable database per
test binary, rather than embedding a container runtime. The essential property of D7 — a real
PostgreSQL rather than a mock — is unchanged; what changes is who starts the server. The Compose
stack (ENC-113) and CI's service container both have to exist regardless, so a container library
would duplicate them and put an image pull on the critical path of every local test run. It also
sidesteps a practical problem: anonymous Docker Hub pulls were returning 401 during development.
If per-test isolation ever becomes necessary, testcontainers can be added behind a feature flag
without changing a single test's shape.

### D8 — Stub policy services deny by default

`PolicyEngine` is wired in M0 with stub implementations of all six services. Every stub returns
**deny**, and each is replaced by a real implementation in M1/M2. A stub that returns allow would
silently disable the chain and nobody would notice until a security test was written months later.

### D9 — The policy engine lives in `core`, and audit is a port

`docs/03-LLD.md §12` specifies `PolicyEngine` but not which crate owns it. Two options: a new
`policy` crate depending on all six service crates, or `core`.

Decision: **`core`**, with the six service traits defined beside it. The engine is composition and
nothing else — it holds six trait objects and calls them in order — so it needs no concrete
implementation and adds no dependency on the crates that provide them. The canonical crate list
(`docs/02-HLD.md §4`) is unchanged, and every entry point reaches one implementation instead of
each binary growing its own variant.

The engine must audit, and `audit` depends on `core`, so `core` depending back would be a cycle.
Resolved with a narrow `PolicyAuditSink` port defined in `core` and implemented in `audit`:
`record_allow` and `record_deny`, nothing more. `audit` keeps ownership of the record format, the
canonical serialization and the hash chain; the engine only says that something happened.

Rejected: a `policy` crate. It would work, but it changes the authoritative crate list to buy
separation that the trait objects already provide.

---

## 3. Task breakdown

Estimates are engineer-days. "Tests" lists what must exist before the task is `DONE`.

### ENC-100 · Cargo workspace and crate skeletons · 2d

**Scope.** Workspace manifest, all crates from `docs/02 §4` as compiling stubs, toolchain pinning,
shared lint configuration.

**Files.** `Cargo.toml`, `crates/*/Cargo.toml`, `crates/*/src/lib.rs`, `rust-toolchain.toml`,
`rustfmt.toml`, `clippy.toml`, `deny.toml`.

**Design notes.** Package names are `enclave-<crate>`; directories are unprefixed. Workspace-level
`[workspace.dependencies]` pins every shared dependency once, so version drift between crates is
impossible. Lints are configured in `[workspace.lints]` and inherited, not repeated per crate.

**Acceptance.** `cargo check --workspace` and `cargo clippy --workspace -- -D warnings` both clean.
The dependency direction in D1 is expressed in the manifests, so a cycle is a compile error.

**Tests.** Build only.

---

### ENC-101 · CI pipeline · 2d

**Scope.** GitHub Actions: format, lint, test, build, plus the harness the structural gates plug
into.

**Files.** `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `.github/dependabot.yml`,
`.github/pull_request_template.md`.

**Design notes.** Jobs run in parallel and fail fast. Rust and Node caches keyed on lockfiles. The
structural gates (`ENC-106`, `ENC-110`) are separate jobs so a failure names the rule that was
broken rather than "tests failed". `cargo audit` and `cargo deny` run on a schedule as well as on
PRs, because a dependency becomes vulnerable without anyone touching the repository.

**Acceptance.** A PR that violates formatting, lint, or a structural gate is blocked, and the failure
message names the specific rule.

**Tests.** A deliberately-broken branch per gate, verified once and then deleted.

---

### ENC-102 · `config` crate · 3d

**Scope.** Layered configuration with the precedence in `docs/03 §21`, secret references, startup
validation.

**Design notes.** `SecretRef` is a parsed type, not a string — `vault://path#field` is validated at
load. A configuration value that *looks* like a credential but is inline fails startup with a message
naming the field (`docs/08 §19`). Deployment-profile validation lands here too: the `enterprise`
profile refuses to start with AV or audit disabled.

**Acceptance.** Precedence verified across all four layers; an inline secret is refused; an invalid
`SecretRef` fails at load rather than at first use.

**Tests.** Unit tests per layer; a startup test per refusal case.

---

### ENC-103 · `core` crate · 3d

**Scope.** Typed IDs, `RequestContext`, `Actor`, `ClientType`, `Error`, `PolicyDecision`,
`Obligations`.

**Design notes.** IDs are newtypes over `Uuid` with UUIDv7 generation, `Display`, `FromStr`, `serde`
and `sqlx::Type`, produced by a macro so they cannot diverge. `PolicyDecision` is `#[must_use]`; so
is `Obligations`. Deliberately: an unhandled obligation must be a compile error, not a code review
finding.

**Acceptance.** A test that fails to consume a `PolicyDecision` does not compile (verified with
`trybuild`).

**Tests.** `trybuild` compile-fail cases for dropped decisions and obligations; round-trip tests for
every ID type.

---

### ENC-104 · `db` crate and `TenantScoped` · 4d

**Scope.** Pool construction, migration runner, the tenant-scoped query guard.

**Design notes.** `TenantScoped::begin(tenant_id)` opens a transaction and issues `SET LOCAL
app.tenant_id`. All tenant-scoped access goes through the handle it returns. Raw pool access is
`pub(crate)` plus one explicitly-named `platform_admin` path used by migrations, the outbox publisher
and the scheduler's tenant enumerator — and that path is on the deny-list of the `ENC-110` lint.

**Acceptance.** It is not possible to run a tenant-scoped query outside a transaction that has set
the tenant context.

**Tests.** The **pool-exhaustion test**: N concurrent transactions across M tenants on a pool of size
2, asserting no query ever observes another tenant's context. This is D3's proof and it runs on every
commit thereafter.

---

### ENC-105 · Migration 001 · 3d

**Scope.** Tenancy, identity, credentials, refresh tokens, devices, signing keys, audit, outbox,
idempotency — with RLS on everything tenant-scoped.

**Files.** `migrations/0001_foundations.sql`, `migrations/0002_rls_policies.sql`.

**Design notes.** DDL comes from `docs/04` verbatim; if the implementation needs to differ, `docs/04`
changes first. Roles created: `enclave_app` (non-owner, RLS applies), `enclave_migrator` (owner),
`enclave_platform` (BYPASSRLS, used by exactly three code paths). Audit is partitioned from day one
with three months of partitions pre-created.

**Acceptance.** Migration applies to an empty database; `enclave_app` cannot `UPDATE` or `DELETE`
`audit_events`; every tenant-scoped table has a forced policy.

**Tests.** Fresh-apply test; permission assertions per role; T5 with the application predicate
removed.

---

### ENC-106 · RLS coverage CI gate · 1d

**Scope.** A test that enumerates `information_schema` and fails on any table with a `tenant_id`
column lacking `rowsecurity` **and** `forcerowsecurity` **and** at least one policy.

**Design notes.** Written as a Rust integration test rather than a shell script, so it runs against
the migrated database in CI and locally with the same command.

**Acceptance.** Adding a tenant-scoped table without a policy fails the build with the table name.

**Tests.** The gate itself, plus a fixture migration that deliberately violates it.

---

### ENC-107 · `audit` crate · 3d

**Scope.** Append-only event writing, canonical serialization, hash chain, SIEM sink trait.

**Design notes.** Canonical serialization is fixed in M0 and versioned — changing field ordering
later invalidates every previously computed hash. `previous_hash` is read within the same transaction
as the insert, using a per-tenant advisory lock to serialize chain writes. Chain writing is
configurable per `docs/08 §14`; when off, the columns are null and verification says "not chained"
rather than "valid".

**Acceptance.** Chain verifies across 10 000 events; a tampered row is detected and the first
divergent sequence reported.

**Tests.** Chain verification; concurrent-write ordering; the `U2` role assertion.

---

### ENC-108 · `events` crate · 3d

**Scope.** Outbox writing, JetStream publisher with leader election, idempotent consumer helper.

**Design notes.** `Outbox::publish(tx, event)` takes the transaction, so an event cannot be written
outside the state change it describes. The publisher is at-least-once; consumers deduplicate on
`event_id`. Publisher leadership uses a PostgreSQL advisory lock — one fewer moving part than a
Redis lock, and PostgreSQL is already a hard dependency.

**Acceptance.** A rolled-back transaction publishes nothing. A publisher killed mid-batch resumes
without loss or duplication beyond at-least-once.

**Tests.** Rollback test; kill-and-resume test; duplicate delivery handled idempotently.

---

### ENC-109 · `PolicyEngine::enforce` · 4d

**Scope.** The canonical chain with all six services as deny-by-default stubs, obligation
accumulation, audit on both allow and deny.

**Design notes.** Implemented exactly as `docs/03 §12`. The tenant assertion at the top returns
`NotFound`, never `Forbidden`. Obligations accumulate across stages and are returned to the caller,
never applied inside the engine — the engine decides, the caller complies.

**Acceptance.** Every stage is called in the documented order; a denial at any stage short-circuits
and is audited; the tenant mismatch path returns `NotFound`.

**Tests.** Order assertion via instrumented stubs; one test per short-circuit; audit emission on
allow and on deny.

---

### ENC-110 · Policy-routing CI gate · 2d

**Scope.** A lint proving every route handler reaches `PolicyEngine::enforce`, and that no domain
crate bypasses `TenantScoped`.

**Design notes.** Implemented as a `cargo` xtask walking the syn AST of the `api` crate: collect
router registrations, then check each handler's call graph for `enforce`. Handlers that legitimately
need no policy check (health, JWKS, login) are on an explicit allowlist **with a comment giving the
reason** — the allowlist is the review surface.

**Acceptance.** A handler that queries the database without calling `enforce` fails the build.

**Tests.** The gate, plus a deliberately non-compliant fixture handler.

---

### ENC-111 · `auth` crate · 5d

**Scope.** Argon2id hashing, JWT issue and verify, refresh rotation with reuse detection, the
denylist and epoch revocation paths.

**Design notes.** Ed25519 via `ed25519-dalek`; JWTs via `jsonwebtoken` with the algorithm **pinned**,
never read from the token header — this is the K8 defense and it is a one-line mistake to get wrong.
Rotation consumes the presented token and issues its successor in one transaction. Reuse detection
revokes the family, denylists outstanding `jti`s, and raises `SESSION_REPLAY`.

**Acceptance.** K1–K10 from `docs/12 §4.6` all pass.

**Tests.** The full K series, including `alg: none`, algorithm confusion, and the retired-key window.

---

### ENC-112 · Test harness and fixtures · 3d

**Scope.** Testcontainers setup, seeded `tenant-alpha` / `tenant-beta`, shared assertion helpers.

**Design notes.** One container set per test binary, not per test — otherwise the suite takes twenty
minutes and people stop running it. Fixtures are deterministic: same IDs every run, so a failure is
reproducible from the log alone.

**Acceptance.** `cargo test --workspace` runs green from a clean machine with only Docker installed.

---

### ENC-113 · Dev Compose stack · 2d

**Scope.** PostgreSQL, Redis, NATS, MinIO, Milvus, ClamAV, with health checks and first-run
initialization.

**Files.** `deploy/compose/dev.yml`, `deploy/config/enclave.example.yaml`, `deploy/compose/init/`.

**Design notes.** First run generates dev signing keys, creates the MinIO bucket, and applies
migrations. Every service has a health check so `docker compose up --wait` means what it says.

**Acceptance.** Clean machine → `docker compose up -d` → `cargo run -p enclave-api` → `/health/ready`
returns healthy, with no manual steps beyond what `CONTRIBUTING.md` documents.

---

### ENC-114 · OpenTelemetry wiring · 2d · P2

Tracing subscriber, OTLP exporter, the span attribute conventions in `docs/03 §20`, and a redaction
layer that drops anything resembling a token or password before export.

---

### ENC-115 · `enclave-cli seed` · 2d · P2

Seeds a development tenant with users, groups, workspaces and sample content, so a new contributor
has something to look at within a minute of starting the stack.

---

## 4. Sequencing

Critical path in **bold**. Total ≈ 39 engineer-days over 5 weeks with 2–3 engineers plus the floating
backend engineer.

| Week | Critical path | Alongside |
|---|---|---|
| 1 | **ENC-100** workspace → **ENC-103** `core` | ENC-101 CI, ENC-113 Compose stack |
| 2 | **ENC-104** `db` + `TenantScoped` | ENC-102 `config` |
| 3 | **ENC-105** migration 001 → **D3 proof test (day 10)** | ENC-106 RLS gate |
| 4 | **ENC-107** audit → **ENC-108** events | ENC-112 fixtures |
| 5 | **ENC-109** policy engine → **ENC-111** auth | ENC-110 routing gate, ENC-114, ENC-115 |

**Day 10 is the checkpoint that matters.** If the RLS-plus-pooling proof (D3) does not hold, stop and
solve it. Everything after week 3 assumes it does, and the assumption gets more expensive every week
it goes unverified.

---

## 5. Definition of done for M0

- [ ] Every P1 in Phase 0 is `DONE` in `TRACKER.md`.
- [ ] All five roadmap exit criteria in `§1` are demonstrated, not asserted.
- [ ] Four structural gates green and individually proven to fail when violated.
- [ ] Tests T5, K1–K10, U2 passing.
- [ ] `CONTRIBUTING.md` setup instructions verified on a clean machine by someone who did not write
      them.
- [ ] Gate **G0** held: is this foundation sound enough to build on? Recorded in `TRACKER.md §6`.

---

## 6. Open questions

| # | Question | Needs deciding by | Owner |
|---|---|---|---|
| Q1 | Hosted CI runners, or self-hosted for testcontainer performance? | End of week 1 | Platform |
| Q2 | Milvus in the dev stack by default, or opt-in? It is the heaviest container and M0 does not use it. | End of week 1 | Platform |
| Q3 | Minimum supported PostgreSQL — 15, or 16 for its logical replication improvements? | Before ENC-105 | Backend |
| Q4 | Do we publish container images from M0, or from M5? | Before gate G0 | Product |

Each becomes a tracker row when it is answered, if the answer implies work.
