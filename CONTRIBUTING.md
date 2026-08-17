# Contributing to Enclave

Thanks for your interest. Enclave is enterprise content infrastructure: people store contracts, board
packs and regulated records in it. That shapes how we work — correctness and clarity ahead of speed,
and no security control weakened for convenience.

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

## Before you start

- **Read [`docs/README.md`](docs/README.md).** Especially §3, the policy chain. It constrains nearly
  every change.
- **Read [`CLAUDE.md`](CLAUDE.md).** The non-negotiable rules there apply to human contributors too;
  it is simply written for the audience that needs them restated most often.
- **Open an issue first** for anything beyond a small fix. Design discussion is cheaper than a
  rejected PR.
- **Never open a public issue for a security vulnerability.** See [`SECURITY.md`](SECURITY.md).

## Development setup

Requirements: Rust 1.96+ (the toolchain is pinned in `rust-toolchain.toml`, so `rustup` will fetch
it), Node 20+, and Docker. No `sqlx-cli` — migrations run through `enclave-cli`, so the version that
applies them is always the one the code was built against.

```bash
git clone https://github.com/CasualOffice/enclave.git && cd enclave

# infrastructure: PostgreSQL, Redis, NATS, MinIO
# --wait returns when every service is healthy, not merely created
docker compose -f deploy/compose/dev.yml up -d --wait

export DATABASE_URL=postgres://enclave:enclave@localhost:5432/enclave
export REDIS_URL=redis://localhost:6379
export NATS_URL=nats://localhost:4222

cargo run -p enclave-cli -- migrate              # applies 0001 and 0002
cargo run -p enclave-cli -- seed --profile dev   # tenant-alpha and tenant-beta
cargo run -p enclave-cli -- doctor               # read-only; run this when something is wrong
```

Milvus and ClamAV are opt-in — they are the two heavy images and nothing in M0 uses either:

```bash
docker compose -f deploy/compose/dev.yml --profile search up -d --wait   # milvus + etcd
docker compose -f deploy/compose/dev.yml --profile av     up -d --wait   # clamav
```

To run from a configuration file rather than the environment, copy the template — it is a working
development configuration, and it holds references (`env://…`) rather than credentials, which is
why it can be committed at all:

```bash
cp deploy/config/enclave.example.yaml enclave.yaml   # git-ignored
cargo run -p enclave-cli -- --config enclave.yaml doctor
```

Then the application:

```bash
cargo run -p enclave-api                 # http://localhost:8080
```

The web client (`web/`, `npm install && npm run dev`, http://localhost:5173) lands with the
frontend milestone; there is nothing to start yet.

`cargo test --workspace` needs `DATABASE_URL` set as above: the harness creates a uniquely-named
database per test binary and drops it afterwards, so a test run never disturbs the database you
have been working in.

Ports, service-by-service notes, and how to reset the stack are in
[`deploy/README.md`](deploy/README.md).

## Workflow

1. Branch from `main`: `feat/short-description`, `fix/short-description`, `docs/…`.
2. Make the change, with tests.
3. Run the local gate (below).
4. Open a PR against `main` with a description that explains *why*, not just *what*.
5. Address review. Squash-merge; the PR title becomes the commit message.

### Local gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace               # needs DATABASE_URL and the dev stack

# once web/ exists:
# cd web && npm run lint && npm run typecheck && npm run test
```

There is no `cargo sqlx prepare` step: the compile-time-checked `sqlx::query!` macros are not used,
deliberately — they need a live database at build time, which puts a running PostgreSQL on the
critical path of every `cargo check`. See `crates/db/src/lib.rs` for the full reasoning.

CI runs all of the above plus the structural gates in
[`docs/12-TESTING.md §5`](docs/12-TESTING.md) — RLS coverage, policy routing, secret scanning,
OpenAPI drift, bundle size, i18n lint, accessibility.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(search): add language filter to hybrid queries
fix(auth): reject refresh tokens presented from a different device
docs(data-model): document quota reconciliation drift handling
test(security): cover post-filter with a deliberately over-permissive index
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`. Breaking changes
carry `!` and a `BREAKING CHANGE:` footer.

## What a good PR looks like

- **One logical change.** Refactoring bundled with a feature makes both harder to review; send them
  separately.
- **Tests that would fail without the change.** For anything touching policy, auth, sharing,
  retrieval, sync or MCP, that means rows in the leakage matrix
  ([`docs/12-TESTING.md §4`](docs/12-TESTING.md)), not just a happy path.
- **Docs updated in the authoritative place.** DDL only in `04`, endpoint contracts only in `05`, the
  crate list only in `02`. See the `doc-sync` procedure in [`SKILLS.md`](SKILLS.md).
- **Honest description.** If something is incomplete, deferred or uncertain, say so in the PR. A
  known gap flagged in review costs an hour; found in production it costs a weekend.

## Rules that reviewers will hold you to

These are the ones that get PRs sent back. They exist because each has, somewhere, been a real
vulnerability in a real system.

1. Every entry point calls `PolicyEngine::enforce`, in the canonical order. No hand-rolled ACL check,
   no fast path around DLP.
2. Tenant identity comes from the verified token or domain routing — never from a request body.
3. New tenant-scoped tables have `tenant_id` first, RLS enabled and forced, and composite FKs.
4. Search results are confirmed against PostgreSQL. The post-filter is never conditional.
5. Preview, download, print, export and sync stay distinct permissions.
6. Cross-tenant and barrier denials return `404`.
7. Obligations are satisfied or the operation fails. Never silently dropped.
8. Nothing is readable before antivirus completes.
9. No secret literals — references only. No logging of tokens, passwords, DLP match values or file
   content.
10. User-facing strings go through the i18n catalog; no physical `left`/`right` CSS.

If your change genuinely requires bending one of these, that is a design discussion to have in an
issue before writing the code — not something to resolve in review.

## Testing expectations

- New enforcement point ⇒ new leakage-matrix row **and** the test that proves it.
- Integration tests use the seeded `tenant-alpha` / `tenant-beta` fixtures.
- Never skip, `#[ignore]` or quarantine a security test to get a build green.
- Performance-sensitive changes: include a before/after measurement against the budgets in
  [`docs/03-LLD.md §23`](docs/03-LLD.md).

## Documentation contributions

Docs are a first-class deliverable here. When contributing to `docs/`:

- respect the single-source rule — one document is authoritative per concern;
- bump the document's version line and add a change-log row for substantive changes;
- cross-reference as `04-DATA-MODEL.md §7`;
- prefer specifics over adjectives. "P95 < 300 ms" beats "fast"; "fails closed for privileged scopes"
  beats "secure".

## Code of conduct

Be direct about code and considerate about people. Review the change, not the author. Assume the
contributor had a reason and ask what it was before concluding they didn't.

Unacceptable behavior — harassment, personal attacks, sustained disruption — can be reported to the
maintainers at **conduct@casualoffice.org**; reports are handled confidentially.

## Releases

Semantic versioning. `main` is always releasable. Release criteria are in
[`docs/12-TESTING.md §9`](docs/12-TESTING.md) — including that no security test is skipped, no SEV1
or SEV2 defect is open, and migrations verify both forward and against the previous release.

## Questions

Open a [discussion](https://github.com/CasualOffice/enclave/discussions) for design questions, an
[issue](https://github.com/CasualOffice/enclave/issues) for bugs and feature requests, and see
[`SECURITY.md`](SECURITY.md) for anything security-related.
