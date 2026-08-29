# Enclave

**Enterprise shared workspace — content, governance, search and AI access behind one policy boundary.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A [Casual Office](https://casualoffice.org) project · [`github.com/CasualOffice/enclave`](https://github.com/CasualOffice/enclave)

Enclave is a self-hostable, cloud-ready enterprise content and collaboration platform — SharePoint-class
in purpose, built around modern APIs, Rust performance, a React interface, strong security
governance, customer-controlled infrastructure, hybrid vector search and MCP-native AI access.

It is not a file server. It is an information boundary combining content, identity, permissions,
governance, search, collaboration, DLP, retention, audit and AI access.

> **Status: design phase.** This repository currently contains the complete specification pack.
> Implementation follows the phasing in [`docs/01-PRD.md §37`](docs/01-PRD.md).

## What it does

- **Content** — workspaces, libraries, folders, files, immutable versions, lists, pages, metadata and
  content types, 16 view types.
- **Identity** — local, LDAP/AD, OIDC, SAML, SCIM, WebAuthn/passkeys, guests, service accounts.
  JWT access tokens with rotating refresh tokens.
- **Authorization** — granular per-action permissions (preview ≠ download ≠ print ≠ export ≠ sync),
  hierarchical ACL inheritance with explicit break, deny-wins resolution.
- **Governance** — DLP with simulation, classification, information barriers, retention, records,
  legal hold, antivirus, security incidents, tamper-evident audit.
- **Conditional access** — IP/CIDR, country, ASN, network zone, device posture, auth strength,
  client type.
- **Search** — Milvus hybrid retrieval (dense + sparse + BM25) with permission-aware results that are
  confirmed against the authoritative database before they reach a caller.
- **AI** — MCP gateway under the same policy chain, RAG answers with citations, BYO embedding and BYO
  LLM providers with classification-aware routing.
- **BYO infrastructure** — object storage, secrets, KMS, SMTP, vector store, embeddings, LLM,
  antivirus, identity. All behind provider traits.
- **Workflows & signing** — approval/review pipelines, and document signing from click-through
  acknowledgement to PAdES digital signatures with long-term validation.
- **Enterprise delivery** — white-labeling, custom domains, i18n with full RTL, WCAG 2.2 AA,
  desktop/mobile sync, external document editing, HA and DR.

## The invariant

Every operation — Web, desktop sync, mobile, REST, MCP, agent, preview, download, search, external
editor, webhook or admin utility — passes through this chain, in this order:

```text
Tenant Isolation
 -> Authentication
 -> Conditional Access
 -> Authorization (RBAC / ACL)
 -> Information Barriers
 -> Classification Policy
 -> DLP
 -> Retention / Records / Legal Hold
 -> Execute
 -> Audit
```

It is implemented once, in one function, and every entry point calls it. A code path that needs a
different order is a design defect, not a special case.

Two corollaries run through the whole system:

1. **Derived state is never the sole authority.** Search indexes, caches and renditions may be stale;
   what they produce is confirmed against PostgreSQL before it reaches a caller.
2. **The client is hostile.** Identity attributes, IDs, paths and headers from a client are inputs to
   policy, never conclusions of it.

## Documentation

The full specification lives in [`docs/`](docs/README.md) as an ordered pack:

| Doc | Covers |
|---|---|
| [01 PRD](docs/01-PRD.md) | Scope, personas, capabilities, phasing, acceptance criteria |
| [02 HLD](docs/02-HLD.md) | Architecture, services, crate list, failure behavior, deployment |
| [03 LLD](docs/03-LLD.md) | Rust types and traits, policy engine, auth tokens, runtime rules |
| [04 Data model](docs/04-DATA-MODEL.md) | All PostgreSQL DDL, tenant isolation, quotas |
| [05 API](docs/05-API.md) | REST surface, error model, pagination, idempotency, rate limits |
| [06 Security & DLP](docs/06-SECURITY-DLP-ACCESS.md) | Threat model, conditional access, DLP, antivirus, renditions |
| [07 Search & indexing](docs/07-SEARCH-INDEXING.md) | Pipeline, Milvus schema, ACL invalidation, rebuild |
| [08 BYO infrastructure](docs/08-BYO-INFRA.md) | Provider traits, BYO storage/secrets/LLM/AV, configuration |
| [09 UX & white-labeling](docs/09-UX-WHITE-LABELING.md) | UX standards, views, admin UX, branding, accessibility |
| [10 Sync & editing](docs/10-SYNC-AND-EDITING.md) | Desktop/mobile sync, external document editors |
| [11 Operations](docs/11-OPERATIONS.md) | SLOs, runbooks, backup/DR, key rotation, capacity |
| [12 Testing](docs/12-TESTING.md) | Test strategy, security leakage matrix, CI gates |
| [13 Identity & SSO](docs/13-IDENTITY-SSO-SCIM.md) | OIDC, SAML, LDAP, SCIM, JIT, guests, deprovisioning |
| [14 i18n & l10n](docs/14-I18N-L10N.md) | Locales, translation workflow, RTL, multilingual search |
| [15 Workflows & signing](docs/15-WORKFLOWS-AND-SIGNING.md) | Workflow engine, approvals, document signing pipeline |
| [16 Glossary](docs/16-GLOSSARY.md) | Shared vocabulary |

**Planning:** [`ROADMAP.md`](ROADMAP.md) holds the milestones, gates and target dates.
[`TRACKER.md`](TRACKER.md) is the single backlog — every item, priority and status.

Working with an AI assistant on this repository? Start with [`CLAUDE.md`](CLAUDE.md) and
[`SKILLS.md`](SKILLS.md).

## Stack

| Layer | Choice |
|---|---|
| Backend | Rust · Axum · Tokio · Tower · SQLx |
| Frontend | React · TypeScript · Vite · TanStack Query/Table/Virtual |
| Metadata | PostgreSQL 15+ (authoritative, RLS-enforced) |
| Cache | Redis (disposable) |
| Events | NATS JetStream via transactional outbox |
| Objects | S3-compatible behind `BlobStore` |
| Retrieval | Milvus — dense, sparse, BM25 hybrid |
| Observability | OpenTelemetry |

## Repository layout

```text
enclave/
├── Cargo.toml          workspace manifest
├── crates/             see docs/02-HLD.md §4 for the canonical crate list
├── web/                React + TypeScript SPA
├── migrations/         forward-only SQL migrations
├── deploy/             Docker, Compose, Helm, Terraform examples
├── tests/              cross-crate integration and security suites
└── docs/               the specification pack
```

## Running the server

Six things have to be true before `enclave-api` will serve a request, and none of them used to be
written down — the first person to start it needed six attempts, and every fact they were missing
existed only inside a source file. They are here in the order the process needs them.

```bash
git clone https://github.com/CasualOffice/enclave.git && cd enclave

# 1. Infrastructure. PostgreSQL is required; the rest are for the worker and the search stack.
docker compose -f deploy/compose/dev.yml up -d --wait
```

**1. `enclave.yaml` is read from the working directory.** Not from a path in an environment
variable, and not from a `--config` flag — `enclave-api` has neither. Copy the template into the
directory you will run from:

```bash
cp deploy/config/enclave.example.yaml enclave.yaml
```

**2. Both database DSNs are required, and both must be `env://` references.** A password written
into a YAML file is refused at start-up (`CLAUDE.md` rule 11), so `enclave.example.yaml` carries the
`*_env` spellings and you export the values. `platform_url_env` is **commented out** in the
template — uncomment it:

```yaml
database:
  url_env: "DATABASE_URL"
  platform_url_env: "DATABASE_PLATFORM_URL"
  application_role: "enclave_app"
```

```bash
export DATABASE_URL=postgres://enclave:enclave@localhost:5432/enclave
export DATABASE_PLATFORM_URL="$DATABASE_URL"      # see below — not optional in practice
```

`database.platform_url` reads as optional and is not. Two things need it:

- **`POST /api/v1/auth/login`.** Resolving a host to a tenant reads `tenants`, which carries no
  `tenant_id` and therefore has no row-level-security policy — so `migrations/0002` grants
  `enclave_app` nothing on it at all and gives `SELECT` to `enclave_platform`. With no platform DSN
  every host resolves to nothing and **every login answers `404`**, which reads as a wrong URL.
- **Migrations.** `enclave-api` applies them at start-up and takes the migration connection from
  `migration_url`, falling back to `platform_url`. With neither, it refuses to start.

In a real deployment these are two different roles with two different passwords. On the dev stack
the roles have no passwords at all (`deploy/compose/init/01-roles.sql` deliberately creates none),
so both point at the superuser DSN and `database.application_role: enclave_app` is what puts
row-level security back on — without it the pool stays superuser and RLS is bypassed entirely.

**3. Four more variables must resolve, even though `enclave-api` contacts none of them.** They are
*referenced* by the configuration, and an unresolvable reference is a start-up failure:

```bash
export REDIS_URL=redis://localhost:6379
export NATS_URL=nats://localhost:4222
export S3_ACCESS_KEY_ID=enclave
export S3_SECRET_ACCESS_KEY=...                  # deploy/compose/dev.yml has the value
```

The value is not repeated here on purpose: `deploy/config/enclave.example.yaml` declines to print
it too, and a credential that appears in two places is one that gets copied to a third.

**4. Start it.** On the `community` profile bound to a loopback address — the default, and the only
combination that qualifies — a development signing key is generated under
`auth.signing_keys.directory` on first run. Any other profile, or any non-loopback bind, requires
`auth.signing_keys.key_ref` and refuses to start without it.

```bash
cargo run -p enclave-api        # http://localhost:8080
```

Read the start-up banner rather than skipping it: it names every policy stage that is not enforcing,
and warns when the auth surface or object storage is unconfigured. One caveat — the `enclave-api
listening` line reports the address the process was *asked* for, so `server.port: 0` is logged as
`127.0.0.1:0` and you have to find the real port elsewhere.

**5. Seed a tenant and give an account a password.** `seed` writes users and nothing has ever
written a credential, so every seeded account correctly answers `401` until this is done. The
password is read from **stdin** — there is deliberately no flag, because a command line lands in
shell history and in `ps` output:

```bash
cargo run -p enclave-cli -- seed
printf '%s' "$NEW_PASSWORD" | cargo run -p enclave-cli -- \
  set-password --tenant tenant-alpha --email admin@tenant-alpha.example
```

**Use `admin@`, not `owner@`.** The fixture seeds five accounts per tenant and exactly one of them —
`admin@tenant-alpha.example` — carries `users.is_admin`. It is the only administrative grant this
schema has (`crates/authorization/src/admin.rs`), and `POST /admin/workspaces` is what provisions the
first workspace. `owner@` signs in perfectly well and then cannot create anything, which reads as a
broken product rather than as the wrong account: this file said `owner@` until `ENC-925`, and the
walkthrough that found it got as far as an empty `GET /workspaces` before stopping.

**6. Log in on a host that routes to the tenant.** The tenant comes from the routed authority and
never from the request body (`CLAUDE.md` rule 3). A single-label host such as `localhost` routes no
tenant — the first label is read as the tenant's slug and a bare host has none — so a login to
`http://localhost:8080` answers `404` however correct the credentials are. Send the `Host` header
the deployment would really be reached at:

```bash
curl -s http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Host: tenant-alpha.enclave.test' -H 'Content-Type: application/json' \
  -d '{"email":"admin@tenant-alpha.example","password":"'"$NEW_PASSWORD"'"}'

curl -s http://127.0.0.1:8080/api/v1/me \
  -H 'Host: tenant-alpha.enclave.test' -H "Authorization: Bearer $ACCESS_TOKEN"
```

The web client is a separate process:

```bash
cd web && npm install && npm run dev
```

### The journey, end to end

Run against the setup above on 2026-08-29, every step through the HTTP API, nothing touched directly
in the database. This is what "it works" currently means, and it is deliberately concrete — for most
of this project's life the honest answer was that a clean install had nowhere to put a file and no
way to make one.

| Step | Request | Answer |
|---|---|---|
| Sign in | `POST /auth/login` with `Host: tenant-alpha.enclave.test` | `200` + access token |
| Look around | `GET /workspaces` | `200` `{"items":[]}` |
| Provision | `POST /admin/workspaces` | `201`, and the founding grant is in the response's `capabilities` |
| Add a library | `POST /workspaces/{id}/libraries` | `201` |
| Add a folder | `POST /libraries/{id}/folders` | `201` |
| Open it | `GET /files/{id}` | `200` |
| Rename it | `PATCH /files/{id}` with `If-Match` | `200`, `revision` 1 → 2 |
| Let somebody in | `GET` then `PUT /workspaces/{id}/permissions` | `200` — and the second account goes `404` → `200` on the same workspace |
| Delete it | `DELETE /files/{id}` with `If-Match` | `200`, and the listing empties |
| Undo that | `POST /files/{id}/restore` with `If-Match` | `200`, and the listing fills again |

Uploading bytes needs the worker and antivirus as well, which is `docker compose --profile search`
plus `cargo run -p enclave-worker`; the steps above need only PostgreSQL and MinIO.

### Uploading a file

The table above is folders. Uploading *bytes* needs two more things, and both were found by doing
it rather than by reading (`ENC-926`).

**Run the worker.** `POST /uploads/{id}/complete` answers `202 SCANNING` and stops there. Nothing in
`enclave-api` publishes a version — the antivirus pass and the publish that follows it are
`enclave-worker`'s, so without it every upload sits in `SCANNING` forever and that is rule 9 working,
not a bug:

```bash
cargo run -p enclave-worker
```

**Decide what scans it.** The template says `antivirus.provider: clamav`, and the dev stack's ClamAV
is behind a Compose profile:

```bash
docker compose -f deploy/compose/dev.yml --profile av up -d --wait
export CLAMD_ADDR=tcp://localhost:3310
```

On **Apple Silicon** that image is `linux/amd64` only. `dev.yml` pins the platform so it runs under
emulation rather than failing at pull time, and emulation plus a first-boot signature download is
slow. The alternative is to run with no engine, which the configuration supports deliberately:

```yaml
antivirus:
  provider: "none"
  unsupported_policy: "ALLOW_WITH_FLAG"
```

That publishes content **nothing inspected for malware**, recorded `SKIPPED` rather than `CLEAN` —
so it stays distinguishable, and configuring an engine later rescans the whole corpus rather than
leaving it unexamined. `enclave-api` says so at `warn` on every boot. The default
`unsupported_policy: BLOCK` is the other half of that decision and is the one to leave alone in
anything real: with `provider: none` it makes the deployment a **write-only store** — uploads
succeed and nothing can be read back. The `enterprise` profile refuses `provider: none` outright.

The round trip, verified end to end on 2026-08-29:

| Step | Request | Answer |
|---|---|---|
| Reserve | `POST /uploads` with `libraryId`, `name`, `sizeBytes`, `sha256` | `201` + a pre-signed `PutObject` URL and `requiredHeaders` |
| Send | `PUT` to that URL with **both** required headers | `200` |
| Finish | `POST /uploads/{id}/complete` with `sizeBytes`, `sha256`, `parts` | `202 SCANNING` |
| — | the worker's antivirus pass runs | `files.status` → `AVAILABLE`, `av_status` → `SKIPPED` |
| Read | `GET /files/{id}` | `200`, `capabilities.download: true` |
| Fetch | `POST /files/{id}/download`, then the signed URL | the original bytes |

`requiredHeaders` is not advisory: `x-amz-checksum-sha256` is signed into the URL, so the provider
hashes what it receives and refuses a body that disagrees with the digest declared at reserve time.

### What a running server cannot do yet

Checked on every commit by `crates/api/tests/reachability.rs`, which starts this binary, logs in and
calls every registered route. Each of these is a tracker row rather than a surprise:

| Endpoint | Answers | Why |
|---|---|---|
| `POST /sync/devices` | `403` | Enrolling a device asks a question no composed authorization service can answer (`ENC-736`). |
| The `/admin/**` mutations, *if* `security.mfa.admins_required` is `true` | `403` | They require multi-factor authentication within 15 minutes and no factor can be verified in this build (`ENC-771`, `ENC-688`). The template now ships `false`, because `true` with no verifier is refused at start-up — so on the documented setup these **work**, and `POST /admin/workspaces` is one of them (`ENC-925`). |

`POST /uploads` is no longer on that list: `ENC-770` composed the real object store and the write
path answers `201` with a signed `PutObject` URL. The row is deleted rather than reworded, because
a quarantine that outlives its defect is how a stale limitation becomes folklore (`ENC-803`).

**One limit is configuration rather than missing code, and it is the one most likely to be met
first.** With `antivirus.provider: none` — the only workable setting on a machine with no scanner —
what a delivery route will serve is decided by `antivirus.unsupported_policy`:

- `BLOCK`, the default: every version is quarantined `SKIPPED`, and preview, download, print,
  export and sync all answer `404`. **Uploads succeed and nothing can ever be read back.** Both
  binaries say so at start-up, `enclave-api` at `error` level.
- `ALLOW_WITH_FLAG`: versions are published `AVAILABLE`/`SKIPPED` and served, unscanned, with
  `CONFIDENTIAL` and above still refused on rank (`ENC-828`).

Neither is a bug; the first is rule 9 doing its job. `deploy/config/enclave.example.yaml` documents
both beside the key.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full development workflow.

## Deployment profiles

| Profile | Shape |
|---|---|
| **Community** | Single node, MinIO, Milvus standalone, embedded ClamAV |
| **Production** | Scaled API/workers, HA PostgreSQL, Redis, NATS cluster, S3, Milvus cluster |
| **Enterprise** | Multi-AZ, BYO Vault/KMS/storage/SMTP/AV/Milvus/LLM, SSO, SIEM, residency, DR |

The `enterprise` profile refuses to start with antivirus disabled, audit disabled, or a
publicly-readable storage bucket.

## Security

Security issues must not be filed as public issues — report them to **security@casualoffice.org** or
through [private vulnerability reporting](https://github.com/CasualOffice/enclave/security/advisories/new).
See [`SECURITY.md`](SECURITY.md) for scope and response targets. The permanent leakage-test matrix that guards this system is in
[`docs/12-TESTING.md §4`](docs/12-TESTING.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Questions go to
[discussions](https://github.com/CasualOffice/enclave/discussions); bugs and features to
[issues](https://github.com/CasualOffice/enclave/issues).

## License

Apache License 2.0 — Copyright 2026 Casual Office. See [`LICENSE`](LICENSE).
