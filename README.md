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

## Getting started

Once implementation begins:

```bash
git clone https://github.com/CasualOffice/enclave.git && cd enclave

# bring up PostgreSQL, Redis, NATS, MinIO, Milvus, ClamAV
docker compose -f deploy/compose/dev.yml up -d

cp deploy/config/enclave.example.yaml enclave.yaml
cargo run -p enclave-api        # http://localhost:8080
cd web && npm install && npm run dev
```

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
