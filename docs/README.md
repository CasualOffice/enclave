# Enclave — Enterprise Shared Workspace · Documentation Pack

> **Status:** Draft · **Version:** 2.0 · **Owner:** Casual Office · Platform Engineering · **Last updated:** 2026-08-18

A production-grade, SharePoint-class enterprise workspace built with Rust and React: content,
identity, permissions, governance, search, collaboration, DLP, retention, audit and AI access
behind one enforced policy boundary.

## 1. How to read this pack

Documents are ordered. Each answers a distinct question; none repeats another's authority.

| # | Document | Authoritative for |
|---|---|---|
| — | `README.md` (this file) | Index, canonical invariant, doc conventions |
| 01 | [`01-PRD.md`](01-PRD.md) | Scope, personas, capabilities, phasing, acceptance criteria |
| 02 | [`02-HLD.md`](02-HLD.md) | Architecture, service boundaries, **canonical crate list**, failure behavior, deployment |
| 03 | [`03-LLD.md`](03-LLD.md) | Rust types and traits, policy enforcement implementation, runtime rules |
| 04 | [`04-DATA-MODEL.md`](04-DATA-MODEL.md) | **All** PostgreSQL DDL, tenant isolation strategy, quotas |
| 05 | [`05-API.md`](05-API.md) | REST surface, error model, pagination, idempotency, versioning |
| 06 | [`06-SECURITY-DLP-ACCESS.md`](06-SECURITY-DLP-ACCESS.md) | Threat model, conditional access, DLP, antivirus, renditions, incidents |
| 07 | [`07-SEARCH-INDEXING.md`](07-SEARCH-INDEXING.md) | Indexing pipeline, Milvus schema, **ACL invalidation**, rebuild |
| 08 | [`08-BYO-INFRA.md`](08-BYO-INFRA.md) | Provider traits, BYO storage/secrets/mail/vector/embedding/AV, configuration |
| 09 | [`09-UX-WHITE-LABELING.md`](09-UX-WHITE-LABELING.md) | Application UX, views, admin UX, branding, accessibility |
| 10 | [`10-SYNC-AND-EDITING.md`](10-SYNC-AND-EDITING.md) | Desktop/mobile sync clients, external document editors |
| 11 | [`11-OPERATIONS.md`](11-OPERATIONS.md) | SLOs, runbooks, backup/DR, key rotation, upgrades, capacity |
| 12 | [`12-TESTING.md`](12-TESTING.md) | Test strategy, security leakage matrix, CI gates |
| 13 | [`13-IDENTITY-SSO-SCIM.md`](13-IDENTITY-SSO-SCIM.md) | OIDC, SAML, LDAP/AD, SCIM, JIT, guests, deprovisioning |
| 14 | [`14-I18N-L10N.md`](14-I18N-L10N.md) | Locale negotiation, translation workflow, formatting, RTL, multilingual search |
| 15 | [`15-WORKFLOWS-AND-SIGNING.md`](15-WORKFLOWS-AND-SIGNING.md) | Workflow engine, approvals, document signing pipeline |
| 16 | [`16-GLOSSARY.md`](16-GLOSSARY.md) | Shared vocabulary |

**Single-source rules.** When two documents appear to disagree, the authoritative column above wins.
Do not restate DDL outside `04`, endpoint contracts outside `05`, or the crate list outside `02`.

## 2. Core technical stack

- **Backend:** Rust, Axum, Tokio, Tower, SQLx
- **Frontend:** React, TypeScript, Vite, TanStack Query/Table/Virtual, React Router
- **Primary metadata DB:** PostgreSQL (authoritative)
- **Cache/session:** Redis (disposable)
- **Event bus:** NATS JetStream, fed by a transactional outbox
- **Object storage:** S3-compatible behind a provider abstraction
- **Search/vector retrieval:** Milvus — dense, sparse, BM25/hybrid
- **Identity:** Local, LDAP/AD, OIDC, SAML, SCIM, WebAuthn/passkeys; JWT access tokens + rotating refresh tokens
- **Security:** DLP, information barriers, retention, legal hold, conditional access, audit
- **AI integration:** MCP gateway, semantic search, RAG-safe retrieval, BYO embedding **and BYO LLM** providers
- **Observability:** OpenTelemetry
- **Internationalization:** ICU MessageFormat, full RTL, locale-aware search analyzers

## 3. Canonical architectural invariant

Every operation, without exception, passes through this chain in this order:

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

This is the **canonical chain**. It is reproduced verbatim in `02-HLD.md §14`, implemented in
`03-LLD.md §12`, and tested in `12-TESTING.md §4`. It applies to Web, mobile, desktop, sync clients,
REST APIs, MCP, search, preview, download, external editor sessions, agents, plugins, webhooks and
admin utilities.

Two corollaries that are load-bearing throughout the pack:

1. **Derived state is never the sole authority.** Search indexes, caches and renditions may be
   stale; a result they produce is confirmed against PostgreSQL before it reaches a caller
   (`07-SEARCH-INDEXING.md §6`).
2. **The client is hostile.** Identity attributes, IDs, paths and headers arriving from a client
   are inputs to policy, never conclusions of it.

## 4. Document conventions

- Each document opens with a metadata line: status, version, owner, last-updated.
- `MUST` / `MUST NOT` / `SHOULD` / `MAY` carry RFC 2119 meaning.
- SQL is PostgreSQL 15+. Rust is 2021 edition, `async_trait` where shown.
- Identifiers are UUIDv7 unless stated otherwise.
- Times are `TIMESTAMPTZ`, stored UTC.
- Cross-references use the form `04-DATA-MODEL.md §7`.

## 5. Change log

| Version | Date | Change |
|---|---|---|
| 2.0 | 2026-08-18 | Reorganized into an ordered pack. Reconciled the crate list and enforcement chain to single sources. Added `04`, `05`, `07`, `10`–`16`. Specified ACL invalidation for the vector index, tenant isolation via RLS, quotas, antivirus provider, watermark/rendition caching, sync and external-editor designs, SSO/SCIM identity, i18n/l10n, BYO LLM, the workflow engine and the document signing pipeline. Replaced opaque sessions with JWT access tokens + rotating refresh tokens. |
| 1.0 | — | Initial six-document pack. |
