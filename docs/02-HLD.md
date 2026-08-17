# 02 — High-Level Design

> **Status:** Draft · **Version:** 2.0 · **Owner:** Platform Engineering · **Last updated:** 2026-08-18
> **Authoritative for:** architecture, service boundaries, the crate list, failure behavior, deployment topology.

## 1. Architecture objectives

- horizontal scaling;
- strong metadata consistency;
- immutable binary versions;
- tenant isolation enforced in two independent layers;
- synchronous policy enforcement;
- eventually consistent search/AI projections that are never solely authoritative;
- independent failure domains;
- customer-controlled infrastructure;
- enterprise observability and DR.

## 2. Reference architecture

```text
        React SPA / Desktop Sync / Mobile / External Editor / MCP Client
                                      |
                                      v
                           Gateway / Load Balancer
                              (TLS, custom domain -> tenant)
                                      |
                                      v
                               Rust Axum API
                                      |
          +---------------------------+---------------------------+
          |                           |                           |
          v                           v                           v
     PostgreSQL                    Redis                    Object Storage
     (authoritative)            (disposable)              (immutable versions)
          |
          v
  Transactional Outbox
          |
          v
      NATS JetStream
          |
   +------+---------+--------------+--------------+---------------+
   |                |              |              |               |
   v                v              v              v               v
Index Worker    DLP Worker    AV Worker    Preview Worker    Notification Worker
   |                                            |
   v                                            v
 Milvus                                  Rendition Store
```

Enterprise integrations:

```text
Rust API / Workers
 ├── LDAP / Active Directory
 ├── OIDC / SAML
 ├── SCIM
 ├── SMTP
 ├── Vault / KMS
 ├── SIEM
 ├── Antivirus engine (ICAP / ClamAV / vendor)
 ├── Embedding provider
 ├── External document editor
 ├── E-signature provider / TSA
 └── MCP Gateway
```

## 3. Source of truth

**Authoritative** — loss requires restore from backup:

- PostgreSQL metadata and security state;
- object storage file versions;
- audit records;
- DLP/conditional access policies;
- retention/legal hold state.

**Derived / rebuildable** — loss costs time, not data:

- Redis caches;
- Milvus indexes and embeddings;
- extracted text;
- previews/thumbnails/renditions;
- ranking projections;
- sync client caches.

Rebuild procedures for every derived store are in `11-OPERATIONS.md §5`.

## 4. Crate list (canonical)

This is the single authoritative crate list. `03-LLD.md` references it; it does not restate it.

```text
crates/
  # binaries
  api                     HTTP surface, policy enforcement, MCP gateway
  worker                  Event-driven processing (extract, embed, scan, notify)
  scheduler               Time-driven jobs (retention, rescan, sync, cleanup)

  # foundation
  core                    Shared domain types, IDs, errors, RequestContext, PolicyEngine
  config                  Layered configuration and secret references
  db                      SQLx pool, migrations, tenant-scoped query guard
  events                  Outbox, JetStream publish/consume, idempotency
  audit                   Audit event model, hash chain, SIEM forwarding

  # security & governance
  auth                    Sessions, passwords, MFA, WebAuthn, tokens
  identity                Users, groups, guests, service accounts, LDAP/OIDC/SAML/SCIM
  authorization           RBAC, ACL resolution, inheritance, effective permissions
  conditional_access      Network/device/auth-strength policy evaluation
  information_barriers    Mandatory segmentation
  classification          Labels, ranks, inheritance, ceilings
  dlp                     Detectors, policies, decisions, security facts
  incidents               Security incident lifecycle
  retention               Retention policies and schedules
  legal_hold              Hold custodians and deletion blocking
  records                 Record declaration and immutability rules

  # content
  workspaces              Workspaces, membership, visibility
  libraries               Libraries, settings, content types
  files                   Files, folders, moves, trash
  versions                Version lifecycle, restore, compare hooks
  uploads                 Upload sessions, state machine, multipart
  metadata                Field schemas, values, validation, taxonomy
  lists                   Structured lists and items
  pages                   Page blocks and rendering model
  sharing                 Share links, guest access, external sharing

  # search & AI
  search                  Query planning, hybrid retrieval, post-filter
  indexing                Extraction, chunking, manifests, invalidation
  embeddings              Embedding provider routing by classification
  mcp                     MCP tools/resources over domain services

  # infrastructure providers
  storage                 BlobStore implementations
  secrets                 SecretProvider implementations
  mail                    MailProvider implementations
  antivirus               AntivirusScanner implementations
  preview                 Rendition generation, sanitization, watermarking

  # delivery
  sync                    Delta cursors, device registry, sync eligibility
  notifications           In-app and email notification fan-out
  workflows               Workflow engine: stages, steps, approvals, checkout, automation
  signing                 Signature requests, PAdES/CAdES, TSA, verification, providers
  branding                Tenant branding tokens and custom domains

  # tooling — not part of the runtime architecture
  cli                     Operator and developer command line (seeding, diagnostics)
  testing                 Integration-test harness: disposable databases, tenant fixtures
```

`xtask` sits alongside `crates/` rather than inside it. It is build tooling — the structural lints
in `docs/12-TESTING.md §5` — and is never linked into a binary that ships.

Naming rules: crate directory names are lowercase `snake_case`, plural only where the crate owns a
collection of like things (`versions`, `embeddings`, `incidents`).

## 5. Runtime services

### `workspace-api`
HTTP/API, authentication, ACL, synchronous DLP and conditional-access decisions, metadata CRUD,
signed upload/download orchestration, search, sync delta serving, editor session brokering, and the
MCP gateway. Stateless; scales horizontally.

### `workspace-worker`
Extraction, previews/renditions, embeddings, Milvus indexing, malware scan, asynchronous DLP,
notifications, LDAP sync, webhook delivery, cleanup. Consumes JetStream; idempotent per event.

### `workspace-scheduler`
Retention jobs, rescan/reindex scheduling, directory sync, quota reconciliation, recurring cleanup
and maintenance. Singleton-per-schedule via leader election on Redis or Postgres advisory locks.

## 6. PostgreSQL

Stores authoritative tenant, identity, workspace, file, version, policy, retention, audit, incident,
quota and index-manifest metadata. Uses SQLx with a transactional outbox.

Tenant isolation is enforced twice: an application-layer query guard and PostgreSQL Row-Level
Security. Both are specified in `04-DATA-MODEL.md §3`.

## 7. Object storage

Provider abstraction supports local filesystem, S3-compatible, AWS S3, MinIO, Ceph, R2, Wasabi,
Backblaze B2; later Azure Blob and GCS.

Canonical object key:

```text
tenant/{tenant_id}/files/{file_id}/versions/{version_id}
```

Rendition key:

```text
tenant/{tenant_id}/renditions/{version_id}/{profile}/{artifact}
```

Logical folder moves only update metadata; bytes never move for a rename or reparent.

## 8. Redis

Disposable only: sessions, rate limits, short-lived authz caches, compiled policy caches, locks,
coordination, and the retrieval denylist described in `07-SEARCH-INDEXING.md §6.4`. Losing Redis
degrades latency and forces re-authentication; it never loses authoritative state.

## 9. Eventing

NATS JetStream fed by a transactional outbox. Every event carries `tenant_id`, `event_id`,
`occurred_at`, `actor` and a `schema_version`. Consumers are idempotent on `event_id`.

Subjects:

| Subject | Emitted when | Primary consumer |
|---|---|---|
| `file.version.created` | New version committed | AV → DLP → Index |
| `file.deleted` / `file.restored` | Trash transitions | Index, sync |
| `permission.changed` | ACL or membership change | Index invalidation, authz cache |
| `classification.changed` | Label applied or recomputed | Index metadata update |
| `dlp.scan.requested` | Upload, policy change, detector change | DLP worker |
| `av.scan.requested` | Upload complete | AV worker |
| `index.requested` | Content or model change | Index worker |
| `preview.requested` | First preview or profile change | Preview worker |
| `retention.triggered` | Schedule fires | Scheduler → retention |
| `sync.invalidated` | Any change affecting a synced path | Sync delta cursor |
| `workflow.started` / `.step.decided` / `.completed` | Workflow transitions | Workflow engine, notifications |
| `signature.requested` / `.signed` / `.completed` | Signing ceremony progress | Signing worker, filing |
| `webhook.requested` | Outbound integration | Notification worker |

## 10. Milvus search architecture

Collection: `workspace_chunks`. Field-level schema and the retrieval security model live in
`07-SEARCH-INDEXING.md §4–§6`.

Search combines dense ANN, BM25/sparse retrieval, metadata filters and reranking, followed by an
authoritative permission recheck that no result may skip.

## 11. Search pipeline

```text
User Query
 -> Authentication
 -> Resolve tenant / groups / security tokens
 -> Conditional access + search scope resolution
 -> Milvus hybrid query with server-built metadata filters (over-fetched)
 -> Rerank
 -> Authoritative permission + barrier + classification recheck against PostgreSQL
 -> Redact / drop unauthorized hits
 -> Results
```

Never retrieve globally and filter only at the end **as the sole control** — the pre-filter narrows
and the post-filter guarantees. Both are required.

## 12. Indexing pipeline

```text
Version Created
 -> Malware Scan          (blocking: infected -> QUARANTINED, no further stages)
 -> DLP Pre-Scan
 -> Extract
 -> Structure Parse
 -> Semantic Chunk
 -> Embed                 (provider chosen by classification)
 -> Milvus upsert
 -> Mark index manifest READY
```

ACL and classification changes update index metadata without re-embedding when content is
unchanged; when a metadata-only update is not possible, the fallback path in
`07-SEARCH-INDEXING.md §6.3` applies.

## 13. MCP architecture

```text
LLM Client
  -> MCP Transport
  -> Workspace MCP Gateway
      -> Authentication (client credential + scope set)
      -> Tenant context
      -> Conditional access
      -> Authorization / ACL
      -> Information barriers
      -> Classification ceiling
      -> DLP
      -> Audit
      -> Domain service / search
```

MCP never connects directly to PostgreSQL, Milvus or object storage. It calls the same domain
services the HTTP API calls.

## 14. Security enforcement order (canonical)

```text
Tenant Isolation
 -> Authentication
 -> Conditional Access
 -> Authorization / ACL
 -> Information Barriers
 -> Classification Policy
 -> DLP
 -> Retention / Records / Legal Hold
 -> Execute
 -> Audit
```

Implemented once in `03-LLD.md §12`. Any code path that needs a different order is a design defect,
not a special case.

## 15. Preview architecture

```text
Browser
 -> Preview API
 -> Security pipeline
 -> Rendition lookup (base, identity-free, cached)
 -> Watermark composition (per-request, per-identity, not cached)
 -> Protected rendition
```

Original object-storage URLs are never issued for view-only access. Base renditions are cached and
encrypted at rest; watermarked output is composed at delivery time — see
`06-SECURITY-DLP-ACCESS.md §5`.

## 16. Download architecture

```text
POST /files/{id}/download
 -> security pipeline
 -> audit (decision recorded before URL issuance)
 -> short-lived signed URL (single-use where the provider supports it)
 -> object store
```

For no-download policies, a signed original URL is never generated — the endpoint returns a policy
denial, not an empty success.

## 17. Conditional access

Signals: source IP/CIDR, country/region, ASN, named location/network zone, device trust, auth
strength, client type, user/guest type, risk/time context.

Policies may require trusted network, MFA, managed device, preview-only, or full block. Client type
includes `sync` and `editor`, so a policy can permit browser preview while denying sync.

## 18. DLP architecture

Synchronous decisions use precomputed `SecurityFacts` (detector results, classification, counts,
scan version). Full rescans run asynchronously after upload, policy change or detector change.

A synchronous action whose facts are missing or stale-by-scan-version follows the tenant's
configured `facts_unavailable` policy: `FAIL_CLOSED` (default for `RESTRICTED`) or `FAIL_OPEN_AUDIT`.

## 19. Identity architecture

External identities map to stable internal UUIDs. Sources: local, LDAP/AD, OIDC, SAML, SCIM.
SCIM/LDAP sync update local users/groups; sessions always carry internal identities.

## 20. BYO infrastructure abstraction

Provider interfaces: `BlobStore`, `SecretProvider`, `MailProvider`, `VectorStore`,
`EmbeddingProvider`, `KeyProvider`, `IdentityProvider`, `AntivirusScanner`, `RenditionStore`.

Business logic depends on interfaces, never on AWS/Azure/vendor specifics. Details in `08-BYO-INFRA.md`.

## 21. White-labeling architecture

Branding is tenant configuration exposed via a bootstrap/branding API. React applies controlled
design tokens as CSS variables. Custom domains map to tenant IDs at the gateway, before application
code runs.

## 22. Frontend architecture

React + TypeScript + Vite, React Router, TanStack Query/Table/Virtual, React Hook Form, Zod, and
lightweight local Zustand state.

Feature modules: auth, workspaces, files, views, search, sharing, lists, pages, security, admin,
MCP/AI, branding.

## 23. Observability

OpenTelemetry traces, metrics and logs. Span attributes: tenant ID, request ID, actor type,
workspace ID, operation, policy decision. Security events additionally forward to SIEM/syslog/webhook
integrations. Never record raw passwords, tokens or sensitive file content.

## 24. Failure behavior

| Dependency down | Behavior |
|---|---|
| PostgreSQL | Reject writes; no unsafe fallback; reads fail rather than serve stale authority |
| Object storage | Metadata browsing continues; transfers fail with a retryable error |
| Redis | Degrade to direct authorization checks; sessions may require re-auth; no authoritative loss |
| Milvus | Search and AI degrade or return `503`; file operations continue |
| NATS | Outbox retains events until recovery; workers idle |
| Embedding provider | Indexing stays `PENDING`; files remain available and lexically searchable |
| Antivirus | New uploads hold in `SCANNING` per tenant policy; existing content unaffected |
| SMTP | Notification retries then dead-letter; core operations continue |
| Vault | Cached/leased secrets continue within policy; new fetches fail closed |
| External editor | Editing unavailable; preview and download unaffected |

## 25. Deployment profiles

**Community** — single API/worker, PostgreSQL, Redis, NATS, MinIO, Milvus standalone.

**Production** — multiple API/worker replicas, HA PostgreSQL, Redis, NATS cluster, S3, Milvus cluster.

**Enterprise** — multi-AZ, BYO Vault/KMS/storage/SMTP/AV, SIEM, SSO, DLP, data residency, custom
domains, distributed Milvus, backup/DR.

## 26. High availability

Minimum serious production topology: API 3 replicas, workers 2+, NATS 3 nodes, PostgreSQL primary
plus replica with automated failover, HA Milvus where search is business-critical, replicated object
storage.

## 27. Engineering practices

Idempotency, retries with jittered backoff, circuit breakers, bulkheads, graceful shutdown,
dead-letter queues, forward-only migration discipline, supply-chain security, SBOM, signed releases,
container scanning, backup verification, regular DR exercises.

## 28. Core invariant

Every entry point — Web, desktop sync, mobile, REST, MCP, agent, plugin, preview, download, search,
external editor, webhook or admin utility — passes through the same policy chain in `§14`.
