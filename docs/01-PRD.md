# 01 — Product Requirements

> **Status:** Draft · **Version:** 2.0 · **Owner:** Product · **Last updated:** 2026-08-18
> **Authoritative for:** scope, personas, capabilities, phasing, acceptance criteria.

## 1. Vision

Build a self-hostable and cloud-ready enterprise content and collaboration platform comparable in
purpose to SharePoint, but designed around modern APIs, Rust performance, React UX, strong security
governance, customer-controlled infrastructure, hybrid/vector search and MCP-native AI access.

The workspace is not merely a file server. It is an information boundary combining content,
identity, permissions, governance, search, collaboration, DLP, retention, audit and AI access.

## 2. Goals

The platform must support:

- multi-tenant organizations;
- workspaces/sites;
- document libraries;
- folders and files;
- immutable versions;
- multiple file/list views;
- metadata and content types;
- structured lists;
- pages/wiki;
- comments, mentions and activity;
- approval/check-in/check-out;
- workflows, approval pipelines and document signing;
- local auth, LDAP/AD, OIDC, SAML, SCIM and WebAuthn;
- granular RBAC + hierarchical ACL inheritance;
- separate preview/download/export/print/share permissions;
- guest/external sharing;
- password/OTP/MFA protected links;
- conditional access using IP, CIDR, country, region, ASN, network zone, device and auth strength;
- DLP and classification;
- antivirus/malware scanning of all ingested content;
- information barriers;
- retention, records and legal hold;
- security incidents and SIEM integration;
- search using Milvus hybrid retrieval;
- semantic/vector indexing;
- permission-aware MCP tools/resources;
- desktop and mobile sync clients under the same policy chain;
- external document-editor sessions;
- storage, seat and rate quotas;
- BYO object storage, Vault/KMS, SMTP, Milvus and embedding endpoints;
- white-label branding and custom domains;
- production-grade admin, observability, HA and DR.

## 3. Non-goals for V1

- full Power Automate clone;
- full Power Apps clone;
- complete Microsoft 365 protocol/API compatibility;
- native email server;
- native video conferencing;
- arbitrary server-side native plugins;
- real-time co-authoring implemented in-house (delegated to an external editor — see `10-SYNC-AND-EDITING.md`);
- offline editing on sync clients (V1 sync is read/write of whole files, not offline merge);
- client-side desktop editors binding files over WebDAV for no-download classifications;
- guaranteed prevention of screenshots on unmanaged browsers.

## 4. Personas

| Persona | Owns |
|---|---|
| **Employee** | Searching, previewing, editing, sharing, commenting, collaborating |
| **Workspace Owner** | Members, libraries, views, metadata, workflows, workspace-level policy |
| **Tenant Administrator** | Org configuration, domains, branding, storage, quotas, integrations |
| **Identity Administrator** | Local users, LDAP/AD, OIDC, SAML, SCIM, group synchronization |
| **Security Administrator** | DLP, conditional access, information barriers, threat monitoring, incidents |
| **Compliance Administrator** | Retention, legal hold, records, evidence/export workflows |
| **Auditor** | Read-only access to security, configuration and audit histories |
| **AI/Automation Client** | MCP/API tools, under the same security and DLP boundaries as users |
| **Operator (SRE)** | Deployment, capacity, backup/DR, upgrades — see `11-OPERATIONS.md` |

## 5. Product hierarchy

```text
Platform
└── Tenant
    ├── Users / Groups / Guests / Service Accounts
    ├── Workspaces
    │   ├── Pages
    │   ├── Libraries
    │   │   ├── Folders
    │   │   └── Files
    │   ├── Lists
    │   ├── Views
    │   ├── Members
    │   └── Workflows
    ├── Search / AI / MCP
    ├── Security
    │   ├── DLP
    │   ├── Classification
    │   ├── Conditional Access
    │   ├── Information Barriers
    │   └── Incidents
    ├── Compliance
    │   ├── Retention
    │   ├── Records
    │   └── Legal Hold
    ├── Quotas & Usage
    └── Administration
```

## 6. Workspace requirements

Workspace visibility: `PRIVATE`, `MEMBERS_ONLY`, `TENANT_VISIBLE`, `RESTRICTED`.

A workspace provides Home, Files, Lists, Pages, Search, Activity, Favorites, Shared, Trash and
Settings.

## 7. Document libraries

A workspace may contain multiple libraries. Each library independently controls permissions,
metadata schema, classification defaults, versioning, retention, approval, checkout, allowed file
types, external sharing, AI indexing, MCP visibility, sync eligibility, views, and storage profile
where policy permits.

## 8. File model

Logical file and physical version are separate concepts.

```text
File
 ├── metadata
 ├── ACL
 ├── classification
 ├── retention
 ├── current_version_id
 └── versions
      ├── v1
      ├── v2
      └── v3
```

Existing versions are immutable.

## 9. Versions

Support major/minor versions, restore, comments, approval state, retention and compare
integrations. Version policy may inherit `Tenant -> Workspace -> Library -> Content Type`.

## 10. Multiple views

Required view types: list, compact list, details, grid, cards, gallery, tree, timeline, recent,
shared with me, favorites, personal custom view, shared custom view.

Views are stored query/presentation definitions, not copies of data.

## 11. Metadata and content types

Field types include text, number, boolean, date, datetime, user, group, choice, multi-choice, URL,
email, taxonomy, reference and JSON.

Content types allow reusable schemas such as Contract, Policy, Invoice, Engineering Specification
and Record.

## 12. Lists

Lists are structured collaborative datasets with schema, forms, views, filters, history, comments,
permissions, workflows and API access.

## 13. Pages

Pages use structured JSON blocks such as heading, rich text, image, links, file view, list, people,
activity, search and embedded app.

## 14. Collaboration

Support comments, mentions, activity, notifications, approvals, checkout, locks and external
document-editor sessions. Editor integration is designed in `10-SYNC-AND-EDITING.md §7`; only
server-rendered editors are permitted for content the caller may not download.

## 15. Identity

Authentication: local password, LDAP/Active Directory, OIDC, SAML, WebAuthn/passkeys, API token,
service accounts.

Provisioning: local, LDAP sync, SCIM, JIT provisioning.

Authentication and provisioning remain separate concerns.

## 16. Passwords and MFA

Local passwords use Argon2id. Defaults: minimum 12 characters, maximum 128, no mandatory arbitrary
periodic rotation, breach-password checks, login throttling/lockout, optional pepper from an
external secret manager, mandatory MFA for privileged administrators.

MFA supports TOTP, WebAuthn/passkeys and recovery codes.

## 17. Authorization

Principals: user, group, guest, service account, everyone.

Resource scopes: tenant, workspace, library, folder, file, page, list, list item.

Permissions must distinguish at least: metadata read, preview, content read, download, print,
export, edit, copy, move, share, external share, delete, restore, version read/restore, permission
management, audit read.

Inheritance follows `Workspace -> Library -> Folder -> File`, with explicit break-inheritance
support.

## 18. View without download

A user can hold `FILE_PREVIEW=ALLOW` with `FILE_DOWNLOAD=DENY`.

Sensitive previews are rendered and sanitized server-side. The platform must not claim that browser
display can prevent screenshots or physical capture.

## 19. Sharing

Modes: internal, specific person, external authenticated user, domain restricted, anyone-with-link
where tenant policy allows.

Share links may require password, OTP, MFA, expiry, max downloads, allowed domains, or
read-only/no-download. Raw share tokens and passwords are never stored.

## 20. Conditional access

Evaluate IP/CIDR, country/region, ASN, named network zone, trusted proxy chain, VPN/corporate
network, device posture, authentication strength, client type, and time/risk context.

Effects: allow, block, require MFA, require trusted network, require managed device, preview only,
no download.

Policies may be applied at tenant/workspace/library/resource scope.

## 21. DLP

Built-in and custom detectors covering PII, financial data, credentials, secrets, source-code
secrets, PAN/Aadhaar, passports, tax identifiers, bank data, healthcare data, custom
regex/dictionaries and ML classifiers.

Modes: disabled, monitor, simulation, warn, enforce.

Effects: allow, audit, warn, require justification, require approval, block, quarantine, remove
share, preview only, no download, watermark, reclassify, notify security.

Enforcement points include upload, preview, download, sharing, guest access, export, API, MCP,
move/copy, sync, editor session and bulk actions.

## 22. Classification

Default labels: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`, `RESTRICTED`.

Labels may be manual, inherited, automatically detected or workflow-assigned.

## 23. Information barriers

Mandatory separation beyond ordinary ACLs — e.g. Client A vs Client B, M&A vs General Staff,
Investment Banking vs Research.

## 24. Retention, legal hold and records

Retention actions: `KEEP`, `KEEP_THEN_DELETE`, `DELETE_AFTER`, `RECORD`, `LEGAL_HOLD`.

Legal hold blocks destructive deletion. Records may carry stricter modification/delete rules.

## 25. Workflows and document signing

Content processes are first-class: approval, review, publication and signing run as versioned,
auditable workflow definitions bound to an immutable file version.

Document signing must support click-through acknowledgement, electronic signatures, platform digital
signatures (PAdES), signer-held certificates (PKCS#11/DSC), and delegation to external e-signature
providers. Whatever the mode, a completed signing produces a signed artifact, signer identity
evidence, a tamper-evident binding and an audit trail that survives the vendor.

Full design: `15-WORKFLOWS-AND-SIGNING.md`.

## 26. Antivirus and content safety

Every ingested byte stream is scanned before it becomes available. Requirements:

- scanning is a provider interface (`AntivirusScanner`), not a hard dependency on one engine;
- a version is not `AVAILABLE` until scanning completes or the tenant's configured
  scan-unavailable policy explicitly allows degraded acceptance;
- infected content moves to `QUARANTINED` and raises a security incident;
- signature-update-triggered rescan of recent/at-risk content is scheduled, not manual;
- archives are scanned to a configured depth, with bounded expansion limits.

## 27. Search and Milvus

Milvus is the primary retrieval projection for lexical/BM25, dense vectors, sparse vectors, metadata
filters, hybrid search, multi-vector retrieval and permission-aware retrieval.

Authoritative state remains PostgreSQL + object storage.

## 28. Indexing pipeline

```text
File Version Created
 -> Malware Scan
 -> DLP Pre-Scan
 -> Text/Structure Extraction
 -> Semantic Chunking
 -> Metadata Enrichment
 -> Classification
 -> Embedding
 -> Milvus Index
```

Supported initial formats: PDF, DOCX, XLSX, PPTX, TXT, Markdown, HTML, CSV, JSON.

Chunk types: document, section, paragraph, table, row group, sheet range, slide, code block, list.

## 29. MCP

Expose a controlled MCP server for enterprise AI and automation.

Read tools: `search_files`, `semantic_search`, `get_file`, `get_file_metadata`, `get_file_outline`,
`get_file_text`, `list_workspace_files`, `query_list`.

Mutation tools: `create_folder`, `upload_file`, `update_metadata`, `move_file`, `share_file`,
`create_page`, `create_list_item`.

MCP never bypasses tenant isolation, ACL, barriers, DLP or audit.

## 30. Sync clients

Desktop and mobile clients synchronize selected libraries. Requirements:

- a file that the caller may not download is never synchronized to a device;
- sync is a first-class enforcement point, not a bypass;
- devices register, are individually revocable, and support remote wipe of the local cache;
- selective sync by library/folder, with server-declared eligibility;
- deterministic conflict handling that never silently discards user content.

Full design: `10-SYNC-AND-EDITING.md`.

## 31. Quotas and usage

Tenant administrators manage quotas for stored bytes, file count, per-file size, version depth,
seats, API rate and MCP consumption. Quota state is measurable, enforceable at write time and
visible in admin UX before it is breached. Model: `04-DATA-MODEL.md §16`.

## 32. BYO infrastructure

Tenant/enterprise deployments may supply object storage, Vault/secret manager, KMS/encryption keys,
SMTP, Milvus/vector store, embedding endpoint/model, antivirus engine, identity provider, and
PostgreSQL for self-hosted deployments.

The application depends on provider interfaces rather than provider-specific business logic.

## 33. White-labeling

Tenant branding: product name, logo/favicon, colors, login branding, custom domain, email branding,
terms/privacy/support links. Arbitrary CSS injection is not permitted by default.

## 34. Production UX

Keyboard navigation, multi-select, drag/drop, bulk actions, virtualization, skeleton/loading states,
clear empty/error states, optimistic UI where safe, accessible command bar, right-side details
panel, no unnecessary full reloads, WCAG 2.2 AA target, responsive desktop/tablet and functional
mobile.

## 35. Audit and monitoring

Capture authentication, preview, download, upload, edit, delete, restore, sharing, ACL changes, DLP
decisions, classification, retention, legal hold, sync, editor sessions, MCP access, AI retrieval
and admin configuration changes.

Security dashboard: sensitive content, blocked actions, external sharing, suspicious access,
quarantined files, guest activity, open incidents.

## 36. Reliability

Timeouts, retries/backoff, circuit breakers, idempotency, dead-letter handling, graceful shutdown,
health probes, OpenTelemetry, HA deployment options, backup/restore testing, DR procedures.

## 37. Delivery phases

### MVP
Tenanting, users/groups, local/OIDC/LDAP auth, workspaces, libraries, files/folders, S3-compatible
storage, versioning, ACL, multiple views, preview/download split, sharing, trash, metadata, Milvus
hybrid search, antivirus, audit, basic DLP, basic geo/IP controls, quotas, Docker deployment.

### Enterprise V1
SAML, SCIM, WebAuthn, workflows and document signing, advanced DLP, information barriers, legal hold, records, SIEM, custom
domain/white-labeling, BYO infra, Milvus HA, MCP, hybrid AI search, sync clients, external editor
integration, workflow, high availability.

### V1.1 and beyond
Offline sync merge, Azure Blob/GCS adapters, additional vector-store providers, maker/checker
workflows across all privileged surfaces, advanced eDiscovery export.

## 38. Acceptance criteria

Enterprise-ready means at minimum:

1. tenant boundaries cannot be bypassed, and are enforced at the database layer as well as the application layer;
2. ACL applies identically to REST, search, sync, editor sessions and MCP;
3. restricted files do not leak through vector retrieval, **including after a permission revocation** (`07-SEARCH-INDEXING.md §6`);
4. files have immutable versions;
5. preview and download are independently enforceable;
6. geo/IP conditional access is enforced server-side;
7. DLP can synchronously block sensitive actions;
8. DLP simulation exists;
9. all sensitive operations are audited, with a verifiable hash chain where enabled;
10. legal hold blocks deletion;
11. direct object-store access cannot bypass policy;
12. Milvus outage does not lose authoritative data;
13. indexes can be rebuilt from authoritative state, by a documented runbook (`11-OPERATIONS.md §5`);
14. customer-owned storage/Vault/SMTP/AV can be configured safely;
15. MCP cannot bypass DLP or classification ceilings;
16. privileged changes require stronger controls and audit;
17. UI handles large libraries through virtualization and pagination;
18. no-download content never reaches a sync client or a client-side editor;
19. infected content never becomes available to any read path;
20. quota exhaustion degrades predictably and is visible before it blocks work;
21. a signed document verifies independently of the signing provider, and post-signature
    modification is detectable.
