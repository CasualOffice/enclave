# 15 — Glossary

> **Status:** Draft · **Version:** 1.0 · **Owner:** Platform Engineering · **Last updated:** 2026-08-18
> **Authoritative for:** shared vocabulary. Where a term has a precise definition, this is it.

**ACL entry** — A single grant or denial of one action to one principal on one resource
(`04-DATA-MODEL.md §9`). Deny wins over allow at every level.

**`acl_epoch`** — The value of `files.acl_revision` at the moment a chunk's index metadata was
written. If it lags the current revision, the index is known-stale for that file
(`07-SEARCH-INDEXING.md §6.3`).

**`acl_revision`** — A counter on a file, bumped on any permission change. Drives cache keys and
index invalidation.

**Access token** — A short-lived signed JWT (default 10 minutes) proving identity and scope. Verified
without a database lookup (`03-LLD.md §5`).

**Actor** — Who is performing an operation: user, guest, service account, MCP client, or system.

**Authoritative store** — PostgreSQL and object storage. Everything else is rebuildable.

**Barrier token** — An opaque segment identifier attached to principals and content to implement
information barriers. Evaluated at query time, not only at result time.

**Break-glass account** — An offline-stored administrative account exempt from network policy but not
from MFA or audit, used only during an incident (`11-OPERATIONS.md §5.6`).

**Chunk** — A bounded, structure-aware slice of a document's text, the unit of vector indexing and
RAG citation. 400–800 tokens with ~15% overlap.

**Classification** — A sensitivity label (`PUBLIC` … `RESTRICTED`) with a numeric `rank` used for
filtering and ceilings. Applied manually, by inheritance, by detection or by workflow.

**Classification ceiling** — The highest classification a given client (typically an MCP client) may
receive, regardless of the acting user's own access.

**Conditional access** — Policy evaluated on network, device, auth strength and context, before
authorization, so a blocked network never reveals whether a resource exists.

**Content type** — A reusable metadata schema (Contract, Policy, Invoice) that can carry default
classification and retention.

**Cursor** — An opaque, signed pagination token encoding sort key, tie-break, filter hash and tenant.
Not portable across filters or tenants.

**Delta** — The ordered, resumable change feed a sync client consumes (`10-SYNC-AND-EDITING.md §4`).

**Denylist (retrieval)** — A per-tenant set of file IDs excluded from vector search until their index
metadata catches up with a permission change (`07-SEARCH-INDEXING.md §6.4`).

**Derived store** — Redis, Milvus, renditions, extracted text, sync caches. Rebuildable; never the
sole authority for a permission decision.

**Detector** — A DLP matcher (regex, dictionary, checksum, proximity rule or ML classifier) with a
confidence and a minimum match count.

**DLP mode** — `DISABLED`, `MONITOR`, `SIMULATION`, `WARN`, `ENFORCE`. Simulation is mandatory before
enforcing a blocking policy.

**Effective permission** — The result of resolving inheritance, group closure and deny-wins for one
principal, action and resource.

**Enforcement point** — A surface where policy is evaluated: upload, preview, download, share, export,
print, API, MCP, sync, editor session, move/copy, webhook, bulk action.

**Envelope encryption** — A per-version data key encrypting the object, itself wrapped by a
customer-held key. Revoking the customer key makes content unreadable, including to the operator.

**Epoch (`token_epoch`)** — A per-user counter; bumping it invalidates every outstanding access token
for that user immediately.

**Expand → contract** — The two-release migration discipline that keeps rollback safe: add
compatible structures in one release, remove the old ones in a later one.

**Fail closed / fail open** — Behavior when a control's inputs are unavailable. The platform fails
closed for privileged scopes, restricted classifications and external sharing.

**Family (token family)** — All refresh tokens descended from one login, sharing a `sid`. What a user
sees as "a session". Revoked as a unit.

**Hybrid search** — Fusion of dense-vector and sparse/BM25 retrieval, then reranking.

**Idempotency key** — A client-supplied UUID making a create-or-transfer request safely retryable for
24 hours.

**Index manifest** — The per-version record of indexing state, versions and `acl_epoch`
(`04-DATA-MODEL.md §15`).

**Information barrier** — Mandatory segmentation that overrides ACLs, preventing cross-segment
discovery, search, sharing and AI retrieval.

**JIT provisioning** — Creating a user on first successful federated authentication.

**Legal hold** — A compliance state blocking destructive deletion regardless of retention or user
action, releasable only by a privileged, audited operation.

**Library** — A container within a workspace with its own permissions, metadata schema, versioning,
retention, sharing and sync settings.

**Logical property (CSS)** — Direction-agnostic layout property (`margin-inline-start`) required for
RTL support.

**MCP** — Model Context Protocol. The gateway exposing permission-aware tools to AI clients, which
calls the same domain services as the HTTP API and bypasses nothing.

**Obligation** — A requirement returned by the policy engine that the caller must satisfy before an
operation completes: watermark, justification, approval, read-only. Never silently dropped.

**Outbox** — The `events_outbox` table written in the same transaction as a state change, then
published to NATS. Guarantees no event is lost if the broker is down.

**Over-fetch** — Requesting more vector-search candidates than needed (default 3×) so the
authoritative post-filter can drop unauthorized hits without shortening the page.

**Pepper** — An application-wide secret mixed into password hashing, stored in the secret provider
rather than the database.

**Policy chain** — The canonical ordered sequence every operation passes through (`README.md §3`).

**Post-filter** — The mandatory authoritative permission recheck applied to every search candidate.
The guarantee that makes index staleness a performance problem rather than a security one.

**Principal** — Anything a permission can be granted to: user, group, guest, service account, or
everyone.

**Record** — A declared item with stricter modification and deletion rules than ordinary content.

**Refresh token** — An opaque, rotating, hashed-at-rest credential used to obtain new access tokens.
Reuse is treated as theft.

**Rendition** — A derived, safe representation of a document for preview: page images or sanitized
HTML. Base renditions are identity-free and cached; watermarks are composed per request.

**Residency** — The requirement that content and its derivatives stay in specified regions, applying
to storage, database, index, backups, embeddings, LLM endpoints, renditions and logs.

**RLS (Row-Level Security)** — PostgreSQL policies enforcing `tenant_id` isolation independently of
application code (`04-DATA-MODEL.md §3`).

**Scope set** — The permissions a token may attempt to exercise. Narrows what authorization will
consider; never widens it.

**Security facts** — Precomputed detector results for a version, letting synchronous DLP decisions
avoid rescanning content on every request.

**`sid`** — The refresh-token family identifier carried in the access token, used to correlate audit
events to a session without a server-side session store.

**Simulation** — Evaluating a policy against samples or history to see what it would have done,
without side effects.

**Soft delete** — Setting `deleted_at`, moving an item to trash. Distinct from purge, which destroys
bytes and derived state after retention, hold and record checks pass.

**Step-up** — Requiring a fresher or stronger authentication for a sensitive action, expressed
through `acr` and `auth_time` rather than a separate flag.

**Sync eligibility** — The six-condition test determining whether a file may be replicated to a
device (`10-SYNC-AND-EDITING.md §5`).

**Tenant** — The top-level isolation boundary. Every tenant-scoped row carries `tenant_id`; every
tenant-scoped table enforces it twice.

**Tombstone** — A delta entry telling a sync client to remove a local file, always with a reason, so
the client can distinguish deletion from lost access.

**Trusted proxy** — A network peer whose forwarded client-IP headers are honored, to a configured hop
depth. Everything else is ignored.

**View** — A stored query and presentation definition (filters, sort, columns, grouping). Never a
copy of data.

**Workspace** — A collaboration boundary containing libraries, lists, pages, members and workflows.
