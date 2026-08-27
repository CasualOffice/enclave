# 03 — Low-Level Design

> **Status:** Draft · **Version:** 2.1 · **Owner:** Platform Engineering · **Last updated:** 2026-08-28
> **Authoritative for:** Rust types and traits, policy enforcement implementation, runtime rules.
> DDL lives in `04-DATA-MODEL.md`. Endpoint contracts live in `05-API.md`. The crate list lives in `02-HLD.md §4`.

## 1. Repository layout

```text
enclave/
├── Cargo.toml              workspace manifest
├── crates/                 see 02-HLD.md §4 for the canonical crate list
├── web/                    React + TypeScript SPA
├── migrations/             forward-only SQL migrations
├── deploy/                 Docker, Compose, Helm, Terraform examples
├── docs/                   this pack
└── tests/                  cross-crate integration and security suites
```

## 2. Strongly typed IDs

UUIDv7 wrapped in newtypes. No bare `Uuid` crosses a public API boundary.

```rust
pub struct TenantId(Uuid);
pub struct UserId(Uuid);
pub struct GroupId(Uuid);
pub struct WorkspaceId(Uuid);
pub struct LibraryId(Uuid);
pub struct FileId(Uuid);
pub struct VersionId(Uuid);
pub struct ChunkId(Uuid);
pub struct DeviceId(Uuid);
pub struct SessionId(Uuid);   // refresh-token family id, used for audit correlation
```

## 3. Request context

```rust
pub struct RequestContext {
    pub request_id: Uuid,
    pub tenant_id: TenantId,
    pub actor: Actor,
    pub session_id: Option<SessionId>,   // `sid` claim; correlation only, not a server lookup
    pub auth_strength: AuthStrength,
    pub auth_time: DateTime<Utc>,        // for step-up / max-age policies
    pub scopes: ScopeSet,
    pub client: ClientType,
    pub network: NetworkContext,
    pub device: DeviceContext,
}

pub enum ClientType { Web, Desktop, Mobile, Sync, Editor, Api, Mcp, System }
```

Tenant identity is derived from the verified access token or custom-domain routing — **never** from
a request body, query parameter or client-supplied header.

## 4. Actor

```rust
pub enum Actor {
    User(UserId),
    Guest(GuestId),
    ServiceAccount(ServiceAccountId),
    McpClient(McpClientId),
    System,
}
```

## 5. Authentication: JWT access tokens + rotating refresh tokens

### 5.1 Model

| Token | Form | Lifetime | Storage | Revocable |
|---|---|---|---|---|
| **Access token** | Signed JWT (EdDSA/Ed25519, `alg=EdDSA`) | 10 min default, 5 min for privileged scopes | Memory (SPA) / secure keystore (native) | Only via denylist or epoch bump |
| **Refresh token** | Opaque 256-bit random, SHA-256 hashed at rest | 14 days sliding, 90 day absolute | `HttpOnly; Secure; SameSite=Strict` cookie (web) or keystore (native) | Yes, immediately |

The API is stateless on the hot path: it verifies a signature and claims, with no database or Redis
round-trip for the common case. Revocation is handled by the three mechanisms in `§5.4`.

### 5.2 Access token claims

```json
{
  "iss": "https://workspace.example.com",
  "aud": "enclave-api",
  "sub": "01937f2c-...",
  "tid": "01937a10-...",
  "sid": "01937f30-...",
  "typ": "user",
  "scp": ["files:read", "files:write", "search"],
  "amr": ["pwd", "webauthn"],
  "auth_time": 1755500000,
  "acr": "mfa",
  "dev": "01937f44-...",
  "cli": "web",
  "epoch": 7,
  "jti": "01937f55-...",
  "iat": 1755500000,
  "exp": 1755500600
}
```

- `tid` — tenant. Mismatch with the routed custom domain is a hard `401`.
- `sid` — refresh-token family id; the audit correlation key that `session_id` used to carry.
- `epoch` — the user's `token_epoch` at issuance (see `§5.4`).
- `acr` / `amr` / `auth_time` — drive step-up MFA and max-age conditional-access policies.
- `dev` — bound device, required for `sync` and `editor` clients.

Claims are **assertions to be checked**, not permissions. Authorization always re-resolves the ACL;
`scp` can only narrow what a caller may attempt, never widen it.

### 5.3 Refresh rotation and reuse detection

```rust
#[async_trait]
pub trait TokenService: Send + Sync {
    async fn issue_pair(&self, ctx: &AuthContext) -> Result<TokenPair>;
    async fn refresh(&self, presented: &RefreshToken, ctx: &NetworkContext) -> Result<TokenPair>;
    async fn revoke_family(&self, sid: SessionId, reason: RevokeReason) -> Result<()>;
    async fn revoke_all_for_user(&self, user: UserId, reason: RevokeReason) -> Result<()>;
}
```

Rules:

1. Every successful refresh **rotates**: the presented token is consumed and a new one issued in the
   same family (`sid`).
2. Presenting an already-consumed refresh token is treated as theft: the entire family is revoked,
   every access token in it is denylisted, a `SESSION_REPLAY` incident is raised, and the user is
   notified.
3. Refresh requires the request to still satisfy conditional access. A user who moves outside an
   allowed network zone loses access within one access-token lifetime, not at token expiry.
4. Refresh tokens are bound to `sid` + device; a refresh presented with a different `dev` is rejected.
5. Web clients receive the refresh token only as an `HttpOnly` cookie scoped to `/api/v1/auth`.
   CSRF protection is double-submit + `SameSite=Strict` on the refresh endpoint.

### 5.4 Revocation

Because a JWT is valid until it expires, revocation uses three layers:

| Mechanism | Latency | Use |
|---|---|---|
| **Short TTL** | ≤ 10 min | Baseline for all ordinary changes |
| **`jti` denylist** (Redis, TTL = remaining token life) | Immediate | Explicit logout, family revoke, theft detection |
| **`token_epoch` bump** (PostgreSQL, per user; cached) | Immediate | Password change, MFA reset, disable/offboard, mass revoke, role removal |

The API checks the denylist and epoch **only** when a cheap precondition says it must: the tenant
has a non-empty denylist generation, or the user's cached epoch differs. Epoch and denylist
generation are cached in-process with a short TTL and invalidated by the `identity.revoked` event.

If Redis is unavailable, the denylist check fails **closed** for privileged scopes
(`admin:*`, `security:*`, `share:external`) and fails open with an audit record for ordinary reads —
bounded by the 10-minute access-token TTL.

### 5.5 Signing keys

Ed25519 keypairs held by the configured `KeyProvider`. Public keys are published at
`GET /.well-known/jwks.json` with a `kid` per key. Rotation is overlapping: a new key is published
and used for signing after a propagation delay, the old key stays verifiable for one full access +
refresh lifetime, then is retired. Rotation procedure: `11-OPERATIONS.md §7`.

### 5.6 Service accounts and MCP clients

Machine callers use OAuth2 client credentials to obtain the same access-token format with
`typ: "service"` or `typ: "mcp"`, a fixed scope set and, for MCP, a classification ceiling claim
(`max_cls`). They receive no refresh token; they re-authenticate. Share-link recipients receive a
narrowly scoped token bound to one resource and one permission.

## 6. Access actions

```rust
pub enum FileAction {
    MetadataRead,
    Preview,
    ContentRead,
    Download,
    Print,
    Export,
    Edit,
    Copy,
    Move,
    Share,
    ShareExternal,
    Delete,
    Restore,
    VersionRead,
    VersionRestore,
    ManagePermissions,
    Sync,
}
```

There is deliberately no generic `read`. `Sync` is a distinct action so that a policy can allow
`Preview` and `Download` in a browser while denying replication to a device.

## 7. Authorization interface

```rust
#[async_trait]
pub trait AuthorizationService: Send + Sync {
    async fn authorize(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<AuthzDecision>;

    /// Batch form used by search post-filtering and bulk operations.
    async fn authorize_many(
        &self,
        ctx: &RequestContext,
        action: Action,
        resources: &[ResourceRef],
    ) -> Result<Vec<AuthzDecision>>;
}
```

`authorize_many` is mandatory for the search post-filter path in `07-SEARCH-INDEXING.md §6.2`; a
per-hit loop is not an acceptable implementation.

## 8. Conditional-access interface

```rust
#[async_trait]
pub trait ConditionalAccessService: Send + Sync {
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: SecurityAction,
        resource: &ResourceRef,
    ) -> Result<ConditionalDecision>;
}

pub enum ConditionalEffect {
    Allow,
    Block,
    RequireMfa,
    RequireManagedDevice,
    RequireTrustedNetwork,
    PreviewOnly,
    NoDownload,
    NoSync,
}
```

`RequireMfa` returns a step-up challenge referencing `auth_time`/`acr`, not a bare denial.

## 9. Information barriers and classification

```rust
#[async_trait]
pub trait BarrierService: Send + Sync {
    async fn evaluate(&self, ctx: &RequestContext, resource: &ResourceRef) -> Result<BarrierDecision>;
    async fn allowed_barrier_tokens(&self, ctx: &RequestContext) -> Result<Vec<String>>;
}

#[async_trait]
pub trait ClassificationService: Send + Sync {
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<ClassificationDecision>;
    async fn ceiling(&self, ctx: &RequestContext) -> Result<ClassificationRank>;
}
```

The classification step enforces per-client ceilings — most importantly MCP client ceilings and
export/print restrictions on `HIGHLY_CONFIDENTIAL` and above.

## 10. DLP interface

```rust
#[async_trait]
pub trait DlpService: Send + Sync {
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        request: DlpEvaluationRequest,
    ) -> Result<DlpDecision>;
}
```

`DlpDecision` carries an effect, a matched-policy id, a severity, and an optional obligation
(`RequireJustification`, `RequireApproval`, `Watermark`, `Reclassify`) that the caller must satisfy
or apply before the operation completes.

## 11. Retention interface

```rust
#[async_trait]
pub trait RetentionService: Send + Sync {
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<RetentionDecision>;
}
```

## 12. Unified policy enforcement

One function. Every entry point calls it; nothing else evaluates policy piecemeal.

It lives in `enclave-core::engine`. The engine is pure composition over six trait objects, so it
needs no concrete policy implementation and introduces no dependency on the crates that provide
them; putting it in `core` means `api`, `worker`, `scheduler` and `mcp` reach the same code rather
than each growing a variant. The six service traits are defined alongside it, and each security
crate implements the trait for its own stage.

Auditing is the exception. `audit` depends on `core`, so `core` cannot depend back — the engine
calls a narrow `PolicyAuditSink` port defined in `core` and implemented in `audit`, which keeps the
dependency pointing inward.

```rust
pub struct PolicyEngine {
    conditional_access: Arc<dyn ConditionalAccessService>,
    authorization:      Arc<dyn AuthorizationService>,
    barriers:           Arc<dyn BarrierService>,
    classification:     Arc<dyn ClassificationService>,
    dlp:                Arc<dyn DlpService>,
    retention:          Arc<dyn RetentionService>,
    audit:              Arc<dyn AuditSink>,
}

impl PolicyEngine {
    /// Canonical chain — 02-HLD.md §14. Tenant isolation and authentication are
    /// established before this point, by middleware, and asserted here.
    pub async fn enforce(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
    ) -> Result<PolicyDecision> {
        debug_assert_eq!(ctx.tenant_id, resource.tenant_id);
        if ctx.tenant_id != resource.tenant_id {
            self.audit.deny(ctx, action, resource, DenyReason::TenantMismatch).await?;
            return Err(Error::NotFound); // never confirm existence across tenants
        }

        let mut obligations = Obligations::default();

        obligations.merge(
            self.conditional_access.evaluate(ctx, action.into(), resource).await?
                .into_obligations()?);

        self.authorization.authorize(ctx, action, resource).await?
            .ensure_allowed()?;

        self.barriers.evaluate(ctx, resource).await?
            .ensure_allowed()?;

        obligations.merge(
            self.classification.evaluate(ctx, action, resource).await?
                .into_obligations()?);

        obligations.merge(
            self.dlp.evaluate(ctx, DlpEvaluationRequest::build(ctx, action, resource)).await?
                .into_obligations()?);

        self.retention.evaluate(ctx, action, resource).await?
            .ensure_allowed()?;

        let decision = PolicyDecision::allow(obligations);
        self.audit.record(ctx, action, resource, &decision).await?;
        Ok(decision)
    }
}
```

Rules that make this safe:

1. **Order is fixed.** Conditional access before authorization, so a blocked network never reveals
   whether a resource exists.
2. **Denials are indistinguishable from absence** across tenants and barriers: both return `404`.
   Within a tenant, an ACL denial returns `403` with a remediation code (`06-SECURITY-DLP-ACCESS.md §24`).
3. **Obligations are returned, not silently applied.** The caller must satisfy each one
   (`Watermark`, `RequireJustification`, `RequireApproval`) or fail; an unhandled obligation is a
   compile-time-checked `#[must_use]` error.
4. **Audit is inside the engine**, so no path can succeed unaudited. Denials are audited too.

## 13. Idempotency

Mutating endpoints accept `Idempotency-Key`. The key, actor, endpoint, request-hash and serialized
response are stored for 24 hours (`04-DATA-MODEL.md §17`). A replay with a matching hash returns the
stored response; a mismatching hash on the same key returns `409`.

## 14. Concurrency

Mutable metadata carries `revision`. Reads return `ETag: "{revision}"`; writes require `If-Match`.
Stale writes return `409 CONFLICT` with the current revision. ACL writes additionally bump
`acl_revision`, which drives cache keys and index invalidation.

## 15. Upload state machine

```text
CREATED -> UPLOADING -> UPLOADED -> SCANNING -> PROCESSING -> AVAILABLE
```

Failure states: `QUARANTINED`, `FAILED`, `ABORTED`, `EXPIRED`.

Blob storage cannot join a SQL transaction, so bytes are staged under an upload-scoped key and
promoted on commit. Orphaned staged objects are reaped after `upload.session_ttl` (default 24h) by
**`enclave-worker`'s `upload-reaper` pass**, which also reclaims sessions stranded in `SCANNING`
with no version behind them.

That sentence used to say "by the scheduler", and it was untrue of everything that shipped:
`enclave_uploads::reap_expired` existed from M1 with no caller in any binary, so no deployment ever
released a staged object (`ENC-806`). It names a process now because a document naming a role
nobody implemented is how that survived five milestones. The reaper is in the worker rather than in
`enclave-scheduler` because it needs a verified object store, a tenant enumerator, per-tenant
failure isolation and a way to be *visibly* unscheduled when no bucket is configured — see
`crates/worker/src/uploads.rs` for the argument.

Atomic version commit:

```text
BEGIN
  INSERT file_versions
  UPDATE files.current_version_id, revision = revision + 1
  UPDATE quota_usage (bytes, file_count)
  INSERT events_outbox('file.version.created')
  INSERT audit_events
COMMIT
```

A version is only visible to read paths once its `status = AVAILABLE`; `SCANNING` and `PROCESSING`
versions are visible to their uploader with an explicit state, and to nobody else.

## 16. Caching

Cache metadata, effective permissions, classification and compiled policies with bounded TTL and
revision-based invalidation.

```text
authz:{tenant}:{actor}:{resource}:{acl_revision}          TTL 60s
policy:{tenant}:{policy_kind}:{policy_generation}         TTL 300s
epoch:{tenant}:{user}                                     TTL 30s
facts:{tenant}:{version}:{scan_version}                   TTL 300s
```

Every key embeds the revision or generation it was computed from, so invalidation is a bump, never
a scan-and-delete.

## 17. Pagination

Cursor pagination everywhere. Cursors are opaque, signed, and encode
`(sort_key, tie_break_id, filter_hash, tenant_id)`. A cursor presented with different filters or by
a different tenant is rejected. Deep `OFFSET` is prohibited in the query layer.

## 18. Deletion

User delete is a soft delete (`deleted_at`). Permanent deletion checks, in order: trash expiry,
retention schedule, legal hold, record status. Any one of them blocking means the object is not
destroyed and the attempt is audited.

Purge cascades to derived state: renditions, extracted text, chunks in Milvus, sync tombstones.

## 19. Health

- `GET /health/live` — process is up.
- `GET /health/ready` — PostgreSQL reachable, migrations current, object storage reachable.

Milvus, embedding provider, SMTP and antivirus degradation are reported in
`GET /health/dependencies` but do **not** make the service unready; file APIs must keep serving.

## 20. Observability

Span attributes: `tenant.id`, `request.id`, `actor.type`, `workspace.id`, `operation`,
`policy.decision`, `policy.reason_code`, `client.type`. Never record raw passwords, tokens,
refresh cookies or sensitive file content. Token `jti` may be logged; the token itself may not.

## 21. Configuration

Precedence: `defaults -> config file -> environment -> secret provider`. Security-changing
configuration is versioned and audited (`04-DATA-MODEL.md §18`).

## 22. Error model

Implementation of the wire format in `05-API.md §5`. Internally:

```rust
pub enum Error {
    NotFound,
    Conflict { current_revision: i64 },
    PolicyDenied { code: ReasonCode, remediation: Remediation },
    QuotaExceeded { quota: QuotaKind, limit: i64 },
    Validation(Vec<FieldError>),
    Upstream { dependency: Dependency, retryable: bool },
    Internal(anyhow::Error),
}
```

`PolicyDenied` never carries internal policy details to the client — it carries a stable reason code
and a user-safe remediation string.

## 23. Performance targets

- metadata API P95 < 300 ms;
- search P95 < 500 ms at expected load;
- cached policy/DLP decision P95 < 100 ms;
- access-token verification P99 < 2 ms (no I/O in the common path);
- 100k+ logical entries per folder/list via cursor pagination and virtualization;
- resumable multi-GB upload without buffering a whole file in API memory.
