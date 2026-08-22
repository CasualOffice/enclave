# 05 — API Surface

> **Status:** Draft · **Version:** 1.3 · **Owner:** Platform Engineering · **Last updated:** 2026-08-22
> **Authoritative for:** REST contracts, error model, pagination, idempotency, versioning, rate limits.

## 1. Principles

- Base path `/api/v1`. A machine-readable OpenAPI 3.1 document is generated from the Axum routes and
  served at `/api/v1/openapi.json`; it is a build artifact, not a hand-maintained file.
- JSON request and response bodies, `camelCase` field names, UTF-8.
- Every response carries `X-Request-Id`. Clients echo it in bug reports; it joins logs, traces and
  audit rows.
- Resource identifiers are opaque UUIDs. Clients never construct object-storage paths.
- Mutations that change security posture return the new `revision` so clients can chain `If-Match`.
- No endpoint returns data that the policy chain (`02-HLD.md §14`) has not cleared.

## 2. Versioning and compatibility

`v1` is stable once released. Within `v1`: fields may be added, enum members may be added, and
optional request fields may be introduced. Removing a field, tightening validation, or changing a
default is a `v2` change. Clients must ignore unknown fields.

Deprecations carry `Deprecation` and `Sunset` response headers for at least two minor releases.

## 3. Authentication

All authenticated requests carry:

```http
Authorization: Bearer <access-token>
```

Access tokens are JWTs as specified in `03-LLD.md §5`. Refresh tokens are opaque and, for browser
clients, live only in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/auth/login` | Password (+ MFA) login; returns an access token and sets the refresh cookie |
| `POST` | `/auth/mfa/verify` | Completes a `MFA_REQUIRED` challenge |
| `POST` | `/auth/refresh` | Rotates the refresh token, returns a new access token |
| `POST` | `/auth/logout` | Revokes the current refresh family and denylists the presented `jti` |
| `POST` | `/auth/logout-all` | Bumps `token_epoch`; kills every session for the user |
| `GET` | `/auth/sessions` | Lists active refresh families with device, IP and last-use |
| `DELETE` | `/auth/sessions/{sid}` | Revokes one family |
| `GET` | `/auth/oidc/{provider}/start` · `/callback` | OIDC authorization code + PKCE |
| `POST` | `/auth/saml/{provider}/acs` | SAML assertion consumer |
| `POST` | `/auth/webauthn/register/start` · `/finish` | Passkey registration |
| `POST` | `/auth/webauthn/login/start` · `/finish` | Passkey authentication |
| `POST` | `/auth/token` | OAuth2 client credentials for service accounts and MCP clients |
| `GET` | `/.well-known/jwks.json` | Public signing keys (unauthenticated) |

### 3.1 Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{ "email": "amara@example.com", "password": "…", "deviceId": "01937f44-…" }
```

`200 OK`

```json
{
  "accessToken": "eyJhbGciOiJFZERTQSIsImtpZCI6Im…",
  "tokenType": "Bearer",
  "expiresIn": 600,
  "sessionId": "01937f30-…",
  "user": { "id": "01937f2c-…", "displayName": "Amara Osei", "isAdmin": false }
}
```

`401` with `{"error":{"code":"MFA_REQUIRED","challengeId":"…","methods":["TOTP","WEBAUTHN"]}}` when a
second factor is outstanding. The challenge is single-use and expires in 5 minutes.

### 3.2 Refresh

```http
POST /api/v1/auth/refresh
Cookie: enclave_rt=…
X-CSRF-Token: …
```

Returns the same shape as login. The response sets a **new** refresh cookie; the presented token is
consumed. Reuse of a consumed token revokes the whole family and returns `401 SESSION_REPLAY`
(`03-LLD.md §5.3`).

Refresh re-evaluates conditional access. A client that has moved to a blocked network receives
`403 NETWORK_NOT_ALLOWED` and must re-authenticate from a permitted location.

### 3.3 Step-up

Any endpoint may respond `403` with `{"error":{"code":"STEP_UP_REQUIRED","acr":"mfa","maxAge":300}}`.
The client completes `/auth/mfa/verify`, receives a token with a fresh `auth_time`, and retries.

## 4. Common request conventions

| Header | Applies to | Meaning |
|---|---|---|
| `If-Match: "{revision}"` | All mutations of versioned resources | Optimistic concurrency; `409` on mismatch |
| `Idempotency-Key: {uuid}` | `POST` that creates or transfers | 24-hour replay protection (`03-LLD.md §13`) |
| `X-Justification: {text}` | Actions carrying a `RequireJustification` obligation | Recorded in audit and the incident |
| `Prefer: return=minimal` | Any mutation | Returns `204` instead of the entity |

## 5. Error model

Every error uses one envelope:

```json
{
  "error": {
    "code": "DOWNLOAD_BLOCKED_BY_POLICY",
    "message": "Downloading this file is restricted outside the corporate network.",
    "remediation": "Connect to the corporate VPN, or request an exception from your security administrator.",
    "requestId": "01937f60-…",
    "details": []
  }
}
```

Rules:

- `code` is stable and machine-readable; `message` and `remediation` are user-safe and localizable.
- Policy denials never disclose which policy matched, its conditions, or whether other users have
  access. Internal reasoning goes to audit, not to the client.
- Validation errors populate `details` with `{ "field": "name", "code": "TOO_LONG" }` entries. An
  endpoint whose refusal carries a diagnosis the caller cannot otherwise reconstruct may add a
  `detail` sentence to an entry — see `§14.1`, which is the only one that does today, and which
  states the bound on what such a sentence may contain.

| HTTP | Use |
|---|---|
| `400` | Malformed request or failed validation |
| `401` | Missing, expired or invalid token; MFA challenge outstanding |
| `403` | Authenticated but denied by policy — ACL, conditional access, DLP, classification, retention |
| `404` | Not found **or** cross-tenant / barrier-blocked (deliberately indistinguishable) |
| `409` | Revision conflict, name collision, idempotency-key mismatch, lock held |
| `413` | Body or file exceeds the configured limit |
| `422` | Well-formed but semantically rejected (e.g. circular folder move) |
| `429` | Rate limit or quota-rate exceeded; `Retry-After` present |
| `451` | Blocked for legal/residency reasons |
| `503` | Dependency degraded; `Retry-After` present when retry is sensible |

Representative policy codes: `ACCESS_DENIED`, `DOWNLOAD_BLOCKED_BY_POLICY`,
`EXTERNAL_SHARE_BLOCKED`, `PREVIEW_ONLY`, `NETWORK_NOT_ALLOWED`, `DEVICE_NOT_MANAGED`,
`STEP_UP_REQUIRED`, `DLP_BLOCKED`, `DLP_JUSTIFICATION_REQUIRED`, `DLP_APPROVAL_REQUIRED`,
`CLASSIFICATION_CEILING`, `LEGAL_HOLD_ACTIVE`, `RETENTION_BLOCKS_DELETE`, `RECORD_IMMUTABLE`,
`QUOTA_EXCEEDED`, `SYNC_NOT_PERMITTED`, `MALWARE_DETECTED`, `SESSION_REPLAY`.

## 6. Pagination

Cursor-based, everywhere:

```http
GET /api/v1/libraries/{id}/items?limit=100&cursor=eyJrIjoi…
```

```json
{
  "items": [ … ],
  "page": { "nextCursor": "eyJrIjoi…", "hasMore": true, "limit": 100 }
}
```

`limit` defaults to 50, maximum 500. Cursors are opaque, signed and bound to the filter set and
tenant (`03-LLD.md §17`). Total counts are **not** returned by default: counting a filtered,
ACL-trimmed set is expensive and leaks information about inaccessible items. `?includeApproximateCount=true`
returns a lower-bounded estimate over accessible rows only.

## 7. Files and folders

| Method | Path | Notes |
|---|---|---|
| `GET` | `/libraries/{libraryId}/items` | Browse; `parentId`, `viewId`, filter, sort params |
| `POST` | `/libraries/{libraryId}/folders` | Create folder |
| `GET` | `/files/{id}` | Metadata + effective permissions for the caller |
| `PATCH` | `/files/{id}` | Rename, reparent, change content type; `If-Match` required |
| `DELETE` | `/files/{id}` | Soft delete to trash |
| `POST` | `/files/{id}/restore` | Restore from trash |
| `POST` | `/files/{id}/copy` · `/move` | Bulk-capable; DLP evaluated per destination |
| `GET` | `/files/{id}/versions` | Version history |
| `GET` | `/files/{id}/versions/{versionId}` | Version metadata |
| `POST` | `/files/{id}/versions/{versionId}/restore` | Creates a new version from an old one |
| `GET` | `/files/{id}/permissions` | Effective + explicit ACL |
| `PUT` | `/files/{id}/permissions` | Replace ACL; bumps `aclRevision` |
| `POST` | `/files/{id}/permissions/break-inheritance` | Materializes inherited entries |
| `GET` | `/files/{id}/activity` | Audit-derived activity feed |
| `POST` | `/files/{id}/checkout` · `/checkin` | Explicit lock lifecycle |

`GET /files/{id}` includes what the caller may do, so the UI never renders an action that the server
will reject:

```json
{
  "id": "01937fa0-…",
  "name": "FY26 Board Pack.pdf",
  "mimeType": "application/pdf",
  "sizeBytes": 4210332,
  "classification": { "key": "CONFIDENTIAL", "label": "Confidential", "rank": 30 },
  "currentVersion": { "id": "01937fa1-…", "major": 3, "minor": 0, "status": "AVAILABLE" },
  "revision": 12,
  "aclRevision": 4,
  "capabilities": {
    "preview": true, "download": false, "print": false, "export": false,
    "edit": true, "share": true, "shareExternal": false, "delete": false, "sync": false
  },
  "obligations": { "watermark": true, "justificationRequired": ["download"] },
  "governance": { "onLegalHold": true, "isRecord": false, "retentionPolicy": "Board Records 7y" }
}
```

`capabilities` is computed by the same policy engine that will enforce the action — it is a UI hint
derived from the real decision, not a parallel implementation.

## 8. Upload

```text
POST   /api/v1/uploads                       → { uploadId, method, urls|uploadUrl, partSize }
PUT    <signed part URLs>                    → direct to object storage
POST   /api/v1/uploads/{id}/complete         → { fileId, versionId, state }
GET    /api/v1/uploads/{id}                  → progress and state
DELETE /api/v1/uploads/{id}                  → abort and release staged bytes
```

- The API never proxies file bytes for large uploads; it issues scoped, short-lived signed URLs.
- `POST /uploads` runs the full policy chain **before** issuing URLs, including quota and
  file-type checks, so a rejected upload never consumes bandwidth.
- `complete` verifies size and SHA-256 against what was declared, then drives the state machine in
  `03-LLD.md §15`.
- The response after `complete` is `202` with `state: "SCANNING"`. Clients poll or subscribe; a file
  is not presented as ready before antivirus and required processing finish.

## 9. Preview, download, export

```text
GET  /api/v1/files/{id}/preview?page=1&profile=page-png-2x
GET  /api/v1/files/{id}/thumbnail?size=256
POST /api/v1/files/{id}/download
POST /api/v1/files/{id}/export        { "format": "pdf" }
POST /api/v1/files/{id}/print-token
```

`POST /files/{id}/download`:

```json
{ "justification": "Client audit request #4412", "versionId": null }
```

`200 OK`

```json
{ "url": "https://s3…/…?X-Amz-Expires=120", "expiresIn": 120, "singleUse": true }
```

Download is a `POST` because it has side effects: it consumes a share-link download budget, records
an audit event, and may require a justification. Signed URLs are short-lived (default 120 s) and
single-use where the storage provider supports it.

Preview responses set `Cache-Control: private, no-store` and carry
`Content-Security-Policy: sandbox` for HTML renditions. Watermarked page images are generated per
request and never cached (`06-SECURITY-DLP-ACCESS.md §5`).

## 10. Sharing

| Method | Path | Notes |
|---|---|---|
| `POST` | `/files/{id}/shares` | Create a share link; DLP-evaluated |
| `GET` | `/files/{id}/shares` | List links for a resource |
| `PATCH` | `/shares/{id}` | Change expiry, permission, download budget |
| `DELETE` | `/shares/{id}` | Revoke |
| `POST` | `/shares/{token}/authenticate` | Password / OTP / MFA for a link recipient |
| `GET` | `/shares/{token}` | Resolve a link to a scoped, resource-bound access token |

The raw token appears exactly once, in the creation response. Only its SHA-256 hash is stored.

## 11. Search

```http
POST /api/v1/search
```

```json
{
  "query": "deployment architecture",
  "mode": "hybrid",
  "workspaceIds": [],
  "libraryIds": [],
  "types": ["pdf", "docx"],
  "classificationMax": "CONFIDENTIAL",
  "modifiedAfter": "2026-01-01T00:00:00Z",
  "limit": 20,
  "cursor": null
}
```

```json
{
  "results": [
    {
      "fileId": "01937fa0-…",
      "versionId": "01937fa1-…",
      "title": "Platform Deployment Architecture",
      "path": "Engineering / Architecture / Platform",
      "workspace": "Engineering",
      "mimeType": "application/pdf",
      "classification": "INTERNAL",
      "score": 0.834,
      "excerpt": "…multi-AZ deployment with <em>Milvus</em> replicas…",
      "location": { "page": 12, "sectionPath": "3.2 Topology" },
      "capabilities": { "preview": true, "download": true }
    }
  ],
  "page": { "nextCursor": null, "hasMore": false },
  "diagnostics": { "mode": "hybrid", "degraded": false }
}
```

- `excerpt` is returned only when the caller holds `ContentRead`; metadata-only callers get title and
  path.
- `excerpt` is bounded at **240 characters** plus its elision marks, and that bound does not vary
  with `diagnostics.mode` or `diagnostics.degraded` — a client sizing a page may assume it.
  `07-SEARCH-INDEXING.md §6.2.1` defines what an excerpt is and which window each mode quotes.
- The `<em>` above is applied **here**, at the API layer, from offsets retrieval carries alongside
  the text. Retrieval never emits markup: it is the layer furthest from a renderer, and interpolating
  document content into a markup string there is how stored XSS is delivered. Only lexical hits carry
  offsets — a dense hit matched a whole chunk and nothing in it matched *at a position* — so an
  excerpt from a dense hit arrives **unmarked**, and a client must not read the absence of `<em>` as
  a failure. Everything outside the `<em>` tags is the document's own text.
- An excerpt is a **fragment** of a document, so it may contain a bidirectional control the document
  balances and the quotation does not. Renderers isolate it (`14-I18N-L10N.md §7`); the characters
  are never stripped, because an excerpt is a verbatim quotation and a caller shown one must be able
  to find it in the file.
- `diagnostics.degraded` is `true` when the vector store is unavailable and the query fell back to
  lexical-only, so the UI can say so honestly rather than silently returning fewer results.
- Related: `POST /search/suggest`, `POST /search/answer` (RAG; always returns cited chunk sources).

## 12. Lists, pages, views, metadata

```text
GET|POST         /workspaces/{id}/lists
GET|PATCH|DELETE /lists/{id}
GET|POST         /lists/{id}/items
GET|PATCH|DELETE /lists/{id}/items/{itemId}
GET|POST         /workspaces/{id}/pages
GET|PATCH|DELETE /pages/{id}
POST             /pages/{id}/publish
GET|POST         /libraries/{id}/views
GET|PATCH|DELETE /views/{id}
GET|PUT          /files/{id}/metadata
GET|POST         /libraries/{id}/fields
```

## 13. Sync

```text
POST /api/v1/sync/devices                    register a device
GET  /api/v1/sync/devices                    list; admin can list tenant-wide
POST /api/v1/sync/devices/{id}/wipe          request remote cache wipe
GET  /api/v1/sync/delta?scope=…&cursor=…     ordered change feed
POST /api/v1/sync/reserve                    claim an upload slot for a changed local file
```

Delta entries carry `syncEligible`; ineligible files appear as tombstones with a reason so the client
can show "available on the web only" rather than silently omitting them. Full semantics:
`10-SYNC-AND-EDITING.md §4`.

## 14. Administration

```text
/admin/users            /admin/groups             /admin/guests
/admin/workspaces       /admin/libraries          /admin/quotas
/admin/identity-providers                          /admin/scim/v2/*
/admin/dlp/policies     /admin/dlp/incidents      /admin/dlp/simulate
/admin/conditional-access/policies                 /admin/conditional-access/simulate
/admin/classifications  /admin/barriers           /admin/network-zones
/admin/retention        /admin/legal-holds        /admin/records
/admin/audit            /admin/audit/verify       /admin/audit/export
/admin/storage-profiles /admin/mail               /admin/secrets/test
/admin/search/reindex   /admin/search/status
/admin/mcp/clients      /admin/branding           /admin/domains
/admin/config/versions  /admin/webhooks
```

Admin endpoints require an access token whose `acr` is `mfa` and whose `auth_time` is within the
configured step-up window (default 15 minutes) for any privileged mutation listed in
`06-SECURITY-DLP-ACCESS.md §22`.

Simulation endpoints (`/admin/*/simulate`) accept a proposed policy plus a sample set or a historical
time range and return the decisions that *would* have been made, with no side effects.

### 14.1 Conditional-access rules

Implemented `ENC-603`. The path is `/admin/conditional-access/**rules**`, not the `policies` the map
above lists: `04-DATA-MODEL.md §12.1` records why the stored resource is a *rule* —
`conditional_access_policies`' `priority`, `scope_type` and `scope_id` describe an evaluator that was
deliberately not built, and a path naming a resource whose fields are ignored is a path an operator
tunes in vain. `06-SECURITY-DLP-ACCESS.md §7` is authoritative for what a rule decides; this section
is the contract only.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/admin/conditional-access/rules` | The tenant's live rules |
| `POST` | `/admin/conditional-access/rules` | Write one |
| `PATCH` | `/admin/conditional-access/rules/{id}` | Move it between `SIMULATION` and `ENFORCE` |
| `DELETE` | `/admin/conditional-access/rules/{id}` | Withdraw it |

```http
POST /api/v1/admin/conditional-access/rules
Content-Type: application/json

{
  "audience": "HUMAN",
  "name": "Finance downloads from the corporate network only",
  "effect": "BLOCK",
  "mode": "SIMULATION",
  "when": [
    { "outside_every_zone": ["Corporate India", "VPN"] },
    { "action_is": [{ "resource": "file", "action": "download" }] }
  ]
}
```

- **`audience` is required and is never inferred from `when`.** It selects which rule set — and
  therefore which condition vocabulary — the document is read in; several condition names are
  legitimately in both (`06 §7.4`). A document that is not that audience's is refused, **naming the
  clause**, and is never trimmed to the clauses that parsed.
- **Condition names are `snake_case`**, unlike every other field in this API. They are the stored
  vocabulary, and a second spelling at the edge would be a second vocabulary that can drift — and
  would make the refusal above name a clause the administrator did not write.
- **`mode` defaults to `SIMULATION`.** A rule written without saying which it is rehearses;
  enforcing is a statement an administrator makes. Unknown fields in the body are **rejected**, so a
  misspelled `mode` cannot silently produce a rehearsal.
- **`effect` has no `allow`.** `06 §7.4`: under most-restrictive-wins an allow could never change an
  outcome, so accepting one would be an exception that appears to exist. `ALLOW` is refused with
  that reason in `details[].detail`.
- **`when: []` is legitimate** and means every request — "require a managed device, always".

The response is the stored rule, and it carries the rule's **name**; no error ever does. It also
carries `decodes` (and `decodeError` when false), which is `true` for anything written through this
API and can be `false` for a row written by a repair script: a rule that no longer decodes fails
every request in the tenant, and this list is where an administrator finds out which one to withdraw.

`GET` returns the whole live set with `page: { "nextCursor": null, "hasMore": false }`. There is no
cursor: the same set is read on every request in the policy chain, so a tenant with enough rules to
page has a per-request cost that matters long before the page envelope does. §6's shape is kept so
that a cursor can be added without a `v2`.

`PATCH` carries `mode` and nothing else. **A rule's conditions and effect are not editable**:
changing what a rule refuses is a withdrawal and a new rule, so the text of what was in force during
any period remains readable, which is the same argument the table makes for having no `DELETE`. An
edit in place would leave an audit trail saying that a rule changed and no way to see what it said
before.

`DELETE` is **withdrawal**: the row and its text stay and `deleted_at` is set (`04 §12.1`). A rule's
history is audit evidence, and the application role holds no `DELETE` on the table. Withdrawing a
rule that is already withdrawn, that never existed, or that belongs to another tenant are all `404`.

There is no `Idempotency-Key` on the create. A live rule's name is unique within its tenant, so a
replayed create is refused as a collision rather than duplicated; the name is reusable once the rule
holding it has been withdrawn.

| Status | When |
|---|---|
| `201` | Created. `Location` names the rule |
| `200` | The mode changed |
| `204` | Withdrawn |
| `400` | `VALIDATION_FAILED` — one entry in `details`, naming the field |
| `403` | `ACCESS_DENIED` from the chain, or `STEP_UP_REQUIRED` (see below) |
| `404` | Unknown, already withdrawn, or another tenant's — deliberately indistinguishable |
| `409` | `RULE_NAME_IN_USE` |
| `422` | `RULE_WOULD_DENY_ITS_AUTHOR` (see below) |

**`details` entries here carry a third key, `detail`.** §5 defines `{ "field", "code" }`; a refused
rule adds a sentence, because `unknown variant \`posture_below\`` is the whole diagnostic value of a
closed decoder and an administrator told only "rejected" writes the same document again. It is
bounded in length and never contains the rule's name.

**Writing, promoting and withdrawing require recent multi-factor authentication** — the rule stated
at the top of §14, for the privileged mutation `06 §22` calls *changing conditional access*. Reading
does not. A refusal is `403 STEP_UP_REQUIRED` with `{"acr": "mfa", "maxAge": 900}` in `details`
rather than beside `code`, which is where §3.3's older example puts it; the envelope in §5 is fixed.

**A rule may not begin deciding if it would deny its author's own session.** `422
RULE_WOULD_DENY_ITS_AUTHOR` is returned for a create in `ENFORCE`, or a promotion to it, when the
rule would refuse the caller's own `admin/manage_policy` — the action that would undo it. A zone rule
that denies the network an administrator is on cannot be undone through the product
(`plans/M4-GOVERNANCE.md §5`), and break-glass is deliberately *not* honoured by this check: the
question is whether an ordinary session would be refused. Any rule may be written and rehearsed; the
way to enforce one is from a session it allows.

## 15. MCP

MCP is served at `/mcp` over Streamable HTTP, authenticated with the same bearer tokens
(`typ: "mcp"`). Tools map one-to-one onto domain services; there is no privileged MCP path.

| Scope | Tools |
|---|---|
| `SEARCH` | `search_files`, `semantic_search` |
| `READ_METADATA` | `get_file_metadata`, `get_file_outline`, `list_workspace_files`, `query_list` |
| `READ_CONTENT` | `get_file`, `get_file_text` |
| `CREATE` | `create_folder`, `upload_file`, `create_page`, `create_list_item` |
| `UPDATE` | `update_metadata`, `move_file` |
| `SHARE` | `share_file` |

Every tool call is audited with the MCP client identity. Write tools are disabled by default per
client (`mcp_clients.write_tools_enabled`). A tool result never includes content above the client's
`classification_ceiling`, even when the acting user could read it directly.

## 16. Workflows and signing

Semantics, states and the signing pipeline are in `15-WORKFLOWS-AND-SIGNING.md`; the contracts are
registered here.

```text
GET|POST         /api/v1/workflows/definitions
GET|PATCH|DELETE /api/v1/workflows/definitions/{id}
POST             /api/v1/workflows/definitions/{id}/simulate
POST             /api/v1/files/{id}/workflows                start an instance
GET              /api/v1/workflows/instances/{id}
POST             /api/v1/workflows/instances/{id}/cancel     { reason }
GET              /api/v1/workflows/tasks                     steps assigned to me
POST             /api/v1/workflows/steps/{id}/approve        { comment }
POST             /api/v1/workflows/steps/{id}/reject         { comment }   comment required
POST             /api/v1/workflows/steps/{id}/delegate       { toUserId, reason }

POST   /api/v1/files/{id}/signature-requests                 prepare + seal byte hash
GET    /api/v1/signature-requests/{id}
POST   /api/v1/signature-requests/{id}/send
POST   /api/v1/signature-requests/{id}/void                  { reason }
POST   /api/v1/signature-requests/{id}/remind
GET    /api/v1/signature-requests/{id}/certificate           evidence package (PDF + JSON)
GET    /api/v1/sign/{token}                                  signer view, server-rendered
POST   /api/v1/sign/{token}/authenticate
POST   /api/v1/sign/{token}/consent
POST   /api/v1/sign/{token}/sign                             { signatureImage | signedDigest }
POST   /api/v1/sign/{token}/decline                          { reason }
GET    /api/v1/files/{id}/versions/{versionId}/signatures
POST   /api/v1/files/{id}/versions/{versionId}/verify-signature
```

Signer endpoints under `/sign/{token}` are the only endpoints authenticated by a signing token rather
than a bearer access token. That token is single-purpose, single-document, single-use and
short-lived; it grants nothing beyond the ceremony it was issued for.

Additional policy codes: `SIGNING_NOT_PERMITTED`, `DOCUMENT_NOT_SIGNABLE`,
`SIGNATURE_ORDER_VIOLATION`, `SIGNER_AUTH_REQUIRED`, `SIGNATURE_EXPIRED`,
`DOCUMENT_MODIFIED_SINCE_SEAL`, `CERTIFICATE_UNAVAILABLE`,
`PROVIDER_NOT_PERMITTED_FOR_CLASSIFICATION`.

## 17. Webhooks

```text
GET|POST         /admin/webhooks
DELETE           /admin/webhooks/{id}
POST             /admin/webhooks/{id}/test
```

Deliveries are signed: `X-Enclave-Signature: t=<unix>,v1=<hex hmac-sha256>` over `t.body`, with the
secret held in the secret provider. Receivers must reject timestamps older than 5 minutes. Retries
use exponential backoff for 24 hours, then dead-letter with an admin notification.

Webhook payloads carry identifiers and event types only — never file content, never DLP match
excerpts.

## 18. Rate limiting

Independent buckets by IP, account, tenant, token and MCP client. The strictest applicable bucket
wins.

| Bucket | Default |
|---|---|
| `POST /auth/login` | 10 / 5 min per account, 60 / 5 min per IP |
| `POST /auth/refresh` | 60 / hour per family |
| `POST /search` | 120 / min per user |
| `POST /files/*/download` | 300 / hour per user; bulk export separately capped |
| `POST /files/*/shares` | 60 / hour per user |
| MCP tool calls | Per-client profile, default 600 / min |
| All others | 1000 / min per user |

Responses include `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` and, on `429`,
`Retry-After`. Rate-limit rejections are audited when they concern authentication or sharing.

## 19. Health and metadata endpoints

```text
GET /health/live            liveness
GET /health/ready           readiness (PostgreSQL, migrations, object storage)
GET /health/dependencies    per-dependency status, unauthenticated summary / authenticated detail
GET /api/v1/bootstrap       branding, feature flags, locale, policy hints for the SPA
GET /api/v1/me              current identity, groups, capabilities, quota headroom
```
