# 05 — API Surface

> **Status:** Draft · **Version:** 1.9 · **Owner:** Platform Engineering · **Last updated:** 2026-08-30
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

Refresh re-evaluates conditional access, against the address the *refresh* request arrived on and
the authentication strength the session actually holds — not against whatever was true when the
session was created. A client that has moved to a blocked network, or whose tenant has tightened its
rules since sign-in, receives `403 NETWORK_NOT_ALLOWED` and must re-authenticate from a permitted
location.

`NETWORK_NOT_ALLOWED` is the common refusal and not the only one: the stage's other effects produce
`403 DEVICE_NOT_MANAGED` and `401 STEP_UP_REQUIRED` (`§3.3`), and the refresh path returns whichever
code the stage decided, unchanged, because a session refused for its authentication strength that
was told to change networks cannot act on what it was told. No refusal names the rule that produced
it (`§5`).

A refusal does **not** consume the presented token: the same refresh token still rotates from a
permitted location, so a tightening that is later relaxed does not sign everyone out permanently. A
refresh the server could not *decide* — the rule store is unreachable — is `503
DEPENDENCY_UNAVAILABLE` and never a rotation.

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
| `DELETE` | `/files/{id}` | Soft delete to trash, cascading; `If-Match` required |
| `POST` | `/files/{id}/restore` | Restore from trash; `If-Match` required |
| `POST` | `/files/{id}/copy` · `/move` | Bulk-capable; DLP evaluated per destination |
| `GET` | `/files/{id}/versions` | Version history |
| `GET` | `/files/{id}/versions/{versionId}` | Version metadata |
| `POST` | `/files/{id}/versions/{versionId}/restore` | Creates a new version from an old one |
| `GET` | `/files/{id}/permissions` | Effective + explicit ACL |
| `PUT` | `/files/{id}/permissions` | Replace ACL; bumps `aclRevision` |
| `POST` | `/files/{id}/permissions/break-inheritance` | Materializes inherited entries |
| `GET` | `/files/{id}/activity` | Audit-derived activity feed |
| `POST` | `/files/{id}/checkout` · `/checkin` | Explicit lock lifecycle |

**The lifecycle three, and what is not obvious about them** (`ENC-807`). `rename`, `reparent`,
`trash` and `restore` had been in `crates/files` since M1 with no caller in any binary, so a folder,
once created, was permanent.

* **`PATCH` asks two questions.** A rename is `file.edit`; a move is `file.move`; a body asking for
  both must satisfy both. A move additionally asks **`container.create` of the destination**, because
  `file.move` on the source alone is enough to place content into a folder the caller cannot write
  to. A caller who may not write to the destination cannot tell it from one that does not exist.
* **`If-Match` is required on all three and never defaulted**, including `DELETE` and `restore`. A
  missing header is `400 IF_MATCH_REQUIRED`; a stale one is `409`, per `§4`'s optimistic-concurrency
  rule rather than the `412` HTTP reflex would suggest. `ETag` is `files.revision`.
* **`DELETE` cascades, and so does its authorization.** The whole live subtree is enumerated, every
  node is asked `file.delete`, and one denial refuses the operation entirely — nothing partial. A
  subtree refusal is **`404`, not `403`**: the denying node may be one the caller holds no
  `file.metadata_read` on, and a `403` would confirm that the folder contains something hidden from
  them. The addressed folder stays readable, so a `GET` answering `200` beside a `DELETE` answering
  `404` is the intended shape.
* **`restore` is decided against the container the node returns into**, not against the node. A
  trashed row has an empty inheritance chain — `FILE_CHAIN_SQL` joins on `deleted_at IS NULL` — so
  enforcing `file.restore` on the trashed node itself would make restore unreachable forever.
* **"Change content type" in the `PATCH` row above is not implemented and cannot be.**
  `files.content_type_id` references a catalogue that does not exist: there is no `ContentTypeId`,
  `FileNode` omits the column, and no repository mutates it. The handler refuses the field rather
  than accepting and dropping it (`ENC-922`).

`GET /files/{id}` includes what the caller may do, so the UI never renders an action that the server
will reject:

```json
{
  "id": "01937fa0-…",
  "name": "FY26 Board Pack.pdf",
  "mimeType": "application/pdf",
  "sizeBytes": 4210332,
  "classification": { "key": "CONFIDENTIAL", "label": "Confidential", "rank": 30 },
  "currentVersion": {
    "id": "01937fa1-…", "major": 3, "minor": 0,
    "status": "AVAILABLE", "avStatus": "CLEAN", "isReadable": true
  },
  "revision": 12,
  "aclRevision": 4,
  "capabilities": {
    "preview": true, "download": false, "print": false, "export": false,
    "edit": true, "share": true, "shareExternal": false, "delete": false,
    "move": true, "restore": false, "sync": false
  },
  "capabilityReasons": {
    "download": "PREVIEW_ONLY", "print": "PREVIEW_ONLY", "export": "PREVIEW_ONLY",
    "shareExternal": "EXTERNAL_SHARE_BLOCKED", "delete": "ACCESS_DENIED",
    "sync": "SYNC_NOT_PERMITTED"
  },
  "obligations": { "watermark": true, "justificationRequired": ["download"] },
  "governance": { "onLegalHold": true, "isRecord": false, "retentionPolicy": "Board Records 7y" }
}
```

`capabilities` is computed by the same policy engine that will enforce the action — it is a UI hint
derived from the real decision, not a parallel implementation.

**`capabilityReasons` says why each `false` is `false`** (`ENC-674`). Without it a client that wants
to explain a disabled control has only one option — compose a sentence of its own — and that is the
client re-deriving a policy decision, which `CLAUDE.md`'s React conventions forbid and which produces
a wrong explanation as soon as two rules can withhold the same action. `docs/06 §24` requires a
denial to carry a stable code, a user-safe explanation and a remediation; this is that requirement
applied to the capability hint rather than only to the `403` a caller gets after clicking.

The rules, each held by a test:

- **A key here is a capability name, and it appears only when that capability is `false`.** The keys
  are the same strings `capabilities` uses (`shareExternal`, not `SHARE_EXTERNAL`), so a client
  indexes both objects with one key. A reason for an *available* capability would describe a refusal
  that did not happen, and none is ever emitted.
- **The value is a `§5` reason code and nothing else.** Never the rule, policy id, condition,
  threshold or matched value that produced it (`CLAUDE.md` rule 10, `docs/06 §24`). Those reach
  audit, inside the policy engine. The field is a closed enumeration, so there is nowhere for prose
  to be added by mistake.
- **No sentence is on the wire.** `docs/14 §5` makes the client authoritative for wording: it
  renders its own localized string keyed by the code. An English sentence here would be a second
  source of truth for text the client owns.
- **The object is always present, even when empty.** An absent object and an empty one would have to
  mean the same thing to a client and they do not — absent also reads as *this build does not report
  reasons*, and a client that cannot tell those apart falls back to inventing an explanation, which
  is the defect being closed.
- **`metadataRead` and `read` never appear.** Both are true by construction on any object a caller
  can see, so a reason for either could only be fiction.
- **The reason is the one that actually withheld the capability.** Where the ACL refused, the code is
  the authorization stage's. Where the ACL granted and an obligation then suppressed it, the code is
  the obligation's — `NoDownload` reports `PREVIEW_ONLY` on `download`, `print` and `export`, and
  `SYNC_NOT_PERMITTED` on `sync`, because "available on the web only" is what a user needs to hear
  about a replica that will not appear.

The same object, under the same name and the same rules, is on the container capabilities of `§7.1`.

**`currentVersion` says whether the content can actually be served, and why.** `status` alone cannot:
`CLAUDE.md` rule 9 is *two* conditions, and a version is served only when `status` is `AVAILABLE`
**and** `avStatus` is `CLEAN`. Those come apart in practice — a deployment whose antivirus engine is
disabled records an admitted version `AVAILABLE` / `SKIPPED`, which is published and unscanned — so
until `ENC-825` this object was byte-for-byte identical for a file that previews and a file for which
every delivery route answers `404`.

| Field | Meaning |
|---|---|
| `status` | Pipeline state: `PENDING`, `SCANNING`, `PROCESSING`, `AVAILABLE`, `QUARANTINED`, `FAILED` |
| `avStatus` | Antivirus verdict: `PENDING`, `CLEAN`, `INFECTED`, `SKIPPED`, `ERROR` |
| `isReadable` | Whether `GET /files/{id}/preview`, `POST /files/{id}/download` and every other content path would serve this version |

- **`isReadable` is the field to branch on.** It is the server's own readable predicate, not a
  restatement of it, and it is the contract that `isReadable: true` and a `404` from a delivery
  route cannot both happen for the same version and caller. Never re-derive it from `status`:
  `status === "AVAILABLE"` is the specific mistake this contract exists to prevent, because
  `AVAILABLE` means *published*, not *scanned*.
- **`status` and `avStatus` are for the message, not the decision.** They are what turns "not
  readable" into `09-UX-WHITE-LABELING.md §8`'s ladder — `Scanning`, `Processing`, `Quarantined`,
  `Failed` — instead of an unexplained spinner. `AVAILABLE` with an `avStatus` other than `CLEAN`
  means no scanner has cleared these bytes and none will until one is configured; it is not a
  transient state to keep polling.
- **`currentVersion` present does not mean readable.** It is absent only when the file has no
  version at all. A freshly completed upload has one immediately, and it is `SCANNING`.
- Neither field is an enumeration oracle: reaching this object means the caller already passed
  `file.metadata_read` on this file. A caller without that grant gets `404` and learns nothing
  (`§5`, `CLAUDE.md` rule 7).

The same object, with the same three fields, is what `GET /uploads/{id}` returns as `version`
(`§8`). One shape, one meaning, so a client parses "is this content ready" once.

### 7.1 Navigation — workspaces and libraries

| Method | Path | Notes |
|---|---|---|
| `GET` | `/workspaces` | The workspaces this caller can see; cursor-paged |
| `GET` | `/workspaces/{workspaceId}` | One workspace + this caller's capabilities |
| `GET` | `/workspaces/{workspaceId}/libraries` | The libraries in it; cursor-paged |
| `GET` | `/libraries/{libraryId}` | One library, its settings + this caller's capabilities |
| `POST` | `/workspaces/{workspaceId}/libraries` | Create a library in it; `201` + `Location` |
| `GET` | `/workspaces/{workspaceId}/permissions` · `/libraries/{libraryId}/permissions` | Effective + explicit ACL |
| `PUT` | same two paths | Replace the explicit ACL |
| `POST` | `/libraries/{libraryId}/permissions/break-inheritance` | Materializes inherited entries |

**Why this section exists.** `§7` above documents how to browse a library, `§12` documents
sub-resources of workspaces and libraries, and `§14` documents `/admin/workspaces` and
`/admin/libraries` — and until `ENC-791` none of them said how a client *finds* a workspace or a
library. The consequence was concrete: the web shell could open a library only if the id already sat
in its URL, and drew its library picker as unbuilt.

**One of these mutates, and the split is deliberate** (`ENC-916`). Creating a *library* is
`container.create` against the parent workspace, answered by that workspace's own ACL — so a
workspace owner may add one without being the tenant's administrator, which is the arrangement
`01-PRD.md §4` describes and the one every comparable product has. Creating a *workspace* is not
that, and cannot be: `crates/authorization`'s `classify` maps a tenant reference to
`Target::Unsupported`, so a container action against a tenant is refused whoever asks. It is an
administrative act against the tenant and it lives at `POST /admin/workspaces` (`§14`), with the
step-up requirement every route there carries.

This section said *"nothing here mutates"* until `ENC-916`, and it said so accurately — the
consequence was that a deployment could enumerate workspaces and libraries and create neither, while
`enclave-cli seed` writes tenants, users and groups and no container at all. An upload needs a
library to go into, so a fresh deployment had nowhere to put a file and no way to make one.

Renaming and trashing a container remain unbuilt on both paths.

**The permissions surface is the same shape as `§7`'s file one, one level up** (`ENC-917`), and it
exists because `enclave_authorization::grant` could write an `acl_entries` row from the day it landed
and its only caller was the founding grant `POST /admin/workspaces` writes. Every workspace this
product provisioned was therefore permanently single-occupant: the founder held
`container.manage_permissions`, every container endpoint reported `managePermissions: true` to
clients, and no request acted on it — an API describing a button whose handler was never written.

Four things are worth stating on the wire contract, because a client cannot infer them:

* **`PUT` is a replace, not a merge.** An entry the body omits is gone afterwards. That is what makes
  a permissions dialog — read the set, change one row, send the whole thing back — correct rather
  than an accumulation of everything anyone ever granted.
* **It replaces the *explicit* set only.** Rows with `inheritedFrom` set are materialized copies from
  a broken inheritance and no `PUT` removes them, or breaking inheritance would be undoable by an
  unrelated grant.
* **`GET` returns `explicit` and `effective` separately**, each entry tagged with the `source` it
  came from. A collapsed per-principal verdict cannot answer *why* somebody has access, which is the
  only question a permissions screen is ever opened to answer.
* **A caller cannot remove their own ability to manage permissions here.** The refusal is
  `409 WOULD_REMOVE_OWN_MANAGE_PERMISSIONS`, computed on the *effective* answer after the proposed
  change and inside the same transaction as the write — so inheritance still granting it is a pass,
  and a replace that committed before failing its own check is impossible. A tenant administrator is
  **not** exempt: `users.is_admin` confers `admin.*`, never `container.manage_permissions`, so an
  exemption would be a fiction. `aclRevision` is reported on the file surface only, because
  `04-DATA-MODEL.md §7` gives that column to `files` alone.

```json
{
  "items": [
    {
      "id": "01937fb0-…",
      "name": "Engineering",
      "slug": "engineering",
      "description": "Platform and infrastructure",
      "visibility": "PRIVATE",
      "revision": 4,
      "capabilities": {
        "read": true, "create": true, "update": false,
        "delete": false, "manageMembers": false, "managePermissions": false
      },
      "capabilityReasons": {
        "update": "ACCESS_DENIED", "delete": "ACCESS_DENIED",
        "manageMembers": "ACCESS_DENIED", "managePermissions": "ACCESS_DENIED"
      },
      "obligations": { "watermark": false, "justificationRequired": [], "approvalRequired": [] },
      "createdAt": "2026-01-04T09:12:00Z",
      "updatedAt": "2026-08-19T14:02:11Z"
    }
  ],
  "page": { "hasMore": false, "limit": 50 }
}
```

A library row adds `workspaceId` and a `settings` object:

```json
{
  "id": "01937fb1-…",
  "workspaceId": "01937fb0-…",
  "name": "Specifications",
  "slug": "specifications",
  "revision": 2,
  "settings": {
    "versioningMode": "MAJOR_MINOR",
    "versionLimit": 50,
    "requireCheckout": true,
    "requireApproval": false,
    "allowedExtensions": ["pdf", "docx"],
    "maxFileSizeBytes": 5368709120,
    "externalSharing": "EXISTING_GUESTS",
    "aiIndexingEnabled": true,
    "mcpVisible": false,
    "syncEnabled": true
  },
  "capabilities": { "read": true, "create": true, "update": false, "delete": false,
                    "manageMembers": false, "managePermissions": false },
  "capabilityReasons": { "update": "ACCESS_DENIED", "delete": "ACCESS_DENIED",
                         "manageMembers": "ACCESS_DENIED", "managePermissions": "ACCESS_DENIED" },
  "obligations": { "watermark": false, "justificationRequired": [], "approvalRequired": [] },
  "createdAt": "2026-01-04T09:14:00Z",
  "updatedAt": "2026-06-02T11:40:00Z"
}
```

Rules, each of which the implementation is held to by a test:

- **A listing is trimmed by the same chain that would refuse each row.** A workspace or library the
  caller may not see is **absent**, never `403` — and a `GET` of it is `404`, indistinguishable from
  an id that never existed and from another tenant's (`§5`, `CLAUDE.md` rule 7). A caller who cannot
  read a workspace cannot learn how many libraries it holds: `GET /workspaces/{id}/libraries` is
  `404`, not an empty page.
- **A page may be shorter than `limit` while `hasMore` is `true`**, and carries no total, for the
  reasons `§6` gives. Clients page until `hasMore` is false, never until a short page arrives.
- **`capabilities` is per row and is the same six `container.*` answers `/admin/**` will enforce**,
  computed by the policy engine rather than derived by the client. `read` is `true` on every row
  returned: a row the caller could not read would not be there.
- **`settings` are ceilings and modes, never grants.** `externalSharing: "ANYONE"` says what the
  library permits at most; whether *this* caller may share externally is `file.share_external` on the
  file. `defaultClassificationId`, `storageProfileId`, `retentionPolicyId` and `inheritPermissions`
  are **not** on the wire — the first three are internal references (a navigation response is not
  where a client learns which bucket content lands in), and the fourth describes the shape of the ACL
  rather than the caller's position in it, which `capabilities` already answers.

### 7.2 Creating a folder

`POST /libraries/{libraryId}/folders` appears in `§7`'s table above as four words — "Create folder" —
and nothing else: no body, no response, no status, no statement of where `parentId` goes. This
section is that specification, written for the same reason `§7.1` was (`ENC-794`): the code follows
the document, so the document has to say something first. `ENC-788` is the row.

```http
POST /api/v1/libraries/{libraryId}/folders
Content-Type: application/json

{ "name": "Q3 Board Pack", "parentId": "01937fb2-…" }
```

`parentId` is **optional**; absent means the library root. It is a body field rather than a path
segment because the path already names the library, and a folder's parent is a *choice* the request
makes rather than a second route.

`201 Created`, with the folder rendered exactly as `GET /libraries/{id}/items` renders it — the same
object, the same `capabilities`, the same `obligations`:

```json
{
  "id": "01937fb3-…",
  "type": "FOLDER",
  "name": "Q3 Board Pack",
  "mimeType": "inode/directory",
  "sizeBytes": 0,
  "parentId": "01937fb2-…",
  "libraryId": "01937fb1-…",
  "status": "AVAILABLE",
  "revision": 1,
  "capabilities": { "metadataRead": true, "preview": true, "download": false, "print": false,
                    "export": false, "edit": true, "share": true, "shareExternal": false,
                    "delete": true, "move": true, "restore": false, "sync": true },
  "obligations": { "watermark": false, "justificationRequired": [], "approvalRequired": [] },
  "createdAt": "2026-08-27T22:07:07Z",
  "modifiedAt": "2026-08-27T22:07:07Z"
}
```

Rules, each of which the implementation is held to by a test:

- **The chain decides `container.create` on the container the folder would go into** — the folder
  named by `parentId`, or the library when none is named. Never the library id in the path when a
  `parentId` is present: a folder may break inheritance (`files.inherit_permissions`, `§7`'s
  `break-inheritance`), and resolving against the library would ignore the ACL the folder actually
  carries. This is the same choice `§8`'s `POST /uploads` makes for the same request shape, and the
  two must not diverge — a folder a caller may put a file in and may not put a folder in would be two
  answers to one question.
- **A container the caller may not see is absent, not forbidden.** A `libraryId` or `parentId` in
  another tenant, one that never existed, one that is trashed, and one this caller holds no grant on
  are **one** answer: `404` (`§5`, `CLAUDE.md` rule 7). An id that does not parse is the same `404`
  and not a `400`, because a `400` on one of them is a distinction.
- **A duplicate name in one parent is `409`**, per `§5`'s status table, with `code:
  "NAME_IN_USE"` and a `details` entry naming the `name` field. The refusal does **not** echo the
  name: a collision report is the one place a folder the caller has not been shown could be named to
  them.
- **A folder created here always inherits.** There is deliberately no `inheritPermissions` field.
  Breaking inheritance is `POST /files/{id}/permissions/break-inheritance`, a separate
  `permissions.manage` question — a create that could ship a folder with inheritance already broken
  would make the highest-consequence ACL edit in the tree reachable in one unreviewed request.
- **Renaming, reparenting, trashing and restoring a folder are `§7`'s `/files/{id}` routes**, because
  a folder is a node of the file tree (`04-DATA-MODEL.md §8`). There is no `/folders/{id}` resource.
  Listing a folder's children is `GET /libraries/{id}/items?parentId=`.

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
- The pre-signed `PUT` covers `content-type`. Send exactly the `mimeType` declared at
  `POST /uploads` or the store answers `403`, which reads as a permission failure and is a header
  mismatch (`ENC-821`).
- `complete` verifies size and SHA-256 against what was declared, then drives the state machine in
  `03-LLD.md §15`.
- The response after `complete` is `202` with `state: "SCANNING"`. Clients poll or subscribe; a file
  is not presented as ready before antivirus and required processing finish.

`POST /uploads`:

```json
{
  "libraryId": "01937fa0-…",
  "parentId": null,
  "fileId": null,
  "name": "Quarterly Plan.pdf",
  "sizeBytes": 4823119,
  "mimeType": "application/pdf",
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

`201 Created`

```json
{
  "uploadId": "01a04573-…",
  "method": "SINGLE",
  "uploadUrl": "https://s3…/tenant/…/versions/…?X-Amz-Signature=…",
  "requiredHeaders": {
    "content-type": "application/pdf",
    "x-amz-checksum-sha256": "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="
  },
  "urlsExpireAt": "2026-08-27T23:04:59Z",
  "expiresAt": "2026-08-28T22:59:59Z"
}
```

### 8.1 `sha256` is required, and `requiredHeaders` is not advisory

`sha256` is a **required** lowercase-hex SHA-256 of the whole object, and it is the field the
integrity of a version rests on. It is not stored on the session and it is not merely repeated back
at `complete`: the API signs it into the pre-signed `PUT` as `x-amz-checksum-sha256`, which makes
the object store compute the digest of the body it receives and refuse the request if the two
disagree. A client that declares one digest and sends different bytes gets a failed `PUT`, and
`complete` never sees an object at all.

`requiredHeaders` carries every header that `PUT` **must** send, with the exact value that was
signed. It is not a suggestion:

- a `PUT` that **omits** one fails the provider's signature check (`403 SignatureDoesNotMatch`),
  because the header names appear in `X-Amz-SignedHeaders`;
- a `PUT` that sends a **different value** fails the same way;
- a `PUT` that sends the right `x-amz-checksum-sha256` over the **wrong bytes** is refused by the
  provider on the digest (`400 BadDigest`), and nothing is stored.

Send them verbatim, and send nothing this object does not name. `content-type` in particular has
always been signed and was documented nowhere, which cost the first client written against this API
two attempts to diagnose (`ENC-821`).

The absence of a checksum is now the *only* thing a completion cannot recover from, and it is
therefore refused up front rather than discovered afterwards:

| Condition | Answer |
|---|---|
| `sha256` **absent** | `400 VALIDATION_FAILED`, `details[].field: "body"` — the whole body failed to decode, as it does for any missing required field on this endpoint (`ENC-830`) |
| `sha256` present but not 64 lowercase hex characters | `400 VALIDATION_FAILED`, `details[].field: "sha256"`, `code: "INVALID_FORMAT"` |
| `sizeBytes` above what this deployment's object store can have the provider verify | `403 QUOTA_EXCEEDED` |

The last is a real limit today and not a hypothetical. On an S3-compatible backend an upload above
the multipart threshold is sent as a multipart upload, for which S3 and MinIO compute a *composite*
checksum — a checksum of the part checksums — and not the whole-object SHA-256 a version records.
Rather than issue such a session and record a digest nothing verified, `POST /uploads` refuses it.
`ENC-829` is the row for restoring large uploads under a scheme the provider can confirm.

The refusal is `MAX_FILE_BYTES` internally and carries the limit, but the envelope
(`§5`) renders no `quota` and no `limit` field for any `QUOTA_EXCEEDED`, so a client cannot today
show the number it was refused against. That is a gap in the error rendering rather than in this
endpoint — it affects the library ceiling and the tenant storage quota identically — and is
`ENC-831`.

### 8.2 What `complete` refuses

```json
{ "sizeBytes": 4823119, "sha256": "9f86d081…", "parts": [] }
```

`202 Accepted` → `{ "uploadId": …, "fileId": …, "versionId": …, "state": "SCANNING" }`

Every refusal below is **persisted**: the session is written `FAILED` and retrying the same
completion cannot succeed. A new `POST /uploads` is the remedy.

| Condition | Answer |
|---|---|
| `sizeBytes` differs from the size declared at `POST /uploads` | `400 VALIDATION_FAILED`, `field: "sizeBytes"` |
| `sizeBytes` differs from what the object store holds | `400 VALIDATION_FAILED`, `field: "sizeBytes"` |
| `sha256` is not 64 lowercase hex characters | `400 VALIDATION_FAILED`, `field: "sha256"`, `code: "INVALID_FORMAT"` |
| `sha256` differs from the digest the object store computed | `400 VALIDATION_FAILED`, `field: "sha256"` |
| the object store computed **no** digest | `503 UPSTREAM_UNAVAILABLE` |

The last row is a statement about the deployment's object store, not about the client's request,
which is why it is not a `400` naming `sha256`. A digest nobody verified is not recorded: a version's
`checksumSha256` is immutable once written and is read later as evidence that the stored bytes are
the bytes that were sent, so a value the store could not confirm is refused rather than persisted
(`ENC-820`). It should be unreachable on a backend that honoured the signed checksum header; a
BYO S3-compatible store that accepts the header and does not report the digest on `HeadObject` is
what it catches.

### 8.3 `GET /uploads/{id}` — progress, and how an upload ends

```json
{
  "uploadId": "01937fc0-…",
  "state": "SCANNING",
  "libraryId": "01937fb1-…",
  "fileId": "01937fa0-…",
  "version": {
    "id": "01937fa1-…", "major": 1, "minor": 0,
    "status": "AVAILABLE", "avStatus": "CLEAN", "isReadable": true
  },
  "name": "FY26 Board Pack.pdf",
  "declaredSize": 4210332,
  "bytesReceived": 4210332,
  "createdAt": "2026-08-28T09:12:00Z",
  "updatedAt": "2026-08-28T09:12:31Z",
  "expiresAt": "2026-08-29T09:12:00Z"
}
```

**An upload is two rows, and this response reports both.** That is the whole of `ENC-826`, which is
worth stating because the obvious reading of a single `state` field is wrong.

- **`state` is the upload *session's* state** — `CREATED`, `UPLOADING`, `UPLOADED`, `SCANNING`, and
  the terminal `ABORTED`, `EXPIRED`, `FAILED`. It is **terminal at `SCANNING`**: handing the staged
  object to antivirus is the last transition the session makes, and everything after it happens to
  the version. A client that polls `state` waiting for it to become "ready" waits forever, and did.
- **`version` is what finishes the story.** It appears once `complete` has committed a version and
  carries the same three fields as `currentVersion` on `GET /files/{id}` (`§7`), with the same
  meanings. `isReadable` is the field to branch on; `status` and `avStatus` are what explain a
  `false`.
- **`fileId`** is the file this upload is for. For a new-version upload it is present from creation.
  For a **new-file** upload the file does not exist until `complete` commits it, so `fileId` is
  absent until then and appears alongside `version` — it is not a prediction. Both are absent, not
  `null`.
- `version` describes **this upload's** version, not whatever the file currently points at. A later
  upload into the same file does not change what this session reports.

Mapping to `09-UX-WHITE-LABELING.md §8`'s progress ladder:

| Ladder rung | Condition |
|---|---|
| Queued / Uploading | `state` is `CREATED` or `UPLOADING` |
| Scanning | `version` absent, or `version.status` is `PENDING` or `SCANNING` |
| Processing · Indexing | `version.status` is `PROCESSING` |
| **Ready** | `version.isReadable` is `true` — **and no other condition** |
| Quarantined | `version.status` is `QUARANTINED` |
| Failed | `state` is `FAILED`, or `version.status` is `FAILED` |
| Aborted | `state` is `ABORTED` or `EXPIRED` |

Two notes on that table. `Processing` and `Indexing` are one rung here because `file_versions.status`
has one state covering both — text extraction, renditions and indexing all run under `PROCESSING`,
and reporting a distinction the database does not record would be invention. And **`Ready` is
`isReadable`, never `status === "AVAILABLE"`**: a version can be `AVAILABLE` with an `avStatus` of
`SKIPPED` or `ERROR`, meaning published but never cleared by a scanner, and every delivery route
answers `404` for it. That combination is a terminal state for the ladder's purposes, not a
transient one to keep polling — it changes only when a scanning engine is configured and re-judges
the version.

The session's `state` is **not** advanced by the antivirus pass, deliberately. The version row owns
the pipeline's state, `upload_sessions` is transient — reaped after `upload.session_ttl` — and a
second writable copy of one fact is a copy that drifts. The response derives what it reports rather
than reading a column somebody had to remember to write.

`404` for a session in another tenant, a session that never existed, and a session whose target
container this caller may not read — indistinguishable, as `§5` and `CLAUDE.md` rule 7 require.

## 9. Preview, download, export

```text
GET  /api/v1/files/{id}/preview?page=1&profile=page-png-2x
GET  /api/v1/files/{id}/thumbnail?size=256
POST /api/v1/files/{id}/download
POST /api/v1/files/{id}/export        { "format": "pdf" }
POST /api/v1/files/{id}/print-token
POST /api/v1/files/{id}/print         { "token": "…" }
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

### 9.1 Print is two calls: mint, then spend (`ENC-724`)

`POST /files/{id}/print-token` enforces `file.print` and returns a capability once:

```json
{
  "token": "…43 url-safe base64 characters…",
  "expiresIn": 120,
  "singleUse": true,
  "redeemAt": "/api/v1/files/{id}/print",
  "watermark": true
}
```

Only its SHA-256 is stored, so this response is the one time the value exists outside the caller's
process. It names one tenant, one file, one version, one actor and one sign-in, and it is spendable
at `redeemAt` and nowhere else.

`POST /files/{id}/print` spends it:

```json
{ "token": "…", "justification": "Client audit request #4412" }
```

`200 OK` — `image/png`, `Content-Disposition: inline`, `Cache-Control: private, no-store`, one page
image composited with the viewer's watermark where policy requires one.

**Why two calls rather than one.** The mint is the decision and the redemption is the delivery, and
they are separated because a browser print dialog is a user gesture that happens some seconds after
the affordance is offered. A single call would have to either serve the page before the user asked
for it or re-open the whole policy chain from a click handler with no request of its own.

**Why the token is in the body and not the path.** `§10`'s `GET /shares/{token}` puts a share token
in a URL because a share link *is* a URL, pasted into an email by a person. A print grant is never
seen by a human, and a capability in a URL is a capability in an access log, a proxy log, a `Referer`
header and a browser history entry.

**What a redemption returns is not a download, and cannot become one.** The response is a
*re-rendered page image* at `page-png-2x` — a PDF's embedded fonts, attachments, form fields,
metadata, revision history and selectable text do not survive rasterisation — served `inline`, never
`attachment`. No original object-storage URL is issued on this path and none can be: the handler
holds the rendition pipeline and no object store, so "give me the original" is not expressible in the
vocabulary it has (`12-TESTING.md §4.2` A15). Print remains separately deniable from download, from
export and from preview (`CLAUDE.md` rule 6).

**The chain runs again at redemption.** A grant is a decision about an earlier request; an ACL
withdrawn, a barrier raised or a DLP rule added inside its 120 seconds takes effect. Obligations from
the two decisions are unioned, so a mark required by either is required.

**Every way of failing is one answer.** A token that was never issued, one whose lifetime elapsed,
one already redeemed, one minted for another file, another actor, another sign-in, or in another
tenant — all `404`, and none of them distinguishable from the others. Telling a presenter their token
was real but expired tells them it was real (`CLAUDE.md` rule 7). A body carrying no `token` field at
all is `400 VALIDATION_FAILED`, which is a statement about the request rather than about what the
tenant holds.

**Single use is enforced by PostgreSQL**, not by the API process: redemption is one
`UPDATE … WHERE redeemed_at IS NULL … RETURNING` against `print_tokens` (`04-DATA-MODEL.md §15.2`),
so two replicas racing the same grant produce exactly one winner. A refusal *after* a successful
redemption — an obligation this path cannot discharge, or a rendition the deployment cannot produce
— rolls the transaction back, so the caller keeps the capability they were issued.

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

`POST /sync/reserve` opens an upload session and therefore takes `§8.1`'s contract unchanged:
`checksumSha256` is **required**, lowercase hex, and is what the object store is made to verify the
body against. It was optional, which gave the sync push path `ENC-820` in the same shape as
`POST /uploads`.

## 14. Administration

```text
/admin/users            /admin/groups             /admin/guests
/admin/workspaces       /admin/libraries          /admin/quotas
   POST /admin/workspaces is built (ENC-916); the rest of that row is not.
/admin/identity-providers                          /admin/scim/v2/*
/admin/dlp/policies     /admin/dlp/incidents      /admin/dlp/simulate
/admin/conditional-access/policies                 /admin/conditional-access/simulate
/admin/classifications  /admin/barriers           /admin/network-zones
/admin/retention        /admin/legal-holds        /admin/records
   /admin/retention/policies is built (ENC-943); legal-holds and records are not.
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

**Who is authorized.** Every route here runs `PolicyEngine::enforce` with an `admin.*` action against
the **tenant** — never against the object being edited, which would make the decision an oracle for
that object's existence. The authorization stage answers it from the caller's administrative grants,
and the grants a deployment can express today are one role: `users.is_admin`, the tenant's global
administrator, which holds every `admin.*` action (`ENC-619`). The narrower administrator personas of
`01-PRD.md §4` — an Identity Administrator who may not change DLP, an Auditor who may read the log
and change nothing — need `role_assignments`, which `04-DATA-MODEL.md §2` lists and `§9` has no DDL
for; until then those callers are refused like anyone else. Which action each route uses is not
cosmetic: `06-SECURITY-DLP-ACCESS.md §22` separates *changing conditional access* from *changing
branding*, so policy surfaces authorize as `admin.manage_policy` and configuration surfaces as
`admin.write_config`, and the two must not be answered by one question.

A principal that is not a directory user — a service account, an MCP client, a guest — is never an
administrator, and a suspended, deprovisioned or deleted one holds nothing from the moment the row
says so, whatever its outstanding token still claims.

**`POST /admin/workspaces`** (`ENC-916`) provisions a workspace. It authorizes as
`admin.write_config` against the tenant, per the rule above, and answers `201` with the same
`WorkspaceView` and capabilities object `GET /workspaces/{id}` renders — a create that invented its
own shape would hand clients two decoders for one thing. `409` on a duplicate slug, detected by the
unique index rather than by a prior read.

The part worth knowing is what it writes **besides** the workspace. In the same transaction it
writes the creator's founding grant into `acl_entries` — thirteen rows, one per action: the six
container actions, and seven file actions. Both halves are needed and the reason is not symmetry.
`POST /uploads` enforces `container.create`, so a container-only grant let a founder upload a file
and then receive `404` opening it, because the resolver matches action strings literally and nothing
implies `file.metadata_read` from `container.create`. What the founding grant deliberately does
**not** confer is `print`, `export`, `share`, `share_external`, `sync`, `copy`, `move`, `restore`,
`version_restore` or file-level `manage_permissions`: `CLAUDE.md` rule 6 holds that preview,
download, print, export and sync are five permissions and never one, and provisioning is an
automatic act nobody reviewed. A founder who wants them holds `container.manage_permissions` and
writes them deliberately — which is the second act rule 6 exists to require, and which **no HTTP
route can perform yet** (`ENC-917`). Until one does, the founding grant is the only way any
principal obtains access to a new workspace.

The workspace insert and the founding grant commit together or not at all. A provisioning that
half-succeeded would leave a workspace nobody can open and nobody can delete.

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

### 14.2 DLP rules

Implemented `ENC-633`. The path is `/admin/dlp/**rules**`, not the `policies` the map above lists,
for `§14.1`'s reason one stage over: `04-DATA-MODEL.md §12.3` records which of the documented
columns were deliberately not created, and a path naming a resource whose fields are ignored is a
path an operator tunes in vain. `06-SECURITY-DLP-ACCESS.md §8`–`§10` is authoritative for what a
rule means; this section is the contract only.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/admin/dlp/rules` | The tenant's live rules, in evaluation order |
| `POST` | `/admin/dlp/rules` | Write one |
| `DELETE` | `/admin/dlp/rules/{id}` | Withdraw it |

```http
POST /api/v1/admin/dlp/rules
Content-Type: application/json

{
  "name": "No external sharing of payment data",
  "priority": 100,
  "scope": ["external_sharing"],
  "conditions": [
    { "category_at_least": { "category": "FINANCIAL", "count": 1 } }
  ],
  "action": "BLOCK"
}
```

- **`scope` and `conditions` are the stored vocabulary, `snake_case`**, carried verbatim and decoded
  by the same function the policy chain runs on every request. A second spelling at the edge would be
  a second vocabulary that can drift, and the drift would be silent.
- **`conditions` is closed, and that is Q16.** Every condition is a comparison against a count, a
  rank, a severity or a score; there is no variant a **pattern** could occupy, so no regex reaches
  the synchronous path. A document naming one is refused **naming the clause** — including a pattern
  smuggled *inside* an otherwise valid clause, which a lenient decoder drops in silence. A rule is
  never trimmed to the clauses that parsed: one that lost a condition matches more requests than its
  author wrote, and one that lost a scope governs fewer.
- **`scope` may not be empty.** An empty scope governs *nothing* — the permissive reading is how a
  mis-migrated row becomes a tenant-wide block — so a rule with one would be stored, listed, and
  never fire.
- **`conditions: []` is legitimate** and means "whenever the action is governed".
- **`action` has no `ALLOW`.** `06 §10` lists it; the evaluator does not implement it. Its demand is
  nothing, and the verdict scans *past* a rule demanding nothing to the next one that refuses — so an
  `ALLOW` written above a `BLOCK` fires, changes nothing, and the caller is refused anyway. It is
  refused with that reason in `details[].detail`. Write the exception as a narrower scope or
  condition on the restrictive rule.
- **`reclassifyTo` belongs to `RECLASSIFY` and to no other action**, in both directions.
- **`priority` is zero or greater and defaults to `100`.** It decides which reason code a refused
  caller sees when two rules refuse, and the order fired rules are recorded in. It does *not* decide
  whether a rule fires: no action suppresses a later one.
- **There is no `mode` field, and a body carrying one is rejected.** A DLP rule has no per-rule mode
  by construction — `plans/M4-GOVERNANCE.md` D28 keeps `SIMULATION` and `ENFORCE` from diverging by
  giving the evaluator no mode argument — so the mode is deployment configuration. A body field
  accepted and ignored would be an administrator believing a rule rehearses while it decides.

The response is the stored rule, and it carries the rule's **name**; no error ever does. It also
carries `decodes` (and `decodeError` when false), which is `true` for anything written through this
API and can be `false` for a row written by a repair script: a rule that no longer decodes fails
every request in the tenant, and this list is where an administrator would find out which one to
withdraw — see the caveat below.

`GET` returns the whole live set with `page: { "nextCursor": null, "hasMore": false }`, for §14.1's
reason: the same set is loaded on every request in the policy chain.

**There is no `PATCH`.** §14.1 has one because a conditional-access rule carries a mode and a rollout
step; this one has neither. A rule's scope, conditions, action and priority are not editable at all:
changing what a rule refuses is a withdrawal and a new rule, so the text of what was in force during
any period stays readable.

`DELETE` is **withdrawal**: the row and its text stay and `deleted_at` is set (`04 §12.3`). The
application role holds no `DELETE` on the table, and here the reason is stronger than "history is
evidence" — `06 §9` refuses enforcement of a policy that has never been simulated, and that gate is a
query over observation history that *names a rule*. A deleted rule is one whose rehearsal cannot be
found. Withdrawing a rule that is already withdrawn, that never existed, or that belongs to another
tenant are all `404`.

There is no `Idempotency-Key` on the create. A live rule's name is unique within its tenant — and the
name **is** the rule's identity to the evaluator — so a replayed create is refused as a collision
rather than duplicated; the name is reusable once the rule holding it has been withdrawn.

| Status | When |
|---|---|
| `201` | Created. `Location` names the rule |
| `204` | Withdrawn |
| `400` | `VALIDATION_FAILED` — one entry in `details`, naming the field |
| `403` | `ACCESS_DENIED` from the chain, or `STEP_UP_REQUIRED` |
| `404` | Unknown, already withdrawn, or another tenant's — deliberately indistinguishable |
| `409` | `RULE_NAME_IN_USE` |
| `422` | `RULE_WOULD_GOVERN_ITS_OWN_WITHDRAWAL` (see below) |

**Writing and withdrawing require recent multi-factor authentication** — the rule at the top of §14,
for the privileged mutation `06 §22` calls *disabling or weakening DLP*; a rule that is not written
is a refusal that does not happen. Reading does not.

**A rule may not govern the action that would withdraw it.** `422
RULE_WOULD_GOVERN_ITS_OWN_WITHDRAWAL` is returned when the scope covers `admin.manage_policy` —
which `["any"]` does, and so does naming the action outright. This is not the same check §14.1 makes,
and it is stricter for two reasons. The DLP stage runs on administrative actions like any other, and
an administrative call is made *against the tenant*, which has no content and therefore no security
facts: whether a rule fires is decided **after** whether it governs, so a governed administrative
action is refused outright under `facts_unavailable: FAIL_CLOSED` whatever the rule's conditions say.
And there is no rehearsal to write it into — a DLP rule has no per-rule mode — and no session it
decides differently for, because DLP conditions are about the resource rather than the principal. One
such rule therefore refuses every administrative request in the tenant, including the one that would
withdraw it, and the way back is a database session. Scope a rule to `exposes_content`,
`external_sharing`, or the exact actions it is about.

**One caveat this surface does not fix.** A stored rule that no longer decodes fails the *whole* rule
set, and the chain runs before this handler — so in a tenant holding such a row, `GET` answers `500`
and the list that would identify the row cannot be reached. The handler decodes each row
individually and would report it; the stage above it is what fails. `ENC-651`, and the same shape as
`ENC-623` one stage over.


#### Retention (`ENC-943`)

Implemented. `ENC-940` gave the chain a retention stage and the two tables it reads, and left the
only path to a policy row as `psql` — a control the product enforces on every delete that nobody
using the product could configure.

| Method | Path | What it does |
|---|---|---|
| `GET` | `/admin/retention/policies` | The tenant's policies, its assignments, and the stored vocabularies |
| `POST` | `/admin/retention/policies` | Write a policy |
| `POST` | `/admin/retention/policies/{id}/assignments` | Apply it to a scope |
| `DELETE` | `/admin/retention/policies/{id}/assignments?scopeType=&scopeId=` | Withdraw it from that scope |

Four things about this surface are decisions rather than defaults.

**One `GET` returns all three collections.** Policies, assignments and vocabularies are one screen
and are read together every time. Split across three requests, a client can render a policy list
against an assignment list fetched a moment later and show a live control as unapplied in the gap.

**The vocabularies are served, not published.** `actions`, `bases` and `scopeTypes` come from the
stored enumerations, so a client builds its pickers from the schema instead of from a copy that
drifts silently — the drift surfacing later as an option that produces a `400` nobody can explain.

**An assignment has no identifier.** `migrations/0031` keys it by
`(tenant_id, policy_id, scope_type, COALESCE(scope_id, …))`, so the address *is* the scope, and
withdrawal names it in the query string. That is also the form an administrator reads straight off
the listing in front of them rather than a handle they must look up first.

**`DELETE` at the edge is an `UPDATE` underneath.** `enclave_app` holds no `DELETE` on either
table; withdrawal stamps `expires_at` and leaves the row, because a statement that erases the
evidence a retention control ever applied is the statement these tables exist to make impossible.
Withdrawing an assignment that is already withdrawn and one that never existed are the same `404`,
deliberately: the caller administers this tenant so the distinction leaks nothing, and two messages
that must keep agreeing about a difference nobody can act on are two messages that stop agreeing.

Validation is the schema's. `migrations/0031` carries six named `CHECK` constraints and **none is
restated in Rust** — the handler writes, the database refuses, and `write_failure` maps the
constraint name to a sentence. Two copies of a rule are two chances to relax it one at a time, and
the copy that drifts is the one nobody is reading. A constraint the mapping does not recognise
becomes a `500` rather than a generic `400`: a rule the schema enforces and the API cannot explain
is a gap in that function, not something to paper over.

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
GET /api/v1/me/recent       the files this caller opened, newest first (?limit=8, capped)
GET /api/v1/trash           what this caller deleted and may restore (?limit=50, capped)
```

### 19.2 `GET /trash` — what was deleted, and what can be brought back (`ENC-938`)

`§7` registers `DELETE /files/{id}` and `POST /files/{id}/restore` and, until `ENC-938`, nothing that
listed the bin — so a file deleted through the product left every surface and the restore endpoint
was reachable only by somebody holding an id they had written down first.

```json
{
  "items": [
    {
      "fileId": "01a04eb4-…", "name": "Q3 Notes.pdf", "type": "FILE",
      "mimeType": "application/pdf", "libraryId": "01a04eb4-…", "parentFolderId": null,
      "deletedAt": "2026-08-29T20:11:04Z", "purgeAfter": "2026-09-28T20:11:04Z",
      "deletedBy": { "id": "…", "displayName": "…" },
      "revision": 4,
      "capabilities": { "…": "the same twelve as §7" }
    }
  ],
  "filteredCount": 0
}
```

**`revision` is on the wire because `restore` requires `If-Match`.** A listing that omitted it would
show somebody their file and give them no way to get it back, which is the same dead end as not
listing it at all, one step further in.

**Authorized on `file.restore`, not `file.metadata_read`.** The list exists to be acted on, so
showing a row the caller cannot restore is offering an action that will refuse them. A candidate the
chain drops increments `filteredCount` and never becomes a `403` — rule 7, and the disclosure is
sharper here than elsewhere, because the caller *did* once have access and a `403` would confirm the
file is still there.

**Only the roots of a cascade are listed.** `DELETE` stamps one `deleted_at` across a folder and
every descendant, and `restore` restores exactly the subtree sharing that instant. Listing every
trashed row would show a folder and each of its hundred children as separate entries, and restoring
any child would be a partial restore of somebody's folder. A row is kept only when no parent shares
its `deleted_at` — which correctly keeps a file deleted *before* the folder above it, since its
parent's instant differs.

Ordered most-recently-deleted first. The read model is `04-DATA-MODEL.md §7`'s `files`, and
`idx_files_trash` — documented since the file surface was specified and created by no migration
until `migrations/0030` — is what keeps it off a sequential scan.

### 19.1 `GET /me/recent` — the home screen's *Continue working* list (`ENC-930`)

```json
{
  "items": [
    {
      "fileId": "01a04eb4-…",
      "name": "fox.txt",
      "extension": "txt",
      "mimeType": "text/plain",
      "classification": { "key": "INTERNAL", "label": "Internal", "rank": 20 },
      "lastAccessedAt": "2026-08-30T00:11:04Z",
      "libraryId": "01a04eb4-…",
      "parentFolderId": null,
      "capabilities": { "metadataRead": true, "preview": true, "…": "the same twelve as §7" }
    }
  ],
  "filteredCount": 0
}
```

`limit` defaults to 8 and is clamped rather than refused. `parentFolderId` is `null` for a file at
the library root. `capabilities` is `§7`'s object, produced by the same code — a second copy of that
shape is `ENC-929`, which blanked the library screen for a week when the server grew two fields the
client did not have.

**`classification` is the file's own label, deliberately not the inherited chain maximum**, and
`null` means *this row has nothing to display* rather than *this file is unclassified*. Drawing
`Unclassified` on a document that inherits `RESTRICTED` from its folder is exactly the disclosure the
badge exists to prevent (`06-SECURITY-DLP-ACCESS.md §6.2`), so a client renders no chip at all for
`null`.

**`filteredCount` is the count the policy chain removed, and it names nothing.** Every candidate the
read model produces goes through `PolicyEngine::enforce` before it reaches the wire; a row the chain
drops increments this and never becomes a `403` (rule 7 — a `403` would confirm the file exists).
The count is what lets a client tell *"you have opened nothing"* from *"you opened things you may no
longer see"*, which `09-UX-WHITE-LABELING.md §11` requires be two different sentences. A caller
learns how many they cannot see and never which.

**What records a row**: `GET /files/{id}`, preview and download — *you looked at it*. Browsing a
folder does not, or the list would be the folders somebody walked past rather than the work they
were doing. **The write never fails the read it records**: a missing recency row is cosmetic, and a
file that will not open because its bookkeeping failed is an outage.

The read model is `04-DATA-MODEL.md §15.3` and is **not** derived from `audit_events`.
