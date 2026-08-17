# 10 — Sync Clients & External Editing

> **Status:** Draft · **Version:** 1.0 · **Owner:** Platform Engineering · **Last updated:** 2026-08-18
> **Authoritative for:** desktop/mobile sync, device management, external document-editor integration.

## 1. Why this document exists

Sync and external editing are the two surfaces where content legitimately leaves the server's direct
control. Both were named as requirements and as DLP enforcement points; neither can be treated as an
implementation detail, because both are exactly where a preview/download split gets quietly defeated.

The governing rule: **a client that may not download a file may not sync it, and may not open it in
an editor that requires the original bytes on the client.**

## 2. Sync architecture

```text
Desktop / Mobile client
   |  registers device, obtains device-bound tokens
   v
Sync API  ──►  Policy chain (per file, per operation)
   |
   +── GET  /sync/delta       ordered change feed per scope
   +── POST /sync/reserve     claim an upload slot for a local change
   +── uploads/downloads via the normal signed-URL paths
```

The sync client is an ordinary API consumer with a distinct `client_type`. It gets no privileged
endpoint, no bulk export path and no relaxed policy evaluation. Everything it can do, the web client
could do; it simply does it on a schedule.

## 3. Device registration and trust

```text
POST /api/v1/sync/devices
  { name, platform, clientVersion, publicKey }
   -> deviceId, enrollment challenge
```

- A device is bound to one user. Its `dev` claim is required on every sync token
  (`03-LLD.md §5.2`), so a token stolen from one device cannot be replayed from another.
- Posture (`UNKNOWN`, `UNMANAGED`, `MANAGED`, `COMPLIANT`) comes from MDM attestation where
  configured, and feeds conditional access. `IF client_type == SYNC AND device.posture != MANAGED
  THEN NO_SYNC` is a one-line policy.
- Admins and users can list, pause, revoke and wipe devices. Revocation kills the refresh family;
  the next delta call fails closed.
- `sync.max_devices_per_user` (default 5) bounds fan-out.

### 3.1 Remote wipe

`POST /sync/devices/{id}/wipe` sets `wipe_requested_at`. The client, on its next successful
authentication, deletes its local cache and its stored tokens, then acknowledges — at which point
`wiped_at` is stamped and an audit event is written.

This is a cooperative wipe. It works against loss and offboarding; it does not defeat an attacker who
controls the device and has removed it from the network. The documentation and admin UI say exactly
that. Local caches are encrypted at rest with a key held in the OS keystore, which is the control
that actually matters for a stolen laptop.

## 4. The delta protocol

```http
GET /api/v1/sync/delta?scope=library:01937f…&cursor=8841203&limit=500
```

```json
{
  "entries": [
    { "op": "UPSERT", "fileId": "…", "versionId": "…", "path": "Contracts/MSA.pdf",
      "sizeBytes": 812311, "checksumSha256": "…", "modifiedAt": "2026-08-18T09:14:02Z",
      "syncEligible": true, "seq": 8841204 },
    { "op": "TOMBSTONE", "fileId": "…", "path": "Contracts/Draft.docx",
      "reason": "POLICY_NOT_ELIGIBLE", "seq": 8841205 }
  ],
  "cursor": "8841205",
  "hasMore": false
}
```

Properties:

- **Monotonic and ordered.** `seq` is a per-scope change sequence. A client that replays from an old
  cursor converges; it never needs a full re-scan.
- **Idempotent.** Applying the same entry twice is a no-op.
- **Policy-evaluated per entry.** The delta is generated through the policy chain, so a file the user
  lost access to appears as a `TOMBSTONE` with a reason, not as an omission.
- **Honest about exclusions.** `reason` values — `POLICY_NOT_ELIGIBLE`, `NO_DOWNLOAD`,
  `CLASSIFICATION_BLOCKED`, `QUARANTINED`, `ACCESS_REVOKED`, `DELETED`, `LIBRARY_SYNC_DISABLED` —
  let the client show "Available on the web only" instead of silently losing a file, which is the
  behavior that generates support tickets and shadow-IT copies.

Deltas are cursor-bounded and resumable. A cursor older than the change-log retention window (default
30 days) returns `410 CURSOR_TOO_OLD`, and the client performs a scoped re-enumeration.

## 5. Sync eligibility

A file is eligible only when **all** of these hold:

1. the library has `sync_enabled = true`;
2. the classification does not set `sync_blocked`;
3. the caller holds both `Download` and `Sync` on the file;
4. no conditional-access policy returns `NoSync` or `NoDownload` for this client/device/network;
5. DLP returns no blocking effect for the `SYNC` enforcement point;
6. the version is `AVAILABLE` with `av_status = CLEAN`.

Eligibility is evaluated at delta time **and** re-evaluated when the client requests bytes. A file
that became ineligible between the two returns `403 SYNC_NOT_PERMITTED`, and the client tombstones it.

## 6. Upload, conflicts and locking

V1 sync is whole-file, not offline-merge (`01-PRD.md §3`).

```text
POST /api/v1/sync/reserve
  { fileId, baseVersionId, checksumSha256, sizeBytes }
   -> { uploadId, ... }  |  409 CONFLICT { currentVersionId }
```

- The client declares the version it edited from. If the server has moved on, it gets `409`.
- **Conflict resolution never discards user content.** On conflict the client uploads its copy as
  `Name (conflicted copy — Device, 2026-08-18).ext` alongside the server version and raises a
  notification. Both versions exist; a human decides.
- Files under `CHECKOUT` or an active `EDITOR` lock are read-only to sync; the client marks them
  locked with the holder's name.
- Rename and move are transmitted as metadata operations, not delete-plus-create, so history and
  permissions survive.
- Quota is checked at `reserve`, so a device does not upload gigabytes to be rejected at commit.

## 7. External document editing

### 7.1 The constraint

A client-side editor (desktop Word over WebDAV, for instance) requires the original bytes on the
user's machine. That is a download in every sense that matters. A server-side editor
(Collabora Online, ONLYOFFICE Document Server) renders on the server and ships pixels and edit
operations — the bytes never leave the trust boundary.

Therefore:

| Caller may download? | Permitted editors |
|---|---|
| Yes | Server-rendered **or** client-side |
| No | Server-rendered only |

A tenant that has not deployed a server-rendered editor simply cannot offer editing for
no-download content. The UI says "Editing unavailable for this classification" rather than
degrading the control quietly.

### 7.2 Session brokering

```text
POST /api/v1/files/{id}/editor-session   { mode: "EDIT" }
   -> { editorUrl, sessionToken, expiresIn, mode }
```

1. The API runs the full policy chain for `Edit` (and `Download` if the editor is client-side).
2. It creates an `editor_sessions` row and a **scoped, single-resource, short-lived token**
   (default 60 minutes, renewable while the session is live).
3. It takes an `EDITOR` lock on the file.
4. The editor calls back to a narrow, dedicated endpoint set to fetch and store content, presenting
   only that token. The token grants access to exactly one file version and nothing else.
5. On save, a new version is created through the ordinary version path, with the editor recorded as
   the modifying agent. Antivirus, DLP and indexing run as they would for any upload.
6. On close or expiry, the lock releases and the token is revoked.

The editor never receives a user access token, never talks to PostgreSQL or object storage directly,
and never gets a token that outlives its session.

### 7.3 Editor deployment requirements

- Deployed inside the trust boundary, in the tenant's residency region.
- No public internet egress from the editor's document path.
- TLS between API and editor, with mutual authentication where the editor supports it.
- Watermark and no-print obligations are passed to the editor as session parameters and applied by
  the editor's own rendering; where an editor cannot honor an obligation, the session is refused
  rather than issued unprotected.

### 7.4 Co-authoring

Real-time co-authoring is delegated to the server-rendered editor's own collaboration model. The
platform contributes identity, permissions, locking and version commits; it does not implement OT/CRDT
merge itself in V1. Comments and mentions remain platform features, anchored to file and version, so
they survive independently of the editor.

## 8. Auditing

Sync and editing are first-class audited surfaces, not background noise:

| Event | Recorded |
|---|---|
| Device registered / revoked / wiped | Actor, device, platform, posture |
| Delta served | Scope, cursor range, entry count (not file list, for volume) |
| File materialized to a device | File, version, device, size — this is a download, and is audited as one |
| Sync upload | File, base version, new version, conflict outcome |
| Editor session opened / closed | File, version, editor, mode, duration |
| Save from editor | New version, obligations applied |

Bulk-materialization detection runs on the same signals as bulk-download detection: a device pulling
an unusual volume raises a security incident.

## 9. Failure behavior

| Condition | Client behavior |
|---|---|
| Access token expired | Refresh; on failure, pause sync and prompt |
| Refresh rejected (`SESSION_REPLAY`) | Wipe tokens, require full re-authentication |
| Network zone now blocked | Pause with an explanatory state, retry on network change |
| Cursor too old | Scoped re-enumeration |
| File ineligible mid-transfer | Abort, tombstone, show "Available on the web only" |
| Quota exceeded | Pause uploads, keep downloads, surface the quota state |
| Server `503` | Exponential backoff with jitter, capped; never a hot retry loop |

## 10. Client platform notes

- **Desktop (Windows/macOS/Linux):** placeholder/on-demand files where the OS supports it
  (Windows Cloud Files API, macOS File Provider), so a 2 TB library does not require 2 TB of disk.
  Local cache encrypted at rest.
- **Mobile (iOS/Android):** selective, on-demand caching only; no whole-library replication. Offline
  availability is opt-in per file and respects the same eligibility rules.
- All clients ship a minimum-supported-version check; the server can refuse an outdated client whose
  policy evaluation is known to be stale.
