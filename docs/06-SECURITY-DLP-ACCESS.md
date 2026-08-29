# 06 — Security, DLP & Access Controls

> **Status:** Draft · **Version:** 2.5 · **Owner:** Security Engineering · **Last updated:** 2026-08-30
> **Authoritative for:** threat model, conditional access, DLP, antivirus, renditions, incidents, privileged operations.

## 1. Security model

Assume the browser and client are hostile, URLs are guessable, files are malicious, identity
attributes supplied by clients are untrusted, and derived indexes contain sensitive material.

Every control is enforced server-side. Client-side checks exist only to avoid offering an action the
server will reject.

### 1.1 Threat model summary

| Threat | Primary control |
|---|---|
| Cross-tenant access | Two-layer isolation: query guard + PostgreSQL RLS (`04-DATA-MODEL.md §3`) |
| Direct object-store access | No public buckets; short-lived, single-use signed URLs; keys unguessable |
| Stolen access token | 10-minute TTL, device binding for sync/editor, denylist + epoch revocation |
| Stolen refresh token | Rotation with reuse detection; family revocation on replay |
| Permission revocation not reaching search | Authoritative post-filter + denylist (`07-SEARCH-INDEXING.md §6`) |
| Malicious upload | Antivirus before availability; rendition sandboxing; type allowlists |
| Data exfiltration via AI | MCP scopes, classification ceilings, DLP on retrieval, full audit |
| Exfiltration via sync | `Sync` is a distinct permission; no-download implies no-sync |
| Insider bulk download | Rate limits, bulk-download detection, DLP justification/approval, incidents |
| Audit tampering | Append-only role, hash chain, external anchoring |
| Header spoofing (`X-Forwarded-For`) | Trusted-proxy allowlist with hop counting |

## 2. Canonical security chain

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

Defined in `README.md §3`, implemented once in `03-LLD.md §12`.

## 3. Granular content controls

Separate permissions for preview, download, print, export, copy, edit, share, external share and
sync. There is no generic "read".

Preview-only policies never issue the original storage URL. Export and print are independently
deniable, because a permitted preview must not imply a permitted paper copy.

## 4. Authentication and token security

Full design in `03-LLD.md §5`. Security-relevant properties:

- **Access tokens** are Ed25519-signed JWTs with a 10-minute default lifetime and no server-side
  session lookup on the hot path.
- **Refresh tokens** are opaque 256-bit values, SHA-256 hashed at rest, rotated on every use, with
  reuse treated as theft: family revocation, token denylist, `SESSION_REPLAY` incident, user
  notification.
- **Revocation** works through three layers — short TTL, `jti` denylist, and a per-user
  `token_epoch` bump for immediate mass revocation on password change, MFA reset, offboarding or
  privilege loss.
- **Conditional access is re-evaluated on refresh**, so a change of network or device posture takes
  effect within one access-token lifetime rather than at session expiry.
- **Browser storage:** the access token lives in memory only; the refresh token lives in an
  `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`. Neither is written to
  `localStorage`, which is readable by any injected script.
- **Binding:** `sync` and `editor` clients must present a registered `dev` (device) claim; a token
  minted for one device cannot be replayed from another.

Design note: opaque server-side sessions revoke instantly but cost a lookup on every request. The
JWT model above trades that for a bounded revocation window, closed by the denylist and epoch
mechanisms. Privileged scopes (`admin:*`, `security:*`, `share:external`) additionally **fail closed**
if the denylist store is unreachable.

## 5. Secure preview and renditions

Sensitive documents are rendered server-side to controlled HTML, canvas or page images. Renditions
are produced in a sandboxed worker with no network egress, a CPU/memory/time budget, and a hard page
limit, because document parsers are a large attack surface.

### 5.1 Rendition caching and watermarks

A watermark identifies the viewer, so a naively cached watermarked page would either leak one user's
identity to another or defeat caching entirely. The split:

| Layer | Content | Cached? | Key |
|---|---|---|---|
| **Base rendition** | Identity-free page images / sanitized HTML | Yes, encrypted at rest | `(version_id, profile, generator_version)` |
| **Watermark layer** | User, email, timestamp, file ID, session ID, classification | No | Composed per request |

Composition happens at delivery: an SVG or canvas overlay is applied over the base rendition in the
response stream. Nothing identity-bearing is written to the rendition store.

Where a format requires a flattened artifact (a watermarked PDF for permitted export), it is
generated on demand, streamed once, and stored only if `export.retain_artifacts` is enabled — in
which case it is keyed by `(version_id, user_id, issued_at)` with a short TTL and is itself an
audited object.

Base renditions inherit the source file's classification and ACL. Deleting or purging a version
purges its renditions in the same job.

### 5.2 Honest limits

No-download means the product will not deliver an original or downloadable representation. It cannot
prevent screenshots, photographs of a screen, or capture on an unmanaged device. Documentation, UI
copy and sales material must not claim otherwise.

## 6. Antivirus and content safety

### 6.1 Provider interface

```rust
#[async_trait]
pub trait AntivirusScanner: Send + Sync {
    async fn scan(&self, stream: ByteStream, hint: ScanHint) -> Result<ScanVerdict>;
    async fn engine_info(&self) -> Result<EngineInfo>;   // engine name + signature version
}

pub enum ScanVerdict {
    Clean,
    Infected { signature: String },
    Unsupported,                       // e.g. encrypted archive
    Error { retryable: bool },
}
```

Implementations: ClamAV (embedded or `clamd`), ICAP for enterprise gateways, and vendor HTTP APIs.

### 6.2 Rules

- A version cannot reach `AVAILABLE` while `av_status = 'PENDING'`.
- `Infected` moves the version to `QUARANTINED`, blocks every read path including preview and
  search, raises a `CRITICAL` incident and notifies security. The uploader is told the upload failed
  policy — not which signature matched.
- `Unsupported` (encrypted archives, exceeding depth limits, or no engine configured at all)
  follows tenant policy: `BLOCK` (default for `CONFIDENTIAL` and above) or `ALLOW_WITH_FLAG`.
  - `BLOCK` moves the version to `QUARANTINED` with `av_status = 'SKIPPED'`. No read path serves it.
  - `ALLOW_WITH_FLAG` moves it to `AVAILABLE` with `av_status = 'SKIPPED'`, and **every delivery
    path serves it** — preview, download, print, export and sync alike. This is what the policy
    means; a version it published that no route would serve is the setting failing to do anything
    (`ENC-828`). `SKIPPED` is never rewritten to `CLEAN`: it is what keeps the version
    distinguishable from scanned content and what the signature-update sweep below keys on.
  - The `CONFIDENTIAL`-and-above ceiling is applied on rank alone and is not a default this policy
    can switch off: unscanned content at or over that rank is `BLOCK`ed whatever the tenant set.
  - A version whose scan has **not completed** is a different case with the opposite answer, and it
    is the one clause of rule 9 the policy cannot reach: `AVAILABLE` with `av_status = 'PENDING'` —
    what `ALLOW_AND_RESCAN` writes below — is refused by every read path.
- Scanner outage follows `av.unavailable_policy`: `HOLD` (default — versions wait in `SCANNING`) or
  `ALLOW_AND_RESCAN`. `HOLD` is required for tenants under regulated profiles.
- Archives are expanded to a configured depth (default 5) with total-size and entry-count caps, to
  resist decompression bombs.
- Signature updates enqueue a rescan of content modified within a configurable window (default 30
  days) and of everything currently flagged `Unsupported`.
- Rescan results update `file_versions.av_*` in place; the content bytes remain immutable.

## 7. Conditional access

Inputs: IP/CIDR, country/region, ASN, named locations/network zones, trusted proxies,
managed/unmanaged device, authentication strength (`acr`/`amr`/`auth_time`), client type, user/guest
type, and time/risk context.

Effects: allow, block, require MFA, require trusted network, require managed device, preview only,
no download, no sync.

Policies are evaluated in priority order; the most restrictive matching effect wins. Every policy
supports `SIMULATION` mode before enforcement.

### 7.1 Geo-fence examples

```text
IF classification == RESTRICTED
AND action == DOWNLOAD
AND country != IN
THEN BLOCK
```

```text
IF department == FINANCE
AND country NOT IN [IN, US]
THEN REQUIRE_MFA
```

```text
IF client_type == SYNC
AND device.posture != MANAGED
THEN NO_SYNC
```

### 7.2 IP allowlisting

Admins define trusted zones — Corporate India, Corporate US, VPN, HQ, Datacenter, Trusted Partner.
Admin console access may itself be restricted to trusted zones, with a documented break-glass path
(`11-OPERATIONS.md §11`) so a misconfigured zone cannot permanently lock every administrator out.

### 7.3 Trusted proxy handling

Never trust arbitrary `X-Forwarded-For`. A forwarded address is accepted only when the immediate
peer is inside a configured trusted-proxy CIDR, and only `hops` entries deep from the right. Anything
beyond the configured depth is discarded, not merged. Geo/ASN lookups run on the resolved client
address only.

### 7.4 How matching effects resolve

Added after implementation (`ENC-583`); the rules above did not say what happens when two effects
match, and the answer turned out to have consequences worth writing down.

**Two rule sets, matched by principal class, never one set with exemptions.** Users and guests are
matched by rules that can speak about device posture, authentication strength, country and zone.
Service accounts, MCP clients and `system` are matched by a *separate* set whose vocabulary is
network allowlists and token binding. A posture rule against a service account is not a rule that is
skipped — it cannot be expressed. This is what removes the escape clause a single rule set would
need on every posture rule, and with it the gap a compromised service token would walk through.

`system` is in the machine set and is **not** exempt. A token can assert `typ: "system"`, so an
exemption for it would be reachable. The consequence is that a machine allowlist which omits
loopback refuses in-process work — the retention sweep, the outbox publisher — loudly, which is the
correct direction and is stated here so it is not rediscovered as a bug.

**Most restrictive matching effect wins, and that decides the reason code only.** Denials are
considered in a fixed severity order — block, require trusted network, require managed device,
require MFA, preview only, no download, no sync — so two deployments with the same rules in
different order return the same reason. Obligations are *unioned* across every matching effect: the
resolution rule chooses which refusal to report and never discards a constraint.

**There is no `ALLOW` effect.** Under most-restrictive-wins an allow can never change an outcome, so
offering one would let an administrator write an exception, see it accepted, and have it do nothing.
An exception is written as a narrower condition on the restrictive rule, where it is visible in the
rule that actually decides.

**Break-glass traverses this stage rather than skipping it.** `11-OPERATIONS.md §5.6` exempts the
emergency account from IP and zone policy and from nothing else; a skipped stage cannot make that
distinction and could not be audited, since audit happens inside the policy engine. So the exemption
is narrow: rules that match *because of where the caller is* stop matching, a trusted-network
requirement is satisfied, and every other effect applies unchanged. The exemption is conditioned on
multi-factor authentication, so it cannot be used to avoid the requirement it does not cover.

**An unknown country is outside every geo-fence and inside none.** `country NOT IN [IN]` matches a
caller whose location cannot be resolved; `country IN [IN]` does not. Both directions read the same
way: absence of evidence never satisfies a location requirement.

### 7.5 Where a rule lives, and what its storage may not express

Added after implementation (`ENC-590`); §7 said what a rule decides and never said who writes one or
where it is kept, and the answer turned out to constrain the rule itself.

**Rules are tenant data; zones are the deployment's.** An administrator writes rules against their
own tenant, and one `enclave.yaml` serves every tenant on a host — so rules are rows
(`04-DATA-MODEL.md §12.1`), read per request under that tenant's row-level-security context. Zone
*definitions* stay in configuration, because a zone names this deployment's networks and is what the
edge resolves an address against before any tenant is known.

**Storage may not express what the rule types cannot.** §7.4's two rule sets are a *type*
separation, and a table would dissolve it silently: a JSONB document holds any clause. So the
audience is a column, it selects which type the document is decoded into, and a document that is not
that type is refused **by name** rather than having the offending clause dropped. A rule that lost a
condition would match more requests than the administrator wrote, and every rule in this stage
denies. For the same reason one undecodable rule fails the whole set rather than being skipped: a
policy silently missing one refusal is a policy nobody wrote.

**A stale rule set is permissive, so its staleness is bounded in time.** Because there is no `ALLOW`
effect, every rule here denies or constrains, and a cache that has not yet seen the newest rule
allows something the administrator has forbidden. Rules are therefore cached per tenant for a short,
fixed interval rather than until something evicts them, and the interval — not an invalidation
message — is what an administrator is told: a message reaches the replica that sent it, and a
deployment is several. Tightening a rule during an incident is the case this bound exists for.

**Removing a rule leaves the rule.** The application role holds no `DELETE` on the table, because one
such statement lifts every network restriction a tenant has and leaves nothing to say it existed.
Withdrawal sets a timestamp; the text stays, and it can be read and reinstated.

## 8. DLP detectors

Built-in and custom: Aadhaar, PAN, passport, tax identifiers, credit card (with Luhn), bank account,
healthcare identifiers, email/phone, credentials, API keys, private keys, source-code secrets,
financial records, regex, dictionaries, checksums, proximity rules and ML classifier plugins.

Detectors declare a confidence and a minimum match count. Proximity rules ("card number within 50
characters of an expiry date") materially reduce false positives and are preferred over raw regex for
financial data.

## 9. DLP modes

`DISABLED`, `MONITOR`, `SIMULATION`, `WARN`, `ENFORCE`.

Simulation is mandatory before enforcement for any policy whose effect is `BLOCK` or `QUARANTINE`.
The admin UI refuses to enable enforcement on a policy that has never been simulated.

### 9.1 What each mode does

The modes are a ladder, and every rung adds exactly one thing to the one below it:

| Mode | Evaluates | Records | Applies obligations | Refuses |
|---|---|---|---|---|
| `DISABLED` | no | no | no | no |
| `MONITOR` | yes | yes | no | no |
| `SIMULATION` | yes | yes | no | no |
| `WARN` | yes | yes | yes | no |
| `ENFORCE` | yes | yes | yes | yes |

`DISABLED` is a mode a tenant may legitimately run in, not the absence of configuration. It is the
one mode that does not inspect content, and that is what the mode *means* rather than an
optimization.

`MONITOR` and `SIMULATION` have the same effect on a request and are not the same mode. The
difference is what the record means: `MONITOR` says a live policy observed this, `SIMULATION` says a
candidate policy was rehearsed against it. The gate in the paragraph above — enforcement refused on a
policy never simulated — is a question asked of the second kind of record, so the mode that produced
an observation is part of the record and not a detail of it.

**`SIMULATION` must be indistinguishable from `ENFORCE` except in its effect.** Same detectors, same
facts, same evaluation, same record shape, same latency budget. A simulation that is fast because it
skips work measures something other than what enforcement will do, which makes the mandatory-
simulation rule worthless. The implementation makes the divergence hard to write rather than merely
forbidden: nothing that computes a verdict is told which mode is running, and the "what would
enforcement have done" field on every record is produced by calling the *same* mode-to-effect
function with `ENFORCE`.

### 9.2 Modes and `facts_unavailable` are different questions

`facts_unavailable` (`§12`) decides what an evaluation **concludes** when it has no usable facts. The
mode decides whether any conclusion is **acted on**. A tenant in a non-enforcing mode has not asked
DLP to refuse anything, and `facts_unavailable` does not enable blocking on their behalf — so a
missing-facts conclusion is recorded under `MONITOR`, `SIMULATION` and `WARN`, and refused only under
`ENFORCE`. The alternative would be a mode that still blocks during a rollout, which is a mode nobody
can roll out.

### 9.3 An action no rule governs never consults facts

Whether any rule applies to an attempt is settled **before** facts are required. Without that
ordering a `FAIL_CLOSED` tenant would find every action refused while a scanning backlog drained —
including actions no policy has anything to say about — and the control would be switched off and
never switched back on.

## 10. DLP actions

`ALLOW`, `AUDIT`, `WARN`, `REQUIRE_JUSTIFICATION`, `REQUIRE_APPROVAL`, `BLOCK`, `QUARANTINE`,
`REMOVE_SHARE`, `READ_ONLY`, `NO_DOWNLOAD`, `WATERMARK`, `RECLASSIFY`, `NOTIFY_SECURITY`.

Actions that modify the request rather than reject it (`WATERMARK`, `READ_ONLY`, `NO_DOWNLOAD`,
`RECLASSIFY`) are returned as **obligations** the caller must apply — they are never silently dropped
(`03-LLD.md §12`).

## 11. Enforcement points

Upload, preview, download, external share, anonymous share, guest access, export, print, API access,
MCP access, agent retrieval, move/copy, sync, editor session, signing ceremony (including dispatch to
an external signature provider), webhook payload construction and bulk actions.

A new surface is not "done" until it appears in this list and in the leakage matrix of
`12-TESTING.md §4`.

## 12. Security facts and synchronous evaluation

Full scanning is asynchronous; synchronous decisions consume precomputed `SecurityFacts` — detector
counts, classification, scan version, detector-set version, risk signals.

When facts are missing or their `detector_set_version` is older than the active one, behavior follows
`dlp.facts_unavailable`:

- `FAIL_CLOSED` — deny the sensitive action and explain that scanning is in progress. Default for
  `RESTRICTED` and for external sharing at any classification.
- `FAIL_OPEN_AUDIT` — allow, record a high-visibility audit event, and enqueue a priority rescan.

`dlp.facts_unavailable` is **tenant configuration and never a per-request choice**. A caller, a
header and an operation may not select it; the shape that gets added for "just this bulk import"
stays.

### 12.1 What the mandatory escalations are compared against

Two of the inputs are properties of the **resource**, not of the scan, and both are read in the same
breath as the facts so that every stage of one request sees the same values:

- **The classification.** `FAIL_CLOSED` is mandatory at and above the rank a tenant calls
  `RESTRICTED` (`dlp.restricted_at`, since ranks are tenant-defined). That rank comes from the label
  the resource carries *now* and not from the scan — otherwise the escalation is asked about an
  unknown rank in exactly the case it exists for, and an unscanned `RESTRICTED` document is
  permitted under `FAIL_OPEN_AUDIT` because the evidence that it was `RESTRICTED` was expected from
  the scan that had not happened.
- **The existing exposure.** "External sharing" is two questions. The actions that *create* external
  exposure are a property of the action alone. Changing the terms of a share that is **already
  external** — its expiry, its permission, its password — is not: whether that share is external is
  a property of the resource. Both fail closed. Broadening a permission or dropping a password
  increases the exposure of a document nobody has scanned, and the reading that the content was
  already exposed so nothing new is does not hold.

**Revocation is deliberately excluded from the second.** Revoking reduces exposure, and a tenant that
cannot revoke an external link over unscanned content is left holding the link — the same trap a
delete refused on an exhausted quota creates, reached by a different road.

### 12.2 Facts are gathered once per request

Every stage that needs facts receives the *same* value, read once before the chain's first stage. No
stage re-fetches.

The cost argument is the smaller one. The argument that decides it is that a stage re-fetching can
observe *different* facts from the stage before it — a scan completing mid-chain — so the request is
decided against two views of one document while the audit row records one of them. That is not a
race that occasionally gives a wrong answer; it is a race that gives a decision nobody can
reconstruct afterwards.

The consequence is accepted rather than mitigated: **facts are as of the start of the request**, and
a scan finishing during a request does not affect that request.

A facts *read failure* is not "no facts". Returning "missing" on a database error converts an outage
into a policy answer, and under `FAIL_OPEN_AUDIT` that answer is allow.

### 12.3 A document the scan could not read has **no** facts, not empty ones

The asynchronous scan is content inspection, so it inherits every way content can refuse to be
inspected: an encrypted container, a corrupt file, a media type this deployment has no extractor
for, a scanned page where OCR is not mounted. All four yield no text.

Such a version records **no fact row at all**. It does not record a scan with every count at zero,
and the distinction is the whole of this section. Every condition a rule can express is a threshold
over counts, a severity or a score, so a row of zeroes makes each of them evaluate cleanly and
*permit* — with a `scanned_at` timestamp and the active detector-set version standing behind it, and
with nothing downstream able to tell it apart from a document that was read and found clean. An
absent row is the `§12` state above, whose meaning the tenant has already chosen: `FAIL_CLOSED`
refuses the sensitive action and says scanning is in progress, `FAIL_OPEN_AUDIT` permits and records.

A document that *did* yield text and carried nothing does record a row with zero counts. That is a
real scan finding nothing, and it is what stops the rule collapsing into "record nothing ever".

Two consequences follow, and both are intended:

- **Coverage is a number an operator has to be able to see.** A tenant whose corpus is largely
  unreadable is either sitting on an outage or on a hole in the control, depending on
  `facts_unavailable`, and neither is visible from the fact table — which holds no evidence of the
  versions it has no rows for.
- **Retrying an unscannable version is correct, not waste.** What could not be read today becomes
  readable the day the missing extractor or OCR volume is mounted, with no backfill to run.

## 13. Incidents

Each violation records policy/rule, file, version, actor, IP/country/device/session, matched
sensitive data types (types and counts — **not** the matched values), attempted action, destination,
severity, risk score, decision, justification, notes and evidence references.

States: `OPEN`, `INVESTIGATING`, `REMEDIATED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`, `CLOSED`.

Evidence references point at the file and version; incident records never embed the sensitive
excerpt, because the incident store has a broader audience than the file itself.

## 14. Information barriers

Mandatory segmentation prevents cross-segment discovery, search, sharing and MCP retrieval even
where ACL membership would otherwise permit it. Barriers are evaluated after authorization and before
classification, and a barrier denial is indistinguishable from absence (`404`).

Barrier tokens are indexed alongside chunks so segmented content is excluded at query time, not only
at result time.

## 15. Retention, records and legal hold

Retention and record policies override user deletion. Legal hold prevents destructive deletion,
applies to versions as well as current content, and is fully auditable. Release of a hold is a
privileged, audited operation with a recorded reason.

Ordering matters: retention is evaluated last in the chain, so a user who lacks permission is told
they lack permission rather than learning that a matter-specific legal hold exists.

**Where overlapping policies disagree, the strictest wins** — ranked by action
(`LEGAL_HOLD` > `RECORD` > `KEEP` > `KEEP_THEN_DELETE` > `DELETE_AFTER`), then by the longer
duration, with scope specificity only a tiebreak between policies that are otherwise equal. This is
the opposite of the most-specific-wins rule that governs ACLs, and it is deliberate: under
most-specific-wins, anyone who can attach a `DELETE_AFTER` to a library could override a
tenant-wide `KEEP`, which is a legal hold that its own subject can lift. A narrower scope may
therefore only ever add restriction.

The refusal is a **stage of the chain**, not a predicate on the delete statement. The two would
reject the same requests; only the stage writes the audit record, and a hold whose stated property
is that it is fully auditable cannot be a `WHERE` clause. A cascading delete is a delete of every
descendant, so the stage evaluates the subtree rather than the named node.

Enforcement is unconditional. A deployment that has configured no policy is answered identically by
a stage that runs and finds nothing, so there is no flag to enable — and no deployment where the
control is off because nobody checked.

## 16. Passwords

Local account and share-link passwords use Argon2id with per-deployment tuned parameters (memory,
iterations, parallelism) recorded alongside the hash so parameters can be raised over time and
rehashed on next successful login.

Raw passwords are never logged or persisted. An optional application pepper is held in the secret
provider, not in the database.

## 17. MFA

TOTP, WebAuthn/passkeys, recovery codes. Privileged administrators must hold at least one phishing-
resistant factor. Step-up MFA is required for sensitive actions and is expressed through `acr` and
`auth_time` rather than a separate session flag.

Recovery codes are single-use, hashed, and regenerating them invalidates the previous set and raises
an audit event.

## 18. Session management (token families)

What administrators and users see as a "session" is a refresh-token family (`sid`):

- `GET /auth/sessions` lists active families with device, client type, IP, country and last use;
- a user may revoke one family or all of them;
- an administrator may revoke families for any user in their tenant, and may bump `token_epoch` to
  terminate everything immediately;
- absolute lifetime (default 90 days) and idle lifetime (default 14 days) are enforced on refresh;
- family revocation cascades: refresh rows revoked, outstanding `jti`s denylisted, sync devices for
  that family paused.

## 19. Security dashboard

Sensitive files, blocked actions, external shares, high-risk users, bulk downloads, unusual
geographies, malware/quarantine, guest activity, privileged changes, open incidents, policy coverage,
and — importantly — **policies still in simulation**, so a tenant can see what it believes is
enforced but is not.

## 20. Alerts and SIEM

Email, webhook, syslog (RFC 5424) and SIEM forwarding for high-risk events, preserving request-ID and
event-ID correlation. Forwarding is at-least-once with a local buffer; a SIEM outage must not drop
security events or block user operations.

## 21. Data protection

- TLS 1.2+ in transit, TLS 1.3 preferred; HSTS on all tenant domains.
- Encryption at rest for object storage (provider-managed, customer KMS, or application envelope
  encryption), database, backups and renditions.
- Secrets exist only as references in configuration (`08-BYO-INFRA.md §6`).
- Backups are encrypted and their restore path is exercised on a schedule (`11-OPERATIONS.md §4`).

## 22. Privileged operations

Recent MFA plus audit are required for: disabling or weakening DLP, changing legal hold, changing
external-sharing policy, changing identity providers, changing storage or Vault/KMS configuration,
changing conditional access, modifying global admin membership, exporting audit data, releasing
quarantine, and bumping another user's `token_epoch`.

Optional maker/checker approval for critical configuration changes: the change is written as a
pending `config_version` and takes effect only after a second administrator approves it. The proposer
cannot approve their own change.

## 23. Policy simulation

Administrators can evaluate DLP, conditional access, sharing, retention and barrier changes against
sample content or a historical time range before enforcement, receiving the decisions that would have
been produced and a diff against current behavior.

## 24. Security UX

Policy denials return a stable reason code plus a user-safe explanation and a remediation, e.g.
`DOWNLOAD_BLOCKED_BY_POLICY` → "Downloading this file is restricted outside the corporate network."
→ "Connect to the corporate VPN, or request an exception."

Never leak internal policy names, conditions, thresholds, or whether other users have access.
Everything the client is not told still goes to audit.

## 25. Vulnerability management

Dependency scanning and SBOM generation on every build; container image scanning before publish;
signed releases; a documented disclosure address and response SLA; regular third-party penetration
testing against the leakage matrix in `12-TESTING.md §4`.
