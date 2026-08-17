# 16 — Workflows, Approvals & Document Signing

> **Status:** Draft · **Version:** 1.0 · **Owner:** Platform Engineering · **Last updated:** 2026-08-18
> **Authoritative for:** the workflow engine, approval/review pipelines, and the document signing flow.

## 1. Scope

Two related capabilities:

- **Workflows** — multi-step processes over content: approval, review, publication, onboarding a
  contract, routing an invoice. Deterministic, auditable, resumable.
- **Signing** — obtaining legally meaningful signatures on a document version, either through an
  in-platform ceremony or an external e-signature provider, producing a verifiable artifact.

Signing is modeled as a workflow step, not a separate universe. That is deliberate: a signature is
almost never the whole process — it is preceded by review and followed by filing, retention and
sometimes counter-signature.

Non-goals for V1: arbitrary user-authored code execution, a general BPMN engine, and acting as a
Certificate Authority.

## 2. Workflow model

```text
WorkflowDefinition                 (template, versioned)
   └── Stage[]                     ordered
         └── Step[]                parallel within a stage
               ├── type            APPROVAL | REVIEW | SIGNATURE | TASK | AUTOMATION | CONDITION
               ├── assignees       users, groups, roles, or a dynamic resolver
               ├── policy          quorum, order, SLA, escalation
               └── on_outcome      next stage | reject | branch

WorkflowInstance                   (running, bound to a resource + version)
   └── StepInstance[]              with state, actor, decision, timestamps
```

Core properties:

1. **Bound to a version, not a file.** An approval approves *what was actually reviewed*. A new
   version invalidates in-flight approvals unless the definition sets
   `on_new_version: CONTINUE` (rare, and it is audited loudly).
2. **Deterministic.** Given the same definition and the same event sequence, the instance reaches the
   same state. No wall-clock reads inside evaluation; timers are events.
3. **Resumable.** State lives in PostgreSQL; workers are stateless. A restart mid-workflow loses
   nothing.
4. **Policy-bound.** Every transition runs through `PolicyEngine::enforce`. A workflow cannot grant
   an actor access they do not otherwise have — it can only *require* action from someone who does.

## 3. Step types

| Type | Semantics |
|---|---|
| `APPROVAL` | Assignees approve or reject. Quorum: `ALL`, `ANY`, `N_OF_M`, `SEQUENTIAL` |
| `REVIEW` | Comment-and-acknowledge without a gate decision |
| `SIGNATURE` | A signing ceremony — see `§6` |
| `TASK` | A human task with a due date and a checklist |
| `AUTOMATION` | A platform action: move, classify, apply retention, notify, call a webhook |
| `CONDITION` | Branch on metadata, classification, DLP facts or a previous outcome |

`AUTOMATION` steps call **allowlisted platform actions only**. There is no scripting host; a step
cannot execute arbitrary code, which is what keeps a workflow from becoming a privilege-escalation
surface.

## 4. Lifecycle and states

```text
WorkflowInstance:  DRAFT -> RUNNING -> COMPLETED
                              |  \-> REJECTED
                              |  \-> CANCELLED
                              \----> EXPIRED

StepInstance:      PENDING -> ASSIGNED -> {APPROVED | REJECTED | SIGNED | DECLINED | SKIPPED | EXPIRED}
```

Rules:

- Rejection at any step terminates the instance unless the definition declares a rework branch, which
  returns to a named earlier stage with a required comment.
- Cancellation requires the initiator or a workspace owner, a reason, and is audited.
- SLA breach fires `escalation`: reassign, notify a manager, or auto-expire — declared per step, never
  implicit.
- Delegation is explicit and recorded (`acted_on_behalf_of`), never a silent substitution.
- **Self-approval is rejected by default.** A definition may allow it only with
  `allow_self_approval: true`, which surfaces in the admin UI as a control weakness.

## 5. Workflow triggers

| Trigger | Example |
|---|---|
| Manual | A user starts "Contract review" on a file |
| Event | `file.version.created` in the `contracts` library starts approval |
| Metadata | Content type set to `Contract` |
| Schedule | Quarterly policy re-attestation |
| API/MCP | An integration starts a workflow (subject to scopes) |

Trigger evaluation is idempotent on `(definition_id, resource_id, version_id)`, so a redelivered
event cannot start a duplicate instance.

---

## 6. Document signing

### 6.1 What a signature must produce

Whatever the mechanism, a completed signing produces four things, and the design is judged on all
four:

1. **A signed artifact** — normally a PDF with an embedded cryptographic signature.
2. **Signer identity evidence** — how each signer was authenticated, at what strength, when, from
   where.
3. **A tamper-evident binding** — a change to the document after signing is detectable.
4. **An audit trail** that can be produced years later, independently of any vendor still existing.

### 6.2 Signing modes

| Mode | Mechanism | Assurance | Typical use |
|---|---|---|---|
| `ACKNOWLEDGEMENT` | Authenticated click-through, recorded | Low | Policy attestation, read receipts |
| `ELECTRONIC` | Drawn/typed signature image + platform-applied PAdES signature over the result | Medium | Internal approvals, NDAs |
| `DIGITAL_PLATFORM` | PAdES/PKCS#7 signature using a platform or tenant certificate, signer identity bound in the signature | Medium-high | Issued documents, invoices |
| `DIGITAL_SIGNER_CERT` | Signature made with the signer's own key: PKCS#11 token, smart card, or HSM-held key | High | Regulated filings, DSC-mandated jurisdictions |
| `EXTERNAL_PROVIDER` | Delegated to DocuSign, Adobe Acrobat Sign, Aadhaar eSign, or another provider | Provider-defined | Counterparty signing, jurisdiction-specific compliance |

A tenant enables the modes it is entitled to use. The mode is recorded per signature — "signed" is
never displayed without the mode that produced it, because the modes are not legally equivalent.

### 6.3 The signing pipeline

```text
1. PREPARE
   - Select file version. Signing always targets an immutable version.
   - Validate: AV clean, not quarantined, format signable (PDF, or convertible with an approved
     rendition), no active editor lock.
   - Policy chain runs for Action::Sign. DLP may block (e.g. unresolved sensitive content),
     classification may restrict which providers may see the document.
   - Define signers: order, roles, authentication requirements, field placement.

2. SEAL BASELINE
   - Compute and record SHA-256 of the exact bytes to be signed.
   - Freeze the version: no metadata that is rendered into the document may change while signing
     is open.

3. INVITE
   - Generate per-signer, single-purpose, scoped tokens (one document, one action, short TTL).
   - Notify by email in the recipient's locale. External signers get a guest identity with an
     explicit expiry.

4. AUTHENTICATE
   - Per the step's requirement: existing session + step-up MFA, OTP to a verified channel,
     knowledge-based verification, ID verification via provider, or certificate/PKCS#11 presence.
   - Record method, strength, IP, country, device, timestamp.

5. PRESENT & CONSENT
   - Server-rendered view of the exact bytes hashed in step 2. No client-side re-render of a
     different artifact.
   - Explicit, localized consent to sign electronically, recorded with the presented text version.

6. SIGN
   - Apply the signature per mode (§6.2). Signature fields are placed at prepared coordinates.
   - Multi-signer: each signature is applied as an incremental PDF update, so earlier signatures
     remain individually verifiable.

7. FINALIZE
   - After the last signer: apply a document-level timestamp (RFC 3161 TSA), optionally seal with
     the tenant certificate.
   - Attach LTV data (§6.5).
   - Commit the signed artifact as a NEW VERSION of the file, marked signed and, if configured,
     declared a record.

8. DISTRIBUTE & FILE
   - Deliver copies per definition, apply retention/record policy, index for search, notify.
   - Emit signature.completed.
```

Two properties hold that pipeline together: **what is presented is what is hashed** (step 2 vs.
step 5), and **the output is a new version** (step 7) — the original never mutates, so the
pre-signature state remains available and auditable.

### 6.4 Signature formats

- **PDF: PAdES** (ETSI EN 319 142), B-B baseline minimum, B-T with a timestamp for anything
  externally consequential, B-LT/B-LTA where long-term validation is required.
- **Non-PDF: detached CAdES/PKCS#7** (`.p7s`) stored alongside the version, plus a manifest recording
  the exact bytes covered.
- **XML: XAdES** where a jurisdiction requires it.

Signature algorithms: RSA-PSS 3072+ or ECDSA P-256/P-384, SHA-256 or stronger. MD5 and SHA-1 are
rejected on both signing and verification.

### 6.5 Long-term validation

A signature that verifies today and fails in five years is a liability. Every finalized signature
embeds:

- the full certificate chain;
- OCSP responses and/or CRLs current at signing time;
- an RFC 3161 timestamp from a configured TSA.

The scheduler re-timestamps archived signed documents before their existing timestamp's algorithm or
TSA certificate weakens (`archive_timestamp_interval`, default 2 years), which is what B-LTA
requires and what makes a 10-year-old signature still verifiable.

### 6.6 Key custody

| Mode | Key location |
|---|---|
| `DIGITAL_PLATFORM` | Tenant signing certificate in HSM or `KeyProvider`; the platform never holds an exportable private key |
| `DIGITAL_SIGNER_CERT` | The signer's own token/smart card/HSM. The private key **never** reaches the server — the server sends a hash, the client returns a signature |
| `EXTERNAL_PROVIDER` | The provider's custody, per its own model |

For `DIGITAL_SIGNER_CERT` the flow is explicitly hash-then-sign: the server computes the digest, the
signer's local agent or browser (WebCrypto/PKCS#11 bridge) signs it, and the server embeds the result.
Any design that uploads a private key is rejected outright.

### 6.7 External providers

```rust
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    async fn create_envelope(&self, req: EnvelopeRequest) -> Result<EnvelopeRef>;
    async fn status(&self, envelope: &EnvelopeRef) -> Result<EnvelopeStatus>;
    async fn fetch_signed(&self, envelope: &EnvelopeRef) -> Result<SignedArtifact>;
    async fn fetch_certificate(&self, envelope: &EnvelopeRef) -> Result<AuditCertificate>;
    async fn void(&self, envelope: &EnvelopeRef, reason: &str) -> Result<()>;
    fn residency(&self) -> Residency;
}
```

Adapters: DocuSign, Adobe Acrobat Sign, Dropbox Sign, Aadhaar eSign (NSDL/eMudhra), and a generic
webhook-driven adapter.

Rules:

- **Classification gates provider use**, exactly as with embeddings and LLMs. A `RESTRICTED` document
  is not shipped to a third-party SaaS signer unless the tenant has explicitly permitted that
  provider for that classification; the default is deny.
- Provider callbacks are signature-verified (HMAC or provider certificate) and replay-protected.
- Status is **polled as well as pushed** — a missed webhook must not strand an envelope.
- On completion the signed artifact and the provider's audit certificate are both pulled into Enclave.
  The platform never relies on the provider remaining reachable to prove what happened.
- Voiding an envelope cancels the workflow step and is audited with the reason.

### 6.8 Verification

```text
POST /api/v1/files/{id}/versions/{versionId}/verify-signature
```

Returns, per signature: signer identity, mode, signing time, timestamp authority, certificate chain
status, revocation status at signing time, algorithm, whether the document has been modified since,
and which byte ranges each signature covers.

Verification is performed against embedded LTV material first, falling back to live OCSP/CRL. A
verification result is cached with the version and re-computed when trust anchors change.

The UI states results plainly: **Valid**, **Valid (signed by an unrecognized authority)**,
**Invalid — document modified after signing**, or **Cannot verify** — never a bare green check that
means several different things.

### 6.9 Security properties

| Threat | Control |
|---|---|
| Signing a different document than displayed | Byte hash sealed at prepare; presentation renders those exact bytes; hash re-verified before signature application |
| Signature link forwarded to a third party | Tokens are single-purpose, per-signer, short-lived, IP/device-recorded, and invalidated on completion |
| Replay of a completed signing link | Single-use; a used token returns a completed state, never a new ceremony |
| Post-signature tampering | Incremental updates plus verification; any byte change outside the signed increments is reported |
| Repudiation | Authentication evidence, consent text version, IP/device, timestamps, and an independently verifiable cryptographic signature |
| Provider outage or discontinuation | Signed artifact and audit certificate are stored locally; verification does not require the provider |
| Insider modifying the audit trail | Signature events live in the append-only, hash-chained audit log (`04-DATA-MODEL.md §14`) |
| Signer coercion by a workflow author | Self-approval denied by default; separation of duties enforced per definition |

### 6.10 Honest limits

The platform cannot verify that the human at the keyboard is the person named — it verifies the
authentication factors presented. Assurance rises with the mode: an OTP to a corporate address is not
an ID check, and neither is a drawn signature image. Legal enforceability depends on jurisdiction
(eIDAS, ESIGN/UETA, India's IT Act and DSC requirements), and the product surfaces the mode and
evidence so counsel can judge it — it does not assert legal validity on their behalf.

---

## 7. Data model

Defined here as an extension of `04-DATA-MODEL.md`; the conventions in `04 §1` apply.

```sql
CREATE TABLE workflow_definitions (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    scope_type    TEXT NOT NULL CHECK (scope_type IN ('TENANT','WORKSPACE','LIBRARY')),
    scope_id      UUID,
    name          TEXT NOT NULL,
    version       INT NOT NULL,
    definition    JSONB NOT NULL,          -- stages, steps, assignees, policies
    trigger       JSONB NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    allow_self_approval BOOLEAN NOT NULL DEFAULT FALSE,
    created_by    UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, scope_type, scope_id, name, version)
);

CREATE TABLE workflow_instances (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    definition_id  UUID NOT NULL,
    definition_version INT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_id    UUID NOT NULL,
    version_id     UUID,
    state          TEXT NOT NULL CHECK (state IN ('DRAFT','RUNNING','COMPLETED','REJECTED','CANCELLED','EXPIRED')),
    current_stage  INT NOT NULL DEFAULT 0,
    started_by     UUID NOT NULL,
    started_at     TIMESTAMPTZ NOT NULL,
    due_at         TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    outcome_reason TEXT,
    revision       BIGINT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, definition_id, resource_id, version_id)   -- idempotent triggering
);
CREATE INDEX idx_wf_open ON workflow_instances (tenant_id, state, due_at) WHERE state = 'RUNNING';

CREATE TABLE workflow_steps (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    instance_id   UUID NOT NULL,
    stage         INT NOT NULL,
    position      INT NOT NULL,
    step_type     TEXT NOT NULL CHECK (step_type IN ('APPROVAL','REVIEW','SIGNATURE','TASK','AUTOMATION','CONDITION')),
    assignee_id   UUID,
    assignee_type TEXT,
    delegated_to  UUID,
    state         TEXT NOT NULL CHECK (state IN ('PENDING','ASSIGNED','APPROVED','REJECTED','SIGNED','DECLINED','SKIPPED','EXPIRED')),
    decision_at   TIMESTAMPTZ,
    comment       TEXT,
    due_at        TIMESTAMPTZ,
    config        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_wf_step_assignee ON workflow_steps (tenant_id, assignee_id, state) WHERE state = 'ASSIGNED';

CREATE TABLE signature_requests (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    file_id         UUID NOT NULL,
    version_id      UUID NOT NULL,
    workflow_step_id UUID,
    mode            TEXT NOT NULL CHECK (mode IN ('ACKNOWLEDGEMENT','ELECTRONIC','DIGITAL_PLATFORM','DIGITAL_SIGNER_CERT','EXTERNAL_PROVIDER')),
    provider        TEXT,
    provider_ref    TEXT,
    sealed_sha256   TEXT NOT NULL,           -- bytes presented and signed
    signing_order   TEXT NOT NULL CHECK (signing_order IN ('PARALLEL','SEQUENTIAL')),
    state           TEXT NOT NULL CHECK (state IN ('PREPARING','SENT','PARTIALLY_SIGNED','COMPLETED','DECLINED','VOIDED','EXPIRED','FAILED')),
    signed_version_id UUID,                  -- new version holding the signed artifact
    expires_at      TIMESTAMPTZ,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ
);
CREATE INDEX idx_sig_open ON signature_requests (tenant_id, state, expires_at)
    WHERE state IN ('SENT','PARTIALLY_SIGNED');

CREATE TABLE signature_participants (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    request_id      UUID NOT NULL,
    position        INT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('SIGNER','APPROVER','WITNESS','CC')),
    user_id         UUID,
    guest_id        UUID,
    email           TEXT NOT NULL,
    auth_requirement TEXT NOT NULL CHECK (auth_requirement IN ('SESSION','MFA','OTP_EMAIL','OTP_SMS','ID_VERIFICATION','CERTIFICATE')),
    token_hash      TEXT,
    state           TEXT NOT NULL CHECK (state IN ('PENDING','NOTIFIED','VIEWED','SIGNED','DECLINED','EXPIRED')),
    auth_method     TEXT,
    auth_strength   TEXT,
    consent_version TEXT,
    consented_at    TIMESTAMPTZ,
    signed_at       TIMESTAMPTZ,
    decline_reason  TEXT,
    ip              INET,
    country         TEXT,
    device_id       UUID,
    user_agent      TEXT,
    UNIQUE (tenant_id, request_id, position)
);

CREATE TABLE signature_artifacts (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    request_id     UUID NOT NULL,
    participant_id UUID,
    format         TEXT NOT NULL CHECK (format IN ('PADES','CADES','XADES','PROVIDER_CERTIFICATE')),
    object_key     TEXT NOT NULL,
    signer_subject TEXT,
    issuer         TEXT,
    serial_number  TEXT,
    algorithm      TEXT NOT NULL,
    signed_at      TIMESTAMPTZ NOT NULL,
    tsa_url        TEXT,
    timestamp_at   TIMESTAMPTZ,
    ltv_embedded   BOOLEAN NOT NULL DEFAULT FALSE,
    last_verified_at TIMESTAMPTZ,
    last_verify_result JSONB,
    created_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE signing_certificates (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    label         TEXT NOT NULL,
    subject       TEXT NOT NULL,
    issuer        TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    not_before    TIMESTAMPTZ NOT NULL,
    not_after     TIMESTAMPTZ NOT NULL,
    key_ref       TEXT NOT NULL,             -- KeyProvider / HSM reference, never a key
    usage         TEXT NOT NULL CHECK (usage IN ('DOCUMENT_SIGNING','SEAL','TIMESTAMP')),
    state         TEXT NOT NULL CHECK (state IN ('ACTIVE','EXPIRING','REVOKED','RETIRED')),
    created_at    TIMESTAMPTZ NOT NULL
);
```

Certificate expiry is alerted at 60 and 30 days — a signing certificate that lapses silently stops
every signing workflow in the tenant.

## 8. API

Endpoint contracts are registered in `05-API.md §16` — the authoritative place for wire formats.
Two constraints belong to this document rather than that one:

- **Signer endpoints (`/sign/{token}`) are the only endpoints not authenticated by a bearer access
  token.** The signing token is single-purpose, single-document, single-use and short-lived.
- **`POST /files/{id}/signature-requests` seals the byte hash.** Everything downstream — presentation,
  consent, signature application — verifies against that seal, and a mismatch aborts with
  `DOCUMENT_MODIFIED_SINCE_SEAL`.

## 9. Events

| Subject | Emitted when |
|---|---|
| `workflow.started` / `workflow.completed` / `workflow.rejected` | Instance transitions |
| `workflow.step.assigned` / `.decided` / `.escalated` | Step transitions |
| `signature.requested` | Request sent |
| `signature.viewed` / `.signed` / `.declined` | Per participant |
| `signature.completed` | All signers done, artifact committed |
| `signature.voided` / `.expired` | Terminal without completion |
| `signature.verification.failed` | Scheduled re-verification found a problem |

`signature.completed` drives filing: retention application, record declaration, indexing,
notification and any downstream workflow stage.

## 10. Interaction with the rest of the platform

| Area | Interaction |
|---|---|
| **Versions** | Signing targets an immutable version; output is a new version. Signed versions are protected from deletion by policy |
| **Records** | A completed signature may auto-declare a record with `immutable_until` |
| **Legal hold** | A hold blocks voiding and deletion of signed artifacts and their evidence |
| **DLP** | Runs at prepare (is this document allowed to leave for an external signer?) and at completion |
| **Classification** | Gates which signing modes and providers are permitted |
| **Conditional access** | Signer authentication is subject to network/device policy like any other action |
| **Search** | Signed artifacts index normally; signature status is a filterable facet |
| **Sync** | A signature request in flight does not block sync of the base version; the signed version syncs on completion subject to normal eligibility |
| **Audit** | Every step and every signature event is audited into the hash-chained log |
| **i18n** | Signer-facing text, consent language and reminders render in the recipient's locale |

## 11. UX requirements

- **Task inbox** — one place for everything awaiting the user: approvals, reviews, signatures. Bulk
  approve is permitted only for `REVIEW` and low-risk `APPROVAL` steps, never for signatures.
- **Progress is legible** — a stage/step tracker showing who is next, who is late, and what happens
  on rejection.
- **Signing view is unambiguous** — the exact document, the exact fields, an explicit consent step,
  and a plain statement of what mode is being used and what it means.
- **No dark patterns.** Decline is as prominent as sign. Consent is not pre-checked.
- **Verification is visible** — an open signed document shows its signature panel with the plain
  result from `§6.8`.
- **Mobile signing works**, including a touch signature surface, because counterparties sign on
  phones more often than not.

## 12. Testing

Added to the matrix in `12-TESTING.md §4`:

| # | Assertion |
|---|---|
| W1 | A workflow cannot grant an actor access they do not independently hold |
| W2 | Self-approval is rejected unless explicitly enabled |
| W3 | A new version invalidates in-flight approvals by default |
| W4 | Duplicate trigger events create exactly one instance |
| W5 | Automation steps cannot invoke anything outside the allowlist |
| N1 | The bytes presented to the signer hash to `sealed_sha256`; a mismatch aborts |
| N2 | A signing token is single-use, single-document and expires |
| N3 | A signature link forwarded to another authenticated user is refused |
| N4 | Modifying a byte of a signed artifact makes verification report `DOCUMENT_MODIFIED` |
| N5 | A private key is never transmitted to the server in `DIGITAL_SIGNER_CERT` mode |
| N6 | A `RESTRICTED` document is not sent to a non-permitted external provider |
| N7 | Verification succeeds offline from embedded LTV material with the provider unreachable |
| N8 | Sequential ordering is enforced; signer 2 cannot sign before signer 1 |
| N9 | Declining terminates the request and the workflow step, with the reason audited |
| N10 | An expired signing certificate blocks new requests and alerts, and does not invalidate past signatures |
