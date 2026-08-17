# 13 — Identity, SSO & Provisioning

> **Status:** Draft · **Version:** 1.0 · **Owner:** Identity Engineering · **Last updated:** 2026-08-18
> **Authoritative for:** authentication protocols, federation, directory sync, SCIM, guest identity, deprovisioning.

## 1. Separation of concerns

Three things enterprises routinely conflate, kept distinct here:

| Concern | Question | Mechanism |
|---|---|---|
| **Authentication** | Who is this, right now? | Password, OIDC, SAML, WebAuthn, client credentials |
| **Provisioning** | Who exists, and in which groups? | Local, LDAP sync, SCIM, JIT |
| **Authorization** | What may they do? | Roles and ACLs (`04-DATA-MODEL.md §9`) |

A user may be provisioned by SCIM, authenticate via SAML, and be authorized entirely by local roles.
Changing one must not require changing the others.

Every external identity resolves to a stable internal `UserId`. External identifiers change —
people marry, domains migrate, IdPs get replaced — and internal references must not break when they
do. `identity_links` holds the mapping (`04-DATA-MODEL.md §5`).

## 2. Authentication methods

| Method | Use | Notes |
|---|---|---|
| Local password | Small deployments, break-glass | Argon2id, breach checks, lockout |
| OIDC | Primary SSO for modern IdPs | Authorization code + PKCE |
| SAML 2.0 | Enterprises standardized on SAML | SP-initiated and IdP-initiated |
| LDAP/AD bind | On-prem directories without a federation layer | Bind against the directory |
| WebAuthn/passkeys | Phishing-resistant first or second factor | Required for privileged admins |
| API token | Scripts, integrations | Scoped, expiring, revocable |
| Client credentials | Service accounts, MCP clients | OAuth2, no refresh token |

All of them terminate in the same place: an access token as specified in `03-LLD.md §5`. There is no
second session model for federated users.

## 3. OIDC

### 3.1 Flow

Authorization Code with PKCE (S256). Implicit and hybrid flows are not supported.

```text
/auth/oidc/{provider}/start
  -> state (signed, 10 min TTL) + nonce + code_verifier stored server-side against the state
  -> redirect to IdP authorization endpoint
IdP
  -> /auth/oidc/{provider}/callback?code=…&state=…
  -> validate state, exchange code (with code_verifier) at the token endpoint
  -> validate ID token: iss, aud, exp, iat, nonce, azp; signature against cached JWKS
  -> resolve or provision the user
  -> issue platform access + refresh tokens
```

Validation rules that are non-negotiable: `iss` must match exactly, `aud` must contain the configured
client ID, `nonce` must match the one issued, the signature must verify against a `kid` present in
the cached JWKS (refreshed on unknown `kid`, rate-limited to prevent a fetch storm), and clock skew
tolerance is 60 seconds.

### 3.2 Configuration

```yaml
identity:
  oidc:
    - key: "corp-entra"
      display_name: "Company SSO"
      enabled: true
      discovery_url: "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
      client_id: "…"
      client_secret:
        secret_ref: "vault://workspace/oidc#corp_entra_secret"
      scopes: ["openid", "profile", "email", "groups"]
      claims:
        subject: "sub"
        email: "email"
        display_name: "name"
        groups: "groups"
        department: "department"
      jit_provisioning: true
      allowed_email_domains: ["company.com", "company.co.in"]
      group_mapping:
        "Vault-Admins": "role:tenant-admin"
        "Vault-Security": "role:security-admin"
        "Engineering": "group:engineering"
      acr_values_for_mfa: ["mfa", "urn:...:multifactor"]
      logout:
        rp_initiated: true
```

### 3.3 Claim-based MFA

When the IdP asserts MFA (`acr`/`amr`), the platform accepts it and stamps its own `acr: "mfa"`.
When it does not, and policy requires MFA, the platform enforces its own second factor rather than
assuming. Trusting an unverified claim is the common failure here, so `acr_values_for_mfa` is an
explicit allowlist — an unlisted value never satisfies an MFA requirement.

## 4. SAML 2.0

Supports SP-initiated and IdP-initiated SSO, with metadata exchange in both directions
(`/auth/saml/{provider}/metadata`).

Assertion validation:

- signature over the assertion (and/or response) verified against the configured IdP certificate —
  **signature required**, never optional;
- `Destination`, `Recipient` and `Audience` match this SP;
- `NotBefore` / `NotOnOrAfter` within tolerance;
- `InResponseTo` matches an outstanding request for SP-initiated flows;
- assertion ID cached to reject replay for the assertion's validity window;
- XML parsing hardened against XSW (signature wrapping), XXE and entity expansion — the parser
  resolves no external entities and validates that the signed element is the one consumed.

Encrypted assertions are supported; the SP decryption key is a `KeyProvider` reference. Certificate
rotation supports two active IdP certificates so a rollover does not require a maintenance window.
Single Logout (SLO) is supported where the IdP implements it; where it does not, logout revokes
locally and says so.

## 5. LDAP / Active Directory

Two independent capabilities, configured separately:

- **Bind authentication** — validate credentials directly against the directory.
- **Directory sync** — import users and groups on a schedule.

Configuration is in `08-BYO-INFRA.md §16`. Behavioral rules:

- **Paged searches** for large directories; a directory with 100 000 users must not require one
  unbounded query.
- **Incremental sync** using `uSNChanged` (AD) or `modifyTimestamp`, with a periodic full
  reconciliation to catch deletions.
- **Nested groups** resolved to a configured depth (default 8), with cycle detection.
- **Stable identifiers**: `objectGUID`/`entryUUID`, never DN — a user moving OU must not become a new
  person.
- **Deprovision safety**: `deprovision_action` defaults to `SUSPEND`. A sync that would deactivate
  more than a configured share of the tenant (default 10%) aborts and raises an alert instead —
  the classic failure mode is an LDAP filter typo silently disabling an entire company.
- **TLS**: `ldaps` or StartTLS with certificate verification on by default; disabling it requires an
  explicit acknowledgement recorded in `config_versions`.

## 6. SCIM 2.0

The platform is a SCIM **service provider** at `/admin/scim/v2`, authenticated with a dedicated
bearer token scoped to provisioning only.

| Resource | Operations |
|---|---|
| `/Users` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, filtering on `userName`, `externalId`, `emails` |
| `/Groups` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, membership `PATCH` operations |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | Discovery |
| `/Bulk` | Optional, bounded batch size |

Behavior:

- `active: false` **suspends**; it does not delete. `DELETE` soft-deletes and starts the retention
  clock. Content ownership is never destroyed by a provisioning event.
- `externalId` is the durable key; `userName` may change.
- `PATCH` implements RFC 7644 path semantics including `members` add/remove without a full replace,
  because a full replace on a 10 000-member group is both slow and lossy under concurrency.
- Enterprise user extension attributes (`department`, `manager`, `employeeNumber`) are mapped to
  local fields and are available as DLP and conditional-access conditions.
- Every SCIM mutation writes an audit event attributed to the provisioning client.
- Rate limits are separate from user API limits, so an IdP's nightly sync cannot exhaust a tenant's
  interactive budget.

Errors follow SCIM's own format (`urn:ietf:params:scim:api:messages:2.0:Error`), not the platform
error envelope — IdPs are strict about this.

## 7. Just-in-time provisioning

When enabled, a successful federated authentication for an unknown subject creates a user, subject to:

- the email domain being in `allowed_email_domains`;
- seat quota headroom (`04-DATA-MODEL.md §16`);
- group mapping applied from asserted claims;
- default role assignment from provider configuration.

JIT and SCIM can coexist: SCIM is authoritative for attributes and membership when both are active,
and JIT only fills the gap for a user who authenticates before the sync has reached them.

## 8. Group and role mapping

Mapping rules translate external groups into internal groups and roles:

```yaml
group_mapping:
  "Vault-Admins":    "role:tenant-admin"
  "Vault-Security":  "role:security-admin"
  "Finance-All":     "group:finance"
  "*-Contractors":   "group:external-partners"     # glob supported
```

Rules:

- mapping is **additive** by default; a user's manually assigned local groups survive a sync unless
  `strict_mapping: true`, which makes the IdP fully authoritative;
- privileged roles granted by mapping still require MFA to exercise (`06-SECURITY-DLP-ACCESS.md §22`);
- a mapping change is a security-sensitive configuration change: versioned, diffed, audited, and it
  reports how many users it will affect before it is applied;
- removal of a mapped group bumps affected users' `token_epoch`, so lost privileges take effect
  immediately rather than at token expiry.

## 9. Guests and external identity

Guests are first-class principals with their own lifecycle (`04-DATA-MODEL.md §5`):

- invited by email, optionally requiring approval;
- authenticate via their own IdP (federated guest), a local guest credential, or a share-link OTP;
- always time-bounded — `expires_at` is mandatory, with a tenant default (90 days);
- restricted by default: no directory browsing, no member enumeration, no search outside explicitly
  shared resources;
- reviewable — admins get a periodic guest access review listing guests, what they can reach, and
  when they last used it.

## 10. Service accounts and MCP clients

Both authenticate with OAuth2 client credentials and receive an access token with no refresh token.
Distinctions:

| | Service account | MCP client |
|---|---|---|
| Scopes | API scopes | MCP tool scopes |
| Classification ceiling | Optional | Required |
| Write capability | By scope | Off by default (`write_tools_enabled`) |
| Workspace restriction | Optional allowlist | Optional allowlist |
| Rate limits | Per-account profile | Per-client profile |

Client secrets are hashed at rest, shown once at creation, rotatable with an overlap window, and
their use is audited with the calling IP.

## 11. Authentication policy

Per-tenant configuration:

- which methods are enabled, and whether local password login is disabled entirely once SSO is
  mandatory (with a break-glass exception, `11-OPERATIONS.md §5.6`);
- session lifetimes (`08-BYO-INFRA.md §15`);
- MFA requirements by role, with phishing-resistant factors required for privileged roles;
- step-up requirements per action class;
- account lockout thresholds and unlock policy;
- allowed email domains for invitations.

## 12. Deprovisioning and offboarding

The full sequence, triggered by SCIM `active: false`, LDAP absence, or a manual admin action:

```text
1. users.status = SUSPENDED
2. token_epoch bumped        -> every access token invalid immediately
3. refresh families revoked  -> no silent renewal
4. sync devices revoked and wipe requested
5. editor sessions terminated, locks released
6. share links created by the user flagged for review (not auto-revoked — that breaks partners)
7. owned content reassigned per policy, or retained under the departing user's ID
8. audit event recording the trigger and the actor
```

Content is never deleted by offboarding. Retention and legal hold govern deletion; provisioning does
not.

## 13. Failure behavior

| Condition | Behavior |
|---|---|
| IdP unreachable | Federated login fails with a clear message; existing tokens remain valid until expiry; local break-glass still works |
| JWKS fetch fails | Cached keys used within TTL; unknown `kid` rejected rather than trusted |
| LDAP sync fails | Previous state retained; alert raised; no bulk deactivation |
| SCIM token expired | `401` in SCIM format; IdP retries; admin alerted |
| Clock skew | 60 s tolerance; beyond that, reject and log — do not widen the window |
| Mass-deactivation guard trips | Sync aborts, nothing applied, alert with the proposed diff |

## 14. Testing

Covered by `12-TESTING.md §4.6`, plus identity-specific cases: SAML signature-wrapping (XSW1–XSW8)
rejection, XXE rejection, assertion replay rejection, OIDC `nonce`/`state` mismatch rejection,
algorithm-confusion rejection, SCIM `PATCH` membership semantics under concurrency, and the
mass-deactivation guard firing on a deliberately broken LDAP filter.
