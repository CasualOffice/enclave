# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately to **security@casualoffice.org**, or through GitHub's private vulnerability
reporting on [`casualoffice/enclave`](https://github.com/casualoffice/enclave/security/advisories/new).

Please include:

- what the issue is, and which component or endpoint it affects;
- steps to reproduce, or a proof of concept;
- the impact you believe it has — data exposure, privilege escalation, denial of service;
- the version, commit or deployment profile you tested against;
- whether the issue is already public anywhere.

Encrypt sensitive reports with the PGP key published at
[`casualoffice.org/.well-known/security.txt`](https://casualoffice.org/.well-known/security.txt).

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 2 business days |
| Initial assessment and severity | 5 business days |
| Fix or documented mitigation, critical/high | 30 days |
| Fix or documented mitigation, medium/low | 90 days |
| Public disclosure | Coordinated, after a fix ships |

We will keep you updated as the assessment progresses, credit you in the advisory unless you prefer
otherwise, and tell you plainly if we disagree that something is a vulnerability — with the
reasoning, not a dismissal.

We support coordinated disclosure and ask for a reasonable window before publication. We will not
pursue legal action against good-faith research that respects the scope below.

## Scope

**In scope**

- Cross-tenant data access of any kind.
- Authentication and authorization bypass, including token forgery, replay, refresh-rotation defeat
  and privilege escalation.
- Any leak through a derived surface: search, RAG answers, MCP tools, previews, sync, exports,
  webhooks.
- Bypass of preview/download separation, DLP enforcement, classification ceilings, information
  barriers, retention or legal hold.
- Signature forgery, or signing a document other than the one presented to the signer.
- Injection, SSRF, XXE, deserialization and path traversal.
- Audit tampering or evasion.
- Secrets exposure in logs, traces, errors, exports or configuration output.

**Out of scope**

- Findings that require a compromised device already under the attacker's control.
- Screenshot or photograph capture of previewed content — a limit we state openly rather than claim
  to solve ([`docs/06-SECURITY-DLP-ACCESS.md §5.2`](docs/06-SECURITY-DLP-ACCESS.md)).
- Rate-limit tuning opinions without a demonstrated impact.
- Missing hardening headers with no exploitable consequence.
- Automated scanner output without a working proof of concept.
- Social engineering of maintainers or users.
- Denial of service through raw traffic volume.

## Supported versions

| Version | Supported |
|---|---|
| Latest minor of the current major | Yes |
| Previous minor | Security fixes only, 6 months |
| Older | No |

Self-hosted deployments are responsible for applying releases. Advisories are published with a
severity, affected versions, the fix version and any available mitigation.

## Security design

Enclave’s security model, threat model and controls are documented rather than implied:

- [`docs/06-SECURITY-DLP-ACCESS.md`](docs/06-SECURITY-DLP-ACCESS.md) — threat model, conditional
  access, DLP, antivirus, renditions, privileged operations.
- [`docs/04-DATA-MODEL.md §3`](docs/04-DATA-MODEL.md) — two-layer tenant isolation.
- [`docs/07-SEARCH-INDEXING.md §6`](docs/07-SEARCH-INDEXING.md) — how permission changes are
  guaranteed to reach search.
- [`docs/12-TESTING.md §4`](docs/12-TESTING.md) — the permanent leakage-test matrix. If you find a
  gap in that matrix, that itself is a finding worth reporting.

## For operators

If you run Enclave, the deployment-side security checklist is in
[`docs/11-OPERATIONS.md`](docs/11-OPERATIONS.md): key rotation, backup verification, audit-chain
verification, break-glass handling and incident response.

Two operator mistakes cause most real-world incidents in systems like this: a publicly readable
storage bucket, and an antivirus or audit setting disabled "temporarily". The `enterprise` deployment
profile refuses to start in either state — do not work around that check.
