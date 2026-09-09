# Completion — what stands between this and a working product

> **Status:** Living · **Version:** 1.0 · **Owner:** Engineering · **Last updated:** 2026-09-10
> **Authoritative for:** nothing. This is an index. Each item's contract lives in the document
> `docs/README.md §1` makes authoritative for it, and each item's status lives in `TRACKER.md`.

## 1. Why this document exists

`ROADMAP.md` says when. `TRACKER.md` says what is in flight. Neither answers the question a person
actually asks — **can somebody use this?** — because both are organised by milestone, and a
milestone can close with a flow half-built.

The standard here is deliberately harsher than either: **a feature is complete when a person can
finish the task it exists for, end to end, without hitting a wall.** Not when its crate has tests.
Not when its endpoint returns `200`. Not when its milestone is ticked.

By that standard the product is **not complete**, and the gap is not small. This document is the
whole of it, in one place, ordered.

## 2. Flows a user starts and cannot finish

These are the worst category, because the product *appears* to support them. A half-built flow is
worse than an absent one: it spends the user's time before failing.

| Flow | Where the wall is | Row |
|---|---|---|
| **Share a file with someone outside the tenant** | The link is created, listed, amended and revoked. `GET /shares/{token}` is not registered, so **the recipient cannot open it.** | `ENC-692`, blocked on `ENC-694`, `ENC-896` |
| **Upload a file over 16 MiB** | Refused at session creation: `declared_sha256` is mandatory and no S3 multipart checksum is the whole-object digest. | `ENC-829` |
| **Edit a document's properties** | The fields and values are readable. Nothing can write one. | `ENC-996` |
| **Sign in with a corporate identity** | No OIDC, no SAML, no SCIM, no passkeys. Password only. | M6 |
| **Verify a token this product issued** | `/.well-known/jwks.json` is documented and unserved, so no external relying party can. | `ENC-997` found it |
| **Find a scanned document by its content** | Works — *if* an operator staged OCR models the licence does not let us ship. | `ENC-161` |

## 3. Subsystems that are a doc comment

Twelve crates contain a module header and no code. Everything each one names is absent.

| Crate | What is missing | Milestone |
|---|---|---|
| `signing` | The entire e-signature product — PAdES/CAdES, TSA, the signer ceremony, 13 endpoints | M9 |
| `mcp` | `/mcp`, every tool in `docs/05 §15`'s table — the AI access story | M7 |
| `ai` | LLM providers, `/search/answer`, `/search/suggest` | M7 |
| `lists`, `pages` | Two of the four content types the product claims | M8 |
| `records`, `legal_hold` | Two mandatory stages of the governance chain | M6 |
| `incidents` | The security incident lifecycle. EICAR raises a log line, not a record | M6 |
| `notifications`, `mail` | Nobody is ever told anything | M6 |
| `branding` | Tenant branding and custom domains, half of the white-label promise | M8 |
| `secrets` | Vault and cloud secret managers; only `env://` and `file://` resolve | M6 |

## 4. Controls that cannot refuse

`CLAUDE.md` rule 2 fixes the policy chain's order. Two of its stages are allow-all, so two rules the
product advertises are not enforced anywhere:

- **information barriers** — `UnconfiguredBarriers` returns `allow()` and an empty token set.
- **classification** — `UnconfiguredClassification`; no ceiling restricts any action, and `NO_INDEX`
  cannot be set on anything.

The `enterprise` deployment profile refuses to boot while either is inert, which is the honest
behaviour and also means **no enterprise deployment can start today**.

## 5. Nowhere to run it

`docs/11 §2` names four environments. `dev` and `ci` exist. `staging` is a single-node compose stack
(`ENC-993`) with no WAL archive, no replica, no ingress and no secret manager, so `docs/11 §4`'s
RPO ≤ 5 min and RTO ≤ 4 h cannot be demonstrated on it. `production` does not exist.

No k6 harness (`docs/12 §6`), no chaos harness (`§7`), no `proptest`, no `testcontainers` — four of
the eight rows in `§2`'s own test pyramid describe tooling that is not in the tree, which `§2` says
about itself.

## 6. Things no amount of code closes

Named because they set the date, not because they are optional:

- an **external penetration test** — scheduling, execution, remediation, retest;
- a **restore drill**, which needs `§5`;
- a **screen-reader pass** on NVDA and VoiceOver, by a person;
- an **operator who has never seen the repo** installing from `README`.

## 7. The order, and why

Dependency-driven, not value-driven — several items are cheap only if something else lands first.

1. **Finish the started flows** (`§2`). A user hitting a wall in a feature that looks present is the
   worst defect class here, and three of the six are already in flight.
2. **Governance stages** (`§4`) — `records`, `legal_hold`, `incidents`, classification ceilings,
   barriers. They unblock **ten** of `docs/12 §4`'s deferred matrix rows and the `enterprise`
   profile, and `ENC-999`'s exception list retires as they land.
3. **Identity** — SSO, SCIM, passkeys, JWKS. Everything enterprise is downstream.
4. **Deployment** (`§5`), because `§6` cannot start without it.
5. **Content types and delivery** — lists, pages, branding, notifications, mail.
6. **AI and signing** — the two largest, and the two with external counterparties (a TSA, a
   certificate authority) whose lead time is not ours.

## 8. How each item is finished

The same bar every time, because it is the bar that made the difference on the items already done:

- the flow works against the **real** binary and a real database — not a fixture, not a unit test;
- every new assertion is **watched to fail** (`docs/12 §1.2`), and a rule-7 test carries its
  positive control in the same test;
- the authoritative document is updated, and `docs/05 §0`'s table stops saying "not built";
- the leakage-matrix rows it unblocks are cited and, where they were deferred, retired from
  `matrix_coverage.py`'s `DEFERRED` list;
- `TRACKER.md`'s row, the rollup and the log move in the same edit.
