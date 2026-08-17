# M1 — Content Core · Implementation Plan

> Enclave · Phase 1 · 6 weeks planned · Tracker: `ENC-119` … `ENC-14x`
> Roadmap: [`ROADMAP.md §5`](../ROADMAP.md) · Preceded by [`G0-GATE.md`](G0-GATE.md)

---

## 1. Objective

**Content can be stored and versioned safely, and nothing is readable before it is scanned.**

M0 built the constraints. M1 is the first work that lives inside them, which makes it the first real
test of whether they are usable rather than merely correct.

### Exit criteria (from the roadmap — may not be weakened here)

- [ ] 5 GB resumable upload with flat API memory.
- [ ] Version rows reject mutation of `object_key`, `checksum`, `size`, `major`, `minor`.
- [ ] EICAR upload → `QUARANTINED`, unreadable through every path, incident raised (G1).
- [ ] AV down with `HOLD` → versions wait in `SCANNING`, existing content unaffected (G6).
- [ ] Sibling name collision rejected by constraint, not by application check alone.

Plus the condition carried from G0:

- [ ] **Criterion 1 of M0 fully met**: one real request traverses login → JWT → `enforce` →
      tenant-scoped query → audit row.

---

## 2. Sequencing, and why it opens this way

### 2.1 First: close the G0 conditions

Two tasks before any content work, in this order.

**`ENC-119`…`ENC-123` — the five dependency majors.** `jsonwebtoken 9→11`, `ed25519-dalek 2→3`,
`rand 0.8→0.10`, `sqlx 0.8→0.9`, `ipnetwork 0.20→0.21`. They land first because the quantity of
code depending on them only increases: `sqlx 0.9` touches every query in the workspace, and doing it
after M1 means revisiting every repository written in between. Three of the five are cryptographic
or data-layer dependencies, where staying current is itself a control.

Order within the batch: `ipnetwork` and `rand` first (smallest blast radius, builds confidence in
the process), then `ed25519-dalek` and `jsonwebtoken` together since both touch token signing, then
`sqlx` alone because it touches everything.

**`ENC-124` — one endpoint, end to end.** `GET /api/v1/me`, wired through the real chain:
authenticate the JWT, build a `RequestContext`, call `PolicyEngine::enforce`, run a `TenantScoped`
query, emit an audit row, return the response. Deliberately trivial as a *feature* and deliberately
complete as a *path*.

This is the first time the M0 components meet. Expect it to surface friction that unit tests could
not: how a handler obtains the engine, where the tenant comes from on a custom domain, what the
error mapper does with `Error::PolicyDenied`, whether the audit sink's transaction is the same one
the query used. Better discovered on an endpoint that returns a user's own name than on the upload
path.

It also flips the policy-routing lint from "0 handlers, nothing to check" to actually checking
something, which is the first evidence that gate does what it claims.

### 2.2 Then: content, in dependency order

| Order | Tracker | Work | Why here |
|---|---|---|---|
| 3 | `ENC-125` | Tenancy, users, groups, membership | Everything below needs principals |
| 4 | `ENC-126` | Real `AuthorizationService` — ACL resolution, inheritance, group closure, deny-wins | The first stub replaced by a real stage |
| 5 | `ENC-127` | Workspaces and libraries | The containers ACLs attach to |
| 6 | `ENC-128` | `BlobStore` — S3-compatible, public-access self-check | Needed before uploads, not during |
| 7 | `ENC-129` | Upload state machine, multipart, signed URLs | The 5 GB criterion |
| 8 | `ENC-130` | Files and folders, trash, move/copy | |
| 9 | `ENC-131` | Immutable versions, atomic commit, restore | |
| 10 | `ENC-132` | `AntivirusScanner` + ClamAV, quarantine | Gates availability; must precede any read path |
| 11 | `ENC-133` | Read paths: metadata, listing, cursor pagination | |
| 12 | `ENC-134` | Leakage matrix rows for everything above | Same PR as each surface, not batched |

`ENC-126` before `ENC-127` is deliberate. Building containers before the thing that decides who may
see them invites a temporary "everyone can read" shortcut, and temporary shortcuts in authorization
have a way of becoming permanent.

---

## 3. Design decisions to lock in M1

### D10 — Repository shape

Domain crates own their SQL and take a `&mut PgConnection` — never a pool. The caller supplies a
`TenantScoped` transaction, so a repository physically cannot run outside a tenant context, and the
no-raw-pool gate keeps it that way. This is the shape `events::Outbox::publish` and
`audit::record_in_tx` already use; M1 makes it the rule rather than a coincidence.

### D11 — Where the policy chain is called

**In the handler, before the domain service is reached.** Not inside repositories, and not inside
domain services. Two reasons: the routing lint can only verify what it can see from a route, and a
service called from both an HTTP handler and a worker would otherwise enforce twice or not at all.

Domain services are therefore *unauthorized by construction* — they assume the caller already
checked. That is safe only because the lint proves the caller did.

### D12 — Version immutability is enforced by the database

A trigger rejects `UPDATE` of `object_key`, `checksum_sha256`, `size_bytes`, `major`, `minor` on
`file_versions`. Application-level immutability is a convention; a trigger is a guarantee, and the
exit criterion says "reject", not "avoid".

### D13 — Availability is a state, not a flag

A version becomes readable only via the state machine in `docs/03 §15`, and every read path filters
on `status = 'AVAILABLE' AND av_status = 'CLEAN'`. No read path takes a boolean parameter that could
be passed wrongly. G1 and G6 are then properties of the query, not of remembering to check.

### D14 — Signed URLs are minted at the last moment

Never during listing, never speculatively, never cached. One URL per authorized request, short TTL,
single-use where the provider supports it — so a URL cannot outlive the decision that produced it.

---

## 4. Risks specific to M1

| Risk | Mitigation |
|---|---|
| `sqlx 0.9` migration is larger than expected | Land it alone, first, before more queries exist |
| ACL resolution is slow at depth | Benchmark `authorize_many` on 200 candidates during `ENC-126`, not after search needs it in M3 |
| The 5 GB upload buffers in memory | Assert flat RSS in the test rather than eyeballing it |
| ClamAV in CI is slow or flaky | EICAR only; no real signature database in the test path |
| Leakage matrix slips to "later" | Each surface's rows land in the same PR as the surface |

---

## 5. Definition of done

- [ ] Every M1 P1 is `DONE`.
- [ ] All five roadmap exit criteria demonstrated, plus the carried G0 condition.
- [ ] Leakage matrix sections 4.1 and 4.2 complete and green.
- [ ] The policy-routing lint reports a non-zero handler count, all passing.
- [ ] No test `#[ignore]`d without a written reason naming where it does run.
- [ ] Gate **G1** held: ship the MVP?

---

## 6. Open questions

| # | Question | Needs deciding by | Owner |
|---|---|---|---|
| Q5 | MinIO or LocalStack for S3 in CI? MinIO is already in the dev stack | Before `ENC-128` | Platform |
| Q6 | Does the audit row for a write share the write's transaction, or follow it? `docs/03 §15` says share; confirm the ordering under `record_in_tx` | Before `ENC-131` | Backend |
| Q7 | Trash retention default — 30 days, or tenant-configurable from day one? | Before `ENC-130` | Product |
