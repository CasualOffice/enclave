# M4 — a provenance walkthrough of one denial

> **Status:** Draft · **Version:** 1.0 · **Owner:** Engineering · **Last updated:** 2026-08-22

`plans/M4-GOVERNANCE.md §6` requires this, and says why it is a *provenance* walkthrough rather
than a threat one: M3's question was whether anything leaks, and M4's is whether the system refuses
**for the right reasons, with an audit trail**. That second clause is a claim about explainability,
and explainability is only demonstrable by taking one refusal and reading what it left behind.

So this document follows one HTTP request through the chain and out into `audit_events`, and then
follows a second one that the same system refuses **without** leaving a usable record. Both were
executed against a live PostgreSQL. Every transcript below is copied from the run, not composed.

It is written against the code, not the design. Where the trail is weaker than `CLAUDE.md` rule 10
implies, that is recorded here rather than smoothed over — and `§4` is the part that matters.

---

## 1. The denial that explains itself

### 1.1 Request in

`crates/api/tests/delivery.rs::preview_allowed_and_download_denied_yields_a_rendition_path_and_no_signed_url`,
run against a freshly migrated throwaway database:

```
DATABASE_URL=postgres://enclave:enclave@127.0.0.1:55432/enclave \
  cargo test -p enclave-api --test delivery preview_allowed_and_download_denied \
  -- --include-ignored
```

A `tenant-alpha` member holds `file.preview` = `ALLOW` and `file.download` = `DENY` on one file.
They send:

```
POST /api/v1/files/{file}/download
Authorization: Bearer <token for tenant-alpha, actor=member>
```

The tenant is taken from the verified token. Nothing in the body, the query string or a header can
change it (`CLAUDE.md` rule 3).

### 1.2 The stage that refused

`Authenticated::from_request_parts` builds the `RequestContext` — actor, session, client type,
resolved source address, device posture — and the handler's first act is
`PolicyEngine::enforce(&ctx, Action::File(FileAction::Download), &resource)`. It is not permitted to
be anything else: `xtask policy-routing` fails the build for a route handler with no reachable
`enforce`.

Inside the chain (`crates/core/src/engine.rs`):

1. **tenant isolation** — `ctx.tenant_id == resource.tenant_id`, so it proceeds;
2. `FactsSnapshot` is gathered **once**, before any stage (D26);
3. **conditional access** allows;
4. **authorization** resolves the ACL to `DENY` for `file.download` and returns
   `StageDecision::deny(ReasonCode::AccessDenied)`.

The chain short-circuits. Barriers, classification, DLP and retention never run — a later stage
cannot overwrite a refusal, and the caller learns nothing about controls they never reached.

### 1.3 Audit row out

The engine calls `record_deny(ctx, action, resource, Stage::Authorization, AccessDenied)` **before**
returning `Err`. `audit_events`, in write order, for the whole test:

```
seq=1 action=file.preview   outcome=ALLOW reason=None                 policy_refs=null
      detail=null  request_id=01a0297c-3f34-72a0-81f4-80342ba00997
seq=2 action=file.download  outcome=DENY  reason=Some("ACCESS_DENIED")
      policy_refs=[{"id":null,"kind":"authorization","version":null}]
      detail=null  request_id=01a0297c-3f8d-7260-be41-e35458d03cc8
seq=3 action=file.metadata_read outcome=ALLOW reason=None             policy_refs=null
      detail=null  request_id=01a0297c-3f8d-7260-be41-e35458d03cc8
```

Read row 2 as an investigator would. It answers all three of the questions an incident starts from:

| Question | Column | Value |
|---|---|---|
| Was it refused? | `outcome` | `DENY` |
| Why? | `reason_code` | `ACCESS_DENIED` — the same word the caller was given |
| By what? | `policy_refs` | `kind: authorization` |

The stage lives in `policy_refs`, which is **inside the canonically hashed bytes**
(`crates/audit/src/canonical.rs`), so which control refused is tamper-evident along with the fact of
the refusal. "Denied" without "by which control" is not something an investigation can work from,
and it is the field that a mock-based test cannot prove is present — see `§3`.

### 1.4 The third row, which is the interesting one

Rows 2 and 3 share a `request_id`. One HTTP request produced **two** chain evaluations, and the
second is why the caller received `403` rather than `404`.

`crates/api/src/download.rs::sharpen` exists because the chain deliberately collapses *explicitly
denied* and *never granted* into one `ACCESS_DENIED`, and that code alone tells a caller nothing
about whether the resource exists. So the edge asks one further question **through the same chain
and nothing else**: may this caller read the file's metadata? Row 3 says yes, so the caller already
knows the file exists and gets the actionable `403`. Had row 3 been a `DENY`, the response would
have been `404` and the caller would have learned nothing (`CLAUDE.md` rule 7, `docs/12 §4.1` T1).

This is provenance working as intended: the disambiguation that decides the *status code* is itself
a policy decision, and it is in the trail rather than being a side effect of one. An auditor asking
"why did this user see a 403 rather than a 404" can answer it from the table.

---

## 2. The denial that does not explain itself

The same walkthrough, on the request `plans/M4-GOVERNANCE.md §6` actually names — *request in, stage
that refused, **obligation raised**, audit row out*.

### 2.1 Request in

`crates/api/tests/delivery.rs::a_no_download_obligation_refuses_before_any_url_is_generated`, same
command, same fixture, one difference: the ACL **allows** `file.download`, and the DLP stage attaches
`Obligation::NoDownload` instead of refusing. This is the shape `docs/01-PRD.md §18` describes when
the restriction comes from DLP rather than from an ACL.

### 2.2 What happened

1. Every stage allowed. DLP returned `StageDecision::allow_with([NoDownload])`.
2. The engine merged the obligations and called `record_allow`.
3. `enforce` returned `Ok(PolicyDecision)` carrying `NO_DOWNLOAD`.
4. `crates/api/src/download.rs::satisfy` matched the obligation, could not satisfy it on a path
   whose entire output is a signed URL to the original bytes, and returned
   `Error::denied(ReasonCode::PreviewOnly)`.
5. The caller received **`403 PREVIEW_ONLY`**, and no URL was minted — asserted directly against the
   store, which recorded no touch.

Steps 1–4 are all correct. `CLAUDE.md` rule 8 requires exactly this: an obligation is satisfied or
the operation fails, never dropped. The refusal is the control working.

### 2.3 Audit row out

```
seq=1 action=file.download outcome=ALLOW reason=None policy_refs=null
      detail={"obligations":["{\"type\":\"NO_DOWNLOAD\"}"]}
      request_id=01a0297b-d11c-7e62-97d7-edb6d0698495
seq=2 action=file.preview  outcome=ALLOW reason=None policy_refs=null
      detail={"obligations":["{\"type\":\"WATERMARK\"}"]}
      request_id=01a0297b-d19f-7f01-9ee3-b618cc78271f
```

**The request that returned `403` is recorded as `ALLOW`.** There is one row for it and its outcome
is the opposite of what happened. Against the three questions from `§1.3`:

| Question | Answer in the table |
|---|---|
| Was it refused? | The table says it was **allowed** |
| Why? | `reason_code` is `NULL`. The caller was told `PREVIEW_ONLY`; the table holds no reason at all |
| By what? | `policy_refs` is `NULL` |

The only trace is `detail.obligations`, and it is a hint rather than a record: it says a restriction
was attached to a permitted operation, which is a true statement about the *chain* and says nothing
about what the *handler* then did with it. The identical row would be written if the download had
succeeded with the obligation discharged — which is precisely the case on `seq=2`, where the
watermark obligation **was** discharged and the preview was served. Two rows that are structurally
identical, describing one refusal and one success.

An operator investigating "this user says they cannot download anything" reads `outcome = ALLOW` and
concludes the product is working. An auditor asked to produce every refusal in a period runs
`WHERE outcome = 'DENY'` and this one is not in the result set.

### 2.4 The comment in the test that says otherwise

`delivery.rs`, immediately above the assertion:

> The chain allowed; the handler refused. Both facts are in the log, which is what makes the
> obligation's effect auditable rather than merely believed.
>
> `assert_eq!(audited(&db, "file.download", "ALLOW").await, 1);`

Only the first fact is in the log. The assertion is correct — there is exactly one `ALLOW` row — and
the sentence above it describes a trail that does not exist. This is worth recording as its own
observation: the belief that the refusal was audited had already been written down, reviewed and
merged. Nothing in the test suite disagreed with it, because no test asked.

---

## 3. Why no existing test caught this, which is the same question as why the gate is shaped as it is

Three things were already true before `ENC-585`, and none of them was enough:

1. **`crates/core`'s engine tests assert that denials are audited.**
   `a_denial_short_circuits_and_no_later_stage_runs` drives every stage into a refusal and asserts
   the audit mock received `(stage, code)`. It proves the engine *calls* the sink. It cannot prove
   a row results, because the mock is not a record format — and it never sees the handler, which is
   where the refusal in `§2` is taken.

2. **`xtask policy-routing` asserts every handler reaches the chain.**
   The download handler does reach it. It reached it, was allowed, and then refused on its own.
   Routing is a question about the *entry*, and this is a defect at the *exit*.

3. **The leakage matrix has an audit row, `U1`: "every allow and every deny in the matrix produces
   an audit event."** It was satisfied by counting rows for actions the matrix covers. Counting is
   satisfied by the `ALLOW` in `§2.3`.

Each is a real control and each is green. The gap is between them, which is the argument for a check
that enumerates rather than samples — `plans/M4-GOVERNANCE.md` D32, and `ENC-543` before it:
the composite-FK rule was a *review item* for a milestone and reported `pass`, in green, having
inspected no foreign key.

`ENC-585` therefore lands as two halves, because they fail differently:

* **`cargo run -p xtask -- audit-coverage`** enumerates every site in `crates/*/src` that constructs
  a refusal — `StageDecision::deny`, `Error::denied`, `Error::denied_with` — and fails on any that
  returns it to something other than `PolicyEngine::enforce`. This is what found `§2`: five sites in
  `download.rs::satisfy`, seven across `preview.rs` (`satisfy`, `mark`, `viewer_identity`) and one
  in `me.rs`. All thirteen are `ENC-606`.
* **`crates/audit/tests/policy_audit_coverage.rs`** drives the real chain into the real record
  format, once per `Stage::ORDER` entry, and asserts the row can answer all three questions from
  `§1.3`. This is what would catch a regression in `§1`.

Neither is sufficient. Deleting `record_deny` from the chain leaves the lint green — every refusal
is still constructed in a `Result<StageDecision>` function. Dropping `policy_refs.push(stage)` from
the sink leaves the lint **and** `enclave-core`'s 81 unit tests green, and only
`policy_audit_coverage` fails, with `the row does not say which stage refused. policy_refs = []`.
Both were verified by doing it.

---

## 4. What is not stopped

**An obligation-refusal is not audited** (`ENC-606`). `§2` in full. Thirteen sites across
`download.rs`, `preview.rs` and `me.rs`. Every one of them is rule 8 being honoured correctly and
rule 10 not being honoured at all. The fix needs an audit sink reachable from the handler, and
`ApiState` is assembled in `crates/api/src/main.rs`; `ENC-606` owns it. Until then the sites are in
`ACKNOWLEDGED` in `xtask/src/audit_coverage.rs`, printed with their reasons in the log of every pull
request, and the gate fails if a fourteenth appears.

**A pre-authentication refusal is not audited, and should not be.** `crates/api/src/auth.rs` refuses
a missing or unverifiable bearer token. The audit chain is keyed and sequenced *per tenant*, and at
that point no tenant has been established. Attributing the row to a tenant named by the rejected
token would let an unauthenticated caller write into any tenant's audit chain — a worse defect than
the gap. These are counted by `crates/observability` instead. The same reasoning exempts `login` and
`refresh` from `policy_routing`'s allowlist.

**A refusal expressed as `Error::NotFound` is invisible to the static gate.** `crates/api` returns
`NotFound` for genuine absence in dozens of places, so enumerating it would produce an inventory
nobody reads. A cross-tenant `NotFound` *is* audited — the engine records `Stage::TenantIsolation`
before returning it, and `a_cross_tenant_attempt_is_audited_even_though_the_caller_is_told_nothing`
asserts the row exists precisely because the caller is told nothing. A handler that invented its own
policy `NotFound` after the chain allowed would not be caught by either half of this gate. It would
be caught by review, and it is recorded here so that "the gate covers it" is not assumed.

**The static gate cannot tell "consumed by the engine" from "consumed by nobody".** A
`StageDecision::deny` in a `Result<StageDecision>` function that nothing calls is classified
`audited (stage)`. Verified: adding one to `crates/sharing/src/lib.rs` moved the count from 36 to 37
and the gate stayed green. This is not a security gap — a refusal nothing consumes refuses nobody —
but the *reachable* variant of it is, and that is what the `ensure_allowed()` enumeration exists to
catch: a stage decision consumed by something other than the engine, which is the only way a stage's
refusal becomes a caller's error without a row.

**`detail.obligations` is JSON inside a JSON string.** The stored value is
`{"obligations":["{\"type\":\"NO_DOWNLOAD\"}"]}` — each obligation serialized to a string and the
strings put in an array, so `detail -> 'obligations' @> '[{"type": "NO_DOWNLOAD"}]'` does not match
and an auditor has to do string comparison inside the array. It is correct, it hashes stably, and it
is awkward to query. `ENC-607`, P3: it is a query-ergonomics defect, not a correctness one, and the
encoding is inside the canonical hash so changing it is a versioning exercise rather than an edit.

---

## 5. What this walkthrough establishes

The `§6` line item is "a written walkthrough of one denial end to end: request in, stage that
refused, obligation raised, audit row out." Both denials were executed rather than narrated.

* For a **stage** refusal, the trail is complete and the claim in `plans/M4-GOVERNANCE.md §1` holds:
  the system refuses for a reason it can state, attributed to the control that took the decision,
  inside tamper-evident bytes, correlated to the request by `request_id`, and — in the case of the
  `403`-versus-`404` disambiguation — with the second decision that produced the status code
  recorded beside the first.
* For an **obligation** refusal, it does not. The audit row says `ALLOW`.

The second finding is worth more than the document, which is why it is in `TRACKER.md` as `ENC-606`
and in the gate's acknowledgement list rather than only here. A walkthrough that had found nothing
would have been a description of the design; this one disagrees with a comment that had already been
reviewed and merged.
