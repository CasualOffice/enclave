# M5a — API completion

> **Status:** Draft · **Version:** 1.0 · **Owner:** Engineering · **Last updated:** 2026-08-27

**Goal.** Every documented endpoint exists, is reachable, and returns data to a client that logged
in. Not "the crate is tested" — a request, a token, a response with content in it.

---

## 1. Why this plan exists

M0–M4 produced a backend of ~130k lines with tests that have been watched to fail, and **nothing
could reach it**. Four milestones of exit criteria asked whether each control was correct and none
asked whether the product could be used. The first `curl` against a running server happened after
M4 closed, and it found, in one evening:

1. `crates/api` registered **10** of `docs/05`'s 43 endpoints. No `/auth/*` at all.
2. Those routes, once added, answered `503` — `main.rs` built an empty `KeySet` and an
   `AuthSurface::unconfigured`.
3. Once wired, login worked and **every authenticated route answered `403`** — the binary composed
   `SelfServiceAuthorization` with no ACL resolver.
4. Once that was composed, `/me` **still** answered `403`: the token's `iss` is derived from
   `server.public_url` at the minting site, and the verifier is constructed separately with
   `issuer: ""`. Two code paths, one configuration value, no shared source.

Each layer was individually correct and tested. The defect was always the seam between two of them,
and seams are exactly what a unit test cannot see.

**So this plan's first rule: a task is done when a request returns the right answer, not when its
tests pass.**

---

## 2. The one sentence

**Every endpoint is proven by a request, from a client that authenticated, against a running
server.**

---

## 3. Where things actually stand

| | Count |
|---|---|
| Documented in `docs/05-API.md` | 43 |
| Registered in `crates/api` | 26 |
| Proven end to end by a real request | **1** (`POST /auth/login`) |

Sync (4 routes) and workflows (8) are complete on branches and unmerged. Signing (11) is a crate,
a migration and four tables with no routes — deliberately stopped, because it is M9 work that
nothing else needs.

---

## 4. The plan, in dependency order

### Step 1 — Make one authenticated request work (**blocks everything**)

The issuer mismatch above. One value must reach both the minting and the verifying path from one
place, and a test must fail if they diverge — the same shape as `ENC-533`'s width agreement, which
was caught precisely because one test compared the two numbers.

**Done when:** `GET /api/v1/me` returns the caller's record after a real login.

### Step 2 — A smoke test that runs the real binary

Not an integration test with an in-process router. Start the server, log in over HTTP, call every
registered route with the token, assert none answers `403` or `503` for a caller who should be
allowed.

This is the check whose absence caused all four failures above. It goes in CI.

**Done when:** the suite fails if any registered route becomes unreachable.

### Step 3 — Merge sync and workflows

Both are finished and verified in their own worktrees. They add 12 routes. Step 2's smoke test
must cover them, which is what turns "merged" into "reachable".

### Step 4 — The four remaining wirable endpoints

`GET /bootstrap` (a session was stopped mid-build; its work is preserved), and the three that need
a decision recorded rather than code: `/shares/{token}` and `/sign/{token}` both need an
unauthenticated cross-tenant token lookup that RLS forbids and `platform_connection` gates. Two
sessions independently hit this wall and both refused to ship a route that would answer `503` for
ever. **That refusal was right.** The fix is one narrow `share_link_tenant(digest)` beside
`active_tenants` in `crates/db`, plus a platform URL — the procedure `platform_connection`'s own
documentation prescribes.

### Step 5 — Signing (11 routes)

M9 on the roadmap. The crate, migration `0025` and four tables exist and are preserved. **Not
scheduled here** — it is the largest remaining piece, nothing depends on it, and it should be a
milestone with its own plan rather than a tail on this one.

---

## 5. What this plan will not do

- **No parallel subagents until step 2 exists.** Four ran at once yesterday, cost over a million
  tokens, and produced work that was individually good and collectively unverifiable — because
  nothing could tell whether the assembled product worked. Step 2 is that test. Until it exists,
  parallelism multiplies the seams nobody is checking.
- **No task called done on green tests.** Every step above names a request and a response.
- **No new subsystem** until the existing ones are reachable.

---

## 6. Definition of done

- [ ] A client logs in and reads its own record.
- [ ] Every registered route is exercised by the smoke test against the real binary.
- [ ] Sync and workflows merged, and covered by it.
- [ ] `bootstrap` registered; the two token routes either registered or refused **in writing**.
- [ ] `README` documents how to start the server — the five secrets, `enclave.yaml`'s location, and
      the `env://` reference form. Starting it tonight took six attempts and none of it was written
      down.
