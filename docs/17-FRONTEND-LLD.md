# 17 — Frontend low-level design

> **Status:** Draft · **Version:** 1.0 · **Owner:** Frontend · **Last updated:** 2026-08-25

**Authoritative for:** frontend module boundaries, state ownership, the interface layer, component
contracts, routing, and the client-side error taxonomy.

**Not authoritative for:** what the interface looks like or how it behaves — that is
[`09-UX-WHITE-LABELING.md`](09-UX-WHITE-LABELING.md). Token values are
`web/design-system/`. The REST contract is [`05-API.md`](05-API.md). Where this document and
`docs/09` appear to disagree, `docs/09` wins on behaviour and this one is wrong.

---

## 1. The sentence this design is built on

**The server decides; the client renders the decision.**

Every other rule here follows from it. The policy chain (`03-LLD.md §12`) is the only authority on
what a user may do, and it runs on the server. A client that computes a permission — even
correctly, even once — has created a second authority that will drift from the first, and the drift
is invisible until it is a leak.

This is not caution. `CLAUDE.md` rule 6 exists because preview, download, print, export and sync are
five different permissions that look like one, and `ENC-152` put `capabilities` on every listing row
precisely so the client would never need to reason about them.

---

## 2. Module boundaries

Feature-sliced, with a strict dependency direction. A module may import from a layer below it and
never from one above or beside it.

```
app/          router, providers, error boundaries, the shell frame
  ↓
features/     libraries · files · search · admin · auth · upload
  ↓           (a feature never imports another feature)
entities/     file, library, workspace, user, classification
  ↓           domain types + their Zod schemas + display helpers
shared/       api client, i18n, hooks, primitives, tokens
```

**Features do not import each other.** When two features need the same thing, it moves down to
`entities/` or `shared/`. This is enforced by an ESLint boundary rule, not by convention — the rule
is the gate, and `ENC-543` is why a rule nobody enforces is worse than no rule.

**`app/` is thin.** Routing, providers, error boundaries and the shell frame. No business logic
lives there, because everything in `app/` runs on every route and is therefore the most expensive
place to be wrong.

---

## 3. The interface layer — Zod at the boundary, and only there

Every response is parsed by a Zod schema at the fetch boundary. Nothing downstream re-validates,
and nothing downstream sees `unknown`.

```ts
// entities/file/model.ts
export const FileCapabilities = z.object({
  preview: z.boolean(),  download: z.boolean(),  print: z.boolean(),
  export: z.boolean(),   edit: z.boolean(),      share: z.boolean(),
  shareExternal: z.boolean(), delete: z.boolean(), sync: z.boolean(),
});
export type FileCapabilities = z.infer<typeof FileCapabilities>;
```

**Types are inferred from schemas, never declared beside them.** Two declarations of one shape drift;
`z.infer` cannot.

**A parse failure is an error state, not a crash and not a silent default.** `catch`ing it into
`{}` would produce a row with every capability `false`, which reads as *policy denied everything* —
the wrong story told confidently. Parse failures surface as the fetch-error state (`docs/09 §11`)
with the request ID.

**No `any`, anywhere.** `unknown` at the boundary, narrowed by the schema. This is `CLAUDE.md`'s rule
and it is checkable: `@typescript-eslint/no-explicit-any` at error level.

---

## 4. State ownership — four kinds, and where each lives

The commonest frontend defect in a product like this is state kept in the wrong place. Four
categories, each with exactly one home:

| Kind | Home | Examples | Lifetime |
|---|---|---|---|
| **Server state** | TanStack Query | files, libraries, capabilities, search results, quota | Cached, invalidated by mutation |
| **URL state** | The route | library, folder, filters, sort, saved view, selected file | Shareable, survives reload, back/forward |
| **Local UI state** | Zustand | selection set, peek open/pinned, density, group collapse | Session, deliberately not persisted |
| **Ephemeral** | `useState` | a menu's open flag, an input's draft value | Component lifetime |

**There is no global store and no normalized cache.** `CLAUDE.md` line 103, and the reason is
specific to this product: a normalized cache holds one copy of a file keyed by id, and
`capabilities` is *not a property of the file* — it is a property of *this user, this action, this
moment*, and `05-API.md §7` says so. Normalizing it is how a stale permission renders as an enabled
button.

**Filters live in the URL, not in a store.** A filtered view a user cannot send to a colleague is a
worse product, and `docs/09 §3` requires that scroll, selection and expansion survive back/forward.

### 4.1 `capabilities` is never cached beyond its request

Query keys include the action context, `staleTime` is zero for capability-bearing queries, and any
mutation that could change access invalidates them. When the server says a capability is `false`,
the control renders disabled with the server's reason (`ENC-674`) — **never a client-invented one**.

---

## 5. Routing

Route = the addressable state of the application. Everything a user could reasonably link to is in
the URL.

```
/                                  → redirect to last workspace
/w/:workspaceId                    → home
/w/:workspaceId/l/:libraryId       → library list      ?view= &filter= &sort= &group=
   …/f/:folderId                   → folder            (same query contract)
   …?peek=:fileId                  → peek panel open over the list
/w/:workspaceId/search             → results           ?q= &scope=
/admin/…                           → admin surfaces
/signin                            → unauthenticated
```

**The peek panel is a query parameter, not a route.** It opens over the list without unmounting it —
which is the whole point of peek-before-open (`docs/09 §7`), and a nested route would destroy the
list's scroll position and virtualization window.

**Route-level code splitting** at each top-level segment. The bundle budget is 250 KB gzipped and it
is a CI gate (`ENC-677`), so admin must not ship to a user who never opens it.

---

## 6. The three ways a control can be non-actionable

This product has **three** distinct reasons a control is not usable, and conflating any two of them
is a defect. `ENC-673` carries this; it is repeated here because it is a component contract.

| | **Denied** | **Unbuilt** | **Busy** |
|---|---|---|---|
| Cause | Policy refused (`capabilities.x === false`) | Milestone not reached (D33) | Request in flight |
| Focusable | Yes | **No** | Yes |
| Marker | Reason + one remedy | Neutral `Later` chip, no remedy | Spinner in place |
| Tense | Present, about **you** | Future, about **the product** | Present, about the request |
| Colour | The denial treatment | **Never** the denial treatment | Neutral |
| a11y | `aria-disabled` + `aria-describedby` → reason | `aria-disabled` + `aria-describedby` → release note | `aria-busy` |

**Why this is a security contract and not styling:** the denial treatment is how a user learns that
DLP, a barrier or conditional access stopped them. If most dimmed controls in the product mean *"not
written yet"*, users learn that dimmed is background noise — and they learn it on harmless surfaces,
then carry the habit to the one that matters.

---

## 7. Error taxonomy — a denial is not a failure

Four outcomes from a request, and they render differently:

1. **Success** — the data.
2. **Denial** (`403` with a stable `code`) — a *successful* request with a refusing answer. Renders
   inline per `docs/06 §24`: the code, a user-safe sentence, one remedy. **Never a retry button** —
   retrying a policy denial teaches a user the product is broken rather than that they lack
   permission.
3. **Failure** (`5xx`, network, parse) — the error state of `docs/09 §11`: what failed, whether it is
   retryable, a retry action, a **copyable request ID**.
4. **Step-up** (`403 STEP_UP_REQUIRED`, `401 MFA_REQUIRED`) — neither. Intercepted by the api client,
   which raises the challenge and replays the original request on success.

**The client never composes an error message from a policy rule.** `05-API.md §5` gives `message`
and `remediation` already localized and user-safe; rule 10 forbids showing which rule matched.

---

## 8. Component contracts

**Every data surface implements four states** (`docs/09 §11`): empty (new), empty (filtered),
loading, error — plus success. A component that renders `null` while loading has three states and
fails review.

**Skeletons share the loaded row's box model.** No layout shift; the reserved box and the real box
are the same box.

**Lists over 100 rows are virtualized.** `CLAUDE.md`, and `docs/09 §2`'s budget is 60 fps at 100k
rows with first paint under 400 ms.

**Actions render from `capabilities`.** A component that decides for itself whether a button is
enabled is the defect this whole document exists to prevent.

**No user-facing string literal in `web/src`.** Everything through the i18n catalog from the first
component — `CLAUDE.md` rule 12, and retrofitting it is a rewrite.

**No physical direction.** `margin-inline-start`, not `margin-left`. `text-align: start`, not
`right`. `en-XB` mirrors direction in CI and fails on physical properties. The v2 design reference
itself violates this (`ENC-676`); copy its *values*, never its property names.

**No manual formatting.** `Intl.DateTimeFormat`, `Intl.NumberFormat`, `Intl.RelativeTimeFormat`.
`₹ 4.8 Cr` and `2 h ago` in the reference are defects, not patterns.

---

## 9. The API client

One client, in `shared/api`. Every request goes through it, and it owns four cross-cutting concerns
so that no feature has to remember them:

1. **Tenant identity is never sent by the client.** It comes from the verified token
   (`CLAUDE.md` rule 3). There is no tenant parameter in any client function signature — the shape
   makes the mistake unrepresentable rather than forbidden.
2. **Idempotency keys** on every mutation, per `05-API.md`.
3. **Step-up interception**, per §7 above.
4. **Request ID capture** from every response, so the error state can offer it.

---

## 10. Testing

`12-TESTING.md` §1.1 and §1.2 apply to the frontend unchanged:

- **Test our integration, not the library's correctness.** Not that TanStack Query caches; that *our*
  invalidation fires when a mutation changes access.
- **A test is not believed until it has been watched to fail.** Break it, watch it fail by name,
  restore.
- **An assertion about an absence passes for free.** *"The download button is not shown"* passes
  against a component that renders nothing. Pair it with the positive control.

Three assertions this product specifically needs:

| | Assertion |
|---|---|
| F1 | A capability of `false` renders disabled with the **server's** reason, and no client-composed text appears |
| F2 | The denied and unbuilt treatments **never share a class**, and unbuilt is never focusable (`ENC-673`) |
| F3 | A policy denial renders no retry affordance, and a fetch failure always does |

---

## 11. Directory shape

```
web/src/
  app/         router.tsx · providers.tsx · shell/ · error-boundary.tsx
  features/
    libraries/ list/ (virtualized, grouped) · peek/ · selection-bar/
    files/     upload/ · versions/ · access/
    search/    palette/ · results/ · degraded-header/
    admin/     conditional-access/ · dlp/ · quotas/
    auth/      signin/ · step-up/
  entities/    file/ library/ workspace/ user/ classification/
  shared/      api/ i18n/ hooks/ ui/ styles/
```

`shared/ui` holds primitives only — things with no domain knowledge. A component that knows what a
classification is belongs in `entities/classification`, not in `shared/ui`.

---

## 12. Open questions

| # | Question | Blocks |
|---|---|---|
| Q24 | Does the peek panel's Activity tab read a user-facing feed? `audit_events` is hash-chained and deliberately *not* one (rule 10), and no read model exists | The peek panel's fifth tab |
| Q25 | Optimistic updates: which mutations may render before the server confirms? A rename is safe; anything touching access is not, because the optimistic state would be a client-computed permission | The mutation layer |
