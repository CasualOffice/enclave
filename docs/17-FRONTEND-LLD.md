# 17 — Frontend low-level design

> **Status:** Draft · **Version:** 1.1 · **Owner:** Frontend · **Last updated:** 2026-08-28

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
`entities/` or `shared/`. This is enforced by a real gate and not by convention — the rule is the
gate, and `ENC-543` is why a rule nobody enforces is worse than no rule.

The gate is `web/tools/lint-web.mjs`, rule `arch/layer-boundary`, run by `npm run lint:i18n` in CI.
Earlier revisions of this sentence said "an ESLint boundary rule"; there is no ESLint in this tree
and there was no rule either, so the sentence described an enforcement that did not exist. Corrected
rather than quietly deleted, because it is the second time a claim in this document has outrun the
code, and both times the claim is what a later reader trusted.

Two limits of the gate are worth knowing before you route around them by accident: it resolves only
relative specifiers, so introducing a path alias silently disables it, and it matches `from '…'` on
the same line as the `import`, so a multi-line import is invisible to it.

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

## 12. The component library

**Authoritative for:** when a surface must become a component, what a component must expose, how a
variant is expressed, and where the boundary between the three layers runs.

**Not authoritative for:** what anything looks like (`09-UX-WHITE-LABELING.md`), or what a token's
value is (`web/design-system/`). The inventory of what currently exists is
[`web/src/shared/ui/README.md`](../web/src/shared/ui/README.md), which is a map rather than a
contract and is expected to change every time a component lands.

### 12.1 The rule

**A surface that appears twice is a component. A number that appears twice is a token.**

Not a preference. The measurement that produced this section: `web/src/features` held 4,548 lines of
CSS against `web/src/shared`'s 571 — an 8:1 ratio, which is the inverse of a design system — and
`shared/ui` was five files. Behind those numbers were four byte-identical copies of one 44px figure,
six copies of one paragraph rule, seven copies of a request-ID row, three copies of the button, four
copies of the classification badge and eight per-file answers to `prefers-reduced-motion`.

Duplication of this kind is not a tidiness problem, and the evidence is in the copies themselves:

- Three of the seven request-ID rows isolated the identifier's text direction and four did not, so
  the same string rendered correctly on three screens and reversed on four.
- One of the three "not built yet" row treatments added an opacity change the other two deliberately
  refused — the exact drift `§6` exists to prevent, in the treatment whose whole job is to stay
  distinguishable from a policy denial.
- The library list's avatars hardcoded light-theme hex and did not flip in dark mode, while the two
  other copies used the token pairs and did.

Each is a defect that was fixed once and left broken two, three or four times over. **A surface
duplicated five times is a surface fixed once and broken four times**, and that is the cost being
avoided, not the line count.

### 12.2 Reach for a primitive rather than write CSS

Write CSS in a feature only when all four are true:

1. Nothing in `shared/ui`, `entities/` or the token layer already does it.
2. It is genuinely one screen's. A second caller means it moves down — that is `§2`, and
   `tools/lint-web.mjs` enforces the boundary rather than trusting the convention.
3. Every dimension in it is a token. A literal `px` is a value that escaped the scale.
4. Any animation in it reads `var(--dur-*)` and `var(--ease-*)`.

A feature stylesheet that grows past a few dozen lines is usually reporting a missing primitive.

### 12.3 What a component must expose

| | Requirement | Why |
|---|---|---|
| **Text** | A `MessageKey`, never a `string` | `CLAUDE.md` rule 12 made unrepresentable rather than forbidden: `<Button label="Save" />` does not compile |
| **Geometry** | From tokens. No literal `px` in a primitive | `docs/09 §13`'s density brief is only enforceable if the numbers are in one place |
| **Direction** | Logical properties. `--icon-flip` / `--chev-collapsed` for the rotations and translations logical properties cannot reach | `en-XB` mirrors direction in CI |
| **States** | All four of `docs/09 §11` where the component displays data | A component that renders `null` while loading has three states and fails review |
| **Motion** | `var(--dur-*)`, `var(--ease-*)`. Never a literal duration or a hand-written curve | The reduced-motion answer works by rewriting those tokens, so a component inherits it without knowing it exists |
| **Permissions** | Rendered from `capabilities`. Never re-derived | `§1` |
| **Non-actionability** | The `ControlState` union — `ready` / `denied` / `unbuilt` / `busy` | `§6`. A component that takes a `disabled: boolean` has collapsed three things into one and cannot be un-collapsed later |

That last row is the one worth arguing about. `disabled` is the obvious prop and it is the defect:
it merges a policy refusal, an unbuilt feature and an in-flight request into one appearance and one
focus behaviour, which is precisely what `ENC-673` forbids. A component that never accepts it cannot
express the mistake.

### 12.4 How a variant is expressed

**A data attribute selected in CSS, not a class list assembled in TypeScript.**

```tsx
<button className="ui-btn" data-variant={variant} data-size={size} data-state={state.kind} />
```

Three reasons, in order of how much they cost when ignored:

1. **A state that has an accessible attribute is styled from that attribute.** `aria-pressed`,
   `aria-current`, `aria-selected`, `aria-disabled` are the accessible truth; keying the appearance
   off the same attribute means what a control looks like and what it announces cannot fall out of
   step. A parallel `data-active` is a second source of truth for one fact.
2. **The variant axes stay orthogonal.** `data-variant` and `data-size` compose; a
   `ui-btn--primary-sm` naming scheme multiplies.
3. **The set of variants is checkable.** A test can read the stylesheet and assert that the denied
   and unbuilt treatments share no selector — which is F2 of `§10` — and that is only possible
   because the treatments are values of one attribute rather than strings concatenated at runtime.

Variants are closed sets, deliberately. Two sizes rather than an open size prop, because the four
copies of the classification badge arrived at four different heights by accident and not by choice.

### 12.5 The boundary rule, restated for components

```
shared/ui/     no domain knowledge. A Button, a Card, a Row, a Field.
entities/      knows what a thing is. ClassificationChip, the file-kind icon,
               upload phase steps.
features/      knows what a screen does. Composes the two layers above.
```

The classification chip is the worked example. It is the only reader of `--c-pub … --c-restr` in the
tree, and a test asserts that. `docs/09 §16a` locks that palette so a user reads *Restricted*
identically on every screen — and four hand-maintained copies of the badge defeat that from the
inside, whatever the token says. **Locking a token and duplicating its only consumer locks nothing.**

### 12.6 What holds this in place

- `tests/unit/design-system.test.tsx` — one implementation per surface, expressed as *where* a
  declaration may appear: one `prefers-reduced-motion` block in the tree, no `@keyframes` under
  `features/`, one reader of the classification palette, and the three non-actionable treatments
  sharing no marker.
- `tools/lint-web.mjs` — the layer boundary, physical CSS, string literals, manual formatting.
- `tests/a11y/routes.spec.ts` — axe on every surface in both themes.
- `tests/shots/surfaces.spec.ts` — not a gate; one capture per surface at the reference's viewport,
  to be looked at beside `tools/prototype-shot.mjs`'s capture of the prototype. Reading each other's
  markup instead of looking is how the divergence this section documents was allowed to happen.

---

## 13. Open questions

| # | Question | Blocks |
|---|---|---|
| Q24 | Does the peek panel's Activity tab read a user-facing feed? `audit_events` is hash-chained and deliberately *not* one (rule 10), and no read model exists | The peek panel's fifth tab |
| Q25 | Optimistic updates: which mutations may render before the server confirms? A rename is safe; anything touching access is not, because the optimistic state would be a client-computed permission | The mutation layer |
