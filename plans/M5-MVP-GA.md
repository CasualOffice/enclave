# M5 — MVP GA

> **Status:** Draft · **Version:** 1.1 · **Owner:** Engineering · **Last updated:** 2026-08-24

`ROADMAP.md`: *"A real team could use this daily. Ship it."* Gate **G1** decides here.

---

## 1. Objective

Four milestones built a product with no way to use it. M5 is the first milestone whose output a
person can see, and the only one whose exit criteria include an outside party — a penetration test
and an operator who has never seen the repo.

The backend is further along than the shell suggests and *less* far along than the design suggests,
and both halves of that sentence set this milestone's shape.

### Exit criteria (from the roadmap — may not be weakened here)

- [ ] Every P1 in Phase 1 `DONE`.
- [ ] Leakage matrix §4.1–4.6 green, zero skips.
- [ ] Performance budgets met: metadata P95 < 300 ms, search P95 < 500 ms, 100k-item folder first
      paint < 400 ms.
- [ ] Restore drill executed end to end and documented.
- [ ] axe clean on every primary route; keyboard-only walkthrough completed.
- [ ] A new operator can install from `README` on a clean machine without asking a question.
- [ ] External penetration test scoped to `docs/12 §4` — no unresolved high findings.

---

## 2. The one sentence this milestone is built on

**A screen is a promise, and a promise the backend cannot keep is a defect that ships looking
finished.**

M0–M4's recurring failure was a control that read as enforced and was reachable by nothing:
`ENC-543`'s gate printing `pass` while inspecting no foreign keys, `ENC-606`'s `403` recorded as
`ALLOW`, `ENC-641`'s antivirus with no caller, `ENC-643`'s index queue nothing wrote to. Four
instances, each found by a gate rather than by review.

The UI is where that failure becomes *visible to a customer* rather than to us. A sidebar entry, a
tab, a button — each asserts that something exists. The design shows a finished product; roughly
40% of it has no backend at all. This milestone's discipline is that every assertion on screen is
either true or **visibly, deliberately marked as not yet true** — and that the second treatment is
never confusable with the first.

---

## 3. Decisions locked before the shell is built

### D33 — Surfaces without a backend are shown, disabled, and marked *unbuilt* — never *denied*

**Decided by the repo owner, 2026-08-24.** Ask (`⌘J`), Inbox, Lists, Pages, Activity, approvals,
legal-hold and retention pills, checkout state, and passkey/SSO sign-in all appear in the design and
are backed by five-line stubs or by milestones M6–M9. They render, disabled, each carrying an honest
reason.

**The risk this creates is named in the same breath as the decision, because it is the whole of the
implementation cost.** `docs/09 §12` and the design's *denied-explained-inline* pattern already use
a dimmed control plus a reason to mean **policy refused this**. That is a security affordance: it is
how a user learns that DLP, a barrier or a conditional-access rule stopped them. If half the dimmed
controls in the product mean *"we have not written this yet"*, users learn that dimmed is background
noise — and they learn it on the surfaces where it is harmless, then carry the habit to the one
place it is not.

So the two states are **different treatments, not one treatment with two sentences**:

| | Policy-denied | Not yet built |
|---|---|---|
| Control | Focusable, `aria-disabled="true"` | **Not focusable**, `hidden` from the tab order |
| Marker | Reason + one remedy, inline | A neutral `Later` chip, no remedy |
| Semantics | `aria-describedby` → the reason | `aria-disabled` + `aria-describedby` → the release note |
| Colour | The denial treatment from `docs/09 §12` | Neutral — **never** the denial colour |
| Copy | *"Blocked off-network"* — present tense, about **you** | *"Arrives in a later release"* — future tense, about **the product** |
| Recourse | *Request access* | None offered |

A test asserts the two never share a class, and `docs/12 §4` gains a row: **a not-yet-built control
is never rendered in the denial treatment.** That row is not decoration — it is the only thing
standing between this decision and the erosion it invites.

### D34 — The details panel is the design's peek, and `docs/09 §7` is rewritten to match

**Decided by the repo owner, 2026-08-24.** A transient 372 px peek — `Space` opens, `Esc` closes,
`⌘\` pins, `J`/`K` walk the list — with five tabs: Preview, Details, Access, Versions, Activity.

`docs/09 §7`'s docked, resizable panel with eleven tabs is superseded. The four tabs that lose a
home are re-placed rather than dropped: **DLP status and retention become inline treatments on
Details** (they are facts about the file, not workspaces of their own), **Sharing is already a
dialog**, and **Comments defers with the milestone that owns it** — there is no comments crate.

Fewer tabs is also the cheaper answer for M5's own accessibility exit criterion: one focus model,
one ARIA tree, one keyboard map to test.

### D35 — `docs/` remains authoritative for behaviour; the design system for appearance; conflicts are resolved in writing before code

`web/design-system/README.md` already draws this line and it held up: reading the design against
`docs/09` surfaced **seven** genuine contradictions, not stylistic differences. Each is settled here
rather than in a component:

1. **Row density** — `docs/09 §13` says 48/36; the design says 36/30 and labels them
   *Default/Compact*. **The design wins**; `docs/09 §13` is updated. Density is appearance.
2. **Details panel** — D34.
3. **Keyboard bindings** — four disagree (`I`, `Del`, `Space`, `/`) and the design adds `J`/`K`,
   `⌘J`, `L R`. **`docs/09 §6` wins and absorbs the additions**: the keyboard model is behaviour,
   it is an accessibility commitment, and it is the one surface a screen-reader user cannot work
   around. `⌘J` is registered but disabled under D33.
4. **`docs/09 §3`'s shell diagram is stale** — it draws a full-width top bar the design retired.
   **Corrected**, because a reader implements what is drawn.
5. **Denied actions: shown or hidden?** `docs/09 §5` reads as hide; the design shows and explains.
   **The design wins** — a hidden action is indistinguishable from one that does not exist, which
   is `docs/06 §24`'s own argument — and §5 is rewritten.
6. **Rule 12 violations in the reference itself**: `₹ 4.8 Cr` is manual number formatting, `2 h ago`
   / `Yesterday` / `Fri` are hand-built relative times, and the reference is physical-CSS
   throughout (`left`, `margin-left:auto`, `text-align:right`, `float`). **All three are defects in
   the reference**, not licences to copy. M5 step 3 ships `en-XB` in CI, which mirrors direction —
   the reference as drawn fails this milestone's own gate.
7. **No empty state and no fetch-error state appear anywhere in the reference**, on any of five
   layouts. `docs/09 §11` requires four states per surface. **`docs/09` wins**; the states are
   designed as part of the work rather than discovered during it.

### D35a — The visual-design skills raise the ceiling; they do not move the floor

**Decided by the repo owner, 2026-08-25: the installed design skills are to be used throughout this
project, not case by case.** They are linked into `~/.claude/skills` and load on restart:
`brandkit`, `design-taste-frontend`, `high-end-visual-design`, `redesign-existing-projects`,
`gpt-taste`, `imagegen-frontend-web`.

Used naively they would break things that are already decided, so the precedence is written here
once rather than argued per pull request. **Three of the six declare a scope that is not this
product** — `design-taste-frontend`'s own text says *"Landing pages, portfolios, and redesigns. Not
dashboards, not data tables, not multi-step product UI"*, which is exactly what the M5 shell is;
`high-end-visual-design` targets marketing sites and carries a *never generate the same layout
twice* variance mandate, which is the opposite of what a design system exists to do; and
`redesign-existing-projects` audits an existing interface, which does not yet exist here. That does
not make them useless. It makes them **sources of craft rather than sources of truth**.

**The order, highest first:**

1. **`CLAUDE.md`'s non-negotiable rules.** Rule 12 in particular: no string literals in `web/src`, no
   manual date or number formatting, no physical `left`/`right` CSS. A skill that emits
   `margin-left: auto` or a hand-formatted date is wrong here whatever it looks like, and `en-XB`
   in CI will say so.
2. **`docs/` — behaviour.** `docs/09` owns budgets, the keyboard model, accessibility and the four
   required states. `docs/06 §24` owns denial language. These are commitments with tests behind
   them.
3. **`web/design-system/` — token values.** Especially the **locked classification palette**: a
   tenant cannot recolour `Restricted`, because a user misreading sensitivity at a glance is a
   security failure, not a taste one. No skill may substitute that scale.
4. **The skills — everything above the floor.** Spacing rhythm within the 8pt grid, elevation and
   shadow craft, micro-interaction quality, empty-state and error-state composition (which the
   reference does not cover at all — see D35.7), typographic hierarchy inside the chosen families,
   and motion beyond the three durations already fixed.

**Where they are most useful, concretely**, because "use them constantly" should mean something
specific rather than a vibe:

- **`brandkit` → Q20**, the logo and favicon. The repo has **no mark at all**; three candidates sit
  in Claude Design. This is brand identity work with nothing above it to conflict with, and it
  blocks the shell's first pull request.
- **The four missing states** (D35.7): empty, filtered-empty, fetch-error, offline appear nowhere in
  the reference, on any of five layouts. `docs/09 §11` requires them and the design does not supply
  them — so the craft has to come from somewhere, and this is exactly that gap.
- **`docs/09 §10`'s degraded-search header** (D37), never designed because never reachable.
- **The D33 *unbuilt* treatment**: a neutral `Later` marker that must read as deliberate rather than
  broken, and must never be confusable with the denial treatment. That is a visual-design problem
  with a security consequence.
- **Micro-interaction and motion polish** on the peek panel, the selection bar and the palette.

**What they may never do:** change a classification colour, contradict `docs/09`'s keyboard map,
introduce a font outside the self-hosted set (`ENC-135` — an external font request is a network call
an air-gapped install cannot make), emit physical-direction CSS, or add a dependency that pulls a
remote asset at runtime. Each of those is already a rule with a reason.

### D36 — `capabilities` gains a reason per denied action, or the design's hover reasons are a lie

`crates/api/src/content.rs` builds `capabilities` from nine named booleans and an `obligations`
list. There is **no reason attached to a `false`**. The design hovers a disabled action and explains
why — which today would have to be invented client-side, and `CLAUDE.md`'s React conventions forbid
re-deriving permissions in the client for exactly this reason.

So the shape changes: a denied capability carries a stable `ReasonCode` and the user-safe sentence
`docs/06 §24` already specifies. **Never the rule that matched** — that is rule 10, and it is why
the reason is a code plus a sentence rather than a free-text explanation.

`aria-disabled` + `title` is additionally not a reliable screen-reader path (`docs/09 §15`), so the
reason is associated with `aria-describedby` and rendered as text, not as a tooltip alone.

### D37 — Search in M5 is lexical, and the UI says so where a user can see it

`ENC-661` is open: there is no `EmbeddingProvider` in the workspace, so nothing is embedded and
dense retrieval returns nothing. `docs/07 §6` already specifies hybrid retrieval, and `docs/09 §10`
already specifies a degraded-search header — which has never been designed because it has never
been reachable.

M5 ships lexical search and **renders that header**. The alternative — a search box that silently
returns fewer results than the product promises — is the "reads as working" failure with a customer
on the other end of it.

### D38 — Grouped virtualization is the milestone's real technical risk, and it is sequenced first

The design has grouping **on by default** with collapsible headers and a collapsed `Archive 96`.
`docs/09 §2` requires 60 fps at 100k rows and first paint under 400 ms, and that is an exit
criterion.

Flat virtualization is a solved problem with libraries. **Grouped, collapsible virtualization with
sticky headers is materially harder**: row height varies, collapse changes the index space under
the scroll position, and sticky headers fight the windowing. This is the one part of M5 that could
fail on its own merits, so it goes first — the same reason M2 opened with the rendition pipeline and
M4 with `SecurityFacts`.

---

## 4. Sequencing, by uncertainty

1. **Grouped virtualized list at 100k rows** (D38). If this cannot hit the budget, the design's
   default view changes, and everything built on it changes with it.
2. **The shell and the peek panel** (D34) — geometry, focus model, keyboard map.
3. **`capabilities` with reasons** (D36) — a server change the client cannot fake.
4. **The four states, on every surface** (D35.7), and the disabled/unbuilt distinction (D33).
5. **i18n scaffolding and `en-XA`/`en-XB` in CI** — after the surfaces exist, because the gate is
   only meaningful against real strings, and before the accessibility pass, because direction
   mirroring changes focus order.
6. **Accessibility**, then **release hardening**.

---

## 5. Risks specific to M5

| Risk | Why it is specific to this milestone |
|---|---|
| The dimmed-means-later habit erodes the dimmed-means-denied signal | D33's named cost. It is a *security* regression produced by a *product* decision, and no existing gate would catch it — hence the new matrix row |
| The design is a static mock-up; every state it does not show is one nobody has designed | Empty, filtered-empty, fetch-error, offline, partial-failure. `docs/09 §11` requires four states and the reference shows one |
| Grouped virtualization misses the budget late | Sequenced first for exactly this reason |
| The pen test lands on a UI nobody has attacked yet | Every prior milestone was tested by us. This one is scoped to `docs/12 §4` by an outside party, and the client is a new surface for every row in it |
| "A new operator installs without asking a question" is untestable by the people who wrote it | The only honest test is someone who has not seen the repo, on a machine that has never built it |

---

## 6. Definition of done

- [ ] Every M5 P1 `DONE`, and every Phase 1 P1 with it (the gate's own first criterion).
- [ ] Leakage matrix §4.1–4.6 green with zero skips, plus the D33 row.
- [ ] Every surface has all four states, demonstrated.
- [ ] `en-XB` passes in CI — which means no physical CSS and no hand-built formatting anywhere.
- [ ] axe clean on every primary route; a keyboard-only walkthrough recorded.
- [ ] The performance budgets measured under the grouped default view, not a flat one.
- [ ] `docs/09` updated where D35 says it loses, in the same PR as the code that diverges from it.

---

## 7. Open questions

| # | Question | Needs deciding by | Owner |
|---|---|---|---|
| Q20 | Which logo — gate, strata or orbit? Three variants exist in Claude Design and the repo has no mark or favicon at all | Before the shell's first PR | Owner |
| Q21 | Is the location bar's avatar stack *people with access* (ACL data, available now) or *presence* (nothing in the tree, and a real-time subsystem M5 does not have)? | Before the location bar is built | Owner |
| Q22 | The Display popover offers a **Board** layout that `docs/09 §4` does not list among its view types. Ship it, or drop it from the design? | Before step 2 | Owner |
| Q23 | Sign-in shows passkey and SSO as the two primary buttons and email as the third. Under D33 the first two are disabled, which leaves the primary action disabled and the fallback carrying the screen. Is that acceptable for GA, or does sign-in get its own M5 treatment? | Before the sign-in route | Owner |
