# admin-dlp — implementation spec

> Extracted from `enclave-client-prototype.html` by the spec workflow.
> The prototype stays the reference; this is a reading of it, not a replacement.

## Structure

SCREEN: Admin > Security > DLP rule editor. Routes `/admin/dlp/rules/:ruleId` and `/admin/dlp/rules/new`. Slice `web/src/features/admin/dlp/`. Route-split at `/admin` (17-LLD s5, 250KB gzip CI gate). All VALUES below are the prototype's (enclave-client-prototype.html L473-573); all PROPERTY NAMES are the logical replacements (17-LLD s8, ENC-676).

A. ROOT
`display:grid; grid-template-columns:200px 1fr; flex:1; min-block-size:0`. The `min-block-size:0` is load-bearing: each column scrolls itself, body never scrolls.

B. SECTION NAV (col 1, 200px)
nav: `padding-block:14px; padding-inline-start:12px; padding-inline-end:8px; color:var(--fg2); font-size:12.5px; overflow:auto`.
Group heading h3: `font-size:11px; color:var(--fg4); padding-inline:8px; padding-block-end:4px; font-weight:500`. First group padding-block-start:0; later groups 12px.
Items = router NavLink (never href="#"): `display:flex; align-items:center; padding-block:5px; padding-inline:8px; border-radius:var(--r-ctrl); text-decoration:none; color:var(--fg2)`. hover + :focus-visible -> `background:var(--hover); color:var(--fg)`. current -> `background:var(--selected); color:var(--fg)` + aria-current="page".
Order: Security > Data loss prevention (current), Conditional access, Classification, Information barriers, Incidents | Detectors > Built-in, Custom.
Incidents count span: `margin-inline-start:auto; font-family:var(--mono); color:var(--fg4); font-size:11px`, Intl.NumberFormat. Server data: while loading show an 18x14px shimmer, never a literal 0 (a fabricated zero reads as "no incidents").

C. CONTENT PANE (col 2)
`padding-block-start:20px; padding-inline:28px; padding-block-end:28px; overflow:auto; min-inline-size:0`.

C1 Breadcrumb nav: `color:var(--fg3); font-size:12.5px; padding-block-end:4px`. Separator span "/": `color:var(--fg4); margin-inline:2px`, aria-hidden. Trail: Security / DLP / <current, color:var(--fg), font-weight:500, aria-current="page">. Ancestors are links.

C2 Title row: `display:flex; align-items:center; gap:8px; margin-block:6px 18px`.
- h1 (h2 in prototype; must be h1 here): `font-family:var(--tight); font-size:20px; font-weight:600; letter-spacing:-.02em; margin:0`. Editable name -> click or Enter turns it into an inline input of identical box (h 26px, font inherit) to avoid shift.
- Mode chip: `display:inline-flex; align-items:center; block-size:20px; padding-inline:8px; border-radius:999px; font-size:11px; font-weight:500; background:color-mix(in srgb,var(--warn) 14%,transparent); color:var(--warn)`. Text from server mode enum; NOT tenant-recoloured.
- Spacer: `flex:1`.
- Secondary button (Save draft): `display:inline-flex; align-items:center; block-size:28px; padding-inline:10px; border-radius:var(--r-ctrl); border:0; font:inherit; font-size:12.5px; font-weight:500; background:var(--sheet); color:var(--fg); box-shadow:var(--hairline)`; hover `background:var(--sunken)`.
- Primary button (Enable/Enforce): same metrics + `gap:6px; background:var(--accent); color:#fff`; hover `filter:brightness(1.08)`. Kbd hint span: `font-family:var(--mono); font-size:10px; padding-block:1px; padding-inline:4px; border-radius:4px; background:rgba(255,255,255,.2)`, aria-hidden (shortcut announced via aria-keyshortcuts="Meta+Enter Control+Enter").

C3 RULE CARD (the sentence builder): `border-radius:var(--r-surf); box-shadow:var(--hairline); overflow:hidden`. Three band+row pairs.
Band (WHEN / THEN / WHERE): `display:flex; align-items:center; gap:8px; padding-block:10px; padding-inline:14px; font-size:11px; font-weight:500; color:var(--fg3); text-transform:uppercase; letter-spacing:.06em; background:var(--sunken)`. WHEN band carries a qualifier span ("all of these are true"): `text-transform:none; letter-spacing:0; font-weight:400; color:var(--fg4)`.
Clause row: `display:flex; align-items:center; flex-wrap:wrap; gap:6px; padding-block:12px; padding-inline:14px; font-size:13px; line-height:1.5`.
Chip variants, all `block-size:26px; border-radius:7px; box-shadow:var(--hairline); background:var(--sheet)`, hover `background:var(--sunken)`:
 - FIELD chip (Classification / Detected data / Action / Whole tenant): `display:inline-flex; align-items:center; gap:6px; padding-inline:9px; font-weight:500` + chevron svg 12x12 `color:var(--fg4)`. Rendered as a combobox button.
 - VALUE chip (Payment card, Aadhaar, Share externally, Legal / Deal room): `gap:4px; padding-inline-start:9px; padding-inline-end:4px; font-weight:500` + remove button 18x18, `border-radius:5px; color:var(--fg4)`, glyph U+00D7.
 - CLASSIFICATION VALUE chip: `gap:6px; padding-inline-start:6px; padding-inline-end:4px`; inner badge `block-size:18px; padding-inline-start:7px; padding-inline-end:8px; border-radius:999px; font-size:11px; font-weight:500; background:color-mix(in srgb,var(--c-restr) 11%,transparent); color:color-mix(in srgb,var(--c-restr) 82%,var(--fg))`; dot `inline-size:6px; block-size:6px; border-radius:50%; background:var(--c-restr)`; then the 18x18 remove button. Badge always carries text as well as colour (09 s15).
 - EFFECT chip (Block): `gap:6px; padding-inline:6px`; inner badge `block-size:18px; padding-inline:8px; gap:5px; border-radius:999px; font-size:11px; font-weight:500; background:color-mix(in srgb,var(--danger) 12%,transparent); color:var(--danger)` + 11x11 block icon; trailing chevron 12x12 `color:var(--fg4)`.
 - MESSAGE chip (the user-safe denial sentence): value-chip metrics but `font-weight:400; color:var(--fg2)`; trailing pencil button 18x18 (U+270E) opens an edit popover. Quotation marks are locale-aware, from the catalog, never literal typographic quotes in JSX.
 - ADD affordance (+ condition / + action / + exception): `display:inline-flex; align-items:center; gap:5px; block-size:26px; padding-inline:9px; border-radius:7px; color:var(--fg3); font-size:12.5px; border:0; background:transparent` + 12x12 plus icon; hover `background:var(--hover); color:var(--fg)`.
 - CONNECTOR text ("is at least", "and", "includes any of", "is", "or", "and show", ", then", "except"): plain span `color:var(--fg3)`. See techniqueFixes: these are ICU slots, not concatenated fragments.
Content, mapped to the stored vocabulary (05-API s14.2, snake_case, carried verbatim):
 WHEN -> conditions[]: classification `category_at_least`, detected data (multi), governed action. THEN -> `action` + obligations (Notify security, Open incident/Critical) + user-safe message. WHERE -> `scope[]` plus exceptions.

C4 SIMULATION HEADER: `display:flex; align-items:center; gap:8px; margin-block:20px 10px`. h2: `font-size:11px; font-weight:500; color:var(--fg3); text-transform:uppercase; letter-spacing:.06em`. Spacer `flex:1`. Two text buttons (Re-run, Export): `border:0; background:transparent; font:inherit; color:var(--fg4); font-size:11.5px`; hover `color:var(--fg2)`. The "last 30 days" window is a formatted interval, not a baked string (see techniqueFixes).

C5 STAT GRID: `display:grid; grid-template-columns:repeat(4,1fr); gap:10px`. Card: `border-radius:var(--r-surf); box-shadow:var(--hairline); padding-block:12px; padding-inline:14px; animation:encIn .25s <index*40ms> both`. Value: `display:block; font-family:var(--tight); font-size:22px; font-weight:600; letter-spacing:-.02em; line-height:1.1`. Label: `color:var(--fg3); font-size:11.5px`. Below 900px the grid drops to `repeat(2,1fr)`.

C6 TWO PANELS: `display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-block-start:12px`; below 900px `1fr`. Panel: `background:var(--sheet); border-radius:var(--r-surf); box-shadow:var(--hairline); padding:14px`. Panel h3: `margin-block-end:10px` + the 11px uppercase style above.
 - "Would block, by workspace": rows `display:grid; grid-template-columns:110px 1fr 28px; align-items:center; gap:10px; font-size:12px`; bar `block-size:6px; border-radius:3px; background:var(--fg2); opacity:.7; inline-size:calc(var(--ratio)*100%); transition:inline-size .5s cubic-bezier(.2,.7,.3,1)`; count `text-align:end; color:var(--fg4); font-family:var(--mono); font-size:11px`. Rows carry role="row" semantics inside a table-shaped list, and the bar itself is aria-hidden (the count is the accessible value).
 - "Sample events": `display:flex; flex-direction:column; gap:8px; font-size:12.5px`; row `display:flex; align-items:center; gap:8px`; avatar `inline-size:20px; block-size:20px; border-radius:50%; font-size:9.5px; font-weight:600` using --av-a/b/c/d pairs, initials derived server-side (never client-sliced from a name); actor name `font-weight:500`; date `margin-inline-start:auto; color:var(--fg4); font-size:11px; font-family:var(--mono)`.

C7 FOOTNOTE p: `color:var(--fg4); font-size:11.5px; margin-block-start:14px`. States that enforcing requires recent MFA and writes an audit entry; contains the "View as JSON (read-only)" disclosure link, `color:var(--fg3)`. The JSON view is the power-user mirror required by 09 s21 and stays in sync with the builder; it is read-only here.

## Interactions

FOCUS RING (global, do not restyle): `outline:2px solid var(--accent-ring); outline-offset:1px; border-radius:6px` on :focus-visible.

1. NAV LINKS. Tab-reachable in DOM order. Enter/Space navigates. Each is a real route (09 s21: every admin object has a stable URL). Unbuilt sections are not links and not focusable.

2. TITLE. Click or Enter on the name swaps to an inline text input of the same box. Esc reverts, Enter commits to local draft state (not the server). Name collision returns 409 RULE_NAME_IN_USE -> inline field error under the title, focus moves to the input.

3. SAVE DRAFT (secondary). Enabled from `capabilities.saveDraft`. Click -> POST/PUT with an idempotency key via shared/api. Busy: label unchanged, 12px spinner replaces the leading slot, `aria-busy="true"`, button stays focusable. Success -> toast.

4. ENABLE / ENFORCE (primary). Shortcut Cmd+Enter / Ctrl+Enter, registered only while this route is mounted and never while a text input or popover has focus. Behaviour is entirely capability-driven:
   - `capabilities.enforce === true` -> active. Click opens the confirm dialog (see 8).
   - `false` -> DENIED treatment: `aria-disabled="true"`, still focusable, `aria-describedby` pointing at the server's `reason` + `remediation` strings rendered beneath. The commonest reason is the mandatory-simulation gate (06 s9: enforcement is refused on a rule never simulated) and the recent-MFA requirement (05-API s14.2). The client NEVER computes either; it renders what the server sent (17-LLD s4.1, s6).
   - Missing from `capabilities` because the milestone has not shipped -> UNBUILT treatment: neutral `Later` chip, `aria-disabled`, `tabindex="-1"`, no remedy, never the denial colour.
   A 403 STEP_UP_REQUIRED is intercepted by the api client, which raises the MFA challenge and replays the request (17-LLD s7 item 4). The screen writes no step-up logic of its own.

5. FIELD CHIP (combobox). `role="combobox" aria-haspopup="listbox" aria-expanded`. Enter/Space/ArrowDown opens a listbox popover anchored to the chip; Up/Down move the active option (`aria-activedescendant`), Enter selects, Esc closes and returns focus to the chip, Tab closes and moves on. Typing filters. The option set comes from the server's condition vocabulary (05-API s14.2: `conditions` is closed) — the client never invents an operator.

6. VALUE CHIP. The chip body is a button that re-opens the value picker; the trailing x is a SEPARATE button with its own accessible name from the catalog ("Remove {value}"), so a screen reader never has to guess. Backspace or Delete while the chip body has focus removes the chip and moves focus to the previous chip (or, if it was first, to the following one). Removal is undoable from the toast for 8 s.

7. CLAUSE-ROW ROVING TABINDEX. Each clause row is a single tab stop (`role="group"`, labelled by its band). Inside it, ArrowForward/ArrowBackward walk the chips. Arrow keys are PHYSICAL, so resolve them against `getComputedStyle(el).direction`: in LTR ArrowRight = next, in RTL ArrowRight = previous. Home/End jump to the first/last chip. This must not be written as `ArrowRight -> next`.

8. CONFIRM DIALOG (enforce). Required by 09 s21: diff before save, blast radius before applying. Contents: field-level diff of the rule, the blast-radius sentence ("affects N files across M libraries", both counts via Intl.NumberFormat), the maker/checker notice when 06 s22 applies, and a plain statement that the action writes an audit entry. Focus trap; focus starts on the cancel control; Esc cancels; on close focus returns to the primary button.

9. ADD AFFORDANCES (+ condition / + action / + exception). Buttons. Click or Enter opens the same combobox popover as a field chip, pre-focused, and on selection inserts a new chip and moves focus into it.

10. RE-RUN SIMULATION. POST to the simulate endpoint. While in flight the button shows a spinner in place and gets `aria-busy="true"` — the stat cards and both panels keep their previous values dimmed to 0.5 opacity rather than being replaced by skeletons, because the old numbers are still true and a skeleton would claim otherwise. `aria-live="polite"` on the stat grid announces completion. Never disable the section nav during a re-run.

11. EXPORT. Downloads the simulation result. If `capabilities.exportSimulation` is false it renders denied (focusable, server reason), not hidden (09 s5, ENC-676: a hidden action is indistinguishable from one that does not exist).

12. VIEW AS JSON. Toggles a read-only disclosure with the stored `snake_case` document exactly as the server would store it. `aria-expanded` on the trigger. A copy button uses the clipboard API and confirms via toast.

13. GLOBAL KEYS still active on this screen (09 s6, which overrules the design reference): Cmd+K palette, `/` focus search, `?` shortcut reference, Esc closes the topmost popover/dialog then clears chip focus. `Cmd+J` (Ask) is registered and disabled until M7 with the UNBUILT treatment.

14. UNSAVED CHANGES. Navigating away from a dirty builder raises a router blocker with keep/discard. The dirty flag lives in feature-local state; the rule itself is server state in TanStack Query, filters and the selected section are URL state (17-LLD s4).

15. TOASTS. Position `inset-block-end:24px; inset-inline-start:24px` (prototype used left/bottom); `background:var(--selbar-bg); color:var(--selbar-fg); padding-block:8px; padding-inline-start:12px; padding-inline-end:8px; border-radius:10px; box-shadow:var(--el3); font-size:12.5px`; optional action button `block-size:24px; border-radius:7px; background:var(--selbar-hov)`. `role="status"`, auto-dismiss 8 s, never for errors that need a decision.

16. AUDITOR MODE (09 s21). Read-only auditors get this same screen with every mutating control in the DENIED treatment carrying the server's reason — not a separate, poorer view, and not hidden controls.

17. MOTION. `encIn` 250 ms on stat cards, staggered 40 ms; bar width transition 500 ms; popovers 120-200 ms. `prefers-reduced-motion: reduce` keeps opacity changes only and drops transforms and the width transition (09 s12).

## States

Two independent data surfaces, each of which implements all four states plus success (09 s11, 17-LLD s8). They are never collapsed into one page-level spinner.

SURFACE 1 — THE RULE (GET /admin/dlp/rules/{id})
- LOADING: skeletons that share the loaded box model exactly. Title row: a 20px-tall, 260px-wide shimmer plus a 20px pill. Card: the three bands render at full opacity with their real labels (they are static), and each clause row renders 4-6 chip skeletons at `block-size:26px; border-radius:7px` with widths 90/64/110/78px. Zero CLS. Shimmer uses the `encSh` keyframe over `var(--sunken)`. No full-screen spinner on navigation.
- EMPTY (new) — route `/admin/dlp/rules/new`: the card renders with all three bands and one add-affordance per row, plus a single centred line explaining what a rule does and the one action that starts it ("Add a condition"). The simulation block is replaced by a single explanatory card stating that simulation runs once the rule has a condition, because 06 s9 makes simulation mandatory before enforcement.
- EMPTY (filtered): not applicable to a single rule; on the rules LIST that this screen links back to, it is "No rules match these filters" with a clear-filters action bound to the URL query.
- ERROR (5xx, network, Zod parse failure): the error state — what failed, whether it is retryable, a retry button, and a copyable request ID captured by the api client. A Zod parse failure is this state, never a silent `{}` default: an empty capabilities object would render as "policy denied everything", a wrong story told confidently (17-LLD s3).
- DENIAL (403 with a stable code) is NOT this state. It renders inline per 06 s24: the code in a copyable details disclosure, the server's user-safe sentence as the primary message, one remedy offered as an action where one exists. NO RETRY BUTTON — retrying a policy denial teaches the user the product is broken rather than that they lack permission (17-LLD s7). A cross-tenant or barrier miss arrives as 404 and renders the not-found state, never 403.

SURFACE 2 — THE SIMULATION (POST /admin/dlp/simulate)
- LOADING (first run): four stat-card skeletons at the real card box (`padding-block:12px; padding-inline:14px`, 22px value line, 11.5px label line) and, in each panel, 4 bar-row skeletons on the same `110px 1fr 28px` grid. Same box, no shift.
- LOADING (re-run over existing data): previous values stay, dimmed to `opacity:.5`, container `aria-busy="true"`, spinner in the Re-run button. Not skeletons.
- EMPTY (new) — never simulated: the stat grid and panels are replaced by one full-width card at the same `border-radius:var(--r-surf)` + `box-shadow:var(--hairline)` explaining that no simulation has run, with the single action "Run simulation". This is also what makes the enforce denial legible, since the server refuses enforcement on an unsimulated rule.
- EMPTY (filtered) — simulation ran and matched nothing in the window: distinct copy ("No events in the last 30 days would have been affected") with an action to widen the window, and the stat cards still render, showing formatted zeroes. A genuine zero and an unrun simulation must not look alike.
- ERROR: inline within the simulation block only; the rule card above stays interactive. Retry + copyable request ID.

THE THREE NON-ACTIONABLE TREATMENTS (17-LLD s6, ENC-673) — they may never share a CSS class, and a test asserts it:
- DENIED (policy): focusable, `aria-disabled="true"`, `aria-describedby` -> the server's reason + one remedy, present tense about the user, uses the denial treatment (`--danger` family). Applies to Enforce without recent MFA, Export in auditor mode, any control whose capability is false.
- UNBUILT (milestone): NOT focusable (`tabindex="-1"`), `aria-disabled="true"`, `aria-describedby` -> the release note, neutral `Later` chip, no remedy, future tense about the product, and NEVER the denial colour. Applies to Custom detectors, Cmd+J Ask, and any nav row whose milestone has not landed.
- BUSY (request in flight): focusable, `aria-busy="true"`, spinner in place of the control's leading slot, neutral colour, present tense about the request. Applies to Save draft, Enforce, Re-run.
Rationale to keep in the PR description: if most dimmed controls mean "not written yet", users learn dimmed is background noise on harmless surfaces and carry the habit to the one where DLP actually stopped them.

## Tokens

- `--canvas (page ground)`
- `--sheet (card and chip fill)`
- `--sunken (band fill, chip hover, skeleton base)`
- `--hover (nav and add-affordance hover)`
- `--selected (current nav row)`
- `--line / --line-strong`
- `--hairline (0 0 0 1px var(--line)) — every card and chip border; never a real 1px border`
- `--fg (title, current nav, chip label)`
- `--fg2 (nav idle, message chip, bar fill)`
- `--fg3 (breadcrumb, band label, connectors, stat label)`
- `--fg4 (separators, counts, remove glyph, footnote, chevrons)`
- `--accent (primary button fill)`
- `--accent-soft`
- `--accent-ring (focus outline)`
- `--r-ctrl (6px; buttons, nav rows)`
- `--r-surf (10px; cards and panels)`
- `--r-sheet (14px; dialogs)`
- `--danger (Block effect badge, denial treatment)`
- `--warn (Simulation mode chip)`
- `--ok`
- `--info`
- `--c-pub / --c-int / --c-conf / --c-hconf / --c-restr — LOCKED, not tenant-editable (09 s16a); classification chips must use these and also carry text`
- `--el1 / --el2 (popovers) / --el3 (dialogs, toast)`
- `--selbar-bg / --selbar-fg / --selbar-hov / --selbar-kbd (toast)`
- `--av-a-bg/-fg .. --av-d-bg/-fg (sample-event avatars)`
- `--sans (Inter, body)`
- `--tight (Inter Tight; title 20px and stat value 22px only)`
- `--mono (JetBrains Mono; counts, dates, kbd hints)`
- `chip radius 7px is a literal in the prototype, not a token — add --r-chip:7px to tokens.css rather than hard-coding it eight times`
- `rgba(255,255,255,.2) on the primary button kbd hint is a literal — add --kbd-on-accent`

## Technique fixes — the prototype breaks a hard rule here

- PHYSICAL CSS THROUGHOUT. Prototype uses padding:14px 8px 14px 12px, margin:6px 0 18px, float:right, margin-left:auto, text-align:right, left:24px, width/height. Fix: padding-block / padding-inline-start / padding-inline-end, margin-block, margin-inline-start:auto, text-align:end, inset-inline-start, inline-size / block-size. Same pixels, same appearance. en-XB pseudo-locale mirrors in CI and fails the build on any physical property.
- float:right on the Incidents count. Fix: the nav row is display:flex; align-items:center and the count uses margin-inline-start:auto. Identical position in LTR, correct in RTL, and it stops the float escaping the row.
- text-align:right on the bar count. Fix: text-align:end.
- Bar width injected as a formatted percentage string (width:{{sb.w}}). Fix: pass a unitless ratio into a --ratio custom property and set inline-size:calc(var(--ratio)*100%); transition inline-size, not width. Any percentage shown to a user goes through Intl.NumberFormat(locale,{style:'percent'}).
- Toast anchored left:24px;bottom:24px. Fix: inset-inline-start:24px; inset-block-end:24px.
- Dates written as 'Aug 15' / 'Aug 12'. Fix: Intl.DateTimeFormat(locale,{month:'short',day:'numeric'}) over an ISO-8601 instant in the user's timezone, with the full date via {dateStyle:'long',timeStyle:'short'} in a <time> title. Never a month-name lookup table, never a hand-built relative string.
- 'last 30 days' baked into the heading. Fix: an ICU message taking a formatted interval — Intl.DateTimeFormat.formatRange(start,end) — so the window is the server's actual simulation window and reads correctly in every locale.
- Stat values and counts as raw numerals. Fix: Intl.NumberFormat(locale). The prototype's Rs 4.8 Cr elsewhere is the documented defect this rule exists for (17-LLD s8); currency, when it appears, is {style:'currency',currency} with the server's currency code.
- The sentence is assembled from word fragments ('is at least', 'includes any of', 'and show', ', then'). This is the biggest i18n trap on the screen: word order and the position of the operator differ per language, and a concatenated sentence cannot be translated. Fix: one ICU message per clause shape with the chips as rich-text slots — e.g. dlp.clause.classificationAtLeast = '{field} is at least {value}' rendered with react-intl rich-text chunks, dlp.clause.detectedIncludesAny = '{field} includes any of {values}' with the value list passed through Intl.ListFormat(locale,{type:'disjunction'}). The connector spans then come from the message, not from JSX text nodes, and the visual result — var(--fg3) text between chips — is byte-identical.
- Typographic quotes and the &ldquo;/&rdquo; entities around the denial message. Fix: quotation is part of the catalog entry (locales differ), never hard-coded punctuation in JSX.
- Glyph buttons x and pencil with no accessible name. Fix: real <button> elements with aria-label from the catalog ('Remove {value}', 'Edit message'), the glyph itself aria-hidden. Keep the 18x18 box, 5px radius and var(--fg4) colour.
- href='#' with onClick for nav and the JSON link. Fix: router NavLink for navigation, <button type='button'> for actions. Same visual rules, but keyboard activation, middle-click and copy-link all work.
- style-hover attributes and inline styles. Fix: CSS modules with :hover and :focus-visible sharing one rule, so keyboard users get the hover affordance. Do not override the global :focus-visible ring.
- Screen title rendered as <h2> with no <h1>. Fix: the rule name is the <h1>; band labels are <h2>/<h3> in order. The three bands are role='group' with aria-labelledby pointing at their band label.
- Buttons re-derive nothing: the prototype hard-codes an enabled Enable/Enforce. Fix: render strictly from capabilities, with the three non-actionable treatments kept visually and semantically distinct.
- The prototype shows only the success state. It has no empty, filtered-empty, loading or error rendering anywhere (09 s11 records this as a gap in the reference, ENC-676). Its absence is not permission to ship three states — all four are specified above and are reviewed as part of the feature.

## Backend required

- GET /api/v1/admin/dlp/rules/{id} — currently 05-API s14.2 documents only GET (list) / POST / DELETE. A single-rule read is required for this route to be linkable (09 s21) and does not exist.
- capabilities object on the rule response — 05-API s7 puts capabilities on listing rows; admin rule responses need the same shape for saveDraft, enforce, withdraw, exportSimulation, editMessage. Without it this screen cannot render actions at all, and the client is forbidden from deriving them.
- ENC-674: a reason + remediation attached to every capability false. Until it lands, a disabled control with a client-invented explanation is worse than none (09 s5), so the enforce button must render UNBUILT rather than DENIED.
- POST /api/v1/admin/dlp/simulate — listed in the 05-API s13 admin map but with no request/response contract. Needs: window (interval), per-workspace would-block counts, four headline stats, and a sample-event list carrying actor display name, pre-computed initials, avatar slot, action class and an ISO-8601 timestamp.
- GET of the condition/scope/action vocabulary — the chip comboboxes must be populated from the server's closed condition set (05-API s14.2 makes conditions closed and refuses unknown clauses naming the clause). A client-side enum would be a second vocabulary that drifts silently.
- Rule lifecycle status. The prototype shows a per-rule Simulation badge and an Enable/Enforce button, but 05-API s14.2 states there is NO mode field and a body carrying one is rejected; mode is deployment configuration and 06 s9 keeps SIMULATION and ENFORCE from diverging by giving the evaluator no mode argument. Backend must decide between (a) a draft/live status distinct from mode, or (b) this screen surfaces the tenant deployment mode read-only. Until decided, the chip is read-only tenant config and the enforce button is UNBUILT.
- Workspace-scoped exceptions. The WHERE row shows 'Whole tenant except Legal / Deal room'. Stored `scope[]` is action classes (external_sharing, exposes_content, any, admin.manage_policy) with no library or workspace exception. Either a condition variant or an explicit exception list is needed, or the WHERE row must be reduced to scope selection only.
- Blast-radius endpoint for the confirm dialog (09 s21): affected file and library counts as numbers, never a preformatted string.
- Error codes this screen renders inline: 409 RULE_NAME_IN_USE (title field), 422 RULE_WOULD_GOVERN_ITS_OWN_WITHDRAWAL (WHERE row, with the documented remedy: scope it to exposes_content, external_sharing, or the exact actions), 403 STEP_UP_REQUIRED (api-client intercept).
- Crates: audit (the enforce write is audited inside the policy engine), auth (recent-MFA assertion for the privileged mutation), config (tenant dlp.facts_unavailable and dlp.restricted_at for classification rank labels), core (PolicyEngine::enforce on the admin action itself).