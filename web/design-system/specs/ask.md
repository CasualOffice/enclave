# ask — implementation spec

> Extracted from `enclave-client-prototype.html` by the spec workflow.
> The prototype stays the reference; this is a reading of it, not a replacement.

## Structure

## Route, ownership, module

Route: `/w/:workspaceId/ask` and `/w/:workspaceId/ask/:threadId`. Query contract: `?scope=<libraryId|workspace>&range=<iso8601-duration>`. Thread id, scope and range are URL state (17-FRONTEND-LLD §4/§5) so a thread is linkable and survives back/forward. Feature slice: `web/src/features/ask/` — `thread/`, `composer/`, `citation/`, `source-panel/`. Citation rendering imports `entities/classification` and `entities/file`; it must not import `features/libraries` (§2 boundary rule). Route-level code split.

**Milestone gate.** Ask ships in M7. Until then `⌘J` and every Ask entry point render the **unbuilt** treatment (not focusable, neutral `Later` chip, no remedy) — never the denial treatment. This spec describes the built surface.

---

## 1. Screen root — `<AskScreen>`

```
element: <main role="main" aria-labelledby="ask-thread-title">
display:grid
grid-template-columns: 1fr            (sourcePanelOpen === false)
                       1fr 440px      (sourcePanelOpen === true)
grid-template-rows: auto 1fr
flex:1; min-block-size:0
```
`440px` is a fixed track. Grid tracks follow writing mode automatically, so no direction fix is needed here. The column transition is a track change, not a mount/unmount — the thread column must not remount when the panel opens (it holds scroll position).

Three grid children: header bar (row 1, spans both columns), thread column (row 2 col 1), source panel (row 2 col 2).

---

## 2. Header bar — `<AskHeader>` (grid-column: 1 / -1)

```
display:flex; align-items:center; gap:6px
padding-block: 10px 0
padding-inline: 16px 14px
color: var(--fg3); font-size: 12.5px; min-block-size: 38px
```

Children in order:
1. `<span>` breadcrumb root — text `ask.breadcrumb.root`.
2. `<span aria-hidden="true">` separator `/` — `color:var(--fg4); margin-inline:2px`.
3. `<h1 id="ask-thread-title">` — `color:var(--fg); font-weight:500; font-size:inherit; margin:0`. Content: thread title from the server, or `ask.thread.new` when `threadId` is absent. **Truncation is CSS, not JS** — the prototype slices at 42 chars in JS, which cuts mid-grapheme and mid-word in any script. Use `max-inline-size:42ch; overflow:hidden; text-overflow:ellipsis; white-space:nowrap` and put the full title in `title=`/`aria-label`.
4. Right cluster — `display:flex; align-items:center; gap:4px; margin-inline-start:auto`.
   - **Scope chip** (`<Chip>` from `shared/ui`, non-interactive, `role="status"` omitted): `display:inline-flex; align-items:center; gap:5px; block-size:20px; padding-inline:8px; border-radius:999px; font-size:11px; font-weight:500; box-shadow:var(--hairline); color:var(--fg2)`. Leading `<svg>` folder glyph `inline-size:11px; block-size:11px`. Label: `ask.scope.chip` with `{name}` = server-supplied scope display name.
   - **Share thread** `<button type="button">`: `display:inline-flex; align-items:center; block-size:24px; padding-inline:8px; border-radius:var(--r-ctrl); border:0; font:inherit; font-size:12px; font-weight:500; background:transparent; color:var(--fg2)`. Hover/focus-visible: `background:var(--hover); color:var(--fg)`.

---

## 3. Thread column — `<AskThread>` (row 2, col 1)

```
padding-block: 20px
padding-inline: 28px
overflow: auto
display:flex; flex-direction:column; gap:22px
min-inline-size: 0
position: relative          /* for the divider pseudo-element */
```
Divider (only when `sourcePanelOpen`), replacing the prototype's `box-shadow:1px 0 0 var(--line)`:
```
&::after { content:''; position:absolute; inset-block:0; inset-inline-end:0;
           inline-size:1px; background:var(--line); pointer-events:none }
```
`aria-live="polite"` on the turn container so streamed answer text is announced; `aria-busy` mirrors `isStreaming`.

### 3.1 User turn — `<AskUserTurn>`
```
font-size:13px; line-height:1.55; animation: enc-in .2s both
> header row: display:flex; align-items:center; gap:6px;
              color:var(--fg3); font-size:12px; margin-block-end:6px
  > avatar: inline-size:20px; block-size:20px; border-radius:50%;
            background:var(--av-a-bg); color:var(--av-a-fg);
            display:inline-flex; align-items:center; justify-content:center;
            font-size:9.5px; font-weight:600
  > question text (the user's own input — rendered as text, never as markup)
```
Avatar initials come from the server's user object; the palette slot (`--av-a-*` … `--av-d-*`) is chosen by a stable hash of user id in `entities/user`.

### 3.2 Assistant turn — `<AskAnswer>`
```
font-size:13px; line-height:1.55; max-inline-size:62ch; position:relative
> status row: same box as 3.1's header row, but the avatar is
    inline-size:20px; block-size:20px; border-radius:50%;
    background:var(--accent-soft); color:var(--accent);
    inline-flex centered; icon 11×11 (spark)
  status text: i18n key by phase — ask.status.retrieving {scopeName} /
               ask.status.answered {count} (ICU plural over source count)
```

**Retrieving skeleton** (`phase === 'retrieving'`), replacing the prototype's three shimmer bars:
```
container: display:flex; flex-direction:column; gap:6px;
           inline-size:70%; margin-block-start:6px
bar:       block-size:10px; border-radius:4px;
           background: linear-gradient(var(--enc-shimmer-angle),
                       var(--sunken) 25%, var(--g150) 50%, var(--sunken) 75%);
           background-size:200% 100%;
           animation: enc-shimmer 1.4s infinite
bar widths: 90%, 70%, 45%
```
`--enc-shimmer-angle: 90deg` on `:root`; `[dir="rtl"] { --enc-shimmer-angle: 270deg }`. This is a skeleton, so it also carries `aria-hidden="true"` (the status row is what is announced).

**Answer body.** Paragraph 1: `margin:0; animation: enc-fade .35s both`. Paragraph 2 onward: `margin-block-start:8px; color:var(--fg2)`. The prototype hard-codes English prose with `<b>` and `<em>`; in the real product the body is server-returned structured content: an array of `{ kind: 'text' | 'emphasis' | 'strong' | 'citation', value | citationIndex }` spans. **Never `dangerouslySetInnerHTML`** — the excerpt/answer text is document content, and 05-API §11 is explicit that interpolating document content into markup is how stored XSS is delivered. Each span maps to a `<span>`, `<strong>`, `<em>` or `<CitationRef>`. Bidi-isolate every text span (`unicode-bidi:isolate`) per 14-I18N §7.

**Citation reference — `<CitationRef>`** (prototype uses `<sup>` with hover-only handlers; must be a real control):
```
element: <button type="button" aria-describedby={popoverId} aria-expanded>
display:inline-flex; align-items:center; justify-content:center
min-inline-size:16px; block-size:16px; padding-inline:4px
border:0; border-radius:5px
background:var(--sunken); color:var(--fg2)
font-family:var(--mono); font-size:10px; font-weight:600
vertical-align:1px; margin-inline-start:1px
box-shadow:var(--hairline)
hover / focus-visible: background:var(--accent-soft); color:var(--accent)
```
The index digit is rendered with `Intl.NumberFormat` (locale digits), not string concatenation.

**Sources list** (`phase === 'complete'`):
```
container: display:flex; flex-direction:column; gap:4px; margin-block-start:10px;
           animation: enc-fade .35s both
row (<button type="button"> — it changes app state, so not an <a href="#">):
  display:flex; align-items:center; gap:8px
  font-size:12px; color:var(--fg2)
  padding-block:5px; padding-inline:8px; border-radius:var(--r-ctrl)
  background:transparent; border:0; inline-size:100%; text-align:start
  hover / focus-visible: background:var(--hover)
  children:
    index      font-family:var(--mono); font-size:10.5px; color:var(--fg4)
    file icon  inline-size:14px; block-size:14px; color:var(--ft-<ext>)
    filename   flex:1 1 auto; overflow:hidden; text-overflow:ellipsis
    class dot  inline-size:7px; block-size:7px; border-radius:50%;
               background:var(--c-<rank>)   + visually-hidden label
    locator    margin-inline-start:auto; color:var(--fg4);
               font-family:var(--mono); font-size:10.5px
```
Locator text (`p.14 · §18.2`) is composed from an i18n message with `Intl.NumberFormat` page numbers — `ask.source.locator.page` / `.section` / `.pageAndSection`. Never `"p." + n`.

**Assurance footer:**
```
display:flex; align-items:center; gap:6px; margin-block-start:8px
color:var(--fg4); font-size:11px; animation: enc-fade .35s both
> shield icon 12×12
> text  ask.assurance.line  (interpolated, not concatenated from fragments)
> audit link  <Link to={auditHref}> color:var(--fg3)
```
The audit link renders only when the server returns `auditEntryHref` on the answer. It is not a client-constructed URL.

### 3.3 Citation popover — `<CitationPopover>`
Anchored to the invoking `<CitationRef>`, not to fixed coordinates. The prototype's `left:34px; top:52px` are its measured resting offsets; reproduce them as the anchor's placement defaults (`placement: block-end / inline-start`, `offset: 6px`) via the `shared/ui` popover primitive with collision flipping.
```
position:absolute; z-index:6
background:var(--sheet); border-radius:var(--r-surf); box-shadow:var(--el2)
padding-block:10px; padding-inline:12px
inline-size:280px; font-size:12px
animation: enc-fade .15s both
> header: display:flex; align-items:center; gap:8px; margin-block-end:6px
    icon 14×14 (typed colour) · title font-weight:500 ·
    locator margin-inline-start:auto; font-family:var(--mono);
            font-size:10.5px; color:var(--fg4)
> blockquote: margin:0; padding-block:6px; padding-inline:8px;
    background:var(--sunken); border-radius:6px; color:var(--fg2);
    line-height:1.45; font-size:11.5px
    (verbatim document text, bidi-isolated, rendered as text)
> footer: display:flex; align-items:center; gap:6px; margin-block-start:8px
    [Open at passage] button:
      inline-flex; block-size:24px; padding-inline:8px;
      border-radius:var(--r-ctrl); border:0; font:inherit; font-size:12px;
      font-weight:500; background:var(--sheet); color:var(--fg);
      box-shadow:var(--hairline); hover: background:var(--sunken)
    obligation chip: margin-inline-start:auto; inline-flex; block-size:20px;
      padding-inline:8px; border-radius:999px; font-size:11px; font-weight:500;
      background:color-mix(in srgb, var(--warn) 14%, transparent);
      color:var(--warn)
```
The obligation chip and the `Open at passage` button both render **from the citation's `capabilities` object**. `capabilities.preview === false` ⇒ the button renders disabled with the server's `reason` + `remediation`, and the chip shows the server's obligation label. The client never infers "preview only" from a classification rank.

### 3.4 Composer — `<AskComposer>`
```
wrapper outer: margin-block-start:auto        /* pins to the column's end */
wrapper: display:flex; flex-direction:column; gap:6px
  border-radius:var(--r-surf); box-shadow:var(--hairline)
  padding-block:8px 6px; padding-inline:10px 8px
  background:var(--sheet)
  &:focus-within { box-shadow: 0 0 0 1px var(--accent),
                               0 0 0 4px var(--accent-ring) }
input <textarea rows=1 auto-grow, max 5 rows>:
  border:0; background:transparent; font:inherit; font-size:12.5px
  color:var(--fg); outline:0; inline-size:100%; resize:none
  placeholder: ask.composer.placeholder.new / .followUp (i18n)
toolbar: display:flex; align-items:center; gap:4px
  scope chip     (see §2, with folder icon 11×11) — removable, sets ?scope=
  range chip     block-size:20px; padding-inline:8px; border-radius:999px;
                 font-size:11px; font-weight:500; box-shadow:var(--hairline);
                 color:var(--fg2)
  spacer         flex:1
  hint           color:var(--fg4); font-size:11px  → ask.composer.hint
  send button    inline-size:24px; block-size:24px; border-radius:7px;
                 background:var(--accent); color:var(--on-accent); border:0;
                 inline-flex centered; icon 12×12
```
The range chip label (`Last 12 months`) is `Intl.RelativeTimeFormat(locale, {numeric:'auto'}).format(-12, 'month')` wrapped in `ask.composer.range` — never the literal string.

---

## 4. Source panel — `<AskSourcePanel>` (row 2, col 2, 440px)

```
display:flex; flex-direction:column; min-inline-size:0; overflow:hidden
animation: enc-peek .2s ease-out both
```
`@keyframes enc-peek { from { opacity:0; transform: translateX(calc(14px * var(--enc-dir))) } to { opacity:1; transform:none } }` with `--enc-dir:1` on `:root` and `-1` under `[dir="rtl"]`. Transforms have no logical form; the multiplier is the correct technique and preserves the LTR appearance exactly.

```
header: display:flex; align-items:center
        padding-block:8px 0; padding-inline:14px 8px
        color:var(--fg3); font-size:11.5px
  > label   ask.source.counter {current}{total}  (ICU, Intl digits)
  > spacer  flex:1
  > open-in-place button: inline-size:26px; block-size:26px; inline-flex centered;
      border-radius:var(--r-ctrl); border:0; background:transparent;
      color:var(--fg3); hover: background:var(--hover); color:var(--fg)
      icon 14×14

title block: padding-block-start:6px; padding-inline:14px
  > <h2> margin:0; font-size:13.5px; font-weight:500   (filename)
  > <p>  color:var(--fg3); font-size:12px; margin-block-start:2px  (locator)

obligation row: display:flex; flex-wrap:wrap; gap:5px;
                padding-block:8px; padding-inline:14px
  classification chip: inline-flex; align-items:center; gap:6px; block-size:20px;
    padding-inline:7px 8px; border-radius:999px; font-size:11px; font-weight:500;
    background: color-mix(in srgb, var(--c-restr) 11%, transparent);
    color:      color-mix(in srgb, var(--c-restr) 82%, var(--fg));
    dot: inline-size:6px; block-size:6px; border-radius:50%;
         background:var(--c-restr)
  obligation chip (No download): block-size:20px; padding-inline:8px;
    border-radius:999px; font-size:11px; font-weight:500;
    background: color-mix(in srgb, var(--warn) 14%, transparent);
    color: var(--warn)
  neutral chip (Watermarked): background:var(--sunken); color:var(--fg2);
    same box
```
The `--c-restr` in the classification chip is a **token lookup by the server's rank**, not a hardcoded rank: `var(--c-{pub|int|conf|hconf|restr})`. The obligation chips are rendered one-per-entry from the server's `obligations[]` array with server labels.

```
preview stage:
  margin-block-end:14px; margin-inline:14px; flex:1
  border-radius:var(--r-surf); background:var(--sunken)
  position:relative; overflow:hidden
  display:flex; align-items:flex-start; justify-content:center
  padding-block-start:18px
```
Inside it, the real product renders the **server-issued watermarked rendition tiles** from `preview` crate (never an object-storage URL — CLAUDE.md rule 6). The prototype's fake page is the *loading skeleton's* geometry, and should be kept as exactly that:
```
page skeleton: inline-size:78%; background:var(--sheet); box-shadow:var(--el2)
  padding-block:22px; padding-inline:20px
  display:flex; flex-direction:column; gap:7px; border-radius:2px
  heading line: block-size:4px; inline-size:38%; background:var(--g300)
  body lines:   block-size:2px; background:var(--g200);
                widths 100%, 96%, 70%  … then 100%, 88%, 94%, 50%
  highlight band: margin-block:6px; margin-inline:-6px; padding:6px
    background: color-mix(in srgb, var(--accent) 12%, transparent)
    border-radius:4px
    border-inline-start: 2px solid var(--accent)
    display:flex; flex-direction:column; gap:6px
    3 lines: block-size:2px; background:var(--g300); widths 100%, 92%, 60%
```
On the loaded rendition, the cited passage keeps the same highlight treatment (`color-mix(in srgb, var(--accent) 12%, transparent)` + `border-inline-start:2px solid var(--accent)`), positioned from the server's chunk offsets.

```
watermark overlay:
  position:absolute; inset:0
  display:flex; align-items:center; justify-content:center
  font-family:var(--mono); font-size:9px
  color: color-mix(in srgb, var(--c-restr) 25%, transparent)
  transform: rotate(-22deg)
  line-height:3; text-align:center; white-space:nowrap
  pointer-events:none
```
**The client does not compose the watermark text.** The prototype interpolates `priya.nair@northwind · RESTRICTED · f7c2…9a1e` client-side; a client-rendered watermark is removable with devtools. The watermark is burned into the rendition by the `preview` crate. This DOM layer exists only as the *skeleton-phase* placeholder and is `aria-hidden`.

## Interactions

## Interactive inventory

| # | Element | Trigger | Behaviour | Keyboard |
|---|---|---|---|---|
| 1 | Suggestion button (idle, ×3) | click / `Enter` / `Space` | Submits that question. Server-supplied suggestions (`GET /search/answer/suggestions?scope=`) — never a hardcoded list. Focus moves to the answer status row. | native button; `Tab` order = visual order |
| 2 | Composer textarea | typing | Local `useState` draft. Keystroke→paint < 16 ms (docs/09 §2): no per-keystroke query, no debounce work on the input path. | `Enter` submits when non-empty and not composing; `Shift+Enter` inserts a newline; `Esc` clears the draft if non-empty, otherwise blurs |
| 3 | Send button | click | Submits the draft. Disabled (busy treatment, `aria-busy`, spinner in place, 24×24 box unchanged) while a request is in flight. **Never** disabled by a client-derived permission. | reachable by `Tab`; `⌘Enter` also submits from anywhere in the composer |
| 4 | Scope chip (composer) | click | Opens the scope picker popover; selection writes `?scope=` and refetches suggestions. Removing the scope reverts to the workspace default. | `Enter`/`Space` opens; `Esc` closes and returns focus |
| 5 | Range chip (composer) | click | Opens the range picker; writes `?range=`. | as #4 |
| 6 | Citation ref `<sup>` | hover, focus, click | Hover **or keyboard focus** opens the popover (prototype is hover-only and unreachable by keyboard — a defect). Open on `mouseenter` after 120 ms, on `focus` immediately, on click toggles and pins. Closes on `mouseleave` after 200 ms, on `blur` if not pinned, on `Esc` always. `aria-expanded` reflects state; the popover has `id` referenced by `aria-describedby`. | `Enter`/`Space` pins; `Esc` closes and returns focus to the `<sup>`; `Tab` from a pinned popover moves into it |
| 7 | `Open at passage` (popover) | click | Opens the source in the source panel and scrolls the rendition to the chunk. Renders from `citation.capabilities.preview`. If `false`: `aria-disabled="true"`, denial treatment, server `reason` + one `remediation`, **no retry**. | native button |
| 8 | Source row (answer footer) | click | Selects that source into the panel; sets panel index. Does not navigate away from the thread. | `Enter`; `↑`/`↓` move within the source list when focus is inside it |
| 9 | Panel open-in-place button | click | Navigates to `/w/:ws/l/:lib?peek=:fileId` at the cited page. Gated on `capabilities.preview`. | native button |
| 10 | Share thread | click | Opens the share dialog. Gated on the thread's `capabilities.share` / `shareExternal` (two separate booleans — never collapsed). | native button |
| 11 | Audit entry link | click | Navigates to the audit record for this ask. Rendered only when the server supplies `auditEntryHref`. | native link |
| 12 | Thread column | scroll | Auto-scrolls to the streaming answer only while the user is already within 48 px of the end; a user who has scrolled up is never yanked. | `Home`/`End` jump within the scroll container |

## Screen-level keyboard

- `⌘J` / `Ctrl+J` — opens Ask from anywhere (docs/09 §6). Registered and **unbuilt-disabled until M7**.
- `⌘K` — command palette; Ask actions appear in it with their shortcuts shown.
- `Esc` — closes the citation popover if open; else closes the source panel; else blurs the composer. One `Esc` per layer, outermost last.
- `/` — focuses search (global binding), not the ask composer. Do not steal `/`.
- `?` — keyboard reference. The ask surface contributes its bindings to that sheet.
- Focus order follows visual order. When the source panel opens it does **not** steal focus (it is a consequence of an answer, not a user navigation); a visually-hidden live region announces `ask.a11y.sourcePanelOpened`.
- Focus returns to the triggering element when the popover, the share dialog or the scope picker closes.

## Streaming and phases

Server phase enum drives the thread: `queued → retrieving → answering → complete`, plus terminal `denied` and `failed`. The prototype's timed 4-phase fake (900/1700/2400 ms) maps to: `retrieving` = skeleton; `answering` = spans arrive incrementally, source list not yet shown; `complete` = source list + assurance footer + source panel mount.

- The source panel mounts **only** at `complete`, and only if `sources.length > 0`.
- Streamed spans append; already-rendered spans never re-animate (docs/09 §12: no motion on data updates in place).
- `prefers-reduced-motion: reduce` removes `enc-in`, `enc-peek`, `enc-shimmer` movement and keeps opacity only.
- Abort: an in-flight ask is cancellable; the send button becomes a stop button in the same 24×24 box.

## Capabilities contract

Actions on this surface read from three capability objects, never from anything the client computes:
- **thread**: `{ share, shareExternal, delete }`
- **citation** (per source): `{ preview, download, print, export }` + `obligations[]` + `reason`/`remediation` when a flag is `false`
- **ask** (per scope): `{ ask }` — a scope the user may browse but not ask across renders the composer disabled with the server's reason.

`staleTime: 0` on every capability-bearing query (17-FRONTEND-LLD §4.1). A share or ACL mutation invalidates them.

## States

All four are required on **both** data surfaces on this screen — the thread and the source panel — plus on the suggestion list.

## Thread surface

**Empty (new)** — no thread, no query yet. This is the prototype's idle block, and it is the only one the prototype draws:
```
container: margin:auto; text-align:center; max-inline-size:420px;
           animation: enc-in .25s both
badge:  inline-size:40px; block-size:40px; border-radius:12px;
        background:var(--accent-soft); color:var(--accent);
        inline-flex centered; margin-block-end:14px; icon 18×18 spark
h2:     margin-block-end:6px; font-family:var(--tight); font-size:18px;
        font-weight:600; letter-spacing:-.02em     → ask.empty.new.title {scopeName}
p:      margin-block-end:18px; color:var(--fg3); font-size:12.5px;
        line-height:1.5                            → ask.empty.new.body
list:   display:flex; flex-direction:column; gap:6px
row:    display:flex; align-items:center; gap:8px;
        padding-block:9px; padding-inline:12px;
        border-radius:var(--r-surf); border:0; font-size:12.5px;
        background:var(--sheet); color:var(--fg2);
        box-shadow:var(--hairline); text-align:start
        hover / focus-visible: background:var(--sunken); color:var(--fg)
        leading icon 12×12, color:var(--accent), flex:none
```
The one action that starts the surface is the composer, always visible below.

**Empty (filtered)** — scope and/or range are set and the server returns zero addressable documents for them (`sources.length === 0` before any question is asked, or `code: NO_MATCHING_CONTENT` on submit). Same box as empty(new), swapped copy: title `ask.empty.filtered.title`, body `ask.empty.filtered.body` naming the active scope and range, and a single **Clear filters** button (same row treatment as a suggestion row, but `color:var(--fg)` and no leading spark icon) that strips `?scope=` and `?range=`. The suggestion list is *not* shown here — suggestions for an empty scope are noise.

**Loading** — two shapes:
- *Thread load* (opening an existing `/ask/:threadId`): skeleton turns that share the loaded turn's box model — a 20×20 avatar circle, a 12px status line, then 2–3 body lines at `block-size:10px; border-radius:4px`, widths 90/70/45%, `gap:6px`, using the same `enc-shimmer` gradient. Same `gap:22px` between turns, so nothing shifts when the real turns land. `aria-busy="true"` on the thread container.
- *Answer in flight*: §3.2's retrieving skeleton (the 70%-wide three-bar block), with the status row already rendered above it.

**Error** — a request that **failed** (5xx, network, Zod parse): a card in the thread flow, `background:var(--sheet); box-shadow:var(--hairline); border-radius:var(--r-surf); padding:12px; font-size:12.5px`. Contains: what failed (`ask.error.title`), whether it is retryable, a **Retry** button (same box as `Open at passage`), and a copyable request ID in `font-family:var(--mono); font-size:10.5px; color:var(--fg4)` with a copy button. The composer stays enabled.

**Denied** — a `403` with a stable code. **This is not the error state and it never shows Retry** (docs/09 §11, 17-FRONTEND-LLD §7). Rendered inline in the thread with the denial treatment: the server's `message` and exactly one `remediation` action, focusable, present tense. Never names the rule that matched (CLAUDE.md rule 10). Distinguishable from the failure card by treatment, not by copy alone.

**Unbuilt** — reachable here only when a citation points into a surface a later milestone owns. Neutral `Later` chip (`background:var(--sunken); color:var(--fg2); block-size:20px; padding-inline:8px; border-radius:999px; font-size:11px`), `aria-disabled="true"`, **not focusable**, `aria-describedby` → release note, no remedy, future tense about the product. Must not share a CSS class with the denial treatment (test F2).

## Source panel surface

- **Empty (new)** — the panel does not mount when there are no sources. If the server returns an answer with `sources: []` (it should not), the assurance footer says so via `ask.sources.none` and the panel stays closed; the grid stays at `1fr`.
- **Empty (filtered)** — n/a as a separate shape; a scope with no addressable content is caught upstream by the thread's empty(filtered).
- **Loading** — the §4 page-skeleton geometry (78%-wide sheet, 4px heading rule, 2px body rules, the highlight band) is exactly this state. Chips and title render as soon as the citation metadata arrives; only the rendition area skeletons.
- **Error** — rendition fetch failed: the stage area (`background:var(--sunken)`, same box) holds a centred failure block with `ask.preview.error.title`, a Retry button and the request ID. The chips and title above stay, because that metadata succeeded.
- **Denied** — `capabilities.preview === false`: the stage renders the denial treatment with the server's reason and one remedy, and no rendition is requested at all. **No retry.**
- **Busy** — a rendition still being generated (`preview.requested` in flight) or content still `SCANNING`: neutral spinner in place of the page, `aria-busy="true"`, no denial colour. Nothing is served while `SCANNING` (CLAUDE.md rule 9).

## Suggestion list

- Empty(new): the three server suggestions.
- Empty(filtered): omitted (see above).
- Loading: three rows at the loaded row's exact box (`block-size` from `padding-block:9px` + 12.5px line), shimmered.
- Error: the suggestion list is non-critical — it collapses silently and the composer alone carries the empty(new) state. It must never block first paint (docs/09 §2).

## Tokens

- `--accent`
- `--accent-soft`
- `--accent-ring`
- `--on-accent  (NEW — replaces the prototype's literal #fff on the send button; #fff light, #141412 in the dark/meridian brand where --accent is near-white)`
- `--sheet`
- `--sunken`
- `--canvas`
- `--hover`
- `--selected`
- `--line`
- `--hairline`
- `--el2`
- `--fg`
- `--fg2`
- `--fg3`
- `--fg4`
- `--g150`
- `--g200`
- `--g300`
- `--warn`
- `--danger`
- `--c-pub`
- `--c-int`
- `--c-conf`
- `--c-hconf`
- `--c-restr`
- `--av-a-bg`
- `--av-a-fg`
- `--av-b-bg`
- `--av-b-fg`
- `--av-c-bg`
- `--av-c-fg`
- `--av-d-bg`
- `--av-d-fg`
- `--r-ctrl`
- `--r-surf`
- `--r-sheet`
- `--sans`
- `--tight`
- `--mono`
- `--ft-pdf  (NEW — was literal #D0453A)`
- `--ft-doc  (NEW — was literal #3B6FD4)`
- `--ft-sheet`
- `--ft-slide`
- `--ft-image`
- `--ft-generic`
- `--enc-dir  (NEW — 1 in LTR, -1 under [dir="rtl"]; multiplies every translateX)`
- `--enc-shimmer-angle  (NEW — 90deg LTR, 270deg RTL; the skeleton gradient direction)`

## Technique fixes — the prototype breaks a hard rule here

- Header bar `padding:10px 14px 0 16px` (physical shorthand, T/R/B/L) → `padding-block: 10px 0; padding-inline: 16px 14px`. Identical LTR box; mirrors correctly in RTL.
- `margin-left:auto` on the header's right cluster, the sources-row locator, the popover locator and the popover's obligation chip → `margin-inline-start:auto` in every case.
- Breadcrumb separator `margin:0 2px` → `margin-inline: 2px` (block margin was already 0).
- Suggestion row `text-align:left` → `text-align:start`.
- Citation `<sup>` `margin-left:1px` → `margin-inline-start:1px`.
- Citation popover `position:absolute; left:34px; top:52px` → anchored placement via the shared popover primitive with `inset-inline-start` / `inset-block-start` and collision flipping. The literal 34/52 px are the LTR resting offsets to reproduce, not coordinates to hardcode — a fixed `left` puts the popover on the wrong side of its anchor in RTL and off-screen near the viewport edge.
- Preview highlight band `border-left:2px solid var(--accent)` → `border-inline-start: 2px solid var(--accent)`. Same 2 px accent rule on the reading-start edge.
- Preview highlight band `margin:6px -6px` → `margin-block:6px; margin-inline:-6px`.
- Thread-column divider `box-shadow: 1px 0 0 var(--line)` (offset-x is physical; the hairline lands on the wrong edge in RTL) → `position:relative` on the column plus `&::after { content:''; position:absolute; inset-block:0; inset-inline-end:0; inline-size:1px; background:var(--line) }`. Pixel-identical in LTR, correct in RTL, and it does not consume layout width the way a `border-inline-end` would.
- Source-panel entrance `@keyframes encPeek { transform: translateX(14px) }` (transforms have no logical form) → `translateX(calc(14px * var(--enc-dir)))` with `--enc-dir:1` on `:root` and `-1` under `[dir="rtl"]`. The panel always slides in from the inline-end edge it occupies.
- Skeleton shimmer `linear-gradient(90deg, …)` (gradient angles are physical) → `linear-gradient(var(--enc-shimmer-angle), …)` with `90deg` LTR / `270deg` RTL, so the sweep always runs with the reading direction.
- Every `width:` / `height:` / `min-width:` / `max-width:` in the range → `inline-size` / `block-size` / `min-inline-size` / `max-inline-size`. Notably `max-width:62ch` on the answer body → `max-inline-size:62ch`, and `min-width:0` on the grid children → `min-inline-size:0` (the flex/grid overflow guard, which must follow the writing mode).
- Send button `color:#fff` → `var(--on-accent)`. The literal is unreadable under the `meridian` brand in dark mode, where `--accent` is `#E5E7EB`.
- Source-row and popover file icons `color:#D0453A` / `#3B6FD4` → `var(--ft-pdf)` / `var(--ft-doc)`, selected by the server-supplied MIME type through `entities/file`.
- Watermark `color:rgba(194,39,58,.25)` (an un-tokenised copy of `--c-restr`) → `color-mix(in srgb, var(--c-restr) 25%, transparent)`, matching the same construction already used by the classification and obligation chips.
- Thread title truncated in JS: `s.askQ.slice(0, 42) + '…'` → CSS `max-inline-size:42ch; overflow:hidden; text-overflow:ellipsis; white-space:nowrap`, full text in `title`/`aria-label`. `String.prototype.slice` cuts code units, which splits grapheme clusters and surrogate pairs in Hindi, Arabic, Thai, Japanese and emoji.
- Every user-facing literal → i18n catalog: `Ask`, `New thread`, `Scope: Contracts`, `Share thread`, `Ask across Contracts`, `Answers come only from documents you can open…`, all three suggestion strings, `Searching Contracts — hybrid retrieval, your access only…`, `Answer · from 2 documents you can open`, `Ask across Contracts…` / `Ask a follow-up…` placeholders, `Hybrid retrieval · sources always shown`, `Answered inside your access · Restricted content stays preview-only`, `Audit entry`, `Open at passage`, `Preview only`, `Source 1 of 2`, `Page 14 · §18.2 Termination`, `Restricted`, `No download`, `Watermarked`. The suggestion strings additionally move server-side — they are scope-derived, not static copy.
- `Source 1 of 2` string-concatenated → ICU message `ask.source.counter` with `Intl.NumberFormat` digits and a plural category on the total.
- `p.14 · §18.2` and `Page 14` composed by concatenation → `ask.source.locator.pageAndSection` with `Intl.NumberFormat` for the page number. Arabic-Indic and Devanagari locales render different digits; `"p." + n` cannot.
- `Last 12 months` literal → `Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(-12, 'month')` inside `ask.composer.range`.
- `Answer · from 2 documents you can open` hardcodes the count → ICU plural `ask.status.answered` over `sources.length`.
- Citation `<sup>` opens only on `onMouseEnter`/`onMouseLeave` and is not a focusable element → `<button type="button">` with `aria-expanded` and `aria-describedby`, opening on hover *and* focus, closing on `Esc`. A citation that only a mouse can reach fails docs/09 §15 outright — verifying a source is the point of the surface.
- Source rows and the audit entry are `<a href="#" onClick>` → `<button type="button">` for the in-app state change (source selection) and a real router `<Link>` for the audit entry. `href="#"` breaks middle-click, breaks the status bar preview and pushes a history entry that goes nowhere.
- Answer body is hardcoded HTML with `<b>`/`<em>` → server-returned structured spans rendered as React elements. Never `dangerouslySetInnerHTML`: 05-API §11 states that retrieval never emits markup and that interpolating document content into a markup string is how stored XSS is delivered. Quoted document text (the blockquote, the answer spans) is additionally bidi-isolated per 14-I18N §7 without stripping the control characters.
- Watermark text `priya.nair@northwind · RESTRICTED · f7c2…9a1e` composed in the client DOM → burned into the rendition by the `preview` crate. A client-side overlay is removed with one devtools node deletion, and the fake page it sits on is a skeleton, not content. The DOM layer survives only as the loading placeholder, `aria-hidden`.
- `Preview only` / `No download` / `Restricted` chips are static markup → rendered from the citation's server `capabilities` + `obligations[]`. A client that renders `No download` because the classification is `Restricted` has re-derived a permission (CLAUDE.md rule 6 collapses five permissions into one exactly this way).
- `openSource1` / `openSource2` are unconditional → gated on `capabilities.preview`; when `false`, disabled with the server's `reason` and `remediation` and **no retry affordance** (17-FRONTEND-LLD §7, test F3).
- The prototype's phase timer (`900 / 1700 / 2400 ms`) is a demo device → replace with the server's streamed phase enum. Do not ship a minimum-duration skeleton; the 100 ms acknowledgement budget (docs/09 §2) is a ceiling on the *first* paint, not a floor on the skeleton.
- The prototype draws no empty(filtered), no error and no denied state on this screen — docs/09 §11 names that as a gap in the reference, not a licence. All are specified above.

## Backend required

- POST /search/answer — the ask itself (05-API §11 names it; RAG, always returns cited chunk sources). Request: { question, scope: { workspaceId | libraryId | folderId }, range?, threadId? }. Streams SSE frames: { phase: 'queued'|'retrieving'|'answering'|'complete'|'denied'|'failed' }, span deltas, then the final sources array. Tenant identity comes from the verified token — there is no tenant parameter in the client signature (17-FRONTEND-LLD §9).
- Answer span model — the response body must be structured spans ({ kind: 'text'|'strong'|'emphasis'|'citation', value | citationIndex }), not an HTML string. Blocked on the same rule as 05-API §11's excerpt handling: retrieval never emits markup.
- Per-citation capabilities — each source carries { preview, download, print, export } plus obligations[] with server-authored labels, and reason + remediation on any false. ENC-674 (a reason attached to a false capability) is a hard prerequisite: until it lands, a disabled Open-at-passage button has no honest explanation and the client must not invent one.
- GET /search/answer/suggestions?scope=&range= — the three scope-derived starter questions. Must be server-side: the suggestions name the scope's actual content and must already be filtered to what the caller can open.
- POST /search/threads, GET /search/threads/{id}, GET /search/threads/{id}/messages — thread persistence, so /ask/:threadId is loadable and shareable. Thread-level capabilities { share, shareExternal, delete }.
- POST /search/threads/{id}/share — share-thread dialog target. shareExternal is a separate boolean and must not be collapsed into share (CLAUDE.md rule 6).
- GET /files/{id}/preview?page=&chunk= — watermarked, sanitized rendition tiles from the preview crate. Must never return an original object-storage URL on a preview path (CLAUDE.md rule 6), and must not serve while the file is SCANNING (rule 9).
- Chunk-offset payload on each citation — { fileId, versionId, page?, section?, charStart, charEnd } so the rendition highlight is positioned from the server, not guessed from the excerpt text.
- GET /audit/entries/{id} plus an auditEntryHref on the answer — the assurance footer's link. The client must not construct this URL; it renders only when the server supplies it.
- crates/search — query planning, hybrid retrieval, and the PostgreSQL post-filter. The vector index is a candidate generator only; every returned source is confirmed against PostgreSQL before it reaches the client (CLAUDE.md rule 5).
- crates/embeddings — embedding provider routing by classification, so a Restricted document is not embedded through a provider its label forbids.
- crates/indexing — chunk manifests; the citation locator (page, section, offsets) comes from the manifest, not from a re-parse at answer time.
- crates/preview — rendition generation, sanitization and watermarking. The watermark is burned server-side; the client renders no identity overlay.
- crates/classification + crates/dlp — the rank and the obligations behind every chip on the source panel.
- crates/audit — one audit event per ask, per source opened, and per denial. Audit happens inside the policy engine, for denials as well as allows (CLAUDE.md rule 10), and never records the question's DLP matches or document content.
- crates/mcp — the same retrieval surface exposed to AI clients; the ask screen and MCP must share one enforcement path, not two.
- Degraded-retrieval signal — diagnostics.degraded on the answer response (the field already exists on search per 05-API §11), so the status row can say the vector store is unavailable rather than quietly answering from lexical hits alone (docs/09 §10).