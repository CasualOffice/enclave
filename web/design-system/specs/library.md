# library — implementation spec

> Extracted from `enclave-client-prototype.html` by the spec workflow.
> The prototype stays the reference; this is a reading of it, not a replacement.

## Structure

SURFACE: Library list — route `/w/:workspaceId/l/:libraryId[/f/:folderId]?view=&filter=&sort=&group=&peek=`
Owner module: `features/libraries/` (`list/`, `peek/`, `selection-bar/`). Prototype source: `web/design-system/enclave-client-prototype.html` lines 218–357 + state factory lines 619–760.

=== 0. SHELL CONTEXT (not owned here, but the geometry this screen sits in) ===
Shell root: `display:grid; grid-template-columns:232px 1fr; block-size:100%`. Sidebar is `<aside>`.
Content sheet (`app/shell/ContentSheet`): `margin-block:8px; margin-inline:0 8px; background:var(--sheet); border-radius:var(--r-sheet)/*14px*/; box-shadow:var(--el1); display:flex; flex-direction:column; min-inline-size:0; overflow:hidden; position:relative`.
`position:relative` on the sheet is load-bearing: it is the containing block for the floating selection bar. Do not remove it.

Library root: `<main>` `display:flex; flex-direction:column; flex:1; min-block-size:0`.
Five children, in order: LocationBar, ViewBar, FilterChipRow, BodyGrid, SelectionBar(absolute).

=== 1. LocationBar — `features/libraries/list/LocationBar.tsx` ===
Box: `display:flex; align-items:center; gap:6px; padding-block:10px 0; padding-inline:16px 14px; min-block-size:38px; color:var(--fg3); font-size:12.5px`.

1.1 Breadcrumb `<nav><ol>`: each crumb 12.5px `var(--fg3)`; separator is a CSS `::after` on every `li` except the last — `content:"/"; color:var(--fg4); margin-inline:2px`. Last crumb: `<span aria-current="page">` `color:var(--fg); font-weight:500`. Middle crumbs collapse to a `…` menu button when the row overflows (measure with ResizeObserver; keep first + last always).

1.2 Folder classification chip (`entities/classification/ClassificationChip`, size `sm`):
`display:inline-flex; align-items:center; gap:6px; block-size:20px; padding-inline:7px 8px; border-radius:999px; font-size:11px; font-weight:500; margin-inline-start:6px`
`background: color-mix(in srgb, var(--c-{level}) 11%, transparent)`
`color: color-mix(in srgb, var(--c-{level}) 82%, var(--fg))`
Dot: `inline-size:6px; block-size:6px; border-radius:50%; background:var(--c-{level}); flex:none`.
Level→token: `public→--c-pub`, `internal→--c-int`, `confidential→--c-conf`, `highly_confidential→--c-hconf`, `restricted→--c-restr`. Label text comes from `t('classification.'+level)`, never from the token name. Colour is reinforcement only — the text label is always present (docs/09 §15).

1.3 Trailing cluster: `margin-inline-start:auto; display:flex; align-items:center; gap:4px`.
- Presence avatar stack (`shared/ui/AvatarStack`, max 3 + `+N`): each `inline-size:20px; block-size:20px; border-radius:50%; font-size:9.5px; font-weight:600; box-shadow:0 0 0 2px var(--sheet)`; 2nd and later `margin-inline-start:-6px`. Palettes `--av-a-bg/-fg` … `--av-d-bg/-fg`, chosen by a stable hash of user id (not by index — index reshuffles on reorder). Initials come from `Intl` -agnostic first-grapheme extraction via `Intl.Segmenter('grapheme')`, not `str[0]`.
- `Share` text button: `block-size:24px; padding-inline:8px; border-radius:var(--r-ctrl); border:0; font-size:12px; font-weight:500; background:transparent; color:var(--fg2)`. Hover `background:var(--hover); color:var(--fg)`.
- `Toggle details` icon button: `26×26`, `border-radius:var(--r-ctrl)`, icon `14×14`, `color:var(--fg3)`; hover `background:var(--hover); color:var(--fg)`. `aria-pressed={peekOpen}`.
- `More` icon button: same 26×26 box, opens the folder overflow menu.

=== 2. ViewBar — `features/libraries/list/ViewBar.tsx` ===
Box: `display:flex; align-items:center; gap:6px; padding-block:8px; padding-inline:14px 12px`.

2.1 Saved-view pills, `role="tablist"`, container `display:inline-flex; gap:2px`.
Each: `<button role="tab">` `padding-block:4px; padding-inline:9px; border-radius:999px; border:0; font-size:12.5px; font-weight:500; display:inline-flex; align-items:center; gap:6px`.
Selected: `background:var(--sunken); color:var(--fg)`. Unselected: `background:transparent; color:var(--fg3)`; hover `background:var(--sunken); color:var(--fg)`.
Count badge: `font-size:10.5px; color:var(--fg4); font-family:var(--mono)` — value from `Intl.NumberFormat(locale).format(n)`.
Views come from the server (`savedViews[]`), not a hardcoded array. Selecting one writes `?view=<id>` — it is URL state, not store state.

2.2 Trailing cluster: `margin-inline-start:auto; display:flex; align-items:center; gap:4px`.
- `Filter`, `Display`, `Upload`: `display:inline-flex; align-items:center; gap:6px; block-size:26px; padding-inline:10px; border-radius:var(--r-ctrl); border:0; font-size:12px; font-weight:500; background:transparent; color:var(--fg2)`; icon `14×14`; hover `background:var(--hover); color:var(--fg)`. Each is `aria-haspopup="dialog"` / `"menu"` and `aria-expanded`.
- `New` primary: `block-size:24px; padding-inline:8px; border-radius:var(--r-ctrl); background:var(--accent); color:#fff; font-size:12px; font-weight:500; gap:6px`; icon `12×12`; hover `filter:brightness(1.08)`.
Both `Upload` and `New` render from `folderCapabilities.upload` / `.createFolder`. If false → the DENIED treatment (§6 of the states field), never hidden.

=== 3. FilterChipRow — `features/libraries/list/FilterChips.tsx` ===
Box: `display:flex; align-items:center; gap:6px; padding-inline:16px; padding-block-end:8px; flex-wrap:wrap`. Rendered only when `filter` in the URL is non-empty.

Chip (three-segment): outer `display:inline-flex; align-items:center; block-size:24px; border-radius:var(--r-ctrl); box-shadow:var(--hairline); font-size:12px; overflow:hidden; position:relative`.
- key segment: `padding-inline:7px; color:var(--fg3)`
- value segment: `padding-inline:7px; color:var(--fg); font-weight:500`
- remove `<button>`: `padding-inline:6px; color:var(--fg4)`, label `t('library.filters.remove', {facet})`, glyph `×` rendered as an icon (`#x`, 10×10), not the literal character.
1px dividers sit at the inline-end edge of the key and value segments (see techniqueFixes #2 — pseudo-element, not an inset box-shadow).
Trailing summary: `font-size:12px; color:var(--fg4); margin-inline-start:4px`; the group/sort values inside it `color:var(--fg2); font-weight:500`. Built from one ICU message `library.viewSummary` with `{groupBy}` and `{sortBy}` placeholders and `<b>` tags handled by the i18n rich-text renderer — never string concatenation, and the `↓` glyph is an icon, not a character in the catalog.

=== 4. BodyGrid ===
`display:grid; flex:1; min-block-size:0`
`grid-template-columns:` `minmax(0,1fr)` when peek closed; `minmax(0,1fr) minmax(320px,var(--peek-w,372px))` when open.
`--peek-w` is set from the persisted peek width (Zustand `ui.peekWidth`, clamped 320–520).

=== 4A. List column — `features/libraries/list/FileList.tsx` ===
Scroller: `overflow:auto; position:relative`. Inner track: `min-inline-size:680px` (below that the scroller scrolls horizontally; the page body never does).

Column template, shared verbatim by the header row and every data row:
`grid-template-columns: 32px minmax(0,1fr) 128px 116px 108px 64px 32px; gap:8px`
(checkbox · name · modified · classification · status · size · row-actions)

4A.1 Header row `role="row"`: `block-size:30px; padding-inline:10px 6px; font-size:11px; color:var(--fg4); font-weight:500; position:sticky; inset-block-start:0; background:var(--sheet); z-index:2; align-items:center`. Cells: empty, `Name`, `Modified`, `Classification`, `Status`, `Size` (`text-align:end`), empty. Sortable headers are `<button>` with `aria-sort="ascending|descending|none"`; clicking writes `?sort=`.

4A.2 Group header `role="row"` + `<button>` inside spanning the row: `block-size:28px; display:flex; align-items:center; gap:8px; padding-inline:16px; font-size:11.5px; color:var(--fg3); font-weight:500; background:var(--sheet)`; hover `color:var(--fg)`. Chevron `10×10`, `color:var(--fg4)`, `transform:rotate(var(--chev-rot))` where `--chev-rot:0deg` expanded / `var(--chev-collapsed)` collapsed (see techniqueFixes #5). Count `font-family:var(--mono); font-size:10.5px; color:var(--fg4)`, `Intl.NumberFormat`-formatted. `aria-expanded`.
Groups collapse to local UI state (Zustand `ui.collapsedGroups`), not the URL — but docs/09 §3 requires expansion to survive back/forward, so the store is keyed by `${libraryId}:${folderId}` and restored on route re-entry.

4A.3 Data row `role="row"`, `<div>` (not a button — it holds interactive children):
`display:grid; align-items:center; block-size:36px; padding-inline:10px 6px; gap:8px; position:relative; font-size:13px; cursor:default`
`background:` `var(--selected)` when in the selection set, else `transparent`; hover `var(--hover)`.
Enter animation: `animation: encIn .22s cubic-bezier(.2,.7,.3,1) both; animation-delay: calc(min(var(--row-i),12) * 20ms)`. `@keyframes encIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}`. Under `prefers-reduced-motion:reduce` only the opacity half survives (docs/09 §12).
Selected marker: `position:absolute; inset-inline-start:0; inset-block:6px; inline-size:2px; border-radius:2px; background:var(--accent)`.

Cells:
(a) Checkbox cell (32px), `display:flex; justify-content:center`. Control is a real `<input type="checkbox">` visually replaced (`appearance:none`), `inline-size:14px; block-size:14px; border-radius:4px; flex:none`.
  unchecked → `background:var(--sheet); box-shadow: inset 0 0 0 1.5px var(--line-strong); opacity:.35`; row hover / `:focus-visible` / any selection active → `opacity:1`.
  checked → `background:var(--accent); opacity:1;` tick via `background-image:url("data:image/svg+xml;utf8,<svg …stroke='white' stroke-width='3.2'><path d='m5 12 5 5L20 7'/></svg>"); background-size:10px; background-position:center; background-repeat:no-repeat`.
  Disabled while the row is Busy (uploading/scanning).
(b) Name cell: `display:flex; align-items:center; gap:9px; min-inline-size:0; overflow:hidden; font-weight:450; color:var(--fg)`. Type icon `16×16; flex:none`, colour by MIME family: pdf `#D0453A`, word `#3B6FD4`, presentation `#D2591C`, spreadsheet `#2E8B57`, plain/markdown `var(--fg3)`. Title span `min-inline-size:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap`; extension in a trailing span `color:var(--fg4); font-weight:400; font-size:12px`. Title + ext are one server-supplied filename split at the last dot — a display concern, not translated.
(c) Modified cell (128px): `color:var(--fg3); font-size:12.5px; display:flex; align-items:center; gap:6px; white-space:nowrap; overflow:hidden`. Optional 20×20 actor avatar (`flex:none`, `font-size:9.5px; font-weight:600`), then the relative timestamp (`<time dateTime={iso}>`, `title` = absolute formatted date).
(d) Classification cell (116px): `ClassificationChip` size `sm` — identical box to §1.2. Unclassified variant: no dot, `background:transparent; color:var(--fg2); box-shadow:var(--hairline)`.
(e) Status cell (108px), exactly one of:
   • Progress steps (row is Busy): `display:inline-flex; align-items:center; gap:6px; font-size:11px; color:var(--fg3)`. Each step `display:inline-flex; align-items:center; gap:4px`; dot `6×6; border-radius:50%`.
     done → dot `var(--ok)`, text `var(--fg2)`, weight 400
     current → dot `var(--accent)`, `box-shadow:0 0 0 3px var(--accent-soft)`, text `var(--fg)`, weight 500
     pending → dot `var(--g300)`, text `var(--fg4)`, weight 400
     The prototype shows 3 abbreviations (`Up`/`Scan`/`Index`). The real pipeline is the six of docs/09 §8 — `Queued → Uploading → Scanning → Processing → Indexing → Ready` — collapsed for the 108px cell into three visible buckets (upload / security / index) with the exact server stage in the `aria-label` and the tooltip. Never render `Ready` before `Scanning` completes (CLAUDE.md rule 9).
   • StatusPill: `display:inline-flex; align-items:center; gap:5px; block-size:20px; padding-inline:8px; border-radius:999px; font-size:11px; font-weight:500; white-space:nowrap`, optional `11×11` icon. Four variants:
     `warn` → `background:color-mix(in srgb,var(--warn) 14%,transparent); color:var(--warn)`
     `danger` → `background:color-mix(in srgb,var(--danger) 12%,transparent); color:var(--danger)`
     `ok` → `background:color-mix(in srgb,var(--ok) 12%,transparent); color:var(--ok)`
     `plain` → `background:var(--sunken); color:var(--fg2)`
     Variant and label both come from the server row (`row.status.{tone,code}` → `t('fileStatus.'+code)`); the client never picks a tone from a permission it inferred.
(f) Size cell (64px): `color:var(--fg3); font-size:12.5px; text-align:end; white-space:nowrap`.
(g) Row-actions cell (32px): 26×26 icon button, `opacity:0`; `opacity:1` on row `:hover`, row `:focus-within`, and always when a screen reader / keyboard user focuses it (never `display:none` — a hidden button is not reachable by keyboard).

Busy rows: cells (b)(c)(d)(f) get `opacity:.5`; the row is `aria-busy="true"`, not selectable, and does not open on click/Enter.

4A.4 Trailing collapsed-group affordance (the prototype's `Archive 96`): `block-size:28px; display:flex; align-items:center; gap:8px; padding-inline:16px; font-size:11.5px; color:var(--fg4); font-weight:400`, chevron `10×10`. Same `<button role="row">` contract as 4A.2.

4A.5 Virtualization: TanStack Virtual, fixed `36px` row estimate, `overscan:8`. Group headers participate as 28px items in a single flat index (a nested virtualizer per group breaks the keyboard walk). `role="grid"` on the track with `aria-rowcount` = total server count, and `aria-rowindex` on every rendered row (1-based, absolute), so a screen reader reports position in the whole list and not the window.

=== 4B. Peek panel — `features/libraries/peek/PeekPanel.tsx` ===
`<aside aria-label={t('library.peek.label')}>`: `display:flex; flex-direction:column; min-inline-size:0; overflow:hidden; background:var(--sheet); animation: encPeek .18s ease-out both` (`from{opacity:0;transform:translateX(14px)}` — mirror the translate under RTL, techniqueFixes #6). 1px inline-start rule (techniqueFixes #3).
Resize handle: 5px wide hit area on the inline-start edge, `cursor:col-resize`, keyboard-operable (`role="separator" aria-orientation="vertical" aria-valuenow/min=320/max=520`, ← → move by 16px, Home/End snap).

4B.1 Header strip: `display:flex; align-items:center; gap:4px; padding-block-start:8px; padding-inline:12px 8px; color:var(--fg3)`.
  Kbd chip (`shared/ui/Kbd`): `font-family:var(--mono); font-size:10px; padding-block:1px; padding-inline:4px; border-radius:4px; background:var(--sunken); color:var(--fg3); box-shadow:inset 0 -1px 0 var(--line-strong)` + `font-size:11.5px` caption.
  Trailing `display:flex` of four 26×26 icon buttons: previous, next, open-full, close. Prev/next chevrons must point per writing direction (techniqueFixes #5).
4B.2 Title block: `padding-inline:16px; padding-block-start:8px`. `<h3>` `font-size:14px; line-height:1.35; font-weight:500; letter-spacing:-.012em; margin:0`. Meta line `color:var(--fg3); font-size:12px; margin-block-start:2px` — an ICU message with `{version} {size} {owner} {modified}` placeholders and a `·` separator supplied by the catalog, so a locale can reorder it.
4B.3 Pill row: `display:flex; flex-wrap:wrap; gap:5px; padding-block:10px 8px; padding-inline:16px` — classification chip first, then status/obligation pills (same StatusPill box as 4A(e)).
4B.4 Tab strip `role="tablist"`: `display:inline-flex; gap:2px; padding-inline:12px; padding-block-end:6px`, block-end hairline `box-shadow: inset 0 -1px 0 var(--line)` (block-axis, direction-neutral — permitted). Exactly five tabs (docs/09 §7): Preview, Details, Access, Versions, Activity. Pills use the same styling as §2.1.
4B.5 Tab panel: `padding-block:12px; padding-inline:16px; overflow:auto; flex:1; display:flex; flex-direction:column; gap:14px`.
  • Preview thumb: `flex:none; block-size:170px; border-radius:var(--r-surf); background:var(--sunken); position:relative; overflow:hidden; display:flex; align-items:center; justify-content:center`. Placeholder page `inline-size:56%; block-size:82%; background:var(--sheet); box-shadow:var(--el2); padding-block:12px; padding-inline:10px; gap:5px; border-radius:2px`; skeleton bars `block-size:4px` (title, 50% width, `var(--g300)`) and `block-size:2px` (`var(--g200)`, widths 100/100/100/70/100/100/100/40%).
  • Watermark overlay (when the server marks the preview watermarked): `position:absolute; inset:0; pointer-events:none; font-family:var(--mono); font-size:9px; color:rgba(194,39,58,.28); transform:rotate(-22deg); line-height:2.8; text-align:center; white-space:nowrap`. Content is server-rendered text (identity + timestamp + label + hash); the client interpolates nothing.
  • `Open preview` button: `position:absolute; inset-inline-end:8px; inset-block-end:8px; block-size:24px; padding-inline:8px; border-radius:var(--r-ctrl); background:var(--sheet); color:var(--fg); box-shadow:var(--hairline); font-size:12px; font-weight:500`; hover `background:var(--sunken)`. Renders from `capabilities.preview`. Never links to an object-storage URL (CLAUDE.md rule 6).
  • Policy notice: `display:flex; gap:10px; padding-block:10px; padding-inline:12px; border-radius:var(--r-ctrl); font-size:12.5px; line-height:1.45; background:color-mix(in srgb,var(--warn) 9%,transparent)`; icon `15×15; flex:none; margin-block-start:1px; color:var(--warn)`. Body = the server's `message`; the link = the server's `remediation`. Never a retry.
  • `<dl>` facts grid: `display:grid; grid-template-columns:100px 1fr; gap:7px 10px; font-size:12.5px; align-items:center; margin:0`. `dt` `color:var(--fg3)`; `dd` `margin:0; min-inline-size:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap`. DLP status and retention are rows here, not tabs (docs/09 §7).
  • Activity list: `<h4>` `font-size:11px; font-weight:500; color:var(--fg3); text-transform:uppercase; letter-spacing:.06em; margin-block-end:2px`. Each entry `display:flex; align-items:center; gap:8px`, avatar 20×20, timestamp `margin-inline-start:auto; color:var(--fg4); font-size:11px; font-family:var(--mono)`. Policy-denial entries use a `!` avatar `background:color-mix(in srgb,var(--danger) 14%,transparent); color:var(--danger)`; agent entries use `background:var(--accent-soft); color:var(--accent)` with an 11×11 bot icon. NOTE: this tab is blocked on `docs/17 §12 Q24` — `audit_events` is hash-chained and is not a user feed. Ship the tab shell with the "unbuilt" treatment until a read model exists; do not render it from the audit log.
  • `text-transform:uppercase` is applied only under a `:lang()` allowlist — it is wrong for several locales (docs/14).
4B.6 Ask composer footer: `margin-block-start:auto; padding-block:10px 12px; padding-inline:12px`, block-start hairline `inset 0 1px 0 var(--line)`. Card: `display:flex; flex-direction:column; gap:6px; border-radius:var(--r-surf); box-shadow:var(--hairline); padding-block:8px 6px; padding-inline:10px 8px; background:var(--sheet)`. Input `border:0; background:transparent; font-size:12.5px; color:var(--fg); outline:0; inline-size:100%`. Scope chip `This file` uses the `plain` pill box with `background:transparent; box-shadow:var(--hairline); color:var(--fg2)`. Send button `24×24; border-radius:7px; background:var(--accent); color:#fff`. Ask is M7 — the whole footer renders in the UNBUILT treatment until then, never the denied one.

=== 5. SelectionBar — `features/libraries/selection-bar/SelectionBar.tsx` ===
`<div role="toolbar" aria-label={t('library.selection.toolbar')}>`:
`position:absolute; inset-block-end:22px; inline-size:max-content; max-inline-size:calc(100% - 24px); inset-inline:0; margin-inline:auto;` (centring without `transform`, techniqueFixes #4)
`display:flex; align-items:center; gap:2px; padding-block:6px; padding-inline:12px 6px; background:var(--selbar-bg); color:var(--selbar-fg); border-radius:12px; box-shadow:var(--el3); font-size:12.5px; z-index:5; white-space:nowrap; overflow-x:auto; animation: encPop .16s ease-out both`.
Count label: `font-weight:500; margin-inline-end:8px; display:flex; align-items:center; gap:8px`, followed by a divider `inline-size:1px; block-size:16px; background:var(--selbar-i)`.
Action buttons: `padding-inline:9px; block-size:26px; border-radius:7px; display:inline-flex; align-items:center; gap:6px; background:transparent; color:inherit; font-size:12.5px; opacity:.9`; hover `background:var(--selbar-hov)`; icon `14×14`. Trailing shortcut chip: `font-family:var(--mono); font-size:10px; padding-block:1px; padding-inline:4px; border-radius:4px; background:var(--selbar-kbd)`.
Order: Share (S) · Download (D) · Move (M) · Label (L) · Retention · More · Clear.
Clear button: `opacity:.6; margin-inline-start:4px`; hover `opacity:1; background:var(--selbar-hov)`.
Every action's enabled/denied state is `intersectionOfCapabilities(selection)` computed **from the server's per-row `capabilities`** — an AND over booleans the server sent, which is not re-deriving a permission. If any row's capability is false, the action is DENIED with that row's server reason.


## Interactions

All labels, tooltips, aria-labels and shortcut hints come from the catalog (`features/libraries/*` namespace). No literal below is a string to paste into JSX.

=== POINTER ===
| Element | Action |
|---|---|
| Row body (single click) | Opens peek → sets `?peek=<fileId>`. Does NOT navigate, does not change selection. Busy rows ignore the click. |
| Row body (double click) | Opens the file (route change / editor). |
| Row checkbox | Toggles that row in the selection set. `stopPropagation` so the row's open handler does not fire. |
| Row checkbox + Shift | Range-selects from the last-toggled anchor to this row, over the *visible flattened order* (collapsed groups excluded). |
| Row-actions `⋯` | Opens the per-row menu, anchored to the button; focus returns to the button on close. |
| Group header | Toggles collapse. Collapsing a group deselects nothing but removes its rows from range-select ordering. |
| Column header | Cycles sort asc → desc → none; writes `?sort=`. |
| Saved-view pill | Writes `?view=`; resets scroll to top, preserves selection only if the selected ids survive the new view. |
| Filter / Display | Open popovers (`role="dialog"`, focus trapped, Esc closes, focus returns). Applying writes `?filter=` / `?group=`. |
| Filter chip `×` | Removes that facet from `?filter=`; if it was the last one the chip row unmounts. |
| Upload / New | Opens the file picker / creation menu. Drag-and-drop onto the list column is equivalent; the drop target is the scroller, with a 2px `var(--accent)` inset ring and a `var(--accent-soft)` wash while a drag is over it. |
| Toggle details (LocationBar) | Opens peek on the first visible row if none is peeked; closes it otherwise. |
| Peek prev / next | Moves `?peek=` to the previous/next row in visible order, skipping busy rows; disabled (BUSY-neutral, not denied) at the ends. |
| Peek open-full | Navigates to the file route. |
| Peek close / Esc | Clears `?peek=`; focus returns to the row that opened it. |
| Peek resize handle | Drag or ←/→ to resize 320–520; persists to `ui.peekWidth`. |
| Selection bar buttons | Act on the whole selection; each shows its shortcut chip. |
| Clear selection | Empties the set; the bar exits with `encPop` reversed. |

=== KEYBOARD (docs/09 §6 is authoritative and overrides the prototype) ===
The list is a roving-tabindex composite: exactly one row is `tabindex="0"` (the focused row), everything else `-1`. Tab enters and leaves the list as one stop; arrows move inside it.

| Key | Behaviour on this surface |
|---|---|
| `↑` `↓` | Move focus one row in visible order, crossing group boundaries and skipping collapsed groups. Moves the selection when nothing is multi-selected. |
| `Shift+↑/↓` | Extend the selection from the anchor. |
| `⌘/Ctrl+↑/↓` | Move focus without changing selection. |
| `⌘/Ctrl+Space` or `⌘/Ctrl+click` | Toggle the focused row in the selection. |
| `→` | On a collapsed group header: expand. On an expanded header: move into the first row. On a row: move to the next cell (grid cell navigation for the actions button). Under RTL, `←` performs this and `→` performs the collapse (map through `dir`, do not hardcode). |
| `←` | Inverse of `→`: collapse an expanded group, or jump from a row to its group header. |
| `Enter` | Open the focused file. |
| `Space` | Toggle peek for the focused row. If peek is already open on that row, closes it. Prevent the default scroll. |
| `J` / `K` | Move the peeked row down / up *without closing the peek* — the panel content swaps in place, list scroll follows focus. |
| `⌘/Ctrl+A` | Select every row in the current view (expanded groups only); announce the count via a polite live region. |
| `R` `M` `C` `S` | Rename · Move · Copy · Share the selection. Each is a no-op with a polite announcement when the corresponding capability is false — it must not silently do nothing. |
| `L` then `R` | Two-key chord: apply a classification label to the selection (opens the label picker with Restricted preselected). |
| `Del` | Move selection to trash, with an undo toast. (Not `⌫` — the prototype's binding loses.) |
| `I` | Toggle the peek panel. `⌘/Ctrl+\` pins it open (pinned peek survives `Esc` and row navigation). |
| `⌘/Ctrl+K` | Command palette (shell-owned; the library contributes selection-scoped commands). |
| `/` | Focus the search field (shell-owned). |
| `⌘/Ctrl+J` | Ask — registered and rendered in the UNBUILT treatment until M7. |
| `?` | Shortcut reference dialog. |
| `Esc` | Precedence, first match wins: close an open popover/menu → close the (unpinned) peek → clear the selection. |

Rules that hold everywhere: focus is always visible (`:focus-visible{outline:2px solid var(--accent-ring); outline-offset:1px; border-radius:6px}`), focus order follows visual order, and focus returns to the trigger when any overlay closes. Keys never fire while focus is inside a text input.

=== ARIA ===
- List track `role="grid" aria-multiselectable="true" aria-rowcount={serverTotal}`; groups `role="rowgroup"`; group headers `role="row"` with a single `role="columnheader"`-less `gridcell` carrying `aria-expanded`; rows `role="row" aria-selected aria-rowindex`; cells `role="gridcell"`.
- Selection changes announce through one polite live region owned by the list (`t('library.selection.announce', {count})` via ICU plural).
- The selection bar is `role="toolbar"` with its own left/right arrow roving tabindex, independent of the list's.
- The peek panel is *not* a dialog: it does not trap focus and the list stays interactive. It is `<aside aria-label>` with `aria-live="polite"` on its title so a J/K walk is announced.
- Busy rows: `aria-busy="true"` plus a per-row `aria-describedby` pointing at the stage text.

=== DATA / MUTATION BEHAVIOUR ===
- The list query key includes workspace, library, folder, view, filter, sort, group and cursor. `staleTime:0` because every row carries `capabilities` (docs/17 §4.1).
- Prefetch the next cursor page when the scroller is within 400px of the end; prefetch a row's peek payload on hover after 120ms and on keyboard focus after 250ms.
- Any mutation that can change access (share, label, move, retention, delete) invalidates the list query *and* any open peek query. No optimistic update touches access-bearing fields (docs/17 §12 Q25); rename may render optimistically.
- Every mutation carries an idempotency key, issued by `shared/api` — the feature never generates one.
- A `403 STEP_UP_REQUIRED` never reaches this surface: `shared/api` raises the challenge and replays.


## States

Five renderable outcomes for the list, plus the peek panel's own four, plus the three non-actionable control treatments. All are part of the feature, reviewed with it (docs/09 §11).

=== A. LIST: LOADING ===
Skeleton rows share the loaded row's box model exactly: same 36px height, same seven-column template, same 10px/6px inline padding, same 8px gap — so nothing shifts when data lands (CLS 0).
Render the real sticky header (it needs no data), then 12 skeleton rows plus 2 skeleton group headers at 28px.
Skeleton fill: `background:var(--sunken); border-radius:4px`, heights — name 12px @ 62% width, modified 12px @ 70%, classification a 20px×88px pill radius 999px, status 20px×72px pill, size 12px @ 100% with `margin-inline-start:auto`. Checkbox cell renders a 14px `var(--sunken)` square.
Shimmer: a single `opacity` pulse 1.4s ease-in-out infinite; removed entirely under `prefers-reduced-motion`. No translate-based sweep.
`aria-busy="true"` on the grid; one polite announcement of `library.list.loading` after 500ms only (an instant announcement fights fast responses).
No full-screen spinner on navigation. The LocationBar and ViewBar render immediately from route params and cached folder metadata.

=== B. LIST: EMPTY (new — the folder has no items and no filters are applied) ===
Centred block in the list column, `max-inline-size:360px; margin-block:64px auto; text-align:center`.
Icon 32×32 `color:var(--fg4)`. Title `font-size:14px; font-weight:500; color:var(--fg)`. Body `font-size:12.5px; color:var(--fg3); line-height:1.45; margin-block-start:4px`. One primary action at `margin-block-start:16px`, using the `New` button box (24px, `var(--accent)`, `#fff`).
Copy answers "what is this surface for" and offers the single action that starts it: upload. If `folderCapabilities.upload` is false, the action renders DENIED with the server reason instead of being hidden.
The ViewBar and FilterChipRow still render. The selection bar does not exist.

=== C. LIST: EMPTY (filtered — filters or a saved view exclude everything) ===
Same block geometry as B, different content and a *different* primary action: `Clear filters`, styled as the secondary button (`background:var(--sheet); color:var(--fg); box-shadow:var(--hairline)`), which strips `?filter=` and resets `?view=` to `all`.
Body names the active facets by count via ICU plural (`library.empty.filtered.body`), never by concatenating chip labels.
This must not be confused with B: B says the folder is empty, C says your filters are. Distinct copy keys, distinct icons, and a test asserts both render.

=== D. LIST: ERROR (5xx, network, or Zod parse failure) ===
Same block geometry. Icon in `var(--danger)`.
Four required parts (docs/09 §11): what failed (`library.error.title`), whether it is retryable (from the API client's classification, not guessed), a `Retry` button (secondary box), and a **copyable request ID** — `font-family:var(--mono); font-size:11px; color:var(--fg3); background:var(--sunken); padding-block:2px; padding-inline:6px; border-radius:4px` with a copy icon button beside it and a polite "copied" announcement.
A Zod parse failure lands here, never in a `catch(()=>({}))` — an empty capabilities object would render as "policy denied everything", which is a lie told confidently (docs/17 §3).
A partial failure (page 3 of an infinite scroll) renders this block inline at the end of the loaded rows, not in place of them.

=== E. LIST: DENIAL — deliberately *not* an error state
Two distinct outcomes and they must not be merged:
- **404 (cross-tenant, or a barrier)** — CLAUDE.md rule 7 means the server will not confirm existence. Render the not-found surface: "this library does not exist or you do not have access", no retry, no request-for-access action (offering one would confirm existence).
- **403 with a stable code (ACL / DLP / conditional access)** — a successful request with a refusing answer. Render inline in the list column using the server's `code`, user-safe `message` and single `remediation` (docs/06 §24). **Never a retry button.** Never the rule that matched. Never a client-composed sentence.
Visual: `display:flex; gap:10px; padding-block:10px; padding-inline:12px; border-radius:var(--r-ctrl); font-size:12.5px; line-height:1.45; background:color-mix(in srgb,var(--danger) 10%,transparent)`, icon `15×15; color:var(--danger); flex:none; margin-block-start:1px`.

=== F. PEEK PANEL: its own four states ===
- Loading: the panel frame, title skeleton (14px bar @ 70%), meta skeleton, two pill skeletons, the tab strip live, and a 170px `var(--sunken)` preview block — the exact boxes the loaded panel uses.
- Empty (no row peeked, panel pinned open): centred hint at `color:var(--fg3); font-size:12.5px` — "select a file to see its details".
- Error: the same four-part error block as D, scoped to the panel; the list behind it stays usable.
- Denied preview: the panel loads (title, classification, facts) and only the preview region carries the policy notice from §4B.5 — a denial on one capability never blanks the whole panel.

=== G. ROW-LEVEL BUSY (the upload/scan pipeline) ===
Not a page state — a per-row one. `aria-busy="true"`, content cells at `opacity:.5`, the status cell showing truthful progress (§4A(e)), checkbox disabled, row not openable. The row leaves Busy only when the server reports `Ready`; nothing renders as available while `SCANNING` (CLAUDE.md rule 9). Terminal failures (`Quarantined`, `Failed`, `Aborted`, `QuotaExceeded`) replace the steps with a `danger` StatusPill and leave the row selectable so it can be removed.

=== H. THE THREE NON-ACTIONABLE TREATMENTS (docs/17 §6, ENC-673) ===
They share no CSS class, and a test asserts it (F2).
| | DENIED `.control--denied` | UNBUILT `.control--unbuilt` | BUSY `.control--busy` |
|---|---|---|---|
| Cause | `capabilities.x === false` | milestone not reached (Ask/⌘J, Activity tab) | request in flight |
| Focusable | yes, `tabindex="0"` | **no**, `tabindex="-1"` | yes |
| Attrs | `aria-disabled="true"` + `aria-describedby`→reason node | `aria-disabled="true"` + `aria-describedby`→release note | `aria-busy="true"`, label unchanged |
| Visual | full opacity, `color:var(--fg3)`, an 11×11 `#block` icon at the inline-end; the reason surface uses `color-mix(in srgb,var(--danger) 12%,transparent)` / `var(--danger)` | `opacity:.4`, plus a neutral `Later` chip in the `plain` pill (`var(--sunken)` / `var(--fg2)`) — **never any danger tint** | 14×14 spinner replacing the leading icon, in place, same box |
| Text | the server's message + one remedy | a future-tense note about the product, no remedy | none |
| Retry | never | n/a | n/a |
The prototype's Download button (`opacity:.4; cursor:not-allowed; title="Downloading is restricted outside the corporate network"`) is wrong twice: it uses the unbuilt visual for a denial, and the sentence is invented client-side. Correct: DENIED treatment, focusable, reason from `capabilities.reasons.download`. Until ENC-674 ships that field, render DENIED with the icon and *no* explanatory sentence — docs/09 §5 is explicit that an invented explanation is worse than none.


## Tokens

- `--canvas / --sheet / --sunken — page ground, the content sheet, recessed wells (list header sticky background is --sheet, skeleton fills and kbd chips are --sunken)`
- `--hover rgba(20,20,18,.045) — row and button hover wash`
- `--selected rgba(20,20,18,.06) — selected row background`
- `--line rgba(20,20,18,.07) / --line-strong rgba(20,20,18,.13) — hairlines and the unchecked checkbox ring`
- `--hairline (= 0 0 0 1px var(--line)) — the standard 1px outline shadow on filter chips, the ask composer card and unclassified pills`
- `--fg (=--ink #141412) / --fg2 (--g600 #5B5B56) / --fg3 (--g500 #7A7A74) / --fg4 (--g400 #A6A6A0) — the four-step text ramp: row title / secondary button label / meta text / counts and separators`
- `--g200 #DEDEDA, --g300 #C8C8C3 — preview placeholder bars and the pending progress dot`
- `--el1 / --el2 / --el3 — content sheet, peek preview page, floating selection bar`
- `--r-ctrl 6px (buttons, chips, notices) / --r-surf 10px (cards, preview well) / --r-sheet 14px (the content sheet) — all three are tenant-editable`
- `--accent #4F46E5 / --accent-soft rgba(79,70,229,.10) / --accent-ring rgba(79,70,229,.35) — primary buttons, the selected-row 2px marker, the checked checkbox, the current progress dot's ring, and the focus outline. Tenant-editable; must pass AA against its own background (docs/09 §17)`
- `--c-pub #8A97A6 / --c-int #2F6FDB / --c-conf #B7791F / --c-hconf #D2591C / --c-restr #C2273A — classification. LOCKED, never tenant-overridable, and never the only carrier: the chip always shows text too`
- `--ok #1D8A55 / --warn #B7791F / --danger #C0392B / --info #2F6FDB — status pill tones and the policy notice tints`
- `--selbar-bg (=--ink) / --selbar-fg #fff / --selbar-hov rgba(255,255,255,.12) / --selbar-kbd rgba(255,255,255,.14) / --selbar-i rgba(255,255,255,.18) — the floating selection bar inverts against the sheet and has its own five tokens; all five flip in dark mode`
- `--av-a-bg/-fg … --av-d-bg/-fg — the four avatar palettes, assigned by a stable hash of user id`
- `--sans Inter / --tight Inter Tight / --mono JetBrains Mono — self-hosted variable fonts from web/public/fonts (ENC-135). --mono carries every count, timestamp, shortcut chip and request ID`
- `Root type: font-size 13px, line-height 1.45, letter-spacing -.006em, -webkit-font-smoothing:antialiased`
- `Dark mode is a [data-theme="dark"] block that redefines the same names (--sheet #161615, --sunken #1D1D1B, --accent #8B85FF, --g200 #2B2B28, and the inverted selbar set) — never a second set of names`
- `Motion: encIn .22s cubic-bezier(.2,.7,.3,1) with a min(i,12)×20ms row stagger, encPeek .18s ease-out, encPop .16s ease-out — all inside the 120–200ms band of docs/09 §12, all reduced to opacity-only under prefers-reduced-motion`

## Technique fixes — the prototype breaks a hard rule here

- `margin-left:auto` on the LocationBar/ViewBar trailing clusters, on the avatar overlap (`margin-left:-6px`), and on the peek Activity timestamps → `margin-inline-start`. Identical rendering in LTR; correct in RTL. Same for `padding:10px 14px 0 16px` → `padding-block:10px 0; padding-inline:16px 14px`, and `padding:5px 8px 5px 20px` → `padding-block:5px; padding-inline:20px 8px`.
- Filter-chip segment dividers `box-shadow: inset -1px 0 0 var(--line)` → a pseudo-element: `.chip-seg{position:relative} .chip-seg:not(:last-child)::after{content:""; position:absolute; inset-block:0; inset-inline-end:0; inline-size:1px; background:var(--line)}`. Do NOT use `border-inline-end` here — a border consumes layout width and would shift the 24px chip's text by 1px, while the inset shadow did not. The pseudo-element reproduces the original pixel-for-pixel and mirrors correctly.
- Peek panel edge `box-shadow:-1px 0 0 var(--line)` (an outer 1px rule on the panel's leading edge) → `aside::before{content:""; position:absolute; inset-block:0; inset-inline-start:0; inline-size:1px; background:var(--line)}` with `position:relative` on the aside. Again not `border-inline-start`, which would eat 1px from the 372px content box; the original shadow drew outside the box and cost nothing.
- Selection bar `left:50%; transform:translateX(-50%)` → `inset-inline:0; margin-inline:auto; inline-size:max-content`. The transform version is doubly wrong under RTL: `inset-inline-start:50%` measures from the opposite edge while `translateX(-50%)` still pulls toward physical left, so the bar lands off-centre. The margin-auto form centres in both directions and needs no transform — which also lets `@keyframes encPop` drop its `translateX(-50%)` and animate only `opacity` + `translateY(8px)` + `scale(.97)`, so the centring and the animation stop fighting.
- Direction-sensitive icon rotations — the collapsed group chevron `transform:rotate(-90deg)`, the peek `previous` button's `transform:rotate(180deg)`, and the sidebar back arrow's `rotate(90deg)` — are all mirrored under RTL. Drive them from a direction-aware custom property rather than hardcoding: `:root{--chev-collapsed:-90deg; --icon-flip:1} :root:dir(rtl){--chev-collapsed:90deg; --icon-flip:-1}`, then `transform:rotate(var(--chev-collapsed))` and `transform:scaleX(var(--icon-flip))` for the horizontal chevrons. Same rendering in LTR, correct arrow semantics in RTL. The `→`/`←` key handlers must map through `dir` for the same reason.
- `@keyframes encPeek{from{transform:translateX(14px)}}` slides the panel in from physical right. Under RTL the panel is on the left and would slide the wrong way. Fix: `from{transform:translateX(calc(14px * var(--icon-flip)))}` using the same direction variable. `encIn`'s `translateY(4px)` is block-axis and needs no change.
- Row size cell `text-align:right` and the `Size` column header `text-align:right` → `text-align:end`. Numbers right-align in LTR and left-align in RTL, which is what a reader of either expects.
- The peek `Open preview` button `right:8px; bottom:8px` → `inset-inline-end:8px; inset-block-end:8px`. The selected-row marker `left:0; top:6px; bottom:6px; width:2px` → `inset-inline-start:0; inset-block:6px; inline-size:2px`.
- `when: '2 h ago' | 'Yesterday' | 'Fri' | 'Aug 9'` are hand-written and are defects. Build one `useRelativeTime(iso)` hook: under 7 days use `Intl.RelativeTimeFormat(locale,{numeric:'auto'})` on the largest whole unit (which yields the locale's own 'yesterday' for free); at or beyond 7 days use `Intl.DateTimeFormat(locale,{month:'short',day:'numeric'})`, adding `year:'numeric'` across a year boundary. Render inside `<time dateTime={iso}>` with `title` = the full `Intl.DateTimeFormat` long form. The peek Activity column's `2h` / `Mon` go through the same hook with a narrow `style`.
- `size: '4.2 MB' | '210 KB'` → the server sends bytes; format with `Intl.NumberFormat(locale,{style:'unit', unit, unitDisplay:'short', maximumFractionDigits:1})`, picking `byte|kilobyte|megabyte|gigabyte|terabyte` by magnitude. The 1024-vs-1000 divisor is a product decision, but the *rendering* is Intl's.
- `{ k:'Value', v:'₹ 4.8 Cr' }` in the peek facts is the worst offender — a hardcoded symbol, a hardcoded Indian-numbering abbreviation, and a hardcoded space. → `Intl.NumberFormat(locale,{style:'currency', currency: value.currency, notation:'compact'})`, with the currency code coming from the server field, never assumed. In `en-IN` this produces the crore grouping natively; in `en-US` it correctly does not.
- Counts — the view-pill numbers, group counts, the trailing `96`, and the admin `1,284` — → `Intl.NumberFormat(locale).format(n)`. The comma in `1,284` is a locale decision.
- `${n} file${n>1?'s':''}` in the move/share toasts and `{{selCnt}} selected` in the selection bar are English pluralization in code. → ICU plural messages: `library.selection.count` = `{count, plural, one {# selected} other {# selected}}`, `library.toast.moved` = `{count, plural, one {Moved # file to {dest}} other {Moved # files to {dest}}}`. Languages with three-plus plural categories break the ternary outright.
- Concatenated meta strings — the peek `${ver} · ${size} · ${who} · ${when}` and the row `'Jul 12 · Comms'` — are assembled in JS. → single ICU messages with named placeholders, so a translator controls both the order and the separator.
- The `×` in the filter chip and the `↓` in `Modified ↓` are literal glyphs in markup. Replace with the sprite icons (`#x`, and a rotated `#chev`), so they inherit `currentColor`, size with the control, and never become a translatable string.
- `text-transform:uppercase` on the peek `ACTIVITY` heading is unsafe for several locales (Turkish dotted i, Greek accents, and locales with no case). Gate it behind a `:lang()` allowlist, or hold the uppercase form in the catalog for locales where it is right.
- The prototype's dead-end handler `nyi: () => toast('Not wired in this prototype yet')` sits behind Share, More, Filter, Display, Label, Retention and the row `⋯`. None of those may ship as a toast. Each is either wired, or rendered in the UNBUILT treatment (non-focusable, `Later` chip, neutral tint) — and never in the denied treatment, which must stay reserved for policy.
- The selection bar's Download carries `title="Downloading is restricted outside the corporate network"` — a client-authored policy explanation, which is exactly the second authority docs/17 §1 exists to prevent, and a `title` attribute is also unreachable by keyboard and unreliable for screen readers. Replace with the server's reason rendered in a real popover referenced by `aria-describedby`.
- The prototype renders the whole file list eagerly. Any list that can exceed 100 rows must be virtualized (CLAUDE.md; docs/09 §2 budgets 60fps at 100k rows and first paint under 400ms at 10k). Use TanStack Virtual over a single flat index that includes group headers; keep `aria-rowcount`/`aria-rowindex` absolute so the announced position reflects the full list, not the rendered window.
- The prototype styles everything with inline `style` attributes and paired `style-hover` / `style-focus` pseudo-attributes, which are a Claude Design runtime convention with no React equivalent. Port the values into CSS modules keyed to the token names; hover and focus become real `:hover` / `:focus-visible` rules. Copy the reference's values, never its property names (docs/17 §8) — `en-XB` mirrors direction in CI and fails the build on any physical property.

## Backend required

- GET /workspaces/{workspaceId}/libraries/{libraryId}/items — and .../folders/{folderId}/items. Cursor-paginated. Query: view, filter, sort, group, cursor, limit. Returns per row: id, name, extension, mimeFamily, size (bytes, integer — never a preformatted string), modifiedAt (RFC 3339), modifiedBy {id, displayName, initialsSource}, classification level, status {code, tone}, pipelineStage when busy, and capabilities. Must also return the total count for aria-rowcount and the group buckets with their own counts.
- capabilities on every listing row (ENC-152): {preview, download, print, export, edit, share, shareExternal, delete, sync} — nine booleans, one per distinct permission. Preview, download, print, export and sync must stay five fields; collapsing any two is CLAUDE.md rule 6.
- ENC-674 — a reason attached to every false capability: {code, message, remediation}, already localized and user-safe, carrying no indication of which rule matched (CLAUDE.md rule 10). This blocks the DENIED treatment shipping with any text at all; until it lands, denied controls render with no sentence.
- GET /files/{fileId} — the peek payload: title, version, size, owner, timestamps, classification, obligations (retention, legal hold, watermark flag), DLP category summary, indexing status, and the same capabilities object. Must be a separate endpoint so peek can prefetch on hover without refetching the list.
- GET /files/{fileId}/preview — a policy-mediated preview stream or token. Must never return an object-storage URL on the preview path (CLAUDE.md rule 6), and must carry the watermark text server-side rather than letting the client compose it.
- A user-facing activity read model — blocked on docs/17 §12 Q24. audit_events is hash-chained and deliberately not a feed; the peek Activity tab cannot be built on it. Needs its own projection with its own policy filter, or the tab ships unbuilt.
- GET /libraries/{libraryId}/views — saved views with id, label, count, and the filter/sort/group they encode. The four pills in the prototype (All / Expiring / Needs approval / Restricted) are data, not constants.
- GET /libraries/{libraryId}/facets — available filter facets and their value sets, for the Filter popover, scoped by what this user may see.
- GET /libraries/{libraryId}/breadcrumb (or breadcrumb embedded in the items response) — ancestor chain with each ancestor's id and name, plus the current folder's classification for the LocationBar chip.
- Presence for the LocationBar avatar stack — who is in this folder now. Likely the events/websocket path rather than REST.
- Upload: POST to initiate, resumable part upload, and a stage stream (SSE or websocket) emitting Queued/Uploading/Scanning/Processing/Indexing/Ready plus the four failure states, so the status cell reports the true stage and never shows Ready before antivirus completes (CLAUDE.md rule 9).
- Mutations, all idempotency-keyed: move, copy, rename, share, apply classification label, set retention, trash (with an undo window). Each must return the affected rows' refreshed capabilities so the client can invalidate rather than infer.
- Rust crates behind these: db (TenantScoped only), core (PolicyEngine::enforce on every one of the above), audit (written inside the policy engine, for denials too), events (presence + upload stage stream), search (only if the saved views are search-backed).