# 09 — Production UX, File Views & White-Labeling

> **Status:** Draft · **Version:** 2.0 · **Owner:** Design + Frontend · **Last updated:** 2026-08-18
> **Authoritative for:** application UX standards, view types, admin UX, branding, accessibility.
> Localization mechanics live in `14-I18N-L10N.md`. **Token values** live in
> `web/design-system/design-system-v2.html`, the visual reference, and are extracted to
> `web/src/styles/tokens.css` — this document governs behaviour, that one governs appearance.

## 1. UX objective

The application must feel like a mature daily-use productivity suite — the class of tool people keep
open all day — not a developer console with a file table bolted on.

Three standards everything is judged against:

1. **Professional.** Restrained visual language, consistent density, no decorative motion, no
   surprises in destructive paths.
2. **Fluid.** Interaction feels immediate. Nothing blocks on a spinner that could have been
   optimistic; nothing janks while scrolling 100 000 rows.
3. **Trustworthy.** The UI never offers an action the server will refuse, never claims a file is
   ready before it is, and never hides why something was blocked.

## 2. Interaction performance budgets

These are product requirements, not aspirations. They are measured in CI with Lighthouse and in
production with RUM.

| Interaction | Budget |
|---|---|
| Keystroke → visible input update | < 16 ms (one frame) |
| Click → visible acknowledgement (state change, skeleton, optimistic row) | < 100 ms |
| Navigation between views (cached data) | < 200 ms |
| Folder open, 10k items, first paint | < 400 ms |
| Search results rendered | < 700 ms P95 |
| Scroll of a virtualized 100k-row table | 60 fps, no dropped frames |
| Initial app load (cold, gzipped) | LCP < 2.5 s, main bundle < 250 KB |

Rules that keep them: virtualize every list over 100 rows, paginate by cursor, prefetch on hover and
on route intent, keep an optimistic cache with TanStack Query, never block first paint on a
non-critical request, and code-split admin and editor routes out of the main bundle.

## 3. Main shell

```text
+--------------------------------------------------------------------------+
| ◱ Logo   Workspace ▾        ⌕ Search (⌘K)          + New    ⚙    Avatar  |
+--------------+-----------------------------------------------------------+
| Home         |  Breadcrumb / View switcher / Filter / Sort               |
| Files        | ---------------------------------------------------------|
| Lists        |                                                           |
| Pages        |              Content region (virtualized)                 |
| Activity     |                                                           |
| Favorites    |                                                           |
| Shared       |                                                           |
| Trash        |                                                           |
|              |                                                           |
| Admin        |                                                           |
+--------------+-----------------------------------------------------------+
| Selection bar: 3 selected · Download · Move · Share · Delete · ✕         |
+--------------------------------------------------------------------------+
```

The shell persists across navigation; only the content region swaps. Navigation never triggers a
full page reload, and scroll position, selection and expansion state survive back/forward.

## 4. File and library views

List, Compact List, Details, Tiles, Cards, Gallery, Grid, Tree, Timeline, Recently Modified, Shared
With Me, Favorites, My Files, Expiring Documents, Classification View, and Custom Saved Views.

View state (type, columns, widths, sort, grouping, filters) is a stored definition, never a copy of
data. Switching views does not refetch when the underlying query is unchanged.

### 4.1 Grid view

The grid is the workhorse and is held to spreadsheet standards: inline metadata editing, keyboard
navigation (arrows, tab, enter to edit, escape to cancel), column resize and reorder by drag, frozen
leading columns, multi-column sort, grouping with collapsible headers, bulk edit across a selection,
copy/paste of metadata ranges, and virtual scrolling in both axes.

Editing is optimistic with rollback: the cell updates immediately, and on failure it reverts with an
inline explanation rather than a toast that scrolls away.

### 4.2 View scopes

`PERSONAL`, `LIBRARY`, `WORKSPACE`, `TENANT_TEMPLATE`. Users create private views freely; owners
publish shared defaults. A shared view that a user has personalized shows a "Modified — reset"
affordance rather than silently diverging.

## 5. Command bar and command palette

Context-aware actions: New, Upload, Open, Share, Download, Move, Copy, Rename, Automate, Details,
More. Actions appear based on selection, ACL, DLP, conditional access and classification — sourced
from the `capabilities` object the API returns (`05-API.md §7`), so the UI and the server can never
disagree.

`⌘K` / `Ctrl+K` opens a command palette spanning navigation, actions on the current selection, recent
files and search. Every command in the palette shows its keyboard shortcut, which is how users learn
them.

## 6. Keyboard model

The product is fully operable without a mouse.

| Key | Action |
|---|---|
| `⌘K` | Command palette |
| `/` | Focus search |
| `↑ ↓` | Move selection · `Shift` extends · `⌘` toggles |
| `→ ←` | Expand/collapse in tree; next/previous column in grid |
| `Enter` | Open · `Space` preview |
| `⌘A` | Select all in view |
| `R` `M` `C` `S` | Rename, Move, Copy, Share on the selection |
| `Del` | Move to trash (with undo) |
| `I` | Toggle details panel |
| `?` | Keyboard shortcut reference |
| `Esc` | Close panel/dialog, clear selection |

Focus is always visible, focus order follows visual order, and focus returns to the triggering
element when a dialog closes.

## 7. Details panel

A right-side panel, not a separate page: Preview, Info, Metadata, People, Permissions, Versions,
Activity, Comments, DLP, Retention, Sharing.

The panel is resizable, its width persists, and its tab selection persists per resource type. Routine
work — renaming, retagging, checking who has access — happens here without losing the list behind it.

## 8. Upload UX

True states, always:

```text
Queued -> Uploading -> Scanning -> Processing -> Indexing -> Ready
```

Failure states: Quarantined, Failed, Aborted, Quota Exceeded.

Rules: never report a file as ready before required security processing completes; show per-file and
aggregate progress; support pause, resume and retry of individual files; keep uploads running across
navigation within the app; warn before a tab close that would abort transfers; surface a rejected
file type or size *before* bytes are sent, using the limits returned by the API.

## 9. DLP and policy-denial UX

When a policy warns, explain what was detected in category terms ("This file contains payment card
numbers") without echoing the sensitive values. If override is permitted, collect a justification
inline, state plainly that it will be recorded, and audit it.

When a policy blocks, show the user-safe message and remediation from the API
(`05-API.md §5`) — "Downloading this file is restricted outside the corporate network. Connect to the
VPN, or request an exception." Offer the remediation as an action where one exists: connect,
complete MFA, request access. Never show an internal policy name or a raw error code as the primary
message; the code belongs in a copyable details disclosure for support.

## 10. Search UX

Universal search across filename, natural language, metadata, person, date, workspace, file type and
classification. Filters are chips that compose and are individually removable; the active filter set
is reflected in the URL so a search is shareable and restorable.

Each result shows title, path, workspace, matched excerpt, file type, owner, modified date,
classification badge, and the page/sheet/section location, which deep-links directly into the
preview at that location.

AI answers always expose their source documents and chunks, with the same deep links. A degraded
search (vector store unavailable) says so in the results header rather than quietly returning less.

## 11. Empty, loading and error states

Every surface defines all four states, and they are reviewed as part of the feature, not afterwards:

- **Empty (new)** — what this surface is for, and the one action that starts it.
- **Empty (filtered)** — "No files match these filters", with a clear-filters action.
- **Loading** — skeletons that match the final layout so nothing shifts when data lands. No
  full-screen spinners on navigations.
- **Error** — what failed, whether it is retryable, a retry action, and a copyable request ID.

Loading states never cause cumulative layout shift; the reserved skeleton and the loaded row share
the same box model.

## 12. Motion

Motion clarifies causality; it never entertains. Durations 120–200 ms, standard easing, and only on
enter/exit, expansion and position changes. No motion on data updates in place. `prefers-reduced-motion`
removes all non-essential animation, keeping only opacity changes.

## 13. Density and layout

Two densities, user-selectable and remembered: Comfortable (48 px rows) and Compact (36 px rows).
An 8 px spacing scale, a 4 px radius scale, and a type ramp of six sizes. Tables align numbers right
and dates in a fixed-width font so columns scan cleanly.

## 14. Reliability of the interface

Skeletons over spinners; optimistic updates where the server is very likely to agree; autosave with
a visible saved-state indicator; undo for every reversible destructive action (trash, bulk move,
bulk metadata edit) with a 10-second window; preserved navigation state; and no unnecessary
full-page reloads. A failed optimistic update rolls back visibly and explains itself in place.

## 15. Accessibility

WCAG 2.2 AA is the target and is tested, not assumed:

- keyboard-only operation of every flow, including grid editing and drag-and-drop (which has a
  keyboard equivalent via Move);
- visible focus with a 3:1 contrast ratio against adjacent colors;
- semantic controls and correct ARIA roles for the grid, tree, tabs and dialogs;
- screen-reader announcements for async results (upload complete, policy denial, selection count)
  through polite live regions;
- 4.5:1 text contrast, 3:1 for UI components and graphical objects, in every brand theme;
- respect for `prefers-reduced-motion`, `prefers-color-scheme` and user font scaling to 200%;
- no information conveyed by color alone — classification badges carry text as well as color;
- accessible names on all icon-only buttons.

Automated axe checks run in CI; manual screen-reader passes (NVDA, VoiceOver) gate each release.

## 16. Responsive behavior

Desktop and tablet are primary. Mobile is functional, not vestigial: search, preview, approve, share,
comment, upload and basic metadata all work on a phone. Complex admin remains desktop-first, and the
mobile admin surface says so rather than rendering an unusable table.

Breakpoints collapse the navigation rail to a drawer, the details panel to a bottom sheet, and the
grid to a card list with the columns from the active view as fields.

## 16a. The design system

`web/design-system/design-system-v2.html` is the rendered reference: layouts, interaction patterns
and the complete token set. It is authoritative for values; this document stays authoritative for
behaviour.

Its interaction patterns are the visual form of commitments made elsewhere in this pack, which is
what makes them testable rather than decorative — *denied, explained inline* is `06 §24`, *truthful
progress* is `§8` above, *DLP intercept* is `§9`.

Tokens fall into three groups with different rules, and the middle one is a control rather than a
preference:

| Group | Rule |
|---|---|
| Neutrals, surfaces, elevation | Structural. Not tenant-editable. |
| **Classification** (`--c-pub` … `--c-restr`) | **Locked.** A tenant recolouring "Restricted" to match its palette is a tenant whose users misread sensitivity at a glance. |
| Brand accent, radii | Tenant-editable through the branding API (`§18`), subject to the contrast validation in `§17`. |

Locking classification colour does not make colour load-bearing: badges carry text as well (`§15`),
so the palette reinforces a label that is already readable without it.

## 17. Theming and dark mode

Light and dark themes are both first-class and both derive from the same token set. Theme follows the
system preference by default, with an explicit override. Every brand color is validated for contrast
in both themes at configuration time — a tenant cannot save a brand color that fails AA against its
own background.

## 18. White-labeling

Tenant configuration: product name, logo, favicon, brand and accent colors, login logo and
background, email logo and footer, support URL, privacy URL, terms URL.

The branding API returns design tokens; React maps them to CSS variables (`--brand-primary`,
`--brand-accent`, `--brand-radius`, and the derived contrast-safe foreground pairs). Arbitrary CSS
injection is not permitted by default — it is an XSS vector and a support burden. Tenants needing
more can request a reviewed theme package.

## 19. Custom domains

`workspace.customer.com` with domain verification (DNS TXT), automatic certificate issuance or a
manual certificate upload, and tenant resolution at the gateway before application code runs. The
admin UI walks the DNS steps, verifies live, and shows certificate status and expiry.

## 20. Email branding

Per tenant: sender name, sender address, reply-to, templates, header/footer/logo. BYO SMTP
(`08-BYO-INFRA.md §8`) integrates with this branding, and every template has a plain-text
alternative and a localized variant (`14-I18N-L10N.md §5`).

## 21. Admin UX

Navigation: Overview, Users, Groups, Workspaces, Authentication, Security, DLP, Conditional Access,
Classification, Retention, Audit, Storage, Search / Milvus, AI / MCP, SMTP, Vault / Secrets,
Branding, Integrations, Quotas, Monitoring, Backups, System.

Standards for the admin surface, which is where enterprise products usually fail:

- **Rule builders, not JSON.** Normal policy creation uses a form-based condition/effect builder.
  A JSON view is available for power users and for copying between tenants, and the two stay in sync.
- **Simulate before enforce.** Any policy with a blocking effect offers "Test against last 30 days"
  and shows what would have been blocked, by whom, and how often.
- **Diff before save.** Security-sensitive changes show a field-level diff and require confirmation;
  maker/checker changes show who must approve.
- **Explain the blast radius.** "This affects 1 240 files across 3 libraries" before applying, not
  after.
- **Everything is searchable and linkable.** Every admin object has a stable URL.
- **Read-only auditor mode** renders the same screens without mutating controls, rather than a
  separate, poorer interface.

## 22. Internationalization

The interface is fully localizable and layout-independent of language: no concatenated strings, no
text baked into images, no assumptions about text length or date/number format, and full RTL support.
Mechanics, locale negotiation, translation workflow and search-language handling are specified in
`14-I18N-L10N.md`.
