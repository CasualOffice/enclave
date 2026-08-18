# Design system

`design-system-v2.html` is the visual reference: layouts, interaction patterns and the full token
set, rendered so they can be looked at rather than imagined. Open it in a browser.

It is **authoritative for token values**. `web/src/styles/tokens.css` is extracted from it, and
[`docs/09-UX-WHITE-LABELING.md`](../../docs/09-UX-WHITE-LABELING.md) remains authoritative for UX
standards — budgets, keyboard model, accessibility, the four required states. The two do not
overlap: one says what things look like, the other says how they must behave.

Change a token in the HTML first, then re-extract. A value edited only in `tokens.css` drifts from
the reference nobody re-reads afterwards.

## What it covers

| | |
|---|---|
| **Layouts** | Library list with peek panel and floating selection bar · command palette and display popover · Ask (AI beside the work) · admin policy-as-a-sentence · sign-in and mobile |
| **Interaction patterns** | Selection bar · peek before open · label and effect language · denied-explained-inline · DLP intercept · truthful progress |
| **Tokens** | Warm neutral scale, semantic surfaces, elevation ladder, classification, brand accent, type |

Several of these are the visual form of things `docs/` already commits to in prose, which is worth
noting because it means they are testable, not decorative:

- **Denied, explained inline** is `docs/06-SECURITY-DLP-ACCESS.md §24` — a stable reason code, a
  user-safe sentence, a remediation, and nothing about which policy matched.
- **Truthful progress** is `docs/09 §8` — `Uploading → Scanning → Processing → Indexing → Ready`,
  and never reporting a file as ready before antivirus completes.
- **DLP intercept** is `docs/09 §9` — say what was detected in category terms, collect a
  justification inline, say plainly that it is recorded.

## Three groups of token, three different rules

**Neutrals, surfaces, elevation** — structural. Not tenant-editable.

**Classification (`--c-pub` … `--c-restr`) — locked.** A tenant recolouring "Restricted" to fit its
palette is a tenant whose users misread sensitivity at a glance. Colour is never the only carrier
either: badges carry text as well (`docs/09 §15`), so the palette is a reinforcement, not the
signal.

**Brand accent and radii** — tenant-editable through the branding API (`docs/09 §18`). These are the
only values a `[data-brand]` block overrides, and a brand colour that fails AA contrast against its
own background cannot be saved (`docs/09 §17`).

## The fonts are self-hosted (`ENC-135`)

The reference used to load Inter, Inter Tight and JetBrains Mono from Google's font CDN. That was
fine for a
design artefact and not fine for the product: it sent every user's IP address to a third party on
page load, it broke air-gapped installs outright, and it quietly contradicted the data-residency
promise in `docs/08-BYO-INFRA.md §18` — which lists exactly the derived surfaces that must stay in
region and would be embarrassing to undermine with a webfont.

So the files now live in [`web/public/fonts/`](../public/fonts/) and the HTML declares them with
`@font-face` instead of a `<link>`. **The reference makes no third-party request at all** — the only
external string left in the file is the SVG namespace URI, which is an identifier and not a fetch.

Three things about how it is done are worth knowing before you change it:

- **They are variable fonts.** One file carries the whole weight range (Inter 400–600, Inter Tight
  500–600, JetBrains Mono 400–500), so adding a weight inside those ranges costs no new download.
  Going outside one does — that is a deliberate speed bump.
- **They are split by Unicode range, and each `@font-face` carries the matching `unicode-range`.**
  Twenty files are vendored, but a browser fetches only the ranges it actually renders: loading the
  reference pulls four of them, 205 KB (three Latin faces plus Latin Extended, which some glyph on
  the page reaches into); an English page with no extended characters pulls three, 122 KB. Sixteen
  of the twenty are never requested. The non-Latin ranges are there so the first locale that
  lands does not regress against `docs/14-I18N-L10N.md`; until then they cost nothing. Keep the
  `unicode-range` on any face you add, or that property stops holding.
- **`font-display: swap` on every face**, so text is readable before the font arrives rather than
  invisible — the same truthfulness rule the progress states follow.

All three families are SIL Open Font License 1.1, verified against upstream rather than assumed;
none declares a Reserved Font Name. [`web/public/fonts/LICENSE`](../public/fonts/LICENSE) carries
the licence text, the authors, the exact upstream versions and a SHA-256 per file, which is what
lets a future reader confirm these binaries are unmodified.

The files are upstream's own subsets, taken as-is. Cutting them further by glyph coverage needs
`pyftsubset` or equivalent, which means a build step — that belongs with the SPA build, not here.

`tokens.css` names the families and does not fetch them, so it needed no change; the SPA will point
its own `@font-face` at the same directory.
