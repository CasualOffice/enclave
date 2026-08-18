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

## One thing that must change before this ships

The reference loads Inter and JetBrains Mono from `fonts.googleapis.com`.

That is fine for a design artefact and not fine for the product. It sends every user's IP address to
a third party on page load, it breaks air-gapped installs outright, and it quietly contradicts the
data-residency promise in `docs/08-BYO-INFRA.md §18` — which lists exactly the derived surfaces that
must stay in region and would be embarrassing to undermine with a webfont.

**Self-host the fonts** when the SPA is built (`ENC-135`). The token file names the families and
does not fetch them, so nothing here depends on the CDN; only the reference HTML does.
