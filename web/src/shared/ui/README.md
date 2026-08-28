# `shared/ui` — the component library

**Read [`docs/17-FRONTEND-LLD.md §13`](../../../../docs/17-FRONTEND-LLD.md) first.** That section is
authoritative for the component contract: when to reach for a primitive, what a component must
expose, how variants are expressed, and where the layer boundary runs. This file is the map of what
is actually here, so you can find the thing before you write it again.

Nothing below restates a rule. Where a rule is relevant, it is named and linked.

## The map

| Reach for | When | File |
|---|---|---|
| `Button` · `IconButton` · `LaterChip` | Any actionable control. Carries the three non-actionable treatments (`docs/17 §6`) | `primitives.tsx` |
| `Pill` · `Kbd` · `Avatar` · `AvatarStack` · `Skeleton` · `ScreenReaderOnly` | Small marks and reserved boxes | `primitives.tsx` |
| `Card` · `Bar` · `Push` · `Eyebrow` · `Row` · `Truncate` · `Popover` · `TabList`/`Tab` · `Field` | Containers and layout idioms | `layout.tsx` |
| `StateBlock` · `EmptyState` · `FilteredEmptyState` · `ErrorState` · `DeniedPanel` · `FailureState` · `UnbuiltState` · `RequestId` | The states of `docs/09 §11`. **The only** implementation | `surface-states.tsx` |
| `Icon` · `IconSprite` | Every glyph. Generated from the reference by `tools/extract-sprite.mjs` | `icon-sprite.tsx` |
| `AccessLoader` | The mark, scanning, while a route settles | `mark.tsx` |
| `ClassificationChip` | The sensitivity badge. **The only** one — it reads the locked palette | `entities/classification/chip.tsx` |

Geometry and motion are tokens, not components:

| | File |
|---|---|
| Colour, radii, font families, the classification palette | `src/styles/tokens.css` — extracted from the reference; re-extracted as one block |
| Space, type ramp, control heights, rows, icons, measures, the z-ladder | `src/styles/scale.css` |
| Durations, easings, travel, stagger, keyframes, the reduced-motion answer | `src/styles/motion.css` |

## The three questions this library answers before you write CSS

**"Is there a component for this?"** Check the table. If a surface appears on two screens, it belongs
here or in `entities/` — that is `docs/17 §2`, and it is enforced by `tools/lint-web.mjs`, not by
review.

**"Is this number on the scale?"** If you are typing a `px`, it is almost certainly `--sp-*`,
`--fs-*`, `--ctl-h*`, `--row-h*` or `--r-*`. A literal is a value that escaped the scale, and the
tree accumulated roughly 700 of them before the scale existed. Two exceptions are documented in
place: a grid column specification, and the classification figure's own proportions.

**"Does this animate?"** Then it reads `var(--dur-*)` and `var(--ease-*)`. Never a literal duration
and never a hand-written `cubic-bezier`. The reduced-motion answer lives in `motion.css` and works by
rewriting those tokens — so a component that uses them degrades whether or not its author remembered
the media query exists. `tests/unit/design-system.test.tsx` asserts there is exactly one
`prefers-reduced-motion` block in the tree and no `@keyframes` under `features/`.

## What is deliberately *not* here

`shared/ui` holds primitives only (`docs/17 §11`). A component that knows what a classification, a
file kind, an upload phase or a capability *is* belongs in `entities/`. The classification chip is
the worked example: it is the locked palette's only reader, and it lives one directory over for
exactly that reason.

## Changing a token

Change it in `web/design-system/` first, then re-extract. A value edited only in `tokens.css` drifts
from the reference nobody re-reads afterwards — `web/design-system/README.md` says so, and `ENC-678`
is what happened when a hand-extraction missed the dark accent ladder.

`scale.css` and `motion.css` are *derived* rather than extracted: they name values the reference
uses, and adding a step to either is a design decision worth stating in the commit.

## The tests that keep this a library

- `tests/unit/design-system.test.tsx` — one implementation per surface, expressed as *where* a
  declaration may appear. Two of its assertions are security assertions (`docs/17 §6`, `docs/09 §16a`).
- `tests/unit/failure-states.test.tsx` — a denial is not a failure (`docs/17 §10` F3).
- `tests/a11y/routes.spec.ts` — axe on every surface, in both themes, in real Chromium.
- `tests/shots/surfaces.spec.ts` — not a gate. One PNG per surface, at the reference's 1440×900, so a
  change can be looked at beside `tools/prototype-shot.mjs`'s capture of the prototype.
