# The Enclave mark

## What it means

A bounded field with a window held inside it, enclosed on all four sides, touching no edge — what
the word means, and what the product is: an information boundary with the work kept inside it
(`docs/01-PRD.md §1`). The boundary is deliberately uneven, and the window's top-left corner is
square where it seats into the heavy corner. It is a place, not a diagram.

Not a padlock, a shield or a keyhole. The security is what makes the work safe; it is not the
product's personality.

## Construction

One rounded square, twice. On the 24 grid: field `24`, radius `6` (25%); window inset `7.5`, side
`12`, radius `3` (25% again), seated square at top-left. Every edge lands on a whole device pixel
at 16px — which is why it is legible there, and why the favicon needs no separate silhouette.

## Files

| File | Use | Colour |
|---|---|---|
| `logo.svg` | everywhere in product and print | `currentColor` — inherits `--fg`, works in both themes |
| `favicon.svg` | browser tab only | accent plate, solid white window |
| `logo-wordmark.svg` | email headers, sign-in, print, anywhere CSS fonts do not load | `currentColor` |

The wordmark is Inter Tight 600 at `-0.02em`, outlined to paths. It references no font, so it
survives an air-gapped install (`docs/08-BYO-INFRA.md §18`).

## Rules

- **Minimum size:** mark `16px`. Lockup `20px` tall.
- **Clear space:** the mark's corner radius — 25% of its height — on all four sides.
- **Never place the mark inside another plate.** It *is* the plate. Nested squares read as a target.
- **Never recolour the window separately from the field**, add a stroke, rotate, or stretch it.
- Beside a tenant's mark it is subordinate: monochrome, `--fg3` or lighter, never larger.
- Do not add `<title>` or `<desc>` — that is a user-facing string, and those live in the i18n
  catalog (`CLAUDE.md` rule 12). Label the mark at the call site.

## A tenant replacing it

`docs/09 §18` lets a tenant swap the mark, favicon, login and email art. A replacement must be SVG
with no external reference of any kind, square, legible at 16px, and pass AA against its own
background (`docs/09 §17`). Classification colours are never brandable. Where the Enclave mark is
retained as a credit, its minimum size and clear space still apply.
