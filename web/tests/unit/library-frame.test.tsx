import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/* The library frame's geometry, asserted as numbers.
 *
 * `TRACKER.md` ENC-849 says a file of this name exists on
 * `wip/enc-757-prototype-fidelity` and is "the first test in `web/` to assert
 * the prototype's geometry". It does not: `git ls-tree` on that branch and on
 * `worktree-agent-a84436454805e2dfd` returns nothing matching `frame`. So this
 * is written rather than merged, and the row's claim is answered rather than
 * repeated.
 *
 * ## Why it reads stylesheets instead of computed styles
 *
 * `vite.config.ts` does not set `test.css`, so Vitest does not process CSS
 * imports and jsdom has no cascade to measure. A `getComputedStyle` assertion
 * here would read the browser default for every property and pass against any
 * stylesheet at all — the vacuous-gate shape `docs/12 §1.2` and `ENC-677` are
 * both about. Reading the declarations is the honest form: it checks the thing
 * that is actually written down.
 *
 * ## What it is for
 *
 * `docs/09 §13` commits to an 8pt grid, two densities and a type ramp, and
 * `web/design-system/specs/library.md` fixes the numbers. A commitment
 * expressed as several hundred px literals cannot be checked and cannot be
 * changed — which is how this tree arrived at roughly 700 of them, the same
 * 44px state figure written out four times, and a `12.5px` body size in ten
 * separate files. These assertions are what makes "the tokens are the density"
 * a fact rather than an intention.
 */

const SRC = join(process.cwd(), 'src');
const read = (path: string) => readFileSync(join(SRC, path), 'utf8');
/** Comments carry prose about the values; only declarations are asserted on. */
const declarations = (source: string) => source.replace(/\/\*[\s\S]*?\*\//g, '');

describe('the density tokens carry the prototype’s own numbers', () => {
  const scale = declarations(read('styles/scale.css'));

  /* Counted from `enclave-client-prototype.html` rather than chosen:
   * `height:26px` appears on 63 of its controls and `font-size:12.5px` on 61 of
   * its elements, which is why those two are the defaults. */
  const EXPECTED: readonly (readonly [string, string])[] = [
    // Rows and bands — `specs/library.md §4A.1/§4A.2/§4A.3` and §1.
    ['--row-h', '36px'],
    ['--row-h-head', '30px'],
    ['--row-h-group', '28px'],
    ['--bar-h', '38px'],
    // Controls — §1.3, §2.2. Three heights and no more.
    ['--ctl-h-sm', '24px'],
    ['--ctl-h', '26px'],
    ['--ctl-h-lg', '28px'],
    // The peek panel — §4B and §4B's resize handle, which reuses the floor and
    // the ceiling as its `aria-valuemin` / `aria-valuemax`.
    ['--peek-w', '372px'],
    ['--peek-w-min', '320px'],
    ['--peek-w-max', '520px'],
    // The shell the screen sits in — §0.
    ['--shell-nav-w', '232px'],
    // The product's icon: 45 of the prototype's icons are 14px and 30 of its
    // symbols carry a 1.8 stroke.
    ['--icon', '14px'],
    ['--icon-stroke', '1.8'],
  ];

  for (const [token, value] of EXPECTED) {
    it(`sets ${token} to ${value}`, () => {
      expect(scale).toMatch(new RegExp(`${token}:\\s*${value.replace('.', '\\.')}\\s*;`));
    });
  }

  it('shrinks only the data row in compact density', () => {
    /* `docs/09 §13`'s second density is one declaration, because every list row
     * in the tree reads `--row-h`. The group header and the sticky header do
     * **not** shrink with it: they are already at 28 and 30, and a 24px group
     * header stops reading as a heading. */
    const compact = /\[data-density='compact'\]\s*\{([^}]*)\}/.exec(scale);
    expect(compact, "no [data-density='compact'] block in styles/scale.css").not.toBeNull();
    expect(compact?.[1]).toMatch(/--row-h:\s*30px/);
    expect(compact?.[1]).not.toMatch(/--row-h-group|--row-h-head/);
  });
});

describe('the library’s surfaces read the density rather than restating it', () => {
  /* Every px literal still allowed in each of these files, and why.
   *
   * The list is exhaustive on purpose: a rule that says "few literals" is a
   * rule nobody can fail. Adding a number here is a decision with a reason
   * beside it, which is the only form in which "geometry comes from the scale"
   * survives the next feature.
   */
  const ALLOWED: Readonly<Record<string, readonly string[]>> = {
    /* `88px` is the facts-grid label column: as wide as the longest field name,
     * which is a measure and not a step on a spacing scale. `1px`/`-1px` are
     * hairlines — the panel's leading rule, drawn outside the box so it costs
     * the 372px content nothing. */
    'features/libraries/library.css': ['1px', '-1px', '88px'],
    /* The seven-column template of `specs/library.md §4A`, verbatim, plus
     * hairlines, the 2px focus ring and the 2px selected-row marker. */
    'features/libraries/list/grouped-list.css': [
      '32px',
      '128px',
      '116px',
      '108px',
      '64px',
      '1px',
      '-1px',
      '2px',
      '-2px',
    ],
    'features/libraries/peek/preview-tab.css': [],
    /* The picker's reading measure: wider and the external-sharing tag sits
     * half a screen from the name it qualifies. */
    'features/libraries/picker.css': ['560px'],
    /* A 3px determinate progress bar with a 2px cap, and hairlines. */
    'features/upload/upload-tray.css': ['1px', '2px', '3px'],
    /* The 7px classification dot beside a library — the reference's own size,
     * and below the 8pt grid on purpose so it reads as a marker rather than as
     * an element. `460px` is the boot failure's measure. */
    'app/shell.css': ['1px', '2px', '3px', '7px', '460px'],
    'entities/file/kind-icon.css': [],
  };

  for (const [file, allowed] of Object.entries(ALLOWED)) {
    it(`${file} holds no unnamed dimension`, () => {
      const found = [...declarations(read(file)).matchAll(/-?\d*\.?\d+px/g)].map((m) => m[0]);
      const unexpected = [...new Set(found)].filter((value) => !allowed.includes(value));
      expect(unexpected, `${file} has px literals outside its allowlist`).toEqual([]);
    });
  }
});

describe('the file-kind tints are named, and named once', () => {
  /* Four raw hexes — `#D0453A / #3B6FD4 / #2E8B57 / #D2591C` — were written out
   * byte-identically in three feature stylesheets. A colour written three times
   * is a colour that gets corrected twice, and none of the three said what it
   * was for. */
  const kindIcon = declarations(read('entities/file/kind-icon.css'));

  it('defines all four as tokens', () => {
    for (const token of ['--kind-pdf', '--kind-doc', '--kind-xls', '--kind-ppt']) {
      expect(kindIcon).toMatch(new RegExp(`${token}:\\s*#`));
    }
  });

  it('leaves no raw kind hex under features/libraries', () => {
    /* Scoped to what this session owns. `features/home/home.css` and
     * `features/search/search.css` still hold their copies; both can adopt
     * `entities/file/kind-icon`'s `FileKindIcon` and delete them, which is
     * reported rather than done here because those files belong to other
     * sessions. */
    const RAW = /#(d0453a|3b6fd4|2e8b57|d2591c)/i;
    for (const file of [
      'features/libraries/library.css',
      'features/libraries/list/grouped-list.css',
      'features/libraries/picker.css',
      'features/libraries/peek/preview-tab.css',
    ]) {
      expect(declarations(read(file)), `${file} still hard-codes a file-kind tint`).not.toMatch(
        RAW,
      );
    }
  });
});

describe('the frame’s motion is the shared motion', () => {
  it('enters a data row with the row utility and the capped stagger', () => {
    /* `specs/library.md §4A.3` is exact: `enc-in var(--dur-row) var(--ease-enter)
     * both` with `animation-delay: calc(min(var(--i),12) * 20ms)`. Both halves
     * are utilities, so the reduced-motion answer — travel to zero, duration to
     * 1ms, stagger to 0 — is inherited rather than restated per component. */
    const list = declarations(read('features/libraries/list/grouped-file-list.tsx'));
    expect(list).toContain('enc-enter-row');
    expect(list).toContain('enc-stagger');
    expect(list).toMatch(/'--i':\s*windowIndex/);
  });

  it('slides the peek panel with the direction-aware panel utility', () => {
    /* The local `@keyframes encPeek` held
     * `translateX(calc(14px * var(--icon-flip, 1)))` — the last physical-axis
     * declaration in the tree. `styles/motion.css` owns it as `enc-panel`,
     * reading `--travel-panel` and `--icon-flip`. */
    const peek = declarations(read('features/libraries/peek/peek-panel.tsx'));
    expect(peek).toContain('enc-enter-panel');
    expect(declarations(read('features/libraries/library.css'))).not.toContain('encPeek');
  });
});
