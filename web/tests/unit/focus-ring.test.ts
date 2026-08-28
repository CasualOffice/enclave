import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/* The focus indicator, measured rather than asserted by eye.
 *
 * `docs/09 §15` requires "visible focus with a 3:1 contrast ratio against
 * adjacent colors", and until `ENC-702` nothing checked it. **axe cannot**: it
 * measures text contrast and some graphical objects, and an `outline` colour
 * declared on a `:focus-visible` pseudo-class is neither — it is not in the
 * accessibility tree and it is not painted until a key is pressed. So 94 green
 * axe pages said exactly nothing about the one indicator a keyboard user
 * depends on, which is the "green gate proving nothing" shape one layer below
 * where this repository last found it.
 *
 * What the tree drew was `2px solid var(--accent-ring)`, and `--accent-ring` is
 * a 30–40% alpha wash. Composited, it measures between 1.68:1 and 2.42:1 across
 * the six theme × brand combinations — the best of them four fifths of the
 * floor. That is `ENC-895`.
 *
 * This test reads `tokens.css` for the values rather than restating them, so a
 * brand added to the palette without a legible focus ring fails here instead of
 * shipping.
 */

const TOKENS = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8');

/* ---------------------------------------------------------------- the maths */

type Rgb = readonly [number, number, number];

function parseHex(value: string): Rgb {
  const raw = value.replace('#', '').trim();
  const full = raw.length === 3 ? [...raw].map((c) => c + c).join('') : raw;
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ] as const;
}

/** WCAG 2.x relative luminance. */
function luminance([r, g, b]: Rgb): number {
  const channel = (value: number): number => {
    const c = value / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

export function contrast(a: Rgb, b: Rgb): number {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high! + 0.05) / (low! + 0.05);
}

/** Source-over compositing, which is what the browser does before axe measures. */
function over(fg: Rgb, alpha: number, bg: Rgb): Rgb {
  return [
    Math.round(alpha * fg[0] + (1 - alpha) * bg[0]),
    Math.round(alpha * fg[1] + (1 - alpha) * bg[1]),
    Math.round(alpha * fg[2] + (1 - alpha) * bg[2]),
  ] as const;
}

function parseRgba(value: string): { readonly rgb: Rgb; readonly alpha: number } {
  const match = /rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)/.exec(value);
  if (match === null) throw new Error(`not an rgba() value: ${value}`);
  return {
    rgb: [Number(match[1]), Number(match[2]), Number(match[3])] as const,
    alpha: match[4] === undefined ? 1 : Number(match[4]),
  };
}

/* --------------------------------------------------- the values under test */

/**
 * Every `selector { … }` block in `tokens.css`, in source order.
 *
 * Parsed rather than pattern-matched per selector. A regex built from the
 * selector text matches `[data-brand="northwind"]` inside
 * `[data-theme="dark"][data-brand="northwind"]` as well, so "the light
 * northwind accent" silently resolved to the dark one — a test reading the
 * wrong value and passing. Comparing whole selector strings cannot do that.
 */
const BLOCKS: readonly { readonly selector: string; readonly body: string }[] = [
  ...TOKENS.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g),
].map((match) => ({ selector: match[1]!.trim(), body: match[2]! }));

/**
 * A token's value under `selector`, taking the last declaration — which is what
 * the cascade does when one selector appears in several blocks, as `:root`
 * does three times here.
 */
function tokenIn(selector: string, name: string): string {
  let found: string | undefined;
  for (const block of BLOCKS) {
    if (block.selector !== selector) continue;
    const decl = new RegExp(`${name}\\s*:\\s*([^;}]+)`).exec(block.body);
    if (decl !== null) found = decl[1]!.trim();
  }
  if (found === undefined) throw new Error(`${name} not found in ${selector}`);
  return found;
}

/**
 * The surfaces a focus ring can land on, per theme.
 *
 * Not an arbitrary list: `--sheet` is every row and control, `--canvas` is the
 * shell behind the sidebar, `--sunken` is the upload band and every pill, and
 * `selected` is a selected row — which is precisely where the grid's focus ring
 * spends most of its life, and the one surface a "measured it on white" check
 * would miss.
 */
const SURFACES = {
  light: {
    sheet: parseHex('#ffffff'),
    canvas: parseHex('#F7F7F5'),
    sunken: parseHex('#F0F0ED'),
    selected: over(parseHex('#141412'), 0.06, parseHex('#ffffff')),
  },
  dark: {
    sheet: parseHex('#161615'),
    canvas: parseHex('#0F0F0E'),
    sunken: parseHex('#1D1D1B'),
    selected: over(parseHex('#ffffff'), 0.07, parseHex('#161615')),
  },
} as const;

/** Every theme × brand combination the palette ships, and its accent. */
const COMBINATIONS = [
  { name: 'light/default', theme: 'light', selector: ':root' },
  { name: 'light/northwind', theme: 'light', selector: '[data-brand="northwind"]' },
  { name: 'light/meridian', theme: 'light', selector: '[data-brand="meridian"]' },
  { name: 'dark/default', theme: 'dark', selector: '[data-theme="dark"]' },
  {
    name: 'dark/northwind',
    theme: 'dark',
    selector: '[data-theme="dark"][data-brand="northwind"]',
  },
  {
    name: 'dark/meridian',
    theme: 'dark',
    selector: '[data-theme="dark"][data-brand="meridian"]',
  },
] as const;

/** WCAG 1.4.11: a graphical object that carries meaning needs 3:1. */
const FLOOR = 3;

/**
 * The colour the focus ring actually paints under `selector`, composited.
 *
 * **Resolved, not named.** The first version of this test measured `--accent`
 * directly and passed against the broken tree, because `--accent` was never the
 * problem — the ring was drawn in `--accent-ring` and nothing connected the two.
 * A test that measures a token no rule references is an assertion about an
 * absence: it passes for free, and it passed for free here until the value it
 * was supposed to be guarding was put in front of it.
 *
 * So this follows `--focus-ring` through one level of `var()` indirection to a
 * literal, and composites it if it carries alpha. Point `--focus-ring` at the
 * wash and this reports 1.76:1 rather than quietly reporting the accent.
 */
function resolvedRing(selector: string, surface: Rgb): Rgb {
  let value = tokenIn(':root', '--focus-ring');
  const indirection = /^var\(\s*(--[a-z-]+)\s*\)$/.exec(value);
  if (indirection !== null) value = tokenIn(selector, indirection[1]!);
  if (value.startsWith('#')) return parseHex(value);
  const { rgb, alpha } = parseRgba(value);
  return over(rgb, alpha, surface);
}

describe('the focus indicator is visible in every theme and brand', () => {
  for (const combination of COMBINATIONS) {
    const surfaces = SURFACES[combination.theme];

    it(`${combination.name}: the ring clears 3:1 on every surface it can land on`, () => {
      for (const [name, background] of Object.entries(surfaces)) {
        const measured = contrast(resolvedRing(combination.selector, background), background);
        expect(
          measured,
          `focus ring on ${name} in ${combination.name} measures ${measured.toFixed(2)}:1, ` +
            `below the ${FLOOR}:1 docs/09 §15 requires of a focus indicator`,
        ).toBeGreaterThanOrEqual(FLOOR);
      }
    });

    it(`${combination.name}: --accent-ring alone would not clear it, which is why it is not the ring`, () => {
      /* The negative control, pinning the value that was rejected.
       *
       * Without it the suite above proves only that *today's* palette passes —
       * not that the measurement can fail, and not that the wash was the
       * defect. If a future palette makes the wash legible this test fails, and
       * that is worth knowing too: the argument for the change would no longer
       * be the one recorded in `tokens.css`. */
      const ring = parseRgba(tokenIn(combination.selector, '--accent-ring'));
      const composited = over(ring.rgb, ring.alpha, surfaces.sheet);
      const measured = contrast(composited, surfaces.sheet);
      expect(
        measured,
        `--accent-ring in ${combination.name} now measures ${measured.toFixed(2)}:1 on the sheet`,
      ).toBeLessThan(FLOOR);
    });
  }
});

describe('no stylesheet builds a focus indicator out of the wash', () => {
  it('has no `:focus-visible` outline drawn in --accent-ring', () => {
    /* The rule, not the token. `--accent-ring` is still correct as the outer
     * glow *behind* a solid line — `.ui-field:focus-within` and `.esr-hit` both
     * pair it with a 1px `--focus-ring` — so banning the token outright would
     * refuse the right answer. What is banned is a ring whose only colour is
     * the wash, which is what `base.css` and `grouped-list.css` each drew. */
    const walk = (dir: string, out: string[] = []): string[] => {
      for (const entry of readdirSync(dir)) {
        const path = join(dir, entry);
        if (statSync(path).isDirectory()) walk(path, out);
        else if (path.endsWith('.css')) out.push(path);
      }
      return out;
    };

    const offenders: string[] = [];
    for (const path of walk(join(process.cwd(), 'src'))) {
      const source = readFileSync(path, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
      for (const line of source.split('\n')) {
        if (/outline\s*:[^;]*var\(--accent-ring\)/.test(line)) {
          offenders.push(`${path.slice(process.cwd().length + 1)}: ${line.trim()}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
