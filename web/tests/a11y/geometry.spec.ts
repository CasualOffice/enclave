import { test, expect } from '@playwright/test';
import { stubApi } from './api-stub.ts';

/* The reference's geometry, measured on the rendered product.
 *
 * ## Why this exists beside the token test
 *
 * `tests/unit/design-system.test.tsx` asserts the *declared* values — that
 * `--row-h` is `36px`, that `--ctl-h` is `26px`. That catches a token edited
 * wrongly. It cannot catch a token that is correct and **unread**: a row that
 * hardcodes `40px` beside a perfectly good `--row-h` passes every unit test,
 * every lint rule and every axe check, and is wrong on screen.
 *
 * `ENC-757` is that failure in its purest form — every web gate was green while
 * the peek panel did not exist. A number in a spec that no test reads is a
 * number that drifts, and a number a test reads *only in the stylesheet* is a
 * number that drifts one layer further along.
 *
 * So this runs in real Chromium, reads `getBoundingClientRect()` and
 * `getComputedStyle()` off the live DOM, and compares them to the same table
 * `web/design-system/specs/library.md` states. It is part of the `a11y`
 * project because that is the one browser gate CI runs.
 *
 * ## What it deliberately does not do
 *
 * It does not screenshot-compare. A pixel diff against the prototype would fail
 * on font rendering, on seed data, and on every surface the server does not yet
 * populate — and a gate that fails for reasons nobody can act on is a gate
 * people learn to skip. `tests/shots/surfaces.spec.ts` captures the images for
 * a person to look at; this asserts the handful of numbers that carry the
 * design's density and are meant not to move.
 */

/* Sub-pixel tolerance only. These are integer CSS pixels at
 * `deviceScaleFactor: 1`; a 36px row that measures 36.5 is a rounding artefact,
 * a 36px row that measures 40 is the defect. */
const TOLERANCE = 1;

interface Measured {
  readonly name: string;
  readonly selector: string;
  /** `block` is the height in the block axis; `inline` the width. */
  readonly block?: number;
  readonly inline?: number;
  readonly why: string;
}

const FRAME: readonly Measured[] = [
  {
    name: 'sidebar',
    selector: '.shell-nav',
    inline: 232,
    why: 'the prototype shell, measured: grid-template-columns 232px 1fr',
  },
  {
    name: 'location bar',
    selector: '.library-location',
    block: 38,
    why: 'specs/library.md §1 — min-block-size 38px',
  },
  {
    name: 'data row',
    selector: '.egl-row',
    block: 36,
    why: 'docs/09 §13 Default density; specs/library.md §4A.3',
  },
];

test.describe('the library frame holds the reference’s geometry', () => {
  test.beforeEach(async ({ page }) => {
    /* Reduced motion, so a row measured mid-entrance is not measured
     * mid-transform. `enc-in` translates on the block axis, which would move a
     * row's `top` but not its height — measured anyway, because a suite that is
     * right for a reason it does not state is a suite that breaks silently. */
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await stubApi(page);
    await page.goto('/library?library=lib-1');
    await page.waitForSelector('[role="treegrid"] .egl-row', { timeout: 30_000 });
  });

  for (const item of FRAME) {
    test(`${item.name}: ${item.why}`, async ({ page }) => {
      const box = await page.locator(item.selector).first().boundingBox();
      expect(box, `${item.selector} is not on screen`).not.toBeNull();
      if (item.inline !== undefined) {
        expect(box?.width).toBeGreaterThanOrEqual(item.inline - TOLERANCE);
        expect(box?.width).toBeLessThanOrEqual(item.inline + TOLERANCE);
      }
      if (item.block !== undefined) {
        expect(box?.height).toBeGreaterThanOrEqual(item.block - TOLERANCE);
        expect(box?.height).toBeLessThanOrEqual(item.block + TOLERANCE);
      }
    });
  }

  test('compact density is 30px, and it is the row that changes', async ({ page }) => {
    /* `docs/09 §13` names two densities and this is the second. Asserted
     * against the *default* in the same test so the pair cannot both drift to
     * the same number, which is how a density control quietly stops doing
     * anything. */
    const defaultRow = await page.locator('.egl-row').first().boundingBox();
    expect(defaultRow?.height).toBeCloseTo(36, 0);

    await page.goto('/library?library=lib-1&density=compact');
    await page.waitForSelector('.egl-row', { timeout: 30_000 });
    const compactRow = await page.locator('.egl-row').first().boundingBox();
    expect(compactRow?.height).toBeCloseTo(30, 0);
  });
});

test.describe('the peek panel is 372px, within its clamp', () => {
  test('opens at the reference width', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await stubApi(page);
    await page.goto('/library?library=lib-1&peek=file-3');
    await page.waitForSelector('.library-peek-caps', { timeout: 30_000 });

    const peek = await page.locator('.library-peek').first().boundingBox();
    expect(peek, '.library-peek is not on screen').not.toBeNull();
    /* 372 is the resting width and 320–520 the clamp (`specs/library.md §4`).
     * The clamp is asserted as well as the value because the resting width is a
     * default a user can move and the bounds are not. */
    expect(peek?.width).toBeGreaterThanOrEqual(320);
    expect(peek?.width).toBeLessThanOrEqual(520);
    expect(peek?.width).toBeCloseTo(372, 0);
  });
});

test.describe('reduced motion is answered, and answered by the token layer', () => {
  test('removes the entrance transform and keeps the settled appearance', async ({ page }) => {
    /* `docs/09 §12`: reduced motion removes non-essential animation and keeps
     * only opacity changes. The token layer implements that by rewriting
     * `--travel-*` to `0px` and the durations to `1ms` — *not* by
     * `animation: none`, which would drop `animation-fill-mode: both` along
     * with the animation and snap every entering element back to its
     * un-animated state.
     *
     * So the assertion is: the travel tokens go to zero, and a row that has
     * finished entering is fully opaque rather than stuck at the keyframe's
     * `from`. The second half is the one that catches the `animation: none`
     * mistake. */
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await stubApi(page);
    await page.goto('/library?library=lib-1');
    await page.waitForSelector('.egl-row', { timeout: 30_000 });

    const travel = await page.evaluate(() => {
      const style = getComputedStyle(document.documentElement);
      return {
        in: style.getPropertyValue('--travel-in').trim(),
        panel: style.getPropertyValue('--travel-panel').trim(),
        pop: style.getPropertyValue('--travel-pop').trim(),
        scale: style.getPropertyValue('--scale-pop').trim(),
      };
    });
    expect(travel).toEqual({ in: '0px', panel: '0px', pop: '0px', scale: '1' });

    const opacity = await page
      .locator('.egl-row')
      .first()
      .evaluate((node) => getComputedStyle(node).opacity);
    expect(opacity).toBe('1');
  });

  test('leaves the travel in place when motion is not reduced', async ({ page }) => {
    /* The positive control. An assertion that four tokens are `0px` passes for
     * free against a tree that never defined them — `docs/17 §10`. */
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await stubApi(page);
    await page.goto('/library?library=lib-1');
    await page.waitForSelector('.egl-row', { timeout: 30_000 });

    const travel = await page.evaluate(() =>
      getComputedStyle(document.documentElement).getPropertyValue('--travel-in').trim(),
    );
    expect(travel).toBe('4px');
  });
});
