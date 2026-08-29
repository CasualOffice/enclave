import { test, expect, type Page } from '@playwright/test';
import { stubApi } from './api-stub.ts';

/* `docs/09 §6` in a real browser.
 *
 * ## Why this file exists beside the jsdom suite
 *
 * **axe does not test keyboard traversal.** It reads a static accessibility
 * tree; it never presses a key. A green axe run over 94 pages says nothing
 * about whether the grid can be walked, and reporting it as though it did would
 * be the "green gate proving nothing" pattern this repository keeps finding.
 * These tests move focus and assert where it lands.
 *
 * And two of the properties that matter most cannot be observed in jsdom at
 * all, because jsdom has no layout:
 *
 *   1. **Focus surviving a scroll that unmounts the focused row.** It needs a
 *      real scroll container with a real viewport height, so that a real window
 *      of rows is mounted and the rest are not.
 *   2. **The focus ring being painted.** `docs/09 §15` requires a *visible*
 *      indicator at 3:1. `tests/unit/focus-ring.test.ts` proves the token
 *      clears 3:1; only a browser can say the rule reaches the element.
 *
 * The stub serves 400 rows into the library, which is four times the 100 that
 * `CLAUDE.md` makes the virtualization threshold — so the window is genuinely a
 * window and the "row scrolled out of the DOM" case is reachable rather than
 * hypothetical.
 */

const LIBRARY = '/library?library=lib-1';

/** Where focus is, as the grid's own `data-cursor` identity. */
async function cursor(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement)) return null;
    if (active === document.body) return null;
    return active.dataset['cursor'] ?? `«${active.className || active.tagName}»`;
  });
}

/**
 * The positive control every negative assertion in this file leans on.
 *
 * "Focus did not escape the grid" is true of a page that never loaded, a
 * selector that matched nothing and a grid nobody focused. This asserts the
 * opposite first — focus is *inside* the treegrid, on a row, at a named
 * position — so a run that quietly lost focus fails here by name.
 */
async function enterGrid(page: Page): Promise<void> {
  await page.waitForSelector('[role="treegrid"] .egl-row');
  await page.locator('[role="treegrid"]').focus();
  await expect
    .poll(() => cursor(page), { message: 'focus never reached a row of the grid' })
    /* The stub's listing is three folders then 397 files, so the first thing
     * a keyboard reaches is the Folders group header. Naming it rather than
     * accepting any row is deliberate: 'focus is somewhere in the grid' is the
     * assertion that would pass against a grid that put the ring on the wrong
     * thing. */
    .toBe('h:folders');
  const inside = await page.evaluate(() =>
    document.querySelector('[role="treegrid"]')!.contains(document.activeElement),
  );
  expect(inside, 'focus is not inside the treegrid').toBe(true);
}

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await stubApi(page);
});

test('the grid can be entered, walked and left', async ({ page }) => {
  await page.goto(LIBRARY);
  await enterGrid(page);

  await page.keyboard.press('ArrowDown');
  expect(await cursor(page)).toBe('r:0');
  await page.keyboard.press('ArrowDown');
  expect(await cursor(page)).toBe('r:1');
  await page.keyboard.press('ArrowUp');
  expect(await cursor(page)).toBe('r:0');

  /* `Tab` leaves in one press. That is the whole point of roving `tabindex`:
   * without it a keyboard user would `Tab` through four hundred rows to reach
   * whatever is after the list. */
  await page.keyboard.press('Tab');
  const stillInside = await page.evaluate(() =>
    document.querySelector('[role="treegrid"]')!.contains(document.activeElement),
  );
  expect(stillInside, 'Tab did not leave the grid in one press').toBe(false);

  /* And back in one press, onto the row the user left rather than the top of
   * the list. The grid is the last thing on this page, so `Tab` forward hands
   * focus to the browser's own chrome — asserting it landed on some element
   * would be asserting a property of Chromium. Coming *back* is the property
   * that belongs to this product, and it is the one that proves the container
   * took its tab stop back when the row gave it up. */
  await page.keyboard.press('Shift+Tab');
  await expect
    .poll(() => cursor(page), { message: 'Shift+Tab did not return to the grid' })
    .toBe('r:0');
});

test('focus survives the focused row being scrolled out of the DOM', async ({ page }) => {
  await page.goto(LIBRARY);
  await enterGrid(page);
  await page.keyboard.press('ArrowDown');
  expect(await cursor(page)).toBe('r:0');

  /* The row is really in the DOM to begin with — the control that makes the
   * assertion after the scroll mean something. */
  await expect(page.locator('[data-cursor="r:0"]')).toHaveCount(1);

  /* A mouse-wheel scroll far past the window. This is the case the whole cursor
   * model exists for: the element holding `tabindex="0"` is unmounted, and if
   * nothing catches it `document.activeElement` becomes `<body>` and the user's
   * next `Tab` restarts from the top of the page. */
  await page.locator('[role="treegrid"]').evaluate((node) => {
    node.scrollTop = 6000;
  });
  await expect(page.locator('[data-cursor="r:0"]')).toHaveCount(0);

  const lost = await page.evaluate(() => document.activeElement === document.body);
  expect(lost, 'focus fell to <body> when the focused row was unmounted').toBe(false);

  const stillInside = await page.evaluate(() =>
    document.querySelector('[role="treegrid"]')!.contains(document.activeElement),
  );
  expect(stillInside, 'focus left the grid when a scroll unmounted the focused row').toBe(true);

  /* And the keyboard still works from there, which is the property that
   * actually matters — "focus is technically somewhere" is not enough. The
   * cursor resumes where the user left it rather than at row 1. */
  /* Polled, not read once. The row is six thousand pixels away: the arrow
   * scrolls the window back, and the row it names does not exist as an element
   * until the window has caught up a frame later. Asserting synchronously here
   * would be asserting the frame rate. */
  await page.keyboard.press('ArrowDown');
  await expect
    .poll(() => cursor(page), { message: 'the cursor did not resume where it was left' })
    .toBe('r:1');
});

test('the focus ring is painted, and is the token rather than the wash', async ({ page }) => {
  await page.goto(LIBRARY);
  await enterGrid(page);
  await page.keyboard.press('ArrowDown');

  const ring = await page.locator('[data-cursor="r:0"]').evaluate((node) => {
    const style = getComputedStyle(node);
    return { color: style.outlineColor, width: style.outlineWidth, style: style.outlineStyle };
  });

  /* The three ways a focus ring is absent in practice: no outline style, zero
   * width, and `transparent`. All three are assertions here because each has
   * shipped somewhere. */
  expect(ring.style).not.toBe('none');
  expect(Number.parseFloat(ring.width)).toBeGreaterThanOrEqual(2);
  /* `--accent` in the light default theme, opaque. The *ratio* is measured in
   * `tests/unit/focus-ring.test.ts` against every theme and brand; what this
   * adds is that the rule reaches the element at all, which no unit test can
   * say. A translucent value here would mean the wash came back. */
  expect(ring.color).toBe('rgb(79, 70, 229)');
});

test('→ reaches the row-actions button, which hover-reveal never hides from the keyboard', async ({
  page,
}) => {
  await page.goto(LIBRARY);
  await enterGrid(page);
  await page.keyboard.press('ArrowDown');
  expect(await cursor(page)).toBe('r:0');

  /* The control — a button that is *not* revealed — read on a row that does not
   * have focus.
   *
   * It used to be read on **this** row, after `ArrowDown` had already focused
   * it, and that assertion was never true: `grouped-list.css` reveals on
   * `.egl-row:focus-within`, so a focused row's actions are visible by design.
   * It passed for months because the read landed mid-transition and caught a
   * value on its way to `1`. `ENC-921` made it a poll, on the theory that the
   * transient was the flake — and polling waits for the settled value, which is
   * `1`, so it started failing honestly instead. The poll did not break it; it
   * showed that the control had been asserting a transient all along.
   *
   * Row 1 is the real control. Its actions are unrevealed because nothing is
   * hovering or focused inside it, which is a *state* rather than a moment, so
   * there is no race to lose. It still fails against a button that is always
   * shown, which is the only thing this assertion was ever for. */
  const unfocused = page.locator('[data-cursor="r:1:6"]');
  await expect
    .poll(() => unfocused.evaluate((node) => getComputedStyle(node).opacity))
    .toBe('0');

  const actions = page.locator('[data-cursor="r:0:6"]');
  /* And **not** `display:none`, which is the decision this test exists to
   * protect: a display-hidden button is not in the focus order at all, so no
   * amount of arrow-key handling could reach it. */
  expect(await actions.evaluate((node) => getComputedStyle(node).display)).not.toBe('none');

  for (let press = 0; press < 7; press += 1) await page.keyboard.press('ArrowRight');
  expect(await cursor(page)).toBe('r:0:6');
  /* Polled: the reveal is an `opacity` transition, and reading the computed
   * value in the same tick as the keypress reads it mid-flight. Under
   * `prefers-reduced-motion` that window is one millisecond, which is exactly
   * long enough to be flaky and not long enough to be noticed. */
  await expect
    .poll(() => actions.evaluate((node) => getComputedStyle(node).opacity))
    .toBe('1');
  expect(await page.evaluate(() => document.activeElement?.tagName)).toBe('BUTTON');
});

test('the shortcut sheet opens on ?, traps Tab, and returns focus on Escape', async ({ page }) => {
  await page.goto(LIBRARY);
  await enterGrid(page);
  await page.keyboard.press('ArrowDown');
  const opener = await cursor(page);
  expect(opener).toBe('r:0'); // positive control: something specific had focus

  await page.keyboard.press('?');
  const dialog = page.locator('[data-surface="shortcuts"] [role="dialog"]');
  await expect(dialog).toBeVisible();
  expect(
    await page.evaluate(() =>
      document.querySelector('[role="dialog"]')!.contains(document.activeElement),
    ),
    'the dialog opened without taking focus',
  ).toBe(true);

  /* The trap. Ten presses is more stops than the dialog has, so if it leaked,
   * focus would be outside by now. */
  for (let press = 0; press < 10; press += 1) await page.keyboard.press('Tab');
  expect(
    await page.evaluate(() =>
      document.querySelector('[role="dialog"]')!.contains(document.activeElement),
    ),
    'Tab escaped the dialog',
  ).toBe(true);

  /* `docs/09 §6`: "focus returns to the triggering element when a dialog
   * closes". Without it the user is dropped on `<body>` and their next `Tab`
   * restarts from the top of the page. */
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect.poll(() => cursor(page)).toBe(opener);
});

test('/ focuses search from another route, and ⌘K opens the palette from a text field', async ({
  page,
}) => {
  await page.goto(LIBRARY);
  await page.waitForSelector('[role="treegrid"] .egl-row');

  await page.keyboard.press('/');
  await page.waitForURL(/\/search/);
  /* Not merely "we navigated": the caret has to land, or `/` is half a
   * shortcut and the annoying half. The search screen is a lazy chunk, so this
   * also proves the focus request survived the mount. */
  await expect
    .poll(() => page.evaluate(() => document.activeElement?.getAttribute('type')))
    .toBe('search');

  /* `⌘K` is the one binding that must work *from inside a field*, because that
   * is where a user reaches for it. Typing first, so the field genuinely holds
   * the caret and a guard that swallowed everything would fail here. */
  await page.keyboard.type('agreement');
  await page.keyboard.press('ControlOrMeta+k');
  await expect(page.locator('[data-surface="palette"] [role="dialog"]')).toBeVisible();
  await expect(page.locator('[data-surface="palette"] [role="combobox"]')).toBeFocused();
});

test('a letter binding does not fire while it is being typed', async ({ page }) => {
  await page.goto('/search?q=');
  await page.waitForSelector('input[type="search"]');
  await page.locator('input[type="search"]').focus();

  /* `i` toggles the details panel and `?` opens the shortcut sheet. Both are
   * characters in an ordinary query. If the guard were missing, the sheet would
   * be on screen and the query would be missing its punctuation — which is a
   * defect a user reaches within a minute of opening the product. */
  await page.keyboard.type('is it a policy?');
  await expect(page.locator('[data-surface="shortcuts"]')).toHaveCount(0);
  await expect(page.locator('input[type="search"]')).toHaveValue('is it a policy?');
});
