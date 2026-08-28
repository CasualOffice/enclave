import { test, expect, type Page } from '@playwright/test';
import { stubApi } from './api-stub.ts';

/* `I`, `⌘\` and `Esc` — the three bindings the library screen owns.
 *
 * They live with the screen rather than in `app/` because all three act on the
 * details panel, and the panel's state is a query parameter this screen holds.
 * A global handler could only reach it by inventing a sentinel to write into a
 * URL `docs/09 §3` promises is a link a user can send to a colleague.
 *
 * Kept in their own file so the grid suite next door stays about the grid.
 */

const LIBRARY = '/library?library=lib-1';

async function enterGrid(page: Page): Promise<void> {
  await page.waitForSelector('[role="treegrid"] .egl-row');
  await page.locator('[role="treegrid"]').focus();
  await expect
    .poll(
      () =>
        page.evaluate(() =>
          document.activeElement instanceof HTMLElement
            ? (document.activeElement.dataset['cursor'] ?? null)
            : null,
        ),
      { message: 'focus never reached a row of the grid' },
    )
    .toBe('h:folders');
}

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await stubApi(page);
});

test('I toggles the details panel and ⌘\\ pins it open', async ({ page }) => {
  await page.goto(LIBRARY);
  await page.waitForSelector('[role="treegrid"] .egl-row');

  /* The panel's own landmark is the assertion. Checking only the URL would
   * pass against a query parameter nothing reads. */
  await page.keyboard.press('i');
  await expect(page.locator('.library-peek')).toBeVisible();

  await page.keyboard.press('i');
  await expect(page.locator('.library-peek')).toHaveCount(0);

  /* Pinning is a real distinction rather than a flag with no consequence: it
   * is what makes `Esc` clear the selection instead of closing the panel,
   * which is how §6's two-step order becomes reachable at all. */
  await page.keyboard.press('ControlOrMeta+\\');
  await expect(page.locator('.library-peek')).toBeVisible();
  await expect.poll(() => page.url()).toContain('pin=1');

  await page.keyboard.press('Escape');
  await expect(
    page.locator('.library-peek'),
    'Escape closed a pinned panel — pinning it meant nothing',
  ).toHaveCount(1);

  await page.keyboard.press('ControlOrMeta+\\');
  await expect.poll(() => page.url()).not.toContain('pin=1');
  await page.keyboard.press('Escape');
  await expect(page.locator('.library-peek')).toHaveCount(0);
});

test('Esc closes the panel first and clears the selection second', async ({ page }) => {
  await page.goto(LIBRARY);
  await enterGrid(page);

  /* Two rows selected and the panel open — the state §6's ordering exists for. */
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Shift+ArrowDown');
  await expect(page.locator('.egl-row[aria-selected="true"]')).toHaveCount(2);
  await page.keyboard.press('Space');
  await expect(page.locator('.library-peek')).toBeVisible();

  /* First press takes the panel and **not** the selection. Taking the
   * selection out from under a panel that stayed is the wrong half: a user who
   * wanted the panel gone would have to re-select two rows to get back to
   * where they were. */
  await page.keyboard.press('Escape');
  await expect(page.locator('.library-peek')).toHaveCount(0);
  await expect(
    page.locator('.egl-row[aria-selected="true"]'),
    'Escape cleared the selection while the panel was still open',
  ).toHaveCount(2);

  await page.keyboard.press('Escape');
  await expect(page.locator('.egl-row[aria-selected="true"]')).toHaveCount(0);
});
