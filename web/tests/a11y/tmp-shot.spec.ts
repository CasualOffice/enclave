import { test } from '@playwright/test';

/* TEMPORARY — deleted after use. Screenshots the search screen so its design can
 * be looked at rather than reasoned about. */

const SHOTS = [
  ['results-light', '/search?q=terminate', 'light'],
  ['results-dark', '/search?q=terminate', 'dark'],
  ['degraded-light', '/search?q=terminate&retrieval=degraded', 'light'],
  ['hybrid-light', '/search?q=terminate&retrieval=hybrid', 'light'],
  ['empty-new-light', '/search', 'light'],
  ['filtered-empty-light', '/search?q=terminate&type=xls&workspace=Legal', 'light'],
  ['loading-light', '/search?q=terminate&surface=loading', 'light'],
  ['error-light', '/search?q=terminate&surface=error', 'light'],
] as const;

for (const [name, url, theme] of SHOTS) {
  test(`shot ${name}`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.goto(url);
    await page.waitForTimeout(500);
    await page.screenshot({ path: `bench-results/shot-${name}.png` });
  });
}
