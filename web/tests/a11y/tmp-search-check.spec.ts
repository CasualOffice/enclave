import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/* TEMPORARY. `tests/a11y/routes.spec.ts` belongs to another session; this file
 * exists only so the search screen can be axe-checked before it is handed over,
 * and is deleted immediately afterwards. The surfaces below are the ones to add
 * to `routes.spec.ts`. */

const SURFACES = [
  { name: 'search, results (lexical, the M5 default)', url: '/search?q=agreement', ready: '.esr-hit' },
  { name: 'search, results (hybrid, no notice)', url: '/search?q=agreement&retrieval=hybrid', ready: '.esr-hit' },
  { name: 'search, degraded fallback', url: '/search?q=agreement&retrieval=degraded', ready: '[data-notice="degraded"]' },
  { name: 'search, empty (new)', url: '/search', ready: '[data-state="empty"]' },
  { name: 'search, empty (filtered)', url: '/search?q=agreement&type=xls&workspace=Legal&modified=7d', ready: '[data-state="filtered-empty"]' },
  { name: 'search, loading', url: '/search?q=agreement&surface=loading', ready: '.esr-loading' },
  { name: 'search, fetch error', url: '/search?q=agreement&surface=error', ready: '[data-state="error"]' },
  { name: 'search, a filter menu open', url: '/search?q=agreement', ready: '.esr-chip-open' },
] as const;

for (const surface of SURFACES) {
  for (const theme of ['light', 'dark'] as const) {
    test(`axe: ${surface.name} (${theme})`, async ({ page }) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(error.message));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(message.text());
      });

      await page.emulateMedia({ colorScheme: theme });
      await page.goto(surface.url);
      await page.waitForSelector(surface.ready, { timeout: 30_000 });

      if (surface.name.includes('filter menu')) {
        await page.locator('.esr-chip-open').first().click();
        await page.waitForSelector('[role="menu"]');
      }

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();

      const violations = results.violations.map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        help: violation.help,
        nodes: violation.nodes.slice(0, 60).map((node) => ({
          target: node.target.join(' '),
          summary: node.failureSummary?.replace(/\s+/g, ' ').slice(0, 300) ?? '',
        })),
      }));

      expect(errors, errors.join('\n')).toEqual([]);
      expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
    });
  }
}
