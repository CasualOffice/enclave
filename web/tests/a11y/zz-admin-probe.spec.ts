import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/* TEMPORARY. `tests/a11y/routes.spec.ts` is not this session's file, so the
 * admin routes are reported for the owner to add rather than added here. This
 * probe exists only to confirm the surfaces pass before reporting them, and is
 * deleted in the same session. */

const SURFACES = [
  { name: 'admin dlp, policy builder', url: '/admin?surface=fixture', ready: '.adm-builder' },
  {
    name: 'admin dlp, auditor read-only',
    url: '/admin?surface=fixture&as=auditor',
    ready: '.adm-builder',
  },
  { name: 'admin dlp, loading', url: '/admin?surface=loading', ready: '[role="status"]' },
  { name: 'admin dlp, empty', url: '/admin?surface=empty', ready: '[data-state="empty"]' },
  {
    name: 'admin dlp, filtered empty',
    url: '/admin?surface=fixture&q=zzzz',
    ready: '[data-state="filtered-empty"]',
  },
  { name: 'admin dlp, fetch error', url: '/admin?surface=error', ready: '[data-state="error"]' },
  { name: 'admin dlp, denied', url: '/admin?surface=denied', ready: '[data-state="denied"]' },
];

for (const surface of SURFACES) {
  for (const theme of ['light', 'dark'] as const) {
    test(`axe: ${surface.name} (${theme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto(surface.url);
      await page.waitForSelector(surface.ready, { timeout: 30_000 });

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();

      const violations = results.violations.map((violation) => ({
        id: violation.id,
        impact: violation.impact,
        help: violation.help,
        nodes: violation.nodes.slice(0, 4).map((node) => ({
          target: node.target.join(' '),
          summary: node.failureSummary?.replace(/\s+/g, ' ').slice(0, 300) ?? '',
        })),
      }));

      expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
    });
  }
}
