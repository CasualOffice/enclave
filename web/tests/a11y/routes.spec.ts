import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/* `docs/09 §15` and `docs/12 §5`: axe passes on every primary route.
 *
 * "Every primary route" is a list, and the list has to live somewhere a gate
 * can read — otherwise the run passes by checking one page and calling it the
 * product. `SURFACES` is that list; `test:a11y` fails if it is empty, and it
 * grows as M5 step 2 adds routes.
 */

interface Surface {
  readonly name: string;
  readonly url: string;
  /** What must be on screen before axe looks, so a skeleton is never mistaken for the route. */
  readonly ready: string;
}

const SURFACES: readonly Surface[] = [
  {
    name: 'library list, grouped, 5k rows',
    url: '/?rows=5000',
    ready: '[role="treegrid"] [role="row"][aria-level], [role="treegrid"] .egl-row',
  },
  {
    name: 'library list, compact density',
    url: '/?rows=2000&density=compact',
    ready: '.egl-row',
  },
  {
    name: 'library list, a group collapsed',
    url: '/?rows=2000&collapse=g0',
    ready: '.egl-group[aria-expanded="false"]',
  },
  { name: 'library list, loading', url: '/?surface=loading', ready: '[role="status"]' },
  { name: 'library list, empty', url: '/?surface=empty', ready: '[data-state="empty"]' },
  {
    name: 'library list, filtered empty',
    url: '/?surface=filtered-empty&rows=4213',
    ready: '[data-state="filtered-empty"]',
  },
  { name: 'library list, fetch error', url: '/?surface=error', ready: '[data-state="error"]' },
];

test('the surface list is not empty', () => {
  /* The `ENC-543`/`ENC-677` assertion, in test form: an accessibility gate that
   * iterates an empty list passes without looking at anything. */
  expect(SURFACES.length).toBeGreaterThan(0);
});

for (const surface of SURFACES) {
  for (const theme of ['light', 'dark'] as const) {
    test(`axe: ${surface.name} (${theme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto(surface.url);
      await page.waitForSelector(surface.ready, { timeout: 30_000 });

      const results = await new AxeBuilder({ page })
        // WCAG 2.2 AA is the stated target (`docs/09 §15`), so the tag set is
        // the target rather than axe's defaults.
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();

      /* The failure summary is kept because a bare rule id sends the next
       * reader to the axe docs; the summary names the element, the two colours
       * and the ratio, which is the whole of the fix. */
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
