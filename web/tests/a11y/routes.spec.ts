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
    url: '/library?rows=5000',
    ready: '[role="treegrid"] [role="row"][aria-level], [role="treegrid"] .egl-row',
  },
  {
    name: 'library list, compact density',
    url: '/library?rows=2000&density=compact',
    ready: '.egl-row',
  },
  {
    name: 'library list, a group collapsed',
    url: '/library?rows=2000&collapse=g0',
    ready: '.egl-group[aria-expanded="false"]',
  },
  { name: 'library list, loading', url: '/library?surface=loading', ready: '[role="status"]' },
  { name: 'library list, empty', url: '/library?surface=empty', ready: '[data-state="empty"]' },
  {
    name: 'library list, filtered empty',
    url: '/library?surface=filtered-empty&rows=4213',
    ready: '[data-state="filtered-empty"]',
  },
  { name: 'library list, fetch error', url: '/library?surface=error', ready: '[data-state="error"]' },

  /* Ask, all four of its states. It is the D33 surface — every control on it is
   * *unbuilt* rather than denied — so it is also where the unbuilt treatment is
   * checked against a real renderer rather than only in jsdom. */
  { name: 'ask, unbuilt', url: '/ask', ready: '[data-screen="ask"][data-state="unbuilt"]' },
  { name: 'ask, loading', url: '/ask?surface=loading', ready: '[data-screen="ask"] [role="status"]' },
  {
    name: 'ask, scope empty',
    url: '/ask?surface=scope-empty',
    ready: '[data-screen="ask"] [data-state="filtered-empty"]',
  },
  {
    name: 'ask, fetch error',
    url: '/ask?surface=error',
    ready: '[data-screen="ask"] [data-state="error"]',
  },

  /* Sign-in, which is the first paint anyone ever sees and the only route that
   * renders outside the shell. Its refused state is listed separately from its
   * failed state on purpose: they are different things and `docs/09 §11` only
   * gives the second one a retry. */
  { name: 'sign in, resting form', url: '/signin', ready: '[data-signin-state="idle"]' },
  { name: 'sign in, loading', url: '/signin?state=loading', ready: '[data-signin-state="submitting"]' },
  { name: 'sign in, refused', url: '/signin?state=refused', ready: '[data-signin-state="refused"]' },
  { name: 'sign in, fetch error', url: '/signin?state=failed', ready: '[data-signin-state="failed"]' },
  { name: 'sign in, success', url: '/signin?state=success', ready: '[data-signin-state="success"]' },

  /* Home. Its state parameter is `home=` rather than `surface=` because the
   * library screen already answers `surface=` on the same query string. */
  { name: 'home, populated', url: '/', ready: '.home-page' },
  { name: 'home, loading', url: '/?home=loading', ready: '[role="status"]' },
  { name: 'home, empty', url: '/?home=empty', ready: '[data-state="empty"]' },
  { name: 'home, scoped empty', url: '/?home=scoped-empty', ready: '[data-state="scoped-empty"]' },
  { name: 'home, fetch error', url: '/?home=error', ready: '[data-state="error"]' },

  /* Search. Both retrieval notices are listed: the *lexical* one is a product
   * state (this deployment has no dense retrieval — `ENC-661`, D37) and the
   * *degraded* one is an incident. They say different things and only one of
   * them carries a `Later` chip, so both need a run. */
  { name: 'search, results (lexical, the M5 default)', url: '/search?q=agreement', ready: '.esr-hit' },
  {
    name: 'search, results (hybrid, no notice)',
    url: '/search?q=agreement&retrieval=hybrid',
    ready: '.esr-hit',
  },
  {
    name: 'search, degraded fallback',
    url: '/search?q=agreement&retrieval=degraded',
    ready: '[data-notice="degraded"]',
  },
  { name: 'search, empty (new)', url: '/search', ready: '[data-state="empty"]' },
  {
    name: 'search, empty (filtered)',
    url: '/search?q=agreement&type=xls&workspace=Legal&modified=7d',
    ready: '[data-state="filtered-empty"]',
  },
  { name: 'search, loading', url: '/search?q=agreement&surface=loading', ready: '.esr-loading' },
  {
    name: 'search, fetch error',
    url: '/search?q=agreement&surface=error',
    ready: '[data-state="error"]',
  },

  /* Admin — DLP policy. It carries a *fifth* state the other screens do not:
   * `denied`, which is a policy refusal rather than a failure and shares no
   * class with the error state (`docs/17 §10` F2/F3). Both are listed, and the
   * auditor view is listed separately because it is the same screen with every
   * mutating control removed (`docs/09 §21`) rather than a poorer one. */
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

test('the surface list is not empty', () => {
  /* The `ENC-543`/`ENC-677` assertion, in test form: an accessibility gate that
   * iterates an empty list passes without looking at anything. */
  expect(SURFACES.length).toBeGreaterThan(0);
});

for (const surface of SURFACES) {
  for (const theme of ['light', 'dark'] as const) {
    test(`axe: ${surface.name} (${theme})`, async ({ page }) => {
      /* Reduced motion, always.
       *
       * axe computes contrast from the *composited* pixel, so a run that lands
       * mid-entrance reads a half-faded colour and fails — measured at 2.12:1
       * on a line whose settled value is 6.83:1. That is a false negative, and
       * a suite that fails at random is a suite that gets quarantined.
       *
       * It is also the honest configuration rather than a workaround: every
       * animation in this tree is required to degrade under
       * `prefers-reduced-motion` (`docs/09 §12`), so this asserts the settled
       * appearance *and* the reduced-motion path in one run. A screen whose
       * contrast is only acceptable once an animation finishes is a screen that
       * fails for a user who has turned animation off. */
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
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
