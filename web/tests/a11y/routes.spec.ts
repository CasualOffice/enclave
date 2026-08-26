import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { stubApi, type ApiPlan } from './api-stub.ts';

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
  /**
   * What the stubbed API answers for this surface.
   *
   * Every screen reads the real API now and `npm run preview` has no API behind
   * it, so without a stub every route would render the sign-in screen and this
   * gate would check one page fifty times while reporting fifty passes — the
   * `ENC-677` failure shape, which is why the emptiness assertion below exists.
   * `api-stub.ts` explains why stubbing here is not the fixture problem this
   * milestone was fixing.
   */
  readonly api?: ApiPlan;
}

const SURFACES: readonly Surface[] = [
  /* The library list. `?library=` carries the id because there is no
   * `GET /api/v1/libraries` to enumerate them — the picker is unbuilt, and its
   * unbuilt state is a surface in its own right below. */
  {
    name: 'library list, grouped, 400 rows',
    url: '/library?library=lib-1',
    ready: '[role="treegrid"] .egl-row',
  },
  {
    name: 'library list, compact density',
    url: '/library?library=lib-1&density=compact',
    ready: '.egl-row',
  },
  /* The peek panel: 372px, its own four states, and the surface where the
   * capability contract is actually rendered. The stub refuses download, print,
   * export and share-external on every third row, so the *refused* treatment is
   * on screen for axe to measure rather than only the permitted one. */
  {
    name: 'library list, peek open',
    url: '/library?library=lib-1&peek=file-3',
    ready: '.library-peek-caps',
  },
  {
    name: 'library list, loading',
    url: '/library?library=lib-1',
    ready: '[role="status"]',
    api: { hang: true },
  },
  {
    name: 'library list, empty',
    url: '/library?library=lib-1',
    ready: '[data-state="empty"]',
    api: { items: 0 },
  },
  {
    name: 'library list, fetch error',
    url: '/library?library=lib-1',
    ready: '.surface-state[data-tone="error"]',
    api: { status: 500 },
  },
  /* The denial treatment, which shares no class with the error state above
   * (`docs/17 §10` F2/F3) and carries no retry. Both are listed so the contrast
   * of each is measured, not just whichever one a run happened to reach. */
  {
    name: 'library list, policy denial',
    url: '/library?library=lib-1',
    ready: '.surface-state[data-tone="neutral"]',
    api: { status: 403 },
  },
  /* The library picker, which cannot exist until an endpoint enumerates
   * libraries. Unbuilt, and never the denial treatment. */
  {
    name: 'library, no picker (unbuilt)',
    url: '/library',
    ready: '.surface-state[data-tone="unbuilt"]',
  },

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
  { name: 'sign in, resting form', url: '/signin', ready: '[data-signin-state="idle"]', api: { signedIn: false } },
  { name: 'sign in, loading', url: '/signin?state=loading', ready: '[data-signin-state="submitting"]', api: { signedIn: false } },
  { name: 'sign in, refused', url: '/signin?state=refused', ready: '[data-signin-state="refused"]', api: { signedIn: false } },
  { name: 'sign in, fetch error', url: '/signin?state=failed', ready: '[data-signin-state="failed"]', api: { signedIn: false } },
  { name: 'sign in, success', url: '/signin?state=success', ready: '[data-signin-state="success"]', api: { signedIn: false } },

  /* Home. Its state parameter is `home=` rather than `surface=` because the
   * library screen already answers `surface=` on the same query string. */
  { name: 'home, populated', url: '/', ready: '.home-page' },
  { name: 'home, loading', url: '/?home=loading', ready: '[role="status"]' },
  { name: 'home, empty', url: '/?home=empty', ready: '[data-state="empty"]' },
  { name: 'home, scoped empty', url: '/?home=scoped-empty', ready: '[data-state="scoped-empty"]' },
  { name: 'home, fetch error', url: '/?home=error', ready: '[data-state="error"]' },
  {
    name: 'home, tasks refused',
    url: '/',
    ready: '.surface-state[data-tone="neutral"]',
    api: { status: 403 },
  },

  /* Search. Both retrieval notices are listed: the *lexical* one is a product
   * state (this deployment has no dense retrieval) and the *degraded* one is an
   * incident. They say different things and only one carries a `Later` chip, so
   * both need a run. `degraded` now comes from the server's own diagnostics
   * rather than from a URL knob, so the stub sets it. */
  { name: 'search, results (lexical)', url: '/search?q=agreement', ready: '.esr-hit' },
  {
    name: 'search, degraded fallback',
    url: '/search?q=agreement',
    ready: '[data-notice="degraded"]',
    api: { degraded: true },
  },
  { name: 'search, empty (new)', url: '/search', ready: '[data-state="empty"]' },
  {
    name: 'search, no results',
    url: '/search?q=agreement',
    ready: '[data-state="filtered-empty"]',
    api: { results: 0 },
  },
  {
    name: 'search, loading',
    url: '/search?q=agreement',
    ready: '.esr-loading',
    api: { hang: true },
  },
  {
    name: 'search, fetch error',
    url: '/search?q=agreement',
    ready: '.surface-state[data-tone="error"]',
    api: { status: 500 },
  },
  {
    name: 'search, policy denial',
    url: '/search?q=agreement',
    ready: '.surface-state[data-tone="neutral"]',
    api: { status: 403 },
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
      /* Before the first navigation, so the app's own boot requests — the
       * refresh exchange and `/me` — are answered too. Installed after
       * navigation, the shell would already have concluded nobody is signed
       * in. */
      await stubApi(page, surface.api);
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
