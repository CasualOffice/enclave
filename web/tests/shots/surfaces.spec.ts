import { test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { stubApi, type ApiPlan } from '../a11y/api-stub.ts';

/* Screenshots of the real app, at the prototype's viewport, one file per surface.
 *
 * `web/design-system/enclave-client-prototype.html` renders in a browser, and
 * `tools/prototype-shot.mjs` captures it at 1440×900. This is the other half of
 * that comparison: the app, at the same size, reading the same stubbed wire
 * shapes the accessibility gate uses. Looking at both is the only honest way to
 * know whether the code matches the reference — reading each other's markup is
 * how the divergence happened.
 *
 * It is a separate Playwright project (`--project=shots`) and not a gate: it
 * asserts nothing. It exists so a reviewer can see a change rather than be told
 * about one.
 *
 *   ENCLAVE_SHOT_DIR=/tmp/before npx playwright test --project=shots
 */

const OUT = process.env['ENCLAVE_SHOT_DIR'] ?? '/tmp/enclave-app-shots';

interface Shot {
  readonly name: string;
  readonly url: string;
  readonly ready: string;
  readonly api?: ApiPlan;
  /** Capture the full scrollable page rather than the 900px viewport. */
  readonly full?: boolean;
}

const SHOTS: readonly Shot[] = [
  { name: '01-library', url: '/library?library=lib-1', ready: '[role="treegrid"] .egl-row' },
  {
    name: '02-library-peek',
    url: '/library?library=lib-1&peek=file-3',
    ready: '.library-peek-caps',
  },
  { name: '03-library-loading', url: '/library?library=lib-1', ready: '[role="status"]', api: { hang: true } },
  { name: '04-library-empty', url: '/library?library=lib-1', ready: '[data-state="empty"]', api: { items: 0 } },
  {
    name: '05-library-error',
    url: '/library?library=lib-1',
    ready: '.surface-state[data-tone="error"]',
    api: { status: 500 },
  },
  {
    name: '06-library-denied',
    url: '/library?library=lib-1',
    ready: '.surface-state[data-tone="neutral"]',
    api: { status: 403 },
  },
  { name: '07-home', url: '/', ready: '.home-page' },
  { name: '08-home-loading', url: '/?home=loading', ready: '[role="status"]' },
  { name: '09-home-empty', url: '/?home=empty', ready: '[data-state="empty"]' },
  { name: '10-search', url: '/search?q=agreement', ready: '.esr-hit' },
  { name: '11-search-empty', url: '/search', ready: '[data-state="empty"]' },
  {
    name: '12-search-no-results',
    url: '/search?q=agreement',
    ready: '[data-state="filtered-empty"]',
    api: { results: 0 },
  },
  { name: '13-ask-unbuilt', url: '/ask', ready: '[data-screen="ask"][data-state="unbuilt"]' },
  { name: '14-admin-dlp', url: '/admin?surface=fixture', ready: '.adm-builder', full: true },
  { name: '15-admin-denied', url: '/admin?surface=denied', ready: '[data-state="denied"]' },
  { name: '16-signin', url: '/signin', ready: '[data-signin-state="idle"]', api: { signedIn: false } },
  { name: '17-picker', url: '/library', ready: '.lib-picker-lib' },
];

for (const theme of ['light', 'dark'] as const) {
  for (const shot of SHOTS) {
    test(`shot: ${shot.name} (${theme})`, async ({ page }) => {
      const dir = join(OUT, theme);
      mkdirSync(dir, { recursive: true });
      await page.emulateMedia({ colorScheme: theme });
      await stubApi(page, shot.api);
      await page.goto(shot.url);
      await page.waitForSelector(shot.ready, { timeout: 30_000 });
      /* Long enough for the enter animations and their row stagger to settle;
       * a shot taken mid-entrance describes the animation, not the design. */
      await page.waitForTimeout(900);
      await page.screenshot({
        path: join(dir, `${shot.name}.png`),
        fullPage: shot.full ?? false,
      });
    });
  }
}
