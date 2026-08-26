/* Screenshot the running app and the prototype at the same viewport.
 *
 * The prototype renders in a browser — `support.js` is vendored beside it
 * precisely so it does — and the only way to know whether the app matches it is
 * to look at both, at one size, side by side. Reading each other's markup is how
 * the divergence happened in the first place.
 *
 *   node tools/compare-shot.mjs <out-dir>
 *
 * Signs in with the dev credential, so the shots are of the real product
 * reading real data rather than of the sign-in screen.
 */

import { chromium } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const OUT = process.argv[2] ?? '/tmp/enclave-shots';
const APP = process.env.ENCLAVE_APP_URL ?? 'http://tenant-alpha.localhost:5174';
const PROTOTYPE = process.env.ENCLAVE_PROTOTYPE_URL ?? null;
const EMAIL = process.env.ENCLAVE_DEV_EMAIL ?? 'admin@tenant-alpha.example';
/* Read from the environment, never written here: `CLAUDE.md` rule 11 forbids a
 * credential literal in any tracked file, and a development password is still a
 * credential. */
const PASSWORD = process.env.ENCLAVE_DEV_PASSWORD;
const LIBRARY = process.env.ENCLAVE_DEV_LIBRARY ?? '';

const VIEWPORT = { width: 1440, height: 900 };

mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 2 });
const page = await context.newPage();

const problems = [];
page.on('console', (message) => {
  if (message.type() === 'error') problems.push(message.text());
});
page.on('pageerror', (error) => problems.push(String(error)));

async function shot(name) {
  await page.waitForTimeout(700);
  const path = join(OUT, `${name}.png`);
  await page.screenshot({ path });
  console.log(`  ${name} -> ${path}`);
}

console.log(`app: ${APP}`);
await page.goto(APP, { waitUntil: 'networkidle' });
await shot('01-signin');

if (PASSWORD === undefined) {
  console.error('ENCLAVE_DEV_PASSWORD is not set; stopping after the sign-in shot.');
} else {
  await page.fill('input[type="email"]', EMAIL);
  await page.fill('input[type="password"]', PASSWORD);
  await page.keyboard.press('Enter');
  await page.waitForTimeout(2500);
  await shot('02-home');

  /* What `/me` actually returned, read out of the page rather than asserted
   * from the fixture — this is the evidence that a real response reached a
   * real component. */
  const me = await page.evaluate(async () => {
    const response = await fetch('/api/v1/me', { credentials: 'same-origin' });
    return { status: response.status, body: await response.text() };
  });
  console.log(`  GET /me -> ${me.status} ${me.body}`);

  await page.goto(`${APP}/search?q=board`, { waitUntil: 'networkidle' });
  await shot('03-search');

  if (LIBRARY.length > 0) {
    await page.goto(`${APP}/library?library=${LIBRARY}`, { waitUntil: 'networkidle' });
    await shot('04-library');

    await page.goto(`${APP}/library?library=${LIBRARY}&peek=40000000-0000-4000-8000-000000000001`, {
      waitUntil: 'networkidle',
    });
    await shot('05-library-peek');

    /* The three numbers the reviewer said were absent, measured from the live
     * DOM rather than claimed from the stylesheet. */
    const geometry = await page.evaluate(() => {
      const read = (selector) => {
        const node = document.querySelector(selector);
        if (node === null) return null;
        const box = node.getBoundingClientRect();
        const style = getComputedStyle(node);
        return {
          width: Math.round(box.width),
          height: Math.round(box.height),
          radius: style.borderTopLeftRadius,
          margin: `${style.marginTop} ${style.marginRight} ${style.marginBottom} ${style.marginLeft}`,
          border: style.borderWidth,
          shadow: style.boxShadow,
        };
      };
      return {
        sidebar: read('.shell-nav'),
        sheet: read('.shell-sheet'),
        locationBar: read('.library-location'),
        viewBar: read('.library-viewbar'),
        peek: read('.library-peek'),
        row: read('.egl-row'),
      };
    });
    console.log('  geometry:', JSON.stringify(geometry, null, 2));
  }

  await page.goto(`${APP}/admin`, { waitUntil: 'networkidle' });
  await shot('06-admin');
}

if (PROTOTYPE !== null) {
  console.log(`prototype: ${PROTOTYPE}`);
  await page.goto(PROTOTYPE, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  await shot('00-prototype');
}

if (problems.length > 0) {
  console.log('\nconsole errors:');
  for (const problem of problems.slice(0, 20)) console.log(`  ${problem}`);
}

await browser.close();
