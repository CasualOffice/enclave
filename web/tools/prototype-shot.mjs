/* Screenshot the prototype's library screen, and measure its frame.
 *
 * The prototype renders in a browser — `support.js` is vendored beside it so it
 * does — and the only honest way to compare it with the app is to open both at
 * the same viewport and look. Reading each other's markup is how the divergence
 * happened.
 *
 *   node tools/prototype-shot.mjs <out-dir>
 */

import { chromium } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const OUT = process.argv[2] ?? '/tmp/enclave-shots';
const FILE = pathToFileURL(
  new URL('../design-system/enclave-client-prototype.html', import.meta.url).pathname,
).href;

mkdirSync(OUT, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: 1440, height: 900 },
  deviceScaleFactor: 2,
});

await page.goto(FILE, { waitUntil: 'networkidle' });
await page.waitForTimeout(1200);

/* The prototype persists its own screen, theme and brand, so it does not open
 * where a comparison needs it. Drive it: back to the workspace, into Files,
 * onto the light theme, and open a row so the peek panel is on screen — that is
 * the frame the app has to match. Each step is best-effort, because the
 * prototype's starting point depends on what it last stored. */
async function tap(name) {
  const target = page.getByText(name, { exact: true }).first();
  if (await target.isVisible().catch(() => false)) {
    await target.click().catch(() => undefined);
    await page.waitForTimeout(600);
  }
}

await tap('Back to workspace');
await tap('Light');
await tap('Files');
await page.waitForTimeout(600);

/* Open the peek panel by clicking the first file row. */
const firstRow = page.locator('[data-screen-label="Library"] >> text=/\\.pdf$/').first();
if (await firstRow.isVisible().catch(() => false)) {
  await firstRow.click().catch(() => undefined);
  await page.waitForTimeout(900);
}

await page.screenshot({ path: join(OUT, '00-prototype-library.png') });

/* The same six numbers the app is measured on, read from the prototype's own
 * rendered DOM rather than from its stylesheet. */
const geometry = await page.evaluate(() => {
  const box = (node) => {
    if (node === null || node === undefined) return null;
    const rect = node.getBoundingClientRect();
    const style = getComputedStyle(node);
    return {
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      radius: style.borderTopLeftRadius,
      margin: `${style.marginTop} ${style.marginRight} ${style.marginBottom} ${style.marginLeft}`,
      border: style.borderWidth,
      shadow: style.boxShadow.slice(0, 80),
    };
  };

  const asides = [...document.querySelectorAll('aside')];
  const byLabel = (label) =>
    document.querySelector(`[aria-label="${label}"]`) ??
    asides.find((node) => node.getAttribute('aria-label') === label) ??
    null;

  /* The prototype has no class names to speak of — it is inline styles — so the
   * elements are found by shape: the widest grid whose first track is 232px is
   * the shell, and the details panel names itself. */
  const grids = [...document.querySelectorAll('div')].filter((node) =>
    getComputedStyle(node).gridTemplateColumns.startsWith('232'),
  );
  const shell = grids[0] ?? null;

  return {
    shell: box(shell),
    sidebar: box(shell?.children?.[0] ?? null),
    sheet: box(shell?.children?.[1] ?? null),
    peek: box(byLabel('Details')),
  };
});

console.log(JSON.stringify(geometry, null, 2));
await browser.close();
