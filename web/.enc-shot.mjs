import { chromium } from '@playwright/test';
import fs from 'node:fs';

const PROTO = 'http://127.0.0.1:5198/design-system/enclave-client-prototype.html';
const APP = 'http://localhost:5199';

const mode = process.argv[2];
const arg = process.argv[3];
const out = process.argv[4];

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

if (mode === 'proto' || mode === 'proto-measure') {
  await page.route('**/enclave-client-prototype.html', async (route) => {
    const res = await route.fetch();
    let body = await res.text();
    body = body
      .replace('&quot;default&quot;:&quot;dark&quot;', '&quot;default&quot;:&quot;light&quot;')
      .replace('&quot;default&quot;:&quot;northwind&quot;', '&quot;default&quot;:&quot;harbor&quot;')
      .replace('&quot;default&quot;:&quot;admin&quot;', `&quot;default&quot;:&quot;${arg}&quot;`);
    await route.fulfill({ response: res, body });
  });
  await page.goto(PROTO, { waitUntil: 'networkidle' });
} else {
  await page.goto(`${APP}${arg}`, { waitUntil: 'networkidle' });
}

await page.waitForTimeout(1200);

if (mode.endsWith('measure')) {
  const data = await page.evaluate(() => {
    const seen = [];
    const walk = (el, depth) => {
      if (depth > 14) return;
      const r = el.getBoundingClientRect();
      if (r.width < 1 || r.height < 1) return;
      const cs = getComputedStyle(el);
      seen.push({
        tag: el.tagName.toLowerCase(),
        cls: (el.className && typeof el.className === 'string' ? el.className : '').slice(0, 40),
        txt: (el.textContent || '').trim().slice(0, 34),
        w: Math.round(r.width * 10) / 10,
        h: Math.round(r.height * 10) / 10,
        x: Math.round(r.x * 10) / 10,
        y: Math.round(r.y * 10) / 10,
        fs: cs.fontSize,
        pad: cs.padding,
        radius: cs.borderRadius,
        shadow: cs.boxShadow.slice(0, 60),
        bg: cs.backgroundColor,
        d: depth,
      });
      for (const c of el.children) walk(c, depth + 1);
    };
    walk(document.body, 0);
    return seen;
  });
  fs.writeFileSync(out, JSON.stringify(data, null, 1));
} else {
  await page.screenshot({ path: out, fullPage: false });
}

await browser.close();
