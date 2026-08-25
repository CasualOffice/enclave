#!/usr/bin/env node
/**
 * The `check:bundle-size` gate.
 *
 * `docs/09 §2` and `docs/12 §5`: the main bundle is at most 250 KB gzipped.
 *
 * "Main bundle" is defined here as **everything a browser must download before
 * it can render the first route** — the entry chunk, every chunk it statically
 * imports, and the CSS they pull in. Measuring only the entry chunk would let a
 * regression hide behind an import, which is a way of passing rather than a way
 * of being small. Lazily-imported chunks are reported but do not count, because
 * that is what code-splitting is for (`docs/09 §2`: split admin and editor
 * routes out of the main bundle).
 *
 * Like `lint-web.mjs`, this refuses to pass when it has measured nothing.
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const WEB_ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIST = join(WEB_ROOT, 'dist');
const MANIFEST = join(DIST, '.vite', 'manifest.json');
const BUDGET_BYTES = 250 * 1024;

if (!existsSync(DIST)) {
  console.error(`check:bundle-size: ${DIST} does not exist. Run \`npm run build\` first.`);
  process.exit(2);
}

/* Vite only writes a manifest when asked. Without one the initial-payload graph
 * cannot be walked, and guessing it from filenames is how the number stops
 * meaning anything. */
if (!existsSync(MANIFEST)) {
  console.error(
    'check:bundle-size: dist/.vite/manifest.json is missing. ' +
      'Set `build.manifest: true` in vite.config.ts — without it this gate cannot ' +
      'tell an initial chunk from a lazy one, and a gate that cannot tell does not pass.',
  );
  process.exit(2);
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
const entries = Object.values(manifest).filter((chunk) => chunk.isEntry === true);

if (entries.length === 0) {
  console.error('check:bundle-size: the manifest names no entry chunk. Nothing was measured.');
  process.exit(2);
}

const initial = new Set();
const lazy = new Set();

function collect(chunkKey, target) {
  if (target.has(chunkKey)) return;
  const chunk = manifest[chunkKey];
  if (chunk === undefined) return;
  target.add(chunkKey);
  for (const css of chunk.css ?? []) target.add(`css:${css}`);
  for (const imported of chunk.imports ?? []) collect(imported, target);
  for (const dynamic of chunk.dynamicImports ?? []) collect(dynamic, lazy);
}

for (const entry of entries) {
  const key = Object.keys(manifest).find((k) => manifest[k] === entry);
  if (key !== undefined) collect(key, initial);
}

function fileFor(key) {
  return key.startsWith('css:') ? key.slice(4) : manifest[key].file;
}

function gzippedSize(file) {
  return gzipSync(readFileSync(join(DIST, file)), { level: 9 }).length;
}

const measured = [...initial]
  .map((key) => {
    const file = fileFor(key);
    return { file, bytes: gzippedSize(file) };
  })
  .sort((a, b) => b.bytes - a.bytes);

if (measured.length === 0) {
  console.error('check:bundle-size: measured zero files. The gate is not wired to anything.');
  process.exit(2);
}

/* Air-gap check, in the one place that already reads every shipped byte.
 *
 * `ENC-135` self-hosts all three families precisely so no page load reaches a
 * CDN: an external request leaks every user's IP to a third party, breaks an
 * air-gapped install outright (`docs/08 §18` makes those first-class), and is a
 * compliance conversation an enterprise security product does not want to have.
 * A dependency added six months from now that quietly `@import`s a font would
 * pass every other gate in this repo.
 *
 * The rule is deliberately about *fetching positions* rather than about any
 * string that looks like a URL: `http://www.w3.org/2000/svg` is an XML
 * namespace identifier and `react.dev` appears inside an error message, and
 * failing on either would train people to add exceptions. */
const FETCHING = [
  /@import\s+(?:url\()?["']?https?:/i,
  /url\(\s*["']?https?:/i,
  /["'`]https?:\/\/[^"'`]*\.(?:woff2?|ttf|otf|eot|css)["'`]/i,
];
const KNOWN_CDN =
  /fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|use\.typekit\.net|use\.fontawesome\.com/i;

const remote = [];
for (const { file } of measured) {
  const text = readFileSync(join(DIST, file), 'utf8');
  for (const pattern of FETCHING) {
    const hit = pattern.exec(text);
    if (hit !== null) remote.push(`${file}: ${hit[0].slice(0, 120)}`);
  }
  const cdn = KNOWN_CDN.exec(text);
  if (cdn !== null) remote.push(`${file}: ${cdn[0]}`);
}

if (remote.length > 0) {
  console.error('\ncheck:bundle-size FAILED: the initial payload fetches from another origin.');
  for (const line of remote) console.error(`  ${line}`);
  console.error(
    '\nSelf-host it under web/public and reference it with a same-origin path. ' +
      'See ENC-135 and docs/08 §18.',
  );
  process.exit(1);
}

const total = measured.reduce((sum, item) => sum + item.bytes, 0);
const pad = (n) => `${(n / 1024).toFixed(1)} KB`.padStart(9);

console.log('Initial payload, gzipped:');
for (const item of measured) console.log(`  ${pad(item.bytes)}  ${item.file}`);

const lazyOnly = [...lazy].filter((key) => !initial.has(key));
if (lazyOnly.length > 0) {
  console.log('Lazy (not counted):');
  for (const key of lazyOnly) {
    const file = fileFor(key);
    console.log(`  ${pad(gzippedSize(file))}  ${file}`);
  }
}

console.log(
  `\n  total ${pad(total).trim()} of ${(BUDGET_BYTES / 1024).toFixed(0)} KB budget ` +
    `(${((total / BUDGET_BYTES) * 100).toFixed(1)}%), across ${measured.length} file(s).`,
);

if (total > BUDGET_BYTES) {
  console.error(
    `\ncheck:bundle-size FAILED: initial payload is ${(total / 1024).toFixed(1)} KB gzipped, ` +
      `over the ${(BUDGET_BYTES / 1024).toFixed(0)} KB budget in docs/09 §2 by ` +
      `${((total - BUDGET_BYTES) / 1024).toFixed(1)} KB.`,
  );
  process.exit(1);
}
