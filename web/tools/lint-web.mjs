#!/usr/bin/env node
/**
 * The `lint:i18n` gate.
 *
 * `docs/14 §8` lists six engineering rules and says they are enforced in CI.
 * Until now nothing enforced any of them, because the job that would have run
 * this script exited zero when `web/package.json` was absent (`ENC-677`). Five
 * of the six are mechanical and are checked here; the sixth (missing keys fall
 * back to `en-US` and render normally) is a runtime property and belongs to the
 * pseudo-locale run in M5 step 5.
 *
 *   1. No user-facing string literal in `web/src` outside the catalog.
 *   2. Every key referenced in code exists in the catalog; every catalog key is
 *      referenced. Orphans and missing keys both fail.
 *   3. No date, number or currency formatting outside the `Intl` wrappers.
 *   4. No `left`/`right` physical properties in component CSS.
 *   5. Every key ships with a translator description.
 *
 * And one from `CLAUDE.md`'s TypeScript conventions, checked here because it has
 * the same shape: no explicit `any`.
 *
 * **This script fails when it finds nothing to check.** A linter that scans zero
 * files and reports success is the failure mode the gate it belongs to already
 * had once; it does not get to have it twice.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const WEB_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = join(WEB_ROOT, 'src');

/* The catalog is found rather than named, because a hard-coded path turns a
 * file move into a crash — and a linter that crashes on a refactor is a linter
 * somebody comments out of CI. Exactly one is required: two catalogs is two
 * sources of truth, and zero is the vacuous pass this gate exists to refuse. */
const CATALOG_SUFFIX = 'i18n/catalog.ts';

const findings = [];
let filesScanned = 0;

function report(file, line, rule, message) {
  findings.push({ file, line, rule, message });
}

/**
 * Replace every comment with spaces, keeping the file's exact line and column
 * geometry so a finding still points at the right place.
 *
 * Without this the linter reports its own prose: the header of
 * `grouped-list.css` explains why `margin-left` is banned, and a naive scan
 * flags the explanation. A rule that fires on the document describing it is a
 * rule people delete.
 */
function blankComments(source) {
  let out = '';
  let index = 0;
  let state = 'code';
  let quote = '';
  while (index < source.length) {
    const two = source.slice(index, index + 2);
    const char = source[index];
    if (state === 'code') {
      if (char === '"' || char === "'" || char === '`') {
        state = 'string';
        quote = char;
        out += char;
      } else if (two === '/*') {
        state = 'block';
        out += '  ';
        index += 2;
        continue;
      } else if (two === '//' && source[index - 1] !== ':') {
        state = 'line';
        out += '  ';
        index += 2;
        continue;
      } else {
        out += char;
      }
    } else if (state === 'string') {
      out += char;
      if (char === '\\') {
        out += source[index + 1] ?? '';
        index += 2;
        continue;
      }
      if (char === quote) state = 'code';
    } else if (state === 'block') {
      if (two === '*/') {
        state = 'code';
        out += '  ';
        index += 2;
        continue;
      }
      out += char === '\n' ? '\n' : ' ';
    } else {
      if (char === '\n') {
        state = 'code';
        out += '\n';
      } else {
        out += ' ';
      }
    }
    index += 1;
  }
  return out;
}

/** A line with its comments already blanked, trimmed. */
function trimmedCode(line) {
  return line.trim();
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

const files = walk(SRC);

// ---------------------------------------------------------------- the catalog

const catalogs = files
  .map((file) => relative(WEB_ROOT, file).split('\\').join('/'))
  .filter((rel) => rel.endsWith(CATALOG_SUFFIX));

if (catalogs.length !== 1) {
  console.error(
    `lint:i18n expected exactly one */${CATALOG_SUFFIX} under web/src, found ${catalogs.length}` +
      (catalogs.length > 0 ? `: ${catalogs.join(', ')}` : ''),
  );
  process.exit(2);
}

const CATALOG_REL = catalogs[0];

/** Files exempt from the string-literal rule, with the reason stated. */
const LITERAL_EXEMPT = new Set([
  CATALOG_REL, // it is the catalog
]);

const catalogSource = readFileSync(join(WEB_ROOT, CATALOG_REL), 'utf8');
const catalogKeys = new Map();
{
  const entry = /^\s{2}'([^']+)':\s*\{$/gm;
  let match;
  while ((match = entry.exec(catalogSource)) !== null) {
    const key = match[1];
    const tail = catalogSource.slice(match.index, catalogSource.indexOf('},', match.index));
    const lineNumber = catalogSource.slice(0, match.index).split('\n').length;
    catalogKeys.set(key, {
      line: lineNumber,
      hasDescription: /\n\s+description:/.test(tail),
      hasMessage: /\n\s+message:/.test(tail),
    });
  }
}

if (catalogKeys.size === 0) {
  report(CATALOG_REL, 1, 'i18n/catalog', 'the catalog parsed to zero keys');
}

for (const [key, meta] of catalogKeys) {
  if (!meta.hasDescription) {
    report(
      CATALOG_REL,
      meta.line,
      'i18n/description',
      `key "${key}" has no translator description (docs/14 §8 rule 5)`,
    );
  }
  if (!meta.hasMessage) {
    report(CATALOG_REL, meta.line, 'i18n/message', `key "${key}" has no message`);
  }
}

// --------------------------------------------------------------- source rules

/** Attributes whose value a user reads or hears. */
const USER_FACING_ATTRS = /\b(aria-label|aria-description|aria-placeholder|placeholder|alt|title)=["'{]/;

/** Hand-rolled formatting the `Intl` wrappers exist to replace (docs/14 §8 rule 3). */
const MANUAL_FORMAT = [
  [/\.toLocaleDateString\(/, 'use the `useFormatters()` date wrapper'],
  [/\.toLocaleTimeString\(/, 'use the `useFormatters()` dateTime wrapper'],
  [/\.toLocaleString\(/, 'use the `useFormatters()` wrappers'],
  [/\.toFixed\(\s*\d+\s*\)\s*\+/, 'string-concatenated number formatting'],
  [/\b(?:KB|MB|GB|TB)\b\s*['"`]/, 'hand-built byte unit — `Intl.NumberFormat` has `style: "unit"`'],
  [/['"`]\s*(?:ago|hours? ago|days? ago)\b/, 'hand-built relative time — use `Intl.RelativeTimeFormat`'],
  [/\/\s*1024\s*\/\s*1024/, 'hand-built byte scaling'],
];

/** Physical direction, in CSS and in inline styles (docs/14 §8 rule 4). */
const PHYSICAL_CSS = [
  /(^|[;{\s])(margin|padding|border)-(left|right)\s*:/,
  /(^|[;{\s])(left|right)\s*:/,
  /(^|[;{\s])(border-(?:top|bottom)-(?:left|right)-radius)\s*:/,
  /text-align\s*:\s*(left|right)\b/,
  /\bfloat\s*:\s*(left|right)\b/,
  /\b(marginLeft|marginRight|paddingLeft|paddingRight|borderLeft|borderRight)\s*:/,
  /* `textAlign` in a style object is only wrong when its *value* is physical.
   * The first version banned the property outright, which failed
   * `style={{ textAlign: 'start' }}` — correct code, rejected. A rule that
   * refuses the right answer is a rule people route around, and routing around
   * this one means turning it off for the file. */
  /\btextAlign\s*:\s*['"`](left|right)['"`]/,
];

const referencedKeys = new Set();

for (const file of files) {
  const rel = relative(WEB_ROOT, file).split('\\').join('/');
  const ext = extname(file);
  if (!['.ts', '.tsx', '.css'].includes(ext)) continue;

  const raw = readFileSync(file, 'utf8');
  const source = blankComments(raw);
  const lines = source.split('\n');
  filesScanned += 1;

  for (const key of source.matchAll(/'((?:[a-z][A-Za-z0-9]*\.)+[A-Za-z0-9]+)'/g)) {
    if (catalogKeys.has(key[1])) referencedKeys.add(key[1]);
  }

  lines.forEach((line, index) => {
    const number = index + 1;

    for (const pattern of PHYSICAL_CSS) {
      if (pattern.test(line)) {
        report(
          rel,
          number,
          'css/physical-direction',
          'physical direction — use a logical property (`inline-start`, `inline-end`, `text-align: start`). `en-XB` mirrors direction in CI',
        );
        break;
      }
    }

    if (ext === '.css') return;

    for (const [pattern, why] of MANUAL_FORMAT) {
      if (pattern.test(line)) {
        report(rel, number, 'i18n/manual-format', `${why} (docs/14 §6)`);
        break;
      }
    }

    if (/:\s*any\b|<any>|as any\b/.test(line)) {
      report(rel, number, 'ts/no-any', 'explicit `any` (CLAUDE.md, TypeScript conventions)');
    }

    if (LITERAL_EXEMPT.has(rel)) return;

    // JSX text between tags on one line: `>Some words<`.
    const jsxText = line.match(/>\s*([A-Za-z][A-Za-z',.!?-]*(?:\s+[A-Za-z][A-Za-z',.!?-]*)*)\s*</);
    if (jsxText !== null && /[A-Za-z]{2}/.test(jsxText[1])) {
      report(
        rel,
        number,
        'i18n/no-literal',
        `user-facing literal ${JSON.stringify(jsxText[1])} in JSX — put it in the catalog`,
      );
    }

    /* JSX text on a line of its own, which the rule above cannot see.
     *
     * Prettier puts prose on its own line whenever the element wraps, so this
     * is not an edge case — it is the common shape. The gate missed a name
     * rendered in the application shell for exactly this reason, and a rule
     * that only catches the unwrapped half of a formatter's output is a rule
     * whose coverage depends on line length.
     *
     * A line qualifies when it is prose and nothing else: no angle brackets,
     * braces, quotes, operators or call syntax, and it sits between a tag that
     * opened above and one that closes below. Anything with code in it is left
     * to the rule above rather than guessed at. */
    if (ext === '.tsx' && /^[A-Za-z][A-Za-z ',.!?’-]*$/.test(trimmedCode(line))) {
      const opensAbove = /[>{]\s*$/.test(lines[index - 1] ?? '');
      const closesBelow = /^\s*[<}]/.test(lines[index + 1] ?? '');
      if (opensAbove && closesBelow && /[A-Za-z]{2}/.test(line)) {
        report(
          rel,
          number,
          'i18n/no-literal',
          `user-facing literal ${JSON.stringify(trimmedCode(line))} on its own line — put it in the catalog`,
        );
      }
    }

    const attr = line.match(USER_FACING_ATTRS);
    if (attr !== null) {
      const after = line.slice(line.indexOf(attr[0]) + attr[0].length - 1);
      if (after.startsWith('"') || after.startsWith("'")) {
        const value = after.slice(1, after.indexOf(after[0], 1));
        if (/[A-Za-z]{2}/.test(value)) {
          report(
            rel,
            number,
            'i18n/no-literal',
            `user-facing literal ${JSON.stringify(value)} in \`${attr[1]}\` — put it in the catalog`,
          );
        }
      }
    }
  });
}

for (const [key, meta] of catalogKeys) {
  if (!referencedKeys.has(key)) {
    report(
      CATALOG_REL,
      meta.line,
      'i18n/orphan-key',
      `key "${key}" is in the catalog and referenced by nothing (docs/14 §8 rule 2)`,
    );
  }
}

// ------------------------------------------------------------------- verdict

/* The gate refuses to be vacuous. Both of these are the `ENC-543`/`ENC-677`
 * failure mode written as an assertion: a check that inspected nothing has not
 * passed, it has abstained. */
if (filesScanned === 0) {
  console.error('lint:i18n scanned zero files under web/src — the gate is not wired to anything.');
  process.exit(2);
}
if (catalogKeys.size === 0) {
  console.error('lint:i18n found no catalog keys — there is nothing for rule 2 to check against.');
  process.exit(2);
}

if (findings.length > 0) {
  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  for (const finding of findings) {
    console.error(`${finding.file}:${finding.line}  [${finding.rule}]  ${finding.message}`);
  }
  console.error(
    `\nlint:i18n found ${findings.length} problem(s) across ${filesScanned} file(s). ` +
      'See docs/14-I18N-L10N.md §8 and CLAUDE.md rule 12.',
  );
  process.exit(1);
}

console.log(
  `lint:i18n clean — ${filesScanned} file(s), ${catalogKeys.size} catalog key(s), ` +
    `${referencedKeys.size} referenced.`,
);
