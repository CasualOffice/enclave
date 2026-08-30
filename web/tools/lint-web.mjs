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
    /* The entry runs to the start of the next key, or to the end of the object.
     *
     * It used to run to the next `},`, which is wrong for any message
     * containing an ICU placeholder followed by a comma: `'Applies {action},
     * measured from…'` carries `},` inside the *message*, so the tail stopped
     * before `description:` and the entry was reported as having none. A false
     * positive on this rule is worse than it looks — the obvious way to satisfy
     * it is to reword the user-facing string until the linter stops
     * complaining, which is a tool editing copy. Found by `ENC-945`, whose two
     * summary strings are the first in the catalog to punctuate that way. */
    const nextKey = /^\s{2}'[^']+':\s*\{$/gm;
    nextKey.lastIndex = match.index + match[0].length;
    const next = nextKey.exec(catalogSource);
    const tail = catalogSource.slice(match.index, next === null ? undefined : next.index);
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

/* ------------------------------------------------- the layer boundary rule */

/** The layers of `docs/17 §2`, outermost first. A module may import strictly below its own. */
const LAYERS = ['app', 'features', 'entities', 'shared'];

/** Which layer a `web/src/...` path belongs to, and which feature if any. */
function locate(relPath) {
  const match = /^src\/([^/]+)\/(?:([^/]+)\/)?/.exec(relPath);
  if (match === null) return undefined;
  const rank = LAYERS.indexOf(match[1]);
  if (rank === -1) return undefined;
  return { layer: match[1], rank, feature: match[1] === 'features' ? match[2] : undefined };
}

/** Resolve a relative import against the importing file, to a `src/...` path. */
function resolveImport(fromRel, spec) {
  if (!spec.startsWith('.')) return undefined;
  const parts = fromRel.split('/').slice(0, -1);
  for (const segment of spec.split('/')) {
    if (segment === '.' || segment === '') continue;
    if (segment === '..') parts.pop();
    else parts.push(segment);
  }
  return parts.join('/');
}

/**
 * The reason an import is refused, or `undefined` when it is fine.
 *
 * Two rules, and the second is the one that bites: a feature importing a
 * sibling feature couples two things that are meant to evolve separately, and
 * the remedy is always to move the shared piece down rather than to allow the
 * edge.
 */
function boundaryViolation(fromRel, spec) {
  const target = resolveImport(fromRel, spec);
  if (target === undefined) return undefined;

  const from = locate(fromRel);
  const to = locate(target);
  if (from === undefined || to === undefined) return undefined;

  if (to.rank < from.rank) {
    return `\`${from.layer}/\` may not import from \`${to.layer}/\` — imports go downward only (docs/17 §2)`;
  }

  if (
    from.layer === 'features' &&
    to.layer === 'features' &&
    from.feature !== undefined &&
    to.feature !== undefined &&
    from.feature !== to.feature
  ) {
    return `feature \`${from.feature}\` may not import feature \`${to.feature}\` — move the shared piece down to \`entities/\` or \`shared/\` (docs/17 §2)`;
  }

  return undefined;
}

const referencedKeys = new Set();

for (const file of files) {
  const rel = relative(WEB_ROOT, file).split('\\').join('/');
  const ext = extname(file);
  if (!['.ts', '.tsx', '.css'].includes(ext)) continue;

  const raw = readFileSync(file, 'utf8');
  const source = blankComments(raw);
  const lines = source.split('\n');
  filesScanned += 1;

  /* The catalog is not a reference to itself.
   *
   * This rule was vacuous until now, and silently so. The scan below matches a
   * single-quoted dotted identifier, and a catalog *declaration* is exactly
   * that — `  'search.state.error.requestId': {` — so every key referenced
   * itself, `referencedKeys` was always equal to `catalogKeys`, and the run
   * reported "435 catalog key(s), 435 referenced" whatever the tree contained.
   * A rule that cannot fail is the `ENC-543` shape one layer down, in the tool
   * that exists to catch it.
   *
   * Found by a session that removed a key's last real use and expected the
   * gate to say so. It did not. */
  if (rel !== CATALOG_REL) {
    /* Both quote styles.
     *
     * The scan used to accept single quotes only, which meant the commonest
     * form of all — a JSX attribute, `label="upload.cancel"` — did not count as
     * a reference. Invisible while the rule was vacuous; the moment the catalog
     * stopped self-referencing it produced a hundred false orphans on keys that
     * are rendered on screen. Backticks are deliberately still excluded: a
     * template literal is a *computed* key, and `docs/14 §8` wants those
     * spelled out precisely so this scan can see them. */
    for (const key of source.matchAll(/['"]((?:[a-z][A-Za-z0-9]*\.)+[A-Za-z0-9]+)['"]/g)) {
      if (catalogKeys.has(key[1])) referencedKeys.add(key[1]);
    }

    /* A key built from an enum — `` t(`library.status.${version.status}`) ``.
     *
     * The static prefix is a real reference to every key under it: the code can
     * reach any of them and which one it reaches is a runtime value. Counting
     * only the literal forms reported four live keys as dead, and deleting them
     * on that evidence would have shipped a `library.status.…` placeholder into
     * the peek panel.
     *
     * Narrow on purpose — the prefix must end at a dot, so `` `${a}.${b}` ``
     * marks nothing and a whole-catalog wildcard is not expressible. A mapping
     * written out as a `Record<Enum, MessageKey>` (see
     * `entities/classification/model.ts`) is still the better shape, because it
     * is exhaustive and the compiler checks it; this only stops the gate lying
     * about the shape that is already in the tree. */
    for (const prefix of source.matchAll(/`((?:[a-z][A-Za-z0-9]*\.)+)\$\{/g)) {
      for (const key of catalogKeys.keys()) {
        if (key.startsWith(prefix[1])) referencedKeys.add(key);
      }
    }
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

    /* The layer boundary of `docs/17 §2`.
     *
     * A module may import from a layer below it and never from one above or
     * beside it:
     *
     *     app/  ->  features/  ->  entities/  ->  shared/
     *
     * and **a feature never imports another feature**. `docs/17 §2` says this is
     * "enforced by an ESLint boundary rule, not by convention — the rule is the
     * gate, and `ENC-543` is why a rule nobody enforces is worse than no rule."
     * There is no ESLint in this tree and there was no rule either, so the
     * sentence described an enforcement that did not exist. It does now.
     *
     * It has already earned its place: the upload queue began in
     * `features/upload/` and was read by `features/libraries/`, which is
     * precisely the import this refuses. The fix `docs/17 §2` prescribes —
     * move the shared thing down — put it in `entities/upload/`, where both
     * features reach it legally.
     */
    const importPath = /^\s*(?:import|export)\b[^'"]*from\s+['"]([^'"]+)['"]/.exec(line);
    if (importPath !== null) {
      const violation = boundaryViolation(rel, importPath[1]);
      if (violation !== undefined) {
        report(rel, number, 'arch/layer-boundary', violation);
      }
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
