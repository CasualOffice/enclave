/* The `en-XA` and `en-XB` pseudo-locales (`docs/14 §9`, `ENC-994`).
 *
 * ## Why they are generated rather than written
 *
 * A pseudo-locale is a *function of* the source catalog, not a translation of
 * it. Checking one in as a second file would give the tree two places a message
 * lives, and the failure mode is silent: a key added to `catalog.ts` and not to
 * the copy simply stops being covered, which is exactly the coverage the
 * pseudo-locale exists to provide. Everything here reads `catalog.ts` and
 * derives, so a new key is pseudo-localized the moment it is added and there is
 * nothing to keep in step.
 *
 * ## Why two of them
 *
 * They catch different defects and neither substitutes for the other.
 *
 * - **`en-XA` expands.** Every letter is replaced by an accented lookalike and
 *   the string is padded to the expansion budget of `docs/14 §7`. It finds
 *   fixed widths, clipped buttons, single-line assumptions and — because the
 *   replacements reach past Latin-1 — glyph coverage gaps. It also makes an
 *   *unlocalized* string obvious: anything still in plain ASCII never went
 *   through the catalog.
 * - **`en-XB` mirrors.** Each message is wrapped in a terminated right-to-left
 *   override, and the locale resolves to `dir="rtl"`. It finds markup and
 *   geometry that assume visual order. `lint:i18n` already refuses physical
 *   `left`/`right` statically; this is the half a static scan cannot do —
 *   a hand-rolled arrow key, an icon that should have mirrored and did not, a
 *   flex row whose order is carried by DOM sequence rather than by direction.
 *
 * `en-XB` deliberately does **not** accent. If it did, a failure under it would
 * be ambiguous between an expansion defect and a direction defect, and the
 * point of two locales is that each one names its own cause.
 *
 * ## Why the ICU walk
 *
 * Messages are ICU MessageFormat, so a blind character substitution would
 * rewrite `{count, plural, one {…}}` into syntax the formatter cannot parse —
 * and the symptom is a runtime error in a screen, not a build failure. Only
 * *literal* runs are transformed: argument names, types, styles, plural
 * selectors and `#` are copied through byte for byte, which is also what keeps
 * `docs/14 §8` rule 2 checkable — the placeholder skeleton is identical to the
 * source's, so a test can assert it.
 */

import { catalog } from './catalog.ts';

/** The pseudo-locales, as BCP 47 tags. `XA`/`XB` are user-assigned regions. */
export const PSEUDO_LOCALES = ['en-XA', 'en-XB'] as const;

export type PseudoLocale = (typeof PSEUDO_LOCALES)[number];

/** The one that mirrors. Named so `directionFor` and the transform agree. */
export const MIRRORED_LOCALE: PseudoLocale = 'en-XB';

export function isPseudoLocale(tag: string): tag is PseudoLocale {
  return (PSEUDO_LOCALES as readonly string[]).includes(tag);
}

/* ------------------------------------------------------------ the ICU walk */

/** A half-open range of `message` that a translator would see. */
export interface LiteralSpan {
  readonly start: number;
  readonly end: number;
}

/** `noUncheckedIndexedAccess` is on, and a scanner reads past its end constantly. */
function at(source: string, index: number): string {
  return source[index] ?? '';
}

/** The argument types whose bodies contain sub-messages rather than a style. */
const KEYED_TYPES = new Set(['plural', 'selectordinal', 'select']);

/**
 * The literal runs of an ICU message, in source order.
 *
 * Exported because the tests measure expansion against it: "did this message
 * grow by 40%" is a question about the part a reader sees, and counting the
 * whole ICU string would make a plural-heavy message look expanded when its
 * rendered form was not.
 */
export function literalSpans(message: string): LiteralSpan[] {
  const spans: LiteralSpan[] = [];
  scanMessage(message, 0, spans);
  return spans;
}

/** Reads literal text and arguments until the end, or an unmatched `}`. */
function scanMessage(source: string, start: number, spans: LiteralSpan[]): number {
  let literalStart = start;
  let index = start;
  while (index < source.length) {
    const char = at(source, index);
    if (char === '}') break;
    if (char === '{') {
      if (index > literalStart) spans.push({ start: literalStart, end: index });
      index = scanArgument(source, index, spans);
      literalStart = index;
      continue;
    }
    index += 1;
  }
  if (index > literalStart) spans.push({ start: literalStart, end: index });
  return index;
}

/** Reads one `{…}` argument, recording any sub-message literals inside it. */
function scanArgument(source: string, open: number, spans: LiteralSpan[]): number {
  let index = open + 1;
  while (index < source.length && at(source, index) !== ',' && at(source, index) !== '}') {
    index += 1;
  }
  // `{name}` — nothing inside is text.
  if (index >= source.length) return source.length;
  if (at(source, index) === '}') return index + 1;

  const typeStart = index + 1;
  let cursor = typeStart;
  while (cursor < source.length && at(source, cursor) !== ',' && at(source, cursor) !== '}') {
    cursor += 1;
  }
  const type = source.slice(typeStart, cursor).trim();
  // `{name, number}` — a type with no style.
  if (cursor >= source.length) return source.length;
  if (at(source, cursor) === '}') return cursor + 1;

  if (KEYED_TYPES.has(type)) {
    /* `one {# item} other {# items}`: the selectors are keywords and the
     * braces hold sub-messages. Only the sub-messages are text. */
    let scan = cursor + 1;
    while (scan < source.length) {
      const char = at(source, scan);
      if (char === '}') return scan + 1;
      if (char === '{') {
        scan = scanMessage(source, scan + 1, spans);
        if (at(source, scan) === '}') scan += 1;
        continue;
      }
      scan += 1;
    }
    return scan;
  }

  /* `{when, date, medium}` — the style is machine syntax all the way to the
   * closing brace, and accenting `medium` would silently change the format. */
  let depth = 0;
  let scan = cursor + 1;
  while (scan < source.length) {
    const char = at(source, scan);
    if (char === '{') depth += 1;
    else if (char === '}') {
      if (depth === 0) return scan + 1;
      depth -= 1;
    }
    scan += 1;
  }
  return scan;
}

/* ------------------------------------------------------------------- en-XA */

/* The substitution alphabet, as two parallel strings rather than a 52-entry
 * object: the pairing is the whole content, and a table makes a misalignment
 * visible at a glance. A test asserts the two are the same length and that the
 * mapping is injective, because a one-character slip here would quietly map two
 * letters to one glyph and nothing else would notice.
 *
 * Several replacements (Ḋ Ṁ Ṽ Ẋ ɱ ṽ ẋ) sit outside the `latin-ext` subset the
 * self-hosted faces cover (`src/styles/fonts.css`). That is deliberate and is
 * the third thing `docs/14 §9` asks of this locale: a tofu box in staging is a
 * glyph-coverage report. */
const PLAIN = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ACCENTED = 'àƀçđéƒĝĥïĵķļɱñøþǫŕšŧúṽŵẋýžÅƁÇḊÉƑĜĤÏĴĶĻṀÑØÞǪŔŠŦÚṼŴẊÝŽ';

/**
 * Expansion by source length, as a multiple of the original.
 *
 * Short strings expand hardest — a two-word button is where truncation
 * actually happens, and a uniform +40% would leave it almost untouched. The
 * bands are the conventional ones; `docs/14 §7`'s 40% budget is the floor they
 * bottom out at for long prose.
 */
const EXPANSION_BANDS: readonly { readonly upTo: number; readonly factor: number }[] = [
  { upTo: 10, factor: 2.5 },
  { upTo: 20, factor: 2.0 },
  { upTo: 30, factor: 1.8 },
  { upTo: 50, factor: 1.6 },
];

/** The budget of `docs/14 §7`, and the floor of the table above. */
export const EXPANSION_FLOOR = 1.4;

function expansionFactor(length: number): number {
  for (const band of EXPANSION_BANDS) {
    if (length <= band.upTo) return band.factor;
  }
  return EXPANSION_FLOOR;
}

function accent(text: string): string {
  let out = '';
  for (const char of text) {
    const index = PLAIN.indexOf(char);
    out += index === -1 ? char : ACCENTED.charAt(index);
  }
  return out;
}

/**
 * The padding run, `‹›››…`, sized so the visible string reaches its band.
 *
 * Distinct from the accented letters on purpose: a reviewer looking at an
 * overflowing button can tell padding from content, so "this clipped" and
 * "this clipped *the words*" are different observations.
 */
function padding(literalChars: number): string {
  if (literalChars === 0) return '';
  const target = Math.ceil(literalChars * expansionFactor(literalChars));
  const width = Math.max(2, target - literalChars);
  return ` ‹${'›'.repeat(width - 2)}`;
}

/** `Download` -> `[Ḋøŵñļøàđ ‹››››››››››]`, the worked example of `docs/14 §9`. */
function expand(message: string): string {
  const spans = literalSpans(message);
  let out = '';
  let cursor = 0;
  let literalChars = 0;
  for (const span of spans) {
    out += message.slice(cursor, span.start);
    out += accent(message.slice(span.start, span.end));
    literalChars += span.end - span.start;
    cursor = span.end;
  }
  out += message.slice(cursor);
  /* The brackets are the delimiters, and they earn their two characters: a
   * string that is truncated in the interface has lost its `]`, which turns
   * "does this look short?" into a yes/no question. */
  return `[${out}${padding(literalChars)}]`;
}

/* ------------------------------------------------------------------- en-XB */

/* Written as escapes, not as the characters: all three are invisible, and a
 * bidi control pasted literally into source is unreviewable and survives a
 * careless editor only by luck. */
const RIGHT_TO_LEFT_MARK = '\u200F';
const RIGHT_TO_LEFT_OVERRIDE = '\u202E';
const POP_DIRECTIONAL_FORMATTING = '\u202C';

/**
 * Force the whole message to render right-to-left, and **terminate the
 * override**.
 *
 * `docs/14 §7` is explicit about why the pop matters: an override that is
 * opened and not closed reverses everything after it, which in a list is the
 * rest of the row and the rows below — the damage shows up somewhere other than
 * the string that caused it. A pseudo-locale that shipped that defect would
 * teach people to distrust the tool rather than the layout.
 *
 * Applied to the message as a whole rather than to each literal run, because
 * an interpolated value — a file name, a person's name — is exactly what an
 * RTL reader sees inside an RTL sentence, and excluding it would make the
 * pseudo-locale gentler than the real one.
 */
function mirror(message: string): string {
  return (
    RIGHT_TO_LEFT_MARK +
    RIGHT_TO_LEFT_OVERRIDE +
    message +
    POP_DIRECTIONAL_FORMATTING +
    RIGHT_TO_LEFT_MARK
  );
}

/* --------------------------------------------------------------- the entry */

export function pseudoLocalize(message: string, locale: PseudoLocale): string {
  return locale === MIRRORED_LOCALE ? mirror(message) : expand(message);
}

/**
 * The whole catalog, pseudo-localized.
 *
 * Deterministic: same catalog in, same object out, in catalog order. A
 * pseudo-locale that varied run to run would make a screenshot diff useless and
 * a failing CI job unreproducible.
 */
export function pseudoMessages(locale: PseudoLocale): Record<string, string> {
  return Object.fromEntries(
    Object.entries(catalog).map(([key, entry]) => [key, pseudoLocalize(entry.message, locale)]),
  );
}
