import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { IntlProvider } from 'react-intl';
import { catalog, type MessageKey } from '../../src/shared/i18n/catalog.ts';
import {
  I18nProvider,
  SOURCE_LOCALE,
  applyDocumentLocale,
  directionFor,
  messagesForLocale,
  requestedLocale,
  useT,
  type MessageValues,
} from '../../src/shared/i18n/index.tsx';
import {
  EXPANSION_FLOOR,
  MIRRORED_LOCALE,
  PSEUDO_LOCALES,
  literalSpans,
  pseudoLocalize,
  pseudoMessages,
} from '../../src/shared/i18n/pseudo.ts';

/* `docs/14 §9`, in a test runner.
 *
 * ## What this file is defending against
 *
 * `docs/12 §1.2`: **an assertion about an absence passes for free**, and a
 * pseudo-locale is almost entirely absences — "no key is missing", "no message
 * lost its placeholders", "nothing renders a raw key". Every one of those is
 * true of a generator that returns `{}`, and true again of a provider that
 * quietly ignored the locale and served English. Both are the realistic bugs
 * here, so both are ruled out explicitly:
 *
 * 1. The key set is compared against the catalog **and** the catalog is
 *    asserted to be large. An empty catalog would otherwise make every
 *    set-equality below vacuous.
 * 2. Every pseudo message is asserted to *differ* from its source. A generator
 *    that returned the catalog unchanged would satisfy every completeness check
 *    in this file and none of this one.
 * 3. The render tests assert what reaches the DOM, in both directions: the
 *    pseudo string appears under the pseudo locale and the English string
 *    appears under `en-US`. A provider that ignored its `locale` prop fails the
 *    first; a provider that lost the catalog fails the second.
 *
 * The negative control in "a bundle that is missing a key" is the one worth
 * reading: it renders the *unmerged* path to show that it puts a raw message id
 * on screen. Without it, the fallback test proves only that a complete bundle
 * is complete.
 */

/* Spelled out, not pasted: these are invisible, and the source of a test that
 * asserts their placement must show what it is asserting. */
const RIGHT_TO_LEFT_MARK = '\u200F';
const RIGHT_TO_LEFT_OVERRIDE = '\u202E';
const POP_DIRECTIONAL_FORMATTING = '\u202C';

const ASCII_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

const CATALOG_KEYS = Object.keys(catalog);

/** Characters of a message a reader actually sees, placeholders excluded. */
function visibleLength(message: string): number {
  return literalSpans(message).reduce((total, span) => total + (span.end - span.start), 0);
}

/** Everything but the ICU structure, so two messages' skeletons can be compared. */
function skeleton(message: string): string {
  return message.replace(/[^{}#]/g, '');
}

function Probe({ messageKey, values }: { messageKey: MessageKey; values?: MessageValues }) {
  const t = useT();
  return <span data-testid="probe">{t(messageKey, values)}</span>;
}

const probeText = () => screen.getByTestId('probe').textContent;

afterEach(() => {
  cleanup();
  applyDocumentLocale(SOURCE_LOCALE);
});

describe('the catalog is fully covered', () => {
  it('has enough keys for the comparisons below to mean anything', () => {
    /* The floor, not the count: this must not need editing every time a key is
     * added. It exists so that an empty or half-parsed catalog cannot make
     * `toEqual` succeed against an empty pseudo bundle. */
    expect(CATALOG_KEYS.length).toBeGreaterThan(100);
  });

  for (const locale of PSEUDO_LOCALES) {
    it(`${locale} carries every catalog key, in catalog order`, () => {
      expect(Object.keys(pseudoMessages(locale))).toEqual(CATALOG_KEYS);
    });

    it(`${locale} translates every message rather than passing it through`, () => {
      const messages = pseudoMessages(locale);
      for (const key of CATALOG_KEYS) {
        const source = catalog[key as MessageKey].message;
        const pseudo = messages[key];
        expect(pseudo, `${key} is missing from ${locale}`).toBeTypeOf('string');
        expect(pseudo, `${key} is empty in ${locale}`).not.toBe('');
        expect(pseudo, `${key} was passed through unchanged in ${locale}`).not.toBe(source);
      }
    });

    it(`${locale} leaves the ICU skeleton of every message untouched`, () => {
      const messages = pseudoMessages(locale);
      for (const key of CATALOG_KEYS) {
        const source = catalog[key as MessageKey].message;
        expect(skeleton(messages[key] ?? ''), `${key} lost its ICU structure in ${locale}`).toBe(
          skeleton(source),
        );
      }
    });

    it(`${locale} is deterministic`, () => {
      expect(pseudoMessages(locale)).toStrictEqual(pseudoMessages(locale));
    });
  }
});

describe('en-XA — expansion', () => {
  it('reproduces the worked example in docs/14 §9', () => {
    expect(pseudoLocalize('Download', 'en-XA')).toBe('[Ḋøŵñļøàđ ‹››››››››››]');
  });

  it('maps all 52 letters, one to one, out of ASCII', () => {
    /* A slip of one character in the substitution alphabet would map two
     * letters to the same glyph, and every other test in this file would still
     * pass. */
    const body = pseudoLocalize(ASCII_ALPHABET, 'en-XA').slice(1, 1 + ASCII_ALPHABET.length);
    expect(body).toHaveLength(ASCII_ALPHABET.length);
    expect(new Set(body).size).toBe(ASCII_ALPHABET.length);
    expect([...body].every((char) => char.charCodeAt(0) > 127)).toBe(true);
  });

  it('clears the 40% expansion budget on every message in the catalog', () => {
    for (const key of CATALOG_KEYS) {
      const source = catalog[key as MessageKey].message;
      const grown = visibleLength(pseudoLocalize(source, 'en-XA'));
      expect(grown, `${key} did not expand`).toBeGreaterThanOrEqual(
        Math.ceil(visibleLength(source) * EXPANSION_FLOOR),
      );
    }
  });

  it('accents the words of a plural and none of its syntax', () => {
    const plural = '{count, plural, one {# item} other {# items}}';
    const expanded = pseudoLocalize(plural, 'en-XA');

    // The machinery, verbatim — an accented `plural` or `count` is unparseable.
    expect(expanded).toContain('{count, plural, one {');
    expect(expanded).toContain('} other {');
    expect(expanded).toContain('#');

    // The words, accented. The positive control for the assertion above.
    expect(expanded).toContain('ïŧéɱ');
    expect(expanded).not.toContain('item');
  });

  it('still formats a real plural through react-intl', () => {
    /* The structural check above says the braces survived; this says the
     * formatter agrees. `files.list.rowCount` is the catalog's nested plural,
     * so it exercises both branches of the walk. */
    render(
      <I18nProvider locale="en-XA">
        <Probe messageKey="files.list.rowCount" values={{ shown: 3, total: 9 }} />
      </I18nProvider>,
    );
    const rendered = probeText() ?? '';
    expect(rendered).toContain('3');
    expect(rendered).toContain('9');
    expect(rendered).toContain('ïŧéɱš');
  });

  it('reaches the DOM, and en-US still does too', () => {
    render(
      <I18nProvider locale="en-XA">
        <Probe messageKey="files.column.name" />
      </I18nProvider>,
    );
    const expanded = probeText();
    expect(expanded).toBe('[Ñàɱé ‹››››]');

    cleanup();

    render(
      <I18nProvider>
        <Probe messageKey="files.column.name" />
      </I18nProvider>,
    );
    expect(probeText()).toBe('Name');
  });
});

describe('en-XB — direction', () => {
  it('wraps every message in an override it also closes', () => {
    const messages = pseudoMessages(MIRRORED_LOCALE);
    for (const key of CATALOG_KEYS) {
      const pseudo = messages[key] ?? '';
      expect(pseudo.startsWith(RIGHT_TO_LEFT_MARK + RIGHT_TO_LEFT_OVERRIDE), key).toBe(true);
      expect(pseudo.endsWith(POP_DIRECTIONAL_FORMATTING + RIGHT_TO_LEFT_MARK), key).toBe(true);

      /* `docs/14 §7`: an unterminated override reverses the rest of the page,
       * so the damage appears somewhere other than the string that caused it. */
      const opened = [...pseudo].filter((char) => char === RIGHT_TO_LEFT_OVERRIDE).length;
      const closed = [...pseudo].filter(
        (char) => char === POP_DIRECTIONAL_FORMATTING,
      ).length;
      expect(closed, `${key} opens ${opened} override(s) and closes ${closed}`).toBe(opened);
    }
  });

  it('does not expand, so a failure under it names direction and nothing else', () => {
    expect(pseudoLocalize('Download', MIRRORED_LOCALE)).toContain('Download');
    expect(pseudoLocalize('Download', MIRRORED_LOCALE)).not.toContain('‹');
  });

  it('is the only locale here that mirrors', () => {
    expect(directionFor(MIRRORED_LOCALE)).toBe('rtl');
    expect(directionFor('en-XA')).toBe('ltr');
    expect(directionFor(SOURCE_LOCALE)).toBe('ltr');
    // The launch locale `en-XB` stands in for, per `docs/14 §2`.
    expect(directionFor('ar-AE')).toBe('rtl');
  });

  it('mirrors the document, which is where the keyboard and CSS read it', () => {
    applyDocumentLocale(SOURCE_LOCALE);
    expect(document.documentElement.dir).toBe('ltr'); // positive control

    applyDocumentLocale(MIRRORED_LOCALE);
    expect(document.documentElement.dir).toBe('rtl');
    expect(document.documentElement.lang).toBe(MIRRORED_LOCALE);
  });
});

describe('a missing key never reaches a reader as a key (docs/14 §8 rule 6)', () => {
  it('renders the raw id when the bundle alone is consulted — the mechanism this defends', () => {
    /* The negative control. `react-intl` has no en-US to fall back *to* for a
     * message: `defaultLocale` governs formatting, not lookup, and `useT`
     * passes no `defaultMessage` because that would be an English literal in
     * `web/src`. So an incomplete bundle puts the key on screen. */
    render(
      <IntlProvider locale="en-XA" defaultLocale={SOURCE_LOCALE} messages={{}} onError={() => {}}>
        <Probe messageKey="files.column.name" />
      </IntlProvider>,
    );
    expect(probeText()).toBe('files.column.name');
  });

  it('layers the pseudo bundle over en-US so the worst case is English', () => {
    for (const locale of PSEUDO_LOCALES) {
      const bundle = messagesForLocale(locale);
      for (const key of CATALOG_KEYS) {
        expect(bundle[key], `${key} would render as its own id under ${locale}`).not.toBe(
          undefined,
        );
      }
    }

    /* And the fallback works for a key the pseudo bundle does not have, which
     * is the case that will exist the first time a real translation is
     * partial. */
    const partial = { ...messagesForLocale(SOURCE_LOCALE), 'files.column.size': '[Šïžé ‹››]' };
    render(
      <IntlProvider
        locale="en-XA"
        defaultLocale={SOURCE_LOCALE}
        messages={partial}
        onError={() => {}}
      >
        <Probe messageKey="files.column.name" />
      </IntlProvider>,
    );
    expect(probeText()).toBe('Name');
  });
});

describe('choosing a pseudo-locale', () => {
  it('accepts the two pseudo tags from the URL and nothing else', () => {
    expect(requestedLocale('?locale=en-XA')).toBe('en-XA');
    expect(requestedLocale('?locale=en-XB')).toBe('en-XB');
    // Real negotiation is `docs/14 §3` and does not run through a query string.
    expect(requestedLocale('?locale=de-DE')).toBe(SOURCE_LOCALE);
    expect(requestedLocale('?locale=')).toBe(SOURCE_LOCALE);
    expect(requestedLocale('')).toBe(SOURCE_LOCALE);
  });
});
