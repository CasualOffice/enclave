import type { ReactNode } from 'react';
import { IntlProvider, useIntl } from 'react-intl';
import { catalog, messagesFor, type MessageKey } from './catalog.ts';
import { MIRRORED_LOCALE, isPseudoLocale, pseudoMessages } from './pseudo.ts';

/* `react-intl` rather than a hand-rolled substitution map, because `docs/14 §4`
 * requires ICU: plural categories in Slavic, Arabic and South Asian languages
 * cannot be expressed as key/value replacement, and discovering that after two
 * hundred keys exist is the expensive way to learn it. */

export const SOURCE_LOCALE = 'en-US';

const sourceMessages = messagesFor(catalog);

/* One bundle per locale, built once.
 *
 * `pseudoMessages` walks six hundred ICU strings, which is nothing on a page
 * load and a great deal inside a React render that runs on every state change.
 * Keyed by tag rather than memoized per provider so two providers — the shell
 * and a portal, say — cannot disagree about what `en-XA` says. */
const bundles = new Map<string, Record<string, string>>([[SOURCE_LOCALE, sourceMessages]]);

/**
 * The messages a locale renders with.
 *
 * **Layered over `en-US`, and that is `docs/14 §8` rule 6 made real rather than
 * asserted.** `react-intl` falls back to `defaultLocale` only for
 * *formatting* — for a message it has no entry for, and no `defaultMessage`
 * given at the call site, it renders the id. `useT` passes an id and nothing
 * else, by design (a `defaultMessage` at the call site is an English literal in
 * `web/src`), so an incomplete bundle would put `files.column.name` on screen.
 * Spreading the source underneath means the worst case is an untranslated
 * string, which is what the rule requires and what a reader can still act on.
 */
export function messagesForLocale(locale: string): Record<string, string> {
  const cached = bundles.get(locale);
  if (cached !== undefined) return cached;
  const built = isPseudoLocale(locale)
    ? { ...sourceMessages, ...pseudoMessages(locale) }
    : sourceMessages;
  bundles.set(locale, built);
  return built;
}

/** Languages written right to left, by primary subtag (`docs/14 §2`, `§7`). */
const RIGHT_TO_LEFT = new Set(['ar', 'fa', 'he', 'ps', 'ur', 'yi']);

/**
 * The writing direction a locale implies.
 *
 * `en-XB` is here for the same reason `ar-AE` is in the launch set: something
 * has to mirror before an Arabic speaker is available to notice that nothing
 * does. It is the only pseudo-locale that changes direction — `en-XA` stays
 * left-to-right so an expansion failure is never confused for a mirroring one.
 *
 * Note this answers a question about a *locale*, not about an element.
 * `shared/keyboard/keys.ts` has `directionOf(element)` for the second question,
 * and the two are deliberately separate: direction is settable per subtree and
 * a `<bdi dir="auto">` file name inside an LTR page has no locale of its own.
 */
export function directionFor(locale: string): 'ltr' | 'rtl' {
  if (locale === MIRRORED_LOCALE) return 'rtl';
  return RIGHT_TO_LEFT.has(locale.split('-')[0] ?? '') ? 'rtl' : 'ltr';
}

/**
 * Put the locale on `<html>`, where CSS and assistive technology read it.
 *
 * Done at the application entry rather than in an effect inside the provider.
 * An effect would fight anything else that sets direction — a test mounting an
 * RTL subtree, a future `<bdi>` panel — by resetting the document on every
 * mount, and the loser of that fight is whichever ran first.
 */
export function applyDocumentLocale(
  locale: string,
  root: HTMLElement = document.documentElement,
): void {
  root.lang = locale;
  root.dir = directionFor(locale);
}

/**
 * The locale a URL asks for, which is only ever a pseudo-locale.
 *
 * `docs/14 §3` puts real negotiation behind the user preference, the tenant
 * default and `Accept-Language`, and none of that is built. This is not a first
 * step towards it: it accepts the two pseudo tags and nothing else, so when
 * negotiation lands there is no query parameter here that a user could use to
 * override the locale their tenant chose.
 */
export function requestedLocale(search: string): string {
  const requested = new URLSearchParams(search).get('locale');
  return requested !== null && isPseudoLocale(requested) ? requested : SOURCE_LOCALE;
}

export function I18nProvider({
  children,
  locale = SOURCE_LOCALE,
}: {
  children: ReactNode;
  locale?: string;
}) {
  return (
    /* `docs/14 §8` rule 6: a missing translation falls back to en-US and renders
     * normally. It must never render a raw key or an empty element, so the
     * missing-message handler is silenced in production rather than left to
     * react-intl's default console error. The fallback itself is in
     * `messagesForLocale`; this only stops the console noise. */
    <IntlProvider
      locale={locale}
      defaultLocale={SOURCE_LOCALE}
      messages={messagesForLocale(locale)}
      onError={import.meta.env.DEV ? undefined : () => undefined}
    >
      {children}
    </IntlProvider>
  );
}

/** Values a message placeholder may take. Deliberately not `unknown`: an
 *  arbitrary object in a message is how a raw `[object Object]` reaches a user. */
export type MessageValues = Record<string, string | number | Date>;

/**
 * The only way a user-facing string enters a component.
 *
 * Returns a plain string so it can be used for `aria-label` and `title` as well
 * as for text, which `<FormattedMessage>` cannot do — and a component that has
 * to reach for two mechanisms reaches for a literal on the third occasion.
 */
export function useT(): (key: MessageKey, values?: MessageValues) => string {
  const intl = useIntl();
  return (key, values) => intl.formatMessage({ id: key }, values);
}

/**
 * The negotiated locale.
 *
 * Exposed because `Intl.Segmenter` and friends need it and are not part of
 * `react-intl`'s formatter surface — grapheme segmentation for initials, for
 * instance, is locale-sensitive and there is no `intl.formatGraphemes`. Taking
 * it from the provider rather than from `navigator.language` keeps one answer
 * to "what locale is this?" instead of two that drift.
 */
export function useLocale(): string {
  return useIntl().locale;
}
