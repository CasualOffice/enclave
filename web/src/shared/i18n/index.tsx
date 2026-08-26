import type { ReactNode } from 'react';
import { IntlProvider, useIntl } from 'react-intl';
import { catalog, messagesFor, type MessageKey } from './catalog.ts';

/* `react-intl` rather than a hand-rolled substitution map, because `docs/14 §4`
 * requires ICU: plural categories in Slavic, Arabic and South Asian languages
 * cannot be expressed as key/value replacement, and discovering that after two
 * hundred keys exist is the expensive way to learn it. */

export const SOURCE_LOCALE = 'en-US';

const messages = messagesFor(catalog);

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
     * react-intl's default console error. */
    <IntlProvider
      locale={locale}
      defaultLocale={SOURCE_LOCALE}
      messages={messages}
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
