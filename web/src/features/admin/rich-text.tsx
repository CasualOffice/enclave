import { Fragment, type ReactNode } from 'react';
import { useIntl } from 'react-intl';

/* The list joiner this screen needs.
 *
 * `useRichT` used to live here too, with a header saying it belonged in
 * `shared/i18n` and that a second surface wanting it was the signal to move it
 * (`docs/17 §2`). `ENC-757`'s filter-chip summary was that second surface, so it
 * now lives in `shared/i18n/rich-text.tsx` and this file re-exports it for the
 * callers already reaching here.
 *
 * `useListFormat` stays, because it is not general: it emits `.adm-lit` around
 * the separators, which is this screen's styling, and a shared module that knows
 * an admin class name is not shared.
 *
 * The argument for it is `useRichT`'s one level down. A list of chips still
 * needs "and" or "or" between its items, and hard-coding either — or hard-coding
 * a comma — is concatenation wearing a hat: `ja-JP` joins with `、`, `ar` with
 * `و`, and English disjunction has the serial comma that conjunction does not.
 * `Intl.ListFormat.formatToParts` returns the separators as data, so the
 * separators come from the locale and the elements come from us.
 */

export { useRichT } from '../../shared/i18n/rich-text.tsx';

export type ListType = 'conjunction' | 'disjunction';

/**
 * Join rendered nodes the way the active locale joins a list.
 *
 * The trick is to format the *indices* and put our nodes back where the
 * formatter placed them, which keeps `Intl` authoritative over the separators
 * without asking it to understand React.
 */
export function useListFormat(type: ListType): (items: readonly ReactNode[]) => ReactNode {
  const intl = useIntl();
  return (items) => {
    if (items.length === 0) return null;
    const parts = new Intl.ListFormat(intl.locale, { style: 'long', type }).formatToParts(
      items.map((_, index) => String(index)),
    );
    /* Wrapped in a fragment rather than returned as a bare array: the result is
     * handed to `formatMessage` as a placeholder value, and an array in that
     * position reaches React still an array — unkeyed, one warning per clause. */
    return (
      <>
        {parts.map((part, index) =>
          part.type === 'element' ? (
            <Fragment key={index}>{items[Number(part.value)]}</Fragment>
          ) : (
            <span key={index} className="adm-lit">
              {part.value}
            </span>
          ),
        )}
      </>
    );
  };
}
