import { Children, Fragment, type ReactNode } from 'react';
import { useIntl } from 'react-intl';
import type { MessageKey } from '../../shared/i18n/catalog.ts';

/* Two formatters this screen needs and `shared/i18n` does not have yet.
 *
 * **Why they are here and not there.** `useT()` is typed to return a `string`,
 * deliberately — it has to serve `aria-label` and `title` as well as text, and a
 * component that reaches for two mechanisms reaches for a literal on the third
 * occasion. That is the right default. But the policy-as-a-sentence builder is
 * the one surface where the *interactive* parts sit inside the prose: "Detected
 * data includes any of [Payment card] or [Aadhaar]", where the bracketed parts
 * are controls. A string cannot carry a control.
 *
 * The wrong answer is to cut the sentence into fragments and concatenate them
 * around the chips. `docs/14 §4` names that as a defect — `"Deleted " + n + "
 * files"` — and the reason bites hardest exactly here: word order moves. German
 * puts the verb last, Japanese puts the particle after the noun, and a builder
 * assembled left-to-right in English is untranslatable rather than merely ugly.
 *
 * So: **one ICU message per sentence shape, with the controls passed as
 * placeholder values.** The translator moves `{categories}` to wherever their
 * language wants it and the chips follow. Nothing is concatenated.
 *
 * `useListFormat` is the same argument one level down. A list of chips still
 * needs "and" or "or" between its items, and hard-coding either — or hard-coding
 * a comma — is concatenation wearing a hat: `ja-JP` joins with `、`, `ar` with
 * `و`, and English disjunction has the serial comma that conjunction does not.
 * `Intl.ListFormat.formatToParts` returns the separators as data, so the
 * separators come from the locale and the elements come from us.
 *
 * Both belong in `shared/i18n` — a second surface wanting them is the signal
 * (`docs/17 §2`) — and are reported rather than moved, because `shared/` is not
 * this session's to change.
 */

/**
 * A catalog message whose placeholders are React nodes.
 *
 * `Children.toArray` keys the parts: `formatMessage` returns a bare array when
 * any value is an element, and an unkeyed array is a console warning on every
 * render.
 */
export function useRichT(): (key: MessageKey, values: Record<string, ReactNode>) => ReactNode {
  const intl = useIntl();
  return (key, values) => {
    const parts = Children.toArray(intl.formatMessage({ id: key }, values) as ReactNode);
    /* Keyed explicitly rather than left to `Children.toArray` alone. The array
     * `formatMessage` hands back is not one React created from JSX, so React
     * reconciles it as a dynamic list and asks for a key on every member —
     * once per parent element, which is a warning on every clause of every
     * band. The index is a safe key here: the parts of a formatted message are
     * positional by construction and never reorder within one locale. */
    return parts.map((part, index) => <Fragment key={index}>{part}</Fragment>);
  };
}

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
