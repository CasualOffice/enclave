import { Children, Fragment, type ReactNode } from 'react';
import { useIntl } from 'react-intl';
import type { MessageKey } from './catalog.ts';

/* A catalog message whose placeholders are React nodes.
 *
 * `useT()` returns a `string` deliberately — it has to serve `aria-label` and
 * `title` as well as text, and a component that reaches for two mechanisms
 * reaches for a literal on the third occasion. But some sentences have their
 * interactive or emphasised parts *inside* the prose: the DLP builder's
 * "Detected data includes any of [Payment card] or [Aadhaar]", where the
 * bracketed parts are controls, and the library's "Group by **Vendor** · Sort
 * **Modified**". A string cannot carry either.
 *
 * The wrong answer is to cut the sentence up and concatenate around the parts.
 * `docs/14 §4` names that as a defect and it bites hardest here: German puts the
 * verb last, Japanese puts the particle after the noun, and a sentence assembled
 * left to right in English is untranslatable rather than merely ugly. So: **one
 * ICU message per sentence shape, with the parts passed as placeholder values.**
 *
 * This began in `features/admin/rich-text.tsx`, whose own header said it
 * belonged in `shared/i18n` and that a second surface wanting it was the signal
 * to move it (`docs/17 §2`). `ENC-757`'s filter-chip summary is that second
 * surface, so it moved rather than being copied.
 */

/**
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
     * reconciles it as a dynamic list and asks for a key on every member — once
     * per parent element, which is a warning on every clause of every band. The
     * index is a safe key here: the parts of a formatted message are positional
     * by construction and never reorder within one locale. */
    return parts.map((part, index) => <Fragment key={index}>{part}</Fragment>);
  };
}
