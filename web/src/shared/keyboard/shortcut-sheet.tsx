import { useRef } from 'react';
import { useT } from '../i18n/index.tsx';
import { IconButton, Kbd, LaterChip } from '../ui/primitives.tsx';
import { BINDINGS } from './bindings.ts';
import { useDialogFocus } from './use-dialog-focus.ts';
import './keyboard.css';

/* `?` — the keyboard shortcut reference (`docs/09 §6`).
 *
 * It renders `BINDINGS` in order, which is `docs/09 §6`'s own order, so a
 * reader can hold the document beside the sheet and see that nothing was
 * dropped. That is the point of it being one array: `docs/09 §5` requires every
 * command to advertise its shortcut, and a second hand-maintained list is how a
 * product ends up advertising a binding it no longer has.
 *
 * ## The four states
 *
 * `docs/09 §11` asks every surface for empty, loading, error and success. This
 * one has **success only**, and that is a statement rather than an omission:
 * the sheet reads a compile-time constant. It performs no I/O, so there is
 * nothing to be loading; the array cannot be empty, because a build with an
 * empty keyboard map does not compile past `BindingId`; and there is no request
 * to fail. Giving it a spinner and a retry button would be inventing three
 * states it can never reach — the same class of untruth as an error state that
 * cannot fire. `tests/unit/shortcut-sheet.test.tsx` asserts the array is
 * non-empty so that "it cannot be empty" is checked rather than asserted.
 *
 * A *deferred* binding is not a fifth state. It is the unbuilt treatment
 * (`plans/M5-MVP-GA.md` D33): a neutral `Later` chip and a sentence in the
 * future tense about the product. Never the denial treatment — nothing has been
 * refused, and a user who learns that dimmed means "not written yet" must not
 * meet the same grey where it means "DLP said no" (`ENC-673`).
 */

export function ShortcutSheet({ onClose }: { onClose: () => void }) {
  const t = useT();
  const dialogRef = useRef<HTMLDivElement | null>(null);

  /* Focus in on open, trapped while open, and `Esc` closes — one implementation
   * shared with the palette. Focus *returning* to whatever opened the dialog is
   * the caller's job (`app/keyboard.tsx`), because only the caller knows what
   * that was. */
  useDialogFocus(dialogRef, onClose);

  return (
    <div className="kbd-scrim" data-surface="shortcuts">
      <div
        className="kbd-sheet enc-enter-pop"
        role="dialog"
        aria-modal="true"
        aria-labelledby="kbd-sheet-title"
        ref={dialogRef}
      >
        <div className="kbd-sheet-head">
          <div>
            <h2 id="kbd-sheet-title">{t('kbd.sheet.title')}</h2>
            <p className="kbd-sheet-intro">{t('kbd.sheet.intro')}</p>
          </div>
          <IconButton name="x" label="kbd.sheet.close" onClick={onClose} />
        </div>

        {/* A definition list, not a table. There are no columns to compare down
          * — every row is one term and its meaning — and a `<table>` would make
          * a screen reader announce coordinates for a two-column layout that
          * has no second dimension. The visible column headings are the same
          * two words, so the layout still reads as a table to the eye. */}
        <div className="kbd-sheet-cols" aria-hidden="true">
          <span>{t('kbd.sheet.column.keys')}</span>
          <span>{t('kbd.sheet.column.action')}</span>
        </div>
        {/* Focusable, because it scrolls.
          *
          * The list is taller than the sheet and none of its content is
          * focusable — every row is text — so a keyboard user could open the
          * sheet and never reach the bindings past the fold. axe caught it
          * (`scrollable-region-focusable`), which is the one class of keyboard
          * defect it *can* catch: it is a property of the static tree rather
          * than of what happens when a key is pressed.
          *
          * No `role` override. `role="group"` was the first attempt and axe
          * rejected it immediately — it takes the description-list semantics
          * off the element, and every `<dt>`/`<dd>` inside then has no `<dl>`
          * parent (`dlitem`, 28 nodes). A `<dl>` already has a role; it did not
          * need a different one, only a name and a tab stop. */}
        <dl className="kbd-sheet-list" aria-label={t('kbd.sheet.title')} tabIndex={0}>
          {BINDINGS.map((binding) => (
            <div
              key={binding.id}
              className="kbd-sheet-row"
              data-state={binding.state}
              data-binding={binding.id}
            >
              <dt>
                <Kbd>{t(binding.keys)}</Kbd>
              </dt>
              <dd>
                {t(binding.action)}
                {binding.state === 'later' && (
                  <>
                    <LaterChip note="later.chip" />
                    {binding.note !== undefined && (
                      <span className="kbd-sheet-note">{t(binding.note)}</span>
                    )}
                  </>
                )}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}
