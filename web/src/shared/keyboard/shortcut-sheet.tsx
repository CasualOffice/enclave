import { useEffect, useRef } from 'react';
import { useT } from '../i18n/index.tsx';
import { IconButton, Kbd, LaterChip } from '../ui/primitives.tsx';
import { BINDINGS } from './bindings.ts';
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

  /* Focus moves in on open and the dialog traps `Tab`, which is what makes it a
   * dialog rather than a panel that happens to float. `docs/09 §6`'s last
   * paragraph also requires focus to return to the trigger on close — that is
   * the caller's job, because only the caller knows what opened this, and
   * `use-global-keys.ts` does it. */
  useEffect(() => {
    /* Queried rather than held in a ref, because `IconButton` does not forward
     * one and widening a shared primitive for a single caller is the churn
     * `CLAUDE.md` asks this branch to avoid. */
    dialogRef.current?.querySelector('button')?.focus();
  }, []);

  useEffect(() => {
    const node = dialogRef.current;
    if (node === null) return undefined;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      /* The trap. Queried live rather than captured on mount: nothing in this
       * dialog is conditional today, but a trap built from a stale list is one
       * that silently stops trapping the first time something is. */
      const focusable = node.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (first === undefined || last === undefined) return;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    node.addEventListener('keydown', onKeyDown);
    return () => node.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

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
        <dl className="kbd-sheet-list">
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
