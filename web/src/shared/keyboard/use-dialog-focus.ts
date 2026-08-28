import { useEffect, type RefObject } from 'react';

/* What makes a floating panel a dialog: focus goes in, stays in, and comes back
 * out where it started.
 *
 * `docs/09 §6`'s last paragraph — "focus returns to the triggering element when
 * a dialog closes" — plus the half it takes for granted, which is that focus
 * cannot wander out of an open modal in the first place. The return journey is
 * the caller's, because only the caller knows what opened the dialog.
 *
 * ## Why the trap is a `focusin` listener and not only a `Tab` handler
 *
 * Intercepting `Tab` and wrapping between the first and last focusable element
 * is the textbook implementation, and it was the first one here. It leaked: the
 * shortcut sheet holds exactly one focusable control, so "first" and "last" are
 * the same node, and the wrap that should have been a no-op did not hold —
 * `Tab` reached the theme toggle in the sidebar behind the scrim. Whatever the
 * precise cause, the shape of the bug is the point: a trap built out of *what
 * the user pressed* has to correctly predict every route focus can take, and
 * there are more of them than anyone enumerates. `Tab`, `Shift+Tab`, a
 * screen-reader's own navigation, a click on the page behind, and the
 * browser's address bar returning focus to the document all end the same way —
 * with a `focusin` somewhere it should not be.
 *
 * So this watches the *outcome* rather than the cause. Anything that lands
 * focus outside the dialog is pulled straight back to the first control inside
 * it. One rule, no enumeration, and it cannot be defeated by a key combination
 * nobody thought of.
 *
 * The `Tab` handler stays, for order rather than containment: without it `Tab`
 * from the last control would bounce to the *first* by way of the correction,
 * which works but flickers through an element outside the dialog.
 */

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

export function useDialogFocus(ref: RefObject<HTMLElement | null>, onClose: () => void): void {
  /* Focus lands inside on open. Queried rather than held in a second ref: the
   * dialog owns its own first control, and a caller passing the wrong one is a
   * bug that only shows up for keyboard users. */
  useEffect(() => {
    ref.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
  }, [ref]);

  useEffect(() => {
    const node = ref.current;
    if (node === null) return undefined;
    const doc = node.ownerDocument;

    const onFocusIn = (event: FocusEvent) => {
      const target = event.target;
      if (!(target instanceof Node) || node.contains(target)) return;
      node.querySelector<HTMLElement>(FOCUSABLE)?.focus();
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        /* Stopped as well as prevented. `Esc` also means "close the details
         * panel" on the library screen underneath, and one press must not do
         * both — `docs/09 §6` lists them in order for exactly that reason. */
        event.preventDefault();
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      /* Queried live rather than captured on mount: nothing in these dialogs is
       * conditional today, but a list captured once is one that silently stops
       * being right the first time something is. */
      const focusable = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (first === undefined || last === undefined) return;
      if (event.shiftKey && doc.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && doc.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    doc.addEventListener('focusin', onFocusIn);
    node.addEventListener('keydown', onKeyDown);
    return () => {
      doc.removeEventListener('focusin', onFocusIn);
      node.removeEventListener('keydown', onKeyDown);
    };
  }, [ref, onClose]);
}
