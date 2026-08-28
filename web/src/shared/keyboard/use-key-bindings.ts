import { useEffect, useRef } from 'react';
import { isMod, isTypingTarget } from './keys.ts';

/* One document-level listener, shared by everything that owns a global binding.
 *
 * ## Why a hook and not one big handler in `app/`
 *
 * `docs/09 §6` binds `I` and `⌘\` to the details panel and `Esc` to closing it,
 * and the panel's state is a query parameter the library screen owns. A single
 * handler in `app/` could only act on it by inventing a sentinel — writing
 * `peek=first` and hoping the screen knows what that means — which puts a
 * private protocol in a URL that `docs/09 §3` promises is shareable. Each
 * binding is registered by whoever holds the state it changes, and this is the
 * one piece of machinery they share.
 *
 * ## The guard
 *
 * **An unmodified binding never fires while the user is typing.** `/`, `I`, `J`
 * and `?` are all characters somebody will put in the search field within a
 * minute, and a global handler without this makes them unt6ypeable. Two
 * exceptions, both deliberate:
 *
 *   - `Escape` fires everywhere, because it is how a user leaves a field;
 *   - a `⌘`-modified binding fires everywhere, because `⌘K` in a text field is
 *     still the palette on every product that has one.
 *
 * ## Ordering between subscribers
 *
 * Handlers run in registration order and any of them may claim the event by
 * calling `preventDefault`; a claimed event is not offered to the rest. That is
 * what lets `Esc` mean "close the panel" on the library screen and "close the
 * dialog" when a dialog is open, without either knowing about the other — the
 * dialog is mounted later, registers later, and stops the event first because
 * it also stops propagation at its own root.
 */

/**
 * A binding, as a string.
 *
 * `mod+k`, `mod+\`, `/`, `?`, `Escape`, `i`. `mod` is `⌘` or `Ctrl` — both,
 * because `docs/09 §5` writes the binding as "⌘K / Ctrl+K" and a
 * `navigator.platform` test gets a Mac with a PC keyboard wrong.
 */
export type KeySpec = string;

export type KeyHandlers = Readonly<Record<KeySpec, (event: KeyboardEvent) => void>>;

/** Does `event` match `spec`? Exported because it is the part worth testing. */
export function matchesSpec(spec: KeySpec, event: KeyboardEvent): boolean {
  const wantsMod = spec.startsWith('mod+');
  const key = wantsMod ? spec.slice(4) : spec;
  if (wantsMod !== isMod(event)) return false;
  if (event.altKey) return false;
  /* Letters are compared case-insensitively: `⌘⇧A` and caps lock both report
   * the upper-case character, and a user with caps lock on has not asked for a
   * different command. Everything else — `/`, `?`, `\`, `Escape` — is compared
   * exactly, because for those the shifted and unshifted characters *are*
   * different bindings. */
  return key.length === 1 && /[a-z]/i.test(key)
    ? event.key.toLowerCase() === key.toLowerCase()
    : event.key === key;
}

export function useKeyBindings(handlers: KeyHandlers, enabled = true): void {
  /* A ref so that a handler closing over fresh state does not tear down and
   * re-add the listener on every render — which would drop keystrokes that
   * arrive during the gap, rarely and unreproducibly. */
  const latest = useRef(handlers);
  latest.current = handlers;

  useEffect(() => {
    if (!enabled) return undefined;

    const onKeyDown = (event: KeyboardEvent) => {
      /* Somebody nearer the event already claimed it — a dialog's own `Escape`,
       * or the grid's arrow keys. */
      if (event.defaultPrevented) return;

      const typing = isTypingTarget(event.target);
      for (const [spec, handler] of Object.entries(latest.current)) {
        if (!matchesSpec(spec, event)) continue;
        if (typing && !spec.startsWith('mod+') && spec !== 'Escape') continue;
        handler(event);
        if (event.defaultPrevented) return;
      }
    };

    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [enabled]);
}
