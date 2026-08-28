/* "Put the caret in the search field", across a layer boundary.
 *
 * `/` is a global binding and the field it focuses belongs to
 * `features/search`. `docs/17 §2` forbids `features/` from importing `app/`,
 * and `app/` has no business holding a ref into a screen it renders through
 * `lazy()` — so neither side can reach the other directly, and the honest
 * answer is a one-way announcement that both may legally read.
 *
 * The same gap produced `shared/url-state.ts`, for the same reason and with the
 * same shape: a thing the layering says neither layer owns, put where both may
 * use it. Two sessions reached for `window.location` before that existed; this
 * exists so nobody reaches for `document.querySelector('input[type=search]')`.
 *
 * **Deliberately not a store.** There is no state here — "focus the search
 * field" is an event that happens and is over. Modelling it as state would
 * create the question of when to clear the flag, and the answer would be wrong
 * the first time two things asked in one frame.
 */

export type FocusTarget = 'search';

const listeners = new Map<FocusTarget, Set<() => void>>();

/**
 * Requests that arrived before anything was listening.
 *
 * `/` pressed on the library screen navigates to search, and the search screen
 * is a `lazy()` chunk — so it mounts some frames later, after the keystroke is
 * long gone. Without this the binding would navigate and leave the caret
 * nowhere, which is half a shortcut and the more annoying half: the user is on
 * the right screen and still has to reach for the mouse.
 *
 * Held rather than timed out. A pending request survives until a field mounts
 * to take it, which is observable only by pressing `/`, going somewhere that is
 * not search, and arriving at search later — at which point focusing the search
 * field is what the user asked for anyway.
 */
const pending = new Set<FocusTarget>();

/** Subscribe a field to focus requests. Returns the unsubscribe. */
export function onFocusRequest(target: FocusTarget, listener: () => void): () => void {
  const set = listeners.get(target) ?? new Set<() => void>();
  set.add(listener);
  listeners.set(target, set);
  if (pending.delete(target)) listener();
  return () => {
    set.delete(listener);
  };
}

/**
 * Ask for focus. Returns whether anything was listening.
 *
 * The return value is the whole reason this is not fire-and-forget: `/` pressed
 * on the library screen has to *navigate* to search first, and it can only know
 * that if it can tell "the field took it" from "there is no field on this
 * screen". A silent no-op would make `/` work on one route and do nothing on
 * five.
 */
export function requestFocus(target: FocusTarget): boolean {
  const set = listeners.get(target);
  if (set === undefined || set.size === 0) {
    pending.add(target);
    return false;
  }
  for (const listener of set) listener();
  return true;
}

/** Tests mount and unmount screens in one process; module state has to be resettable. */
export function resetFocusBus(): void {
  listeners.clear();
  pending.clear();
}
