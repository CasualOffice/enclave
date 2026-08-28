/* Reading a `KeyboardEvent`: the three questions every handler asks.
 *
 * Pure and DOM-light on purpose. The interesting failures here — a shortcut
 * that fires while the user is typing a filename, an arrow key that moves the
 * wrong way in Hebrew — are cheaper to pin down in a unit test than in a
 * browser, and each of them has one.
 */

/** What an arrow key means once writing direction is taken into account. */
export type Along = 'forward' | 'backward';

/**
 * Is the event coming from somewhere the user is composing text?
 *
 * Every single-letter binding in `docs/09 §6` — `/`, `J`, `K`, `R`, `M`, `C`,
 * `S`, `L`, `I`, `?` — is a character somebody will type into the search field
 * within a minute of the product loading. A global handler that does not ask
 * this question turns "rename" into a key that cannot be typed.
 *
 * `contenteditable` and `role="textbox"` are checked as well as the three tag
 * names, because the rich-text editor in `features/admin` is the first and is
 * not an `<input>`.
 */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (target.isContentEditable) return true;
  return target.getAttribute('role') === 'textbox';
}

/**
 * The platform's command modifier.
 *
 * `docs/09 §5` writes the binding as "`⌘K` / `Ctrl+K`", so both are accepted
 * rather than sniffing the platform: a user on a Mac with an external PC
 * keyboard presses whichever one their fingers know, and a `navigator.platform`
 * test — which is deprecated, and which lies inside every browser's
 * anti-fingerprinting work — gets that user wrong.
 */
export function isMod(event: Pick<KeyboardEvent, 'metaKey' | 'ctrlKey'>): boolean {
  return event.metaKey || event.ctrlKey;
}

/**
 * The writing direction in force at `element`.
 *
 * Computed rather than read off `document.documentElement.dir`, because
 * direction is inheritable and settable per subtree: a `dir="rtl"` panel inside
 * an LTR page is legal and `docs/14 §7` relies on exactly that for bidi file
 * names. Falls back to `ltr` when there is no view — jsdom without a layout,
 * and server rendering.
 */
export function directionOf(element: Element | null): 'ltr' | 'rtl' {
  if (element === null) return 'ltr';
  const view = element.ownerDocument.defaultView;
  if (view === null) return 'ltr';
  return view.getComputedStyle(element).direction === 'rtl' ? 'rtl' : 'ltr';
}

/**
 * `ArrowLeft`/`ArrowRight` resolved **along the writing direction**, not across
 * the screen.
 *
 * `docs/09 §6` binds `→ ←` to "expand/collapse in tree; next/previous column in
 * grid", and *next* in Arabic or Hebrew is the key labelled `ArrowLeft`. A tree
 * that expands on the physical right key is one where a right-to-left user
 * collapses a group by trying to open it — the direct keyboard equivalent of
 * the physical `margin-left` this repository already bans in CSS, and the
 * reason `CLAUDE.md` rule 12's last clause is called out for this row
 * specifically. CI runs an `en-XB` mirrored locale.
 *
 * Vertical arrows are direction-independent: no script this product supports
 * writes top-to-bottom, and inventing a rule for one would be worse than not
 * having it.
 */
export function alongDirection(key: string, direction: 'ltr' | 'rtl'): Along | undefined {
  if (key === 'ArrowRight') return direction === 'rtl' ? 'backward' : 'forward';
  if (key === 'ArrowLeft') return direction === 'rtl' ? 'forward' : 'backward';
  return undefined;
}
