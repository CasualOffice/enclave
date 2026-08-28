import type {
  ButtonHTMLAttributes,
  HTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
} from 'react';
import { useT } from '../i18n/index.tsx';
import type { MessageKey } from '../i18n/catalog.ts';
import { Icon, type IconName } from './icon-sprite.tsx';
import './layout.css';

/* The surfaces every screen assembles itself out of.
 *
 * `shared/ui/primitives.tsx` holds the *controls* — button, pill, avatar, kbd.
 * This file holds the *containers*: the card a section sits in, the bar a
 * toolbar sits on, the row a list is made of, the popover a menu opens into,
 * the field an input lives in. Between them they are what
 * `docs/17 §11`'s "`shared/ui` holds primitives only" was always describing;
 * before this file existed the layer was five files and the containers were
 * written out per feature.
 *
 * The count that made the case: the raised-card recipe
 * (`border-radius: var(--r-surf); box-shadow: var(--hairline); background:
 * var(--sheet)`) appeared by hand in **thirteen** places across six
 * stylesheets. The trailing-spacer idiom `margin-inline-start: auto` appeared
 * **eighteen** times across eight files. The truncation idiom appeared
 * **fourteen** times. None of those is a design decision at its call site; each
 * is a decision made once, restated until it drifts.
 *
 * ## What every component here owes
 *
 * 1. Geometry from a token, never a literal (`styles/scale.css`).
 * 2. Logical properties only — `en-XB` mirrors direction in CI (`docs/17 §8`).
 * 3. A `MessageKey` wherever a user-facing string could appear, so
 *    `CLAUDE.md` rule 12 is enforced by the type rather than by review.
 * 4. No domain knowledge. A component that knows what a classification is
 *    belongs in `entities/` (`docs/17 §11`).
 */

/* -------------------------------------------------------------------- card */

/**
 * A raised surface: the sheet, a hairline, and the surface radius.
 *
 * `tone` is `sunken` for a well the eye should read as *behind* the page rather
 * than on it — a notice, a preview placeholder, a read-only excerpt. It is not
 * a severity: a sunken card is not a warning, and nothing here paints a
 * semantic colour.
 */
export function Card({
  children,
  tone = 'raised',
  padded = true,
  className,
}: {
  children: ReactNode;
  tone?: 'raised' | 'sunken' | 'flat';
  padded?: boolean;
  className?: string;
}) {
  return (
    <div
      className={className === undefined ? 'ui-card' : `ui-card ${className}`}
      data-tone={tone}
      data-padded={padded ? '' : undefined}
    >
      {children}
    </div>
  );
}

/**
 * A horizontal band of controls — a location bar, a view bar, a panel header.
 *
 * `size` picks between the two the reference uses: `--bar-h` (38px minimum, the
 * location bar) and the shorter unconstrained band a view bar sits in. The
 * three byte-identical copies of the first were in `library.css` twice and
 * `ask.css` once.
 */
export function Bar({
  children,
  size = 'md',
  as: Tag = 'div',
  className,
  ...rest
}: {
  children: ReactNode;
  size?: 'sm' | 'md';
  as?: 'div' | 'header' | 'nav';
  className?: string;
} & Omit<HTMLAttributes<HTMLElement>, 'className' | 'children'>) {
  return (
    <Tag
      {...rest}
      className={className === undefined ? 'ui-bar' : `ui-bar ${className}`}
      data-size={size}
    >
      {children}
    </Tag>
  );
}

/**
 * Everything after this goes to the trailing edge.
 *
 * The eighteen hand-written `margin-inline-start: auto` declarations, as one
 * element. Rendering an empty span rather than putting the margin on the next
 * child means the caller does not have to know which child is first in the
 * trailing group — which is the detail that got mis-stated twice.
 */
export function Push() {
  return <span className="ui-push" aria-hidden="true" />;
}

/* ------------------------------------------------------------------ eyebrow */

/**
 * The small capitalised label above a section.
 *
 * **The uppercase is a CSS transform behind a `:lang()` allowlist, never a
 * catalog string.** `docs/14` is explicit: Turkish dotted i, Greek accent
 * stripping and locales with no case at all make a blanket
 * `text-transform: uppercase` wrong, and a catalog holding "NEEDS YOUR
 * ATTENTION" makes it untranslatable. The transform is applied for the locales
 * where it is correct and skipped elsewhere; the sentence-case original is what
 * a screen reader announces either way.
 */
export function Eyebrow({
  label,
  values,
  children,
}: {
  label: MessageKey;
  values?: Record<string, string | number>;
  children?: ReactNode;
}) {
  const t = useT();
  return (
    <h2 className="ui-eyebrow">
      <span className="ui-eyebrow-text">{t(label, values)}</span>
      {children}
    </h2>
  );
}

/* --------------------------------------------------------------------- row */

/**
 * One line of a list: a nav link, a menu item, a picker entry, a result.
 *
 * There were four implementations — `.shell-navlink`, `.adm-nav-link`,
 * `.lib-picker-lib`, `.esr-chip-menuitem` — agreeing on eleven declarations and
 * differing on the twelfth. Three of them also carried the "not built yet"
 * variant, and one of those three added `opacity: .5` while the other two
 * deliberately did not, which is exactly the drift `docs/17 §6` forbids: the
 * unbuilt treatment may not vary by screen, because a user calibrates on it.
 *
 * `current` renders `aria-current="page"`; `unbuilt` renders the non-focusable
 * neutral treatment. There is intentionally **no `denied` variant** — a denied
 * row is a control, and a control's denial is `Button`'s `ControlState`, which
 * keeps the reason and the focusability that a row cannot carry.
 */
export interface RowProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'className' | 'type'> {
  readonly children: ReactNode;
  readonly current?: boolean;
  readonly unbuilt?: boolean;
  readonly indent?: boolean;
}

export function Row({
  children,
  current = false,
  unbuilt = false,
  indent = false,
  ...rest
}: RowProps) {
  /* An unbuilt row is rendered as a `<span>`, not as a `<button>` that has been
   * taken out of the tab order.
   *
   * `docs/17 §6` says unbuilt is **not focusable**, and the honest way to say
   * that is to not render a control at all. A `<button tabindex="-1">` is still
   * a button to the accessibility tree — announced as actionable, and reachable
   * through a screen reader's control rotor, which does not consult `tabindex`.
   * Announcing "button" for something that will never do anything is the same
   * lie as rendering it enabled.
   *
   * `pointer-events: none` would have been shorter and is wrong twice: it also
   * removes the element from hit-testing for assistive technology, and it
   * leaves a keyboard `Enter` handler attached behind it. */
  const shared = {
    className: 'ui-row',
    'data-indent': indent ? '' : undefined,
    'aria-current': current ? ('page' as const) : undefined,
  };

  if (unbuilt) {
    return (
      <span {...shared} data-unbuilt="" aria-disabled="true">
        {children}
      </span>
    );
  }

  return (
    <button {...rest} type="button" {...shared}>
      {children}
    </button>
  );
}

/** A row's text, held to one line with an ellipsis. Fourteen hand-written copies. */
export function Truncate({ children }: { children: ReactNode }) {
  return <span className="ui-truncate">{children}</span>;
}

/* ----------------------------------------------------------------- popover */

/**
 * A floating surface: a menu, a filter editor, the upload tray.
 *
 * Two hand-rolled copies agreed on `z-index: 20` by coincidence — the ladder
 * was prose in a comment, so neither author could read it. It is
 * `var(--z-popover)` now, from `styles/scale.css`.
 *
 * The caller owns positioning, because a popover's anchor is the caller's
 * business and a component that guesses it is a component every caller fights.
 * What is owned here is what must not vary: the elevation, the radius, the
 * padding, and the entrance.
 */
export function Popover({
  children,
  label,
  role = 'menu',
  className,
}: {
  children: ReactNode;
  /** The accessible name. A floating surface without one is an unnamed dialog. */
  label: MessageKey;
  role?: 'menu' | 'dialog' | 'listbox';
  className?: string;
}) {
  const t = useT();
  return (
    <div
      className={className === undefined ? 'ui-popover' : `ui-popover ${className}`}
      role={role}
      aria-label={t(label)}
    >
      {children}
    </div>
  );
}

/* -------------------------------------------------------------------- tabs */

/**
 * A strip of pill tabs — saved views, the peek panel's five tabs, a segmented
 * control.
 *
 * Three copies, all agreeing on `padding-block: 4px; padding-inline: 9px;
 * border-radius: 999px` and none sharing a line. One of them
 * (`.library-peek-tab`) was declared twice in its own file, a merge artefact
 * that had survived because nobody reads a stylesheet end to end.
 */
export function TabList({ children, label }: { children: ReactNode; label: MessageKey }) {
  const t = useT();
  return (
    <div className="ui-tablist" role="tablist" aria-label={t(label)}>
      {children}
    </div>
  );
}

export function Tab({
  label,
  values,
  selected,
  count,
  unbuilt = false,
  ...rest
}: {
  label: MessageKey;
  values?: Record<string, string | number>;
  selected: boolean;
  /** Already formatted through `Intl.NumberFormat` by the caller. */
  count?: string | undefined;
  unbuilt?: boolean;
} & Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'className' | 'type'>) {
  const t = useT();
  return (
    <button
      {...rest}
      type="button"
      className="ui-tab"
      role="tab"
      aria-selected={selected}
      aria-disabled={unbuilt ? true : undefined}
      data-unbuilt={unbuilt ? '' : undefined}
      tabIndex={unbuilt ? -1 : selected ? 0 : -1}
      onClick={unbuilt ? undefined : rest.onClick}
    >
      {t(label, values)}
      {count !== undefined && <span className="ui-tab-count">{count}</span>}
    </button>
  );
}

/* ------------------------------------------------------------------- field */

/**
 * A text input and its focus ring.
 *
 * Five inputs in the tree carried **three incompatible focus treatments** — a
 * two-layer `box-shadow`, an `outline` at `+2px` offset, and an `outline` at
 * `-2px`. `docs/09 §15` requires a visible focus indicator at 3:1, and three
 * indicators for one concept means a keyboard user relearns the affordance per
 * screen. One ring, on the wrapper, driven by `:focus-within` so it appears
 * whether the caller focuses the input or a control inside the field.
 *
 * `icon` renders a leading glyph; `trailing` takes a clear button or a shortcut
 * chip. The `<input>` itself is transparent and borderless — the field draws
 * the box, so a field with a button in it does not have two boxes.
 */
export function Field({
  label,
  icon,
  trailing,
  size = 'md',
  ...rest
}: {
  /** The accessible name, from the catalog. Never a placeholder — a placeholder
   *  disappears on first keystroke and is not a label (`docs/09 §15`). */
  label: MessageKey;
  icon?: IconName;
  trailing?: ReactNode;
  size?: 'sm' | 'md' | 'lg';
} & Omit<InputHTMLAttributes<HTMLInputElement>, 'className' | 'size'>) {
  const t = useT();
  return (
    <div className="ui-field" data-size={size}>
      {icon !== undefined && <Icon name={icon} size={14} className="ui-field-icon" />}
      <input {...rest} className="ui-field-input" aria-label={t(label)} />
      {trailing}
    </div>
  );
}
