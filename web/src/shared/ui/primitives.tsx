import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { useT } from '../i18n/index.tsx';
import type { MessageKey } from '../i18n/catalog.ts';
import { Icon, type IconName } from './icon-sprite.tsx';
import './primitives.css';

/* The primitive layer. No domain knowledge lives here (`docs/17 §11`).
 *
 * One rule shapes the whole file: **a primitive takes a catalog key, never a
 * string.** `CLAUDE.md` rule 12 says no user-facing literal in `web/src`, and
 * the only reliable way to hold that across six screens and several sessions is
 * to make the literal unrepresentable — `label` is typed as `MessageKey`, so
 * `<Button label="Save" />` does not compile.
 */

export type ButtonVariant = 'default' | 'primary' | 'ghost' | 'soft' | 'danger';

/**
 * Why a control cannot be used. **These are security treatments, not styling.**
 *
 * `docs/17 §6` and `plans/M5-MVP-GA.md` D33: a denial and an unbuilt surface
 * must never look alike, because a user who learns that dimmed means "not
 * written yet" on five harmless surfaces carries the habit to the one place
 * where dimmed means "DLP refused this".
 */
export type ControlState =
  | { readonly kind: 'ready' }
  /** Policy refused it. Focusable, keeps its colour, carries the server's reason. */
  | { readonly kind: 'denied'; readonly reason: string; readonly remedy?: MessageKey }
  /**
   * The product does not have it yet. Not focusable, neutral, no remedy.
   *
   * Two strings, not one. D33 specifies a **short neutral chip** *and* a release
   * note reached through `aria-describedby`, and collapsing them meant either a
   * chip long enough to be a sentence or a description short enough to be
   * useless. `chip` defaults to the shared `Later` marker so a caller only
   * writes the note.
   */
  | { readonly kind: 'unbuilt'; readonly note: MessageKey; readonly chip?: MessageKey }
  /** In flight. Resolves on its own; no reason, because there is nothing to explain. */
  | { readonly kind: 'busy' };

export const READY: ControlState = { kind: 'ready' };

export interface ButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'disabled' | 'type'> {
  /** A catalog key. Typed so a literal cannot be passed (`CLAUDE.md` rule 12). */
  readonly label: MessageKey;
  readonly values?: Record<string, string | number>;
  readonly icon?: IconName;
  readonly variant?: ButtonVariant;
  readonly size?: 'sm' | 'md' | 'lg';
  readonly state?: ControlState;
  /** Hide the label visually, keeping it as the accessible name. */
  readonly iconOnly?: boolean;
  /**
   * `submit` where the control submits a form.
   *
   * Defaulted to `button` and previously hard-coded to it, which meant a form
   * had no submit control and therefore no implicit submission — a two-field
   * sign-in form where `Enter` does nothing. Found by the sign-in session, which
   * had to wire `Enter` by hand.
   */
  readonly type?: 'button' | 'submit';
  /**
   * The id given to the rendered reason or release note.
   *
   * A **public contract**, not an implementation detail: a caller that wants a
   * second control — a text field beside its send button — to share one
   * explanation needs to name the id, and the alternative is repeating the note
   * per control, which is how a marker becomes wallpaper. Defaults to a value
   * derived from `label`; pass it when two controls share one note.
   */
  readonly describedById?: string;
  /** Invoked when a denied control is activated, to surface the remedy. */
  readonly onRemedy?: (() => void) | undefined;
}

export function Button({
  label,
  values,
  icon,
  variant = 'default',
  size = 'md',
  state = READY,
  iconOnly = false,
  type = 'button',
  describedById,
  onRemedy,
  ...rest
}: ButtonProps) {
  const t = useT();
  const text = t(label, values);
  /* Distinct default ids per kind. The two states are mutually exclusive, so
   * one id would have worked — but callers assert against these names, and a
   * shared `-explain` suffix made a denial and a release note indistinguishable
   * in a test that was specifically checking they never are. */
  const reasonId = state.kind === 'denied' ? (describedById ?? `${label}-reason`) : undefined;
  const noteId = state.kind === 'unbuilt' ? (describedById ?? `${label}-note`) : undefined;

  return (
    <>
      <button
        {...rest}
        type={type}
        className="ui-btn"
        data-variant={variant}
        data-size={size}
        data-state={state.kind === 'ready' ? undefined : state.kind}
        /* Never the `disabled` attribute for a denial: a disabled control is
         * removed from the tab order, so a keyboard user cannot reach it to
         * discover *why* — which is the entire point of showing it
         * (`docs/09 §5`, `docs/06 §24`). */
        aria-disabled={state.kind === 'ready' ? undefined : true}
        /* Unbuilt is the one that leaves the tab order, because there is
         * nothing to find out and nothing to do (`docs/17 §6`). */
        tabIndex={state.kind === 'unbuilt' ? -1 : rest.tabIndex}
        aria-busy={state.kind === 'busy' ? true : undefined}
        aria-describedby={reasonId ?? noteId}
        aria-label={iconOnly ? text : rest['aria-label']}
        onClick={state.kind === 'ready' ? rest.onClick : undefined}
      >
        {icon !== undefined && <Icon name={icon} size={size === 'sm' ? 12 : 14} />}
        {!iconOnly && text}
      </button>
      {/* The reason is rendered as text and associated by id. `aria-disabled`
       * plus `title` is not a reliable screen-reader path (`docs/09 §15`), and a
       * tooltip is not a reason a keyboard user can reach. */}
      {state.kind === 'denied' && (
        <span id={reasonId} className="ui-denial">
          <span className="ui-denial-reason">{state.reason}</span>
          {/* **The remedy, rendered.** `docs/09 §5` and D33 both require "reason
           * + one remedy", and this component accepted a `remedy` in its type
           * and dropped it — which made the remedy half of the contract
           * unimplementable by any caller while looking implemented. Found by
           * the Ask session reading the type against the doc. */}
          {state.remedy !== undefined && (
            <button type="button" className="ui-denial-remedy" onClick={onRemedy}>
              {t(state.remedy)}
            </button>
          )}
        </span>
      )}
      {state.kind === 'unbuilt' && (
        <>
          <LaterChip note={state.chip ?? 'later.chip'} />
          {/* The release note, which is what `aria-describedby` points at. Kept
           * separate from the chip so the chip can stay one word and the note
           * can be a sentence — D33 asks for both. */}
          <span id={noteId} className="ui-later-note">
            {t(state.note)}
          </span>
        </>
      )}
    </>
  );
}

/**
 * The neutral marker on a control the product does not have yet.
 *
 * A component rather than a bare `<span className="ui-later">`, because five
 * features hand-writing the same span is exactly how a marker drifts — and this
 * one may not drift: D33's whole cost is that *unbuilt* and *denied* stay
 * distinguishable, and two of five copies picking up a semantic colour is how
 * that erodes.
 */
export function LaterChip({ note, id }: { note: MessageKey; id?: string | undefined }) {
  const t = useT();
  return (
    <span id={id} className="ui-later">
      {t(note)}
    </span>
  );
}

export interface IconButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'type'> {
  readonly name: IconName;
  /** The accessible name. An icon-only control without one is unusable. */
  readonly label: MessageKey;
  readonly values?: Record<string, string | number>;
  /**
   * A toggle's current position.
   *
   * Rendered as `aria-pressed`, and the stylesheet keys the pressed appearance
   * off that same attribute — so what the control looks like and what it
   * announces cannot disagree. `features/libraries` had grown a second
   * 26-line icon button for want of this one prop.
   */
  readonly pressed?: boolean | undefined;
  /**
   * Show only on the parent row's hover or focus.
   *
   * Opacity, never `display:none`: a hidden button is not reachable by
   * keyboard, and the row-actions control is the only way to a row's menu
   * without a pointer. It returns on `:focus-visible`.
   */
  readonly reveal?: boolean;
}

export function IconButton({
  name,
  label,
  values,
  pressed,
  reveal = false,
  ...rest
}: IconButtonProps) {
  const t = useT();
  return (
    <button
      {...rest}
      type="button"
      className="ui-iconbtn"
      aria-pressed={pressed}
      data-reveal={reveal ? '' : undefined}
      aria-label={t(label, values)}
    >
      <Icon name={name} size={14} />
    </button>
  );
}

export type PillTone = 'neutral' | 'info' | 'warn' | 'danger' | 'ok' | 'accent' | 'outline';

export function Pill({
  label,
  values,
  tone = 'neutral',
  icon,
}: {
  label: MessageKey;
  values?: Record<string, string | number>;
  tone?: PillTone;
  icon?: IconName;
}) {
  const t = useT();
  return (
    <span className="ui-pill" data-tone={tone === 'neutral' ? undefined : tone}>
      {icon !== undefined && <Icon name={icon} size={11} />}
      {t(label, values)}
    </span>
  );
}

export type AvatarTone = 'a' | 'b' | 'c' | 'd';

export function Avatar({
  initials,
  tone,
  size = 'md',
}: {
  /** Already-computed initials. Never derived by splitting a name on whitespace
   *  — `docs/14 §6` is explicit that name order is not universal. */
  initials: string;
  tone: AvatarTone;
  size?: 'md' | 'lg';
}) {
  return (
    /* Decorative: every avatar in this product sits beside the name it stands
     * for, so announcing the initials again is noise. */
    <span className="ui-avatar" data-tone={tone} data-size={size} aria-hidden="true">
      {initials}
    </span>
  );
}

export function AvatarStack({ children }: { children: ReactNode }) {
  return <span className="ui-avatar-stack">{children}</span>;
}

/** A keyboard shortcut, shown beside the action it triggers. */
export function Kbd({ children }: { children: string }) {
  return <span className="ui-kbd">{children}</span>;
}

/**
 * A reserved box, shaped like the thing that will land in it.
 *
 * `docs/09 §11` and `docs/17 §8`: the skeleton and the loaded element share a
 * box model, so nothing shifts when data arrives. `shape` is how a caller says
 * which box — a pill-shaped skeleton for a pill, a circle for an avatar —
 * rather than hand-rolling the radius per feature, which is how two of the
 * three previous copies ended up with a square avatar placeholder.
 *
 * Widths are the caller's and should be **deterministic**. A skeleton whose
 * widths reshuffle every render reads as data arriving and then leaving again.
 */
export function Skeleton({
  width,
  shape,
}: {
  width?: string;
  shape?: 'pill' | 'circle' | 'text';
}) {
  return (
    <span
      className="ui-skeleton"
      data-shape={shape}
      style={width === undefined ? undefined : { inlineSize: width }}
      aria-hidden="true"
    />
  );
}

/** Visually hidden, still announced. */
export function ScreenReaderOnly({ children }: { children: ReactNode }) {
  return <span className="ui-sr-only">{children}</span>;
}
