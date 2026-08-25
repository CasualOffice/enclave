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
  /** The product does not have it yet. Not focusable, neutral, no remedy. */
  | { readonly kind: 'unbuilt'; readonly note: MessageKey }
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
}

export function Button({
  label,
  values,
  icon,
  variant = 'default',
  size = 'md',
  state = READY,
  iconOnly = false,
  ...rest
}: ButtonProps) {
  const t = useT();
  const text = t(label, values);
  const reasonId = state.kind === 'denied' ? `${label}-reason` : undefined;
  const noteId = state.kind === 'unbuilt' ? `${label}-note` : undefined;

  return (
    <>
      <button
        {...rest}
        type="button"
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
        <span id={reasonId} className="ui-sr-only">
          {state.reason}
        </span>
      )}
      {state.kind === 'unbuilt' && (
        <span id={noteId} className="ui-later">
          {t(state.note)}
        </span>
      )}
    </>
  );
}

export interface IconButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children' | 'type'> {
  readonly name: IconName;
  /** The accessible name. An icon-only control without one is unusable. */
  readonly label: MessageKey;
  readonly values?: Record<string, string | number>;
}

export function IconButton({ name, label, values, ...rest }: IconButtonProps) {
  const t = useT();
  return (
    <button {...rest} type="button" className="ui-iconbtn" aria-label={t(label, values)}>
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

export function Skeleton({ width }: { width: string }) {
  return <span className="ui-skeleton" style={{ inlineSize: width }} aria-hidden="true" />;
}

/** Visually hidden, still announced. */
export function ScreenReaderOnly({ children }: { children: ReactNode }) {
  return <span className="ui-sr-only">{children}</span>;
}
