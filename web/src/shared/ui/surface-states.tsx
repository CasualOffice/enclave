import { useState, type ReactNode } from 'react';
import { useT } from '../i18n/index.tsx';
import type { MessageKey } from '../i18n/catalog.ts';
import type { Failure } from '../api/failure.ts';
import { Button, type ControlState } from './primitives.tsx';
import './surface-states.css';

/* The four states every data surface owes, in one place — and only here.
 *
 * `docs/09 §11` requires four states on every surface: empty (new), empty
 * (filtered), loading and error. `docs/17 §7` adds a fifth outcome that is *not*
 * an error and must not look like one. The prototype draws none of them —
 * `web/design-system/enclave-client-prototype.html` shows the success state of
 * every screen and nothing else — so these are designed here, from the
 * prototype's token values, rather than copied from it.
 *
 * ## Why this file is the only implementation
 *
 * It was not. Five features each wrote their own: `features/home/states.tsx`,
 * `features/search/states.tsx`, `features/ask/states.tsx`,
 * `features/admin/states.tsx` and `features/libraries/list/states.tsx` had a
 * private `Figure` helper that was character-for-character identical in four of
 * them, a `-state-title` rule in six stylesheets, a request-ID row in seven, and
 * a local `{ retryable, requestId }` type in four — none of which was
 * `Failure`, which is precisely why none of them could call the shared
 * component that already existed.
 *
 * That is not a tidiness problem. Three of the seven request-ID rules carried
 * `unicode-bidi: isolate; direction: ltr` on the `<code>` and four did not, so
 * the same identifier rendered correctly on three screens and reversed on four.
 * A surface duplicated five times is a surface fixed once and broken four
 * times, and the states are where a user lands when something has already gone
 * wrong — the worst possible place for the treatment to vary by screen.
 *
 * ## The line in this file that is a security control
 *
 * `DeniedPanel` has no retry affordance and none may be added (`docs/17 §7`).
 * A policy denial is a *successful* request with a refusing answer; a retry
 * button turns "you do not have access" into "this product is flaky", which
 * costs the user a support ticket and the operator a bug report instead of an
 * access request. Every word it shows comes from the server: `docs/05 §5`
 * returns `message` and `remediation` already localized and user-safe, and
 * `CLAUDE.md` rule 10 forbids revealing which rule matched, so the client
 * composes nothing and has nothing to compose it from.
 */

/**
 * The three treatments a state block can wear.
 *
 * Deliberately **not** four. There is no `denied` tone, because a denial is
 * drawn in the neutral treatment on purpose: `docs/17 §6` reserves the danger
 * tint for a *control* whose capability the server refused, and a whole surface
 * refused is a fact about access rather than an alarm. Giving it its own red
 * would put the denial treatment on two things that are not the same, which is
 * how a treatment stops meaning one thing.
 */
export type StateTone = 'neutral' | 'error' | 'unbuilt';

/**
 * The 44px mark that heads a state block.
 *
 * One implementation, one `:dir(rtl)` mirror. There were four copies of this
 * square and four copies of the mirror; the geometry (`13.75px` inset, `5.5px`
 * inner radius) is unmemorable enough that nobody would have noticed one of
 * them drifting.
 */
export function StateFigure({ tone = 'neutral' }: { tone?: StateTone }) {
  return <div className="surface-state-figure" data-tone={tone} aria-hidden="true" />;
}

/**
 * A copyable request ID.
 *
 * `docs/09 §11` requires one on every error state, because "it didn't work" and
 * "it didn't work, here is 01a0402d-cb72" are two different support tickets and
 * only one of them is answerable.
 *
 * The `<code>` is direction-isolated. An opaque identifier is not text in the
 * document's language, and under RTL an un-isolated one renders with its
 * segments reversed — so the user copies a correct string and reads a wrong
 * one, which is the worst of both. Four of the seven copies of this row omitted
 * the isolation.
 */
export function RequestId({ requestId }: { requestId: string }) {
  const t = useT();
  const [copied, setCopied] = useState(false);

  if (requestId.length === 0) return null;

  return (
    <p className="surface-state-rid">
      <span className="surface-state-rid-label">{t('surface.error.requestId')}</span>
      <code>{requestId}</code>
      <Button
        label={copied ? 'surface.error.copied' : 'surface.error.copy'}
        variant="ghost"
        size="sm"
        onClick={() => {
          void navigator.clipboard?.writeText(requestId).then(() => setCopied(true));
        }}
      />
    </p>
  );
}

export interface StateBlockProps {
  readonly tone?: StateTone;
  /**
   * The machine-readable name of the state, on `data-state`.
   *
   * Load-bearing beyond styling: `tests/a11y/routes.spec.ts` selects surfaces by
   * it, so `empty` and `filtered-empty` being two values rather than one is what
   * makes the accessibility gate check both rather than whichever one a run
   * happened to reach.
   */
  readonly state: 'empty' | 'filtered-empty' | 'error' | 'denied' | 'unbuilt' | 'step-up';
  readonly heading: MessageKey;
  readonly body?: MessageKey | undefined;
  readonly values?: Record<string, string | number> | undefined;
  /** Rendered as the body instead of `body`, for a sentence the server supplied. */
  readonly bodyText?: string | undefined;
  readonly children?: ReactNode;
  /** `alert` where the state replaces content the user was already looking at. */
  readonly role?: 'alert' | 'status' | undefined;
  /** Set by a surface that fills its own column rather than sitting in a card. */
  readonly fill?: boolean;
}

/**
 * The block itself: figure, heading, body, then whatever the state adds.
 *
 * `fill` is the one geometric choice a caller makes. A state that replaces a
 * whole list column centres itself in that column; a state that sits inside a
 * section card keeps the card's box so the section's measure does not change
 * when it empties. Both were written out by hand in five stylesheets with four
 * different paddings.
 */
export function StateBlock({
  tone = 'neutral',
  state,
  heading,
  body,
  values,
  bodyText,
  children,
  role,
  fill = false,
}: StateBlockProps) {
  const t = useT();
  return (
    <div
      className="surface-state"
      data-tone={tone}
      data-state={state}
      data-fill={fill ? '' : undefined}
      role={role}
      /* Unbuilt leaves the tab order; nothing here can be acted on and there is
       * nothing to find out (`docs/17 §6`). A denial does not — a user must be
       * able to reach the reason. */
      aria-disabled={tone === 'unbuilt' ? true : undefined}
      tabIndex={tone === 'unbuilt' ? -1 : undefined}
    >
      <StateFigure tone={tone} />
      <p className="surface-state-title">{t(heading, values)}</p>
      {bodyText !== undefined ? (
        <p className="surface-state-body">{bodyText}</p>
      ) : (
        body !== undefined && <p className="surface-state-body">{t(body, values)}</p>
      )}
      {children}
    </div>
  );
}

/** The action row under a state block. One gap, one margin, everywhere. */
export function StateActions({ children }: { children: ReactNode }) {
  return <div className="surface-state-actions">{children}</div>;
}

/**
 * Nothing here, and nothing is hiding it.
 *
 * Kept distinct from `FilteredEmptyState` because the two sentences are not
 * interchangeable: telling a user their library is empty while a filter hides
 * forty files sends them looking for a file that is on the screen behind the
 * chip they forgot about. `docs/09 §11` names them as two states and
 * `library.md §C` requires a test that both render.
 */
export function EmptyState({
  heading,
  body,
  values,
  action,
  onAction,
  actionState,
  fill = false,
}: {
  heading: MessageKey;
  body: MessageKey;
  values?: Record<string, string | number> | undefined;
  action?: MessageKey | undefined;
  onAction?: (() => void) | undefined;
  /**
   * The state of the one action that starts this surface.
   *
   * A capability the server refused renders the action **denied and present**,
   * never hidden (`library.md §B`). A hidden control teaches a user the product
   * cannot do the thing; a denied one teaches them they cannot, which is the
   * truth and is actionable.
   */
  actionState?: ControlState | undefined;
  fill?: boolean;
}) {
  return (
    <StateBlock state="empty" heading={heading} body={body} values={values} fill={fill}>
      {action !== undefined && (
        <StateActions>
          <Button
            label={action}
            variant="primary"
            onClick={onAction}
            {...(actionState === undefined ? {} : { state: actionState })}
          />
        </StateActions>
      )}
    </StateBlock>
  );
}

/**
 * The filters, not the folder, are why this is empty.
 *
 * Its action is *clear the filters* and it is styled as the secondary control,
 * not the primary one — the primary action of an empty folder is to put
 * something in it, and offering that here would answer a question the user did
 * not ask.
 */
export function FilteredEmptyState({
  heading,
  body,
  values,
  clearLabel,
  onClear,
  children,
  fill = false,
}: {
  heading: MessageKey;
  body: MessageKey;
  values?: Record<string, string | number> | undefined;
  clearLabel?: MessageKey | undefined;
  onClear?: (() => void) | undefined;
  children?: ReactNode;
  fill?: boolean;
}) {
  return (
    <StateBlock state="filtered-empty" heading={heading} body={body} values={values} fill={fill}>
      {children}
      {clearLabel !== undefined && (
        <StateActions>
          <Button label={clearLabel} onClick={onClear} />
        </StateActions>
      )}
    </StateBlock>
  );
}

/**
 * The minimum a surface needs to render its own error state.
 *
 * Structural rather than nominal on purpose: four features already hold a local
 * `{ retryable, requestId }` and none of them holds a `Failure`. Requiring the
 * nominal type would have meant either five model refactors or five more copies
 * of this component, and the second is what happened last time.
 */
export interface FetchFailure {
  readonly retryable: boolean;
  readonly requestId: string;
}

/**
 * The request did not complete.
 *
 * `docs/09 §11` names the four parts and all four are here: what failed
 * (`heading`), whether it is retryable (from the API client's classification,
 * never guessed), a retry action, and a copyable request ID.
 *
 * Retry is offered **only when the failure is retryable**. A `400` will answer
 * `400` again, and a button promising otherwise is a lie the user pays for in
 * clicks.
 *
 * The three catalog keys are the caller's because the *title* is the one part
 * that is genuinely per-surface — "This list could not be loaded" and "This
 * search could not be run" are different facts. The other four parts are not,
 * and were duplicated five times to carry the one that is.
 */
export function ErrorState({
  heading,
  body,
  bodyFinal,
  retry,
  error,
  onRetry,
  fill = false,
}: {
  heading: MessageKey;
  body: MessageKey;
  bodyFinal: MessageKey;
  retry: MessageKey;
  error: FetchFailure;
  onRetry?: (() => void) | undefined;
  fill?: boolean;
}) {
  return (
    <StateBlock
      tone="error"
      state="error"
      heading={heading}
      body={error.retryable ? body : bodyFinal}
      role="alert"
      fill={fill}
    >
      {error.retryable && onRetry !== undefined && (
        <StateActions>
          <Button label={retry} variant="primary" onClick={onRetry} />
        </StateActions>
      )}
      <RequestId requestId={error.requestId} />
    </StateBlock>
  );
}

/**
 * The request did not complete — for a caller that already holds a `Failure`.
 *
 * The same block as `ErrorState` with this tree's default wording. Kept as a
 * separate export rather than a default parameter because a surface that has a
 * better title should be made to pass one.
 */
export function ErrorPanel({
  failure,
  onRetry,
}: {
  failure: Extract<Failure, { kind: 'failed' }>;
  onRetry?: (() => void) | undefined;
}) {
  return (
    <ErrorState
      heading="surface.error.title"
      body="surface.error.body"
      bodyFinal="surface.error.bodyFinal"
      retry="surface.error.retry"
      error={failure}
      onRetry={onRetry}
    />
  );
}

/**
 * The server answered, and the answer is no.
 *
 * **No retry affordance exists in this component and none may be added.** See
 * the file header; `docs/17 §7` is the rule and `tests/unit/failure-states`
 * is the test that keeps it.
 */
export function DeniedPanel({
  failure,
  fill = false,
}: {
  failure: Extract<Failure, { kind: 'denied' }>;
  fill?: boolean;
}) {
  const t = useT();
  return (
    <StateBlock
      state="denied"
      heading="surface.denied.title"
      bodyText={failure.message.length > 0 ? failure.message : t('surface.denied.noReason')}
      fill={fill}
    >
      {failure.remediation !== undefined && failure.remediation.length > 0 && (
        <p className="surface-state-body">{failure.remediation}</p>
      )}
      <p className="surface-state-code">
        <span className="surface-state-rid-label">{t('surface.denied.codeLabel')}</span>
        <code>{failure.code}</code>
      </p>
    </StateBlock>
  );
}

/**
 * Whatever went wrong, rendered as the right one of the three.
 *
 * The branch is here so no feature has to remember it. A step-up challenge is
 * neither a denial nor a failure and is shown in the denial-shaped block because
 * that is what it is from the surface's point of view — refused pending
 * something the user must do — while carrying its own code so it is never
 * mistaken for a flat refusal.
 */
export function FailureState({
  failure,
  onRetry,
  fill = false,
}: {
  failure: Failure;
  onRetry?: (() => void) | undefined;
  fill?: boolean;
}) {
  if (failure.kind === 'denied') return <DeniedPanel failure={failure} fill={fill} />;

  if (failure.kind === 'stepUp') {
    return (
      <StateBlock
        state="step-up"
        heading="surface.stepUp.title"
        body="surface.stepUp.body"
        fill={fill}
      />
    );
  }

  return <ErrorPanel failure={failure} onRetry={onRetry} />;
}

/**
 * A surface the product does not have yet.
 *
 * Not focusable, neutral, future tense, no remedy, and it may never borrow the
 * denial treatment (`docs/17 §6`, `ENC-673`). The rule is worth its own
 * component because of what erosion costs: if most dimmed things in the product
 * mean *"not written yet"*, users learn that dimmed is background noise — and
 * they learn it on harmless surfaces, then carry the habit to the one where
 * dimmed means DLP refused them.
 */
export function UnbuiltState({
  heading,
  note,
  fill = false,
}: {
  heading: MessageKey;
  note: MessageKey;
  fill?: boolean;
}) {
  const t = useT();
  return (
    <StateBlock tone="unbuilt" state="unbuilt" heading={heading} body={note} fill={fill}>
      <span className="ui-later">{t('later.chip')}</span>
    </StateBlock>
  );
}
