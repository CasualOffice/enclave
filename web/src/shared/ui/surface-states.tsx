import { useState, type ReactNode } from 'react';
import { useT } from '../i18n/index.tsx';
import type { MessageKey } from '../i18n/catalog.ts';
import type { Failure } from '../api/failure.ts';
import { Button } from './primitives.tsx';
import './surface-states.css';

/* The panels every data surface needs, in one place.
 *
 * `docs/09 §11` requires four states on every surface — empty (new), empty
 * (filtered), loading and error — and `docs/17 §7` adds a fifth outcome that is
 * *not* an error and must not look like one. The prototype draws none of them:
 * `web/design-system/enclave-client-prototype.html` shows only the success
 * state of every screen, on every screen. So these are designed here, from the
 * prototype's token values, rather than copied from it.
 *
 * The single most important line in this file is the absence of a retry button
 * from `DeniedPanel`. That is not a styling choice — see `docs/17 §7`.
 */

function Panel({
  tone,
  title,
  children,
}: {
  tone: 'neutral' | 'error';
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="surface-state" data-tone={tone}>
      <p className="surface-state-title">{title}</p>
      {children}
    </div>
  );
}

/**
 * The request did not complete.
 *
 * Carries the request ID because a user reporting "it didn't work" and a user
 * reporting "it didn't work, here is 01a0402d-cb72" are two very different
 * support tickets, and only one of them is answerable (`docs/09 §11`).
 *
 * Retry is offered **only when the failure is retryable**. A `400` will answer
 * `400` again; a button that promises otherwise is a lie the user pays for.
 */
export function ErrorPanel({
  failure,
  onRetry,
}: {
  failure: Extract<Failure, { kind: 'failed' }>;
  onRetry?: (() => void) | undefined;
}) {
  const t = useT();
  const [copied, setCopied] = useState(false);

  return (
    <Panel tone="error" title={t('surface.error.title')}>
      <p className="surface-state-body">
        {t(failure.retryable ? 'surface.error.body' : 'surface.error.bodyFinal')}
      </p>
      <div className="surface-state-actions">
        {failure.retryable && onRetry !== undefined && (
          <Button label="surface.error.retry" onClick={onRetry} />
        )}
        {failure.requestId.length > 0 && (
          <span className="surface-state-rid">
            <span className="surface-state-rid-label">{t('surface.error.requestId')}</span>
            <code>{failure.requestId}</code>
            <Button
              label={copied ? 'surface.error.copied' : 'surface.error.copy'}
              variant="ghost"
              size="sm"
              onClick={() => {
                void navigator.clipboard?.writeText(failure.requestId).then(() => setCopied(true));
              }}
            />
          </span>
        )}
      </div>
    </Panel>
  );
}

/**
 * The server answered, and the answer is no.
 *
 * **No retry affordance exists in this component and none may be added.**
 * `docs/17 §7`: a policy denial is a successful request with a refusing answer,
 * and a retry button turns "you do not have access" into "this product is
 * flaky" — which is worse for the user and worse for the operator, who now
 * fields a bug report instead of an access request.
 *
 * Every word shown comes from the server. `docs/05 §5` returns `message` and
 * `remediation` already localized and already user-safe, and `CLAUDE.md` rule 10
 * forbids revealing which rule matched — so the client composes nothing here and
 * has nothing to compose it from. The code is shown because it is what a user
 * quotes when they ask for the access.
 */
export function DeniedPanel({ failure }: { failure: Extract<Failure, { kind: 'denied' }> }) {
  const t = useT();
  return (
    <Panel tone="neutral" title={t('surface.denied.title')}>
      <p className="surface-state-body">
        {failure.message.length > 0 ? failure.message : t('surface.denied.noReason')}
      </p>
      {failure.remediation !== undefined && failure.remediation.length > 0 && (
        <p className="surface-state-body">{failure.remediation}</p>
      )}
      <p className="surface-state-code">
        <span className="surface-state-rid-label">{t('surface.denied.codeLabel')}</span>
        <code>{failure.code}</code>
      </p>
    </Panel>
  );
}

/**
 * Whatever went wrong, rendered as the right one of the two.
 *
 * The branch is here so that no feature has to remember it. A step-up challenge
 * is neither, and is shown as a denial-shaped panel because that is what it is
 * from the surface's point of view — the request was refused pending something
 * the user must do — while carrying its own code so it is never mistaken for a
 * flat refusal.
 */
export function FailureState({
  failure,
  onRetry,
}: {
  failure: Failure;
  onRetry?: (() => void) | undefined;
}) {
  const t = useT();

  if (failure.kind === 'denied') return <DeniedPanel failure={failure} />;

  if (failure.kind === 'stepUp') {
    return (
      <Panel tone="neutral" title={t('surface.stepUp.title')}>
        <p className="surface-state-body">{t('surface.stepUp.body')}</p>
      </Panel>
    );
  }

  return <ErrorPanel failure={failure} onRetry={onRetry} />;
}

/**
 * Nothing here, and nothing is hiding it.
 *
 * Kept distinct from `FilteredEmptyState` below because the two sentences are
 * not interchangeable: telling a user their library is empty when a filter is
 * hiding forty files sends them to look for a file that is on the screen behind
 * the filter chip they forgot about.
 */
export function EmptyState({
  title,
  body,
  action,
  onAction,
}: {
  title: MessageKey;
  body: MessageKey;
  action?: MessageKey | undefined;
  onAction?: (() => void) | undefined;
}) {
  const t = useT();
  return (
    <Panel tone="neutral" title={t(title)}>
      <p className="surface-state-body">{t(body)}</p>
      {action !== undefined && (
        <div className="surface-state-actions">
          <Button label={action} onClick={onAction} />
        </div>
      )}
    </Panel>
  );
}

/**
 * A surface the product does not have yet.
 *
 * Not focusable, neutral, future tense, no remedy, and it may never borrow the
 * denial treatment (`docs/17 §6`, `ENC-673`). The reason that rule is worth a
 * component of its own: if most dimmed things in the product mean *"not written
 * yet"*, users learn that dimmed is background noise — and they learn it on
 * harmless surfaces, then carry the habit to the one that matters.
 */
export function UnbuiltState({ title, note }: { title: MessageKey; note: MessageKey }) {
  const t = useT();
  return (
    <div className="surface-state" data-tone="unbuilt" aria-disabled="true" tabIndex={-1}>
      <p className="surface-state-title">{t(title)}</p>
      <p className="surface-state-body">{t(note)}</p>
      <span className="ui-later">{t('later.chip')}</span>
    </div>
  );
}
