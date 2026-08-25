import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Button, Skeleton } from '../../shared/ui/primitives.tsx';

/* The four states `docs/09 §11` requires of every surface — and the awkward
 * fifth thing that is not one of them.
 *
 * **`unbuilt` is not a fifth state; it is a different axis.** `docs/09 §11` is
 * about a *data surface*: what it shows when it has nothing, when a filter
 * excludes everything, while it is fetching, and when the fetch failed.
 * `docs/17 §6` is about a *control*: ready, denied, unbuilt, busy. Ask today is
 * one point in the product of those two — its data surface sits in **empty
 * (new)**, and every control on it sits in **unbuilt**. Reading `unbuilt` as a
 * replacement for the four would be how a surface ships with one state and a
 * good excuse.
 *
 * So all four exist here as real components, and the screen renders the honest
 * one. The other three are reachable with `?surface=loading|error|scope-empty`,
 * the same review and accessibility hook `app.tsx` already uses for the library
 * list — because `plans/M5-MVP-GA.md` §6 asks for the four states
 * *demonstrated*, and a state nobody can reach has not been demonstrated.
 *
 * One thing is deliberately missing: a **success** state carrying an answer.
 * That is not shyness about scope, it is the point of D33 — a fluent paragraph
 * with a footnote citing a document that does not exist is a fabricated answer,
 * and it looks exactly like a real one in a screenshot. The shape of success is
 * drawn in `answer-shape.tsx` with none of its content, which is the most that
 * can be shown honestly and, per `docs/09 §10`, the least that may be promised.
 */

function Figure({ tone }: { tone: 'ask' | 'neutral' | 'error' }) {
  return (
    <span className="ask-figure" data-tone={tone === 'ask' ? undefined : tone} aria-hidden="true">
      {tone === 'ask' && <Icon name="spark" size={20} />}
      {tone === 'error' && <Icon name="warn" size={16} />}
      {tone === 'neutral' && <Icon name="filter" size={16} />}
    </span>
  );
}

/**
 * Empty (new), and the state this screen actually renders.
 *
 * `docs/09 §11` asks a new-empty state for *"what this surface is for, and the
 * one action that starts it"*. There is no action, so the slot where the button
 * would be holds the neutral `Later` marker and the release note instead. That
 * placement is the whole trick: an absence in the position an affordance would
 * occupy reads as a decision, where the same absence anywhere else reads as a
 * missing button.
 *
 * The marker is `.ui-later` — the same chip the sidebar puts on Inbox, Lists
 * and Pages — because a marker that is different on every surface is a marker
 * nobody learns. The copy is future tense and about the product, it offers no
 * remedy, and it is nowhere near the denial treatment (`docs/17 §6`).
 */
export function AskUnbuiltState() {
  const t = useT();
  return (
    <div className="ask-state" data-state="unbuilt">
      <Figure tone="ask" />
      <h2 className="ask-state-title">{t('ask.empty.title')}</h2>
      <p className="ask-state-body">{t('ask.empty.body')}</p>
      <p className="ask-marker">
        <span className="ui-later">{t('later.chip')}</span>
        {t('ask.arrivesInM7')}
      </p>
    </div>
  );
}

/**
 * Loading.
 *
 * The skeleton shares the answer's box model — question turn, answer turn,
 * source rows — so nothing shifts when the answer lands (`docs/09 §11`). It is
 * the one part of this screen that shimmers, and that is deliberate: motion is
 * how *busy* is told apart from *unbuilt* at a glance, without reading either.
 */
export function AskLoadingState() {
  const t = useT();
  return (
    <div className="ask-panel ask-loading" data-state="loading" role="status" aria-busy="true">
      {/* The label is text rather than an `aria-label` on a busy region, so it
       * is read by a screen reader and visible to everyone else. "Searching the
       * documents you can open" says what is happening; a spinner says wait. */}
      <b className="ask-shape-caption">{t('ask.state.loading')}</b>
      <div aria-hidden="true" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div className="ask-wire-turn">
          <span className="ask-wire-badge">
            <Icon name="user" size={11} />
          </span>
          <div className="ask-wire-lines">
            <Skeleton width="54%" />
          </div>
        </div>
        <div className="ask-wire-turn">
          <span className="ask-wire-badge" data-tone="accent">
            <Icon name="spark" size={11} />
          </span>
          <div className="ask-wire-lines">
            <Skeleton width="90%" />
            <Skeleton width="70%" />
            <Skeleton width="45%" />
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Empty (filtered).
 *
 * Separate from empty (new) because they are different problems, and collapsing
 * them into one *"No answer"* is how a user concludes their documents are gone.
 * The count is what distinguishes an over-narrow scope from an empty workspace.
 *
 * It counts documents *outside the scope*, never documents the user may not
 * open: a count of what access is hiding is itself a disclosure, and this
 * surface does not make it.
 */
export function AskScopeEmptyState({
  outsideScope,
  onWidenScope,
}: {
  outsideScope: number;
  onWidenScope?: (() => void) | undefined;
}) {
  const t = useT();
  return (
    <div className="ask-state" data-state="filtered-empty">
      <Figure tone="neutral" />
      <h2 className="ask-state-title">{t('ask.state.scopeEmpty.title')}</h2>
      <p className="ask-state-body">
        {t('ask.state.scopeEmpty.body', { count: outsideScope })}
      </p>
      {onWidenScope !== undefined && (
        <div className="ask-state-actions">
          <Button label="ask.state.scopeEmpty.action" onClick={onWidenScope} />
        </div>
      )}
    </div>
  );
}

export interface AskError {
  readonly retryable: boolean;
  /** The correlation ID from the API. Not translated, and quoted verbatim. */
  readonly requestId: string;
}

/**
 * Error.
 *
 * **A policy denial never arrives here.** `docs/09 §11` and `docs/17 §7`: a
 * `403` from DLP, a barrier or conditional access is a *successful* request
 * with a refusing answer. It renders inline on the control it refused, with a
 * reason and one remedy, and it never offers retry — retrying a denial teaches
 * a user the product is broken rather than that they lack permission. This
 * component is for a request that did not complete, which is why it is the only
 * place on this screen offering an action at all.
 */
export function AskErrorState({
  error,
  onRetry,
}: {
  error: AskError;
  onRetry?: (() => void) | undefined;
}) {
  const t = useT();
  return (
    /* `alert`, not `status`: the user was waiting for this and is now not going
     * to get it. */
    <div className="ask-state" data-state="error" role="alert">
      <Figure tone="error" />
      <h2 className="ask-state-title">{t('ask.state.error.title')}</h2>
      <p className="ask-state-body">
        {error.retryable ? t('ask.state.error.body') : t('ask.state.error.bodyFinal')}
      </p>
      {error.retryable && onRetry !== undefined && (
        <div className="ask-state-actions">
          <Button label="ask.state.error.retry" variant="primary" onClick={onRetry} />
        </div>
      )}
      <p className="ask-request-id">
        <span>{t('ask.state.error.requestId')}</span>
        <code>{error.requestId}</code>
      </p>
    </div>
  );
}
