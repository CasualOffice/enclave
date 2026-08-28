import { useT } from '../../shared/i18n/index.tsx';
import { Card } from '../../shared/ui/layout.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { LaterChip, Skeleton } from '../../shared/ui/primitives.tsx';
import {
  ErrorState,
  FilteredEmptyState,
  StateBlock,
} from '../../shared/ui/surface-states.tsx';

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
 * So all four exist here and the screen renders the honest one. The other three
 * are reachable with `?surface=loading|error|scope-empty`, the same review and
 * accessibility hook `app.tsx` uses for the library list — because
 * `plans/M5-MVP-GA.md` §6 asks for the four states *demonstrated*, and a state
 * nobody can reach has not been demonstrated.
 *
 * ## What this file no longer draws
 *
 * The blocks themselves. There was a private `Figure` helper here that was
 * character-for-character identical to four other copies, a local
 * `{ retryable, requestId }` type that was the reason none of them could call
 * the shared component, and a request-ID row whose `<code>` was **not**
 * direction-isolated — so an Ask request ID rendered with its segments reversed
 * under RTL while the library's rendered correctly. `shared/ui/surface-states`
 * owns all of it now; what stays here is which state Ask is in and which
 * catalog keys it says it with, which is the only part that was ever Ask's.
 *
 * One thing is still deliberately missing: a **success** state carrying an
 * answer. That is not shyness about scope, it is the point of D33 — a fluent
 * paragraph with a footnote citing a document that does not exist is a
 * fabricated answer, and it looks exactly like a real one in a screenshot. The
 * shape of success is drawn in `answer-shape.tsx` with none of its content,
 * which is the most that can be shown honestly and, per `docs/09 §10`, the
 * least that may be promised.
 */

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
 * `StateBlock` directly rather than `UnbuiltState`, because the shared helper
 * puts the note in the body and this surface owes **two** sentences: what Ask
 * is for (`ask.empty.body`) and when it arrives (`ask.arrivesInM7`). The marker
 * is the shared `LaterChip` — the same chip the sidebar puts on Inbox, Lists
 * and Pages — because a marker that is different on every surface is a marker
 * nobody learns. The copy is future tense and about the product, it offers no
 * remedy, and it is nowhere near the denial treatment (`docs/17 §6`).
 */
export function AskUnbuiltState() {
  const t = useT();
  return (
    <StateBlock
      tone="unbuilt"
      state="unbuilt"
      heading="ask.empty.title"
      body="ask.empty.body"
    >
      <p className="ask-marker">
        <LaterChip note="later.chip" />
        {t('ask.arrivesInM7')}
      </p>
    </StateBlock>
  );
}

/**
 * Loading.
 *
 * The skeleton shares the answer's box model — question turn, answer turn,
 * source rows — so nothing shifts when the answer lands (`docs/09 §11`). It is
 * the one part of this screen that pulses, and that is deliberate: motion is
 * how *busy* is told apart from *unbuilt* at a glance, without reading either.
 *
 * A `Card` rather than a hand-written sheet-plus-hairline, and the `role` sits
 * on the stack inside it — the card is chrome and the region is content.
 */
export function AskLoadingState() {
  const t = useT();
  return (
    <Card className="ask-panel enc-enter-panel" padded={false}>
      <div className="ask-panel-inner" role="status" aria-busy="true">
        {/* The label is text rather than an `aria-label` on a busy region, so it
         * is read by a screen reader and visible to everyone else. "Searching the
         * documents you can open" says what is happening; a spinner says wait. */}
        <b className="ask-shape-caption">{t('ask.state.loading')}</b>
        <div aria-hidden="true" className="ask-turns">
          <div className="ask-wire-turn">
            <span className="ask-wire-badge">
              <Icon name="user" size={11} />
            </span>
            <div className="ask-wire-lines">
              <Skeleton width="54%" shape="text" />
            </div>
          </div>
          <div className="ask-wire-turn">
            <span className="ask-wire-badge" data-tone="accent">
              <Icon name="spark" size={11} />
            </span>
            <div className="ask-wire-lines">
              <Skeleton width="90%" shape="text" />
              <Skeleton width="70%" shape="text" />
              <Skeleton width="45%" shape="text" />
            </div>
          </div>
        </div>
      </div>
    </Card>
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
  return (
    <FilteredEmptyState
      heading="ask.state.scopeEmpty.title"
      body="ask.state.scopeEmpty.body"
      values={{ count: outsideScope }}
      clearLabel={onWidenScope === undefined ? undefined : 'ask.state.scopeEmpty.action'}
      onClear={onWidenScope}
    />
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
 *
 * The heading and both bodies stay Ask's own keys: "This question could not be
 * answered" and "This list could not be loaded" are different facts, and the
 * *title* is the one part of an error state that is genuinely per-surface. What
 * the shared component supplies is everything that was duplicated to carry it —
 * the figure, the retry branch, and the direction-isolated request ID.
 */
export function AskErrorState({
  error,
  onRetry,
}: {
  error: AskError;
  onRetry?: (() => void) | undefined;
}) {
  return (
    <ErrorState
      heading="ask.state.error.title"
      body="ask.state.error.body"
      bodyFinal="ask.state.error.bodyFinal"
      retry="ask.state.error.retry"
      error={error}
      onRetry={onRetry}
    />
  );
}
