import { useState } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { AnswerShape } from './answer-shape.tsx';
import { AskComposer } from './composer.tsx';
import { AskErrorState, AskLoadingState, AskScopeEmptyState, AskUnbuiltState } from './states.tsx';
import './ask.css';

/* Ask — AI beside the work, and the surface with no backend behind it.
 *
 * `plans/M5-MVP-GA.md` D33: Ask (`⌘J`) appears in the design and is backed by
 * nothing until M7. `docs/05-API.md` names no Ask endpoint, so there is nothing
 * to call and nothing to invent a path for — this screen makes no request and
 * imports no fixture, because a fixture answer is a fabricated answer wearing a
 * filename.
 *
 * The design problem was to make that read as **deliberate rather than broken**
 * without faking a working AI, and the answer is three moves:
 *
 *   1. **The screen is complete, not truncated.** Header, lede, the shape of an
 *      answer, the composer with its scope chips. A half-drawn screen reads as
 *      unfinished work; a fully drawn screen with one honest sentence reads as
 *      a decision.
 *   2. **The absence sits where the affordance would.** `docs/09 §11` wants a
 *      new-empty state to name "the one action that starts it". There is none,
 *      so that exact slot holds the neutral `Later` chip and *"Arrives in a
 *      later release"*. Absence in the position of an affordance is legible;
 *      absence anywhere else is a bug.
 *   3. **The answer's shape is drawn with none of its words** (`answer-shape`).
 *      `docs/09 §10` binds even while unbuilt — every answer exposes its source
 *      documents and chunks with deep links — and a future session fills this
 *      in, so the shape is the promise being made now.
 *
 * What it is not: a denial. Nothing here is focusable, nothing offers a remedy,
 * nothing uses the denial colour, and the copy is future tense about the
 * product rather than present tense about the user (`docs/17 §6`). That
 * separation is a security property, not a style one — if dimmed comes to mean
 * "not written yet" on the harmless surfaces, it stops being read on the one
 * where it means "DLP refused this".
 */

/** The three states the surface cannot currently reach on its own, plus the one it can. */
type Surface = 'unbuilt' | 'loading' | 'error' | 'scope-empty';

const REVIEWABLE = new Set<Surface>(['loading', 'error', 'scope-empty']);

/* `?surface=` is the same review and accessibility hook `app.tsx` already uses
 * for the library list. `plans/M5-MVP-GA.md` §6 requires the four states to be
 * *demonstrated*, and a state with no route to it has not been demonstrated —
 * axe cannot reach it, a reviewer cannot look at it, and it rots.
 *
 * It reads `window.location.search` rather than importing `app/routes.ts`: a
 * feature may import from a layer below it and never from one above
 * (`docs/17 §2`), and `app/` is above `features/`. */
function readSurface(search: string): Surface {
  const value = new URLSearchParams(search).get('surface') ?? '';
  return REVIEWABLE.has(value as Surface) ? (value as Surface) : 'unbuilt';
}

export default function Screen() {
  const t = useT();
  const [surface] = useState(() => readSurface(window.location.search));

  return (
    <div className="ask" data-screen="ask" data-state={surface}>
      <div className="ask-head">
        {/* The prototype's breadcrumb is `Ask / {{askTitle}}` — a thread name.
         * There are no threads, so there is no second crumb; a placeholder one
         * would be the same lie in smaller type. */}
        <h1 className="ask-heading">{t('ask.heading')}</h1>
      </div>

      <div className="ask-column">
        {/* The state region scrolls; the composer does not. A composer that
         * scrolls away with the conversation is a composer a user has to hunt
         * for, and it is the one control on the surface they came for. */}
        <div className="ask-body">
          {surface === 'unbuilt' && (
            <>
              <AskUnbuiltState />
              <AnswerShape />
            </>
          )}
          {surface === 'loading' && <AskLoadingState />}
          {surface === 'scope-empty' && (
            <AskScopeEmptyState
              outsideScope={1284}
              onWidenScope={() => {
                window.location.search = '';
              }}
            />
          )}
          {surface === 'error' && (
            <AskErrorState
              error={{ retryable: true, requestId: '01K3Q7X0PMDR4W8B2ZC6E5A9TN' }}
              onRetry={() => window.location.reload()}
            />
          )}
        </div>

        {/* The composer stays on every state. It is the surface's identity, and
         * a screen that hides its own input while it is thinking or after it
         * failed has taken the user's next move away from them. */}
        <AskComposer />
      </div>
    </div>
  );
}
