import { useT } from '../../shared/i18n/index.tsx';
import { Card, Push } from '../../shared/ui/layout.tsx';
import { Skeleton, type ControlState } from '../../shared/ui/primitives.tsx';
import {
  EmptyState as SharedEmptyState,
  ErrorState as SharedErrorState,
} from '../../shared/ui/surface-states.tsx';
import type { HomeError } from './model.ts';

/* Home's four states, plus success.
 *
 * `docs/09 §11` requires all four on every surface and the prototype draws none
 * of them — not on Home, not on any of its five layouts. That gap used to be
 * filled here, in full: a private `Figure` helper that was character-for-
 * character identical to four other copies, a `-state-title`, a `-state-body`,
 * an action row and a request-ID row. All five are now
 * `shared/ui/surface-states`, and the only thing this file still decides is
 * *which* state Home is in and *which* catalog keys it says it with.
 *
 * Three decisions survive the move, because they are Home's rather than the
 * shared component's:
 *
 * 1. **The loading state is the real page with its contents removed.** Not a
 *    spinner and not a centred shrug: the same measure, the same three sections
 *    in the same order, the same card and row boxes at the same heights.
 *    `docs/09 §11` states this as a layout-shift requirement, and it is also
 *    the only loading state that tells the user what is coming.
 *
 * 2. **Empty and scoped-empty say different things.** Home has no filter bar,
 *    but it is scoped to one workspace, and that scope can empty it while the
 *    user still has three approvals waiting next door. "Your workspace is
 *    quiet" is the wrong sentence to show that person.
 *
 * 3. **The error state is the only place on Home that offers retry, and a
 *    policy denial never arrives here.** `docs/09 §11` and `docs/17 §7`: a 403
 *    from DLP, a barrier or conditional access is a *successful* request with a
 *    refusing answer. It renders through `FailureState` on the surface that was
 *    refused, and it never offers retry.
 */

/** Home has no backend, so its own actions are unbuilt, never denied (`docs/17 §6`). */
const UNBUILT: ControlState = { kind: 'unbuilt', note: 'later.arrivesLater' };

function SkeletonSectionHead() {
  return (
    <div className="home-section-head" aria-hidden="true">
      <span className="home-skel-line">
        <Skeleton width="112px" shape="text" />
      </span>
    </div>
  );
}

export function LoadingState() {
  const t = useT();
  /* Deterministic widths. A skeleton that reshuffles every render reads as data
   * arriving and then leaving again. */
  const cards = ['58%', '72%', '46%', '64%'];
  const names = ['44%', '68%', '52%', '38%'];
  /* Wide enough to wrap where the real pills wrap. A skeleton row that fits on
   * one line while the data needs two reserves the wrong box, and the section
   * below it moves when the data lands. */
  const asks = ['355px', '265px', '254px'];

  return (
    <div className="home">
      {/* One live region for the whole screen, not one per section: three
       * simultaneous "loading" announcements is noise, and the skeleton itself
       * is decorative. */}
      <div className="home-page" role="status" aria-busy="true" aria-label={t('home.state.loading')}>
        <div aria-hidden="true">
          <div className="home-skel-line" data-line="greeting">
            <Skeleton width="248px" shape="text" />
          </div>
          <div className="home-skel-line" data-line="subline">
            <Skeleton width="332px" shape="text" />
          </div>
        </div>

        <div aria-hidden="true">
          <SkeletonSectionHead />
          <div className="home-attention">
            {cards.map((width) => (
              <Card className="home-card" padded={false} key={width}>
                <Skeleton shape="circle" />
                <div className="home-card-main">
                  <div className="home-skel-line" data-line="title">
                    <Skeleton width={width} shape="text" />
                  </div>
                  <div className="home-skel-line" data-line="sub">
                    <Skeleton width="38%" shape="text" />
                  </div>
                </div>
                <div className="home-card-actions">
                  <Skeleton width="84px" shape="pill" />
                </div>
              </Card>
            ))}
          </div>
        </div>

        <div aria-hidden="true">
          <SkeletonSectionHead />
          <Card className="home-recent" padded={false}>
            {names.map((width) => (
              <div className="home-recent-row" key={width}>
                <Skeleton width="16px" shape="pill" />
                <span className="home-skel-line" data-line="name">
                  <Skeleton width={width} shape="text" />
                </span>
                <Skeleton width="92px" shape="pill" />
                {/* The trailing spacer, as an element rather than as an `auto`
                 * margin repeated in the stylesheet. */}
                <Push />
                <Skeleton width="56px" shape="pill" />
              </div>
            ))}
          </Card>
        </div>

        <div aria-hidden="true">
          <SkeletonSectionHead />
          <div className="home-asks">
            {asks.map((width) => (
              <Skeleton width={width} shape="pill" key={width} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Nothing waiting, nothing recent, nothing asked — and no scope hiding it.
 *
 * The action is `unbuilt`, not `denied`: there is no upload backend yet, which
 * is a fact about the product's milestone and not about this user's
 * permissions. Neutral, no remedy, out of the tab order (`docs/17 §6`).
 */
export function EmptyState() {
  return (
    <div className="home">
      {/* `data-state` sits on the page rather than on the state block because
       * the *screen* is what has two empties. The block below is genuinely
       * `empty` in both; what differs is why, and that is the page's fact.
       * `tests/a11y/routes.spec.ts` waits on both values. */}
      <div className="home-page" data-state="empty">
        <SharedEmptyState
          heading="home.state.empty.title"
          body="home.state.empty.body"
          action="home.state.empty.action"
          actionState={UNBUILT}
          fill
        />
      </div>
    </div>
  );
}

export function ScopedEmptyState({ hiddenCount }: { hiddenCount: number }) {
  return (
    <div className="home">
      <div className="home-page" data-state="scoped-empty">
        {/* The count is the whole point: it separates "you are done" from
         * "you are looking in the wrong workspace". */}
        <SharedEmptyState
          heading="home.state.scoped.title"
          body="home.state.scoped.body"
          values={{ count: hiddenCount }}
          action="home.state.scoped.action"
          actionState={UNBUILT}
          fill
        />
      </div>
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: HomeError;
  onRetry?: (() => void) | undefined;
}) {
  return (
    <div className="home">
      {/* `alert`, not `status`, and the shared block sets it: a read that failed
       * while the user was waiting for it is worth interrupting for. Retry is
       * offered only when the API client classified the failure as retryable —
       * a `400` will answer `400` again. */}
      <div className="home-page" data-state="error">
        <SharedErrorState
          heading="home.state.error.title"
          body="home.state.error.body"
          bodyFinal="home.state.error.bodyFinal"
          retry="home.state.error.retry"
          error={error}
          onRetry={onRetry}
          fill
        />
      </div>
    </div>
  );
}
