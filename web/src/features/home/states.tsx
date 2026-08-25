import { useT } from '../../shared/i18n/index.tsx';
import { Button, Skeleton, type ControlState } from '../../shared/ui/primitives.tsx';
import type { HomeError } from './model.ts';

/* Home's four states, plus success.
 *
 * `docs/09 §11` requires all four on every surface and the prototype shows none
 * of them — not on Home, not on any of its five layouts. That is a gap in the
 * reference rather than a licence to ship three, so they are designed here.
 *
 * Three decisions are worth stating, because they are the ones a later reader
 * would otherwise undo:
 *
 * 1. **The loading state is the real page with its contents removed.** Not a
 *    spinner and not a centred shrug: the same 860px measure, the same three
 *    sections in the same order, the same card and row boxes at the same
 *    heights. `docs/09 §11` states this as a layout-shift requirement, and it
 *    is also the only loading state that tells the user what is coming.
 *
 * 2. **Empty and scoped-empty say different things.** Home has no filter bar,
 *    but it is scoped to one workspace, and that scope can empty it while the
 *    user still has three approvals waiting next door. "Your workspace is
 *    quiet" is the wrong sentence to show that person — it is the same mistake
 *    as telling someone their library is empty when a filter is hiding it, and
 *    `files.state.filtered.body` already carries the count for exactly this
 *    reason.
 *
 * 3. **The error state is the only place on Home that offers retry, and a
 *    policy denial never arrives here.** `docs/09 §11` and `docs/17 §7`: a 403
 *    from DLP, a barrier or conditional access is a *successful* request with a
 *    refusing answer. It renders inline on the surface that was refused, with a
 *    reason and a remedy, and it never offers retry — retrying a denial teaches
 *    a user the product is broken rather than that they lack permission.
 */

/** Home has no backend, so its own actions are unbuilt, never denied (`docs/17 §6`). */
const UNBUILT: ControlState = { kind: 'unbuilt', note: 'later.arrivesLater' };

function Figure({ tone }: { tone: 'neutral' | 'error' }) {
  return <div className="home-state-figure" data-tone={tone} aria-hidden="true" />;
}

function SkeletonSectionHead() {
  return (
    <div className="home-section-head" aria-hidden="true">
      <span className="home-skel-line" data-line="section">
        <Skeleton width="112px" />
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
            <Skeleton width="248px" />
          </div>
          <div className="home-skel-line" data-line="subline">
            <Skeleton width="332px" />
          </div>
        </div>

        <div aria-hidden="true">
          <SkeletonSectionHead />
          <div className="home-attention">
            {cards.map((width) => (
              <div className="home-card" key={width}>
                <span className="home-skel-avatar" />
                <div className="home-card-main">
                  <div className="home-skel-line" data-line="title">
                    <Skeleton width={width} />
                  </div>
                  <div className="home-skel-line" data-line="sub">
                    <Skeleton width="38%" />
                  </div>
                </div>
                <div className="home-card-actions">
                  <span className="home-skel-action" />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div aria-hidden="true">
          <SkeletonSectionHead />
          <div className="home-recent">
            {names.map((width) => (
              <div className="home-recent-row" key={width}>
                <span className="home-skel-block" style={{ inlineSize: '16px', blockSize: '16px' }} />
                <span className="home-skel-line" data-line="name">
                  <Skeleton width={width} />
                </span>
                <span className="home-skel-block" style={{ inlineSize: '92px' }} />
                <span className="home-skel-block home-skel-when" style={{ inlineSize: '56px' }} />
              </div>
            ))}
          </div>
        </div>

        <div aria-hidden="true">
          <SkeletonSectionHead />
          <div className="home-asks">
            {asks.map((width) => (
              <span className="home-skel-ask" key={width} style={{ inlineSize: width }} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export function EmptyState() {
  const t = useT();
  return (
    <div className="home">
      <div className="home-page">
        <div className="home-state" data-tone="neutral" data-state="empty">
          <Figure tone="neutral" />
          <h1 className="home-state-title">{t('home.state.empty.title')}</h1>
          <p className="home-state-body">{t('home.state.empty.body')}</p>
          <div className="home-state-actions">
            {/* Unbuilt, not denied: there is no upload backend yet, which is a
             * fact about the product's milestone and not about this user's
             * permissions. Neutral, no remedy, out of the tab order. */}
            <Button label="home.state.empty.action" icon="up" state={UNBUILT} />
          </div>
        </div>
      </div>
    </div>
  );
}

export function ScopedEmptyState({ hiddenCount }: { hiddenCount: number }) {
  const t = useT();
  return (
    <div className="home">
      <div className="home-page">
        <div className="home-state" data-tone="neutral" data-state="scoped-empty">
          <Figure tone="neutral" />
          <h1 className="home-state-title">{t('home.state.scoped.title')}</h1>
          {/* The count is the whole point: it separates "you are done" from
           * "you are looking in the wrong workspace". */}
          <p className="home-state-body">{t('home.state.scoped.body', { count: hiddenCount })}</p>
          <div className="home-state-actions">
            <Button label="home.state.scoped.action" icon="updown" state={UNBUILT} />
          </div>
        </div>
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
  const t = useT();
  return (
    <div className="home">
      <div className="home-page">
        {/* `alert`, not `status`: a read that failed while the user was waiting
         * for it is worth interrupting for. */}
        <div className="home-state" data-tone="error" data-state="error" role="alert">
          <Figure tone="error" />
          <h1 className="home-state-title">{t('home.state.error.title')}</h1>
          <p className="home-state-body">
            {error.retryable ? t('home.state.error.body') : t('home.state.error.bodyFinal')}
          </p>
          {error.retryable && onRetry !== undefined && (
            <div className="home-state-actions">
              {/* Genuinely actionable, and the only control on Home that is.
               * A failed read can be tried again; a refusal cannot, and must
               * never be offered this button. */}
              <Button label="home.state.error.retry" variant="primary" onClick={onRetry} />
            </div>
          )}
          <p className="home-request-id">
            <span>{t('home.state.error.requestId')}</span>
            <code>{error.requestId}</code>
          </p>
        </div>
      </div>
    </div>
  );
}
