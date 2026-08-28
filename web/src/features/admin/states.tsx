import { useT } from '../../shared/i18n/index.tsx';
import { Card } from '../../shared/ui/layout.tsx';
import { Skeleton } from '../../shared/ui/primitives.tsx';
import {
  EmptyState,
  ErrorState,
  FilteredEmptyState,
  type FetchFailure,
} from '../../shared/ui/surface-states.tsx';

/* Admin's five outcomes, bound to admin's words.
 *
 * `docs/09 §11` requires empty (new), empty (filtered), loading and error on
 * every surface, and `docs/17 §7` adds a fifth that is *not* an error: a `403`
 * from the policy chain is a **successful** request with a refusing answer.
 *
 * ## What this file no longer draws
 *
 * All five were drawn here, by hand, one screen's copy of a shape five features
 * had — down to a `<div className="adm-state-figure" aria-hidden="true" />`
 * inlined at four call sites rather than pulled into a local helper. They are
 * `shared/ui/surface-states` now, and what is left here is the only part that
 * was ever this feature's: **which sentence each state says.** "These policies
 * could not be loaded" and "This search could not be run" are different facts,
 * so the heading is the caller's; the figure, the measure, the request-ID row
 * and the retry rule are not, and were duplicated five times to carry the one
 * thing that is.
 *
 * The denial is gone from this file entirely. It was a fifth copy of
 * `DeniedPanel` differing only by class prefix and by declaring its own
 * `AdminDenial` type instead of using `Failure` — which was precisely why it
 * could not call the shared component that already existed. `admin-screen.tsx`
 * renders `DeniedPanel` directly. **It has no retry affordance and none may be
 * added** (`docs/17 §7`): retrying a policy denial teaches a user the product is
 * broken rather than that they lack permission.
 */

/** The editor's box model, in skeleton form: same bands, same clause rows, no shift. */
export function AdminLoadingState() {
  const t = useT();
  return (
    <div className="adm-editor" role="status" aria-busy="true" aria-label={t('admin.state.loading')}>
      <div className="adm-crumbs" aria-hidden="true">
        <Skeleton width="180px" />
      </div>
      <div className="adm-head" aria-hidden="true">
        <Skeleton width="220px" />
      </div>
      <Card className="adm-builder" padded={false}>
        <div aria-hidden="true">
          {[0, 1, 2].map((band) => (
            <div key={band}>
              <div className="adm-band">
                <Skeleton width="64px" />
              </div>
              <ul className="adm-clauses">
                {[0, 1].map((clause) => (
                  <li className="adm-clause" key={clause}>
                    <Skeleton width={clause === 0 ? '58%' : '42%'} />
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Card>
      <div className="adm-stats" aria-hidden="true">
        {[0, 1, 2, 3].map((index) => (
          <Card key={index}>
            <span className="adm-stat-value">
              <Skeleton width="48px" />
            </span>
            <span className="adm-stat-label">
              <Skeleton width="80%" />
            </span>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function AdminEmptyState({ onCreate }: { onCreate: () => void }) {
  return (
    <EmptyState
      heading="admin.state.empty.title"
      body="admin.state.empty.body"
      action="admin.state.empty.action"
      onAction={onCreate}
    />
  );
}

export function AdminFilteredEmptyState({
  hidden,
  onClear,
}: {
  hidden: number;
  onClear: () => void;
}) {
  return (
    <FilteredEmptyState
      heading="admin.state.filtered.title"
      /* The count separates an over-narrow search from a tenant with no
       * policies, which is the mistake this state exists to prevent. */
      body="admin.state.filtered.body"
      values={{ count: hidden }}
      clearLabel="admin.state.filtered.action"
      onClear={onClear}
    />
  );
}

export function AdminErrorState({
  error,
  onRetry,
}: {
  error: FetchFailure;
  onRetry: () => void;
}) {
  return (
    <ErrorState
      heading="admin.state.error.title"
      body="admin.state.error.body"
      bodyFinal="admin.state.error.bodyFinal"
      retry="admin.state.error.retry"
      error={error}
      onRetry={onRetry}
      fill
    />
  );
}
