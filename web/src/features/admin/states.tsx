import { useT } from '../../shared/i18n/index.tsx';
import { Button, Skeleton } from '../../shared/ui/primitives.tsx';

/* The five outcomes this surface has, and they are not four plus a special case.
 *
 * `docs/09 §11` requires empty (new), empty (filtered), loading and error on
 * every surface, and the reference shows none of them on any layout — that is a
 * gap in the reference, not permission to ship three (`ENC-676`).
 *
 * The fifth is `docs/17 §7`'s: **a denial is not a failure.** A `403` from the
 * policy chain is a *successful* request with a refusing answer. It renders with
 * the server's own message and remediation and **never a retry**, because
 * retrying a denial is how a user concludes the product is broken rather than
 * that they lack permission. The two share no component here for exactly the
 * reason `ENC-673` gives: the moment they share one, one of them grows the
 * other's affordance.
 *
 * **The denial's words are the server's.** `docs/09 §5` after `ENC-674`: the
 * client may not invent a reason, and `docs/06 §24` says the server's is already
 * user-safe and already free of the policy's name. So when the envelope carries
 * no message this renders the code and a neutral sentence about where to ask —
 * not a guess at why.
 *
 * These are `features/admin`'s own copies of shapes `features/libraries` also
 * has. A feature never imports another feature (`docs/17 §2`), and two features
 * wanting one component is the signal it belongs in `shared/ui` — reported, not
 * taken, because `shared/` is not this session's to change.
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
      <div className="adm-builder" aria-hidden="true">
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
      <div className="adm-stats" aria-hidden="true">
        {[0, 1, 2, 3].map((index) => (
          <div className="adm-stat" key={index}>
            <span className="adm-stat-value">
              <Skeleton width="48px" />
            </span>
            <span className="adm-stat-label">
              <Skeleton width="80%" />
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AdminEmptyState({ onCreate }: { onCreate: () => void }) {
  const t = useT();
  return (
    <div className="adm-state" data-state="empty">
      <div className="adm-state-figure" aria-hidden="true" />
      <h2 className="adm-state-title">{t('admin.state.empty.title')}</h2>
      <p className="adm-state-body">{t('admin.state.empty.body')}</p>
      <Button label="admin.state.empty.action" variant="primary" icon="plus" onClick={onCreate} />
    </div>
  );
}

export function AdminFilteredEmptyState({
  hidden,
  onClear,
}: {
  hidden: number;
  onClear: () => void;
}) {
  const t = useT();
  return (
    <div className="adm-state" data-state="filtered-empty">
      <div className="adm-state-figure" aria-hidden="true" />
      <h2 className="adm-state-title">{t('admin.state.filtered.title')}</h2>
      {/* The count separates an over-narrow search from a tenant with no
       * policies, which is the mistake this state exists to prevent. */}
      <p className="adm-state-body">{t('admin.state.filtered.body', { count: hidden })}</p>
      <Button label="admin.state.filtered.action" onClick={onClear} />
    </div>
  );
}

export interface AdminFetchError {
  readonly retryable: boolean;
  readonly requestId: string;
}

export function AdminErrorState({
  error,
  onRetry,
}: {
  error: AdminFetchError;
  onRetry: () => void;
}) {
  const t = useT();
  return (
    <div className="adm-state" data-state="error" data-tone="error" role="alert">
      <div className="adm-state-figure" data-tone="error" aria-hidden="true" />
      <h2 className="adm-state-title">{t('admin.state.error.title')}</h2>
      <p className="adm-state-body">
        {error.retryable ? t('admin.state.error.body') : t('admin.state.error.bodyFinal')}
      </p>
      {error.retryable && <Button label="admin.state.error.retry" variant="primary" onClick={onRetry} />}
      <p className="adm-request-id">
        <span>{t('admin.state.error.requestId')}</span>
        <code>{error.requestId}</code>
      </p>
    </div>
  );
}

export interface AdminDenial {
  readonly code: string;
  /** The server's own user-safe sentence (`docs/05 §5`). Empty when it sent none. */
  readonly message: string;
  readonly remediation: string | undefined;
  readonly requestId: string;
}

export function AdminDeniedState({ denial }: { denial: AdminDenial }) {
  const t = useT();
  return (
    /* `data-state="denied"`, and it shares no class with the error state above.
     * `docs/17 §10` F2/F3: the denied and the failed treatments never share a
     * class, and a denial renders no retry affordance while a fetch failure
     * always does. */
    <div className="adm-state" data-state="denied" data-tone="denied">
      <div className="adm-state-figure" data-tone="denied" aria-hidden="true" />
      <h2 className="adm-state-title">{t('admin.state.denied.title')}</h2>
      {denial.message === '' ? (
        <p className="adm-state-body">{t('admin.state.denied.noReason')}</p>
      ) : (
        <p className="adm-state-body">{denial.message}</p>
      )}
      {denial.remediation !== undefined && denial.remediation !== '' && (
        <p className="adm-state-body">{denial.remediation}</p>
      )}
      <p className="adm-request-id">
        <span>{t('admin.state.denied.codeLabel')}</span>
        <code>{denial.code}</code>
      </p>
    </div>
  );
}
