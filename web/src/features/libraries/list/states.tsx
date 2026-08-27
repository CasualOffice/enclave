import { useT } from '../../../shared/i18n/index.tsx';
import type { Density } from '../../../shared/list/geometry.ts';

/* The four states `docs/09 §11` requires, none of which appears anywhere in the
 * v2 reference on any of its five layouts (`plans/M5-MVP-GA.md` D35.7). So they
 * are designed here rather than discovered later, and the craft budget goes on
 * the two decisions that actually matter:
 *
 * 1. **The loading state has the final layout's box model**, row for row. Not a
 *    spinner, not a centred shrug — the same 36 px rows in the same seven-column
 *    grid, so nothing shifts when data lands. `docs/09 §11` states this as a
 *    CLS requirement and it is also the only loading state that tells the user
 *    what is coming.
 * 2. **Empty and filtered-empty say different things**, because they are
 *    different problems. "This library is new" wants the one action that starts
 *    it. "Your filters exclude everything" wants the count of what is being
 *    hidden and the way back. Collapsing them into one "No files" is how a user
 *    concludes their data is gone.
 *
 * The composition itself is restrained on purpose. The mark's own construction
 * — a bounded field with a window inside it — is drawn from tokens at 44 px and
 * left at that. An empty state is a thing a user sees on their worst day with
 * this product; it should be calm, not charming.
 */

export function LoadingState({ density, rows = 12 }: { density: Density; rows?: number }) {
  const t = useT();
  /* Deterministic widths, not random ones: a skeleton that reshuffles on every
   * render reads as data arriving and then leaving again. */
  const widths = [62, 41, 78, 55, 34, 69, 47, 83, 52, 38, 71, 58];
  return (
    <div role="status" aria-busy="true" aria-label={t('files.state.loading')}>
      {Array.from({ length: rows }, (_, index) => (
        <div
          key={index}
          className="egl-row"
          style={{ blockSize: `${density.rowHeight}px` }}
          aria-hidden="true"
        >
          <span />
          <span className="egl-skeleton-bar" style={{ inlineSize: `${widths[index % 12]}%` }} />
          <span className="egl-skeleton-bar" style={{ inlineSize: '70%' }} />
          <span className="egl-skeleton-bar" style={{ inlineSize: '60%' }} />
          <span />
          <span className="egl-skeleton-bar" style={{ inlineSize: '80%' }} />
          <span />
        </div>
      ))}
    </div>
  );
}

function Figure({ tone }: { tone: 'neutral' | 'error' }) {
  return <div className="egl-state-figure" data-tone={tone} aria-hidden="true" />;
}

export function EmptyState({ onUpload }: { onUpload?: (() => void) | undefined }) {
  const t = useT();
  return (
    <div className="egl-state" data-tone="neutral" data-state="empty">
      <Figure tone="neutral" />
      <h2 className="egl-state-title">{t('files.state.empty.title')}</h2>
      <p className="egl-state-body">{t('files.state.empty.body')}</p>
      {onUpload !== undefined && (
        <div className="egl-state-actions">
          <button type="button" className="egl-btn" data-variant="primary" onClick={onUpload}>
            {t('files.state.empty.action')}
          </button>
        </div>
      )}
    </div>
  );
}

export function FilteredEmptyState({
  hiddenCount,
  onClearFilters,
}: {
  hiddenCount: number;
  onClearFilters?: (() => void) | undefined;
}) {
  const t = useT();
  return (
    <div className="egl-state" data-tone="neutral" data-state="filtered-empty">
      <Figure tone="neutral" />
      <h2 className="egl-state-title">{t('files.state.filtered.title')}</h2>
      {/* The count is the whole point: it distinguishes an over-narrow filter
       * from a library that is genuinely empty, which is the mistake this state
       * exists to prevent a user from making. */}
      <p className="egl-state-body">{t('files.state.filtered.body', { count: hiddenCount })}</p>
      {onClearFilters !== undefined && (
        <div className="egl-state-actions">
          <button type="button" className="egl-btn" onClick={onClearFilters}>
            {t('files.state.filtered.action')}
          </button>
        </div>
      )}
    </div>
  );
}

export interface ListError {
  readonly retryable: boolean;
  /** The correlation ID from the API. Not translated, and quoted verbatim. */
  readonly requestId: string;
}

/* **A policy denial never arrives here.** `docs/09 §11` is explicit about it: a
 * `403` from DLP, a barrier or conditional access is a successful request with
 * a refusing answer, not a failure. It renders as denied-explained-inline on
 * the surface that was refused, with a reason and a remedy, and it never offers
 * *retry* — retrying a denial is how a user learns the product is broken rather
 * than that they lack permission. This component is for a read that did not
 * complete. Routing a refusal into it would be the same defect one layer up. */

export function ErrorState({
  error,
  onRetry,
}: {
  error: ListError;
  onRetry?: (() => void) | undefined;
}) {
  const t = useT();
  return (
    /* `alert`, not `status`: a read that failed while the user was waiting for
     * it is worth interrupting for. `docs/09 §11` wants what failed, whether it
     * is retryable, the retry, and a copyable request ID — all four, in text,
     * never only in a toast that scrolls away. */
    <div className="egl-state" data-tone="error" data-state="error" role="alert">
      <Figure tone="error" />
      <h2 className="egl-state-title">{t('files.state.error.title')}</h2>
      <p className="egl-state-body">
        {error.retryable ? t('files.state.error.body') : t('files.state.error.bodyFinal')}
      </p>
      {error.retryable && onRetry !== undefined && (
        <div className="egl-state-actions">
          <button type="button" className="egl-btn" data-variant="primary" onClick={onRetry}>
            {t('files.state.error.retry')}
          </button>
        </div>
      )}
      <p className="egl-request-id">
        <span>{t('files.state.error.requestId')}</span>
        <code>{error.requestId}</code>
      </p>
    </div>
  );
}

/**
 * The polite live region that tells a screen-reader user how large the list is.
 *
 * A virtualized list has roughly thirty rows in the DOM out of a hundred
 * thousand, so the count has to be stated rather than counted. Collapsing a
 * group changes it, which is exactly when a user needs to hear it.
 */
export function RowCountAnnouncement({ shown, total }: { shown: number; total: number }) {
  const t = useT();
  return (
    <div
      aria-live="polite"
      aria-atomic="true"
      style={{
        position: 'absolute',
        inlineSize: '1px',
        blockSize: '1px',
        overflow: 'hidden',
        clipPath: 'inset(50%)',
        whiteSpace: 'nowrap',
      }}
    >
      {/* ICU does the digit grouping inside the message, so `12,34,567` comes
       * out right in `hi-IN` without this component knowing it exists. */}
      {t('files.list.rowCount', { shown, total })}
    </div>
  );
}
