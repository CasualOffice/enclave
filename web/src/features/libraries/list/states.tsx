import { useT } from '../../../shared/i18n/index.tsx';
import { ScreenReaderOnly, Skeleton } from '../../../shared/ui/primitives.tsx';
import {
  EmptyState as SharedEmptyState,
  ErrorState as SharedErrorState,
  FilteredEmptyState as SharedFilteredEmptyState,
} from '../../../shared/ui/surface-states.tsx';

/* The list's four states — now three thin wrappers and one skeleton.
 *
 * `docs/09 §11` requires four states on every surface, none of which appears
 * anywhere in the reference on any of its five layouts
 * (`plans/M5-MVP-GA.md` D35.7). They were therefore designed here — and then
 * designed again in `features/home`, `features/search`, `features/ask` and
 * `features/admin`, four times, with a private `Figure` helper that was
 * character-for-character identical in four of the five files.
 *
 * They live in `shared/ui/surface-states` now. What is left here is the part
 * that is genuinely about *this* list:
 *
 * 1. **The loading skeleton has the loaded row's box model**, row for row. Not
 *    a spinner, not a centred shrug — the same `--row-h` rows in the same
 *    seven-column grid with the same insets, so nothing shifts when data lands
 *    (`specs/library.md §A`, CLS 0). It is built from `<Skeleton>` now rather
 *    than from a local `.egl-skeleton-bar` whose gradient sweep repainted the
 *    whole bar every frame — `docs/09 §2` budgets 60fps at 100 000 rows and
 *    `web/bench-results/grouped-list.json` records p95 frame 5.4ms of 16.67, so
 *    a repaint per skeleton per frame is a bench this may not spend.
 * 2. **Empty and filtered-empty say different things**, because they are
 *    different problems, and the catalog keys that say them stay this feature's.
 *    "This library is new" wants the one action that starts it; "your filters
 *    exclude everything" wants the count of what is being hidden and the way
 *    back. Collapsing them into one "No files" is how a user concludes their
 *    data is gone.
 * 3. **The row-count announcement**, which is virtualization-specific and has no
 *    equivalent anywhere else in the tree.
 */

/** Deterministic name-column widths. A skeleton that reshuffles on every render
 *  reads as data arriving and then leaving again. */
const NAME_WIDTHS = [62, 41, 78, 55, 34, 69, 47, 83, 52, 38, 71, 58];

export function LoadingState({ rows = 12 }: { rows?: number }) {
  const t = useT();
  return (
    <div role="status" aria-busy="true" aria-label={t('files.state.loading')}>
      {Array.from({ length: rows }, (_, index) => (
        /* No inline `blockSize`: `.egl-row` reads `--egl-row-h`, which the grid
         * sets from `shared/list/geometry.ts`. One height, one source, and the
         * skeleton cannot drift from the row it is reserving. */
        <div key={index} className="egl-row" aria-hidden="true">
          <span className="egl-cell-select">
            <Skeleton />
          </span>
          <Skeleton shape="text" width={`${NAME_WIDTHS[index % NAME_WIDTHS.length]}%`} />
          <Skeleton shape="text" width="70%" />
          {/* The two pill-shaped cells are pill-shaped skeletons: `docs/17 §8`
            * asks the reserved box and the real box to be the same box, and a
            * square placeholder for a 999px badge is not. */}
          <Skeleton shape="pill" width="88px" />
          <Skeleton shape="pill" width="72px" />
          <Skeleton shape="text" width="100%" />
          <span />
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ onUpload }: { onUpload?: (() => void) | undefined }) {
  return (
    <SharedEmptyState
      heading="files.state.empty.title"
      body="files.state.empty.body"
      fill
      {...(onUpload === undefined
        ? {}
        : { action: 'files.state.empty.action' as const, onAction: onUpload })}
    />
  );
}

export function FilteredEmptyState({
  hiddenCount,
  onClearFilters,
}: {
  hiddenCount: number;
  onClearFilters?: (() => void) | undefined;
}) {
  return (
    /* The count is the whole point: it distinguishes an over-narrow filter from
     * a library that is genuinely empty, which is the mistake this state exists
     * to prevent a user from making. ICU does the plural and the grouping. */
    <SharedFilteredEmptyState
      heading="files.state.filtered.title"
      body="files.state.filtered.body"
      values={{ count: hiddenCount }}
      fill
      {...(onClearFilters === undefined
        ? {}
        : { clearLabel: 'files.state.filtered.action' as const, onClear: onClearFilters })}
    />
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
  return (
    /* `ErrorState` renders `role="alert"`: a read that failed while the user was
     * waiting for it is worth interrupting for. All four parts `docs/09 §11`
     * names are in the shared block — what failed, whether it is retryable
     * (from the API client's classification, never guessed), the retry, and a
     * copyable request ID. Only the title is per-surface, which is why only the
     * title's key is passed. */
    <SharedErrorState
      heading="files.state.error.title"
      body="files.state.error.body"
      bodyFinal="files.state.error.bodyFinal"
      retry="files.state.error.retry"
      error={error}
      onRetry={onRetry}
      fill
    />
  );
}

/**
 * The polite live region that tells a screen-reader user how large the list is.
 *
 * A virtualized list has roughly thirty rows in the DOM out of a hundred
 * thousand, so the count has to be stated rather than counted. Collapsing a
 * group changes it, which is exactly when a user needs to hear it.
 *
 * The visually-hidden treatment is `ScreenReaderOnly`, not a style object. The
 * same six declarations — `position:absolute`, a 1px box, `overflow:hidden`,
 * `clip-path: inset(50%)` and `white-space:nowrap` — were written out four
 * times in this tree, and `clip-path` rather than a physical offset is the
 * whole point of them: `left: -9999px` is wrong under RTL.
 */
export function RowCountAnnouncement({ shown, total }: { shown: number; total: number }) {
  const t = useT();
  return (
    <div aria-live="polite" aria-atomic="true">
      <ScreenReaderOnly>
        {/* ICU does the digit grouping inside the message, so `12,34,567` comes
         * out right in `hi-IN` without this component knowing it exists. */}
        {t('files.list.rowCount', { shown, total })}
      </ScreenReaderOnly>
    </div>
  );
}
