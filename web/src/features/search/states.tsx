import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import type { FilterId } from './filters.ts';

/* The four states `docs/09 §11` requires, none of which the prototype draws.
 *
 * `web/design-system/enclave-client-prototype.html`'s Search block has exactly
 * one: a centred *"No files match “{{searchQ}}”"* with a Clear search button.
 * That is the filtered-empty state and it names no filters, so it cannot tell a
 * user whose query is wrong from a user whose *filters* are wrong — which is the
 * single distinction `docs/09 §11` asks this state to draw. There is no new-empty
 * state, no loading state and no error state anywhere in the block.
 *
 * So they are designed here, against the treatment `features/libraries/list`
 * already established: the same 44 px token-drawn figure, the same title/body
 * sizes, the same restraint. The visual language is duplicated rather than
 * imported because a feature may not import another feature (`docs/17 §2`) —
 * two screens wanting the same state components is precisely the signal that
 * they belong in `shared/`, and that is reported rather than taken.
 */

function Figure({ tone }: { tone: 'neutral' | 'error' }) {
  return <div className="esr-state-figure" data-tone={tone} aria-hidden="true" />;
}

/* ------------------------------------------------------------ empty (new) */

/**
 * Nothing has been searched yet.
 *
 * `docs/09 §11`: what this surface is for, and the one action that starts it.
 * The action here is typing, so the state points at the field rather than
 * offering a button that would only move focus — and it says what is searchable,
 * because "universal search across filename, natural language, metadata, person,
 * date, workspace, file type and classification" (`docs/09 §10`) is not
 * guessable from an empty box.
 */
export function NewSearchState() {
  const t = useT();
  return (
    <div className="esr-state" data-state="empty">
      <Figure tone="neutral" />
      <h2 className="esr-state-title">{t('search.state.new.title')}</h2>
      <p className="esr-state-body">{t('search.state.new.body')}</p>
      {/* No keyboard hint here, though the surrounding surfaces have room for
       * one. `docs/09 §6` binds `/` to "focus search" and nothing in this
       * codebase implements it — it is an application-level shortcut and this
       * screen does not own the application. A hint for a key that does nothing
       * is the same promise-without-a-product this milestone is named after, at
       * hint scale. Reported instead. */}
    </div>
  );
}

/* ------------------------------------------------------- empty (filtered) */

/** One active filter, already resolved to the words the chip shows. */
export interface ActiveFilterSummary {
  readonly id: FilterId;
  readonly key: string;
  readonly value: string;
}

export function NoResultsState({
  query,
  filters,
  unfilteredCount,
  lexical,
  onClearFilters,
}: {
  query: string;
  filters: readonly ActiveFilterSummary[];
  /** How many results the same query returns with every filter cleared. */
  unfilteredCount: number;
  /** True when retrieval matched words rather than meaning, which changes the advice. */
  lexical: boolean;
  onClearFilters: () => void;
}) {
  const t = useT();
  const filtered = filters.length > 0;

  return (
    <div className="esr-state" data-state="filtered-empty">
      <Figure tone="neutral" />
      <h2 className="esr-state-title">{t('search.state.noResults.title', { query })}</h2>

      {filtered ? (
        <>
          {/* The count is the whole point of this branch: it separates "your
           * filters are too narrow" from "this query finds nothing", which are
           * different problems with different fixes. Collapsing them is how a
           * user concludes the document is gone. */}
          <p className="esr-state-body">
            {t('search.state.noResults.filtered', { count: unfilteredCount })}
          </p>
          <ul className="esr-state-filters" aria-label={t('search.state.noResults.filterList')}>
            {filters.map((filter) => (
              <li key={filter.id} className="esr-chip" data-active="true">
                <span className="esr-chip-key">{filter.key}</span>
                <bdi className="esr-chip-value" dir="auto">
                  {filter.value}
                </bdi>
              </li>
            ))}
          </ul>
          <div className="esr-state-actions">
            <button type="button" className="esr-btn" data-variant="primary" onClick={onClearFilters}>
              {t('search.state.noResults.clearFilters')}
            </button>
          </div>
        </>
      ) : (
        <p className="esr-state-body">
          {/* On a lexical-only search the useful advice is different, and it is
           * the same advice the retrieval notice gives: the index matched the
           * words you typed, so type the words the document would use. Saying it
           * here as well is not a repetition — this is the moment the user is
           * actually stuck. */}
          {lexical
            ? t('search.state.noResults.lexicalAdvice')
            : t('search.state.noResults.advice')}
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ loading */

/**
 * Skeleton rows in the loaded row's exact box model.
 *
 * `docs/09 §11` states this as a layout-shift requirement, and the shared box is
 * literal: `.esr-hit` and `.esr-skeleton-hit` are the same three lines at the
 * same heights inside the same 80 px row, so nothing moves when results land.
 * Rendering `null` here would be three states and fails review (`docs/17 §8`).
 */
export function LoadingState({ rows = 8 }: { rows?: number }) {
  const t = useT();
  /* Deterministic widths. A skeleton that reshuffles every render reads as data
   * arriving and leaving again. */
  const widths = [58, 71, 46, 64, 52, 77, 61, 44];

  return (
    <div className="esr-loading" role="status" aria-busy="true" aria-label={t('search.state.loading')}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="esr-row" aria-hidden="true">
          <div className="esr-skeleton-hit">
            <span className="esr-line esr-line-title">
              <span className="esr-skeleton esr-skeleton-icon" />
              <span className="esr-skeleton" style={{ inlineSize: `${widths[index % 8]}%` }} />
            </span>
            <span className="esr-line esr-line-meta">
              <span className="esr-skeleton" style={{ inlineSize: '38%' }} />
            </span>
            <span className="esr-line esr-line-excerpt">
              <span className="esr-skeleton" style={{ inlineSize: '86%' }} />
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------- error */

export interface SearchError {
  readonly retryable: boolean;
  /** The correlation ID from the API. Not translated, and quoted verbatim. */
  readonly requestId: string;
}

/**
 * A read that did not complete.
 *
 * **A policy denial never arrives here** (`docs/09 §11`, `docs/17 §7`): a `403`
 * from DLP, a barrier or conditional access is a successful request with a
 * refusing answer, it renders inline with a reason and a remedy, and it never
 * offers retry. Neither does the degraded-search notice arrive here — a lexical
 * fallback returned real results, and rendering it as a failure would teach a
 * user the product is broken when it is merely narrower.
 */
export function ErrorState({
  error,
  onRetry,
}: {
  error: SearchError;
  onRetry: () => void;
}) {
  const t = useT();
  return (
    /* `alert`, not `status`: a read that failed while the user was waiting on it
     * is worth interrupting for — and it is the one thing on this screen that
     * is. The notice above is deliberately `status` for the same reason. */
    <div className="esr-state" data-tone="error" data-state="error" role="alert">
      <Figure tone="error" />
      <h2 className="esr-state-title">{t('search.state.error.title')}</h2>
      <p className="esr-state-body">
        {error.retryable ? t('search.state.error.body') : t('search.state.error.bodyFinal')}
      </p>
      {error.retryable && (
        <div className="esr-state-actions">
          <button type="button" className="esr-btn" data-variant="primary" onClick={onRetry}>
            {t('search.state.error.retry')}
          </button>
        </div>
      )}
      <p className="esr-request-id">
        <span>{t('search.state.error.requestId')}</span>
        <code>{error.requestId}</code>
      </p>
    </div>
  );
}

/* -------------------------------------------------------------- answer slot */

/**
 * Where the AI answer will be, said plainly.
 *
 * `docs/09 §10` promises that AI answers expose their source documents and
 * chunks. M5 has none: RAG is M7 (`plans/M5-MVP-GA.md` D33), so this is the
 * **unbuilt** treatment and never the denied one. `docs/17 §6` gives the
 * contract and every part of it is load-bearing — neutral colour, no remedy, out
 * of the tab order, future tense about the product, a `Later` chip.
 *
 * It is here rather than omitted because omitting it is the failure this
 * milestone is named after: a user who has been sold "ask a question" and sees a
 * plain result list learns nothing about whether the feature exists, is broken,
 * or is refused to them. `ENC-673` is the same argument for controls.
 */
export function AnswerSlot() {
  const t = useT();
  return (
    <div
      className="esr-answer"
      /* Not focusable and not interactive: there is nowhere to go and nothing to
       * find out. `aria-disabled` with a description says so without leaving a
       * dead stop in the tab order. */
      aria-disabled="true"
      aria-describedby="esr-answer-note"
    >
      <span className="esr-answer-icon">
        <Icon name="spark" size={12} />
      </span>
      <span className="esr-answer-text">{t('search.answer.title')}</span>
      <span className="ui-later">{t('later.chip')}</span>
      <span id="esr-answer-note" className="ui-sr-only">
        {t('later.arrivesLater')}
      </span>
    </div>
  );
}
