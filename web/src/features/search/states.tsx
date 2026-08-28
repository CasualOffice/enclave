import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Card } from '../../shared/ui/layout.tsx';
import { LaterChip, Skeleton } from '../../shared/ui/primitives.tsx';
import {
  ErrorState as SurfaceErrorState,
  EmptyState,
  FilteredEmptyState,
  type FetchFailure,
} from '../../shared/ui/surface-states.tsx';
import type { FilterId } from './filters.ts';

/* The four states `docs/09 §11` requires — as this screen's *words* wrapped
 * around the shared block, rather than as a fifth copy of the block.
 *
 * `web/design-system/enclave-client-prototype.html`'s Search block draws exactly
 * one of them: a centred *"No files match “{{searchQ}}”"* with a Clear search
 * button. That is the filtered-empty state and it names no filters, so it cannot
 * tell a user whose query is wrong from a user whose *filters* are wrong — which
 * is the single distinction `docs/09 §11` asks this state to draw. There is no
 * new-empty state, no loading state and no error state anywhere in the block.
 *
 * ## Why there is no `Figure` in this file any more
 *
 * There was one, and it was character-for-character the same helper as the ones
 * in `features/home`, `features/ask` and `features/libraries/list`. Four copies
 * of a 44px square with a 13.75px inset, and four copies of the `:dir(rtl)`
 * mirror that keeps its window's square corner on the leading edge. Nobody would
 * have noticed one of them drifting, and the request-ID row beside it *had*
 * drifted — three of seven copies isolated the identifier and four did not, so
 * the same string rendered correctly on three screens and reversed on four.
 *
 * `shared/ui/surface-states` is the one implementation now. What stays here is
 * the part that is genuinely search's: which sentence each state says, and the
 * list of active filter chips the filtered-empty state has to name.
 */

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
 *
 * No keyboard hint, though the surrounding surfaces have room for one.
 * `docs/09 §6` binds `/` to "focus search" and nothing in this codebase
 * implements it — it is an application-level shortcut and this screen does not
 * own the application. A hint for a key that does nothing is the same
 * promise-without-a-product this milestone is named after, at hint scale.
 */
export function NewSearchState() {
  return <EmptyState heading="search.state.new.title" body="search.state.new.body" fill />;
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

  /* Two different sentences under one heading, and the branch is the whole
   * point of the state.
   *
   * Filtered: the count separates "your filters are too narrow" from "this query
   * finds nothing", which are different problems with different fixes.
   * Collapsing them is how a user concludes the document is gone.
   *
   * Unfiltered and lexical: the useful advice is the retrieval notice's — the
   * index matched the words you typed, so type the words the document would use.
   * Saying it again here is not a repetition; this is the moment the user is
   * actually stuck. */
  const body = filtered
    ? 'search.state.noResults.filtered'
    : lexical
      ? 'search.state.noResults.lexicalAdvice'
      : 'search.state.noResults.advice';

  return (
    <FilteredEmptyState
      heading="search.state.noResults.title"
      body={body}
      values={{ query, count: unfilteredCount }}
      fill
      {...(filtered
        ? { clearLabel: 'search.state.noResults.clearFilters' as const, onClear: onClearFilters }
        : {})}
    >
      {filtered && (
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
      )}
    </FilteredEmptyState>
  );
}

/* ------------------------------------------------------------------ loading */

/**
 * Skeleton rows in the loaded row's exact box model.
 *
 * `docs/09 §11` states this as a layout-shift requirement, and the shared box is
 * literal: `.esr-hit` and `.esr-skeleton-hit` are the same three lines at the
 * same heights inside the same row, so nothing moves when results land.
 * Rendering `null` here would be three states and fails review (`docs/17 §8`).
 *
 * The bars themselves are `Skeleton`. It pulses opacity rather than sliding a
 * 200%-wide gradient across itself, which is what this file used to do: a sweep
 * repaints the whole skeleton every frame and `docs/09 §2` budgets 60fps.
 */
export function LoadingState({ rows = 8 }: { rows?: number }) {
  const t = useT();
  /* Deterministic widths. A skeleton that reshuffles every render reads as data
   * arriving and leaving again. */
  const widths = [58, 71, 46, 64, 52, 77, 61, 44];

  return (
    <div
      className="esr-loading"
      role="status"
      aria-busy="true"
      aria-label={t('search.state.loading')}
    >
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="esr-row" aria-hidden="true">
          <div className="esr-skeleton-hit">
            <span className="esr-line esr-line-title">
              <Skeleton />
              <Skeleton width={`${widths[index % 8]}%`} />
            </span>
            <span className="esr-line esr-line-meta">
              <Skeleton width="38%" />
            </span>
            <span className="esr-line esr-line-excerpt">
              <Skeleton width="86%" />
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------- error */

/**
 * What this screen knows about a failed read.
 *
 * Structurally the shared `FetchFailure`, and deliberately re-exported under the
 * name the screen already uses rather than renamed: `docs/17 §7` says
 * retryability is the API client's classification and never a guess, and both
 * shapes say exactly that.
 */
export type SearchError = FetchFailure;

/**
 * A read that did not complete.
 *
 * **A policy denial never arrives here** (`docs/09 §11`, `docs/17 §7`): a `403`
 * from DLP, a barrier or conditional access is a successful request with a
 * refusing answer, it renders inline with a reason and a remedy, and it never
 * offers retry — `FailureState` in `shared/ui/surface-states` owns that branch.
 * Neither does the degraded-search notice arrive here: a lexical fallback
 * returned real results, and rendering it as a failure would teach a user the
 * product is broken when it is merely narrower.
 *
 * The four catalog keys are this screen's because the *sentence* is; the block,
 * the ring, the retry-only-when-retryable rule and the copyable request ID are
 * not, and were duplicated five times to carry the one part that is.
 */
export function ErrorState({ error, onRetry }: { error: SearchError; onRetry: () => void }) {
  return (
    <SurfaceErrorState
      heading="search.state.error.title"
      body="search.state.error.body"
      bodyFinal="search.state.error.bodyFinal"
      retry="search.state.error.retry"
      error={error}
      onRetry={onRetry}
      fill
    />
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
 *
 * The raised surface is a `Card`; the row inside it carries the ARIA, because
 * `Card` renders no attributes of its own and the `aria-disabled` /
 * `aria-describedby` pair *is* the unbuilt contract.
 */
export function AnswerSlot() {
  const t = useT();
  return (
    <Card padded={false} className="esr-answer-card">
      <span
        className="esr-answer"
        /* Not focusable and not interactive: there is nowhere to go and nothing
         * to find out. `aria-disabled` with a description says so without
         * leaving a dead stop in the tab order. */
        aria-disabled="true"
        aria-describedby="esr-answer-note"
      >
        <span className="esr-answer-icon">
          <Icon name="spark" size={12} />
        </span>
        <span className="esr-answer-text">{t('search.answer.title')}</span>
        <LaterChip note="later.chip" />
        {/* The release note, reached through `aria-describedby` rather than
         * shown. D33 splits the marker in two so the chip can stay one word and
         * the note can be a sentence; `ui-sr-only` is the shared clip, never a
         * physical offset. */}
        <span id="esr-answer-note" className="ui-sr-only">
          {t('later.arrivesLater')}
        </span>
      </span>
    </Card>
  );
}
