import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { replaceParams, useRoute } from '../../app/routes.ts';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Kbd } from '../../shared/ui/primitives.tsx';
import { useGroupedWindow } from '../libraries/list/use-grouped-window.ts';
import type { Density, GroupSpec } from '../libraries/list/geometry.ts';
import {
  activeFilters,
  filterDefs,
  readFilters,
  toParams,
  NO_FILTERS,
  type FilterId,
  type FilterOption,
  type FilterState,
} from './filters.ts';
import { FilterChips } from './filter-chips.tsx';
import { CORPUS_WORKSPACES, runFixtureSearch, unfilteredCount } from './fixture.ts';
import { noticeFor, RetrievalNotice } from './retrieval-notice.tsx';
import { ResultRow } from './result-row.tsx';
import {
  AnswerSlot,
  ErrorState,
  LoadingState,
  NewSearchState,
  NoResultsState,
  type ActiveFilterSummary,
  type SearchError,
} from './states.tsx';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import type { RetrievalMode } from './model.ts';
import './search.css';

/* The search screen.
 *
 * Three documents govern it and they do not overlap: the prototype's
 * `data-screen-label="Search"` block is authoritative for appearance,
 * `docs/09 §10` and `§11` for behaviour, `docs/17` for how the code is arranged.
 * Where the prototype and `docs/09` disagree, `docs/09` wins; the disagreements
 * are recorded at the site of each rather than in a list nobody reads.
 *
 * ── The URL is the state ─────────────────────────────────────────────────────
 *
 * There is no local copy of the query and no filter store. `docs/17 §4` puts
 * filters in the route and `docs/09 §10` requires the active filter set to be in
 * the URL so a search is shareable and restorable; a second copy in `useState`
 * is how the two drift, and the drift is invisible until somebody sends a link.
 * `replaceParams` rather than `navigate`, so typing does not add a history entry
 * per keystroke.
 *
 * ── Where the data comes from ────────────────────────────────────────────────
 *
 * `POST /api/v1/search` is specified in `docs/05 §11` and is **not implemented**
 * — `crates/api/src/` carries no search route. So this reads `fixture.ts`,
 * parsed through the documented response schema, and says so rather than
 * inventing a path. The swap is one call.
 */

/* One fixed-height row, so the list can be windowed by arithmetic rather than by
 * measurement. 80 px is the three lines the prototype draws — title, path,
 * excerpt — at its own sizes. */
const ROW_HEIGHT = 80;

/**
 * The results list as the grouped engine sees it: one group, no header.
 *
 * `geometry.ts` and `use-grouped-window.ts` are the engine `plans/M5-MVP-GA.md`
 * D38 sequenced first, and they are used here rather than copied — a second
 * windowing implementation in a second feature is two things to keep correct. A
 * flat list is the degenerate grouped case: one group of `n` with a header
 * height of zero. `sliceWindow` never emits a header for the group it has
 * pinned, and with one group that is always this one, so no header renders and
 * no sticky element is attached.
 *
 * A search that returns more than a hundred rows is ordinary — the fixture's
 * corpus does it on a one-word query — so `CLAUDE.md`'s virtualization rule
 * applies to this list and not only to the file list.
 */
const RESULT_DENSITY: Density = { rowHeight: ROW_HEIGHT, headerHeight: 0, columnsHeight: 0 };

const NOTHING_COLLAPSED: ReadonlySet<string> = new Set<string>();

/** The review knob's error, shaped like one the API client would raise. */
const REVIEW_ERROR: SearchError = { retryable: true, requestId: '01K3Q7X0PMDR4W8B2ZC6E5A9TN' };

/** Retrieval as this deployment actually behaves, overridable for review and for axe. */
function readRetrieval(params: URLSearchParams): { mode: RetrievalMode; degraded: boolean } {
  switch (params.get('retrieval')) {
    case 'hybrid':
      return { mode: 'hybrid', degraded: false };
    case 'degraded':
      return { mode: 'lexical', degraded: true };
    default:
      /* The M5 default, and not a placeholder: `ENC-661` is open, no
       * `EmbeddingProvider` is deployed, dense retrieval returns nothing.
       * `plans/M5-MVP-GA.md` D37 — the product ships lexical and renders the
       * header that says so. */
      return { mode: 'lexical', degraded: false };
  }
}

type Surface = 'ready' | 'loading' | 'error';

function optionText(option: FilterOption, t: (key: MessageKey) => string): string {
  return 'label' in option ? t(option.label) : option.text;
}

export default function SearchScreen() {
  const t = useT();
  const route = useRoute();

  /* Read once per route snapshot. `readFilters` builds a fresh object, so
   * deriving it inline would give every `useMemo` below a new dependency on
   * every render and quietly turn all of them off. */
  const params = route.params;
  const query = params.get('q') ?? '';
  const filters = useMemo(() => readFilters(params), [params]);
  const retrieval = useMemo(() => readRetrieval(params), [params]);
  const surfaceParam = params.get('surface');
  const retrievalParam = params.get('retrieval');
  const surface: Surface =
    surfaceParam === 'loading' ? 'loading' : surfaceParam === 'error' ? 'error' : 'ready';

  const defs = useMemo(() => filterDefs(CORPUS_WORKSPACES), []);

  /* One writer for the query string. A chip that wrote only its own key would
   * drop the others, because `replaceParams` replaces rather than merges. */
  const write = useCallback(
    (nextQuery: string, nextFilters: FilterState) => {
      const next = toParams(nextQuery, nextFilters);
      /* Carried through so a shared review link keeps the surface it was
       * showing. Neither is part of the product's filter set. */
      if (surfaceParam !== null) next['surface'] = surfaceParam;
      if (retrievalParam !== null) next['retrieval'] = retrievalParam;
      replaceParams(next);
    },
    [surfaceParam, retrievalParam],
  );

  const onFilterChange = useCallback(
    (id: FilterId, value: string) => write(query, { ...filters, [id]: value }),
    [write, query, filters],
  );

  const clearFilters = useCallback(() => write(query, NO_FILTERS), [write, query]);

  const response = useMemo(
    () => runFixtureSearch(query, filters, retrieval.mode, retrieval.degraded),
    [query, filters, retrieval],
  );

  const results = response.results;
  const notice = noticeFor(response.diagnostics);

  /* ------------------------------------------------------------- windowing */

  const groups = useMemo<readonly GroupSpec[]>(
    () => [{ id: 'results', name: '', count: results.length }],
    [results.length],
  );
  const noToggle = useCallback(() => undefined, []);
  const { layout, slice, scrollerRef, windowRef, onScroll } = useGroupedWindow(
    groups,
    NOTHING_COLLAPSED,
    RESULT_DENSITY,
    noToggle,
  );

  /* -------------------------------------------------- keyboard through rows */

  /* `-1` means the user has not entered the list yet. The roving tab stop still
   * exists at row 0 so Tab from the field reaches the results; only the focus
   * ring moves, and only once an arrow key is pressed. */
  const [activeIndex, setActiveIndex] = useState(-1);
  const scrollerNode = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const setScroller = useCallback(
    (node: HTMLDivElement | null) => {
      scrollerNode.current = node;
      scrollerRef(node);
    },
    [scrollerRef],
  );

  /* A new result set is a new list; keeping row 41 highlighted across it would
   * point at a different document with the same index. */
  useEffect(() => {
    setActiveIndex(-1);
  }, [query, filters]);

  useEffect(() => {
    if (activeIndex < 0) return;
    const scroller = scrollerNode.current;
    if (scroller === null) return;

    /* Bring the row into view before looking for it. At 240 px of overscan the
     * neighbouring row is always already rendered; a row further away may not
     * be, and this effect re-runs when the window catches up. */
    const top = activeIndex * ROW_HEIGHT;
    if (top < scroller.scrollTop) scroller.scrollTop = top;
    else if (top + ROW_HEIGHT > scroller.scrollTop + scroller.clientHeight) {
      scroller.scrollTop = top + ROW_HEIGHT - scroller.clientHeight;
    }

    const node = scroller.querySelector<HTMLElement>(`[data-result-index="${activeIndex}"]`);
    node?.focus({ preventScroll: true });
  }, [activeIndex, slice]);

  const moveActive = useCallback(
    (delta: number) => {
      setActiveIndex((current) =>
        Math.max(0, Math.min(results.length - 1, (current < 0 ? -1 : current) + delta)),
      );
    },
    [results.length],
  );

  const onListKeyDown = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        moveActive(1);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        moveActive(-1);
      } else if (event.key === 'Escape') {
        setActiveIndex(-1);
        inputRef.current?.focus();
      }
    },
    [moveActive],
  );

  /* ----------------------------------------------------------------- render */

  const summaries: readonly ActiveFilterSummary[] = activeFilters(filters).map((id) => {
    const def = defs.find((candidate) => candidate.id === id)!;
    const option = def.options.find((candidate) => candidate.value === filters[id]);
    return {
      id,
      key: t(def.label),
      value: option === undefined ? filters[id] : optionText(option, t),
    };
  });

  /* One query for four questions: which state to render, whether to count, and
   * whether the answer slot and the retrieval notice have anything to describe. */
  const searched = query.trim().length > 0;

  let body: ReactNode;
  if (surface === 'error') {
    body = <ErrorState error={REVIEW_ERROR} onRetry={() => write(query, filters)} />;
  } else if (surface === 'loading') {
    body = <LoadingState />;
  } else if (!searched) {
    body = <NewSearchState />;
  } else if (results.length === 0) {
    body = (
      <NoResultsState
        query={query}
        filters={summaries}
        unfilteredCount={unfilteredCount(query)}
        lexical={notice !== null}
        onClearFilters={clearFilters}
      />
    );
  } else {
    body = (
      <div className="esr-scroller" ref={setScroller} onScroll={onScroll} onKeyDown={onListKeyDown}>
        {/* A spacer, hidden from the accessibility tree, whose only job is to
         * give the scrollbar something to measure. The rows live in the
         * absolutely positioned window beside it. */}
        <div
          className="esr-spacer"
          aria-hidden="true"
          style={{ blockSize: `${layout.totalHeight}px` }}
        />
        <div
          className="esr-window"
          role="list"
          aria-label={t('search.results.label')}
          ref={windowRef}
        >
          {slice.items.map((item) => {
            if (item.kind !== 'row') return null;
            const result = results[item.rowIndex];
            return result === undefined ? null : (
              <ResultRow
                key={item.key}
                result={result}
                index={item.rowIndex}
                position={item.rowIndex + 1}
                setSize={results.length}
                active={item.rowIndex === (activeIndex < 0 ? 0 : activeIndex)}
                onActivate={setActiveIndex}
              />
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="esr">
      {/* The sheet has no top bar (`docs/09 §3` after `ENC-676`), so the screen
       * names itself for a screen reader and nowhere else. */}
      <h1 className="ui-sr-only">{t('search.title')}</h1>

      {/* The prototype's search bar, value for value. Its placeholder invites
       * "or ask a question…", which M5 cannot answer — the answer slot below
       * says so in the unbuilt treatment rather than the field implying it. */}
      <div className="esr-bar">
        <Icon name="s" size={16} className="esr-bar-icon" />
        <input
          ref={inputRef}
          className="esr-input"
          type="search"
          value={query}
          aria-label={t('search.input.label')}
          placeholder={t('search.input.placeholder')}
          onChange={(event) => write(event.target.value, filters)}
          onKeyDown={(event) => {
            if (event.key === 'Escape' && query.length > 0) {
              event.preventDefault();
              write('', filters);
            } else if (event.key === 'ArrowDown' && results.length > 0) {
              event.preventDefault();
              setActiveIndex(0);
            }
          }}
        />
        <span className="esr-bar-kbd">
          <Kbd>{t('search.key.escape')}</Kbd>
        </span>
      </div>

      <div className="esr-filters">
        <FilterChips defs={defs} filters={filters} onChange={onFilterChange} />
        {/* No count before anything has been searched. "No results" against an
         * empty field is a report on a search nobody ran, and it is the same
         * class of untruth as the notice below claiming a degraded result set
         * when there is no result set. Nor after a failed one: "136 results"
         * beside "this search could not be run" is two answers to one question,
         * and the confident one is the wrong one. */}
        {searched && surface !== 'error' && (
          <span className="esr-count">
            {surface === 'loading'
              ? t('search.results.counting')
              : t('search.results.count', { count: response.total })}
          </span>
        )}
      </div>

      {/* Order matters. The answer slot is a promise about the product; the
       * retrieval notice is a fact about *this* result set — which is why both
       * wait for a query. A degraded-search header over an empty screen says
       * "every file you can open is still being searched" when nothing is being
       * searched at all, and a notice that is always there is a notice nobody
       * reads on the day it matters. */}
      {searched && surface === 'ready' && <AnswerSlot />}
      {searched && surface === 'ready' && <RetrievalNotice diagnostics={response.diagnostics} />}

      {body}

      {/* The prototype's footer. `Space` / peek is dropped: the peek panel is
       * another feature's surface, and a shortcut hint for something this
       * screen cannot do is the "reads as working" failure at hint scale. What
       * is left is true — the arrows move the roving focus, Enter follows the
       * row's link. */}
      <div className="esr-foot">
        <span>
          <Kbd>{t('search.key.arrows')}</Kbd>
          {t('search.foot.navigate')}
        </span>
        <span>
          <Kbd>{t('search.key.enter')}</Kbd>
          {t('search.foot.open')}
        </span>
        <span className="esr-foot-end">{t('search.foot.access')}</span>
      </div>
    </div>
  );
}
