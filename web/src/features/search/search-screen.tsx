import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { useT } from '../../shared/i18n/index.tsx';
/* `shared/url-state.ts`, not `app/routes.ts`.
 *
 * `docs/17 §2` forbids a feature from importing `app/`, and `url-state` exists
 * precisely to close the gap that rule left — its own header records that two
 * sessions independently reached for `window.location` instead. This screen
 * predates it and kept the illegal import; the boundary rule in
 * `tools/lint-web.mjs` is what finally surfaced that. */
import { useSearchString, useWriteSearchParams } from '../../shared/url-state.ts';
import { Field, Push } from '../../shared/ui/layout.tsx';
import { Button, Kbd } from '../../shared/ui/primitives.tsx';
import { useGroupedWindow } from '../../shared/list/use-grouped-window.ts';
import type { Density, GroupSpec } from '../../shared/list/geometry.ts';
import {
  activeFilters,
  filterDefs,
  readFilters,
  toParams,
  NO_FILTERS,
  type FilterOption,
  type FilterState,
} from './filters.ts';
import { CORPUS_WORKSPACES } from './fixture.ts';
import { useSearch } from './api.ts';
import { FailureState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
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
 * `POST /api/v1/search` is implemented (`crates/api/src/routes/search.rs`) and
 * this screen calls it. `features/search/api.ts` owns the wire schema, which is
 * *smaller* than `docs/05 §11` describes: no classification, no owner, no
 * modified date. Those render as absences rather than as invented defaults —
 * see `model.ts`.
 *
 * `diagnostics.degraded` comes from the server on every response and is `true`
 * today, because the API process holds no vector index. The client renders that
 * statement; it never decides its own degradation.
 *
 * The narrowing filters are refused by the route with a `400` naming the field,
 * so the filter control renders unbuilt rather than sending a request that
 * cannot succeed. Filtering client-side would be worse: it narrows what is shown
 * without narrowing what was searched.
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
  const writeParams = useWriteSearchParams();

  /* Memoized on the search *string*, not on a `URLSearchParams`.
   *
   * `useSearchParams()` allocates a fresh object per render — it has to, the
   * object is mutable — so depending on it would give every `useMemo` below a
   * new dependency on every render and quietly turn all of them off. The
   * string is stable between actual changes, which is what a dependency needs
   * to be. */
  const search = useSearchString();
  const params = useMemo(() => new URLSearchParams(search), [search]);
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
      /* `useWriteSearchParams` merges rather than replaces, so every key this
       * screen does not name is preserved. `toParams` already emits the full
       * filter set, and the two carried keys above are added explicitly, so the
       * behaviour is unchanged — but a key added later by another surface is no
       * longer silently dropped. */
      writeParams(next);
    },
    [surfaceParam, retrievalParam, writeParams],
  );

  const clearFilters = useCallback(() => write(query, NO_FILTERS), [write, query]);

  /* `POST /api/v1/search`, for real (`features/search/api.ts`).
   *
   * The `?retrieval=` knob above still exists for review and for axe, but it no
   * longer decides what the notice says: `diagnostics` comes from the server,
   * which is the only thing that knows whether the vector store answered. A
   * client that decided its own degradation would be reporting on itself. */
  const searchQuery = useSearch(query);
  const response = searchQuery.data;

  const results = response?.results ?? [];
  const diagnostics = response?.diagnostics ?? retrieval;
  const notice = noticeFor(diagnostics);

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
  /* The bar rather than the input.
   *
   * `Field` draws the box, the placeholder colour and the one focus ring
   * `docs/09 §15` asks for, and its props are the `<input>`'s — but not `ref`,
   * which is not part of `InputHTMLAttributes`. Holding the band and asking it
   * for its input is the same query the roving focus below already makes of the
   * scroller, and it is cheaper than widening a shared component for one
   * caller. */
  const barRef = useRef<HTMLDivElement | null>(null);
  const focusInput = useCallback(() => {
    barRef.current?.querySelector('input')?.focus();
  }, []);

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
        focusInput();
      }
    },
    [moveActive, focusInput],
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
  } else if (searchQuery.isError) {
    /* A real failure, rendered as the right one of the two. A `403` from the
     * policy chain is a refusal with no retry; a `5xx` is a fault with one.
     * `FailureState` owns that branch so this screen does not have to. */
    body = (
      <FailureState failure={failureOf(searchQuery.error)} onRetry={() => void searchQuery.refetch()} />
    );
  } else if (surface === 'loading' || (searched && searchQuery.isPending)) {
    body = <LoadingState />;
  } else if (!searched) {
    body = <NewSearchState />;
  } else if (results.length === 0) {
    body = (
      <NoResultsState
        query={query}
        filters={summaries}
        /* Zero, because the server sends no unfiltered total and the client has
         * no honest way to compute one. The empty state reads as "nothing
         * matched" rather than claiming a count it does not have. */
        unfilteredCount={0}
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
    /* `--esr-row-h` is the windowing arithmetic's row height, published to CSS
     * from the one constant that computes with it. Two copies of 80 is how the
     * absolutely positioned window and the spacer that sizes the scrollbar stop
     * agreeing. */
    <div className="esr" style={{ '--esr-row-h': `${ROW_HEIGHT}px` } as CSSProperties}>
      {/* The sheet has no top bar (`docs/09 §3` after `ENC-676`), so the screen
       * names itself for a screen reader and nowhere else. */}
      <h1 className="ui-sr-only">{t('search.title')}</h1>

      {/* The prototype's search bar, value for value — but the *field* is
       * `Field`, which owns the one focus ring in the tree. There were three
       * incompatible treatments across five inputs (a two-layer box-shadow, an
       * outline at +2px, an outline at -2px), and a keyboard user relearning the
       * affordance per screen is what `docs/09 §15` is trying to prevent.
       *
       * Its placeholder invites "or ask a question…", which M5 cannot answer —
       * the answer slot below says so in the unbuilt treatment rather than the
       * field implying it. */}
      <div className="esr-bar" ref={barRef}>
        <Field
          label="search.input.label"
          icon="s"
          size="lg"
          type="search"
          value={query}
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
          trailing={<Kbd>{t('search.key.escape')}</Kbd>}
        />
      </div>

      <div className="esr-filters">
        {/* **The filters render unbuilt, not functional and not denied.**
          *
          * `POST /api/v1/search` declares `workspaceIds`, `libraryIds`, `types`,
          * `classificationMax` and `modifiedAfter` and answers `400` naming the
          * field for every one of them. That refusal is deliberate on the server
          * and the client must not route around it: a narrowing filter that is
          * accepted and then not applied returns **more** than the caller asked
          * for, and a `classificationMax` of `INTERNAL` answered with
          * `CONFIDENTIAL` hits is a disclosure produced by a control that
          * appeared to work.
          *
          * Filtering client-side over one page of results would be the same lie
          * in a different place — it would narrow what is shown without
          * narrowing what was searched, so a document excluded by the chip and
          * absent from the page reads identically to one that does not exist.
          *
          * Unbuilt rather than denied, because this is the product not having
          * the feature yet — not the policy chain refusing this user
          * (`docs/17 §6`). */}
        <span className="esr-filters-unbuilt">
          <Button
            label="search.filters.label"
            icon="filter"
            size="sm"
            state={{ kind: 'unbuilt', note: 'search.filters.unbuilt' }}
          />
        </span>
        {/* No count before anything has been searched. "No results" against an
         * empty field is a report on a search nobody ran, and it is the same
         * class of untruth as the notice below claiming a degraded result set
         * when there is no result set. Nor after a failed one: "136 results"
         * beside "this search could not be run" is two answers to one question,
         * and the confident one is the wrong one. */}
        {searched && surface !== 'error' && (
          <>
            <Push />
            <span className="esr-count">
              {surface === 'loading'
                ? t('search.results.counting')
                : t('search.results.count', { count: results.length })}
            </span>
          </>
        )}
      </div>

      {/* Order matters. The answer slot is a promise about the product; the
       * retrieval notice is a fact about *this* result set — which is why both
       * wait for a query. A degraded-search header over an empty screen says
       * "every file you can open is still being searched" when nothing is being
       * searched at all, and a notice that is always there is a notice nobody
       * reads on the day it matters. */}
      {searched && surface === 'ready' && <AnswerSlot />}
      {searched && surface === 'ready' && response !== undefined && (
        <RetrievalNotice diagnostics={response.diagnostics} />
      )}

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
        <Push />
        <span>{t('search.foot.access')}</span>
      </div>
    </div>
  );
}
