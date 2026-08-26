import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams, useWriteSearchParams } from '../../shared/url-state.ts';
import { buildLibrary } from '../../fixtures/library.ts';
import { GroupedFileList } from './list/grouped-file-list.tsx';
import type { DensityName } from './list/geometry.ts';
import { useListViewStore } from './list-view-store.ts';
import { LocationBar } from './location-bar.tsx';
import { ViewBar } from './view-bar.tsx';
import { FilterChipRow } from './filter-chip-row.tsx';
import { PeekPanel } from './peek/peek-panel.tsx';
import { SelectionBar, type SelectionAction } from './selection-bar/selection-bar.tsx';
import {
  ACTIVE_FILTERS,
  BREADCRUMB,
  PRESENCE,
  SAVED_VIEWS,
  VIEW_SUMMARY,
  peekFor,
  pillFor,
} from './fixture.ts';
import { PEEK_WIDTH_DEFAULT, type PeekTab } from './model.ts';
import './library.css';
import './peek/peek.css';
import './selection-bar/selection-bar.css';

/* The library surface: the five children `specs/library.md §0` lists, in order.
 *
 *   LocationBar (38) · ViewBar (42) · FilterChipRow · BodyGrid · SelectionBar
 *
 * It used to be none of them. The route rendered `GroupedFileList` straight into
 * the sheet, so the first thing on screen was a column header and there was no
 * way to tell which folder you were in, how sensitive it was, or what you could
 * do with a selection. `ENC-757`–`ENC-759`.
 *
 * `position:relative` on the sheet is what the selection bar is absolutely
 * positioned against, and that lives in `app/shell.css`. It is load-bearing.
 */

type Surface = 'ready' | 'loading' | 'error' | 'empty' | 'filtered-empty';

const SURFACES = new Set<Surface>(['ready', 'loading', 'error', 'empty', 'filtered-empty']);

/**
 * The selection's actions, in the prototype's order.
 *
 * `allowed` is an AND over the booleans the server sent for every selected row.
 * With no listing endpoint there is nothing to AND yet, so `download` is `false`
 * — which is the honest placeholder, because it renders the DENIED treatment
 * rather than pretending a capability the client has not been told about.
 */
const SELECTION_ACTIONS: readonly SelectionAction[] = [
  { id: 'share', label: 'library.selection.share', icon: 'share', shortcut: 'key.s', allowed: true },
  {
    id: 'download',
    label: 'library.selection.download',
    icon: 'down',
    shortcut: 'key.d',
    allowed: false,
  },
  { id: 'move', label: 'library.selection.move', icon: 'move', shortcut: 'key.m', allowed: true },
  { id: 'label', label: 'library.selection.label', shortcut: 'key.l', allowed: true },
  { id: 'retention', label: 'library.selection.retention', allowed: true },
];

function readParams(search: string) {
  const params = new URLSearchParams(search);
  const rows = Number.parseInt(params.get('rows') ?? '', 10);
  const surfaceParam = params.get('surface') ?? 'ready';
  const surface: Surface = SURFACES.has(surfaceParam as Surface)
    ? (surfaceParam as Surface)
    : 'ready';
  const density: DensityName = params.get('density') === 'compact' ? 'compact' : 'default';
  const collapse = (params.get('collapse') ?? '').split(',').filter((id) => id.length > 0);
  return {
    rows: Number.isFinite(rows) && rows > 0 ? rows : 100_000,
    surface,
    density,
    collapse,
  };
}

export function LibraryScreen() {
  /* Read once: `rows` and `surface` drive a fixture whose generation is inside
   * the measured window, and re-reading them on every query-string write would
   * rebuild 100 000 rows when a filter chip is removed. */
  const [params] = useState(() => readParams(window.location.search));
  const urlParams = useSearchParams();
  const writeParams = useWriteSearchParams();

  const collapsed = useListViewStore((state) => state.collapsed);
  const selected = useListViewStore((state) => state.selected);
  const toggleGroup = useListViewStore((state) => state.toggleGroup);
  const toggleSelected = useListViewStore((state) => state.toggleSelected);
  const clearSelection = useListViewStore((state) => state.clearSelection);
  const peekWidth = useListViewStore((state) => state.peekWidth);
  const setPeekWidth = useListViewStore((state) => state.setPeekWidth);

  const [peekTab, setPeekTab] = useState<PeekTab>('preview');

  /* Generating the fixture is deliberately inside the measured window: a "first
   * paint" number that starts after the data exists measures the easy half. */
  const library = useMemo(
    () => (params.surface === 'empty' ? { groups: [], rows: [] } : buildLibrary(params.rows)),
    [params.rows, params.surface],
  );

  useEffect(() => {
    for (const id of params.collapse) toggleGroup(id);
  }, [params.collapse, toggleGroup]);

  useEffect(() => {
    /* Two frames: the first callback runs before the commit is painted, the
     * second after it. This is the mark the benchmark reads for `docs/09 §2`'s
     * first-paint budget. */
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        performance.mark('enclave:rows-painted');
      });
    });
  }, []);

  /* Which row is peeked is **URL state** (`docs/17 §4`): it is part of what a
   * colleague receives when the view is shared, and it survives back/forward.
   * How wide the panel is, is not — that is this browser's preference. */
  const peekId = urlParams.get('peek') ?? '';
  const activeView = urlParams.get('view') ?? 'all';
  const filtersInUrl = urlParams.get('filter');
  const filters = filtersInUrl === null ? ACTIVE_FILTERS : [];

  const peekRow = useMemo(
    () => (peekId === '' ? undefined : library.rows.find((row) => row.id === peekId)),
    [library.rows, peekId],
  );

  const setPeek = useCallback(
    (id: string | null) => writeParams({ peek: id }),
    [writeParams],
  );

  const togglePeek = useCallback(() => {
    if (peekRow !== undefined) setPeek(null);
    else setPeek(library.rows[0]?.id ?? null);
  }, [library.rows, peekRow, setPeek]);

  const stepPeek = useCallback(
    (delta: number) => {
      const index = library.rows.findIndex((row) => row.id === peekId);
      if (index < 0) return;
      const next = library.rows[index + delta];
      if (next !== undefined) setPeek(next.id);
    },
    [library.rows, peekId, setPeek],
  );

  const status =
    params.surface === 'loading' ? 'loading' : params.surface === 'error' ? 'error' : 'ready';
  const filtered = params.surface === 'filtered-empty';
  const peekOpen = peekRow !== undefined;

  return (
    <div className="lib" data-screen="library">
      <LocationBar
        crumbs={BREADCRUMB}
        classification="confidential"
        presence={PRESENCE}
        peekOpen={peekOpen}
        onTogglePeek={togglePeek}
      />

      <ViewBar
        views={SAVED_VIEWS}
        activeView={activeView}
        onSelectView={(id) => writeParams({ view: id === 'all' ? null : id })}
        onUpload={() => undefined}
      />

      <FilterChipRow
        filters={filters}
        onRemove={() => writeParams({ filter: 'none' })}
        groupBy={VIEW_SUMMARY.groupBy}
        sortBy={VIEW_SUMMARY.sortBy}
      />

      <div
        className="lib-body"
        data-peek={peekOpen ? 'open' : 'closed'}
        style={{ '--peek-w': `${peekWidth}px` } as React.CSSProperties}
      >
        <div className="lib-list">
          <GroupedFileList
            groups={filtered ? [] : library.groups}
            rows={filtered ? [] : library.rows}
            collapsed={collapsed}
            onToggleGroup={toggleGroup}
            selected={selected}
            onToggleSelect={toggleSelected}
            density={params.density}
            status={status}
            error={
              params.surface === 'error'
                ? { retryable: true, requestId: '01K3Q7X0PMDR4W8B2ZC6E5A9TN' }
                : undefined
            }
            filtersActive={filtered}
            unfilteredCount={filtered ? params.rows : 0}
            onRetry={() => window.location.reload()}
            onClearFilters={() => {
              window.location.search = '';
            }}
            onUpload={() => undefined}
            peekId={peekId}
            onPeek={setPeek}
            pillFor={pillFor}
          />
        </div>

        {peekRow !== undefined && (
          <PeekPanel
            file={peekFor(peekRow)}
            tab={peekTab}
            onSelectTab={setPeekTab}
            width={peekWidth === 0 ? PEEK_WIDTH_DEFAULT : peekWidth}
            onResize={setPeekWidth}
            onClose={() => setPeek(null)}
            onPrevious={() => stepPeek(-1)}
            onNext={() => stepPeek(1)}
          />
        )}
      </div>

      <SelectionBar
        count={selected.size}
        actions={SELECTION_ACTIONS}
        onClear={clearSelection}
      />
    </div>
  );
}

export default LibraryScreen;
