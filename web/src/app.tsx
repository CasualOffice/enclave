import { useEffect, useMemo, useState } from 'react';
import { GroupedFileList } from './components/grouped-list/grouped-file-list.tsx';
import type { DensityName } from './components/grouped-list/geometry.ts';
import { buildLibrary } from './fixtures/library.ts';
import { useListViewStore } from './state/list-view-store.ts';

/* The first surface.
 *
 * M5 step 1 is the grouped list and nothing else — the shell, the peek panel
 * and the routes are step 2 (`plans/M5-MVP-GA.md §4`), so this mounts the list
 * against a fixture library and lets the URL choose what to render. It is what
 * the benchmark drives and what the axe run inspects, which is the point: a
 * harness nothing runs is the thing this milestone exists not to build.
 *
 * The fixture is the data source only because there is no list endpoint to call
 * yet. When one lands it is fetched through TanStack Query and parsed with Zod
 * at the boundary (`CLAUDE.md`), and this module keeps its shape.
 */

type Surface = 'ready' | 'loading' | 'error' | 'empty' | 'filtered-empty';

const SURFACES = new Set<Surface>(['ready', 'loading', 'error', 'empty', 'filtered-empty']);

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

export function App() {
  const [params] = useState(() => readParams(window.location.search));
  const collapsed = useListViewStore((state) => state.collapsed);
  const selected = useListViewStore((state) => state.selected);
  const toggleGroup = useListViewStore((state) => state.toggleGroup);
  const toggleSelected = useListViewStore((state) => state.toggleSelected);

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

  const status = params.surface === 'loading' ? 'loading' : params.surface === 'error' ? 'error' : 'ready';
  const filtered = params.surface === 'filtered-empty';

  return (
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
    />
  );
}
