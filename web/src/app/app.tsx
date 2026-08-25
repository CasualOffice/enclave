import { lazy, Suspense, useEffect, useMemo, useState } from 'react';
import { GroupedFileList } from '../features/libraries/list/grouped-file-list.tsx';
import type { DensityName } from '../features/libraries/list/geometry.ts';
import { buildLibrary } from '../fixtures/library.ts';
import { useListViewStore } from '../features/libraries/list-view-store.ts';
import { AccessLoader } from '../shared/ui/mark.tsx';
import { IconSprite } from '../shared/ui/icon-sprite.tsx';
import { Shell } from './shell.tsx';
import { useRoute } from './routes.ts';

/* The router's body, and the seam every screen plugs into.
 *
 * Each screen is a `lazy` import so it is its own chunk: `docs/09 §2` requires
 * admin and editor routes to be split out of the main bundle, and the budget it
 * protects is a gate. `AccessLoader` covers the gap — the mark's three layers
 * scanning, paired with "Checking your access…", because that is what the
 * policy chain is actually doing while a route settles.
 *
 * `features/` own their own directories and never import each other
 * (`docs/17 §2`). When two need the same thing it moves down into `shared/` or
 * `entities/`; two screens reaching for one component is the signal, not a
 * reason to cross the boundary.
 */

const HomeScreen = lazy(() => import('../features/home/home-screen.tsx'));
const SearchScreen = lazy(() => import('../features/search/search-screen.tsx'));
const AskScreen = lazy(() => import('../features/ask/ask-screen.tsx'));
const AdminScreen = lazy(() => import('../features/admin/admin-screen.tsx'));
const SignInScreen = lazy(() => import('../features/auth/signin-screen.tsx'));

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

/**
 * The library list.
 *
 * Still fed by a fixture, because there is no list endpoint to call yet. When
 * one lands it is fetched through TanStack Query and parsed with Zod at the
 * boundary (`docs/17 §3`) and this component keeps its shape — the list itself
 * takes rows and groups, and has never known where they came from.
 */
function LibraryScreen() {
  const route = useRoute();
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

  const status =
    params.surface === 'loading' ? 'loading' : params.surface === 'error' ? 'error' : 'ready';
  const filtered = params.surface === 'filtered-empty';

  return (
    <GroupedFileList
      key={route.path}
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

function Screen() {
  const route = useRoute();
  switch (route.name) {
    case 'home':
      return <HomeScreen />;
    case 'search':
      return <SearchScreen />;
    case 'ask':
      return <AskScreen />;
    case 'admin':
      return <AdminScreen />;
    case 'signin':
      return <SignInScreen />;
    case 'library':
    default:
      return <LibraryScreen />;
  }
}

export function App() {
  const route = useRoute();

  /* Sign-in is not inside the shell: there is no workspace to navigate yet, and
   * rendering a sidebar full of surfaces an unauthenticated visitor cannot
   * reach is the "screen is a promise" failure this milestone is built around. */
  if (route.name === 'signin') {
    return (
      <>
        <IconSprite />
        <Suspense fallback={<AccessLoader />}>
          <SignInScreen />
        </Suspense>
      </>
    );
  }

  return (
    <>
      <IconSprite />
      <Shell>
        <Suspense fallback={<AccessLoader />}>
          <Screen />
        </Suspense>
      </Shell>
    </>
  );
}
