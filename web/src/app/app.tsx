import { lazy, Suspense } from 'react';
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
 *
 * The library screen used to be **defined here**, as a function that rendered
 * `GroupedFileList` and nothing else — which is how the surface came to have no
 * location bar, no view bar and no peek panel (`ENC-757`). A screen assembled in
 * the router is a screen with no owner; it now lives in `features/libraries/`
 * with the rest of its parts.
 */

const HomeScreen = lazy(() => import('../features/home/home-screen.tsx'));
const SearchScreen = lazy(() => import('../features/search/search-screen.tsx'));
const AskScreen = lazy(() => import('../features/ask/ask-screen.tsx'));
const AdminScreen = lazy(() => import('../features/admin/admin-screen.tsx'));
const SignInScreen = lazy(() => import('../features/auth/signin-screen.tsx'));
const LibraryScreen = lazy(() => import('../features/libraries/library-screen.tsx'));

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
