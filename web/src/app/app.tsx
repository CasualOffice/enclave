import { lazy, Suspense } from 'react';
import { AccessLoader } from '../shared/ui/mark.tsx';
import { IconSprite } from '../shared/ui/icon-sprite.tsx';
import { FailureState } from '../shared/ui/surface-states.tsx';
import { failureOf } from '../shared/api/failure.ts';
import { Shell } from './shell.tsx';
import { useRoute } from './routes.ts';
import { useSession, ViewerProvider } from './session.tsx';

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

/**
 * The application, gated on a real session.
 *
 * The gate is `GET /api/v1/me` and nothing else (`app/session.tsx`). Three of
 * the four branches below exist because a reload legitimately starts with no
 * access token — it is held in memory and never written to disk — so the
 * refresh cookie has to be exchanged before anyone can be called anonymous.
 * Rendering sign-in during that window would flash "you are logged out" at
 * every signed-in user on every reload.
 *
 * Sign-in is not inside the shell: there is no workspace to navigate yet, and
 * rendering a sidebar full of surfaces an unauthenticated visitor cannot reach
 * is the "screen is a promise" failure this milestone is built around.
 */
export function App() {
  const route = useRoute();
  const session = useSession();

  if (session.kind === 'restoring' || session.kind === 'loading') {
    return (
      <>
        <IconSprite />
        <AccessLoader />
      </>
    );
  }

  /* The API answered, and the answer was not about permission — it is down, or
   * its response did not parse. Sending the user to type a password would be
   * the wrong story: their credentials were never the problem. */
  if (session.kind === 'failed') {
    return (
      <>
        <IconSprite />
        {/* Centred on the canvas rather than inside the shell: the shell's
          * sidebar is a set of promises about surfaces we cannot currently
          * reach, and drawing it around a failure invites clicks that will all
          * fail the same way. */}
        <div className="boot-failure">
          <FailureState failure={failureOf(session.error)} />
        </div>
      </>
    );
  }

  if (session.kind === 'anonymous') {
    return (
      <>
        <IconSprite />
        <Suspense fallback={<AccessLoader />}>
          <SignInScreen />
        </Suspense>
      </>
    );
  }

  /* Signed in. `/signin` is no longer a place to be, so asking for it lands on
   * home rather than showing a form to someone who has already filled it in. */
  if (route.name === 'signin') {
    return (
      <ViewerProvider viewer={session.viewer}>
        <IconSprite />
        <Shell>
          <Suspense fallback={<AccessLoader />}>
            <HomeScreen />
          </Suspense>
        </Shell>
      </ViewerProvider>
    );
  }

  return (
    <ViewerProvider viewer={session.viewer}>
      <IconSprite />
      <Shell>
        <Suspense fallback={<AccessLoader />}>
          <Screen />
        </Suspense>
      </Shell>
    </ViewerProvider>
  );
}
