import { useEffect, useState } from 'react';
import { useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import { Viewer } from '../entities/user/model.ts';
import { onSessionEnded, request, SESSION_ENDED } from '../shared/api/client.ts';
import { hasAccessToken, refresh } from '../shared/api/session.ts';

/* Who is signed in, and how the application finds out.
 *
 * **`GET /api/v1/me` is the only answer.** Not the presence of a token, not a
 * flag in storage, not what sign-in returned a moment ago — the server states
 * the identity and the client renders the statement (`docs/17 §1`). A token
 * that was revoked, or signed by a key that has since rotated, looks exactly
 * like a good one from here; only asking finds out.
 *
 * The boot sequence has one step that is easy to leave out and expensive to
 * miss. A reload starts with **no access token**, because the token is held in
 * memory and deliberately never written to disk (`shared/api/session.ts`). The
 * durable half is the `HttpOnly` refresh cookie. So before concluding that
 * nobody is signed in, the application spends one request finding out —
 * otherwise every reload would bounce a signed-in user to the sign-in screen
 * with their session still perfectly valid.
 */

/* The viewer context moved to `entities/user/viewer.tsx`.
 *
 * `features/home` read `useViewer` from here, and `docs/17 §2` forbids a
 * feature importing `app/`. *Who is signed in* is a property of the user
 * entity; *how the application finds out* is the orchestration below, and only
 * the second half is app-level. Re-exported so `app/` keeps one import site. */
export { useViewer, ViewerProvider } from '../entities/user/viewer.tsx';

/** `GET /api/v1/me`, parsed at the boundary and nowhere else (`docs/17 §3`). */
export function fetchViewer(signal?: AbortSignal): Promise<Viewer> {
  return request('/me', Viewer, signal === undefined ? {} : { signal });
}

export function useViewerQuery(enabled: boolean): UseQueryResult<Viewer> {
  return useQuery({
    queryKey: ['me'],
    queryFn: ({ signal }) => fetchViewer(signal),
    enabled,
    /* Capability-bearing, so it is never served stale (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}

export type SessionState =
  | { readonly kind: 'restoring' }
  | { readonly kind: 'anonymous' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'failed'; readonly error: unknown }
  | { readonly kind: 'signedIn'; readonly viewer: Viewer };

/**
 * Resolve the session once, then keep it resolved.
 *
 * `restoring` is a real state and not an implementation detail: it is the
 * window in which the refresh cookie is being exchanged, and rendering the
 * sign-in screen during it would be a visible flash of "you are logged out" on
 * every reload for a user who is not.
 */
export function useSession(): SessionState {
  /* Start in `restoring` only when there is no token in hand. Immediately after
   * sign-in there is one, and re-checking the cookie would be a wasted round
   * trip on the happiest path in the application. */
  const [restoring, setRestoring] = useState(() => !hasAccessToken());
  const [anonymous, setAnonymous] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!restoring) return;
    let live = true;
    void refresh().then((restored) => {
      if (!live) return;
      /* A failed refresh is the ordinary state of a first visit, not an error.
       * It means there is no session to restore, which is a fact about the
       * visitor rather than something that went wrong. */
      if (!restored) setAnonymous(true);
      setRestoring(false);
    });
    return () => {
      live = false;
    };
  }, [restoring]);

  /* Any request proving the session is over returns the whole application to
   * sign-in and drops the cache with it. Without the reset, the next sign-in
   * would paint the previous user's cached rows for a frame — the same person's
   * data on a different person's screen. */
  useEffect(
    () =>
      onSessionEnded(() => {
        queryClient.clear();
        setAnonymous(true);
        setRestoring(false);
      }),
    [queryClient],
  );

  const query = useViewerQuery(!restoring && !anonymous);

  if (restoring) return { kind: 'restoring' };
  if (anonymous) return { kind: 'anonymous' };
  if (query.data !== undefined) return { kind: 'signedIn', viewer: query.data };
  if (query.isError) {
    /* `SESSION_ENDED` has already been handled by the listener above; anything
     * else is a genuine failure — the API is down, or the response did not
     * parse — and must not be shown as "please sign in", which would send a
     * user to type a password that was never the problem. */
    const code = query.error instanceof Error ? query.error.message : '';
    if (code === SESSION_ENDED) return { kind: 'anonymous' };
    return { kind: 'failed', error: query.error };
  }
  return { kind: 'loading' };
}

