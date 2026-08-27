import { useCallback, useSyncExternalStore } from 'react';

/* URL state, reachable from a feature.
 *
 * `docs/17 §4` makes the URL one of the four state homes and puts filters, sort,
 * the saved view and the selected object in it — so a filtered view can be sent
 * to a colleague and survives back/forward. `docs/17 §2` forbids a feature from
 * importing `app/`, which is where the router lives.
 *
 * Together those two left **no legal way for a feature to read its own
 * filters**, and the admin session found it the way you would expect: by
 * reaching for `window.location` and dispatching `popstate` by hand, in a
 * feature, with a comment apologising for it. Two sessions independently wrote
 * a variant of the same workaround.
 *
 * That is a real gap in the layering rather than a preference, and the fix is
 * to put the accessor where both layers may legally use it. `app/routes.ts`
 * owns *which* routes exist and how to move between them; this owns *reading
 * and writing the query string*, which is not routing and does not need to know
 * a single route name.
 */

const listeners = new Set<() => void>();

function snapshotSearch(): string {
  return typeof window === 'undefined' ? '' : window.location.search;
}

let snapshot = snapshotSearch();

function notify(): void {
  const next = snapshotSearch();
  if (next === snapshot) return;
  snapshot = next;
  for (const listener of listeners) listener();
}

if (typeof window !== 'undefined') {
  window.addEventListener('popstate', notify);
  /* `pushState`/`replaceState` fire no event of their own, so anything that
   * navigates has to say so. `app/routes.ts` calls `notifyUrlChanged` after it
   * writes; without that a feature reading this would go stale on every
   * in-app navigation and only correct itself on a back button. */
}

/** Called by whatever writes to history. Exported so `app/` can announce a push. */
export function notifyUrlChanged(): void {
  notify();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/**
 * The raw query string, which is **stable between changes**.
 *
 * `useSearchParams` below has to allocate a fresh `URLSearchParams` on every
 * render — the object is mutable, so handing out a shared one would let any
 * caller corrupt every other's view. That makes it a poor `useMemo`
 * dependency: a screen that writes `useMemo(() => readFilters(params),
 * [params])` gets a new dependency every render and its memo never hits, which
 * is a performance bug that is completely invisible because the values are
 * always correct.
 *
 * The search *string* has no such problem. A screen with derived state should
 * depend on this and build the params inside the memo.
 */
export function useSearchString(): string {
  return useSyncExternalStore(
    subscribe,
    () => snapshot,
    () => '',
  );
}

/** The current query string, re-rendering the caller when it changes. */
export function useSearchParams(): URLSearchParams {
  return new URLSearchParams(useSearchString());
}

/** One parameter, with a default. */
export function useSearchParam(key: string, fallback = ''): string {
  return useSearchParams().get(key) ?? fallback;
}

export interface SearchParamWriter {
  /**
   * Merge keys into the query string. A key set to `null` is removed.
   *
   * Replaces rather than pushes: a filter change per keystroke should not fill
   * the back button with intermediate states (`docs/09 §3` wants back to undo a
   * *navigation*, not a character).
   */
  (patch: Record<string, string | null>): void;
}

export function useWriteSearchParams(): SearchParamWriter {
  return useCallback((patch) => {
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(patch)) {
      if (value === null || value === '') params.delete(key);
      else params.set(key, value);
    }
    const query = params.toString();
    window.history.replaceState(
      null,
      '',
      query.length > 0 ? `${window.location.pathname}?${query}` : window.location.pathname,
    );
    notify();
  }, []);
}
