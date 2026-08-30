import { useSyncExternalStore } from 'react';
import { notifyUrlChanged } from '../shared/url-state.ts';

/* Routing, without a router.
 *
 * `docs/17 §4`: **URL state is a state kind with its own home** — library,
 * folder, filters, sort, saved view and the selected file all live in the route
 * so a view can be sent to a colleague, survives reload, and survives
 * back/forward (`docs/09 §3`). That is the requirement; a routing *library* is
 * not.
 *
 * A dependency is not free here: `docs/09 §2` caps the main bundle at 250 KB
 * gzipped and it is a gate. React Router is roughly 20 KB of that for six flat
 * routes with no nesting, no loaders and no data layer — TanStack Query owns
 * fetching. This is forty lines and does the same job. If nested layouts or
 * route-level code-splitting arrive and this starts growing conditionals, that
 * is the moment to buy the library rather than reimplement it.
 */

export type RouteName =
  | 'signin'
  | 'home'
  | 'library'
  | 'search'
  | 'ask'
  | 'shared'
  | 'trash'
  | 'admin';

const PATHS: Record<RouteName, string> = {
  signin: '/signin',
  home: '/',
  library: '/library',
  search: '/search',
  ask: '/ask',
  shared: '/shared',
  trash: '/trash',
  admin: '/admin',
};

export interface Route {
  readonly name: RouteName;
  readonly path: string;
  /** Query parameters, which is where filters and the selected file live. */
  readonly params: URLSearchParams;
}

function currentRoute(): Route {
  const path = window.location.pathname;
  const name =
    (Object.keys(PATHS) as RouteName[]).find(
      (candidate) => PATHS[candidate] === path && candidate !== 'home',
    ) ?? (path === '/' ? 'home' : 'home');
  return { name, path, params: new URLSearchParams(window.location.search) };
}

const listeners = new Set<() => void>();
let snapshot = currentRoute();

function notify(): void {
  snapshot = currentRoute();
  for (const listener of listeners) listener();
  /* `pushState` fires no event, so anything reading the query string from
   * `shared/url-state` would go stale on every in-app navigation. Features may
   * not import this module (`docs/17 §2`), so this has to push to them. */
  notifyUrlChanged();
}

if (typeof window !== 'undefined') {
  window.addEventListener('popstate', notify);
}

export function navigate(name: RouteName, params?: Record<string, string>): void {
  const search = params === undefined ? '' : `?${new URLSearchParams(params).toString()}`;
  window.history.pushState(null, '', `${PATHS[name]}${search}`);
  notify();
}

/** Replace, not push: a filter change should not add a history entry per keystroke. */
export function replaceParams(params: Record<string, string>): void {
  const search = new URLSearchParams(params).toString();
  window.history.replaceState(null, '', `${window.location.pathname}?${search}`);
  notify();
}

export function useRoute(): Route {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => snapshot,
    () => snapshot,
  );
}

export function pathFor(name: RouteName): string {
  return PATHS[name];
}
