import { createContext, useContext, type ReactNode } from 'react';
import type { Viewer } from './model.ts';

/* The signed-in user, reachable from a feature.
 *
 * This context used to live in `app/session.tsx` alongside the boot sequence,
 * and `features/home` imported it from there — which `docs/17 §2` forbids
 * outright: a feature may import a layer below it and never one above. The
 * boundary rule in `tools/lint-web.mjs` is what surfaced it; before that the
 * rule existed only as a sentence in a document.
 *
 * The split is the one §2 prescribes. **Who is signed in** is a property of the
 * `user` entity and belongs here, where `app/` and `features/` may both reach
 * it. **How the application finds out** — the refresh exchange, the `GET /me`
 * gate, the four boot states — is app-level orchestration and stays in
 * `app/session.tsx`, which is also the only thing that ever calls
 * `ViewerProvider`.
 */

const ViewerContext = createContext<Viewer | null>(null);

/**
 * The signed-in user, inside the authenticated tree.
 *
 * Throws outside it rather than returning `null`, because every caller is
 * rendered inside the session gate and a `null` here would mean the gate is
 * broken — which is worth a loud failure at the boundary rather than an
 * optional chain in forty components.
 */
export function useViewer(): Viewer {
  const viewer = useContext(ViewerContext);
  if (viewer === null) throw new Error('useViewer outside an authenticated tree');
  return viewer;
}

export function ViewerProvider({ viewer, children }: { viewer: Viewer; children: ReactNode }) {
  return <ViewerContext.Provider value={viewer}>{children}</ViewerContext.Provider>;
}
