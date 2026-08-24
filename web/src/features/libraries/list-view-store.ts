import { create } from 'zustand';
import type { DensityName } from './list/geometry.ts';

/* Zustand, for exactly the thing `CLAUDE.md` reserves it for: genuinely local
 * UI state.
 *
 * Which groups are collapsed, which rows are selected and which density is
 * active are not server state — nothing fetches them and nothing invalidates
 * them. They are also not component state, because `docs/09 §3` requires
 * selection and expansion to survive back/forward navigation, and state inside
 * a component that unmounts on a route change does not.
 *
 * Nothing else belongs here. When the list starts fetching, that goes through
 * TanStack Query, and mirroring server data into this store is how the two
 * disagree.
 */

export interface ListViewState {
  readonly collapsed: ReadonlySet<string>;
  readonly selected: ReadonlySet<string>;
  readonly density: DensityName;
  toggleGroup: (id: string) => void;
  toggleSelected: (id: string) => void;
  setDensity: (density: DensityName) => void;
  reset: () => void;
}

const EMPTY: ReadonlySet<string> = new Set<string>();

/** A new Set every time, because the layout memo compares by identity. */
function toggled(source: ReadonlySet<string>, id: string): ReadonlySet<string> {
  const next = new Set(source);
  if (!next.delete(id)) next.add(id);
  return next;
}

export const useListViewStore = create<ListViewState>((set) => ({
  collapsed: EMPTY,
  selected: EMPTY,
  density: 'default',
  toggleGroup: (id) => set((state) => ({ collapsed: toggled(state.collapsed, id) })),
  toggleSelected: (id) => set((state) => ({ selected: toggled(state.selected, id) })),
  setDensity: (density) => set({ density }),
  reset: () => set({ collapsed: EMPTY, selected: EMPTY, density: 'default' }),
}));
