import type { Layout } from './geometry.ts';

/* Where keyboard focus is in a grouped, virtualized grid — as arithmetic.
 *
 * ## Why focus is a cursor and not a DOM node
 *
 * The rows are windowed. At any moment perhaps thirty of a hundred thousand
 * exist as elements, and scrolling unmounts the one that has focus. A focus
 * model that points at an element therefore loses its position every time the
 * user touches the scroll wheel, and — worse — leaves `document.activeElement`
 * on `<body>`, which is a keyboard user stranded with no way back into the
 * grid. That is the "worse than one you cannot focus at all" failure: a grid
 * you can enter and then fall out of.
 *
 * So focus is a **logical position** — group, row within it, column within that
 * — and the DOM follows. Everything in this file is pure and is tested without
 * a browser, because the failure mode it exists to prevent is off-by-one
 * arithmetic across a collapse, and arithmetic is cheaper to pin down in a unit
 * test than in Playwright.
 *
 * ## The order space
 *
 * `geometry.ts` already computes, per group, the 1-based `aria-rowindex` of its
 * header counting the column-header row as 1 and **skipping the rows of
 * collapsed groups**. That is exactly the sequence a keyboard walks, so it is
 * reused rather than recomputed: `order = ariaRowIndex - 2` puts the first
 * group header at 0. Two derivations of "which row is 41,200th" is how the
 * screen reader's announcement and the focus ring end up on different rows.
 */

export interface GridCursor {
  readonly groupIndex: number;
  /** `null` addresses the group header itself; otherwise the row's index within the group. */
  readonly rowInGroup: number | null;
  /**
   * The cell within the row, or `null` for the row element.
   *
   * `docs/09 §6` binds `→ ←` to "next/previous column in grid", so cells are
   * focus targets and not only rows. The row keeps a focus stop of its own —
   * `null` — because selection, `Enter` and `Space` act on a *row*, and landing
   * on cell 3 of a row to press `Enter` would make "which thing am I about to
   * open" a question about horizontal position. Always `null` on a header,
   * which is one cell spanning seven columns.
   */
  readonly column: number | null;
}

/** Present items: every group header, plus the rows of expanded groups. */
export function presentCount(layout: Layout): number {
  return layout.groups.length + layout.presentRowCount;
}

/** A cursor's position in the walked sequence, or `-1` if it addresses nothing. */
export function orderOf(layout: Layout, cursor: GridCursor): number {
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined) return -1;
  const headerOrder = group.ariaRowIndex - 2;
  if (cursor.rowInGroup === null) return headerOrder;
  if (group.collapsed || cursor.rowInGroup >= group.count) return -1;
  return headerOrder + 1 + cursor.rowInGroup;
}

/**
 * The cursor at a position in the walked sequence, clamped into range.
 *
 * Binary search over group headers, O(log G) — the same reason `geometry.ts`
 * refuses to materialize the flat index space. Clamps rather than returning
 * `null`: walking past the end is a normal keypress, not an error, and a
 * `null` here would put the same guard in every caller.
 */
export function cursorAt(layout: Layout, order: number): GridCursor | null {
  const total = presentCount(layout);
  if (total === 0) return null;
  const wanted = Math.max(0, Math.min(order, total - 1));

  let lo = 0;
  let hi = layout.groups.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (layout.groups[mid]!.ariaRowIndex - 2 <= wanted) lo = mid;
    else hi = mid - 1;
  }

  const group = layout.groups[lo]!;
  const within = wanted - (group.ariaRowIndex - 2);
  return { groupIndex: lo, rowInGroup: within === 0 ? null : within - 1, column: null };
}

/** The first thing a keyboard can land on: the first group's header. */
export function firstCursor(layout: Layout): GridCursor | null {
  return cursorAt(layout, 0);
}

/**
 * `↑` / `↓`. Moves by whole rows, keeping the active column.
 *
 * The column is carried so that walking a column of file sizes stays in the
 * size column — the behaviour that makes cell navigation worth having — and is
 * dropped on a group header, which has only one cell to be in.
 */
export function stepRow(layout: Layout, cursor: GridCursor, delta: number): GridCursor | null {
  const order = orderOf(layout, cursor);
  if (order < 0) return firstCursor(layout);
  const next = cursorAt(layout, order + delta);
  if (next === null) return null;
  if (next.rowInGroup === null) return next;
  return { ...next, column: cursor.column };
}

/** What `→` (or `←` in a right-to-left locale) should do from here. */
export type AlongOutcome =
  | { readonly kind: 'move'; readonly cursor: GridCursor }
  | { readonly kind: 'expand'; readonly groupIndex: number }
  | { readonly kind: 'collapse'; readonly groupIndex: number }
  | { readonly kind: 'none' };

/**
 * `→ ←`, resolved for a treegrid — which is both halves of `docs/09 §6`'s
 * sentence, not a choice between them.
 *
 * §6 reads "Expand/collapse in tree; next/previous column in grid" and this
 * list is a `role="treegrid"`: the group headers are the tree and the file rows
 * are the grid. The ARIA authoring practices resolve the same ambiguity the
 * same way, which is reassuring but is not the reason — the reason is that both
 * clauses are satisfiable at once and dropping either would leave a documented
 * binding unimplemented.
 *
 *   on a collapsed header   forward → expand it
 *   on an expanded header   forward → into its first row · backward → collapse
 *   on a row                forward → into the cells, then across them
 *                           backward → out of the cells, then up to the header
 *
 * Backward from a row is the tree's "move to parent", which is the only way to
 * get from a row to its group header without walking every row above it.
 */
export function stepAlong(
  layout: Layout,
  cursor: GridCursor,
  direction: 'forward' | 'backward',
  columnCount: number,
): AlongOutcome {
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined) return { kind: 'none' };

  if (cursor.rowInGroup === null) {
    if (direction === 'forward') {
      if (group.collapsed) return { kind: 'expand', groupIndex: cursor.groupIndex };
      if (group.count === 0) return { kind: 'none' };
      return { kind: 'move', cursor: { ...cursor, rowInGroup: 0, column: null } };
    }
    if (!group.collapsed) return { kind: 'collapse', groupIndex: cursor.groupIndex };
    return { kind: 'none' };
  }

  if (direction === 'forward') {
    const next = cursor.column === null ? 0 : Math.min(cursor.column + 1, columnCount - 1);
    if (next === cursor.column) return { kind: 'none' };
    return { kind: 'move', cursor: { ...cursor, column: next } };
  }

  if (cursor.column === null) {
    return { kind: 'move', cursor: { ...cursor, rowInGroup: null, column: null } };
  }
  return {
    kind: 'move',
    cursor: { ...cursor, column: cursor.column === 0 ? null : cursor.column - 1 },
  };
}

/** The index into the caller's flat row array, or `-1` for a group header. */
export function rowIndexOf(layout: Layout, cursor: GridCursor): number {
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined || cursor.rowInGroup === null) return -1;
  if (cursor.rowInGroup >= group.count) return -1;
  return group.firstRowIndex + cursor.rowInGroup;
}

/** The cursor addressing a flat row index, or `null` when no group holds it. */
export function cursorForRowIndex(layout: Layout, rowIndex: number): GridCursor | null {
  for (let g = 0; g < layout.groups.length; g += 1) {
    const group = layout.groups[g]!;
    if (rowIndex < group.firstRowIndex + group.count) {
      if (rowIndex < group.firstRowIndex) return null;
      return { groupIndex: g, rowInGroup: rowIndex - group.firstRowIndex, column: null };
    }
  }
  return null;
}

/**
 * Every flat row index between two cursors, inclusive — `Shift`-extend.
 *
 * Walks the *present* sequence rather than the flat row array, so a collapsed
 * group between the anchor and the cursor contributes nothing. Selecting rows
 * the user cannot see, because they happened to lie between two visible ones,
 * is the surprise that makes people stop trusting shift-click.
 */
export function rowsBetween(layout: Layout, a: GridCursor, b: GridCursor): readonly number[] {
  const from = orderOf(layout, a);
  const to = orderOf(layout, b);
  if (from < 0 || to < 0) return [];
  const [lo, hi] = from <= to ? [from, to] : [to, from];

  const out: number[] = [];
  for (let order = lo; order <= hi; order += 1) {
    const cursor = cursorAt(layout, order);
    if (cursor === null) continue;
    const index = rowIndexOf(layout, cursor);
    if (index >= 0) out.push(index);
  }
  return out;
}

/**
 * The cursor's pixel offset inside the scroller, for bringing it into view.
 *
 * Mirrors `geometry.ts`'s own layout arithmetic rather than measuring the DOM,
 * because the row may not be in the DOM — which is the whole problem this file
 * exists for.
 */
export function offsetOf(layout: Layout, cursor: GridCursor): { top: number; height: number } | null {
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined) return null;
  if (cursor.rowInGroup === null) {
    return { top: group.top, height: layout.density.headerHeight };
  }
  return {
    top: group.top + layout.density.headerHeight + cursor.rowInGroup * layout.density.rowHeight,
    height: layout.density.rowHeight,
  };
}

/**
 * The DOM key for the element a cursor addresses.
 *
 * The same strings `sliceWindow` puts on its items, so the component can find
 * the rendered node — when there is one — without a second naming scheme to
 * keep in step.
 */
export function domKeyOf(layout: Layout, cursor: GridCursor): string | null {
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined) return null;
  if (cursor.rowInGroup === null) return `h:${group.id}`;
  const index = rowIndexOf(layout, cursor);
  return index < 0 ? null : `r:${index}`;
}

/**
 * Put a cursor back somewhere real after the layout changed under it.
 *
 * A collapse removes the rows the cursor was standing on; new data can remove
 * the group entirely. Both are ordinary, and both must leave focus *somewhere*
 * — dropping to `null` would return the user to the top of a hundred thousand
 * rows, and leaving it dangling would put the focus ring on nothing.
 */
export function clampCursor(layout: Layout, cursor: GridCursor | null): GridCursor | null {
  if (cursor === null) return null;
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined) return firstCursor(layout);
  if (cursor.rowInGroup === null) return cursor;
  /* The row's own group collapsed: land on the header, which is where the row
   * now visually is and the one place the user can re-open it from. */
  if (group.collapsed) return { groupIndex: cursor.groupIndex, rowInGroup: null, column: null };
  /* The row's own group collapsed: land on the header, which is where the row
   * now visually is and the one place the user can re-open it from. */

  if (cursor.rowInGroup >= group.count) {
    return group.count === 0
      ? { groupIndex: cursor.groupIndex, rowInGroup: null, column: null }
      : { ...cursor, rowInGroup: group.count - 1 };
  }
  return cursor;
}

export function sameCursor(a: GridCursor | null, b: GridCursor | null): boolean {
  if (a === null || b === null) return a === b;
  return (
    a.groupIndex === b.groupIndex && a.rowInGroup === b.rowInGroup && a.column === b.column
  );
}
