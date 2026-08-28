import { describe, expect, it } from 'vitest';
import { DENSITY, buildLayout, type GroupSpec } from '../../src/shared/list/geometry.ts';
import {
  clampCursor,
  cursorAt,
  cursorForRowIndex,
  domKeyOf,
  firstCursor,
  offsetOf,
  orderOf,
  presentCount,
  rowIndexOf,
  rowsBetween,
  stepAlong,
  stepRow,
  type GridCursor,
} from '../../src/shared/list/grid-cursor.ts';

/* The focus arithmetic, without a DOM.
 *
 * These are the assertions that matter when a row the cursor is standing on
 * does not exist as an element — which, in a windowed list, is most of them.
 * A browser test cannot distinguish "the cursor is on row 41,200" from "the
 * cursor is nowhere and the grid happens to look right", because neither row is
 * on screen. Here it can.
 */

const GROUPS: readonly GroupSpec[] = [
  { id: 'folders', name: 'Folders', count: 3 },
  { id: 'files', name: 'Files', count: 4 },
  { id: 'archive', name: 'Archive', count: 2 },
];

const COLUMNS = 7;
const layoutOf = (collapsed: readonly string[] = []) =>
  buildLayout(GROUPS, new Set(collapsed), DENSITY.default);

const at = (groupIndex: number, rowInGroup: number | null, column: number | null = null): GridCursor => ({
  groupIndex,
  rowInGroup,
  column,
});

describe('the walked sequence', () => {
  it('counts every header plus the rows of expanded groups', () => {
    expect(presentCount(layoutOf())).toBe(3 + 9);
    /* Collapsing hides four rows and keeps the header, which is the whole
     * reason a collapsed group is still a row a keyboard stops on. */
    expect(presentCount(layoutOf(['files']))).toBe(3 + 5);
  });

  it('walks header, its rows, next header — in order', () => {
    const layout = layoutOf();
    const walked = Array.from({ length: presentCount(layout) }, (_, order) => {
      const cursor = cursorAt(layout, order)!;
      return `${cursor.groupIndex}:${cursor.rowInGroup ?? 'h'}`;
    });
    expect(walked).toEqual([
      '0:h', '0:0', '0:1', '0:2',
      '1:h', '1:0', '1:1', '1:2', '1:3',
      '2:h', '2:0', '2:1',
    ]);
  });

  it('skips a collapsed group’s rows entirely', () => {
    const layout = layoutOf(['files']);
    const walked = Array.from({ length: presentCount(layout) }, (_, order) => {
      const cursor = cursorAt(layout, order)!;
      return `${cursor.groupIndex}:${cursor.rowInGroup ?? 'h'}`;
    });
    expect(walked).toEqual(['0:h', '0:0', '0:1', '0:2', '1:h', '2:h', '2:0', '2:1']);
  });

  it('agrees with geometry.ts about aria-rowindex', () => {
    /* The one property that must hold between this file and the screen reader's
     * announcement: `order` and `aria-rowindex` are two derivations of the same
     * sequence, and if they disagree the ring is on one row while the
     * announcement names another. */
    const layout = layoutOf(['files']);
    for (let order = 0; order < presentCount(layout); order += 1) {
      const cursor = cursorAt(layout, order)!;
      expect(orderOf(layout, cursor)).toBe(order);
    }
  });
});

describe('↑ and ↓', () => {
  it('cross a group boundary into the next header', () => {
    const layout = layoutOf();
    expect(stepRow(layout, at(0, 2), 1)).toMatchObject({ groupIndex: 1, rowInGroup: null });
  });

  it('clamp at both ends rather than falling out of the grid', () => {
    const layout = layoutOf();
    /* The trap this whole row exists to avoid. Returning `null` at the end
     * would drop DOM focus to `<body>` on the last `↓` — a grid the user can
     * enter and then fall out of. */
    expect(stepRow(layout, at(0, null), -1)).toMatchObject({ groupIndex: 0, rowInGroup: null });
    expect(stepRow(layout, at(2, 1), 1)).toMatchObject({ groupIndex: 2, rowInGroup: 1 });
  });

  it('carry the active column down a row, and drop it on a header', () => {
    const layout = layoutOf();
    expect(stepRow(layout, at(0, 0, 5), 1)).toMatchObject({ rowInGroup: 1, column: 5 });
    expect(stepRow(layout, at(0, 2, 5), 1)).toMatchObject({ rowInGroup: null, column: null });
  });

  it('jump over a collapsed group instead of into it', () => {
    const layout = layoutOf(['files']);
    expect(stepRow(layout, at(1, null), 1)).toMatchObject({ groupIndex: 2, rowInGroup: null });
  });
});

describe('→ and ← resolve the treegrid’s two halves', () => {
  it('expand a collapsed header and collapse an expanded one', () => {
    expect(stepAlong(layoutOf(['files']), at(1, null), 'forward', COLUMNS)).toEqual({
      kind: 'expand',
      groupIndex: 1,
    });
    expect(stepAlong(layoutOf(), at(1, null), 'backward', COLUMNS)).toEqual({
      kind: 'collapse',
      groupIndex: 1,
    });
  });

  it('descend from an expanded header into its first row', () => {
    expect(stepAlong(layoutOf(), at(1, null), 'forward', COLUMNS)).toEqual({
      kind: 'move',
      cursor: at(1, 0, null),
    });
  });

  it('walk the columns of a row and stop at the last', () => {
    const layout = layoutOf();
    expect(stepAlong(layout, at(0, 0, null), 'forward', COLUMNS)).toEqual({
      kind: 'move',
      cursor: at(0, 0, 0),
    });
    expect(stepAlong(layout, at(0, 0, 5), 'forward', COLUMNS)).toEqual({
      kind: 'move',
      cursor: at(0, 0, 6),
    });
    expect(stepAlong(layout, at(0, 0, 6), 'forward', COLUMNS)).toEqual({ kind: 'none' });
  });

  it('walk back out of the cells and then up to the group header', () => {
    const layout = layoutOf();
    expect(stepAlong(layout, at(0, 1, 0), 'backward', COLUMNS)).toEqual({
      kind: 'move',
      cursor: at(0, 1, null),
    });
    /* The tree's "move to parent": from a row, back reaches its header without
     * walking every row above it. */
    expect(stepAlong(layout, at(0, 1, null), 'backward', COLUMNS)).toEqual({
      kind: 'move',
      cursor: at(0, null, null),
    });
  });
});

describe('Shift-extend', () => {
  it('covers every row between two cursors', () => {
    expect(rowsBetween(layoutOf(), at(0, 1), at(1, 1))).toEqual([1, 2, 3, 4]);
  });

  it('is symmetric — extending upward selects the same rows', () => {
    expect(rowsBetween(layoutOf(), at(1, 1), at(0, 1))).toEqual([1, 2, 3, 4]);
  });

  it('does not select rows hidden inside a collapsed group', () => {
    /* The surprise that makes people stop trusting shift-click: rows 3–6 are
     * between the two cursors in the flat array but invisible on screen, and a
     * range that swept them up would delete files the user never saw. */
    expect(rowsBetween(layoutOf(['files']), at(0, 1), at(2, 0))).toEqual([1, 2, 7]);
  });

  it('includes a group header as no row at all rather than as row -1', () => {
    expect(rowsBetween(layoutOf(), at(0, null), at(0, 0))).toEqual([0]);
  });
});

describe('surviving a layout change', () => {
  it('lands a cursor on the header when its own group collapses', () => {
    expect(clampCursor(layoutOf(['files']), at(1, 2))).toEqual(at(1, null));
  });

  it('holds position when a group above it collapses', () => {
    /* The `scrollTopForAnchor` property, one layer up: collapsing a group above
     * the cursor changes every `aria-rowindex` below it, and the cursor must
     * still name the same file. */
    const cursor = at(2, 1);
    expect(clampCursor(layoutOf(['folders']), cursor)).toEqual(cursor);
    expect(rowIndexOf(layoutOf(['folders']), cursor)).toBe(8);
    expect(rowIndexOf(layoutOf(), cursor)).toBe(8);
  });

  it('pulls a cursor back into a group that shrank', () => {
    const shrunk = buildLayout(
      [{ id: 'folders', name: 'Folders', count: 1 }],
      new Set(),
      DENSITY.default,
    );
    expect(clampCursor(shrunk, at(0, 2))).toEqual(at(0, 0));
  });

  it('re-homes a cursor whose group disappeared', () => {
    const empty = buildLayout([{ id: 'other', name: 'Other', count: 2 }], new Set(), DENSITY.default);
    expect(clampCursor(empty, at(7, 3))).toEqual(at(0, null));
  });

  it('is null only when there is genuinely nothing to focus', () => {
    const nothing = buildLayout([], new Set(), DENSITY.default);
    expect(firstCursor(nothing)).toBeNull();
    expect(clampCursor(nothing, at(0, 0))).toBeNull();
  });
});

describe('addressing the DOM and the scroller', () => {
  it('produces the keys sliceWindow puts on its items', () => {
    const layout = layoutOf();
    expect(domKeyOf(layout, at(1, null))).toBe('h:files');
    expect(domKeyOf(layout, at(1, 2))).toBe('r:5');
  });

  it('round-trips a flat row index', () => {
    const layout = layoutOf();
    for (let index = 0; index < 9; index += 1) {
      expect(rowIndexOf(layout, cursorForRowIndex(layout, index)!)).toBe(index);
    }
  });

  it('computes an offset for a row that is not rendered', () => {
    /* 3 headers and 9 rows at 28/36: the last row of the last group sits below
     * three headers and eight rows. Derived from the layout, not measured —
     * the element does not exist. */
    const layout = layoutOf();
    expect(offsetOf(layout, at(2, 1))).toEqual({ top: 3 * 28 + 8 * 36, height: 36 });
  });
});
