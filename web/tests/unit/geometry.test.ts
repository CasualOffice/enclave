import { describe, expect, it } from 'vitest';
import {
  anchorAt,
  buildLayout,
  DENSITY,
  groupIndexAt,
  scrollTopForAnchor,
  sliceWindow,
  type GroupSpec,
} from '../../src/features/libraries/list/geometry.ts';

/* The arithmetic, without a DOM.
 *
 * `docs/12 §1.1` draws the line at the boundary: whether Chromium composites a
 * transform correctly is Chromium's problem. Whether the offset handed to it is
 * right is ours, and that is what these assert.
 */

const D = DENSITY.default;

const GROUPS: readonly GroupSpec[] = [
  { id: 'a', name: 'Alpha', count: 3 },
  { id: 'b', name: 'Bravo', count: 1000 },
  { id: 'c', name: 'Charlie', count: 0 },
  /* Delta is large on purpose. With a small tail group the whole list fits in
   * the viewport once Bravo collapses, `scrollTopForAnchor` clamps everything
   * to zero, and the anchor tests pass for the wrong reason — which is how the
   * first version of them passed. */
  { id: 'd', name: 'Delta', count: 200 },
];

const none = new Set<string>();

describe('buildLayout', () => {
  it('lays groups out head to tail, header then rows', () => {
    const layout = buildLayout(GROUPS, none, D);
    expect(layout.groups.map((g) => g.top)).toEqual([
      0,
      D.headerHeight + 3 * D.rowHeight,
      D.headerHeight + 3 * D.rowHeight + (D.headerHeight + 1000 * D.rowHeight),
      D.headerHeight + 3 * D.rowHeight + (D.headerHeight + 1000 * D.rowHeight) + D.headerHeight,
    ]);
    expect(layout.totalHeight).toBe(4 * D.headerHeight + 1203 * D.rowHeight);
    expect(layout.presentRowCount).toBe(1203);
    expect(layout.totalRowCount).toBe(1203);
  });

  it('gives a collapsed group its header height and nothing else', () => {
    const layout = buildLayout(GROUPS, new Set(['b']), D);
    expect(layout.groups[1]!.height).toBe(D.headerHeight);
    expect(layout.totalHeight).toBe(4 * D.headerHeight + 203 * D.rowHeight);
    // The rows still exist; they are just not on screen.
    expect(layout.presentRowCount).toBe(203);
    expect(layout.totalRowCount).toBe(1203);
  });

  it('keeps firstRowIndex tied to the data, not to what is visible', () => {
    const collapsed = buildLayout(GROUPS, new Set(['a']), D);
    const expanded = buildLayout(GROUPS, none, D);
    expect(collapsed.groups.map((g) => g.firstRowIndex)).toEqual(
      expanded.groups.map((g) => g.firstRowIndex),
    );
  });

  it('numbers aria rows past the ones a collapsed group hides', () => {
    const layout = buildLayout(GROUPS, new Set(['b']), D);
    // 1 is the column header. a's header is 2, its rows 3-5, b's header 6, and
    // because b is collapsed c's header follows immediately at 7.
    expect(layout.groups.map((g) => g.ariaRowIndex)).toEqual([2, 6, 7, 8]);
  });

  it('an empty library has no height and no groups', () => {
    const layout = buildLayout([], none, D);
    expect(layout.totalHeight).toBe(0);
    expect(groupIndexAt(layout, 0)).toBe(-1);
  });
});

describe('groupIndexAt', () => {
  const layout = buildLayout(GROUPS, none, D);

  it('finds the group containing a pixel', () => {
    expect(groupIndexAt(layout, 0)).toBe(0);
    expect(groupIndexAt(layout, layout.groups[1]!.top - 1)).toBe(0);
    expect(groupIndexAt(layout, layout.groups[1]!.top)).toBe(1);
    expect(groupIndexAt(layout, layout.groups[3]!.top + 4)).toBe(3);
  });

  it('clamps past the end rather than reporting a miss', () => {
    expect(groupIndexAt(layout, layout.totalHeight + 10_000)).toBe(3);
  });
});

describe('sliceWindow', () => {
  const layout = buildLayout(GROUPS, none, D);

  it('renders a window, not a list', () => {
    const slice = sliceWindow(layout, 10_000, 900, 240);
    expect(slice.items.length).toBeGreaterThan(20);
    expect(slice.items.length).toBeLessThan(80);
  });

  it('covers the viewport it was asked for', () => {
    const scrollTop = 12_345;
    const viewport = 900;
    const slice = sliceWindow(layout, scrollTop, viewport, 240);
    const first = slice.items[0]!;
    const last = slice.items[slice.items.length - 1]!;
    expect(first.top).toBeLessThanOrEqual(scrollTop);
    expect(last.top + last.height).toBeGreaterThanOrEqual(scrollTop + viewport);
  });

  it('never renders the header it is pinning', () => {
    const slice = sliceWindow(layout, 10_000, 900, 240);
    expect(slice.stickyGroupIndex).toBe(1);
    const headers = slice.items.filter((item) => item.kind === 'header');
    expect(headers.map((item) => item.groupIndex)).not.toContain(slice.stickyGroupIndex);
  });

  it('pushes the pinned header off as the next one arrives', () => {
    const nextTop = layout.groups[1]!.top;
    // Far from the boundary: no push.
    expect(sliceWindow(layout, nextTop - 400, 900, 240).stickyPush).toBe(0);
    // Exactly one header-height away: the push has just begun.
    expect(sliceWindow(layout, nextTop - D.headerHeight, 900, 240).stickyPush).toBe(0);
    // Half a header from the boundary: pushed half off.
    const half = Math.round(D.headerHeight / 2);
    expect(sliceWindow(layout, nextTop - half, 900, 240).stickyPush).toBe(half - D.headerHeight);
    expect(sliceWindow(layout, nextTop - half, 900, 240).stickyPush).toBeLessThan(0);
  });

  it('skips the rows of a collapsed group entirely', () => {
    const layoutCollapsed = buildLayout(GROUPS, new Set(['b']), D);
    const slice = sliceWindow(layoutCollapsed, 0, 900, 240);
    const groupsRendered = new Set(slice.items.map((item) => item.groupIndex));
    expect(groupsRendered.has(1)).toBe(true); // its header, if in view
    expect(slice.items.some((item) => item.kind === 'row' && item.groupIndex === 1)).toBe(false);
  });

  it('renders a zero-row group as a header and nothing else', () => {
    const top = layout.groups[2]!.top;
    const slice = sliceWindow(layout, top, 200, 0);
    expect(slice.items.some((item) => item.kind === 'row' && item.groupIndex === 2)).toBe(false);
  });

  it('quantizes the window so a small scroll changes nothing', () => {
    /* The claim the benchmark caught being false. Two scroll positions inside
     * the same quantum must produce byte-identical windows, or the "renders
     * only when the window changes" design is a per-frame re-render. */
    const overscan = 240;
    const a = sliceWindow(layout, 10_000, 900, overscan);
    const b = sliceWindow(layout, 10_000 + 30, 900, overscan);
    expect(b.items.map((i) => i.key)).toEqual(a.items.map((i) => i.key));
    expect(b.startOffset).toBe(a.startOffset);
  });

  it('does change once the scroll leaves the quantum', () => {
    const overscan = 240;
    const a = sliceWindow(layout, 10_000, 900, overscan);
    const b = sliceWindow(layout, 10_000 + 2 * overscan, 900, overscan);
    expect(b.items.map((i) => i.key)).not.toEqual(a.items.map((i) => i.key));
  });

  it('assigns aria row indices that continue across group boundaries', () => {
    const slice = sliceWindow(layout, 0, 400, 0);
    const rows = slice.items.filter((item) => item.kind === 'row');
    expect(rows.slice(0, 3).map((item) => item.ariaRowIndex)).toEqual([3, 4, 5]);
  });
});

describe('the scroll anchor', () => {
  /* This is the case `plans/M5-MVP-GA.md` D38 names as the hard one: collapsing
   * a group changes the index space *under* the scroll position. */

  const viewport = 900;

  it('names the row at the top of the viewport, and how far past its top', () => {
    const layout = buildLayout(GROUPS, none, D);
    const rowsTop = layout.groups[1]!.top + D.headerHeight;
    const anchor = anchorAt(layout, rowsTop + 7 * D.rowHeight + 11)!;
    expect(anchor).toEqual({ groupId: 'b', rowInGroup: 7, delta: 11 });
  });

  it('names the header when a header is at the top', () => {
    const layout = buildLayout(GROUPS, none, D);
    const anchor = anchorAt(layout, layout.groups[1]!.top + 3)!;
    expect(anchor).toEqual({ groupId: 'b', rowInGroup: null, delta: 3 });
  });

  it('holds the viewport still when a group ABOVE it collapses', () => {
    const before = buildLayout(GROUPS, none, D);
    const rowsTop = before.groups[3]!.top + D.headerHeight;
    const scrollTop = rowsTop + 2 * D.rowHeight;
    const anchor = anchorAt(before, scrollTop)!;

    const after = buildLayout(GROUPS, new Set(['b']), D);
    const restored = scrollTopForAnchor(after, anchor, viewport);

    // The same row is at the top of the viewport, and the scroll position moved
    // by exactly the height that was removed above it.
    const afterRowsTop = after.groups[3]!.top + D.headerHeight;
    expect(restored).toBe(afterRowsTop + 2 * D.rowHeight);
    expect(scrollTop - restored).toBe(1000 * D.rowHeight);
  });

  it('lands on the header when the anchored row is inside the group that collapsed', () => {
    const before = buildLayout(GROUPS, none, D);
    const scrollTop = before.groups[1]!.top + D.headerHeight + 400 * D.rowHeight;
    const anchor = anchorAt(before, scrollTop)!;
    expect(anchor.groupId).toBe('b');

    const after = buildLayout(GROUPS, new Set(['b']), D);
    expect(scrollTopForAnchor(after, anchor, viewport)).toBe(after.groups[1]!.top);
  });

  it('is exact across an expand as well as a collapse', () => {
    const collapsed = buildLayout(GROUPS, new Set(['a']), D);
    const rowsTop = collapsed.groups[1]!.top + D.headerHeight;
    const scrollTop = rowsTop + 40 * D.rowHeight + 5;
    const anchor = anchorAt(collapsed, scrollTop)!;

    const expanded = buildLayout(GROUPS, none, D);
    const restored = scrollTopForAnchor(expanded, anchor, viewport);
    expect(restored - (expanded.groups[1]!.top + D.headerHeight + 40 * D.rowHeight)).toBe(5);
  });

  it('never scrolls past the end after a collapse shrinks the content', () => {
    const before = buildLayout(GROUPS, none, D);
    const anchor = anchorAt(before, before.totalHeight - 100)!;
    const after = buildLayout(GROUPS, new Set(['b']), D);
    const restored = scrollTopForAnchor(after, anchor, viewport);
    expect(restored).toBeLessThanOrEqual(Math.max(0, after.totalHeight - viewport));
    expect(restored).toBeGreaterThanOrEqual(0);
  });

  it('returns to zero when the anchored group is gone from the data entirely', () => {
    const before = buildLayout(GROUPS, none, D);
    const anchor = anchorAt(before, before.groups[1]!.top + 50)!;
    const after = buildLayout([GROUPS[0]!], none, D);
    expect(scrollTopForAnchor(after, anchor, viewport)).toBe(0);
  });
});

describe('density', () => {
  it('is the design reference’s 36/30, not docs/09 2.0’s 48/36 (D35.1)', () => {
    expect(DENSITY.default.rowHeight).toBe(36);
    expect(DENSITY.compact.rowHeight).toBe(30);
  });

  it('changes the geometry without changing what is in the list', () => {
    const dense = buildLayout(GROUPS, none, DENSITY.compact);
    const normal = buildLayout(GROUPS, none, DENSITY.default);
    expect(dense.totalHeight).toBeLessThan(normal.totalHeight);
    expect(dense.presentRowCount).toBe(normal.presentRowCount);
  });
});

describe('scale', () => {
  it('describes 100 000 rows without building 100 000 of anything', () => {
    const groups: GroupSpec[] = Array.from({ length: 400 }, (_, i) => ({
      id: `g${i}`,
      name: `Group ${i}`,
      count: 250,
    }));

    const started = performance.now();
    const layout = buildLayout(groups, none, D);
    const built = performance.now() - started;

    expect(layout.totalRowCount).toBe(100_000);
    expect(layout.groups).toHaveLength(400);
    /* The budget is a whole frame and this should be three orders of magnitude
     * inside it. It is asserted at all because the failure it guards against —
     * someone materializing the flat index — would still pass every test above. */
    expect(built).toBeLessThan(16);

    const sliced = performance.now();
    sliceWindow(layout, 1_500_000, 900, 240);
    expect(performance.now() - sliced).toBeLessThan(16);
  });
});
