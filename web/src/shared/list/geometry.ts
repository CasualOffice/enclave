/* Grouped, collapsible virtualization: the geometry.
 *
 * `docs/09 §2` asks for 60 fps over 100 000 rows and a first paint under 400 ms,
 * and `plans/M5-MVP-GA.md` D38 names why the grouped case is the hard one:
 * row heights vary between a header and a row, collapsing changes the index
 * space *under* the scroll position, and sticky headers fight the windowing.
 *
 * All three fall out of one decision: **the flat index space is never
 * materialized.** A 100 000-row folder is described by its groups — a few
 * hundred `{ name, count, collapsed }` records — and every pixel offset is
 * derived from a prefix sum over *groups*, not over rows. So:
 *
 *   - building the layout is O(groups), not O(rows), which is what puts first
 *     paint out of reach of the row count;
 *   - locating the window is a binary search over groups plus arithmetic inside
 *     one, O(log G);
 *   - collapsing a group rewrites a few hundred numbers, not 100 000, so the
 *     "index space moved under the scroll position" problem shrinks to
 *     "recompute one anchor" — see `anchorAt`/`scrollTopForAnchor`.
 *
 * Everything here is pure. It is tested without a DOM, because the failure mode
 * this file exists to prevent is arithmetic, and arithmetic is cheaper to pin
 * down in a unit test than in a browser.
 */

/** Row and header heights. `plans/M5-MVP-GA.md` D35.1: the design's 36/30 wins over `docs/09 §13`'s 48/36 — density is appearance. */
export interface Density {
  readonly rowHeight: number;
  readonly headerHeight: number;
  /** Height of the always-sticky column-header row. */
  readonly columnsHeight: number;
}

/**
 * `Default` and `Compact` are the design reference's own labels and values
 * (`.frow{height:36px}`, and 30 for compact). The reference defines no compact
 * *group* header, so 24 is derived here at the same ratio; if the reference
 * later states one, it wins — `web/design-system/` is authoritative for values.
 */
export const DENSITY = {
  default: { rowHeight: 36, headerHeight: 28, columnsHeight: 30 },
  compact: { rowHeight: 30, headerHeight: 24, columnsHeight: 26 },
} as const satisfies Record<string, Density>;

export type DensityName = keyof typeof DENSITY;

/** What the caller knows about a group before any layout happens. */
export interface GroupSpec {
  readonly id: string;
  readonly name: string;
  /** Rows in the group, whether or not it is currently collapsed. */
  readonly count: number;
}

export interface GroupLayout {
  readonly id: string;
  /**
   * Position in `Layout.groups`.
   *
   * Carried on the record rather than recovered with `indexOf` by whoever holds
   * one. The keyboard cursor addresses a group by index, and the pinned header
   * is handed a `GroupLayout` with no index beside it — searching for it by
   * identity would be O(G) on every keystroke and would find the wrong group
   * the first time two groups share a name.
   */
  readonly index: number;
  readonly name: string;
  readonly count: number;
  readonly collapsed: boolean;
  /** Pixel offset of this group's header from the top of the scrollable content. */
  readonly top: number;
  /** Header plus, when expanded, every row. */
  readonly height: number;
  /** Index of this group's first row in the caller's flat row array. Unaffected by collapse. */
  readonly firstRowIndex: number;
  /**
   * 1-based `aria-rowindex` of this group's header row, counting the column
   * header as row 1 and skipping the rows of collapsed groups. Precomputed here
   * so a rendered row can name its position in O(1) — an assistive technology
   * needs "row 41 200 of 100 400" for a row that is not in the DOM, and the DOM
   * cannot tell it.
   */
  readonly ariaRowIndex: number;
}

export interface Layout {
  readonly groups: readonly GroupLayout[];
  readonly density: Density;
  /** Scrollable content height, in pixels. */
  readonly totalHeight: number;
  /** Rows inside expanded groups — what is actually reachable by scrolling. */
  readonly presentRowCount: number;
  /** Every row in every group, collapsed or not. */
  readonly totalRowCount: number;
}

/**
 * O(groups). Called on every collapse and on every density change, which is why
 * it may not be O(rows): at 100 000 rows in 400 groups this touches 400 records.
 */
export function buildLayout(
  specs: readonly GroupSpec[],
  collapsed: ReadonlySet<string>,
  density: Density,
): Layout {
  const groups: GroupLayout[] = [];
  let top = 0;
  let firstRowIndex = 0;
  let presentRowCount = 0;
  let totalRowCount = 0;
  let ariaRowIndex = 2; // 1 is the column-header row; the first group header is 2.

  for (const spec of specs) {
    const isCollapsed = collapsed.has(spec.id);
    const height = density.headerHeight + (isCollapsed ? 0 : spec.count * density.rowHeight);
    groups.push({
      index: groups.length,
      id: spec.id,
      name: spec.name,
      count: spec.count,
      collapsed: isCollapsed,
      top,
      height,
      firstRowIndex,
      ariaRowIndex,
    });
    top += height;
    ariaRowIndex += 1 + (isCollapsed ? 0 : spec.count);
    firstRowIndex += spec.count;
    totalRowCount += spec.count;
    if (!isCollapsed) presentRowCount += spec.count;
  }

  return { groups, density, totalHeight: top, presentRowCount, totalRowCount };
}

/**
 * Index of the group occupying pixel `offset`, by binary search over group tops.
 * Clamps rather than returning -1: a scroll position past the end is a normal
 * state during a collapse, not an error, and returning -1 here would make every
 * caller carry the same guard.
 */
export function groupIndexAt(layout: Layout, offset: number): number {
  const { groups } = layout;
  if (groups.length === 0) return -1;
  let lo = 0;
  let hi = groups.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    // `noUncheckedIndexedAccess` is on; `mid` is inside the array by construction.
    if (groups[mid]!.top <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

export type WindowItem =
  | {
      readonly kind: 'header';
      readonly key: string;
      readonly groupIndex: number;
      readonly top: number;
      readonly height: number;
    }
  | {
      readonly kind: 'row';
      readonly key: string;
      readonly groupIndex: number;
      /** Index into the caller's flat row array. */
      readonly rowIndex: number;
      /** 1-based position among everything currently present, for `aria-rowindex`. */
      readonly ariaRowIndex: number;
      readonly top: number;
      readonly height: number;
    };

export interface WindowSlice {
  readonly items: readonly WindowItem[];
  /** Pixel offset of the first item, which the window container is translated by. */
  readonly startOffset: number;
  /** Group whose header is pinned to the top of the viewport, or -1 when the list is empty. */
  readonly stickyGroupIndex: number;
  /**
   * How far the pinned header is pushed up by the next one, in pixels, always
   * `<= 0`. This is the whole of "sticky headers fight the windowing": the
   * pinned header is not a `position: sticky` row inside the window — it is one
   * element outside it, and this is its offset.
   */
  readonly stickyPush: number;
}

/**
 * The rows and headers to render for a given scroll position.
 *
 * `overscanPx` is slack above and below the viewport, and it is also the
 * quantum: the window's bounds are **snapped to a multiple of it** rather than
 * tracking the scroll position exactly. That one detail is what stops the
 * rendered set from changing on every frame.
 *
 * Without the snap, the first row in the window changes every 36 px of scroll —
 * which at any real scroll speed is every single frame, so the overscan buys
 * extra DOM and nothing else. The benchmark said so: 898 React commits across
 * 899 frames. With it, the set changes once per `overscanPx` of travel, and the
 * intervening frames cost one `transform` write on one node.
 */
export function sliceWindow(
  layout: Layout,
  scrollTop: number,
  viewportHeight: number,
  overscanPx: number,
): WindowSlice {
  const { groups, density } = layout;
  if (groups.length === 0) {
    return { items: [], startOffset: 0, stickyGroupIndex: -1, stickyPush: 0 };
  }

  const clampedTop = Math.max(0, Math.min(scrollTop, Math.max(0, layout.totalHeight - 1)));
  const quantum = Math.max(1, overscanPx);
  const from = Math.max(0, Math.floor((clampedTop - overscanPx) / quantum) * quantum);
  /* The span is a whole number of quanta measured *from `from`*, not an
   * independently snapped upper bound. Snapping the two ends separately makes
   * them change phase at different scroll positions, so the window changes
   * twice per quantum instead of once — measured at 150 commits over 200
   * frames, against 75 for one shared phase. Both ends move together or the
   * quantization does half its job. */
  const to = from + Math.ceil((viewportHeight + 2 * quantum + quantum) / quantum) * quantum;

  const stickyGroupIndex = groupIndexAt(layout, clampedTop);
  const nextGroup = groups[stickyGroupIndex + 1];
  const stickyPush =
    nextGroup === undefined
      ? 0
      : Math.min(0, nextGroup.top - clampedTop - density.headerHeight);

  const items: WindowItem[] = [];
  let startOffset = -1;

  for (let g = groupIndexAt(layout, from); g < groups.length; g += 1) {
    const group = groups[g]!;
    if (group.top >= to) break;

    /* The pinned group's header is rendered by the sticky element, not here.
     * Rendering it in both places is how a duplicate row reaches the
     * accessibility tree, and hiding one of them is how it reaches it invisibly. */
    if (g !== stickyGroupIndex && group.top + density.headerHeight > from) {
      if (startOffset < 0) startOffset = group.top;
      items.push({
        kind: 'header',
        key: `h:${group.id}`,
        groupIndex: g,
        top: group.top,
        height: density.headerHeight,
      });
    }

    if (group.collapsed || group.count === 0) continue;

    const rowsTop = group.top + density.headerHeight;
    const firstVisible = Math.max(0, Math.floor((from - rowsTop) / density.rowHeight));
    const lastVisible = Math.min(
      group.count - 1,
      Math.ceil((to - rowsTop) / density.rowHeight) - 1,
    );

    for (let r = firstVisible; r <= lastVisible; r += 1) {
      const top = rowsTop + r * density.rowHeight;
      if (startOffset < 0) startOffset = top;
      items.push({
        kind: 'row',
        key: `r:${group.firstRowIndex + r}`,
        groupIndex: g,
        rowIndex: group.firstRowIndex + r,
        ariaRowIndex: group.ariaRowIndex + 1 + r,
        top,
        height: density.rowHeight,
      });
    }
  }

  return {
    items,
    startOffset: startOffset < 0 ? 0 : startOffset,
    stickyGroupIndex,
    stickyPush,
  };
}

/**
 * What the user is looking at, in terms that survive the index space changing
 * underneath them.
 *
 * `rowInGroup` is `null` when the topmost thing on screen is a group header.
 * `delta` is how far the scroll position is past that item's own top, so
 * restoring is exact rather than approximate — an off-by-a-few-pixels restore
 * reads as a jitter and is the reason this is not just "remember the row index".
 */
export interface ScrollAnchor {
  readonly groupId: string;
  readonly rowInGroup: number | null;
  readonly delta: number;
}

export function anchorAt(layout: Layout, scrollTop: number): ScrollAnchor | null {
  if (layout.groups.length === 0) return null;
  const clamped = Math.max(0, Math.min(scrollTop, Math.max(0, layout.totalHeight - 1)));
  const g = groupIndexAt(layout, clamped);
  const group = layout.groups[g]!;
  const withinGroup = clamped - group.top;

  if (group.collapsed || withinGroup < layout.density.headerHeight) {
    return { groupId: group.id, rowInGroup: null, delta: withinGroup };
  }

  const withinRows = withinGroup - layout.density.headerHeight;
  const rowInGroup = Math.min(group.count - 1, Math.floor(withinRows / layout.density.rowHeight));
  return {
    groupId: group.id,
    rowInGroup,
    delta: withinRows - rowInGroup * layout.density.rowHeight,
  };
}

/**
 * Put the anchored item back where it was.
 *
 * Collapsing a group *above* the viewport removes height above the anchor, so
 * without this the browser keeps `scrollTop` and the content slides up by
 * however many rows vanished — the single most visible way grouped
 * virtualization goes wrong, and the reason `docs/09 §3` promises that scroll
 * position and expansion state survive.
 *
 * When the anchored row's own group is the one that collapsed, the row no longer
 * exists; the anchor falls back to that group's header, which is where the user
 * would expect to land.
 */
export function scrollTopForAnchor(
  layout: Layout,
  anchor: ScrollAnchor,
  viewportHeight: number,
): number {
  const group = layout.groups.find((candidate) => candidate.id === anchor.groupId);
  if (group === undefined) return 0;

  let target: number;
  if (anchor.rowInGroup === null || group.collapsed) {
    target = group.top + anchor.delta;
    // A row anchor that lost its group lands on the header, not past it.
    if (group.collapsed && anchor.rowInGroup !== null) target = group.top;
  } else {
    const rowInGroup = Math.min(anchor.rowInGroup, Math.max(0, group.count - 1));
    target =
      group.top +
      layout.density.headerHeight +
      rowInGroup * layout.density.rowHeight +
      anchor.delta;
  }

  const maxScroll = Math.max(0, layout.totalHeight - viewportHeight);
  return Math.max(0, Math.min(target, maxScroll));
}
