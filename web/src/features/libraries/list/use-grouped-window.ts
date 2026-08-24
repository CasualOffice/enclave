import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
import {
  anchorAt,
  buildLayout,
  scrollTopForAnchor,
  sliceWindow,
  type Density,
  type GroupSpec,
  type Layout,
  type ScrollAnchor,
  type WindowSlice,
} from './geometry.ts';

const EMPTY_SLICE: WindowSlice = {
  items: [],
  startOffset: 0,
  stickyGroupIndex: -1,
  stickyPush: 0,
};

/** Two identities and a group index are enough to know a re-render is needed. */
function sliceSignature(slice: WindowSlice): string {
  const first = slice.items[0]?.key ?? '';
  const last = slice.items[slice.items.length - 1]?.key ?? '';
  return `${first}|${last}|${slice.stickyGroupIndex}`;
}

export interface GroupedWindow {
  readonly layout: Layout;
  readonly slice: WindowSlice;
  readonly scrollerRef: (node: HTMLDivElement | null) => void;
  readonly windowRef: (node: HTMLDivElement | null) => void;
  readonly stickyRef: (node: HTMLDivElement | null) => void;
  readonly onScroll: () => void;
  /** Collapse or expand a group without moving what the user is looking at. */
  readonly toggleGroup: (id: string) => void;
}

/**
 * The windowing engine.
 *
 * Two rules shape it, and both come out of `plans/M5-MVP-GA.md` D38:
 *
 * 1. **React state changes only when the set of rendered rows changes**, and
 *    `sliceWindow` snaps the window's bounds to a multiple of the overscan so
 *    that set is stable for a whole block of travel. Only leaving the block, or
 *    crossing a group boundary, is a re-render. Every other scroll frame writes
 *    two `transform`s on two nodes and returns.
 * 2. **A collapse is anchored before it happens.** The scroll position is
 *    captured as *which item is at the top and by how much*, the layout is
 *    rebuilt, and the same item is put back at the same offset in the same
 *    frame — a `useLayoutEffect`, so nothing is ever painted at the wrong
 *    offset. This is `docs/09 §3`'s promise that scroll position and expansion
 *    state survive.
 */
export function useGroupedWindow(
  groups: readonly GroupSpec[],
  collapsed: ReadonlySet<string>,
  density: Density,
  onToggle: (id: string) => void,
  overscanPx = 240,
): GroupedWindow {
  const layout = useMemo(
    () => buildLayout(groups, collapsed, density),
    [groups, collapsed, density],
  );

  const scrollerNode = useRef<HTMLDivElement | null>(null);
  const windowNode = useRef<HTMLDivElement | null>(null);
  const stickyNode = useRef<HTMLDivElement | null>(null);

  const [slice, setSlice] = useState<WindowSlice>(EMPTY_SLICE);
  const sliceRef = useRef<WindowSlice>(EMPTY_SLICE);
  const layoutRef = useRef<Layout>(layout);
  const frameRef = useRef<number>(0);
  const pendingAnchor = useRef<ScrollAnchor | null>(null);

  layoutRef.current = layout;

  /**
   * Read the scroll position and put everything where it belongs.
   *
   * Called from the scroll handler, from the resize observer and from the
   * layout effects. It is the only place that touches the DOM directly, and it
   * is deliberately not a React render: `docs/09 §2` budgets one frame for a
   * keystroke, and a re-render per scroll event does not fit in one.
   */
  const apply = useCallback(() => {
    const scroller = scrollerNode.current;
    if (scroller === null) return;

    const current = layoutRef.current;
    const viewportHeight = Math.max(0, scroller.clientHeight - current.density.columnsHeight);
    const next = sliceWindow(current, scroller.scrollTop, viewportHeight, overscanPx);

    if (stickyNode.current !== null) {
      stickyNode.current.style.transform = `translateY(${next.stickyPush}px)`;
    }
    if (windowNode.current !== null) {
      windowNode.current.style.transform = `translateY(${next.startOffset}px)`;
    }

    if (sliceSignature(next) !== sliceSignature(sliceRef.current)) {
      sliceRef.current = next;
      setSlice(next);
    }
  }, [overscanPx]);

  /* Coalesce to one measurement per frame. A trackpad fires scroll events
   * faster than the compositor paints, and doing the work twice for one frame
   * is how a virtualized list burns its budget on nothing. */
  const onScroll = useCallback(() => {
    if (frameRef.current !== 0) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = 0;
      apply();
    });
  }, [apply]);

  const scrollerRef = useCallback(
    (node: HTMLDivElement | null) => {
      scrollerNode.current = node;
      if (node !== null) apply();
    },
    [apply],
  );

  const windowRef = useCallback((node: HTMLDivElement | null) => {
    windowNode.current = node;
  }, []);

  const stickyRef = useCallback((node: HTMLDivElement | null) => {
    stickyNode.current = node;
  }, []);

  /* The viewport height is an input to the window, so a resize is a scroll. */
  useLayoutEffect(() => {
    const scroller = scrollerNode.current;
    if (scroller === null || typeof ResizeObserver === 'undefined') return undefined;
    const observer = new ResizeObserver(() => apply());
    observer.observe(scroller);
    return () => observer.disconnect();
  }, [apply]);

  /* Recompute whenever the layout changes — a collapse, an expand, a density
   * change, or new data — and restore the anchor in the same commit. */
  useLayoutEffect(() => {
    const scroller = scrollerNode.current;
    const anchor = pendingAnchor.current;
    if (scroller !== null && anchor !== null) {
      pendingAnchor.current = null;
      const viewportHeight = Math.max(0, scroller.clientHeight - layout.density.columnsHeight);
      scroller.scrollTop = scrollTopForAnchor(layout, anchor, viewportHeight);
    }
    apply();
  }, [layout, apply]);

  useLayoutEffect(
    () => () => {
      if (frameRef.current !== 0) cancelAnimationFrame(frameRef.current);
    },
    [],
  );

  const toggleGroup = useCallback(
    (id: string) => {
      const scroller = scrollerNode.current;
      /* Captured against the layout that is on screen *now*. Once `onToggle`
       * runs, the index space it describes no longer exists. */
      pendingAnchor.current =
        scroller === null ? null : anchorAt(layoutRef.current, scroller.scrollTop);
      onToggle(id);
    },
    [onToggle],
  );

  return { layout, slice, scrollerRef, windowRef, stickyRef, onScroll, toggleGroup };
}
