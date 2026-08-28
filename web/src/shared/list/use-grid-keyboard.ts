import { useCallback, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import { alongDirection, directionOf, isMod } from '../keyboard/keys.ts';
import type { Layout, WindowSlice } from './geometry.ts';
import {
  clampCursor,
  cursorForRowIndex,
  firstCursor,
  offsetOf,
  rowIndexOf,
  rowsBetween,
  sameCursor,
  stepAlong,
  stepRow,
  type GridCursor,
} from './grid-cursor.ts';

/* Roving `tabindex` over a window whose rows are unmounted.
 *
 * `grid-cursor.ts` says where focus *is*; this says what the DOM does about it.
 * Three problems, and only the first is the textbook one:
 *
 * 1. **Roving tabindex.** Exactly one element inside the grid is in the tab
 *    order, so `Tab` enters and leaves the grid in one press instead of walking
 *    a hundred thousand rows. Standard, and the easy part.
 *
 * 2. **The tab stop can cease to exist.** In a virtualized grid the element
 *    holding `tabindex="0"` is unmounted as soon as the user scrolls away from
 *    it. If nothing catches that, `document.activeElement` becomes `<body>` and
 *    the next `Tab` restarts from the top of the page — a keyboard user is
 *    ejected from the grid by a mouse wheel. The rescue is in `onBlur` below,
 *    and it is conditioned on the node being *disconnected* rather than on
 *    focus merely leaving, because focus leaving is what `Tab` is supposed to
 *    do.
 *
 * 3. **The container must stay reachable.** While the cursor's element is not
 *    rendered, the scroller itself carries `tabindex="0"`: there has to be some
 *    way back in, and the cursor is remembered so that entering resumes where
 *    the user left rather than at row 1.
 *
 * The window's own machinery is untouched — this hook reads `layout` and
 * `slice` and never re-renders on scroll, because `useGroupedWindow` is
 * carefully arranged not to and undoing that would cost the 60 fps `docs/09 §2`
 * budgets.
 */

/** What the grid does to the product when a key is pressed. Supplied by the screen. */
export interface GridActions {
  readonly toggleGroup: (groupId: string) => void;
  /** Replace the selection with exactly these rows. */
  readonly setSelection: (rowIndices: readonly number[]) => void;
  /** Add or remove one row, leaving the rest alone. */
  readonly toggleSelection: (rowIndex: number) => void;
  /** `Enter` opens; `Space` peeks (`docs/09 §6`, `§7`). */
  readonly activate: (rowIndex: number, mode: 'open' | 'peek') => void;
  /** `J`/`K`: move the peek panel with the cursor, without closing it. */
  readonly walk: (rowIndex: number) => void;
  /** `⌘A`: every row in the view. */
  readonly selectAll: () => void;
}

export interface GridKeyboard {
  readonly cursor: GridCursor | null;
  /** `data-cursor` value of the element that should hold focus, or `null`. */
  readonly focusKey: string | null;
  /** `0` only while the cursor's own element is not in the DOM. */
  readonly containerTabIndex: 0 | -1;
  readonly onKeyDown: (event: KeyboardEvent<HTMLElement>) => void;
  readonly onBlur: (event: React.FocusEvent<HTMLElement>) => void;
  /** `Tab` into the grid: adopt a cursor so the first arrow press *moves*. */
  readonly onFocus: (event: React.FocusEvent<HTMLElement>) => void;
  /** Called when a pointer puts focus on a row, so the cursor follows the mouse. */
  readonly setCursor: (cursor: GridCursor | null) => void;
  readonly scrollerRef: (node: HTMLDivElement | null) => void;
}

/**
 * The `data-cursor` value naming an element.
 *
 * Rows reuse the keys `sliceWindow` already puts on its items so the two
 * naming schemes cannot drift; a cell appends its column.
 */
export function focusKeyOf(layout: Layout, cursor: GridCursor): string | null {
  const group = layout.groups[cursor.groupIndex];
  if (group === undefined) return null;
  if (cursor.rowInGroup === null) return `h:${group.id}`;
  const index = rowIndexOf(layout, cursor);
  if (index < 0) return null;
  return cursor.column === null ? `r:${index}` : `r:${index}:${cursor.column}`;
}

export function useGridKeyboard(
  layout: Layout,
  slice: WindowSlice,
  columnCount: number,
  actions: GridActions,
): GridKeyboard {
  const [cursor, setCursorState] = useState<GridCursor | null>(null);
  const scrollerNode = useRef<HTMLDivElement | null>(null);
  /**
   * Where a `Shift`-extend measures from.
   *
   * A ref rather than state: it never affects what is rendered, and putting it
   * in state would re-render the grid on every plain arrow press for a value
   * nothing draws.
   */
  const anchor = useRef<GridCursor | null>(null);
  /** Set only by a keypress, so a scroll never steals focus back to the grid. */
  const wantsFocus = useRef(false);
  /** The cursor as of the last commit, for handlers that must not re-render to read it. */
  const cursorRef = useRef<GridCursor | null>(null);
  /**
   * Whether the grid held focus, as of the last event.
   *
   * The whole basis of the rescue, and it cannot be derived from
   * `document.activeElement` after the fact — by then the answer is `<body>`
   * and `<body>` is also where focus is when the user simply clicked the page.
   */
  const hadFocus = useRef(false);

  const scrollerRef = useCallback((node: HTMLDivElement | null) => {
    scrollerNode.current = node;
  }, []);

  /* The cursor survives a collapse, an expand and new data — `clampCursor`
   * decides where it lands when the thing it named stopped existing. Recomputed
   * during render rather than in an effect so the `tabindex` written this
   * commit is the one for the cursor this commit. */
  const live = useMemo(() => clampCursor(layout, cursor), [layout, cursor]);
  cursorRef.current = live;
  const focusKey = live === null ? null : focusKeyOf(layout, live);

  /**
   * Which `data-cursor` values exist in this commit.
   *
   * Derived from the slice rather than queried from the DOM, because
   * `containerTabIndex` is needed *during* render and a DOM query is only
   * available after it. The sticky group header is included: it is rendered
   * outside the window, which is exactly the arrangement that stops it being
   * duplicated, and forgetting it here would make the pinned header the one row
   * the keyboard could never hold.
   */
  const rendered = useMemo(() => {
    const keys = new Set<string>();
    for (const item of slice.items) keys.add(item.key);
    const sticky = layout.groups[slice.stickyGroupIndex];
    if (sticky !== undefined) keys.add(`h:${sticky.id}`);
    return keys;
  }, [slice, layout]);

  const cursorRendered =
    focusKey !== null && rendered.has(focusKey.startsWith('h:') ? focusKey : rowKeyOf(focusKey));

  /**
   * A pointer, or the browser, put focus somewhere: follow it.
   *
   * **Ignored when it names where the cursor already is**, and that guard is
   * load-bearing rather than an optimisation. Every keyboard move ends by
   * focusing an element, whose `onFocus` calls straight back into here — so
   * without it, `Shift`-extend re-anchored to the row it had just extended
   * *to*, and the third press of `Shift+↓` selected two rows instead of three.
   * The bug is invisible for one press and wrong for every one after it.
   */
  const setCursor = useCallback((next: GridCursor | null) => {
    if (sameCursor(next, cursorRef.current)) return;
    anchor.current = next;
    setCursorState(next);
  }, []);

  /* ------------------------------------------------------- moving the cursor */

  const moveTo = useCallback(
    (next: GridCursor | null, options: { readonly select: 'replace' | 'extend' | 'toggle' | 'none' }) => {
      if (next === null) return;
      wantsFocus.current = true;
      setCursorState(next);

      const index = rowIndexOf(layout, next);
      if (options.select === 'replace') {
        anchor.current = next;
        actions.setSelection(index < 0 ? [] : [index]);
      } else if (options.select === 'extend') {
        const from = anchor.current ?? next;
        actions.setSelection(rowsBetween(layout, from, next));
      } else if (options.select === 'toggle') {
        anchor.current = next;
        if (index >= 0) actions.toggleSelection(index);
      } else {
        anchor.current = next;
      }
    },
    [layout, actions],
  );

  /* ---------------------------------------------------------- the key handler */

  const onKeyDown = useCallback(
    (event: KeyboardEvent<HTMLElement>) => {
      if (event.altKey) return;
      const total = layout.groups.length;
      if (total === 0) return;

      const current = live ?? firstCursor(layout);
      if (current === null) return;

      /* A control *inside* a row keeps its own keys.
       *
       * The row-actions button and the selection checkbox are the grid's focus
       * stops for their columns (the ARIA rule: a cell holding one widget puts
       * focus on the widget), and they are still real controls. Swallowing
       * `Enter` on a focused button so the row can open instead is how a
       * keyboard user finds a button they can reach and cannot press, and
       * swallowing `Space` on a checkbox is how selection stops working for
       * exactly the people who need the checkbox.
       *
       * Only `Enter` and `Space` defer. The arrows still belong to the grid
       * from anywhere inside it, or `→` onto the checkbox would be a one-way
       * trip. */
      const target = event.target;
      const onControl =
        target instanceof HTMLElement &&
        (target.tagName === 'INPUT' || target.tagName === 'BUTTON');

      switch (event.key) {
        case 'ArrowDown':
        case 'ArrowUp': {
          event.preventDefault();
          const delta = event.key === 'ArrowDown' ? 1 : -1;
          const next = stepRow(layout, current, delta);
          /* `docs/09 §6`: "`↑ ↓` Move selection · `Shift` extends · `⌘`
           * toggles". Read literally, which is how a specification with tests
           * behind it should be read: the plain arrow *moves the selection*, so
           * it replaces it; `⌘` moves and toggles the row it arrives at,
           * leaving everything else selected. */
          moveTo(next, {
            select: event.shiftKey ? 'extend' : isMod(event) ? 'toggle' : 'replace',
          });
          return;
        }

        case 'ArrowRight':
        case 'ArrowLeft': {
          const along = alongDirection(event.key, directionOf(scrollerNode.current));
          if (along === undefined) return;
          event.preventDefault();
          const outcome = stepAlong(layout, current, along, columnCount);
          if (outcome.kind === 'move') {
            moveTo(outcome.cursor, { select: 'none' });
          } else if (outcome.kind === 'expand' || outcome.kind === 'collapse') {
            const group = layout.groups[outcome.groupIndex];
            if (group !== undefined) {
              wantsFocus.current = true;
              actions.toggleGroup(group.id);
            }
          }
          return;
        }

        case 'Enter':
        case ' ': {
          if (onControl) return;
          event.preventDefault();
          const group = layout.groups[current.groupIndex];
          /* On a group header both keys do the one thing a header does. A tree
           * node's `Enter` is its expand toggle; there is nothing else to open. */
          if (current.rowInGroup === null) {
            if (group !== undefined) {
              wantsFocus.current = true;
              actions.toggleGroup(group.id);
            }
            return;
          }
          const index = rowIndexOf(layout, current);
          if (index >= 0) actions.activate(index, event.key === 'Enter' ? 'open' : 'peek');
          return;
        }

        /* `J`/`K` — "walk the list with the peek panel open, without closing
         * it". Case-insensitive: a user with caps lock on is still walking the
         * list, and `event.key` reports the shifted character. */
        case 'j':
        case 'J':
        case 'k':
        case 'K': {
          if (onControl || isMod(event)) return;
          event.preventDefault();
          const next = stepRow(layout, current, event.key.toLowerCase() === 'j' ? 1 : -1);
          if (next === null) return;
          moveTo(next, { select: 'replace' });
          const index = rowIndexOf(layout, next);
          if (index >= 0) actions.walk(index);
          return;
        }

        case 'a':
        case 'A': {
          if (!isMod(event)) return;
          event.preventDefault();
          actions.selectAll();
          return;
        }

        default:
          return;
      }
    },
    [layout, live, columnCount, moveTo, actions],
  );

  /* ------------------------------------------------------------ the DOM side */

  /**
   * Put the cursor's element back in view and give it focus.
   *
   * `wantsFocus` gates the focus call so that a *scroll* never yanks focus back
   * into the grid — the cursor is still remembered, the ring simply is not
   * moved by something the user did with a mouse.
   */
  useLayoutEffect(() => {
    const scroller = scrollerNode.current;
    if (scroller === null || live === null || focusKey === null) return;

    /**
     * Focus is on a row of the grid, and it is the **wrong** one.
     *
     * This is not defensive coding; it is a specific consequence of how the
     * pinned group header works. There is exactly one sticky element and it
     * carries whichever header belongs at the top — which is what stops a
     * duplicate row reaching the accessibility tree, and what makes it an
     * element whose *identity changes underneath focus*. Focus the pinned
     * `Files` header, scroll two pixels, and the same DOM node is now the
     * `Folders` header with your focus still on it: the ring has not moved and
     * the row it marks is a different file.
     *
     * Found by a test walking four rows and landing on the wrong group, and it
     * is invisible without one — nothing blurs, nothing errors, and the ring
     * stays exactly where the user expects it to be.
     */
    const active = document.activeElement;
    const activeKey = active instanceof HTMLElement ? active.dataset.cursor : undefined;
    const misplaced =
      activeKey !== undefined && activeKey !== focusKey && scroller.contains(active);

    /**
     * Focus was in the grid and is now on `<body>`: the element holding it was
     * unmounted by this very commit.
     *
     * **This is the rescue, and `onBlur` is not enough on its own.** Removing a
     * focused node does not reliably fire `blur` or `focusout` — jsdom does not,
     * and browsers disagree about it — so a handler waiting for that event waits
     * for something that may never arrive. The commit is the one moment that is
     * guaranteed to happen, because the commit is what removed the node.
     *
     * Found by a test that walked four rows across a group boundary and landed
     * on `<body>`: the pinned header changed which group it was showing, the
     * window unmounted the row that had focus, and nothing was told.
     */
    const lost = hadFocus.current && active === scroller.ownerDocument.body;

    if (!wantsFocus.current && !misplaced && !lost) return;

    /* Only a keypress scrolls. Correcting a misplaced ring must not, because
     * what misplaced it was a scroll — and scrolling back would take the list
     * away from wherever the user just put it. */
    const box = wantsFocus.current ? offsetOf(layout, live) : null;
    if (box !== null) {
      /* The column header and the pinned group header both overlay the top of
       * the scroll area, so "visible" starts below them. Without this the
       * cursor lands *under* the sticky chrome and the focus ring is invisible
       * on exactly the row the user just moved to. */
      const obscured = layout.density.columnsHeight + layout.density.headerHeight;
      if (box.top - obscured < scroller.scrollTop) {
        scroller.scrollTop = Math.max(0, box.top - obscured);
      } else if (box.top + box.height > scroller.scrollTop + scroller.clientHeight) {
        scroller.scrollTop = box.top + box.height - scroller.clientHeight;
      }
    }

    const node = scroller.querySelector<HTMLElement>(`[data-cursor="${cssEscape(focusKey)}"]`);
    if (node !== null) {
      wantsFocus.current = false;
      node.focus({ preventScroll: true });
    } else if (!scroller.contains(document.activeElement)) {
      /* The row has not been rendered yet — the scroll above has to land and
       * the window has to catch up. Hold focus in the grid meanwhile rather
       * than losing it, and let the next commit finish the job. */
      scroller.focus({ preventScroll: true });
    }
  });

  /**
   * The rescue: focus left because the element it was on was removed.
   *
   * Conditioned on `isConnected`, not on focus merely leaving. `Tab` out of the
   * grid is correct and must not be fought; a row unmounted by a scroll is the
   * case where the browser has quietly dropped the user on `<body>`.
   */
  /**
   * `Tab` landed on the container.
   *
   * Entering a grid puts the user *on* its first item, not beside it — a
   * container that took focus and left the cursor unset would make the first
   * arrow press do nothing visible, which reads as the grid ignoring the
   * keyboard. Only when there is no cursor yet: this also fires when the rescue
   * above hands focus back to the container after a row was unmounted, and
   * resetting to row 1 there would be the position loss the cursor exists to
   * prevent.
   */
  const onFocus = useCallback(
    (event: React.FocusEvent<HTMLElement>) => {
      hadFocus.current = true;
      if (event.target !== event.currentTarget) return;
      if (cursorRef.current !== null) return;
      const first = firstCursor(layout);
      if (first === null) return;
      wantsFocus.current = true;
      anchor.current = first;
      setCursorState(first);
    },
    [layout],
  );

  const onBlur = useCallback((event: React.FocusEvent<HTMLElement>) => {
    const scroller = scrollerNode.current;
    if (scroller === null) return;
    /* A genuine `Tab` away: focus went to a real element outside the grid. Let
     * it go, and stop claiming the grid has focus — otherwise the next commit
     * would drag the user back in from wherever they went. */
    if (event.relatedTarget !== null && !scroller.contains(event.relatedTarget as Node)) {
      hadFocus.current = false;
      return;
    }
    if (event.target.isConnected) return;
    scroller.focus({ preventScroll: true });
  }, []);

  return {
    cursor: live,
    focusKey,
    containerTabIndex: cursorRendered ? -1 : 0,
    onKeyDown,
    onBlur,
    onFocus,
    setCursor,
    scrollerRef,
  };
}

/** `r:12:3` addresses a cell of the row rendered as `r:12`. */
function rowKeyOf(focusKey: string): string {
  const second = focusKey.indexOf(':', 2);
  return second < 0 ? focusKey : focusKey.slice(0, second);
}

/**
 * Enough escaping for the keys this file generates.
 *
 * `CSS.escape` is the right answer and is absent from jsdom, so a component
 * test would throw where the browser would not. The keys are `h:<id>` and
 * `r:<n>[:<n>]`; only the colon and whatever a group id contains need care.
 */
function cssEscape(value: string): string {
  return value.replace(/["\\]/g, '\\$&');
}

/** Re-exported so a screen can address a row by its flat index. */
export { cursorForRowIndex, sameCursor };
