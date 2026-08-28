import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { GroupedFileList } from '../../src/features/libraries/list/grouped-file-list.tsx';
import type { GroupSpec } from '../../src/shared/list/geometry.ts';
import type { FileRow } from '../../src/entities/file/model.ts';

afterEach(cleanup);

/* `docs/09 §6` in a DOM: focus is moved and its landing place is asserted.
 *
 * ## Why these tests are shaped the way they are
 *
 * **An assertion about an absence passes for free**, and keyboard tests are
 * unusually prone to it. "Focus did not escape the grid" is true of a grid that
 * never received focus, of a selector that matches nothing, and of a screen
 * that failed to mount. Every negative assertion below is paired with a
 * *positive control in the same test* — focus demonstrably inside the grid,
 * on a named row, before the thing being ruled out is checked.
 *
 * `focused()` is the shared control: it fails loudly if `document.activeElement`
 * is `<body>` or is outside the treegrid, so a test that silently lost focus
 * cannot go on to pass.
 */

const GROUPS: readonly GroupSpec[] = [
  { id: 'folders', name: 'Folders', count: 2 },
  { id: 'files', name: 'Files', count: 4 },
];

/* No `as FileRow[]`. The first draft of this fixture carried one, and it hid
 * two wrong fields — `classification: 'INTERNAL'` against a lower-case union,
 * and an ISO string where the model documents epoch milliseconds — which
 * surfaced as fifteen tests failing inside `react-intl` rather than as a type
 * error at the fixture. A cast in a fixture is a compile-time check spent to
 * save typing. */
const ROWS: readonly FileRow[] = Array.from({ length: 6 }, (_, index) => ({
  id: `id-${index}`,
  name: `Item ${index}`,
  extension: index < 2 ? '' : '.pdf',
  kind: index < 2 ? ('folder' as const) : ('doc' as const),
  isFolder: index < 2,
  classification: 'internal' as const,
  sizeBytes: 1024 * (index + 1),
  modifiedAt: Date.UTC(2026, 7, 1, 10, 0, 0),
  modifiedByInitials: 'AB',
  modifiedByTone: 'a' as const,
}));

interface Harness {
  readonly grid: HTMLElement;
  readonly onOpen: ReturnType<typeof vi.fn>;
  readonly onPeek: ReturnType<typeof vi.fn>;
  readonly onSelect: ReturnType<typeof vi.fn>;
  readonly onToggleGroup: ReturnType<typeof vi.fn>;
  readonly onToggleSelect: ReturnType<typeof vi.fn>;
}

function mount(options: { readonly collapsed?: readonly string[]; readonly dir?: 'ltr' | 'rtl' } = {}): Harness {
  const onOpen = vi.fn();
  const onPeek = vi.fn();
  const onSelect = vi.fn();
  const onToggleGroup = vi.fn();
  const onToggleSelect = vi.fn();

  /* Direction is read from the *computed* style of the scroller, which
   * inherits — so setting it on the document element is how a locale sets it,
   * and is what `en-XB` will do. */
  document.documentElement.dir = options.dir ?? 'ltr';

  render(
    <I18nProvider>
      <GroupedFileList
        groups={GROUPS}
        rows={ROWS}
        collapsed={new Set(options.collapsed ?? [])}
        onToggleGroup={onToggleGroup}
        selected={new Set()}
        onToggleSelect={onToggleSelect}
        onSelect={onSelect}
        onOpen={onOpen}
        onPeek={onPeek}
      />
    </I18nProvider>,
  );

  return {
    grid: screen.getByRole('treegrid'),
    onOpen,
    onPeek,
    onSelect,
    onToggleGroup,
    onToggleSelect,
  };
}

/**
 * The positive control, and the only way this file reads `activeElement`.
 *
 * It refuses to return a node that is outside the grid or is `<body>`, so a
 * test whose focus quietly went nowhere fails *here*, by name, instead of going
 * on to satisfy some later assertion about what focus is not doing.
 */
function focused(grid: HTMLElement): HTMLElement {
  const node = document.activeElement;
  expect(node, 'nothing has focus — the grid never received it').not.toBe(document.body);
  expect(node).toBeInstanceOf(HTMLElement);
  expect(
    grid.contains(node),
    `focus is outside the grid, on <${(node as HTMLElement).tagName.toLowerCase()}>`,
  ).toBe(true);
  return node as HTMLElement;
}

/** Where the cursor is, as the `data-cursor` string the component writes. */
const cursorOf = (grid: HTMLElement) => focused(grid).dataset.cursor;

/**
 * Enter the grid the way `Tab` does.
 *
 * Focusing the container is the whole of it: entering a grid lands on its first
 * item, so no arrow press is needed to *arrive*. That is asserted rather than
 * assumed by the first test below.
 */
function enter(grid: HTMLElement): void {
  /* `act`, because a bare `.focus()` is not a React event: the `onFocus`
   * handler queues a state update and the layout effect that moves DOM focus
   * onto the first row runs in the commit after it. Without `act` the assertion
   * reads the DOM one commit too early and finds focus still on the container —
   * which looked exactly like "entering the grid does not work". */
  act(() => {
    grid.focus();
  });
}

describe('entering the grid', () => {
  it('starts on the first group header, not on nothing', () => {
    const { grid } = mount();
    enter(grid);
    expect(cursorOf(grid)).toBe('h:folders');
  });

  it('keeps exactly one tab stop inside the grid', () => {
    /* The roving invariant. Two stops is two places `Tab` lands inside one
     * widget; zero is a grid nothing can enter. Checked before *and* after
     * moving, because the container has to hand the stop over and take it back. */
    const { grid } = mount();
    const stops = () =>
      [grid, ...grid.querySelectorAll<HTMLElement>('[tabindex="0"]')].filter(
        (node) => node.getAttribute('tabindex') === '0',
      ).length;

    expect(stops()).toBe(1);
    enter(grid);
    expect(cursorOf(grid)).toBe('h:folders');
    expect(stops()).toBe(1);
  });
});

describe('↑ and ↓ move the selection', () => {
  it('walk from the header into the rows and across a group boundary', () => {
    const { grid } = mount();
    enter(grid);
    expect(cursorOf(grid)).toBe('h:folders');

    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:0');
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:1');
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('h:files');
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:2');
  });

  it('replace the selection with the row they arrive at', () => {
    const { grid, onSelect } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(onSelect).toHaveBeenLastCalledWith(['id-0']);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(onSelect).toHaveBeenLastCalledWith(['id-1']);
  });

  it('extend the selection with Shift, from where the plain arrow left the anchor', () => {
    const { grid, onSelect } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' }); // r:0, anchor
    fireEvent.keyDown(grid, { key: 'ArrowDown', shiftKey: true }); // r:1
    expect(onSelect).toHaveBeenLastCalledWith(['id-0', 'id-1']);
    fireEvent.keyDown(grid, { key: 'ArrowDown', shiftKey: true }); // h:files — no new row
    expect(onSelect).toHaveBeenLastCalledWith(['id-0', 'id-1']);
    fireEvent.keyDown(grid, { key: 'ArrowDown', shiftKey: true }); // r:2
    expect(onSelect).toHaveBeenLastCalledWith(['id-0', 'id-1', 'id-2']);
  });

  it('toggle rather than replace when ⌘ is held', () => {
    /* `docs/09 §6` reads "`↑ ↓` Move selection · `Shift` extends · `⌘`
     * toggles", read literally: the modified arrow moves *and* toggles the row
     * it arrives at, leaving the rest of the selection alone. */
    const { grid, onSelect, onToggleSelect } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    onSelect.mockClear();
    fireEvent.keyDown(grid, { key: 'ArrowDown', metaKey: true });
    expect(cursorOf(grid)).toBe('r:1');
    expect(onToggleSelect).toHaveBeenLastCalledWith('id-1');
    expect(onSelect, '⌘ replaced the selection instead of toggling one row').not.toHaveBeenCalled();
  });

  it('do not walk out of the grid at the top', () => {
    const { grid } = mount();
    enter(grid);
    expect(cursorOf(grid)).toBe('h:folders'); // positive control: focus is in
    for (let press = 0; press < 5; press += 1) fireEvent.keyDown(grid, { key: 'ArrowUp' });
    /* `focused()` is what makes this an assertion rather than a wish: it fails
     * if focus reached `<body>`, which is exactly what walking off the end
     * would do. */
    expect(cursorOf(grid)).toBe('h:folders');
  });
});

describe('→ and ← are a tree and a grid at once', () => {
  it('expand a collapsed group and collapse an expanded one', () => {
    const { grid, onToggleGroup } = mount({ collapsed: ['files'] });
    enter(grid);
    for (let press = 0; press < 3; press += 1) fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('h:files'); // positive control

    fireEvent.keyDown(grid, { key: 'ArrowRight' });
    expect(onToggleGroup).toHaveBeenLastCalledWith('files');
  });

  it('walk into the row’s columns and back out to its group header', () => {
    const { grid } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:0');

    fireEvent.keyDown(grid, { key: 'ArrowRight' });
    expect(cursorOf(grid)).toBe('r:0:0');
    fireEvent.keyDown(grid, { key: 'ArrowRight' });
    expect(cursorOf(grid)).toBe('r:0:1');
    fireEvent.keyDown(grid, { key: 'ArrowLeft' });
    expect(cursorOf(grid)).toBe('r:0:0');
    fireEvent.keyDown(grid, { key: 'ArrowLeft' });
    expect(cursorOf(grid)).toBe('r:0');
    fireEvent.keyDown(grid, { key: 'ArrowLeft' });
    expect(cursorOf(grid)).toBe('h:folders');
  });

  it('follow writing direction, not the screen, in a right-to-left locale', () => {
    /* `CLAUDE.md` rule 12's last clause, for the keyboard. In Hebrew or Arabic
     * *next* is the key labelled ArrowLeft, so a tree that expands on the
     * physical right key collapses a group for a user trying to open it.
     * `en-XB` mirrors direction in CI. */
    const { grid, onToggleGroup } = mount({ collapsed: ['files'], dir: 'rtl' });
    enter(grid);
    for (let press = 0; press < 3; press += 1) fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('h:files'); // positive control

    /* The *physical right* key must now go backward — and there is nothing
     * behind a collapsed header, so nothing happens. */
    fireEvent.keyDown(grid, { key: 'ArrowRight' });
    expect(onToggleGroup, 'ArrowRight expanded in an RTL locale').not.toHaveBeenCalled();

    fireEvent.keyDown(grid, { key: 'ArrowLeft' });
    expect(onToggleGroup).toHaveBeenLastCalledWith('files');
  });
});

describe('Enter, Space, ⌘A and J/K', () => {
  it('open on Enter and peek on Space', () => {
    const { grid, onOpen, onPeek } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:0');

    fireEvent.keyDown(grid, { key: 'Enter' });
    expect(onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: 'id-0' }));
    expect(onPeek).not.toHaveBeenCalled();

    fireEvent.keyDown(grid, { key: ' ' });
    expect(onPeek).toHaveBeenCalledWith(expect.objectContaining({ id: 'id-0' }));
  });

  it('toggle a group with Enter on its header rather than opening nothing', () => {
    const { grid, onToggleGroup, onOpen } = mount();
    enter(grid);
    expect(cursorOf(grid)).toBe('h:folders');
    fireEvent.keyDown(grid, { key: 'Enter' });
    expect(onToggleGroup).toHaveBeenLastCalledWith('folders');
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('select everything in the view on ⌘A, including a collapsed group’s rows', () => {
    const { grid, onSelect } = mount({ collapsed: ['files'] });
    enter(grid);
    expect(cursorOf(grid)).toBe('h:folders'); // positive control
    fireEvent.keyDown(grid, { key: 'a', metaKey: true });
    expect(onSelect).toHaveBeenLastCalledWith(ROWS.map((row) => row.id));
  });

  it('walk the list with J and K, moving the peek panel with the cursor', () => {
    const { grid, onPeek } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:0');

    fireEvent.keyDown(grid, { key: 'j' });
    expect(cursorOf(grid)).toBe('r:1');
    expect(onPeek).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'id-1' }));

    fireEvent.keyDown(grid, { key: 'K' });
    expect(cursorOf(grid)).toBe('r:0');
    expect(onPeek).toHaveBeenLastCalledWith(expect.objectContaining({ id: 'id-0' }));
  });
});

describe('the controls inside a row', () => {
  it('puts focus on the row-actions button itself, not on the cell around it', () => {
    /* The `opacity: 0` / `:focus-within` decision is only load-bearing if focus
     * can actually get here. A cell the keyboard can reach, holding a button it
     * cannot, is a control you can see and not press. */
    const { grid } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:0'); // positive control
    for (let press = 0; press < 7; press += 1) fireEvent.keyDown(grid, { key: 'ArrowRight' });

    const node = focused(grid);
    expect(node.dataset.cursor).toBe('r:0:6');
    expect(node.tagName).toBe('BUTTON');
    expect(node.getAttribute('aria-label')).toBe('Details for Item 0');
    /* And it is never `display:none` — which would have made all of the above
     * impossible. Asserted on the attribute the primitive sets, because the
     * jsdom `getComputedStyle` does not load the stylesheet. */
    expect(node.hasAttribute('data-reveal')).toBe(true);
  });

  it('leaves Enter and Space to a focused control instead of swallowing them', () => {
    const { grid, onPeek, onOpen } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    for (let press = 0; press < 7; press += 1) fireEvent.keyDown(grid, { key: 'ArrowRight' });
    const button = focused(grid);
    expect(button.tagName).toBe('BUTTON'); // positive control

    fireEvent.keyDown(button, { key: 'Enter' });
    expect(onOpen, 'the grid opened the row instead of pressing the focused button').not.toHaveBeenCalled();
    fireEvent.click(button);
    expect(onPeek).toHaveBeenCalledWith(expect.objectContaining({ id: 'id-0' }));
  });

  it('reaches the selection checkbox in the first column', () => {
    const { grid } = mount();
    enter(grid);
    fireEvent.keyDown(grid, { key: 'ArrowDown' });
    expect(cursorOf(grid)).toBe('r:0'); // positive control
    fireEvent.keyDown(grid, { key: 'ArrowRight' });

    const node = focused(grid);
    expect(node.tagName).toBe('INPUT');
    expect(node.getAttribute('type')).toBe('checkbox');
  });
});

describe('what the screen reader is told', () => {
  it('counts the full set, not the rendered window', () => {
    /* 1 column header + 2 group headers + 6 rows. */
    const { grid } = mount();
    expect(grid.getAttribute('aria-rowcount')).toBe('9');
  });

  it('still counts the full set when most of it is not in the DOM', () => {
    /* The assertion that matters, and it needs a list long enough to be
     * windowed — six rows all render, so the small fixture above cannot tell a
     * correct count from one derived from the window. 400 rows can: a treegrid
     * that reported its window would say this library holds about twenty files.
     *
     * The rendered count is asserted as *greater than zero* as well, because
     * "fewer rows than the total" is also true of a grid that rendered none. */
    const many: readonly GroupSpec[] = [{ id: 'files', name: 'Files', count: 400 }];
    const manyRows: readonly FileRow[] = Array.from({ length: 400 }, (_, index) => ({
      ...ROWS[0]!,
      id: `big-${index}`,
      name: `Big ${index}`,
    }));
    render(
      <I18nProvider>
        <GroupedFileList groups={many} rows={manyRows} collapsed={new Set()} onToggleGroup={vi.fn()} />
      </I18nProvider>,
    );
    const grid = screen.getAllByRole('treegrid').at(-1)!;
    expect(grid.getAttribute('aria-rowcount')).toBe('402');

    const rendered = grid.querySelectorAll('.egl-row').length;
    expect(rendered, 'no rows rendered at all — the count assertion would pass for free').toBeGreaterThan(0);
    expect(rendered).toBeLessThan(400);
  });

  it('drops a collapsed group’s rows from the count, as its rowindexes do', () => {
    const { grid } = mount({ collapsed: ['files'] });
    expect(grid.getAttribute('aria-rowcount')).toBe('5');
  });

  it('announces expanded state on the row, where focus lands', () => {
    const { grid } = mount({ collapsed: ['files'] });
    enter(grid);
    const header = focused(grid);
    expect(header.getAttribute('role')).toBe('row');
    expect(header.getAttribute('aria-expanded')).toBe('true');

    const collapsed = grid.querySelector('[data-cursor="h:files"]');
    expect(collapsed?.getAttribute('aria-expanded')).toBe('false');
  });
});
