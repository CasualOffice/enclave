import { memo, useCallback, useMemo, type CSSProperties } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import { ChevronIcon } from '../../../shared/ui/icons.tsx';
import { Avatar, IconButton } from '../../../shared/ui/primitives.tsx';
import { DENSITY, type DensityName, type GroupLayout, type GroupSpec } from '../../../shared/list/geometry.ts';
import { useGroupedWindow } from '../../../shared/list/use-grouped-window.ts';
import { useGridKeyboard, type GridActions } from '../../../shared/list/use-grid-keyboard.ts';
import { rowIndexOf } from '../../../shared/list/grid-cursor.ts';
import { ClassificationChip } from '../../../entities/classification/chip.tsx';
import { FileKindIcon } from '../../../entities/file/kind-icon.tsx';
import type { FileRow } from '../../../entities/file/model.ts';
import { PhaseSteps, type UploadRow } from '../../../entities/upload/index.ts';
import {
  EmptyState,
  ErrorState,
  FilteredEmptyState,
  LoadingState,
  RowCountAnnouncement,
  type ListError,
} from './states.tsx';
import './grouped-list.css';

/** The seven columns of `specs/library.md §4A`, which `→ ←` walks. */
const COLUMN_COUNT = 7;

export interface GroupedFileListProps {
  readonly groups: readonly GroupSpec[];
  /** Flat, in group order. `GroupLayout.firstRowIndex` indexes into it. */
  readonly rows: readonly FileRow[];
  readonly collapsed: ReadonlySet<string>;
  readonly onToggleGroup: (id: string) => void;
  readonly selected?: ReadonlySet<string>;
  readonly onToggleSelect?: ((id: string) => void) | undefined;
  /** Replace the whole selection — what `↑ ↓`, `Shift`-extend and `⌘A` need. */
  readonly onSelect?: ((ids: readonly string[]) => void) | undefined;
  /** `Enter` on a row. A folder opens; a file has no open surface in M5 (see below). */
  readonly onOpen?: ((row: FileRow) => void) | undefined;
  /** `Space`, and `J`/`K` while the peek panel is open (`docs/09 §7`). */
  readonly onPeek?: ((row: FileRow) => void) | undefined;
  readonly density?: DensityName;
  readonly status?: 'loading' | 'ready' | 'error';
  readonly error?: ListError | undefined;
  /** True when a filter is narrowing the query. Distinguishes the two empty states. */
  readonly filtersActive?: boolean;
  /** How many rows the *unfiltered* query would return. Only read when `filtersActive`. */
  readonly unfilteredCount?: number;
  readonly onRetry?: (() => void) | undefined;
  readonly onClearFilters?: (() => void) | undefined;
  readonly onUpload?: (() => void) | undefined;
  /**
   * Uploads in flight into *this* container, drawn as rows.
   *
   * The prototype draws an uploading file as a row in the list with a three-dot
   * stepper in the status column and the rest of the row dimmed
   * (`enclave-client-prototype.html` line 263). That is kept.
   *
   * They are **not** part of the virtualized window: a queue is a handful of
   * rows, they change every frame while transferring, and threading mutable
   * rows through an index-based layout would invalidate the window on every
   * progress tick. They render in their own rowgroup above the groups instead.
   * The prototype appends rather than prepends; the top is chosen so a
   * transfer stays visible in a library with ten thousand rows, which is the
   * point of showing it at all.
   */
  readonly uploads?: readonly UploadRow[];
}

/**
 * `undefined` means this row is not where the cursor is; `null` means the
 * cursor is on the row itself rather than in one of its cells.
 *
 * Three states in one prop so that moving the cursor re-renders **two** rows —
 * the one it left and the one it reached — instead of every row in the window.
 * Passing the focus key down instead would invalidate all thirty on every arrow
 * press, which is the memoization this file's header exists to protect.
 */
type CursorColumn = number | null | undefined;

const GroupHeaderRow = memo(function GroupHeaderRow({
  group,
  onToggle,
  cursorHere,
  onFocusRow,
}: {
  group: GroupLayout;
  onToggle: (id: string) => void;
  cursorHere: boolean;
  onFocusRow: (groupIndex: number, rowInGroup: number | null, column: number | null) => void;
}) {
  const t = useT();
  return (
    /* **`aria-expanded` is on the row**, and the focus stop is the row.
     *
     * It used to sit on the `<button>` inside, which was defensible while
     * nothing could focus a row: a screen reader met the button and heard the
     * state there. Once the row is a roving tab stop it is the row that gets
     * announced, and a row whose expanded state lives on a descendant is
     * announced without it — the collapsed `Archive 96` reads as an ordinary
     * row that happens to have nothing under it. The `<button>` stays, because
     * the header does something and a click target should be a button, and it
     * is taken out of the tab order the way every control in a grid is. */
    <div
      role="row"
      aria-rowindex={group.ariaRowIndex}
      aria-expanded={!group.collapsed}
      aria-level={1}
      className="egl-grouprow"
      data-cursor={`h:${group.id}`}
      tabIndex={cursorHere ? 0 : -1}
      onFocus={() => onFocusRow(group.index, null, null)}
    >
      <button
        type="button"
        className="egl-group"
        role="gridcell"
        aria-colindex={1}
        aria-colspan={COLUMN_COUNT}
        tabIndex={-1}
        aria-label={t(group.collapsed ? 'files.group.expand' : 'files.group.collapse', {
          group: group.name,
        })}
        onClick={() => onToggle(group.id)}
      >
        <ChevronIcon className="egl-group-chevron" />
        <span className="egl-group-name" dir="auto">
          {group.name}
        </span>
        {/* A collapsed group's count is its only clue to what it hides, so it is
         * never dropped for space. */}
        <span className="egl-group-count">{t('files.group.count', { count: group.count })}</span>
      </button>
    </div>
  );
});

/**
 * A row's entrance index, as a typed custom property.
 *
 * `--i` is read by `.enc-stagger` in `styles/motion.css`, which computes
 * `min(--i, --stagger-cap) × --stagger-row` — the prototype's own
 * `Math.min(i, 12) * 0.02s`. Typed rather than cast through `any`: a custom
 * property is not in `CSSProperties`, and the honest way to say so is to name
 * the one property being added.
 */
type StaggerStyle = CSSProperties & Record<'--i', number>;

const FileRowView = memo(function FileRowView({
  row,
  ariaRowIndex,
  rowIndex,
  groupIndex,
  rowInGroup,
  windowIndex,
  selected,
  cursorColumn,
  onToggleSelect,
  onPeek,
  onFocusRow,
}: {
  row: FileRow;
  ariaRowIndex: number;
  /** Index into the caller's flat row array — the `data-cursor` identity. */
  rowIndex: number;
  groupIndex: number;
  rowInGroup: number;
  /** Position within the rendered window, which is what the stagger counts. */
  windowIndex: number;
  selected: boolean;
  cursorColumn: CursorColumn;
  onToggleSelect: ((id: string) => void) | undefined;
  onPeek: ((row: FileRow) => void) | undefined;
  onFocusRow: (groupIndex: number, rowInGroup: number | null, column: number | null) => void;
}) {
  const t = useT();
  const formatters = useFormatters();
  const modified = new Date(row.modifiedAt);
  const stagger: StaggerStyle = { '--i': windowIndex };

  /** `tabIndex`/`data-cursor` for cell `column`, 0-based. */
  const cell = (column: number) => ({
    role: 'gridcell' as const,
    'aria-colindex': column + 1,
    'data-cursor': `r:${rowIndex}:${column}`,
    tabIndex: cursorColumn === column ? 0 : -1,
    onFocus: () => onFocusRow(groupIndex, rowInGroup, column),
  });

  /**
   * A cell holding exactly one control: the control is the focus stop, not the
   * cell around it.
   *
   * This is the ARIA grid rule and it is the difference between "the cell that
   * contains the button is reachable" and "the button is reachable". `→` onto
   * the row-actions cell has to leave the user able to *press* the thing they
   * arrived at; landing on the `<span>` and requiring a further, unbound key to
   * get inside it is a control the keyboard can see and not use. The checkbox
   * in column 0 is the same case, which is how selection is toggled without a
   * pointer.
   *
   * The cell keeps its `gridcell` role and its column index — the grid's shape
   * is unchanged — and gives up only the `tabindex` and the `data-cursor`,
   * which move inward. `:focus-within` on the cell is therefore still what
   * reveals the button, one moment before it takes focus.
   */
  const controlCell = (column: number) => ({
    role: 'gridcell' as const,
    'aria-colindex': column + 1,
  });

  const control = (column: number) => ({
    'data-cursor': `r:${rowIndex}:${column}`,
    tabIndex: cursorColumn === column ? 0 : -1,
    onFocus: () => onFocusRow(groupIndex, rowInGroup, column),
  });

  return (
    /* `specs/library.md §4A.3`: a row rises 4px and fades in over `--dur-row` on
     * the reference's own easing, staggered 20ms and capped at the twelfth so a
     * long list finishes its entrance in 240ms rather than in eight seconds.
     * Both halves are utilities in `styles/motion.css`, so the reduced-motion
     * answer — travel to zero, duration to 1ms, stagger to 0 — is inherited
     * rather than restated here. */
    <div
      className="egl-row enc-enter-row enc-stagger"
      style={stagger}
      role="row"
      aria-rowindex={ariaRowIndex}
      aria-selected={selected}
      aria-level={2}
      data-cursor={`r:${rowIndex}`}
      tabIndex={cursorColumn === null ? 0 : -1}
      onFocus={(event) => {
        /* Only when the row itself took focus. A cell's `focus` bubbles through
         * here, and letting it set `column: null` would undo the `→` the user
         * just pressed. */
        if (event.target === event.currentTarget) onFocusRow(groupIndex, rowInGroup, null);
      }}
    >
      <span className="egl-cell-select" {...controlCell(0)}>
        <input
          type="checkbox"
          className="egl-checkbox"
          checked={selected}
          {...control(0)}
          aria-label={t('files.row.checkbox', { name: row.name })}
          onChange={() => onToggleSelect?.(row.id)}
        />
      </span>
      <span className="egl-name" {...cell(1)}>
        <FileKindIcon kind={row.kind} />
        {/* `dir="auto"` and isolation: a file name mixing Arabic and Latin
         * script must not rearrange the row around it (`docs/14 §7`). */}
        <bdi className="egl-name-text" dir="auto">
          {row.name}
          <span className="egl-name-ext">{row.extension}</span>
        </bdi>
      </span>
      <span className="egl-meta" {...cell(2)}>
        {/* No avatar when the server sent no modifier.
         *
         * `GET /libraries/{id}/items` carries `modifiedAt` but not the name of
         * whoever made the change, and a UUID's first two characters are not
         * initials. An empty circle would read as a person with no name; two
         * letters of an id would read as a person who does not exist. Drawing
         * nothing is the only one of the three that is true. */}
        {row.modifiedByInitials.length > 0 && (
          /* `Avatar`, not a local `.egl-avatar`. The local one hard-coded its
           * four tones as light-theme hex — `#E0E7FF/#3730A3` and friends — so
           * the list's avatars did not flip in dark mode at all. `Avatar` reads
           * the `--av-*-bg` / `--av-*-fg` pairs, which do. */
          <Avatar initials={row.modifiedByInitials} tone={row.modifiedByTone} />
        )}
        {/* Relative time from `Intl.RelativeTimeFormat`, with the absolute value
         * in the title. The reference hand-builds "2 h ago" and "Yesterday";
         * D35.6 records that as a defect, not a pattern. */}
        <time dateTime={modified.toISOString()} title={formatters.dateTime(modified)}>
          {formatters.relative(modified)}
        </time>
      </span>
      <span {...cell(3)}>
        {/* Classification is a label on *content*. A folder has none, and
         * "Unclassified" on one would say nobody had labelled it rather than
         * that the idea does not apply — the same class of invented fact as a
         * guessed capability. */}
        {!row.isFolder && <ClassificationChip level={row.classification} />}
      </span>
      {/* Effect pills (retention, no-download) land with `ENC-674`'s
       * capabilities-with-reasons. Empty and present, so the column exists. */}
      <span {...cell(4)} />
      <span className="egl-meta egl-meta-size" {...cell(5)}>
        {/* The server sends `sizeBytes: 0` for every folder, and rendering it
         * produced "0 byte" — a measurement, and a false one. A folder's size
         * is not zero; it is not a quantity the listing carries. */}
        {row.isFolder ? '' : formatters.bytes(row.sizeBytes)}
      </span>
      {/* ------------------------------------------------------- row actions */}
      <span className="egl-cell-actions" {...controlCell(6)}>
        {/* **`opacity: 0`, never `display: none`.**
         *
         * `.ui-iconbtn[data-reveal]` fades in on the row's hover and on
         * `:focus-within`, and that choice is load-bearing rather than
         * decorative: `display:none` and `visibility:hidden` both remove an
         * element from the focus order, so a row-actions control hidden that
         * way is one a keyboard user can never reach. The primitive has carried
         * the decision since the design system landed; until now nothing in the
         * list rendered it, so there was nothing for focus to reach *to*. `→`
         * walks to this cell, which reveals the button through `:focus-within`,
         * and the button is then the only focusable thing inside it.
         *
         * It opens the **details peek**, and it is not an overflow menu. There
         * is no row menu to open — rename, move, copy and trash have no
         * endpoint (`shared/keyboard/bindings.ts`) — and drawing a `⋯` that
         * opens nothing would promise a menu the product does not have. Details
         * is a real action on a real endpoint, which is why it is the one drawn.
         */}
        {onPeek !== undefined && (
          <IconButton
            name="side"
            label="files.row.details"
            values={{ name: row.name }}
            reveal
            {...control(6)}
            onClick={() => onPeek(row)}
          />
        )}
      </span>
    </div>
  );
});

/**
 * A file being uploaded, as a row.
 *
 * The prototype dims it to `.5`, gives it no checkbox affordance, no
 * classification and no row menu, and puts the stepper in the status column.
 * All four are kept, and each is honest rather than cosmetic:
 *
 * - **No selection.** There is nothing to act on: the file has no id in this
 *   library until `complete` answers, so every selection action would refer to
 *   a row the server has never heard of.
 * - **No classification.** Classification is a server decision about content
 *   that has not been scanned yet. Drawing `Unclassified` would be a claim; an
 *   empty cell is the absence of one.
 * - **No size formatting difference.** The size is known locally and is real.
 *
 * `aria-disabled` rather than removal from the tree: a screen-reader user
 * should hear that the file is arriving, which is the whole point of the live
 * region inside `PhaseSteps`.
 */
const UploadQueue = memo(function UploadQueue({ uploads }: { uploads: readonly UploadRow[] }) {
  const t = useT();
  const formatters = useFormatters();

  if (uploads.length === 0) return null;

  return (
    /* A **list, not grid rows.**
     *
     * The prototype draws these as rows in the file list, and visually they
     * still are — the same seven-column template, the same 36 px height. What
     * they are not is rows of *this grid*: a `treegrid` with `aria-rowcount`
     * requires every row to carry a unique `aria-rowindex`, and the windowed
     * rows already own that index space starting at 2. Splicing a mutable
     * queue into it would either collide or force the layout engine to
     * recompute every index on every progress tick.
     *
     * A queue of files arriving is honestly a list, so it is one. A screen
     * reader announces "list, 2 items" above the grid rather than mislabelling
     * transient work as library content.
     */
    <ul className="egl-uploads" aria-label={t('upload.queue.label')}>
      {uploads.map((row) => (
        <li key={row.id} className="egl-row egl-row-upload">
          <span className="egl-cell-select" />
          <span className="egl-name">
            <FileKindIcon kind="other" />
            <bdi className="egl-name-text" dir="auto">
              {row.name}
            </bdi>
          </span>
          <span className="egl-meta" />
          {/* No classification: it is a server decision about content nothing
           * has scanned yet, and `Unclassified` would be a claim rather than
           * the absence of one. */}
          <span />
          {/* The status column, which is where the prototype puts the stepper. */}
          <span>
            <PhaseSteps phase={row.phase} />
          </span>
          <span className="egl-meta egl-meta-size">{formatters.bytes(row.sizeBytes)}</span>
          <span />
        </li>
      ))}
    </ul>
  );
});

function ColumnHeaderRow() {
  const t = useT();
  return (
    <div className="egl-columns-row" role="row" aria-rowindex={1}>
      <span role="columnheader" aria-colindex={1} />
      <span role="columnheader" aria-colindex={2}>
        {t('files.column.name')}
      </span>
      <span role="columnheader" aria-colindex={3}>
        {t('files.column.modified')}
      </span>
      <span role="columnheader" aria-colindex={4}>
        {t('files.column.classification')}
      </span>
      <span role="columnheader" aria-colindex={5}>
        {t('files.column.status')}
      </span>
      <span role="columnheader" aria-colindex={6} className="egl-col-size">
        {t('files.column.size')}
      </span>
      <span role="columnheader" aria-colindex={7} />
    </div>
  );
}

/**
 * The column header outside a grid.
 *
 * The empty, loading and error states keep the columns so the surface does not
 * change shape between them — `docs/09 §11`'s no-layout-shift rule reads across
 * states, not only within one. Without a grid around it the row carries no
 * `row`/`columnheader` semantics, because there are no cells for it to head.
 */
function ColumnChrome() {
  const t = useT();
  return (
    <div className="egl-columns egl-columns-static">
      <div className="egl-columns-row" aria-hidden="true">
        <span />
        <span>{t('files.column.name')}</span>
        <span>{t('files.column.modified')}</span>
        <span>{t('files.column.classification')}</span>
        <span>{t('files.column.status')}</span>
        <span className="egl-col-size">{t('files.column.size')}</span>
        <span />
      </div>
    </div>
  );
}

const NO_SELECTION: ReadonlySet<string> = new Set<string>();
const NO_UPLOADS: readonly UploadRow[] = [];

/**
 * A grouped, collapsible, virtualized file list.
 *
 * `plans/M5-MVP-GA.md` D38 sequenced this first because it is the one part of
 * M5 that can fail on its own merits. What makes it work is in
 * `geometry.ts` and `use-grouped-window.ts`; what makes it *reachable* is in
 * `grid-cursor.ts` and `use-grid-keyboard.ts`. This file is the markup, and its
 * one job is not to undo them — no per-row state, no context read inside a row,
 * no inline object props, `memo` on both row kinds.
 */
export function GroupedFileList({
  groups,
  rows,
  collapsed,
  onToggleGroup,
  selected = NO_SELECTION,
  onToggleSelect,
  onSelect,
  onOpen,
  onPeek,
  density = 'default',
  status = 'ready',
  error,
  filtersActive = false,
  unfilteredCount = 0,
  onRetry,
  onClearFilters,
  onUpload,
  uploads = NO_UPLOADS,
}: GroupedFileListProps) {
  const t = useT();
  const metrics = DENSITY[density];
  const { layout, slice, scrollerRef, windowRef, stickyRef, onScroll, toggleGroup } =
    useGroupedWindow(groups, collapsed, metrics, onToggleGroup);

  const handleToggleSelect = useCallback(
    (id: string) => onToggleSelect?.(id),
    [onToggleSelect],
  );

  /* The keyboard's view of the product. Row *indices* on this side of the
   * boundary and row *ids* on the other: the cursor arithmetic works in
   * positions, and the selection store keys by id, so exactly one place
   * translates and it is here. */
  const actions = useMemo<GridActions>(
    () => ({
      toggleGroup: (groupId) => onToggleGroup(groupId),
      setSelection: (indices) =>
        onSelect?.(indices.map((index) => rows[index]?.id).filter((id): id is string => id !== undefined)),
      toggleSelection: (index) => {
        const row = rows[index];
        if (row !== undefined) onToggleSelect?.(row.id);
      },
      activate: (index, mode) => {
        const row = rows[index];
        if (row === undefined) return;
        if (mode === 'peek') onPeek?.(row);
        else onOpen?.(row);
      },
      walk: (index) => {
        const row = rows[index];
        if (row !== undefined) onPeek?.(row);
      },
      /* `⌘A` — "select all **in view**". Every row the current listing
       * returned, including rows inside a collapsed group: a collapsed group is
       * still part of this view, and its header says how many rows it holds, so
       * a user who collapses "Archive 96" and presses `⌘A` has not stopped
       * seeing them. It is the *filter* that decides what is in view, and the
       * server has already applied it. */
      selectAll: () => onSelect?.(rows.map((row) => row.id)),
    }),
    [rows, onToggleGroup, onSelect, onToggleSelect, onOpen, onPeek],
  );

  const keyboard = useGridKeyboard(layout, slice, COLUMN_COUNT, actions);

  const setScroller = useCallback(
    (node: HTMLDivElement | null) => {
      scrollerRef(node);
      keyboard.scrollerRef(node);
    },
    [scrollerRef, keyboard],
  );

  const onFocusRow = useCallback(
    (groupIndex: number, rowInGroup: number | null, column: number | null) => {
      keyboard.setCursor({ groupIndex, rowInGroup, column });
    },
    [keyboard],
  );

  const sticky = slice.stickyGroupIndex >= 0 ? layout.groups[slice.stickyGroupIndex] : undefined;
  const cursor = keyboard.cursor;
  const cursorRowIndex = cursor === null ? -1 : rowIndexOf(layout, cursor);

  const styleVars = {
    '--egl-row-h': `${metrics.rowHeight}px`,
    '--egl-header-h': `${metrics.headerHeight}px`,
    '--egl-columns-h': `${metrics.columnsHeight}px`,
  } as React.CSSProperties;

  /* The four states **replace** the grid; they are not laid over it.
   *
   * Two reasons, and the second is the one axe found. A surface that shows an
   * error banner above stale rows has told the user two things at once. And a
   * `role="treegrid"` whose children include a status message or an error panel
   * is a treegrid with children ARIA does not allow — `aria-required-children`,
   * critical, on every state route. Rendering one or the other settles both. */
  if (status === 'error' && error !== undefined) {
    return (
      <div className="egl" style={styleVars}>
        <ColumnChrome />
        <ErrorState error={error} onRetry={onRetry} />
      </div>
    );
  }

  if (status === 'loading') {
    return (
      <div className="egl" style={styleVars}>
        <ColumnChrome />
        {/* The skeleton keeps the grid's exact box model, so nothing shifts when
         * the rows land — but it carries no grid semantics, because there is no
         * grid yet and claiming one would be the same lie the rest of this
         * milestone is about. */}
        <LoadingState />
      </div>
    );
  }

  /* Empty — but only when nothing is arriving.
   *
   * The first upload into a new library would otherwise render "this library is
   * empty, upload something" *over the file the user is uploading*, which is
   * both wrong and the most likely moment for anyone to see this state. An
   * upload in flight means the surface is not empty. */
  if (layout.totalRowCount === 0 && uploads.length === 0) {
    return (
      <div className="egl" style={styleVars}>
        <ColumnChrome />
        {filtersActive ? (
          <FilteredEmptyState hiddenCount={unfilteredCount} onClearFilters={onClearFilters} />
        ) : (
          <EmptyState onUpload={onUpload} />
        )}
      </div>
    );
  }

  return (
    <div className="egl" style={styleVars}>
      <UploadQueue uploads={uploads} />
      <div
        className="egl-scroller"
        ref={setScroller}
        onScroll={onScroll}
        onKeyDown={keyboard.onKeyDown}
        onBlur={keyboard.onBlur}
        onFocus={keyboard.onFocus}
        role="treegrid"
        /* **The container is a tab stop only while the cursor's row is not.**
         *
         * That is the roving part. Two elements carrying `tabindex="0"` inside
         * one grid is two stops on the `Tab` path, which is the thing roving
         * tabindex exists to prevent; zero of them is a grid nothing can enter.
         * The container takes the stop back whenever the cursor's row has been
         * scrolled out of the DOM, so there is always exactly one. */
        tabIndex={keyboard.containerTabIndex}
        aria-label={t('files.list.label')}
        /* Against the **full** set, not the window. `layout` is built from every
         * group's declared count; `slice` is the thirty rows that happen to be
         * mounted. A treegrid that reports the window has told a screen-reader
         * user the library has thirty files in it. */
        aria-rowcount={1 + layout.groups.length + layout.presentRowCount}
        aria-colcount={COLUMN_COUNT}
      >
        <div className="egl-columns" role="rowgroup">
          <ColumnHeaderRow />
        </div>

        {/* One element, outside the window, carrying whichever group header
         * belongs at the top. The window never renders the header it is
         * showing, so there is no duplicate row in the accessibility tree and
         * nothing to hide — which is the whole of "sticky headers fight the
         * windowing", answered by taking the sticky one out of it. */}
        <div className="egl-sticky" role="rowgroup">
          <div ref={stickyRef}>
            {sticky !== undefined && (
              <GroupHeaderRow
                group={sticky}
                onToggle={toggleGroup}
                cursorHere={cursor?.groupIndex === sticky.index && cursor.rowInGroup === null}
                onFocusRow={onFocusRow}
              />
            )}
          </div>
        </div>

        {/* A spacer, hidden from the accessibility tree, whose only job is to
         * give the scrollbar something to measure. The rows live in the
         * absolutely positioned window beside it, so the treegrid's children
         * stay rowgroups all the way down. */}
        <div
          className="egl-spacer"
          aria-hidden="true"
          style={{ blockSize: `${layout.totalHeight}px` }}
        />

        <div className="egl-window" role="rowgroup" ref={windowRef}>
          {slice.items.map((item, windowIndex) => {
            if (item.kind === 'header') {
              const group = layout.groups[item.groupIndex];
              return group === undefined ? null : (
                <GroupHeaderRow
                  key={item.key}
                  group={group}
                  onToggle={toggleGroup}
                  cursorHere={cursor?.groupIndex === item.groupIndex && cursor.rowInGroup === null}
                  onFocusRow={onFocusRow}
                />
              );
            }
            const row = rows[item.rowIndex];
            if (row === undefined) return null;
            const group = layout.groups[item.groupIndex];
            return (
              <FileRowView
                key={item.key}
                row={row}
                ariaRowIndex={item.ariaRowIndex}
                rowIndex={item.rowIndex}
                groupIndex={item.groupIndex}
                rowInGroup={item.rowIndex - (group?.firstRowIndex ?? 0)}
                windowIndex={windowIndex}
                selected={selected.has(row.id)}
                cursorColumn={cursorRowIndex === item.rowIndex ? (cursor?.column ?? null) : undefined}
                onToggleSelect={onToggleSelect === undefined ? undefined : handleToggleSelect}
                onPeek={onPeek}
                onFocusRow={onFocusRow}
              />
            );
          })}
        </div>
      </div>
      <RowCountAnnouncement shown={layout.presentRowCount} total={layout.totalRowCount} />
    </div>
  );
}
