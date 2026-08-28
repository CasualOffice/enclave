import { memo, useCallback, type CSSProperties } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import { ChevronIcon } from '../../../shared/ui/icons.tsx';
import { Avatar } from '../../../shared/ui/primitives.tsx';
import { DENSITY, type DensityName, type GroupLayout, type GroupSpec } from '../../../shared/list/geometry.ts';
import { useGroupedWindow } from '../../../shared/list/use-grouped-window.ts';
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

export interface GroupedFileListProps {
  readonly groups: readonly GroupSpec[];
  /** Flat, in group order. `GroupLayout.firstRowIndex` indexes into it. */
  readonly rows: readonly FileRow[];
  readonly collapsed: ReadonlySet<string>;
  readonly onToggleGroup: (id: string) => void;
  readonly selected?: ReadonlySet<string>;
  readonly onToggleSelect?: ((id: string) => void) | undefined;
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

const GroupHeaderRow = memo(function GroupHeaderRow({
  group,
  onToggle,
}: {
  group: GroupLayout;
  onToggle: (id: string) => void;
}) {
  const t = useT();
  return (
    <div role="row" aria-rowindex={group.ariaRowIndex}>
      {/* The header is a button because it does something. `aria-expanded` on a
       * `role="row"` inside a treegrid is what tells a screen reader that the
       * rows beneath it are hidden rather than absent — the difference a
       * collapsed `Archive 96` has to communicate. */}
      <button
        type="button"
        className="egl-group"
        role="gridcell"
        aria-colspan={7}
        aria-expanded={!group.collapsed}
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
  windowIndex,
  selected,
  onToggleSelect,
}: {
  row: FileRow;
  ariaRowIndex: number;
  /** Position within the rendered window, which is what the stagger counts. */
  windowIndex: number;
  selected: boolean;
  onToggleSelect: ((id: string) => void) | undefined;
}) {
  const t = useT();
  const formatters = useFormatters();
  const modified = new Date(row.modifiedAt);
  const stagger: StaggerStyle = { '--i': windowIndex };

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
    >
      <span className="egl-cell-select" role="gridcell">
        <input
          type="checkbox"
          className="egl-checkbox"
          checked={selected}
          aria-label={t('files.row.checkbox', { name: row.name })}
          onChange={() => onToggleSelect?.(row.id)}
        />
      </span>
      <span className="egl-name" role="gridcell">
        <FileKindIcon kind={row.kind} />
        {/* `dir="auto"` and isolation: a file name mixing Arabic and Latin
         * script must not rearrange the row around it (`docs/14 §7`). */}
        <bdi className="egl-name-text" dir="auto">
          {row.name}
          <span className="egl-name-ext">{row.extension}</span>
        </bdi>
      </span>
      <span className="egl-meta" role="gridcell">
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
      <span role="gridcell">
        {/* Classification is a label on *content*. A folder has none, and
         * "Unclassified" on one would say nobody had labelled it rather than
         * that the idea does not apply — the same class of invented fact as a
         * guessed capability. */}
        {!row.isFolder && <ClassificationChip level={row.classification} />}
      </span>
      {/* Effect pills (retention, no-download) land with `ENC-674`'s
       * capabilities-with-reasons. Empty and present, so the column exists. */}
      <span role="gridcell" />
      <span className="egl-meta egl-meta-size" role="gridcell">
        {/* The server sends `sizeBytes: 0` for every folder, and rendering it
         * produced "0 byte" — a measurement, and a false one. A folder's size
         * is not zero; it is not a quantity the listing carries. */}
        {row.isFolder ? '' : formatters.bytes(row.sizeBytes)}
      </span>
      <span role="gridcell" />
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
      <span role="columnheader" />
      <span role="columnheader">{t('files.column.name')}</span>
      <span role="columnheader">{t('files.column.modified')}</span>
      <span role="columnheader">{t('files.column.classification')}</span>
      <span role="columnheader">{t('files.column.status')}</span>
      <span role="columnheader" className="egl-col-size">
        {t('files.column.size')}
      </span>
      <span role="columnheader" />
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
 * `geometry.ts` and `use-grouped-window.ts`; this file is the markup, and its
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

  const sticky = slice.stickyGroupIndex >= 0 ? layout.groups[slice.stickyGroupIndex] : undefined;

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
        ref={scrollerRef}
        onScroll={onScroll}
        role="treegrid"
        tabIndex={0}
        aria-label={t('files.list.label')}
        aria-rowcount={1 + layout.groups.length + layout.presentRowCount}
        aria-colcount={7}
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
            {sticky !== undefined && <GroupHeaderRow group={sticky} onToggle={toggleGroup} />}
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
                <GroupHeaderRow key={item.key} group={group} onToggle={toggleGroup} />
              );
            }
            const row = rows[item.rowIndex];
            return row === undefined ? null : (
              <FileRowView
                key={item.key}
                row={row}
                ariaRowIndex={item.ariaRowIndex}
                windowIndex={windowIndex}
                selected={selected.has(row.id)}
                onToggleSelect={onToggleSelect === undefined ? undefined : handleToggleSelect}
              />
            );
          })}
        </div>
      </div>
      <RowCountAnnouncement shown={layout.presentRowCount} total={layout.totalRowCount} />
    </div>
  );
}
