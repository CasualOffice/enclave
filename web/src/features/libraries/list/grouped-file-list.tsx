import { memo, useCallback } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import { ChevronIcon, FileIcon } from '../../../shared/ui/icons.tsx';
import { IconButton, Pill } from '../../../shared/ui/primitives.tsx';
import { DENSITY, type DensityName, type GroupLayout, type GroupSpec } from './geometry.ts';
import { useGroupedWindow } from './use-grouped-window.ts';
import { ClassificationChip } from '../../../entities/classification/chip.tsx';
import type { FileRow } from '../../../entities/file/model.ts';
import type { StatusPillSpec } from '../model.ts';
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
  /** The row the peek panel is showing, from `?peek=`. Empty when it is closed. */
  readonly peekId?: string;
  /** Single click on a row body peeks it. It does **not** navigate and does not select. */
  readonly onPeek?: ((id: string) => void) | undefined;
  /**
   * The row's status pill, from the server row's own `{tone, code}`.
   *
   * A function rather than a field on `FileRow` because the listing endpoint
   * does not send it yet and the row model is 100 000 allocations wide. The
   * client never picks a tone from a permission it inferred — the tone is the
   * server's, and this is the seam it will arrive through.
   */
  readonly pillFor?: ((row: FileRow) => StatusPillSpec | undefined) | undefined;
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

const FileRowView = memo(function FileRowView({
  row,
  ariaRowIndex,
  selected,
  peeked,
  onToggleSelect,
  onPeek,
  pill,
}: {
  row: FileRow;
  ariaRowIndex: number;
  selected: boolean;
  peeked: boolean;
  onToggleSelect: ((id: string) => void) | undefined;
  onPeek: ((id: string) => void) | undefined;
  pill: StatusPillSpec | undefined;
}) {
  const t = useT();
  const formatters = useFormatters();
  const modified = new Date(row.modifiedAt);

  return (
    <div
      className="egl-row"
      role="row"
      aria-rowindex={ariaRowIndex}
      aria-selected={selected}
      data-peeked={peeked ? 'true' : undefined}
      /* Single click peeks; it does not navigate and does not change the
       * selection (`specs/library.md`, POINTER). Double click opens the file. */
      onClick={onPeek === undefined ? undefined : () => onPeek(row.id)}
    >
      <span className="egl-cell-select" role="gridcell">
        <input
          type="checkbox"
          className="egl-checkbox"
          checked={selected}
          aria-label={t('files.row.checkbox', { name: row.name })}
          /* The row's own click handler would otherwise peek whatever the user
           * was only trying to tick. */
          onClick={(event) => event.stopPropagation()}
          onChange={() => onToggleSelect?.(row.id)}
        />
      </span>
      <span className="egl-name" role="gridcell">
        <FileIcon className="egl-name-icon" kind={row.kind} />
        {/* `dir="auto"` and isolation: a file name mixing Arabic and Latin
         * script must not rearrange the row around it (`docs/14 §7`). */}
        <bdi className="egl-name-text" dir="auto">
          {row.name}
          <span className="egl-name-ext">{row.extension}</span>
        </bdi>
      </span>
      <span className="egl-meta" role="gridcell">
        <span className="egl-avatar" data-tone={row.modifiedByTone} aria-hidden="true">
          {row.modifiedByInitials}
        </span>
        {/* Relative time from `Intl.RelativeTimeFormat`, with the absolute value
         * in the title. The reference hand-builds "2 h ago" and "Yesterday";
         * D35.6 records that as a defect, not a pattern. */}
        <time dateTime={modified.toISOString()} title={formatters.dateTime(modified)}>
          {formatters.relative(modified)}
        </time>
      </span>
      <span role="gridcell">
        {/* One chip, shared with the location bar and the peek panel. It used to
         * be a fourth private copy of a **locked** palette (`ENC-703`). */}
        <ClassificationChip level={row.classification} />
      </span>
      {/* The effect pill: retention, a legal hold, a download restriction. Tone
       * and label are both the server's — the client never infers a tone from a
       * permission (`specs/library.md §4A(e)`). */}
      <span className="egl-status" role="gridcell">
        {pill !== undefined && <Pill label={pill.label} tone={pill.tone} icon={pill.icon} />}
      </span>
      <span className="egl-meta egl-meta-size" role="gridcell">
        {formatters.bytes(row.sizeBytes)}
      </span>
      <span className="egl-cell-actions" role="gridcell">
        {/* Present at `opacity:0` and revealed on hover or focus-within — never
         * `display:none`, because a hidden button is not reachable by keyboard
         * and this is the only route to the per-row menu. */}
        <IconButton
          name="more"
          label="files.row.menu"
          values={{ name: row.name }}
          onClick={(event) => event.stopPropagation()}
        />
      </span>
    </div>
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
  peekId = '',
  onPeek,
  pillFor,
}: GroupedFileListProps) {
  const t = useT();
  const metrics = DENSITY[density];
  const { layout, slice, scrollerRef, windowRef, stickyRef, onScroll, toggleGroup } =
    useGroupedWindow(groups, collapsed, metrics, onToggleGroup);

  const handleToggleSelect = useCallback(
    (id: string) => onToggleSelect?.(id),
    [onToggleSelect],
  );

  /* Stable identities, so a row's `memo` is not defeated by a new closure on
   * every parent render — the whole reason this list holds 60 fps at 100k. */
  const handlePeek = useCallback((id: string) => onPeek?.(id), [onPeek]);

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
        <LoadingState density={metrics} />
      </div>
    );
  }

  if (layout.totalRowCount === 0) {
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
          {slice.items.map((item) => {
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
                selected={selected.has(row.id)}
                peeked={row.id === peekId}
                onToggleSelect={onToggleSelect === undefined ? undefined : handleToggleSelect}
                onPeek={onPeek === undefined ? undefined : handlePeek}
                pill={pillFor?.(row)}
              />
            );
          })}
        </div>
      </div>
      <RowCountAnnouncement shown={layout.presentRowCount} total={layout.totalRowCount} />
    </div>
  );
}
