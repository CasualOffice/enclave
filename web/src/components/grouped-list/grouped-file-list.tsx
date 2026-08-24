import { memo, useCallback } from 'react';
import { useT } from '../../i18n/index.tsx';
import { useFormatters } from '../../i18n/format.ts';
import { ChevronIcon, FileIcon } from '../icons.tsx';
import { DENSITY, type DensityName, type GroupLayout, type GroupSpec } from './geometry.ts';
import { useGroupedWindow } from './use-grouped-window.ts';
import { CLASSIFICATION_KEY, type FileRow } from './model.ts';
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
  onToggleSelect,
}: {
  row: FileRow;
  ariaRowIndex: number;
  selected: boolean;
  onToggleSelect: ((id: string) => void) | undefined;
}) {
  const t = useT();
  const formatters = useFormatters();
  const modified = new Date(row.modifiedAt);

  return (
    <div className="egl-row" role="row" aria-rowindex={ariaRowIndex} aria-selected={selected}>
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
        <span className="egl-classification" data-level={row.classification}>
          {t(CLASSIFICATION_KEY[row.classification])}
        </span>
      </span>
      {/* Effect pills (retention, no-download) land with `ENC-674`'s
       * capabilities-with-reasons. Empty and present, so the column exists. */}
      <span role="gridcell" />
      <span className="egl-meta egl-meta-size" role="gridcell">
        {formatters.bytes(row.sizeBytes)}
      </span>
      <span role="gridcell" />
    </div>
  );
});

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

  /* The four states come first, and they replace the list rather than sitting
   * beside it: a surface that shows an error banner above stale rows is a
   * surface that has told the user two things at once. */
  let overlay: React.ReactNode = null;
  if (status === 'error' && error !== undefined) {
    overlay = <ErrorState error={error} onRetry={onRetry} />;
  } else if (status === 'ready' && layout.totalRowCount === 0) {
    overlay = filtersActive ? (
      <FilteredEmptyState hiddenCount={unfilteredCount} onClearFilters={onClearFilters} />
    ) : (
      <EmptyState onUpload={onUpload} />
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
        aria-busy={status === 'loading'}
      >
        <div className="egl-columns" role="rowgroup">
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
        </div>

        {status === 'loading' ? (
          <LoadingState density={metrics} />
        ) : (
          <>
            {/* One element, outside the window, carrying whichever group header
             * belongs at the top. The window never renders that header, so
             * there is no duplicate row in the accessibility tree and nothing
             * to hide — which is the whole of "sticky headers fight the
             * windowing", answered by taking the sticky one out of it. */}
            <div className="egl-sticky" role="rowgroup">
              <div ref={stickyRef}>
                {sticky !== undefined && (
                  <GroupHeaderRow group={sticky} onToggle={toggleGroup} />
                )}
              </div>
            </div>

            <div
              className="egl-sizer"
              role="presentation"
              style={{ blockSize: `${layout.totalHeight}px` }}
            >
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
                      onToggleSelect={onToggleSelect === undefined ? undefined : handleToggleSelect}
                    />
                  );
                })}
              </div>
            </div>
          </>
        )}

        {overlay}
      </div>
      <RowCountAnnouncement shown={layout.presentRowCount} total={layout.totalRowCount} />
    </div>
  );
}
