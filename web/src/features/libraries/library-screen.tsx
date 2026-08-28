import { useCallback, useMemo } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Button, IconButton } from '../../shared/ui/primitives.tsx';
import { Bar, Push, Tab, TabList } from '../../shared/ui/layout.tsx';
import { FailureState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { rowFromItem } from '../../entities/file/present.ts';
import type { Item } from '../../entities/file/api-model.ts';
import type { FileRow } from '../../entities/file/model.ts';
import { useUploadStore } from '../../entities/upload/store.ts';
import { useUploadTarget } from '../../entities/upload/use-upload-target.ts';
import { isActive } from '../../entities/upload/model.ts';
import { useSearchParam, useWriteSearchParams } from '../../shared/url-state.ts';
import { GroupedFileList } from './list/grouped-file-list.tsx';
import type { DensityName, GroupSpec } from '../../shared/list/geometry.ts';
import { useListViewStore } from './list-view-store.ts';
import { useFileDetail, useFileVersions, useLibraryItems } from './api.ts';
import { useLibrary } from './picker-api.ts';
import { LibraryPicker } from './picker.tsx';
import { PeekPanel } from './peek/peek-panel.tsx';
import './library.css';

/* The file browser, reading `GET /api/v1/libraries/{id}/items`.
 *
 * ## The picker exists now
 *
 * This file used to open with a note explaining that no endpoint enumerated
 * libraries, so the id had to come from the URL and the screen drew the unbuilt
 * treatment without one. `PR #71` added `GET /workspaces`,
 * `GET /workspaces/{id}/libraries` and `GET /libraries/{id}`, so that note is
 * no longer true and the treatment is withdrawn — a `Later` chip left on a
 * surface that has been built erodes the marker exactly as fast as a denial
 * left on one that has not (`ENC-673`).
 *
 * The library id is still URL state, which is where `docs/17 §5` puts it. What
 * changed is that a viewer with no id in the URL now gets a **picker** rather
 * than an explanation.
 */

/** Folders above files. The only grouping the listing payload can support. */
function groupItems(items: readonly Item[]): {
  readonly groups: readonly GroupSpec[];
  readonly ordered: readonly Item[];
} {
  const folders = items.filter((item) => item.type === 'FOLDER');
  const files = items.filter((item) => item.type === 'FILE');

  const groups: GroupSpec[] = [];
  if (folders.length > 0) groups.push({ id: 'folders', name: 'FOLDER', count: folders.length });
  if (files.length > 0) groups.push({ id: 'files', name: 'FILE', count: files.length });

  return { groups, ordered: [...folders, ...files] };
}

export default function LibraryScreen() {
  const t = useT();
  const formatters = useFormatters();
  /* Library, folder and the peeked file are all **URL state** (`docs/17 §4`):
   * a view a user cannot send to a colleague is a worse product, and peek in
   * particular has to be a query parameter rather than a route so that opening
   * it does not unmount the list. */
  const write = useWriteSearchParams();
  const libraryId = useSearchParam('library');
  const folderIdRaw = useSearchParam('folder');
  const peekIdRaw = useSearchParam('peek');
  const folderId = folderIdRaw.length > 0 ? folderIdRaw : undefined;
  const density: DensityName = useSearchParam('density') === 'compact' ? 'compact' : 'default';
  const peekId = peekIdRaw.length > 0 ? peekIdRaw : undefined;

  const setFolderId = useCallback(
    (id: string | undefined) => write({ folder: id ?? null, peek: null }),
    [write],
  );
  const setPeekId = useCallback((id: string | undefined) => write({ peek: id ?? null }), [write]);
  const setLibraryId = useCallback(
    (id: string) => write({ library: id, folder: null, peek: null }),
    [write],
  );

  const collapsed = useListViewStore((state) => state.collapsed);
  const selected = useListViewStore((state) => state.selected);
  const toggleGroup = useListViewStore((state) => state.toggleGroup);
  const toggleSelected = useListViewStore((state) => state.toggleSelected);

  const hasLibrary = libraryId.length > 0;
  const library = useLibrary(hasLibrary ? libraryId : undefined);
  const items = useLibraryItems(hasLibrary ? libraryId : undefined, folderId);
  const peek = useFileDetail(peekId);
  /* The open peek tab is URL state, so a peek can be shared at the tab the
   * recipient needs (`docs/17 §4`). It was component state, which made
   * "look at the versions of this file" a sentence rather than a link. */
  const peekTabRaw = useSearchParam('tab');
  const peekTab = peekTabRaw.length > 0 ? peekTabRaw : 'details';
  const setPeekTab = useCallback((tab: string) => write({ tab }), [write]);
  /* The Versions tab, and only it.
   *
   * The Preview tab used to need this query too, because `isReadable` lived
   * only on `GET /files/{id}/versions` (`ENC-825`). `GET /files/{id}` carries it
   * on `currentVersion` now, so the preview branch reads the detail it already
   * has and this is one request per peek that no longer happens (`ENC-848`). */
  const versions = useFileVersions(peekId, peekTab === 'versions');

  /* Upload rows for *this* container, drawn in the list as the prototype draws
   * them. The queue itself lives in `entities/upload` because two features read
   * it and a feature may not import a feature (`docs/17 §2`). */
  const uploads = useUploadStore((state) => state.rows);
  const localUploads = useMemo(
    () =>
      uploads.filter(
        (row) =>
          row.libraryId === libraryId &&
          (row.parentId ?? undefined) === folderId &&
          isActive(row.phase),
      ),
    [uploads, libraryId, folderId],
  );

  /* **The server decides.** Upload is offered from the library's own
   * `capabilities.create` and from nothing else — not from `isAdmin`, not from
   * the viewer's role, not from whether the list happens to be non-empty
   * (`docs/17 §1`). While the library metadata is still loading the control is
   * *busy* rather than denied: not knowing yet is not a refusal. */
  const canCreate = library.data?.capabilities.create === true;
  const target = useUploadTarget(hasLibrary ? libraryId : undefined, folderId, canCreate);

  const { groups, ordered } = useMemo(
    () => groupItems(items.data?.items ?? []),
    [items.data?.items],
  );

  const rows = useMemo(() => ordered.map(rowFromItem), [ordered]);

  const namedGroups = useMemo(
    () =>
      groups.map((group) => ({
        ...group,
        name: t(group.name === 'FOLDER' ? 'library.group.folders' : 'library.group.files'),
      })),
    [groups, t],
  );

  const closePeek = useCallback(() => setPeekId(undefined), [setPeekId]);

  /* ------------------------------------------------- what the keyboard does */

  /**
   * `Enter` on a row.
   *
   * A folder opens — it is a real navigation and the listing endpoint takes a
   * `parentId`. **A file has no open surface in M5**, and `docs/09 §6` does not
   * say what "Open" means for one in a product that has no editor and no
   * full-page preview route. It is not silent by accident: §6 itself notes that
   * "`Space` opens the peek, which *is* the preview surface", so the nearest
   * true reading of Open-a-file today is the peek at its Preview tab, which is
   * a built endpoint (`GET /files/{id}/preview`) and a built surface.
   *
   * That reading is recorded rather than assumed — `ENC-897`. What is *not*
   * done here is inventing a second destination and calling the binding
   * finished: `Enter` and `Space` land on the same panel and differ only in
   * which tab it opens, which is honest about the product having one preview
   * surface rather than two.
   */
  const openRow = useCallback(
    (row: FileRow) => {
      if (row.isFolder) setFolderId(row.id);
      else write({ peek: row.id, tab: 'preview' });
    },
    [setFolderId, write],
  );

  const peekRow = useCallback((row: FileRow) => setPeekId(row.id), [setPeekId]);

  /** Replace the whole selection — `↑ ↓`, `Shift`-extend and `⌘A`. */
  const select = useListViewStore((state) => state.select);

  const peekIndex = peekId === undefined ? -1 : ordered.findIndex((row) => row.id === peekId);
  const navigation =
    peekIndex < 0
      ? undefined
      : {
          hasPrevious: peekIndex > 0,
          hasNext: peekIndex < ordered.length - 1,
          onPrevious: () => {
            const target_ = ordered[peekIndex - 1];
            if (target_ !== undefined) setPeekId(target_.id);
          },
          onNext: () => {
            const target_ = ordered[peekIndex + 1];
            if (target_ !== undefined) setPeekId(target_.id);
          },
        };

  /* ------------------------------------------------------------ the picker */
  if (!hasLibrary) {
    return (
      <main className="library" data-screen="library" data-state="picker">
        <Bar className="library-location">
          <nav className="library-crumbs" aria-label={t('library.breadcrumb')}>
            <ol>
              <li>
                <span className="library-crumb" aria-current="page">
                  {t('library.title')}
                </span>
              </li>
            </ol>
          </nav>
        </Bar>
        <LibraryPicker onPick={setLibraryId} />
      </main>
    );
  }

  const peekOpen = peekId !== undefined && peekId.length > 0;

  return (
    <main className="library" data-screen="library">
      {/* --------------------------------------------------- the location bar */}
      <Bar className="library-location">
        <nav className="library-crumbs" aria-label={t('library.breadcrumb')}>
          <ol>
            <li>
              {/* Back to the picker. It is a real destination now. */}
              <button type="button" className="library-crumb" onClick={() => write({ library: null, folder: null, peek: null })}>
                {t('library.title')}
              </button>
            </li>
            <li>
              {/* The library's **name**, from `GET /libraries/{id}`.
               *
               * This crumb used to read the generic word "Files" because the
               * listing endpoint returns items and never the container's own
               * metadata, and an id dressed up as a title was rightly refused.
               * There is a route for it now. While it loads the crumb shows
               * nothing rather than a placeholder that would be replaced by a
               * different string a moment later. */}
              <span className="library-crumb" aria-current={folderId === undefined ? 'page' : undefined}>
                <bdi dir="auto">{library.data?.name ?? ''}</bdi>
              </span>
            </li>
            {folderId !== undefined && (
              <li>
                <button
                  type="button"
                  className="library-crumb"
                  aria-current="page"
                  onClick={() => setFolderId(undefined)}
                >
                  {t('library.folder')}
                </button>
              </li>
            )}
          </ol>
        </nav>

        {/* Everything after here goes to the trailing edge. One element instead
          * of a `margin-inline-start: auto` on whichever child happens to be
          * first in the trailing group — which is the detail that got
          * mis-stated twice across this tree. */}
        <Push />
        <span className="library-location-trailing">
          {/* `aria-pressed` is the accessible truth and `.ui-iconbtn` styles the
            * pressed appearance from that same attribute, so what the toggle
            * looks like and what it announces cannot disagree. This screen had
            * grown a second 26-line icon button for want of that one rule. */}
          <IconButton
            name="side"
            label="library.toggleDetails"
            pressed={peekOpen}
            onClick={() => setPeekId(peekOpen ? undefined : (ordered[0]?.id ?? undefined))}
          />
        </span>
      </Bar>

      {/* ------------------------------------------------------- the view bar */}
      <Bar size="sm" className="library-viewbar">
        <TabList label="library.views">
          <Tab
            label="library.view.all"
            selected
            {...(items.data === undefined
              ? {}
              : { count: formatters.count(items.data.items.length) })}
          />
        </TabList>

        <Push />
        <span className="library-viewbar-trailing">
          {/* Filter and Display stay unbuilt, and honestly so: no endpoint
           * filters a listing and none stores a display preference. Neither is
           * *denied* — the policy chain has refused nobody. */}
          {/* 26px and transparent — `specs/library.md §2.2` reserves the 24px
            * form for `Share`, `New` and `Open preview`, which sit inside
            * another control's row. These three do not. */}
          <Button
            label="library.filter"
            icon="filter"
            variant="ghost"
            state={{ kind: 'unbuilt', note: 'library.filter.unbuilt' }}
          />
          <Button
            label="library.display"
            icon="sliders"
            variant="ghost"
            state={{ kind: 'unbuilt', note: 'library.display.unbuilt' }}
          />

          {/* **Upload is real.** Three states, and they are three different
           * things (`docs/17 §6`):
           *
           *   * `busy`    — the library's capabilities have not arrived. Not
           *                 knowing is not a refusal.
           *   * `denied`  — `capabilities.create` is `false`. Shown, focusable,
           *                 not hidden (`docs/09 §5`). It carries **no reason**,
           *                 because `capabilities` does not yet supply one
           *                 (`ENC-674`) and a client-invented explanation of a
           *                 policy decision is the client re-deriving it.
           *   * `ready`   — opens the file picker.
           */}
          <Button
            label="library.upload"
            icon="up"
            variant="ghost"
            onClick={target.pickFiles}
            state={
              library.isPending
                ? { kind: 'busy' }
                : canCreate
                  ? { kind: 'ready' }
                  : { kind: 'denied', reason: t('library.upload.denied') }
            }
          />
          <Button
            label="library.new"
            icon="plus"
            size="sm"
            variant="primary"
            state={{ kind: 'unbuilt', note: 'library.new.unbuilt' }}
          />
        </span>
      </Bar>

      {/* ----------------------------------------------------------- the body */}
      <div
        className="library-body"
        data-peek={peekOpen ? 'open' : 'closed'}
        {...target.dropHandlers}
      >
        {/* The hidden input the Upload button clicks. `multiple`, because
         * `docs/09 §8` describes a queue rather than one file at a time. */}
        <input
          ref={target.inputRef}
          type="file"
          multiple
          className="ui-sr-only"
          tabIndex={-1}
          aria-hidden="true"
          onChange={target.onInputChange}
        />

        {target.isDragging && (
          <div className="upl-dropzone" aria-hidden="true">
            {t('upload.dropHere')}
          </div>
        )}

        <div className="library-list">
          {items.isError ? (
            <div className="library-peek-body">
              <FailureState failure={failureOf(items.error)} onRetry={() => void items.refetch()} />
            </div>
          ) : (
            <GroupedFileList
              groups={namedGroups}
              rows={rows}
              uploads={localUploads}
              collapsed={collapsed}
              onToggleGroup={toggleGroup}
              selected={selected}
              onToggleSelect={toggleSelected}
              onSelect={select}
              onOpen={openRow}
              onPeek={peekRow}
              density={density}
              status={items.isPending ? 'loading' : 'ready'}
              filtersActive={false}
              onUpload={canCreate ? target.pickFiles : undefined}
            />
          )}
        </div>

        {peekOpen && (
          <PeekPanel
            fileId={peekId}
            detail={peek.data}
            versions={versions.data}
            isLoading={peek.isPending}
            error={peek.error}
            onClose={closePeek}
            onRetry={() => void peek.refetch()}
            activeTab={peekTab}
            onTabChange={setPeekTab}
            navigation={navigation}
          />
        )}
      </div>
    </main>
  );
}
