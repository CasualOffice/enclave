import { useCallback, useMemo } from 'react';
import { useKeyBindings } from '../../shared/keyboard/use-key-bindings.ts';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Button, IconButton } from '../../shared/ui/primitives.tsx';
import { Bar, Push, Tab, TabList } from '../../shared/ui/layout.tsx';
import { FailureState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { rowFromItem } from '../../entities/file/present.ts';
import { reasonMessage } from '../../entities/capability/denial.ts';
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
  /* `⌘\` pins the panel (`docs/09 §6`, `§7`). URL state like everything else
   * on this screen: a pinned panel is part of the view a link describes. */
  const pinned = useSearchParam('pin') === '1';

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
  /* …and the server explains it, too (`ENC-674`). The reason is looked up by the
   * same key the boolean was read from, so the sentence and the refusal cannot
   * come apart. `reasonMessage` handles the absent and the unrecognised code
   * identically and neither of them guesses — see `entities/capability`. */
  const uploadDenial = reasonMessage(library.data?.capabilityReasons?.['create']);
  const target = useUploadTarget(hasLibrary ? libraryId : undefined, folderId, canCreate);

  const { groups, ordered } = useMemo(
    /* Every page, flattened. The window (`shared/list/use-grouped-window.ts`)
     * mounts thirty rows whatever this holds, so growing it is cheap — what
     * changes is how far a reader can scroll before the list stops. */
    () => groupItems(items.data?.pages.flatMap((page) => page.items) ?? []),
    [items.data?.pages],
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
   * That reading is recorded rather than assumed — `ENC-902`. What is *not*
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
  const clearSelection = useListViewStore((state) => state.clearSelection);

  /* ------------------------------------- `I`, `⌘\` and `Esc` (`docs/09 §6`)
   *
   * Registered here rather than in `app/` because all three act on the details
   * panel, and the panel is this screen's URL state. A global handler could
   * only reach it by writing a sentinel into the query string — and
   * `docs/09 §3` promises that query string is a link a user can send to a
   * colleague, not a private protocol between two modules.
   */
  useKeyBindings(
    useMemo(
      () => ({
        /* `I` toggles the panel. With nothing selected it opens on the first
         * row, which is what the toolbar's own toggle already does — a details
         * panel that opens empty when there is something to describe is a
         * surface that has been opened and then wasted. */
        i: (event: KeyboardEvent) => {
          event.preventDefault();
          if (peekIdRaw.length > 0) write({ peek: null, pin: null });
          else write({ peek: ordered[0]?.id ?? null });
        },
        /* `⌘\` pins it open. Pinned means it survives the selection being
         * cleared, which is the empty-but-present state `PeekPanel` already
         * draws — so pinning is a real distinction here rather than a flag with
         * no consequence. */
        'mod+\\': (event: KeyboardEvent) => {
          event.preventDefault();
          write({ pin: pinned ? null : '1', peek: peekIdRaw.length > 0 ? peekIdRaw : (ordered[0]?.id ?? null) });
        },
        /* `Esc` — "Close panel/dialog, clear selection", in `docs/09 §6`'s own
         * order, and the order is the whole meaning. A user with the panel open
         * and three rows selected expects the panel to close; taking the
         * selection instead, out from under a panel that stayed, is the wrong
         * half. One press closes the topmost thing there is; a second reaches
         * the next one down. A *pinned* panel is not closed by `Esc` — that is
         * what pinning it means — so the selection is what clears. */
        Escape: (event: KeyboardEvent) => {
          if (peekIdRaw.length > 0 && !pinned) {
            event.preventDefault();
            write({ peek: null });
            return;
          }
          if (selected.size > 0) {
            event.preventDefault();
            clearSelection();
          }
        },
      }),
      [peekIdRaw, pinned, ordered, selected.size, write, clearSelection],
    ),
  );

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
              : /* What has been *fetched*, not what the library holds. The
                 * server sends no total and counting one would be a scan of
                 * every partition; a number that grew as somebody scrolled and
                 * claimed to be the total would be worse than one that is
                 * honestly a running count (`ENC-973`). */
                {
                  count: formatters.count(
                    items.data.pages.reduce((sum, page) => sum + page.items.length, 0),
                  ),
                })}
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
           *                 not hidden (`docs/09 §5`), and it now carries **the
           *                 server's reason**: `capabilityReasons.create` names
           *                 a code and the catalog phrases it (`ENC-674`,
           *                 `docs/14 §5`). Nothing here composes an explanation
           *                 — a client-invented account of a policy decision is
           *                 the client re-deriving it, which is the whole point
           *                 of reading `capabilities` rather than a role.
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
                  : { kind: 'denied', reason: t(uploadDenial) }
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
              /* Paging (`ENC-973`). `fetchNextPage` is idempotent while a page
               * is in flight and a no-op when `hasNextPage` is false, so the
               * guard is TanStack's rather than a second one kept in step with
               * it here. */
              onEndReached={() => {
                if (items.hasNextPage && !items.isFetchingNextPage) void items.fetchNextPage();
              }}
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
