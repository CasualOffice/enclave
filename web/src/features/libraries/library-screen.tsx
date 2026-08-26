import { useCallback, useMemo } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Button } from '../../shared/ui/primitives.tsx';
import { FailureState, UnbuiltState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { rowFromItem } from '../../entities/file/present.ts';
import type { Item } from '../../entities/file/api-model.ts';
import { useSearchParam, useWriteSearchParams } from '../../shared/url-state.ts';
import { GroupedFileList } from './list/grouped-file-list.tsx';
import type { DensityName, GroupSpec } from './list/geometry.ts';
import { useListViewStore } from './list-view-store.ts';
import { useFileDetail, useLibraryItems } from './api.ts';
import { PeekPanel } from './peek/peek-panel.tsx';
import './library.css';

/* The file browser, reading `GET /api/v1/libraries/{id}/items`.
 *
 * ## The picker that cannot exist yet
 *
 * There is no `GET /api/v1/libraries`. The API registers `/libraries/{id}/items`
 * and nothing that enumerates libraries, workspaces or sites — so a client has
 * no way to discover which library to open, and the sidebar cannot list them.
 *
 * The library id therefore comes from the URL, which is where `docs/17 §5` puts
 * it anyway (`/w/:workspaceId/l/:libraryId`). With no id in the URL the screen
 * renders the **unbuilt** treatment and says why. It does not hard-code an id,
 * and it does not show an empty list — an empty list would be a lie about the
 * user's access, and it is exactly the lie `docs/09 §11` separates the empty
 * states to prevent.
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
  /* Library, folder and the peeked file are all **URL state** (`docs/17 §4`):
   * a view a user cannot send to a colleague is a worse product, and peek in
   * particular has to be a query parameter rather than a route so that opening
   * it does not unmount the list. */
  const write = useWriteSearchParams();
  const libraryId = useSearchParam('library');
  const folderIdRaw = useSearchParam('folder');
  const peekIdRaw = useSearchParam('peek');
  const folderId = folderIdRaw.length > 0 ? folderIdRaw : undefined;
  /* Density is a display preference and belongs in the URL rather than in a
   * store, for the same reason the filters do: a colleague opening the link
   * should see the view that was described to them (`docs/17 §4`). */
  const density: DensityName = useSearchParam('density') === 'compact' ? 'compact' : 'default';
  const peekId = peekIdRaw.length > 0 ? peekIdRaw : undefined;

  const setFolderId = useCallback(
    (id: string | undefined) => write({ folder: id ?? null, peek: null }),
    [write],
  );
  const setPeekId = useCallback((id: string | undefined) => write({ peek: id ?? null }), [write]);

  const collapsed = useListViewStore((state) => state.collapsed);
  const selected = useListViewStore((state) => state.selected);
  const toggleGroup = useListViewStore((state) => state.toggleGroup);
  const toggleSelected = useListViewStore((state) => state.toggleSelected);

  const items = useLibraryItems(libraryId, folderId);
  const peek = useFileDetail(peekId);

  const { groups, ordered } = useMemo(
    () => groupItems(items.data?.items ?? []),
    [items.data?.items],
  );

  const rows = useMemo(() => ordered.map(rowFromItem), [ordered]);

  /* Group names come from the catalog rather than from the payload: `FOLDER`
   * and `FILE` are enum values on the wire, not words to show a person. */
  const namedGroups = useMemo(
    () =>
      groups.map((group) => ({
        ...group,
        name: t(group.name === 'FOLDER' ? 'library.group.folders' : 'library.group.files'),
      })),
    [groups, t],
  );

  const closePeek = useCallback(() => setPeekId(undefined), [setPeekId]);

  if (libraryId.length === 0) {
    return (
      <main className="library">
        <div className="library-location">
          <nav className="library-crumbs" aria-label={t('library.breadcrumb')}>
            <ol>
              <li>
                <span className="library-crumb" aria-current="page">
                  {t('library.title')}
                </span>
              </li>
            </ol>
          </nav>
        </div>
        <div className="library-peek-body">
          <UnbuiltState heading="library.noPicker.title" note="library.noPicker.body" />
        </div>
      </main>
    );
  }

  const peekOpen = peekId !== undefined && peekId.length > 0;

  return (
    <main className="library">
      {/* --------------------------------------------------- the location bar */}
      <div className="library-location">
        <nav className="library-crumbs" aria-label={t('library.breadcrumb')}>
          <ol>
            <li>
              {/* The library's *name* is not on the wire either — `browse`
               * returns items and a page, never the container's own metadata —
               * so the crumb is the generic label rather than an id dressed up
               * as a title. */}
              <button
                type="button"
                className="library-crumb"
                aria-current={folderId === undefined ? 'page' : undefined}
                onClick={() => setFolderId(undefined)}
              >
                {t('library.title')}
              </button>
            </li>
            {folderId !== undefined && (
              <li>
                <span className="library-crumb" aria-current="page">
                  {t('library.folder')}
                </span>
              </li>
            )}
          </ol>
        </nav>

        <span className="library-location-trailing">
          <button
            type="button"
            className="library-iconbtn"
            aria-pressed={peekOpen}
            aria-label={t('library.toggleDetails')}
            onClick={() => setPeekId(peekOpen ? undefined : (ordered[0]?.id ?? undefined))}
          >
            <Icon name="side" />
          </button>
        </span>
      </div>

      {/* ------------------------------------------------------- the view bar */}
      <div className="library-viewbar">
        {/* Saved views come from the server in the design, and there is no
         * endpoint for them. One view is shown — the one that exists — rather
         * than a hard-coded strip of tabs that all show the same rows. */}
        <div className="library-views" role="tablist" aria-label={t('library.views')}>
          <button type="button" role="tab" aria-selected="true" className="library-view">
            {t('library.view.all')}
            {items.data !== undefined && (
              <span className="library-view-count">{items.data.items.length}</span>
            )}
          </button>
        </div>

        <span className="library-viewbar-trailing">
          {/* Upload is not hidden and not denied — it is **unbuilt**, and the
           * distinction is the point (`docs/17 §6`). `POST /api/v1/uploads`
           * exists but `crates/api/src/main.rs` binds `Delivery::unconfigured()`
           * unconditionally, so it answers 503 in every build of this binary.
           * That is the product not having the feature, not the policy chain
           * refusing this user, and it must not wear the denial treatment. */}
          <Button
            label="library.upload"
            icon="up"
            size="sm"
            state={{ kind: 'unbuilt', note: 'library.upload.unbuilt' }}
          />
        </span>
      </div>

      {/* ----------------------------------------------------------- the body */}
      <div className="library-body" data-peek={peekOpen ? 'open' : 'closed'}>
        <div className="library-list">
          {items.isError ? (
            <div className="library-peek-body">
              <FailureState failure={failureOf(items.error)} onRetry={() => void items.refetch()} />
            </div>
          ) : (
            <GroupedFileList
              groups={namedGroups}
              rows={rows}
              collapsed={collapsed}
              onToggleGroup={toggleGroup}
              selected={selected}
              onToggleSelect={toggleSelected}
              density={density}
              status={items.isPending ? 'loading' : 'ready'}
              filtersActive={false}
              onUpload={undefined}
            />
          )}
        </div>

        {peekOpen && (
          <PeekPanel
            fileId={peekId}
            detail={peek.data}
            isLoading={peek.isPending}
            error={peek.error}
            onClose={closePeek}
            onRetry={() => void peek.refetch()}
          />
        )}
      </div>
    </main>
  );
}
