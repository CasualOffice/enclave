import {
  useInfiniteQuery,
  useQuery,
  type UseInfiniteQueryResult,
  type InfiniteData,
  type UseQueryResult,
} from '@tanstack/react-query';
import { request } from '../../shared/api/client.ts';
import { FileDetail, ItemPage, VersionPage } from '../../entities/file/api-model.ts';

/* The library feature's two reads.
 *
 * ## The endpoint that does not exist
 *
 * There is **no `GET /api/v1/libraries`**. The router registers
 * `/libraries/{id}/items` and nothing that enumerates libraries, workspaces or
 * sites — `crates/libraries` has a `list_by_workspace` repository method that no
 * HTTP handler reaches. So a client cannot discover which libraries a user can
 * see, and the sidebar cannot list them.
 *
 * That is why the library id comes from the URL here (`?library=`), which is
 * where `docs/17 §5` puts it anyway — `/w/:workspaceId/l/:libraryId`. What is
 * missing is not the route but the *picker*, and the screen says so under the
 * unbuilt treatment rather than inventing a list or hard-coding an id.
 */

/** `GET /api/v1/libraries/{id}/items` — the file browser's listing. */
export function browse(
  libraryId: string,
  parentId: string | undefined,
  cursor?: string | undefined,
  signal?: AbortSignal,
): Promise<ItemPage> {
  const params = new URLSearchParams();
  if (parentId !== undefined) params.set('parentId', parentId);
  /* `?cursor=` has been accepted by `content.rs` since the endpoint was written
   * and was sent by nothing for as long as this client has existed (`ENC-973`). */
  if (cursor !== undefined) params.set('cursor', cursor);
  const query = params.toString();
  return request(
    `/libraries/${encodeURIComponent(libraryId)}/items${query.length > 0 ? `?${query}` : ''}`,
    ItemPage,
    signal === undefined ? {} : { signal },
  );
}

/**
 * The listing, paged (`ENC-973`).
 *
 * # What this was, and why it was wrong
 *
 * A plain `useQuery` that asked once and kept the first page. The server has
 * always answered fifty rows with `hasMore: true` and a `nextCursor`, and
 * `entities/file/api-model.ts` has always parsed both — **and nothing in
 * `web/src` read either.** So a library with more than fifty files silently
 * showed fifty, in the server's order, with nothing on screen saying anything
 * was missing. For a product whose purpose is being the place a team's
 * documents live, that ceiling is reached in the second week of real use.
 *
 * It was not a quiet defect either: it made `tests/e2e/sign-in.spec.ts` and
 * `tests/e2e/trash.spec.ts` fail — the second reporting *"the row left the bin
 * but the file is not back in its library"*, which was never a restore defect.
 * The restore worked and the file sat at index 63 of a listing the client asked
 * fifty of. And it capped `ENC-972`: refreshing after an upload does nothing if
 * the new row sorts past the end of the only page fetched.
 *
 * # The key is unchanged, deliberately
 *
 * `['library', libraryId, parentId ?? null]` — the same key `ENC-972`'s
 * `UploadListingRefresh` invalidates. An infinite query invalidates as a whole:
 * every fetched page is refetched in order, so an upload still lands in a list
 * the user has scrolled deep into. Changing the key here would have silently
 * unhooked that fix.
 *
 * `parentId` stays part of it, so opening a folder is a different query rather
 * than a refetch that briefly shows the parent's rows.
 */
export function useLibraryItems(
  libraryId: string | undefined,
  parentId: string | undefined,
): UseInfiniteQueryResult<InfiniteData<ItemPage>> {
  return useInfiniteQuery({
    queryKey: ['library', libraryId, parentId ?? null],
    queryFn: ({ pageParam, signal }) =>
      browse(libraryId ?? '', parentId, pageParam ?? undefined, signal),
    initialPageParam: undefined as string | undefined,
    /* `hasMore` decides, not the presence of a cursor. `content.rs` omits
     * `nextCursor` rather than nulling it, and a page may hold fewer items than
     * `limit` and still have more behind it — the endpoint's own header says so.
     * Reading the cursor alone would stop early on exactly the page the trim
     * shortened. */
    getNextPageParam: (last) =>
      last.page.hasMore ? (last.page.nextCursor ?? undefined) : undefined,
    enabled: libraryId !== undefined && libraryId.length > 0,
    /* Every row carries `capabilities`, which is a property of this user, this
     * action and this moment — never cached beyond its request (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}

/** `GET /api/v1/files/{id}` — what the peek panel reads. */
export function fileDetail(fileId: string, signal?: AbortSignal): Promise<FileDetail> {
  return request(
    `/files/${encodeURIComponent(fileId)}`,
    FileDetail,
    signal === undefined ? {} : { signal },
  );
}

export function useFileDetail(fileId: string | undefined): UseQueryResult<FileDetail> {
  return useQuery({
    queryKey: ['file', fileId],
    queryFn: ({ signal }) => fileDetail(fileId ?? '', signal),
    enabled: fileId !== undefined && fileId.length > 0,
    staleTime: 0,
    retry: false,
  });
}

/**
 * `GET /api/v1/files/{id}/versions` — the peek panel's Versions tab.
 *
 * Each entry carries `isReadable`, which the server computes from
 * `status = 'AVAILABLE' AND av_status = 'CLEAN'` (`CLAUDE.md` rule 9: nothing is
 * `AVAILABLE` before antivirus completes). The client **shows** that answer and
 * never recomputes it from the two fields beside it — the same rule as
 * `capabilities`, and the same reason: two authorities drift.
 *
 * Enabled only when the tab is open. A peek that fetched every tab's data on
 * open would issue four requests to render one.
 */
export function useFileVersions(
  fileId: string | undefined,
  enabled: boolean,
): UseQueryResult<VersionPage> {
  return useQuery({
    queryKey: ['file', fileId, 'versions'],
    queryFn: ({ signal }) =>
      request(`/files/${encodeURIComponent(fileId ?? '')}/versions`, VersionPage, { signal }),
    enabled: enabled && fileId !== undefined && fileId.length > 0,
    staleTime: 0,
    retry: false,
  });
}
