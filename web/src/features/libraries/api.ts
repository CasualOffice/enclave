import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { request } from '../../shared/api/client.ts';
import { FileDetail, ItemPage } from '../../entities/file/api-model.ts';

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
  signal?: AbortSignal,
): Promise<ItemPage> {
  const params = new URLSearchParams();
  if (parentId !== undefined) params.set('parentId', parentId);
  const query = params.toString();
  return request(
    `/libraries/${encodeURIComponent(libraryId)}/items${query.length > 0 ? `?${query}` : ''}`,
    ItemPage,
    signal === undefined ? {} : { signal },
  );
}

export function useLibraryItems(
  libraryId: string | undefined,
  parentId: string | undefined,
): UseQueryResult<ItemPage> {
  return useQuery({
    /* `parentId` is part of the key, so opening a folder is a different query
     * rather than a refetch that briefly shows the parent's rows. */
    queryKey: ['library', libraryId, parentId ?? null],
    queryFn: ({ signal }) => browse(libraryId ?? '', parentId, signal),
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
