import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { request } from '../../shared/api/client.ts';
import { Library, LibraryPage } from '../../entities/workspace/api-model.ts';

/* The three reads the library picker is built from.
 *
 * All three landed in `PR #71` and all three are verified against the running
 * binary. The comment they replace said "there is no `GET /api/v1/libraries`"
 * and drew the unbuilt treatment; that was true and is not any more.
 *
 * The shape of the picker follows the shape of the API: workspaces are listed
 * first, a workspace's libraries second. There is no flat "every library I can
 * see" endpoint, and this file does not simulate one by fanning out a request
 * per workspace — that would turn one navigation into N+1 requests whose
 * failures could not be reported coherently, and it would invent a listing the
 * policy chain never composed.
 */

/* `useWorkspaces` moved to `entities/workspace/api.ts` when the search screen's
 * workspace filter needed it too: `docs/17 §2` forbids one feature importing
 * another, so the shared piece went down rather than sideways (`ENC-934`).
 * Re-exported here so this module still reads as the picker's three reads. */
export { useWorkspaces } from '../../entities/workspace/api.ts';

/** `GET /api/v1/workspaces/{id}/libraries` — the libraries inside one workspace. */
export function useLibraries(workspaceId: string | undefined): UseQueryResult<LibraryPage> {
  return useQuery({
    queryKey: ['workspace', workspaceId, 'libraries'],
    queryFn: ({ signal }) =>
      request(
        `/workspaces/${encodeURIComponent(workspaceId ?? '')}/libraries`,
        LibraryPage,
        { signal },
      ),
    enabled: workspaceId !== undefined && workspaceId.length > 0,
    staleTime: 0,
    retry: false,
  });
}

/**
 * `GET /api/v1/libraries/{id}` — the open library's own metadata.
 *
 * This is what puts a **name** in the breadcrumb. The listing endpoint returns
 * items and a page and never the container's own metadata, so before this route
 * existed the crumb was the generic word "Files" — an id dressed up as a title
 * was the alternative, and it was rightly refused.
 */
export function useLibrary(libraryId: string | undefined): UseQueryResult<Library> {
  return useQuery({
    queryKey: ['library', libraryId, 'meta'],
    queryFn: ({ signal }) =>
      request(`/libraries/${encodeURIComponent(libraryId ?? '')}`, Library, { signal }),
    enabled: libraryId !== undefined && libraryId.length > 0,
    staleTime: 0,
    retry: false,
  });
}
