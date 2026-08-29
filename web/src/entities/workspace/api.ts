import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { request } from '../../shared/api/client.ts';
import { WorkspacePage } from './api-model.ts';

/**
 * `GET /api/v1/workspaces` — every workspace the viewer may read.
 *
 * It lives here rather than in `features/libraries` because two features want
 * it: the library picker navigates by it, and the search screen's workspace
 * filter offers it as options. `docs/17 §2` forbids one feature importing
 * another, and the architecture lint says so by name — the shared piece moves
 * down to `entities/`, it does not get imported sideways (`ENC-934`).
 *
 * That rule is worth more than the tidiness: a feature that reaches into
 * another feature's data layer inherits its caching, its error handling and its
 * refetch policy without ever agreeing to them, and the coupling is invisible
 * until one of the three changes.
 */
export function useWorkspaces(): UseQueryResult<WorkspacePage> {
  return useQuery({
    queryKey: ['workspaces'],
    queryFn: ({ signal }) => request('/workspaces', WorkspacePage, { signal }),
    /* Each row carries `capabilities`, which is a property of this user, this
     * action and this moment — never served stale (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}
