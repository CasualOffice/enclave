import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { z } from 'zod';
import { request } from '../../shared/api/client.ts';
import { FileCapabilities } from '../../entities/file/api-model.ts';

/* `GET /api/v1/me/shared` (`docs/05-API.md §14`, `ENC-954`).
 *
 * The listing behind *Shared with me*, which carried an unbuilt chip until the
 * endpoint existed. `acl_entries` has had a writer since `ENC-916` and nothing
 * had ever listed what a person was *given*, so a colleague could share a
 * document outside any workspace this user belongs to and the recipient had no
 * way to find it.
 *
 * Read-only, and that is not a gap. A share is somebody else's act; the things
 * this screen's rows can do — open, preview, download — are the file surface's
 * verbs and belong to the file, not to the fact that it was shared. The one
 * action that *would* belong here is declining a share, and `acl_entries` has
 * no endpoint that removes a grant on somebody's own behalf (`ENC-956`).
 */

/**
 * One shared resource.
 *
 * `strictObject` for `entities/file/api-model.ts`'s reason, and `ENC-929` is
 * what a loose schema cost the library screen once already: a field the server
 * stops sending must be a parse failure, never an `undefined` that renders as
 * an absence nobody decided on.
 */
const SharedItem = z.strictObject({
  fileId: z.string(),
  name: z.string(),
  /* `nodeType` here and `type` in the bin, because that is what the two
   * endpoints actually send. Recorded rather than smoothed over: the client
   * follows the server's spelling per endpoint, and inventing a third name to
   * unify them would put a translation layer between this screen and the
   * contract it is written against. `ENC-957` is the row to reconcile them. */
  nodeType: z.enum(['FILE', 'FOLDER']),
  mimeType: z.string(),
  libraryId: z.string(),
  parentFolderId: z.string().nullable(),
  classification: z
    .strictObject({ key: z.string(), label: z.string(), rank: z.number() })
    .nullable(),
  sharedAt: z.string(),
  /** Who shared it, as an opaque id. No directory lookup exists to resolve it yet. */
  sharedBy: z.string(),
  /** The group it arrived through, or `null` for a direct share. */
  viaGroup: z.string().nullable(),
  capabilities: FileCapabilities,
});

export const SharedPage = z.strictObject({
  items: z.array(SharedItem),
  /**
   * How many candidates the policy chain removed.
   *
   * Never *which* — rule 7. The screen uses it only to tell "nobody has shared
   * anything with you" from "what was shared is no longer yours to open", which
   * are different sentences and would otherwise both render as an empty list.
   */
  filteredCount: z.number(),
  /** Whether the read hit its limit, so the set was cut rather than exhausted. */
  hasMore: z.boolean(),
});

export type SharedPage = z.infer<typeof SharedPage>;
export type SharedItem = z.infer<typeof SharedItem>;

export function useShared(): UseQueryResult<SharedPage> {
  return useQuery({
    queryKey: ['shared'],
    queryFn: ({ signal }) => request('/me/shared', SharedPage, { signal }),
    /* Every row carries `capabilities`, which is a property of this user, this
     * action and this moment — never served stale (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}
