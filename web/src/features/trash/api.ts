import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import { z } from 'zod';
import { request } from '../../shared/api/client.ts';
import { FileCapabilities } from '../../entities/file/api-model.ts';

/* `GET /api/v1/trash` and the restore that acts on it (`docs/05-API.md §19.2`).
 *
 * The two belong in one file because the second cannot be issued without the
 * first: `POST /files/{id}/restore` requires `If-Match`, and the revision it
 * takes is the one this listing carries. A screen that fetched the row and then
 * re-read the revision from somewhere else would be reintroducing the race the
 * precondition exists to close.
 */

/** Who deleted it. `displayName` is absent for a principal with no `users` row. */
const Deleter = z.strictObject({
  id: z.string(),
  displayName: z.string().nullable(),
});

/**
 * One row of the bin.
 *
 * `strictObject`, for `entities/file/api-model.ts`'s reason: a field the server
 * stops sending must be a parse failure and not an `undefined` that renders as
 * an absence nobody decided on. `ENC-929` is what a loose schema cost here once
 * already.
 */
const TrashItem = z.strictObject({
  fileId: z.string(),
  name: z.string(),
  /* `type`, not `nodeType`. The rest of the file surface spells it this way —
   * `GET /libraries/{id}/items` returns `"type": "FOLDER"` — and a listing that
   * invented a second name for the same field would make a client hold two
   * decoders for one concept. This schema said `nodeType` for one afternoon and
   * the strict parse rejected every row, so the bin drew its non-retryable
   * failure against a healthy server: `ENC-929`'s exact shape, caught here by
   * `tests/e2e/trash.spec.ts` on its first run instead of by a person a week
   * later. `docs/05 §19.2` is corrected to match. */
  type: z.enum(['FILE', 'FOLDER']),
  mimeType: z.string(),
  libraryId: z.string(),
  parentFolderId: z.string().nullable(),
  deletedAt: z.string(),
  /** Absent when no retention window was recorded; the row then shows no countdown. */
  purgeAfter: z.string().nullable(),
  deletedBy: Deleter,
  /** What `If-Match` on the restore must carry. The whole reason it is on the wire. */
  revision: z.number(),
  capabilities: FileCapabilities,
});

export const TrashPage = z.strictObject({
  items: z.array(TrashItem),
  /**
   * How many rows the policy chain removed.
   *
   * Never *which* — rule 7, and the disclosure would be sharper here than
   * anywhere else, because the caller once had access to what is hidden. The
   * screen uses it only to tell "you have deleted nothing" from "what you
   * deleted is no longer yours to restore".
   */
  filteredCount: z.number(),
});

export type TrashPage = z.infer<typeof TrashPage>;
export type TrashItem = z.infer<typeof TrashItem>;

export function useTrash(): UseQueryResult<TrashPage> {
  return useQuery({
    queryKey: ['trash'],
    queryFn: ({ signal }) => request('/trash', TrashPage, { signal }),
    /* Every row carries `capabilities`, which is a property of this user, this
     * action and this moment — never served stale (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}

/**
 * `POST /files/{id}/restore`, with the revision this listing supplied.
 *
 * **Not optimistic**, and that is `docs/17` Q25's rule rather than caution: a
 * restore puts a document back where other people can see it, so it touches
 * access. A row that animated away and then failed would have told somebody
 * their file was back when it was not.
 *
 * On success the bin is invalidated rather than edited in place. The server
 * restores a whole subtree — every node sharing the row's `deleted_at` — so the
 * set that leaves the bin is the server's to compute and a client that spliced
 * out one row would be guessing at it.
 */
export function useRestore(): {
  restore: (item: { fileId: string; revision: number }) => void;
  pendingId: string | undefined;
  failedId: string | undefined;
} {
  const client = useQueryClient();
  const mutation = useMutation({
    mutationFn: (item: { fileId: string; revision: number }) =>
      request(`/files/${encodeURIComponent(item.fileId)}/restore`, z.unknown(), {
        method: 'POST',
        ifMatch: item.revision,
      }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['trash'] });
      /* The file is back in its library and in nothing else's cache. */
      void client.invalidateQueries({ queryKey: ['library'] });
    },
  });

  return {
    restore: (item) => mutation.mutate(item),
    pendingId: mutation.isPending ? mutation.variables?.fileId : undefined,
    failedId: mutation.isError ? mutation.variables?.fileId : undefined,
  };
}
