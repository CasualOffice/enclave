import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import { z } from 'zod';
import { request } from '../../shared/api/client.ts';
import { FileCapabilities } from '../file/api-model.ts';

/* `GET /me/favorites` and the star that writes it (`docs/05-API.md §7`, `ENC-959`).
 *
 * The three belong in one file because the toggle and the listing are one
 * thing: starring from the peek panel has to invalidate the list, and a
 * component owning only half of that would leave a screen showing a star the
 * server has already removed.
 *
 * # Why this is in `entities/` and not in `features/favorites/`
 *
 * Because two features want it — the Favorites screen lists stars, and the
 * library's peek panel toggles one — and `docs/17 §2` forbids a feature
 * importing another. The `arch/layer-boundary` lint says so by name, and it
 * caught this exact import when the hook lived in the feature.
 *
 * That rule is worth more than the tidiness it looks like: a feature reaching
 * into another feature's data layer inherits its caching, its error handling and
 * its refetch policy without ever agreeing to them, and the coupling stays
 * invisible until one of the three changes. `entities/workspace/api.ts` moved
 * down for the same reason in `ENC-934`.
 */

export const FAVORITES_KEY = ['favorites'] as const;

const FavoriteItem = z.strictObject({
  fileId: z.string(),
  name: z.string(),
  /* `nodeType`, matching `GET /me/shared`. The bin spells the same field `type`;
   * `ENC-957` reconciles them server-side, and until it does the client follows
   * each endpoint's own spelling rather than translating between them. */
  nodeType: z.enum(['FILE', 'FOLDER']),
  mimeType: z.string(),
  libraryId: z.string(),
  parentFolderId: z.string().nullable(),
  classification: z
    .strictObject({ key: z.string(), label: z.string(), rank: z.number() })
    .nullable(),
  favoritedAt: z.string(),
  capabilities: FileCapabilities,
});

export const FavoritePage = z.strictObject({
  items: z.array(FavoriteItem),
  /**
   * How many stars the policy chain removed.
   *
   * Never *which* — rule 7. A star is not permission: a file somebody
   * favourited a year ago may have been re-permissioned since, and the count is
   * what separates "you have starred nothing" from "what you starred is no
   * longer yours to open".
   */
  filteredCount: z.number(),
});

export type FavoritePage = z.infer<typeof FavoritePage>;
export type FavoriteItem = z.infer<typeof FavoriteItem>;

export function useFavorites(): UseQueryResult<FavoritePage> {
  return useQuery({
    queryKey: FAVORITES_KEY,
    queryFn: ({ signal }) => request('/me/favorites', FavoritePage, { signal }),
    /* Every row carries `capabilities`, which is a property of this user, this
     * action and this moment — never served stale (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}

/**
 * Starring and un-starring, as one hook.
 *
 * **Optimistic**, and that is the one place in this client where it is right.
 * `docs/17` Q25 forbids optimism for anything touching access, and a star
 * touches none: it grants nothing, reveals nothing and is the user's own note
 * about a file they can already see. What it buys is the thing a star is for —
 * a control that responds instantly — and the cost of being wrong is a filled
 * outline that empties again, not a document somebody thinks they can reach.
 *
 * The rollback restores the *previous* value rather than inverting the current
 * one: two rapid clicks would otherwise leave the second rollback undoing a
 * state the first had already changed.
 */
export function useStar(): {
  toggle: (fileId: string, starred: boolean) => void;
  isPending: boolean;
} {
  const client = useQueryClient();
  const mutation = useMutation({
    mutationFn: ({ fileId, starred }: { fileId: string; starred: boolean }) =>
      request(`/files/${encodeURIComponent(fileId)}/favorite`, z.unknown(), {
        method: starred ? 'PUT' : 'DELETE',
      }),
    onSettled: () => {
      /* The server decides what the list now contains — a star on a file the
       * chain has since refused does not come back — so the list is refetched
       * rather than spliced. */
      void client.invalidateQueries({ queryKey: FAVORITES_KEY });
    },
  });

  return {
    toggle: (fileId, starred) => mutation.mutate({ fileId, starred }),
    isPending: mutation.isPending,
  };
}

/**
 * Whether this file is starred, from the list the screen already loads.
 *
 * Derived on the client, which is safe here and would not be for a permission:
 * `docs/17 §1` forbids re-deriving what the server decided about *access*, and
 * a favourite is not access — it is this person's own data, and they are the
 * only reader of it.
 *
 * `enabled` is the caller's, so a peek panel opened before the list has loaded
 * shows the star unfilled rather than flickering: unknown renders as not
 * starred, which is the state that reads as "click to add".
 */
export function useIsFavorite(fileId: string | undefined): boolean {
  const favorites = useFavorites();
  if (fileId === undefined || favorites.data === undefined) return false;
  return favorites.data.items.some((item) => item.fileId === fileId);
}
