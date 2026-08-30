import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { isSettled } from '../../entities/upload/index.ts';
import { useUploadStore } from '../../entities/upload/store.ts';

/* Refresh the listing an upload landed in, once the file is really there
 * (`ENC-972`).
 *
 * # What was broken
 *
 * **The product looked broken at the one moment a user is watching it.** The
 * transfer succeeded, the tray said *Ready*, and the library the file was
 * dropped into did not show it. `useLibraryItems` is keyed `['library',
 * libraryId, parentId]` with `staleTime: 0` — which refetches on remount and on
 * refocus, and never while somebody is sitting on the screen they just uploaded
 * to. So the file was stored, was `AVAILABLE`, and was invisible until a
 * reload. Nothing in `web/src` invalidated that key: `invalidateQueries` had
 * four callers and none of them was upload.
 *
 * # Why this is its own component and not part of the tray
 *
 * The obvious home is `UploadTray` — mounted for the life of the session and
 * already subscribed to these rows. Putting the effect there is what I did
 * first, and it broke ten unit tests immediately: `tests/unit/upload-tray.test.tsx`
 * renders the tray with no `QueryClientProvider`, because until then the tray
 * needed none.
 *
 * That is `ENC-968` repeating — a presentational component quietly acquiring a
 * context dependency it never declared — and the fix is not to wrap the tests.
 * It is to keep the tray free of query context and give the refresh its own
 * mount. This renders nothing; it exists to hold one effect.
 *
 * # Why the store cannot do it
 *
 * `entities/upload/store.ts` is deliberately outside React: a transfer has to
 * survive navigation, which is the whole reason the queue is a module-level
 * store. It has no `QueryClient`, and importing the one from `main.tsx` would
 * give the store a dependency on the application's bootstrap.
 *
 * # Why `isSettled` and not `phase === 'ready'`
 *
 * A quarantined upload changes the listing too — the row exists and is not
 * readable — and so does a version published before scanning, which rests at
 * `scanning` with a note. Asking the server what the container now holds is
 * right in all three cases; deciding here which of them counts would be this
 * client computing a listing it does not own.
 */
export function UploadListingRefresh() {
  const rows = useUploadStore((state) => state.rows);
  const client = useQueryClient();

  /* A string, not an array: the effect must depend on *which* containers hold
   * settled rows, and a fresh array on every render would re-run it on every
   * render. `::` separates, which no UUID contains. */
  const settled = rows
    .filter((row) => isSettled(row.phase))
    .map((row) => `${row.libraryId}::${row.parentId ?? ''}`)
    .join('|');

  useEffect(() => {
    if (settled === '') return;
    for (const container of new Set(settled.split('|'))) {
      const [libraryId, parentId] = container.split('::');
      void client.invalidateQueries({
        queryKey: ['library', libraryId, parentId === '' ? null : parentId],
      });
    }
  }, [settled, client]);

  return null;
}
