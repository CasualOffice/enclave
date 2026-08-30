import { useState } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Card, Push, Truncate } from '../../shared/ui/layout.tsx';
import { Button } from '../../shared/ui/primitives.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import {
  EmptyState,
  FailureState,
  FilteredEmptyState,
} from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { splitName } from '../../entities/file/present.ts';
import { useRestore, useTrash, type TrashItem } from './api.ts';
import './trash.css';

/**
 * What this account deleted, and the one action that undoes it.
 *
 * `ENC-939`. `ENC-807` shipped `DELETE /files/{id}` and `POST
 * /files/{id}/restore` and no way to find a deleted file again, so the nav
 * carried `Trash` as `unbuilt` — a screen that could not be written, because
 * the endpoint it needed did not exist until `ENC-938`. This is the first of the
 * seven `Later` entries to become a real one.
 *
 * # Every row is an offer to act, so every row was authorized to act
 *
 * `GET /trash` decides on `file.restore` rather than `file.metadata_read`
 * (`docs/05-API.md §19.2`), which is why this screen renders a Restore button on
 * every row without asking a second question. A row that arrived here is one the
 * chain already said this caller may put back; a list authorized on *reading*
 * would have made every button a coin toss the server resolves.
 *
 * # The revision comes from the row and from nowhere else
 *
 * `restore` requires `If-Match`, and the value is `item.revision` — the one the
 * listing carried. Re-reading it from a second request would reintroduce exactly
 * the race the precondition exists to close: the file could be restored, moved
 * and re-deleted between the two reads, and the write would then carry a
 * revision that described a different state of the world.
 */
export default function Screen() {
  const t = useT();
  const trash = useTrash();
  const { restore, pendingId, failedId } = useRestore();

  return (
    <div className="trash">
      <div className="trash-page">
        <header>
          <h1 className="trash-title">{t('trash.title')}</h1>
          <p className="trash-subline">{t('trash.subline')}</p>
        </header>
        <Body
          data={trash.data}
          isPending={trash.isPending}
          isError={trash.isError}
          error={trash.error}
          onRetry={() => void trash.refetch()}
          onRestore={restore}
          pendingId={pendingId}
          failedId={failedId}
        />
      </div>
    </div>
  );
}

function Body({
  data,
  isPending,
  isError,
  error,
  onRetry,
  onRestore,
  pendingId,
  failedId,
}: {
  data: { items: readonly TrashItem[]; filteredCount: number } | undefined;
  isPending: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
  onRestore: (item: { fileId: string; revision: number }) => void;
  pendingId: string | undefined;
  failedId: string | undefined;
}) {
  /* A denial is not a failure and gets no retry; a fault gets one and a request
   * ID (`docs/17 §7`). `FailureState` owns that branch. */
  if (isError) return <FailureState failure={failureOf(error)} onRetry={onRetry} fill />;

  /* Pending is not empty. Drawing "Nothing deleted" while the request is in
   * flight tells somebody their files are gone. */
  if (isPending || data === undefined) {
    /* The list's own shape, reserved. A spinner would replace the layout with a
     * different one and make the arrival a jump rather than a fill. */
    return (
      <Card className="trash-loading" padded={false}>
        <ul aria-busy="true">
          {[0, 1, 2].map((slot) => (
            <li className="trash-row trash-row--skeleton" key={slot} />
          ))}
        </ul>
      </Card>
    );
  }

  if (data.items.length === 0) {
    /* Two blank screens, two sentences. `filteredCount` is what separates "you
     * have deleted nothing" from "what you deleted is no longer yours to
     * restore" — `docs/09 §11` requires both, and the second must never name a
     * file, because the caller once had access to it (rule 7). */
    return data.filteredCount > 0 ? (
      <FilteredEmptyState
        heading="trash.filtered.heading"
        body="trash.filtered.body"
        values={{ count: data.filteredCount }}
        fill
      />
    ) : (
      <EmptyState heading="trash.empty.heading" body="trash.empty.body" fill />
    );
  }

  return (
    <Card className="trash-list" padded={false}>
      <ul>
        {data.items.map((item) => (
          <Row
            key={item.fileId}
            item={item}
            onRestore={onRestore}
            busy={pendingId === item.fileId}
            failed={failedId === item.fileId}
          />
        ))}
      </ul>
    </Card>
  );
}

function Row({
  item,
  onRestore,
  busy,
  failed,
}: {
  item: TrashItem;
  onRestore: (item: { fileId: string; revision: number }) => void;
  busy: boolean;
  failed: boolean;
}) {
  const t = useT();
  const f = useFormatters();
  /* One clock per row render rather than a shared tick: this list does not
   * update in place, so a second-by-second countdown would be motion nobody
   * asked for on a screen people arrive at once. */
  const [now] = useState(() => new Date());
  const { stem, extension } = splitName(item.name);

  return (
    <li className="trash-row">
      <span className="trash-icon" data-kind={item.nodeType} aria-hidden="true">
        <Icon name={item.nodeType === 'FOLDER' ? 'folder' : 'file'} size={16} />
      </span>
      <span className="trash-name">
        <Truncate>
          {stem}
          <span className="trash-ext">{extension}</span>
        </Truncate>
        <span className="trash-meta">
          {/* A person's name is data, not a message (`docs/14 §6`) — and an
           * absent one is not "Unknown": a service account has no `users` row,
           * and inventing a name for it would put a principal nobody
           * provisioned in front of a reader. */}
          {item.deletedBy.displayName === null
            ? t('trash.deletedByUnknown')
            : t('trash.deletedBy', { who: item.deletedBy.displayName })}
          {' · '}
          <time dateTime={item.deletedAt}>{f.relative(new Date(item.deletedAt), now)}</time>
          {item.purgeAfter !== null && (
            <>
              {' · '}
              {t('trash.purgeAfter', { when: f.relative(new Date(item.purgeAfter), now) })}
            </>
          )}
        </span>
      </span>
      <Push />
      {failed && (
        /* On the row, because that is where the action was taken. A toast would
         * move the explanation away from the thing it is about. */
        <span className="trash-failed" role="alert">
          {t('trash.restore.failed')}
        </span>
      )}
      <Button
        label="trash.restore"
        size="sm"
        state={busy ? { kind: 'busy' } : { kind: 'ready' }}
        onClick={() => onRestore({ fileId: item.fileId, revision: item.revision })}
      />
    </li>
  );
}
