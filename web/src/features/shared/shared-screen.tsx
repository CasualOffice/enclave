import { useState } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Card, Push, Truncate } from '../../shared/ui/layout.tsx';
import { Pill } from '../../shared/ui/primitives.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { EmptyState, FailureState, FilteredEmptyState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { splitName } from '../../entities/file/present.ts';
import { useShared, type SharedItem } from './api.ts';
import './shared.css';

/**
 * What other people have given this account.
 *
 * `ENC-955`. `ENC-954` shipped `GET /me/shared`; this is the surface for it, and
 * the second of the seven `Later` entries to become a real screen.
 *
 * The hole it closes is worth restating because it was invisible: `acl_entries`
 * has had a writer since `ENC-916`, so a colleague could share a document
 * outside any workspace this person belongs to — the grant was written, the
 * chain honoured it on every request, and **the recipient had no way to find
 * it**. Nothing was broken; there was simply no listing.
 *
 * # Read-only, and that is not an omission
 *
 * A share is somebody else's act. What a row can *do* — open, preview, download
 * — are the file surface's verbs and belong to the file rather than to the fact
 * that it was shared, so this screen navigates and does not act. The one action
 * that would belong here is declining a share, and no endpoint removes a grant
 * on the grantee's own behalf (`ENC-956`).
 *
 * # Why the row says who, and why it does not say their name
 *
 * `sharedBy` is an opaque id: `GET /me/shared` returns the principal and there
 * is no directory read that resolves one to a display name. Rendering the id
 * would be worse than saying nothing, so the row says *when* and, when it
 * applies, *through which group* — and `ENC-958` is the row for the lookup.
 */
export default function Screen() {
  const t = useT();
  const shared = useShared();

  return (
    <div className="shr">
      <div className="shr-page">
        <header>
          <h1 className="shr-title">{t('shared.title')}</h1>
          <p className="shr-subline">{t('shared.subline')}</p>
        </header>
        <Body
          data={shared.data}
          isPending={shared.isPending}
          isError={shared.isError}
          error={shared.error}
          onRetry={() => void shared.refetch()}
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
}: {
  data: { items: readonly SharedItem[]; filteredCount: number } | undefined;
  isPending: boolean;
  isError: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  /* A denial is not a failure and gets no retry; a fault gets one and a request
   * ID (`docs/17 §7`). `FailureState` owns that branch. */
  if (isError) return <FailureState failure={failureOf(error)} onRetry={onRetry} fill />;

  /* Pending is not empty. Drawing "Nobody has shared anything with you" while
   * the request is in flight tells somebody a colleague never sent the file. */
  if (isPending || data === undefined) {
    return (
      <Card className="shr-loading" padded={false}>
        <ul aria-busy="true">
          {[0, 1, 2].map((slot) => (
            <li className="shr-row shr-row--skeleton" key={slot} />
          ))}
        </ul>
      </Card>
    );
  }

  if (data.items.length === 0) {
    /* Two blank screens, two sentences. `filteredCount` separates "nobody has
     * shared anything with you" from "what was shared is no longer yours to
     * open" — `docs/09 §11` requires both, and the second must never name a
     * file, because the caller was once meant to have it (rule 7). */
    return data.filteredCount > 0 ? (
      <FilteredEmptyState
        heading="shared.filtered.heading"
        body="shared.filtered.body"
        values={{ count: data.filteredCount }}
        fill
      />
    ) : (
      <EmptyState heading="shared.empty.heading" body="shared.empty.body" fill />
    );
  }

  return (
    <Card className="shr-list" padded={false}>
      <ul>
        {data.items.map((item) => (
          <Row key={item.fileId} item={item} />
        ))}
      </ul>
    </Card>
  );
}

function Row({ item }: { item: SharedItem }) {
  const t = useT();
  const f = useFormatters();
  /* One clock per render rather than a shared tick: this list does not update in
   * place, so a second-by-second relative time would be motion nobody asked for
   * on a screen people arrive at once. */
  const [now] = useState(() => new Date());
  const { stem, extension } = splitName(item.name);

  /* The whole row is the link, not a nested anchor on the name: a row with one
   * destination should have one target, and `docs/09 §6`'s keyboard model walks
   * rows rather than the controls inside them. */
  const href = `/library/${encodeURIComponent(item.libraryId)}?file=${encodeURIComponent(item.fileId)}`;

  return (
    <li className="shr-row">
      <a className="shr-link" href={href}>
        <span className="shr-icon" data-kind={item.nodeType} aria-hidden="true">
          <Icon name={item.nodeType === 'FOLDER' ? 'folder' : 'file'} size={16} />
        </span>
        <span className="shr-name">
          <Truncate>
            {stem}
            <span className="shr-ext">{extension}</span>
          </Truncate>
          <span className="shr-meta">
            <time dateTime={item.sharedAt}>{f.relative(new Date(item.sharedAt), now)}</time>
            {item.viaGroup !== null && (
              <>
                {' · '}
                {t('shared.viaGroup')}
              </>
            )}
          </span>
        </span>
        <Push />
        {/* The classification the file carries, when it has one. On this screen
          * more than any other: a document that arrived from somebody else is
          * one whose sensitivity the reader has not seen before. */}
        {item.classification !== null && (
          <Pill label="shared.classification" values={{ label: item.classification.label }} />
        )}
      </a>
    </li>
  );
}
