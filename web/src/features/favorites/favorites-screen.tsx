import { useState } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Card, Push, Truncate } from '../../shared/ui/layout.tsx';
import { IconButton, Pill } from '../../shared/ui/primitives.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { EmptyState, FailureState, FilteredEmptyState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { splitName } from '../../entities/file/present.ts';
import { useFavorites, useStar, type FavoriteItem } from '../../entities/favorite/api.ts';
import './favorites.css';

/**
 * What this person starred.
 *
 * `ENC-959`. *Favorites* has carried a `Later` chip in the navigation since the
 * shell was written and had no table behind it until `migrations/0034`, so the
 * chip was the honest treatment of a screen that could not be written. Third of
 * the seven to become a real entry.
 *
 * # The star is the one optimistic control in this client
 *
 * `docs/17` Q25 forbids optimism for anything touching access. A favourite
 * touches none: it grants nothing, reveals nothing, and is this person's own
 * note about a file they can already see. What optimism buys is the thing a
 * star is *for* — a control that answers instantly — and the cost of being
 * wrong is an outline that fills and empties again, not a document somebody
 * believes they can reach.
 *
 * # A star is not permission, so the list is still trimmed
 *
 * `GET /me/favorites` runs every row through the chain before returning it: a
 * file starred a year ago may have been re-permissioned since. `filteredCount`
 * is what separates *"you have starred nothing"* from *"what you starred is no
 * longer yours to open"*, and it says how many and never which (rule 7).
 */
export default function Screen() {
  const t = useT();
  const favorites = useFavorites();

  return (
    <div className="fav">
      <div className="fav-page">
        <header>
          <h1 className="fav-title">{t('favorites.title')}</h1>
          <p className="fav-subline">{t('favorites.subline')}</p>
        </header>
        <Body
          data={favorites.data}
          isPending={favorites.isPending}
          isError={favorites.isError}
          error={favorites.error}
          onRetry={() => void favorites.refetch()}
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
  data: { items: readonly FavoriteItem[]; filteredCount: number } | undefined;
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
      <Card className="fav-loading" padded={false}>
        <ul aria-busy="true">
          {[0, 1, 2].map((slot) => (
            <li className="fav-row fav-row--skeleton" key={slot} />
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
        heading="favorites.filtered.heading"
        body="favorites.filtered.body"
        values={{ count: data.filteredCount }}
        fill
      />
    ) : (
      <EmptyState heading="favorites.empty.heading" body="favorites.empty.body" fill />
    );
  }

  return (
    <Card className="fav-list" padded={false}>
      <ul>
        {data.items.map((item) => (
          <Row key={item.fileId} item={item} />
        ))}
      </ul>
    </Card>
  );
}

function Row({ item }: { item: FavoriteItem }) {
  const f = useFormatters();
  const { toggle } = useStar();
  /* One clock per render rather than a shared tick: this list does not update in
   * place, so a second-by-second relative time would be motion nobody asked for
   * on a screen people arrive at once. */
  const [now] = useState(() => new Date());
  const { stem, extension } = splitName(item.name);

  const href = `/library/${encodeURIComponent(item.libraryId)}?file=${encodeURIComponent(item.fileId)}`;

  return (
    <li className="fav-row">
      <a className="fav-link" href={href}>
        <span className="fav-icon" data-kind={item.nodeType} aria-hidden="true">
          <Icon name={item.nodeType === 'FOLDER' ? 'folder' : 'file'} size={16} />
        </span>
        <span className="fav-name">
          <Truncate>
            {stem}
            <span className="fav-ext">{extension}</span>
          </Truncate>
          <span className="fav-meta">
            <time dateTime={item.favoritedAt}>{f.relative(new Date(item.favoritedAt), now)}</time>
          </span>
        </span>
        <Push />
        {item.classification !== null && (
          <Pill label="favorites.classification" values={{ label: item.classification.label }} />
        )}
      </a>
      {/* **Outside the anchor, deliberately.** A button nested in a link is a
        * control whose activation the browser cannot unambiguously attribute,
        * and a keyboard user pressing Enter on the row would remove the star
        * instead of opening the file. Two siblings, two targets. */}
      <IconButton
        name="star"
        label="favorites.unstar"
        values={{ name: item.name }}
        onClick={() => toggle(item.fileId, false)}
      />
    </li>
  );
}
