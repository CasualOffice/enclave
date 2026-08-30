import { useState } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Card, Push, Truncate } from '../../shared/ui/layout.tsx';

import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { EmptyState, FailureState, FilteredEmptyState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { splitName } from '../../entities/file/present.ts';
import { sentenceFor, useActivity, type ActivityItem } from './api.ts';
import './activity.css';

/**
 * What changed, among the things this person can see.
 *
 * `ENC-960`. The fourth `Later` chip to become a screen, and the first surface
 * ever to read `audit_events` — the hash-chained log has been written since
 * Phase 0 and nothing had selected from it, including the `/admin/audit`
 * endpoint `docs/05 §14` has specified since it was drawn.
 *
 * # It shows changes and never reads, and that is the product decision
 *
 * `metadata_read`, `preview` and `download` are the bulk of any real audit log
 * and the server excludes them. A feed carrying them would be a record of who
 * looked at what, readable by everybody who can open the file — a surveillance
 * tool, and a different product from this one. The data sitting in the table is
 * not an argument for surfacing it.
 *
 * # The empty state is the common case and says so
 *
 * An audit log is dominated by activity on content most callers cannot see, so
 * a feed showing three rows out of two hundred candidates is working correctly.
 * `filteredCount` is what lets the blank screen say *"nothing you can see has
 * changed"* rather than *"nothing has happened"*, which would be false.
 */
export default function Screen() {
  const t = useT();
  const activity = useActivity();

  return (
    <div className="act">
      <div className="act-page">
        <header>
          <h1 className="act-title">{t('activity.title')}</h1>
          <p className="act-subline">{t('activity.subline')}</p>
        </header>
        <Body
          data={activity.data}
          isPending={activity.isPending}
          isError={activity.isError}
          error={activity.error}
          onRetry={() => void activity.refetch()}
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
  data: { items: readonly ActivityItem[]; filteredCount: number } | undefined;
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
      <Card className="act-loading" padded={false}>
        <ul aria-busy="true">
          {[0, 1, 2].map((slot) => (
            <li className="act-row act-row--skeleton" key={slot} />
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
        heading="activity.filtered.heading"
        body="activity.filtered.body"
        values={{ count: data.filteredCount }}
        fill
      />
    ) : (
      <EmptyState heading="activity.empty.heading" body="activity.empty.body" fill />
    );
  }

  return (
    <Card className="act-list" padded={false}>
      <ul>
        {data.items.map((item) => (
          <Row key={item.fileId} item={item} />
        ))}
      </ul>
    </Card>
  );
}

function Row({ item }: { item: ActivityItem }) {
  const t = useT();
  const f = useFormatters();
  const [now] = useState(() => new Date());
  const { stem, extension } = splitName(item.name);

  const href = `/library/${encodeURIComponent(item.libraryId)}?file=${encodeURIComponent(item.fileId)}`;

  return (
    <li className="act-row">
      <a className="act-link" href={href}>
        <span className="act-icon" data-kind={item.nodeType} aria-hidden="true">
          <Icon name={item.nodeType === 'FOLDER' ? 'folder' : 'file'} size={16} />
        </span>
        <span className="act-name">
          <Truncate>
            {stem}
            <span className="act-ext">{extension}</span>
          </Truncate>
          <span className="act-meta">
            {/* One sentence per verb, chosen by the catalog rather than
              * assembled: "was edited" and "was moved" are not one string with a
              * word swapped in any language that inflects. */}
            {t(sentenceFor(item.action))}
            {' · '}
            <time dateTime={item.occurredAt}>{f.relative(new Date(item.occurredAt), now)}</time>
          </span>
        </span>
        <Push />
      </a>
    </li>
  );
}
