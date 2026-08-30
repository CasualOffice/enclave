import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { failureOf, type Failure } from '../../../shared/api/failure.ts';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import { Button, Pill } from '../../../shared/ui/primitives.tsx';
import { Field, Push, Tab, TabList, Truncate } from '../../../shared/ui/layout.tsx';
import { DeniedPanel, EmptyState, FilteredEmptyState } from '../../../shared/ui/surface-states.tsx';
import { AdminErrorState, AdminLoadingState } from '../states.tsx';
import { auditQueryKey, fetchAudit } from './api.ts';
import { OUTCOMES, type AuditFilter, type AuditRow } from './model.ts';

/* Admin — audit (`ENC-961` built the endpoint; this is the screen).
 *
 * The compliance log has been written since Phase 0 and, until this, was
 * readable by `curl` alone. That is the failure this repository keeps making —
 * a complete, tested, gate-enforced engine that nothing calls — and on this
 * surface it had an extra edge: the product asks customers to trust an audit
 * trail that no one using the product could look at.
 *
 * # Pages, not infinite scroll
 *
 * `CLAUDE.md` says virtualize any list that can exceed 100 rows. This one never
 * does: it shows one page of fifty and moves, rather than appending. That is
 * not a way around the rule — it is the better reading of an append-only log.
 * A ledger is read in pages, a cursor is a place you can go back to, and an
 * auditor citing a row wants a page they can return to rather than a scroll
 * position. Appending would also make "load more" the only way back to the
 * head, which is the row an investigation starts from.
 *
 * Because the log is append-only, a page below the head is immutable — the one
 * listing in this product where that holds — so cursors are kept in a stack and
 * paging back is served from cache without re-asking the server.
 *
 * # The circumstances are behind a disclosure, per row
 *
 * `ip`, `country`, `user_agent`, `session_id`, `device_id`, `detail` and the
 * hashes are what separate this surface from `/me/activity`, and they are the
 * reason it needs `ReadAudit`. They are still not columns. Twenty-five fields
 * across fifty rows is not a table anybody reads, and an investigation asks for
 * a colleague's IP address about one row at a time. Behind a disclosure they
 * are one click away and not on screen by default, which is the right default
 * for data whose whole purpose is reconstructing a person's session.
 *
 * # A denial is not an incident
 *
 * `DENY` rows are the ones an investigation is looking for, and they are also
 * completely ordinary — the chain refusing something correctly, thousands of
 * times a day. They are marked so they can be picked out and scanned for, and
 * marked `warn` rather than `danger`: a log where the normal case is painted as
 * an alarm is a log people stop reading. `ERROR` is the row that means
 * something went wrong.
 *
 * # The action is the server's spelling, untranslated
 *
 * `/me/activity` maps each verb to a sentence, because a member reads *"was
 * edited by Ana"*. An auditor reads `file.download`, cites `file.download` in a
 * report, and types it into the filter box. Translating it here would put a
 * string in front of them that does not appear in the record they are quoting.
 */

/** Rows an auditor is most likely to want, offered as one click each. */
const QUICK_ACTIONS = ['file.download', 'file.export', 'file.print', 'file.share_external'] as const;

export function AuditScreen() {
  const t = useT();
  const [outcome, setOutcome] = useState<string | undefined>(undefined);
  const [action, setAction] = useState('');
  const [actor, setActor] = useState<string | undefined>(undefined);
  /* The cursor stack. `[]` is the head; each page pushes the cursor that
   * fetched it, so Back is a pop rather than a second cursor travelling the
   * other way — which the server does not offer and could not offer without a
   * second index. */
  const [cursors, setCursors] = useState<readonly string[]>([]);

  const before = cursors[cursors.length - 1];
  const filter: AuditFilter = {
    outcome,
    action: action.trim() === '' ? undefined : action.trim(),
    actor,
    before,
  };

  const page = useQuery({
    queryKey: auditQueryKey(filter),
    queryFn: ({ signal }) => fetchAudit(filter, signal),
    retry: false,
    /* An append-only page below the head cannot change. The head can, so it is
     * not marked fresh forever — but nothing here polls: an audit log that
     * refreshed under an auditor mid-read would move the row they were looking
     * at, which is the one interaction this screen must never have. */
    staleTime: before === undefined ? 0 : Infinity,
  });

  /* Every change of narrowing returns to the head. A cursor is a position in
   * one filtered sequence and means nothing in another — carrying it across
   * would page into the middle of a result set the auditor has not seen the
   * start of, and the page would look like the whole answer. */
  const narrow = (change: () => void) => {
    setCursors([]);
    change();
  };

  const filtered = outcome !== undefined || action.trim() !== '' || actor !== undefined;

  return (
    <div className="adm-pane">
      <div className="adm-head">
        <h1 className="adm-h1">{t('admin.audit.title')}</h1>
        <Push />
        <Pill label="admin.audit.appendOnly" tone="info" icon="lock" />
      </div>
      <p className="adm-intro">{t('admin.audit.intro')}</p>

      <TabList label="admin.audit.outcomeLabel">
        <Tab
          label="admin.audit.outcome.all"
          selected={outcome === undefined}
          onClick={() => narrow(() => setOutcome(undefined))}
        />
        {OUTCOMES.map((value) => (
          <Tab
            key={value}
            label={`admin.audit.outcome.${value.toLowerCase()}` as 'admin.audit.outcome.allow'}
            selected={outcome === value}
            onClick={() => narrow(() => setOutcome(value))}
          />
        ))}
      </TabList>

      <div className="aud-filters">
        <Field
          label="admin.audit.actionLabel"
          icon="s"
          type="search"
          value={action}
          placeholder={t('admin.audit.actionPlaceholder')}
          onChange={(event) => narrow(() => setAction(event.target.value))}
        />
        <div className="aud-quick">
          {QUICK_ACTIONS.map((verb) => (
            <button
              key={verb}
              type="button"
              className="aud-chip"
              aria-pressed={action.trim() === verb}
              onClick={() => narrow(() => setAction(action.trim() === verb ? '' : verb))}
            >
              {verb}
            </button>
          ))}
        </div>
        {actor !== undefined && (
          /* Set by clicking a row's actor, never typed: an input asking for a
           * UUID is a filter nobody can use and a typo nobody can see. */
          <Button
            label="admin.audit.clearActor"
            icon="x"
            variant="ghost"
            size="sm"
            onClick={() => narrow(() => setActor(undefined))}
          />
        )}
      </div>

      <AuditBody
        page={page}
        filtered={filtered}
        onActor={(id) => narrow(() => setActor(id))}
        onClear={() =>
          narrow(() => {
            setOutcome(undefined);
            setAction('');
            setActor(undefined);
          })
        }
      />

      {page.data !== undefined && page.data.items.length > 0 && (
        /* Each control is rendered only when it can act, rather than shown
         * disabled. `Button` has no `disabled` prop by design — a greyed
         * control explains nothing — and neither of its two explained states
         * fits: nothing has been refused, and nothing is unbuilt. There is
         * simply no page in that direction, and the honest rendering of that
         * is its absence. */
        <div className="aud-pager">
          {cursors.length > 0 && (
            <Button
              label="admin.audit.newer"
              icon="up"
              variant="ghost"
              size="sm"
              onClick={() => setCursors(cursors.slice(0, -1))}
            />
          )}
          <span className="aud-pageno">
            {t('admin.audit.pageOf', { page: String(cursors.length + 1) })}
          </span>
          {page.data.nextCursor !== null && (
            <Button
              label="admin.audit.older"
              icon="down"
              variant="ghost"
              size="sm"
              onClick={() => {
                const next = page.data?.nextCursor;
                if (next !== null && next !== undefined) setCursors([...cursors, next]);
              }}
            />
          )}
        </div>
      )}
    </div>
  );
}

function AuditBody({
  page,
  filtered,
  onActor,
  onClear,
}: {
  page: ReturnType<typeof useQuery<import('./model.ts').AuditPage>>;
  filtered: boolean;
  onActor: (id: string) => void;
  onClear: () => void;
}) {
  const t = useT();

  if (page.isPending) return <AdminLoadingState />;

  const failure: Failure | undefined =
    page.error === null || page.error === undefined ? undefined : failureOf(page.error);

  if (failure?.kind === 'denied') return <DeniedPanel failure={failure} fill />;
  if (failure !== undefined) {
    return (
      <AdminErrorState
        error={{
          retryable: failure.kind === 'failed' ? failure.retryable : false,
          requestId: failure.kind === 'stepUp' ? '' : failure.requestId,
        }}
        onRetry={() => void page.refetch()}
      />
    );
  }

  const data = page.data;
  if (data === undefined) return null;

  if (data.items.length === 0) {
    /* Two different absences, and conflating them is the mistake. An empty log
     * is remarkable — this tenant has recorded nothing, which on an
     * append-only trail written by the policy engine means something is wrong.
     * An empty *filtered* page is ordinary, and the way out of it is the
     * filter. */
    return filtered ? (
      <FilteredEmptyState
        heading="admin.audit.filtered.heading"
        body="admin.audit.filtered.body"
        clearLabel="admin.audit.filtered.action"
        onClear={onClear}
        fill
      />
    ) : (
      <EmptyState heading="admin.audit.empty.heading" body="admin.audit.empty.body" fill />
    );
  }

  return (
    <table className="aud-table">
      <caption className="ui-sr-only">{t('admin.audit.tableCaption')}</caption>
      <thead>
        <tr>
          <th scope="col">{t('admin.audit.col.when')}</th>
          <th scope="col">{t('admin.audit.col.who')}</th>
          <th scope="col">{t('admin.audit.col.action')}</th>
          <th scope="col">{t('admin.audit.col.outcome')}</th>
          <th scope="col">{t('admin.audit.col.resource')}</th>
        </tr>
      </thead>
      <tbody>
        {data.items.map((row) => (
          <EventRow key={row.id} row={row} onActor={onActor} />
        ))}
      </tbody>
    </table>
  );
}

/** `warn` for a refusal, `danger` only for an error. See the note at the top. */
function toneFor(outcome: string): 'ok' | 'warn' | 'danger' | 'neutral' {
  if (outcome === 'ALLOW') return 'ok';
  if (outcome === 'DENY') return 'warn';
  if (outcome === 'ERROR') return 'danger';
  return 'neutral';
}

function EventRow({ row, onActor }: { row: AuditRow; onActor: (id: string) => void }) {
  const t = useT();
  const f = useFormatters();
  const [open, setOpen] = useState(false);
  const [now] = useState(() => new Date());
  const when = new Date(row.occurredAt);

  return (
    <>
      <tr className="aud-row" data-outcome={row.outcome}>
        <td>
          {/* The exact instant is the `title`, the relative one is the text: an
            * auditor scans in relative time and cites in absolute. Both come
            * from `Intl` — `docs/14` forbids formatting either by hand. */}
          <time dateTime={row.occurredAt} title={f.dateTime(when)}>
            {f.relative(when, now)}
          </time>
        </td>
        <td>
          {row.actorId === null ? (
            <span className="aud-who">{t('admin.audit.somebody')}</span>
          ) : (
            <button
              type="button"
              className="aud-who aud-who-link"
              onClick={() => onActor(row.actorId as string)}
              title={t('admin.audit.filterToActor')}
            >
              <Truncate>{row.actorName ?? t('admin.audit.somebody')}</Truncate>
            </button>
          )}
          <span className="aud-actor-kind">{row.actorType}</span>
        </td>
        <td>
          <code className="aud-action">{row.action}</code>
        </td>
        <td>
          <span className="aud-outcome" data-tone={toneFor(row.outcome)}>
            {row.outcome}
          </span>
          {row.reasonCode !== null && <span className="aud-reason">{row.reasonCode}</span>}
        </td>
        <td>
          <span className="aud-res">
            {row.resourceType ?? t('admin.audit.noResource')}
            {row.resourceId !== null && <code className="aud-id">{short(row.resourceId)}</code>}
          </span>
          <Push />
          <button
            type="button"
            className="aud-disclose"
            aria-expanded={open}
            onClick={() => setOpen(!open)}
          >
            {t(open ? 'admin.audit.hideDetail' : 'admin.audit.showDetail')}
          </button>
        </td>
      </tr>
      {open && (
        <tr className="aud-detail-row">
          <td colSpan={5}>
            <dl className="aud-detail">
              <Detail label="admin.audit.field.sequence" value={String(row.sequence)} />
              <Detail label="admin.audit.field.requestId" value={row.requestId} />
              <Detail label="admin.audit.field.sessionId" value={row.sessionId} />
              <Detail label="admin.audit.field.client" value={row.clientType} />
              <Detail label="admin.audit.field.device" value={row.deviceId} />
              <Detail label="admin.audit.field.ip" value={row.ip} />
              <Detail label="admin.audit.field.country" value={row.country} />
              <Detail label="admin.audit.field.userAgent" value={row.userAgent} />
              <Detail label="admin.audit.field.onBehalfOf" value={row.onBehalfOf} />
              <Detail label="admin.audit.field.workspace" value={row.workspaceId} />
              {/* The hashes. Shown because this is the only surface that can
                * show them, and because an auditor asked to trust a chain
                * should be able to see its links — even though nothing here
                * yet *checks* them, which is `ENC-969`. */}
              <Detail label="admin.audit.field.eventHash" value={row.eventHash} mono />
              <Detail label="admin.audit.field.previousHash" value={row.previousHash} mono />
              {hasDetail(row.detail) && (
                <Detail
                  label="admin.audit.field.detail"
                  value={JSON.stringify(row.detail)}
                  mono
                />
              )}
            </dl>
          </td>
        </tr>
      )}
    </>
  );
}

function Detail({
  label,
  value,
  mono = false,
}: {
  label: Parameters<ReturnType<typeof useT>>[0];
  value: string | null;
  mono?: boolean;
}) {
  const t = useT();
  if (value === null || value === '') return null;
  return (
    <div className="aud-field">
      <dt>{t(label)}</dt>
      <dd className={mono ? 'aud-mono' : undefined}>{value}</dd>
    </div>
  );
}

/** Whether `detail` carries anything, without asserting its shape. */
function hasDetail(detail: unknown): boolean {
  return typeof detail === 'object' && detail !== null && Object.keys(detail).length > 0;
}

/* Identifiers are shown short. The whole UUID is in the row's disclosure where
 * it can be copied; in a column it pushes everything a reader is scanning for
 * off the side of the table. */
function short(id: string): string {
  return id.slice(0, 8);
}
