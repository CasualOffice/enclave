import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { failureOf, type Failure } from '../../../shared/api/failure.ts';
import { useT } from '../../../shared/i18n/index.tsx';
import { useWorkspaces } from '../../../entities/workspace/api.ts';
import { Button, LaterChip, Pill } from '../../../shared/ui/primitives.tsx';
import { Field, Push, Row } from '../../../shared/ui/layout.tsx';
import { DeniedPanel, EmptyState } from '../../../shared/ui/surface-states.tsx';
import { AdminErrorState, AdminLoadingState } from '../states.tsx';
import {
  assignPolicy,
  createPolicy,
  fetchRetention,
  retentionQueryKey,
  withdrawAssignment,
} from './api.ts';
import { ABSOLUTE, NEEDS_DURATION, type RetentionPolicy } from './model.ts';

/* Admin — retention (`ENC-945`).
 *
 * `ENC-943` shipped four endpoints and nothing in `web/src` called them, so a
 * control the chain enforces on every delete was reachable by `curl` alone.
 * This is the screen; it closes the request the repo owner actually made,
 * which was retention *configured via workspace admin*.
 *
 * # Two scopes are offered and three are not, on purpose
 *
 * The server accepts five (`TENANT`, `WORKSPACE`, `LIBRARY`, `CONTENT_TYPE`,
 * `FILE`). This offers the two it can name honestly: `TENANT`, which names
 * nothing, and `WORKSPACE`, for which `entities/workspace` already provides a
 * real picker. The other three are rendered `unbuilt` rather than as a UUID
 * box, because a field that asks an administrator to paste an identifier is a
 * control applied to the wrong thing the first time somebody mistypes — and a
 * retention scope applied to the wrong library is a document destroyed or
 * preserved for a reason nobody chose. `CONTENT_TYPE` additionally has no
 * identifier type in the tree at all, and `FILE` scope belongs beside the file,
 * not in a tenant-wide list.
 *
 * # The vocabularies come from the server
 *
 * `actions`, `bases` and `scopeTypes` are the response's, never a literal here
 * (`ENC-943` put them on the wire for this). A hard-coded list drifts from
 * `migrations/0031` silently and surfaces as an option that produces a 400
 * nobody can explain.
 */

/** The sentence a policy makes, assembled from parts the catalog owns. */
function policySummaryKey(policy: RetentionPolicy): 'admin.retention.summary.duration' | 'admin.retention.summary.plain' {
  return policy.durationDays === null
    ? 'admin.retention.summary.plain'
    : 'admin.retention.summary.duration';
}

export function RetentionScreen({ readOnly }: { readOnly: boolean }) {
  const t = useT();
  const client = useQueryClient();
  const view = useQuery({
    queryKey: retentionQueryKey,
    queryFn: ({ signal }) => fetchRetention(signal),
    retry: false,
  });
  const workspaces = useWorkspaces();

  const [drafting, setDrafting] = useState(false);

  /* Every mutation invalidates rather than splicing. The server decides what
   * the list now contains — precedence between overlapping policies is its
   * rule, not this screen's — and a client editing one row in would be
   * guessing at a set it does not compute. */
  const refresh = () => void client.invalidateQueries({ queryKey: retentionQueryKey });
  const create = useMutation({ mutationFn: createPolicy, onSuccess: () => { setDrafting(false); refresh(); } });
  const apply = useMutation({
    mutationFn: ({ id, scopeType, scopeId }: { id: string; scopeType: string; scopeId: string | null }) =>
      assignPolicy(id, scopeType, scopeId),
    onSuccess: refresh,
  });
  const withdraw = useMutation({
    mutationFn: ({ id, scopeType, scopeId }: { id: string; scopeType: string; scopeId: string | null }) =>
      withdrawAssignment(id, scopeType, scopeId),
    onSuccess: refresh,
  });

  if (view.isPending) {
    return (
      <div className="adm-pane">
        <AdminLoadingState />
      </div>
    );
  }

  const failure: Failure | undefined =
    view.error === null || view.error === undefined ? undefined : failureOf(view.error);

  if (failure?.kind === 'denied') {
    return (
      <div className="adm-pane">
        <DeniedPanel failure={failure} fill />
      </div>
    );
  }
  if (failure !== undefined) {
    /* `stepUp` carries a challenge rather than a request id, so the id is read
     * only from the variants that have one. Reading it off the union would be a
     * compile error, which is the type doing the work `docs/17 §7` asks for. */
    return (
      <div className="adm-pane">
        <AdminErrorState
          error={{
            retryable: failure.kind === 'failed' ? failure.retryable : false,
            requestId: failure.kind === 'stepUp' ? '' : failure.requestId,
          }}
          onRetry={() => void view.refetch()}
        />
      </div>
    );
  }

  const data = view.data;
  if (data === undefined) return null;

  /* The refusal every write on this surface can meet, rendered where the write
   * is rather than as a page-level state: the list is still correct and still
   * worth reading when a write is refused. `STEP_UP_REQUIRED` is the one the
   * server raises when `security.mfa.admins_required` is on and no step-up flow
   * exists yet — a refusal, so no retry (`docs/17 §7` F3). */
  const writeFailure = [create.error, apply.error, withdraw.error]
    .filter((error) => error !== null && error !== undefined)
    .map((error) => failureOf(error))[0];

  return (
    <div className="adm-pane">
      <div className="adm-head">
        <h1 className="adm-h1">{t('admin.retention.title')}</h1>
        <Push />
        {readOnly ? (
          <Pill label="admin.auditor.pill" tone="info" icon="eye" />
        ) : (
          <Button
            label="admin.retention.new"
            icon="plus"
            variant="primary"
            onClick={() => setDrafting(true)}
          />
        )}
      </div>
      <p className="adm-muted">{t('admin.retention.intro')}</p>
      {/* Auditor mode is a *rendering* of a decision the server does not send
        * yet — `role_assignments` has no DDL — so it removes controls and never
        * grants one. Hiding is fail-safe: the chain still refuses the write.
        * Showing them `denied` would need a reason sentence, and inventing one
        * client-side is what `docs/17 §1` forbids. Same choice `dlp` made. */}
      {readOnly && <p className="adm-muted">{t('admin.auditor.note')}</p>}

      {writeFailure !== undefined && (
        <p className="adm-writefail" role="status">
          <Pill label="admin.retention.writeRefused" tone="warn" icon="info" />
          <span>{writeFailure.kind === 'denied' ? writeFailure.message : t('admin.retention.writeFailed')}</span>
        </p>
      )}

      {drafting && (
        <PolicyDraftForm
          vocabulary={data.vocabulary}
          busy={create.isPending}
          onCancel={() => setDrafting(false)}
          onSubmit={(draft) => create.mutate(draft)}
        />
      )}

      {data.policies.length === 0 && !drafting ? (
        <EmptyState
          heading="admin.retention.empty.title"
          body="admin.retention.empty.body"
          {...(readOnly ? {} : { action: 'admin.retention.new' as const, onAction: () => setDrafting(true) })}
        />
      ) : (
        <ul className="adm-retlist">
          {data.policies.map((policy) => {
            const mine = data.assignments.filter((a) => a.policyId === policy.id);
            return (
              <li key={policy.id} className="adm-retcard">
                <div className="adm-rethead">
                  <b>{policy.name}</b>
                  <Pill label="admin.retention.actionLabel" values={{ action: policy.action }} tone="neutral" />
                  {policy.allowUserDelete && (
                    <Pill label="admin.retention.userDeletable" tone="warn" icon="info" />
                  )}
                </div>
                <p className="adm-muted">
                  {t(policySummaryKey(policy), {
                    action: policy.action,
                    basis: policy.basis,
                    days: policy.durationDays ?? 0,
                  })}
                </p>

                <ul className="adm-retscopes">
                  {mine.length === 0 && (
                    <li className="adm-muted">{t('admin.retention.noScopes')}</li>
                  )}
                  {mine.map((a) => (
                    <li key={`${a.scopeType}:${a.scopeId ?? 'tenant'}`}>
                      <span>
                        {a.scopeType === 'TENANT'
                          ? t('admin.retention.scope.tenant')
                          : t('admin.retention.scope.named', {
                              scope: a.scopeType,
                              name:
                                workspaces.data?.items.find((w) => w.id === a.scopeId)?.name ??
                                a.scopeId ??
                                '',
                            })}
                      </span>
                      {a.live ? (
                        <Pill label="admin.retention.live" tone="ok" />
                      ) : (
                        <Pill label="admin.retention.withdrawn" tone="neutral" />
                      )}
                      <Push />
                      {a.live && !readOnly && (
                        <Button
                          label="admin.retention.withdraw"
                          size="sm"
                          state={withdraw.isPending ? { kind: 'busy' } : { kind: 'ready' }}
                          onClick={() =>
                            withdraw.mutate({ id: policy.id, scopeType: a.scopeType, scopeId: a.scopeId })
                          }
                        />
                      )}
                    </li>
                  ))}
                </ul>

                {!readOnly && (
                <ApplyControl
                  disabled={apply.isPending}
                  workspaces={workspaces.data?.items ?? []}
                  onApply={(scopeType, scopeId) => apply.mutate({ id: policy.id, scopeType, scopeId })}
                />
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/** Applying a policy: the two scopes this screen can name, and the three it cannot. */
function ApplyControl({
  disabled,
  workspaces,
  onApply,
}: {
  disabled: boolean;
  workspaces: readonly { readonly id: string; readonly name: string }[];
  onApply: (scopeType: string, scopeId: string | null) => void;
}) {
  const t = useT();
  const [scope, setScope] = useState('TENANT');
  const [workspaceId, setWorkspaceId] = useState('');

  return (
    <div className="adm-retapply">
      <label className="ui-label" htmlFor="ret-scope">
        {t('admin.retention.applyTo')}
      </label>
      <select
        id="ret-scope"
        className="adm-select"
        value={scope}
        onChange={(event) => setScope(event.target.value)}
      >
        <option value="TENANT">{t('admin.retention.scope.tenant')}</option>
        <option value="WORKSPACE">{t('admin.retention.scope.workspace')}</option>
      </select>

      {scope === 'WORKSPACE' && (
        <select
          className="adm-select"
          aria-label={t('admin.retention.scope.workspacePicker')}
          value={workspaceId}
          onChange={(event) => setWorkspaceId(event.target.value)}
        >
          <option value="">{t('admin.retention.scope.choose')}</option>
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
      )}

      <Button
        label="admin.retention.apply"
        size="sm"
        state={
          disabled
            ? { kind: 'busy' }
            : scope === 'WORKSPACE' && workspaceId === ''
              ? { kind: 'unbuilt', note: 'admin.retention.chooseScope' }
              : { kind: 'ready' }
        }
        onClick={() => onApply(scope, scope === 'TENANT' ? null : workspaceId)}
      />

      {/* The three the server accepts and this screen will not ask for as a
        * pasted identifier. `docs/17 §6`'s neutral treatment, and the note says
        * which release rather than implying a permission. */}
      <Row unbuilt>
        {t('admin.retention.scope.others')}
        <Push />
        <LaterChip note="later.chip" />
      </Row>
    </div>
  );
}

/** The create form. Validation is the server's; this decides only what is shown. */
function PolicyDraftForm({
  vocabulary,
  busy,
  onCancel,
  onSubmit,
}: {
  vocabulary: { readonly actions: readonly string[]; readonly bases: readonly string[] };
  busy: boolean;
  onCancel: () => void;
  onSubmit: (draft: {
    name: string;
    action: string;
    durationDays: number | null;
    basis: string;
    isRecord: boolean;
    allowUserDelete: boolean;
  }) => void;
}) {
  const t = useT();
  const [name, setName] = useState('');
  const [action, setAction] = useState(vocabulary.actions[0] ?? 'KEEP');
  const [basis, setBasis] = useState(vocabulary.bases[0] ?? 'CREATED');
  const [days, setDays] = useState('2555');
  const [allowUserDelete, setAllowUserDelete] = useState(false);

  const wantsDuration = NEEDS_DURATION.includes(action);
  const absolute = ABSOLUTE.includes(action);

  return (
    <form
      className="adm-retform"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({
          name,
          action,
          /* Sent whenever the action can carry one, so a `KEEP` with a stated
           * period keeps it. The schema refuses a duration on an action that
           * must not have one, and reports which constraint refused. */
          durationDays: days.trim() === '' ? null : Number(days),
          basis,
          isRecord: action === 'RECORD',
          allowUserDelete: absolute ? false : allowUserDelete,
        });
      }}
    >
      <Field
        label="admin.retention.form.name"
        value={name}
        onChange={(event) => setName(event.target.value)}
        required
      />

      <label className="ui-label" htmlFor="ret-action">
        {t('admin.retention.form.action')}
      </label>
      <select
        id="ret-action"
        className="adm-select"
        value={action}
        onChange={(event) => setAction(event.target.value)}
      >
        {vocabulary.actions.map((value) => (
          <option key={value} value={value}>
            {value}
          </option>
        ))}
      </select>

      <label className="ui-label" htmlFor="ret-basis">
        {t('admin.retention.form.basis')}
      </label>
      <select
        id="ret-basis"
        className="adm-select"
        value={basis}
        onChange={(event) => setBasis(event.target.value)}
      >
        {vocabulary.bases.map((value) => (
          <option key={value} value={value}>
            {value}
          </option>
        ))}
      </select>

      <Field
        label="admin.retention.form.days"
        type="number"
        min={1}
        value={days}
        onChange={(event) => setDays(event.target.value)}
        required={wantsDuration}
      />

      <label className="adm-check">
        <input
          type="checkbox"
          checked={absolute ? false : allowUserDelete}
          disabled={absolute}
          onChange={(event) => setAllowUserDelete(event.target.checked)}
        />
        {t('admin.retention.form.allowUserDelete')}
      </label>
      {absolute && <p className="adm-muted">{t('admin.retention.form.absoluteNote')}</p>}

      <div className="adm-head">
        <Button label="admin.retention.form.cancel" onClick={onCancel} />
        <Button
          label="admin.retention.form.save"
          type="submit"
          variant="primary"
          state={busy ? { kind: 'busy' } : { kind: 'ready' }}
        />
      </div>
    </form>
  );
}
