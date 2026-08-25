import { useCallback, useSyncExternalStore } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ApiError } from '../../shared/api/client.ts';
import { useT } from '../../shared/i18n/index.tsx';
import { Pill } from '../../shared/ui/primitives.tsx';
import { AdminNav } from './admin-nav.tsx';
import {
  AdminDeniedState,
  AdminEmptyState,
  AdminErrorState,
  AdminFilteredEmptyState,
  AdminLoadingState,
} from './states.tsx';
import { dlpRulesQueryKey, fetchDlpRules } from './dlp/api.ts';
import { PolicyEditor } from './dlp/policy-editor.tsx';
import { DRAFT, RULES, SIMULATION } from './dlp/fixture.ts';
import type { DlpRule, SimulationResult } from './dlp/model.ts';
import './admin.css';

/* Admin — DLP policy.
 *
 * The sheet's contents only: the shell owns the rail and there is no top bar
 * (`docs/09 §3` after `ENC-676`). Inside, a 200 px section rail and the policy
 * surface, which is the prototype's layout.
 *
 * **What is real and what is not.** `GET /admin/dlp/rules` is specified
 * (`docs/05 §14.2`) and is fetched here through the one API client, parsed by
 * Zod at the boundary and nowhere else (`docs/17 §3`). The *simulation*
 * endpoint is named in `docs/05 §14` but has no written request or response
 * shape, so the rehearsal runs against a local fixture and says so on screen
 * rather than pretending to have called something. The write path is unbuilt
 * for a third reason again — see `dlp/policy-editor.tsx`.
 *
 * `?surface=` selects a state for review and for the axe run, which is the
 * device `app/app.tsx` already uses on the library list. It is a review
 * affordance and not a data source: `?surface=fixture` and the development-only
 * offline fallback both render sample policies behind a visible marker, so
 * nobody mistakes them for a tenant's own.
 */

/* `live` is the default and is the only one that calls the server. The rest are
 * the review surfaces `docs/09 §11` requires and the reference shows none of;
 * they are how the axe run reaches a state that a running gateway would
 * otherwise be needed to produce. `fixture` is named rather than implied,
 * because a fixture that arrives by accident is a fixture somebody mistakes for
 * data. */
const SURFACES = ['live', 'fixture', 'loading', 'error', 'denied', 'empty'] as const;
type Surface = (typeof SURFACES)[number];

/* URL state, read directly rather than through `app/routes.ts`.
 *
 * `docs/17 §4` puts filters and the selected object in the URL; `docs/17 §2`
 * forbids a feature from importing `app/`, which is where the route store
 * lives. Both rules are right and together they leave no way to do this, so
 * this reads `location` itself and reports the gap: a `useSearchParam` hook
 * belongs in `shared/`, and two features will want it.
 */
function subscribe(onChange: () => void): () => void {
  window.addEventListener('popstate', onChange);
  return () => window.removeEventListener('popstate', onChange);
}

function useSearch(): URLSearchParams {
  const href = useSyncExternalStore(
    subscribe,
    () => window.location.search,
    () => '',
  );
  return new URLSearchParams(href);
}

function setParam(key: string, value: string | undefined): void {
  const params = new URLSearchParams(window.location.search);
  if (value === undefined || value === '') params.delete(key);
  else params.set(key, value);
  const query = params.toString();
  window.history.replaceState(null, '', `${window.location.pathname}${query === '' ? '' : `?${query}`}`);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

/** No endpoint exists, so the rehearsal is a fixture with a delay that is honest about being one. */
function simulateFromFixture(_rule: DlpRule): Promise<SimulationResult> {
  return new Promise((resolve) => {
    window.setTimeout(() => resolve({ ...SIMULATION, ranAt: new Date().toISOString() }), 350);
  });
}

export default function Screen() {
  const t = useT();
  const params = useSearch();
  const surfaceParam = params.get('surface') ?? 'live';
  const surface: Surface = (SURFACES as readonly string[]).includes(surfaceParam)
    ? (surfaceParam as Surface)
    : 'live';
  const query = params.get('q') ?? '';
  const selectedId = params.get('rule') ?? undefined;
  /* Auditor mode is a *rendering* of a decision the server does not send yet:
   * `docs/05 §14` says the narrower administrator personas need
   * `role_assignments`, which has no DDL. Removing controls client-side is
   * fail-safe — the chain still refuses the write — but granting anything this
   * way would be a client-computed permission, which `docs/17 §1` forbids. */
  const readOnly = params.get('as') === 'auditor';

  const rules = useQuery({
    queryKey: dlpRulesQueryKey,
    queryFn: ({ signal }) => fetchDlpRules(signal),
    retry: false,
    enabled: surface === 'live',
  });

  const onSelect = useCallback((ruleId: string) => setParam('rule', ruleId), []);
  const onCreate = useCallback(() => setParam('rule', 'draft'), []);

  /* In development there is no gateway in front of this build, so a network
   * failure is the expected answer rather than an incident. The fixture stands
   * in, behind a marker that says what it is. A real failure — a 5xx, a parse
   * error, a denial — is never swallowed this way, and neither is a network
   * failure in a shipped build: there, a gateway that is not answering is an
   * incident, and sample policies on a security screen would be worse than an
   * error state. */
  const offline =
    import.meta.env.DEV &&
    rules.error instanceof ApiError &&
    rules.error.failure.kind === 'failed' &&
    rules.error.failure.code === 'network';

  const fixture = surface === 'fixture' || offline;
  const live: readonly DlpRule[] = fixture ? RULES : rules.data?.items ?? [];

  if (surface === 'loading' || (surface === 'live' && rules.isPending)) {
    return (
      <div className="adm">
        <AdminLoadingState />
      </div>
    );
  }

  if (surface === 'denied' || (rules.error instanceof ApiError && rules.error.failure.kind === 'denied')) {
    const failure =
      rules.error instanceof ApiError && rules.error.failure.kind === 'denied'
        ? rules.error.failure
        : { code: 'ACCESS_DENIED', message: '', remediation: undefined, requestId: '' };
    return (
      <div className="adm">
        <AdminDeniedState
          denial={{
            code: failure.code,
            message: failure.message,
            remediation: failure.remediation,
            requestId: failure.requestId,
          }}
        />
      </div>
    );
  }

  if (surface === 'error' || (surface === 'live' && !offline && rules.error !== null)) {
    const failure =
      rules.error instanceof ApiError && rules.error.failure.kind === 'failed'
        ? rules.error.failure
        : { retryable: true, requestId: '01K3Q7X0PMDR4W8B2ZC6E5A9TN' };
    return (
      <div className="adm">
        <AdminErrorState
          error={{ retryable: failure.retryable, requestId: failure.requestId }}
          onRetry={() => void rules.refetch()}
        />
      </div>
    );
  }

  const all = surface === 'empty' ? [] : live;
  const needle = query.trim().toLocaleLowerCase();
  const visible =
    needle === '' ? all : all.filter((rule) => rule.name.toLocaleLowerCase().includes(needle));

  const drafting = selectedId === 'draft' || (all.length === 0 && selectedId !== undefined);
  const selected = drafting ? undefined : visible.find((rule) => rule.id === selectedId) ?? visible[0];

  return (
    <div className="adm">
      <AdminNav
        rules={visible}
        selectedId={selected?.id}
        query={query}
        onQuery={(next) => setParam('q', next)}
        hrefFor={(ruleId) => `${window.location.pathname}?rule=${encodeURIComponent(ruleId)}`}
        onSelect={onSelect}
        onCreate={onCreate}
        readOnly={readOnly}
      />

      <div className="adm-pane">
        {fixture && (
          <p className="adm-fixture">
            <Pill label="admin.state.fixture" tone="warn" icon="info" />
            <span>{t('admin.state.fixtureNote')}</span>
          </p>
        )}

        {all.length === 0 && !drafting ? (
          <AdminEmptyState onCreate={onCreate} />
        ) : visible.length === 0 && !drafting ? (
          <AdminFilteredEmptyState hidden={all.length} onClear={() => setParam('q', undefined)} />
        ) : (
          <PolicyEditor
            key={selected?.id ?? 'draft'}
            baseline={selected}
            initial={selected ?? DRAFT}
            simulate={simulateFromFixture}
            readOnly={readOnly}
          />
        )}
      </div>
    </div>
  );
}
