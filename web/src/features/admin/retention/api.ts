import { z } from 'zod';
import { request } from '../../../shared/api/client.ts';
import { RetentionView, type PolicyDraft } from './model.ts';

/* `docs/05 §14`, implemented by `ENC-943`.
 *
 * **Unlike `dlp/api.ts`, the write path is here.** DLP declined to ship one
 * because writing needs recent multi-factor authentication and no step-up flow
 * exists. That reasoning is right for DLP and reaches a different answer here,
 * for a reason worth stating rather than inheriting: step-up is
 * `security.mfa.admins_required`, which is **off by default**, so on an
 * ordinary deployment these writes complete — proved end to end against the
 * running binary in `ENC-943`. Where it is on, the server answers `403
 * STEP_UP_REQUIRED` and the screen renders that as the refusal it is, with no
 * retry (`docs/17 §7` F3).
 *
 * Shipping nothing would have been the safer-looking choice and the wrong one:
 * it would leave the surface `ENC-943` built reachable by `curl` alone, which
 * is the failure that row was opened to close.
 */

export const RETENTION_PATH = '/admin/retention/policies';

export const retentionQueryKey = ['admin', 'retention'] as const;

/* The three mutations answer with three different bodies — a `PolicyView`, an
 * empty `201`, and a `204` with nothing at all — and this screen reads none of
 * them: it invalidates and refetches, because the server decides what the list
 * now contains and splicing a response into it would be the client deciding.
 *
 * So the schema is `unknown` rather than three shapes kept in step with three
 * handlers for a value nothing consumes. That is a narrow claim and not a
 * licence: the `GET` is parsed strictly, which is where a drift between server
 * and client would actually mislead somebody.
 */
const IGNORED = z.unknown();

export async function fetchRetention(signal: AbortSignal): Promise<RetentionView> {
  return request(RETENTION_PATH, RetentionView, { signal });
}

export async function createPolicy(draft: PolicyDraft): Promise<void> {
  /* `durationDays` is omitted rather than sent as null when absent: the
   * endpoint's `deny_unknown_fields` accepts the absence and the schema refuses
   * a duration on an action that must not carry one. */
  const body: Record<string, unknown> = {
    name: draft.name,
    action: draft.action,
    basis: draft.basis,
    isRecord: draft.isRecord,
    allowUserDelete: draft.allowUserDelete,
  };
  if (draft.durationDays !== null) body['durationDays'] = draft.durationDays;
  await request(RETENTION_PATH, IGNORED, { method: 'POST', body });
}

export async function assignPolicy(
  policyId: string,
  scopeType: string,
  scopeId: string | null,
): Promise<void> {
  const body: Record<string, unknown> = { scopeType };
  if (scopeId !== null) body['scopeId'] = scopeId;
  await request(`${RETENTION_PATH}/${encodeURIComponent(policyId)}/assignments`, IGNORED, {
    method: 'POST',
    body,
  });
}

export async function withdrawAssignment(
  policyId: string,
  scopeType: string,
  scopeId: string | null,
): Promise<void> {
  const query = new URLSearchParams({ scopeType });
  if (scopeId !== null) query.set('scopeId', scopeId);
  await request(
    `${RETENTION_PATH}/${encodeURIComponent(policyId)}/assignments?${query.toString()}`,
    IGNORED,
    { method: 'DELETE' },
  );
}
