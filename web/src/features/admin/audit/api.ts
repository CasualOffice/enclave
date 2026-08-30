import { request } from '../../../shared/api/client.ts';
import { AuditPage, type AuditFilter } from './model.ts';

/* `GET /admin/audit` (`docs/05 §14`, built by `ENC-961`).
 *
 * **Read only, and not because a write path was deferred.** `audit_events` is
 * append-only by grant: `migrations/0002` gives `enclave_app` `SELECT` and
 * `INSERT` and revokes `UPDATE`, `DELETE` and `TRUNCATE`, so no administrator
 * can edit or erase their own tenant's trail. There is nothing here to write.
 *
 * `/admin/audit/verify` is the endpoint this module is missing, and its absence
 * is `ENC-969` rather than an oversight of this screen: `verify_tenant` and
 * `verify_chain` are implemented and called by nothing, so the product can show
 * an auditor what the table says and cannot yet show them that the table has
 * not been edited underneath.
 */

export const AUDIT_PATH = '/admin/audit';

/** Fifty. See `audit-screen.tsx` on why this screen pages rather than appends. */
export const PAGE_SIZE = 50;

/* The cursor is part of the key: each page is its own cache entry, so paging
 * back to a page already read is instant and does not re-ask the server for
 * rows that cannot have changed. An audit log is append-only, so a page below
 * the head is immutable — the one listing in this product where that is true.
 */
export function auditQueryKey(filter: AuditFilter) {
  return [
    'admin',
    'audit',
    filter.outcome ?? '',
    filter.action ?? '',
    filter.actor ?? '',
    filter.before ?? '',
  ] as const;
}

export async function fetchAudit(filter: AuditFilter, signal: AbortSignal): Promise<AuditPage> {
  const query = new URLSearchParams({ limit: String(PAGE_SIZE) });
  /* Absent rather than empty: the server refuses an unparseable narrowing
   * instead of dropping it, and `outcome=` is not a value it accepts. */
  if (filter.outcome !== undefined) query.set('outcome', filter.outcome);
  if (filter.action !== undefined) query.set('action', filter.action);
  if (filter.actor !== undefined) query.set('actor', filter.actor);
  if (filter.before !== undefined) query.set('before', filter.before);
  return request(`${AUDIT_PATH}?${query.toString()}`, AuditPage, { signal });
}
