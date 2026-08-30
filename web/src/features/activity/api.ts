import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { z } from 'zod';
import { request } from '../../shared/api/client.ts';

/* `GET /me/activity` (`docs/05-API.md §7`, `ENC-960`).
 *
 * The first reader `audit_events` has ever had. It carries **changes only** —
 * no reads, no denials, and nothing about the actor's circumstances — and the
 * server enforces all three; this schema is strict so that a field the server
 * started sending would be a parse failure rather than something rendered by
 * accident.
 *
 * In `features/` rather than `entities/` because exactly one feature wants it.
 * `entities/favorite` moved down when a second did (`ENC-959`); moving this
 * before there is a second caller would be inventing a shared layer for one
 * consumer.
 */

const ActivityItem = z.strictObject({
  fileId: z.string(),
  name: z.string(),
  nodeType: z.enum(['FILE', 'FOLDER']),
  libraryId: z.string(),
  /* `family.verb`, as `acl_entries` and the audit log spell it. A string rather
   * than an enum: the server's list is `SHOWN_ACTIONS` and a client enum would
   * be a second copy that turns a newly-shown action into a parse failure —
   * every row of the feed refused because one verb was added. */
  action: z.string(),
  /** Opaque, and `null` for a principal with no user row. */
  actorId: z.string().nullable(),
  /**
   * Their display name, or `null` when the actor has no `users` row (`ENC-958`).
   *
   * `null` is not "Unknown": `system` and service accounts have no row, and the
   * row says "somebody" rather than naming a principal nobody provisioned.
   */
  actorName: z.string().nullable(),
  occurredAt: z.string(),
});

export const ActivityPage = z.strictObject({
  items: z.array(ActivityItem),
  /**
   * How many events the chain refused.
   *
   * Never *which* — rule 7, and the count matters more here than on the sibling
   * listings: an audit log is dominated by activity on content most callers
   * cannot see, so a feed showing three rows out of two hundred candidates is
   * working correctly and would otherwise look broken.
   */
  filteredCount: z.number(),
});

export type ActivityPage = z.infer<typeof ActivityPage>;
export type ActivityItem = z.infer<typeof ActivityItem>;

export function useActivity(): UseQueryResult<ActivityPage> {
  return useQuery({
    queryKey: ['activity'],
    queryFn: ({ signal }) => request('/me/activity', ActivityPage, { signal }),
    staleTime: 0,
    retry: false,
  });
}

/**
 * The catalog key for one recorded action.
 *
 * A lookup rather than a template, because each verb is its own sentence and a
 * translator needs to see all of them (`docs/14 §8`). An action the server shows
 * and this map does not know renders through `activity.action.other`, which is
 * deliberately vague rather than absent: a feed that dropped the row would hide
 * something that happened, and one that printed `file.share_external` would put
 * an internal identifier in front of a reader.
 */
export function sentenceFor(action: string): 'activity.action.edit' | 'activity.action.delete' |
  'activity.action.restore' | 'activity.action.move' | 'activity.action.copy' |
  'activity.action.permissions' | 'activity.action.share' | 'activity.action.other' {
  switch (action) {
    case 'file.edit':
      return 'activity.action.edit';
    case 'file.delete':
      return 'activity.action.delete';
    case 'file.restore':
      return 'activity.action.restore';
    case 'file.move':
      return 'activity.action.move';
    case 'file.copy':
      return 'activity.action.copy';
    case 'file.manage_permissions':
      return 'activity.action.permissions';
    case 'file.share':
    case 'file.share_external':
      return 'activity.action.share';
    default:
      return 'activity.action.other';
  }
}
