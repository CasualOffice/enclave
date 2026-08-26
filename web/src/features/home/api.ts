import { z } from 'zod';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { request } from '../../shared/api/client.ts';
import type { AttentionItem, AttentionKind } from './model.ts';

/* Home's one real read: `GET /api/v1/workflows/tasks`.
 *
 * ## The two endpoints Home is drawn against and does not have
 *
 * `specs/home.md` designs three independent sections, each with its own four
 * states. Only one of the three has an endpoint:
 *
 * - **Needs your attention** — `GET /api/v1/workflows/tasks`, registered and
 *   implemented. This file.
 * - **Continue working** — `GET /api/v1/me/recent`. Does not exist, and cannot
 *   be improvised: `specs/home.md` is explicit that it must **not** be derived
 *   from `audit_events`, which is hash-chained and deliberately not a
 *   user-facing feed (`CLAUDE.md` rule 10, `docs/17` Q24). It needs its own
 *   read model with its own policy filter. The section renders unbuilt.
 * - **Recent asks** — M7. Unbuilt.
 *
 * ## What the task payload does not carry
 *
 * `TaskView` is `{stepId, instanceId, fileId, versionId, stepType, stage,
 * stageName, delegated, dueAt?}`. It carries **no subject title, no requester
 * and no capabilities** — `specs/home.md` asks for all three, because the card
 * is drawn as "Priya asked you to approve <document>" with an Approve button
 * rendered from `task.capabilities.approve`.
 *
 * The file's name would need a second request per row; the requester is not on
 * the wire at all; and with no capability object the Approve button cannot be
 * rendered from one. `docs/17 §1` leaves exactly one honest option: show what
 * the server said, and leave the rest absent.
 */

const TaskView = z.object({
  stepId: z.string(),
  instanceId: z.string(),
  fileId: z.string(),
  versionId: z.string(),
  stepType: z.enum(['APPROVAL', 'REVIEW', 'SIGNATURE', 'TASK']),
  stage: z.number(),
  stageName: z.string(),
  delegated: z.boolean(),
  dueAt: z.string().optional(),
});

const TaskList = z.object({
  items: z.array(TaskView),
  page: z.object({
    nextCursor: z.string().nullish(),
    hasMore: z.boolean(),
  }),
});

export type TaskList = z.infer<typeof TaskList>;

/** The three step types Home draws differently. `TASK` is shown as a review. */
const KIND: Record<z.infer<typeof TaskView>['stepType'], AttentionKind> = {
  APPROVAL: 'approve',
  REVIEW: 'review',
  SIGNATURE: 'sign',
  TASK: 'review',
};

/**
 * One task, as the attention card wants it.
 *
 * `requesterName` and `requesterInitials` are **empty**, and the card draws no
 * avatar rather than a circle with two characters of a UUID in it. The subject
 * is the workflow stage's own name — the only human-readable string in the
 * payload — rather than a filename the endpoint does not send.
 */
export function attentionFromTask(task: z.infer<typeof TaskView>): AttentionItem {
  return {
    id: task.stepId,
    kind: KIND[task.stepType],
    subject: task.stageName,
    requesterName: '',
    requesterInitials: '',
    requesterTone: 'a',
    /* `dueAt` is a deadline, not an origin. Absent means the card shows no
     * timestamp — better than showing "now", which would say the request had
     * just arrived when nobody knows when it arrived. */
    requestedAt: task.dueAt === undefined ? 0 : Date.parse(task.dueAt),
  };
}

export function useTasks(): UseQueryResult<TaskList> {
  return useQuery({
    queryKey: ['workflows', 'tasks'],
    queryFn: ({ signal }) => request('/workflows/tasks', TaskList, { signal }),
    staleTime: 0,
    retry: false,
  });
}
