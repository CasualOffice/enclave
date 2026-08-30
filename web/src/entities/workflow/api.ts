import { useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { request } from '../../shared/api/client.ts';

/* Deciding a workflow step (`docs/05-API.md §16`, `ENC-968`).
 *
 * `GET /workflows/tasks` has been read by Home since `ENC-739` and its actions
 * have rendered `unbuilt` ever since: a task could be *seen* and not acted on.
 * The endpoints were always there and always worked. What was missing until
 * `ENC-965` was any way to author a definition — so no task could exist to act
 * on, and the chip was honest about a surface with nothing behind it.
 *
 * In `entities/` rather than `features/home/` because a decision is a property
 * of a workflow step, not of the Home screen, and a second surface will want it
 * the moment anything else lists tasks. `docs/17 §2` forbids a feature importing
 * another; `entities/favorite` moved down for the same reason (`ENC-959`).
 */

/** The two decisions this client can take. `SIGNATURE` steps belong to `crates/signing`. */
export type Decision = 'approve' | 'reject';

/**
 * Approving and rejecting, as one hook.
 *
 * **Not optimistic**, and this is the clearest case in the client for that rule.
 * `docs/17` Q25 forbids optimism for anything touching access, and a decision
 * does more: an approval advances a stage for everybody, and a rejection
 * **terminates the instance** for everybody. A row that animated away and then
 * failed would tell somebody they had approved a document they had not.
 *
 * The comment is required on a rejection and optional on an approval, and the
 * asymmetry is the server's (`docs/05 §16`): a rejection ends the workflow for
 * every participant, and *"rejected, no reason given"* is the state a workflow
 * exists to avoid.
 */
export function useDecide(): {
  decide: (stepId: string, decision: Decision, comment?: string) => void;
  pendingId: string | undefined;
  failedId: string | undefined;
} {
  const client = useQueryClient();
  const mutation = useMutation({
    mutationFn: ({
      stepId,
      decision,
      comment,
    }: {
      stepId: string;
      decision: Decision;
      /* `string | undefined` rather than `comment?:` — the project runs
       * `exactOptionalPropertyTypes`, which distinguishes an absent key from a
       * present `undefined`, and the caller passes the latter. */
      comment: string | undefined;
    }) =>
      request(`/workflows/steps/${encodeURIComponent(stepId)}/${decision}`, z.unknown(), {
        method: 'POST',
        body: comment === undefined ? {} : { comment },
      }),
    onSuccess: () => {
      /* The task leaves the list, and the server decides what the list now
       * contains — an approval may open the next stage's steps, which are rows
       * this client has never seen. Splicing one out would be guessing at a set
       * the engine computes. */
      void client.invalidateQueries({ queryKey: ['workflows', 'tasks'] });
    },
  });

  return {
    decide: (stepId, decision, comment) => mutation.mutate({ stepId, decision, comment }),
    pendingId: mutation.isPending ? mutation.variables?.stepId : undefined,
    failedId: mutation.isError ? mutation.variables?.stepId : undefined,
  };
}
