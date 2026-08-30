import { z } from 'zod';

/* The retention surface's wire shapes (`docs/05 §14`, `ENC-945`).
 *
 * **The vocabularies are not enumerated here, deliberately.** `GET
 * /admin/retention/policies` returns `vocabulary.actions`, `.bases` and
 * `.scopeTypes` from the stored enumerations, and `ENC-943` put them on the
 * wire for exactly this reason: a `z.enum([...])` in this file would be a
 * second copy of `migrations/0031`'s CHECK constraints, free to drift, and the
 * drift would surface as a row the client refuses to parse — which is
 * `ENC-929`, where a `strictObject` two fields behind the server made every
 * library row fail and the screen drew its failure state against a healthy
 * one. `z.string()` here is not laxity; it is the client declining to hold an
 * opinion the server is authoritative about.
 *
 * What is still strict is the *shape*. Unknown fields are refused, because a
 * response that has grown a field this screen ignores is a response this screen
 * is rendering incompletely.
 */

export const RetentionPolicy = z.strictObject({
  id: z.string().uuid(),
  name: z.string(),
  action: z.string(),
  durationDays: z.number().int().nullable(),
  basis: z.string(),
  eventKey: z.string().nullable(),
  isRecord: z.boolean(),
  allowUserDelete: z.boolean(),
  createdAt: z.string(),
});
export type RetentionPolicy = z.infer<typeof RetentionPolicy>;

export const RetentionAssignment = z.strictObject({
  policyId: z.string().uuid(),
  scopeType: z.string(),
  scopeId: z.string().uuid().nullable(),
  appliedAt: z.string(),
  expiresAt: z.string().nullable(),
  /* Computed by the server against *its* clock, not derived here from
   * `expiresAt`. Three clients each comparing a timestamp to their own clock is
   * three chances to disagree with the governing read, which compares against
   * the database's. */
  live: z.boolean(),
});
export type RetentionAssignment = z.infer<typeof RetentionAssignment>;

export const RetentionVocabulary = z.strictObject({
  actions: z.array(z.string()),
  bases: z.array(z.string()),
  scopeTypes: z.array(z.string()),
});
export type RetentionVocabulary = z.infer<typeof RetentionVocabulary>;

export const RetentionView = z.strictObject({
  policies: z.array(RetentionPolicy),
  assignments: z.array(RetentionAssignment),
  vocabulary: RetentionVocabulary,
});
export type RetentionView = z.infer<typeof RetentionView>;

/** A policy as this screen submits one. */
export interface PolicyDraft {
  readonly name: string;
  readonly action: string;
  readonly durationDays: number | null;
  readonly basis: string;
  readonly isRecord: boolean;
  readonly allowUserDelete: boolean;
}

/* The two actions the server's `retention_policies_duration_required`
 * constraint refuses without a duration.
 *
 * A client-side copy of a server rule, and the one place this file permits one
 * — with a bounded justification. It decides only whether the *duration field
 * is shown*, never whether the request is sent: a draft this list gets wrong is
 * still submitted and still refused by the constraint, with the constraint's
 * own sentence. So the cost of drift here is a field in the wrong place for one
 * release, not a policy stored that should not have been.
 */
export const NEEDS_DURATION: readonly string[] = ['KEEP_THEN_DELETE', 'DELETE_AFTER'];

/* The two actions `retention_policies_hold_is_absolute` refuses to let a user
 * delete under. Same bounded role: it disables a checkbox, and the server still
 * decides. */
export const ABSOLUTE: readonly string[] = ['LEGAL_HOLD', 'RECORD'];
