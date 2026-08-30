import { z } from 'zod';

/* The audit reader's wire shape (`docs/05 §14`, `ENC-961`).
 *
 * **Nothing here is an enumeration, deliberately** — the same reasoning
 * `retention/model.ts` sets out, and it applies harder on this surface. An
 * audit log holds the spelling that was written *at the time*: verbs the
 * vocabulary has since renamed, and outcomes from a build that predates this
 * one. A `z.enum([...])` in this file would refuse to parse the rows an
 * investigation most wants — the old ones — and would surface as an empty page
 * rather than an error anybody could act on. `z.string()` is the client
 * declining to hold an opinion about a record it did not write.
 *
 * The *shape* is still strict. A response that has grown a field this screen
 * ignores is a response this screen is rendering incompletely, and on this
 * surface an incompletely rendered row is a fact withheld from an auditor.
 */

export const AuditRow = z.strictObject({
  id: z.string().uuid(),
  sequence: z.number().int(),
  occurredAt: z.string(),
  actorType: z.string(),
  actorId: z.string().nullable(),
  /* `null` for every service account, MCP client, link bearer and system
   * action. Rendered as *"somebody"*, never as the identifier (`ENC-958`). */
  actorName: z.string().nullable(),
  onBehalfOf: z.string().nullable(),
  action: z.string(),
  resourceType: z.string().nullable(),
  resourceId: z.string().nullable(),
  workspaceId: z.string().nullable(),
  outcome: z.string(),
  reasonCode: z.string().nullable(),
  policyRefs: z.array(z.unknown()),
  requestId: z.string(),
  sessionId: z.string().nullable(),
  clientType: z.string().nullable(),
  deviceId: z.string().nullable(),
  ip: z.string().nullable(),
  country: z.string().nullable(),
  userAgent: z.string().nullable(),
  detail: z.unknown(),
  previousHash: z.string().nullable(),
  eventHash: z.string().nullable(),
});
export type AuditRow = z.infer<typeof AuditRow>;

export const AuditPage = z.strictObject({
  items: z.array(AuditRow),
  nextCursor: z.string().nullable(),
});
export type AuditPage = z.infer<typeof AuditPage>;

/** What the caller is asking the log. Every field narrows; absent means all. */
export interface AuditFilter {
  readonly outcome: string | undefined;
  readonly action: string | undefined;
  readonly actor: string | undefined;
  readonly before: string | undefined;
}

/* The three outcomes, as the server spells them. A literal list here rather
 * than a server-provided vocabulary — unlike retention's actions, which come
 * down the wire — because these three are the `outcome` column's CHECK
 * constraint and the policy engine's own enum, and neither grows without a
 * migration this screen would be rebuilt for. */
export const OUTCOMES = ['ALLOW', 'DENY', 'ERROR'] as const;
