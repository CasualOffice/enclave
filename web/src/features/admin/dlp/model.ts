import { z } from 'zod';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';

/* The DLP rule, in the vocabulary the server actually stores.
 *
 * `docs/05 §14.2` is the contract and it is unusually strict about spelling:
 * **`scope` and `conditions` are the stored vocabulary, `snake_case`**, carried
 * verbatim and decoded by the same function the policy chain runs on every
 * request. So this module keeps the wire spelling as the type, and maps it to a
 * catalog key for display — a second, prettier spelling at the edge would be a
 * second vocabulary that can drift, and the drift would be silent.
 *
 * Three things the prototype's builder draws have **no field in this contract**,
 * and they are marked `unbuilt` on the screen rather than drawn as if they
 * worked:
 *
 *   1. A per-policy *mode* ("Simulation" / "Enable · Enforce"). `docs/05 §14.2`:
 *      "There is no `mode` field, and a body carrying one is rejected." A DLP
 *      rule has no per-rule mode by construction; the mode is deployment
 *      configuration. A body field accepted and ignored would be an
 *      administrator believing a rule rehearses while it decides.
 *   2. A per-policy denial *sentence*. `docs/14 §5`: the API returns a stable
 *      `code` and the client renders its own localized string keyed by that
 *      code. A tenant-authored sentence is untranslatable, and §14.2 has no
 *      field to put it in.
 *   3. A *where* clause — "whole tenant except Legal / Deal room". A rule has a
 *      `scope` of actions and nothing that narrows it to a library.
 *
 * Zod strips unknown keys by default, and that default is load-bearing here: a
 * server that ever put a matched value on a rule or a simulation event would
 * have it dropped at this boundary rather than carried into a component that
 * could render it (`CLAUDE.md` rule 10).
 */

export const DlpScope = z.enum([
  'external_sharing',
  'public_link',
  'download',
  'export',
  'print',
  'sync',
  'exposes_content',
]);
export type DlpScope = z.infer<typeof DlpScope>;

/** Detector *categories*, never detector output. A category is a term; a match is a secret. */
export const DlpCategory = z.enum([
  'PAYMENT_CARD',
  'AADHAAR',
  'API_KEY',
  'BANK_ACCOUNT',
  'HEALTH_ID',
  'CREDENTIAL',
]);
export type DlpCategory = z.infer<typeof DlpCategory>;

export const DlpAction = z.enum([
  'BLOCK',
  'QUARANTINE',
  'WARN',
  'AUDIT',
  'REQUIRE_JUSTIFICATION',
  'REQUIRE_APPROVAL',
  'NO_DOWNLOAD',
  'READ_ONLY',
  'WATERMARK',
  'NOTIFY_SECURITY',
  'REMOVE_SHARE',
]);
export type DlpAction = z.infer<typeof DlpAction>;

/** The five ranked levels. `unclassified` is an absence and cannot be a threshold. */
export const DlpClassification = z.enum([
  'public',
  'internal',
  'confidential',
  'highlyConfidential',
  'restricted',
]);
export type DlpClassification = z.infer<typeof DlpClassification>;

/* `docs/05 §14.2`: **`conditions` is closed.** Every condition is a comparison
 * against a count, a rank, a severity or a score; there is no variant a
 * *pattern* could occupy, so no regex reaches the synchronous path. The union
 * being closed here is what stops the builder growing a free-text condition. */
export const DlpCondition = z.union([
  z.object({
    category_at_least: z.object({ category: DlpCategory, count: z.number().int().min(1) }),
  }),
  z.object({
    classification_at_least: z.object({ classification: DlpClassification }),
  }),
]);
export type DlpCondition = z.infer<typeof DlpCondition>;

export const DlpRule = z.object({
  id: z.string(),
  name: z.string(),
  priority: z.number().int().min(0),
  /** May not be empty: an empty scope governs nothing (`docs/05 §14.2`). */
  scope: z.array(DlpScope).min(1),
  /** `[]` is legitimate and means "whenever the action is governed". */
  conditions: z.array(DlpCondition),
  action: DlpAction,
  /** `false` for a row written by a repair script that the evaluator can no longer read. */
  decodes: z.boolean(),
  decodeError: z.string().optional(),
});
export type DlpRule = z.infer<typeof DlpRule>;

export const DlpRuleList = z.object({
  items: z.array(DlpRule),
  page: z.object({ nextCursor: z.string().nullable(), hasMore: z.boolean() }),
});
export type DlpRuleList = z.infer<typeof DlpRuleList>;

/* ------------------------------------------------------------------ simulation
 *
 * `docs/05 §14` names `/admin/dlp/simulate` and says only that a simulation
 * endpoint "accepts a proposed policy plus a sample set or a historical time
 * range and returns the decisions that would have been made, with no side
 * effects". The request and response shapes are **not written down anywhere**,
 * so this is a local shape and `fixture.ts` is a local fixture. When `05` grows
 * the contract, this schema is what changes and nothing above it does.
 *
 * The shape has no field a matched value could occupy. That is the point:
 * `docs/09 §9` says explain in category terms, `CLAUDE.md` rule 10 says never a
 * DLP match value, and the cheapest way to hold both is to make the value
 * unrepresentable rather than merely unrendered.
 */

export const SimulationEvent = z.object({
  actorName: z.string(),
  actorInitials: z.string(),
  actorTone: z.enum(['a', 'b', 'c', 'd']),
  scope: DlpScope,
  /** The document's title. A title is metadata; its contents are not. */
  resource: z.string(),
  at: z.string(),
  /** Categories only. There is deliberately no `sample`, `match` or `excerpt`. */
  categories: z.array(DlpCategory),
});
export type SimulationEvent = z.infer<typeof SimulationEvent>;

export const SimulationResult = z.object({
  windowDays: z.number().int().positive(),
  ranAt: z.string(),
  wouldRefuse: z.number().int().nonnegative(),
  attempts: z.number().int().nonnegative(),
  people: z.number().int().nonnegative(),
  /** The blast radius `docs/09 §21` asks for, stated before applying rather than after. */
  files: z.number().int().nonnegative(),
  libraries: z.number().int().nonnegative(),
  byWorkspace: z.array(z.object({ workspace: z.string(), count: z.number().int().nonnegative() })),
  events: z.array(SimulationEvent),
});
export type SimulationResult = z.infer<typeof SimulationResult>;

/* ------------------------------------------------------------- display mapping
 *
 * A wire value maps to a catalog key and to nothing else. There is no other way
 * for a component to get the word, which is how `CLAUDE.md` rule 12 survives a
 * vocabulary that grows.
 */

export const SCOPE_KEY: Record<DlpScope, MessageKey> = {
  external_sharing: 'admin.dlp.scope.externalSharing',
  public_link: 'admin.dlp.scope.publicLink',
  download: 'admin.dlp.scope.download',
  export: 'admin.dlp.scope.export',
  print: 'admin.dlp.scope.print',
  sync: 'admin.dlp.scope.sync',
  exposes_content: 'admin.dlp.scope.exposesContent',
};

export const CATEGORY_KEY: Record<DlpCategory, MessageKey> = {
  PAYMENT_CARD: 'admin.dlp.category.paymentCard',
  AADHAAR: 'admin.dlp.category.aadhaar',
  API_KEY: 'admin.dlp.category.apiKey',
  BANK_ACCOUNT: 'admin.dlp.category.bankAccount',
  HEALTH_ID: 'admin.dlp.category.healthId',
  CREDENTIAL: 'admin.dlp.category.credential',
};

export const ACTION_KEY: Record<DlpAction, MessageKey> = {
  BLOCK: 'admin.dlp.action.block',
  QUARANTINE: 'admin.dlp.action.quarantine',
  WARN: 'admin.dlp.action.warn',
  AUDIT: 'admin.dlp.action.audit',
  REQUIRE_JUSTIFICATION: 'admin.dlp.action.requireJustification',
  REQUIRE_APPROVAL: 'admin.dlp.action.requireApproval',
  NO_DOWNLOAD: 'admin.dlp.action.noDownload',
  READ_ONLY: 'admin.dlp.action.readOnly',
  WATERMARK: 'admin.dlp.action.watermark',
  NOTIFY_SECURITY: 'admin.dlp.action.notifySecurity',
  REMOVE_SHARE: 'admin.dlp.action.removeShare',
};

/**
 * What a refused caller is told, keyed by the **stable reason code**.
 *
 * `docs/06 §24` and `docs/14 §5`: the code is the API's and is stable; the
 * sentence and the remedy are the *client's*, keyed by that code, so wording
 * and translation are ours and the API stays locale-independent. This map is
 * therefore the only place a denial sentence comes from — an administrator
 * cannot author one, and nothing on this screen composes one.
 */
export interface DenialCopy {
  readonly code: string;
  readonly message: MessageKey;
  readonly remediation: MessageKey;
}

const BLOCKED: DenialCopy = {
  code: 'DLP_BLOCKED',
  message: 'admin.dlp.denial.blocked.message',
  remediation: 'admin.dlp.denial.blocked.remediation',
};

const JUSTIFICATION: DenialCopy = {
  code: 'DLP_JUSTIFICATION_REQUIRED',
  message: 'admin.dlp.denial.justification.message',
  remediation: 'admin.dlp.denial.justification.remediation',
};

const APPROVAL: DenialCopy = {
  code: 'DLP_APPROVAL_REQUIRED',
  message: 'admin.dlp.denial.approval.message',
  remediation: 'admin.dlp.denial.approval.remediation',
};

/** `undefined` for the effects that modify a request rather than refuse it. */
export function denialFor(action: DlpAction): DenialCopy | undefined {
  switch (action) {
    case 'BLOCK':
    case 'QUARANTINE':
      return BLOCKED;
    case 'REQUIRE_JUSTIFICATION':
      return JUSTIFICATION;
    case 'REQUIRE_APPROVAL':
      return APPROVAL;
    default:
      return undefined;
  }
}

/**
 * `docs/06 §9`: "Simulation is mandatory before enforcement for any policy whose
 * effect is `BLOCK` or `QUARANTINE`. The admin UI refuses to enable enforcement
 * on a policy that has never been simulated." This predicate is that sentence,
 * and the gate in `policy-editor.tsx` is the refusal.
 */
export function requiresSimulation(action: DlpAction): boolean {
  return action === 'BLOCK' || action === 'QUARANTINE';
}

/** The rule as it goes on the wire: the `POST` body of `docs/05 §14.2`, and nothing else. */
export function toWire(rule: DlpRule): Record<string, unknown> {
  return {
    name: rule.name,
    priority: rule.priority,
    scope: rule.scope,
    conditions: rule.conditions,
    action: rule.action,
  };
}

/**
 * The identity of *what was rehearsed*.
 *
 * A simulation is a statement about one exact rule. Editing the rule after
 * simulating it leaves a result on screen that no longer describes the thing
 * about to be enforced, which is worse than no result — so the gate compares
 * this fingerprint and reopens when it changes.
 */
export function fingerprint(rule: DlpRule): string {
  return JSON.stringify(toWire(rule));
}

export function classificationOf(rule: DlpRule): DlpClassification | undefined {
  for (const condition of rule.conditions) {
    if ('classification_at_least' in condition) {
      return condition.classification_at_least.classification;
    }
  }
  return undefined;
}

export function categoriesOf(rule: DlpRule): DlpCategory[] {
  return rule.conditions.flatMap((condition) =>
    'category_at_least' in condition ? [condition.category_at_least.category] : [],
  );
}
