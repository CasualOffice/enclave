import { z } from 'zod';
import type { MessageKey } from '../../shared/i18n/catalog.ts';

/* Why a capability the server reported as `false` is `false` (`ENC-674`).
 *
 * ## What this file is allowed to do, and what it is not
 *
 * `CLAUDE.md`: *render actions from the server-provided `capabilities` object —
 * never re-derive permissions client side.* Nothing here decides anything. The
 * server has already decided, twice: once when it answered `false`, and once
 * when it named the code that made it `false`. This file turns that code into a
 * sentence and does no other work.
 *
 * The distinction matters because it is easy to lose. Choosing *which* of two
 * sentences to show based on a rule the client evaluated would be re-deriving
 * the decision in a costume. Choosing which sentence based on a code the server
 * sent is rendering it. Everything below is keyed on `code` and on nothing else
 * — no file state, no user role, no classification, no second opinion.
 *
 * ## Why the wording is the client's and the decision is not
 *
 * `docs/14-I18N-L10N.md §5`: *"The API returns a stable `code` plus an English
 * default; the client renders its own localized string keyed by `code`. This
 * keeps the API locale-independent and the client authoritative for wording."*
 * So the sentence lives in the catalog, is translated with the rest of the
 * product, and reaches a user in their own language rather than in the server's.
 *
 * The server sends no sentence at all here — see `crates/api/src/error.rs`.
 * There is nothing to accidentally prefer over the catalog.
 *
 * ## Why an unknown code is not a parse failure
 *
 * `entities/file/api-model.ts` argues, correctly, that a capability boolean the
 * server stops sending must be a parse failure rather than an `undefined` that
 * renders as *refused*. This field is the other case and takes the other answer.
 *
 * A code this build has never heard of is not a missing field — it is a newer
 * server naming a reason this client cannot phrase yet. Refusing to parse would
 * take down the whole listing over a sentence, and the boolean beside it is
 * still perfectly readable: the control is denied either way, and the only thing
 * lost is the specificity of the explanation. So an unrecognised code degrades
 * to the generic sentence, which restates the boolean and asserts nothing about
 * policy. `docs/06 §24` is satisfied by a stable code the user can quote to an
 * administrator, and the code is still on the wire whether or not this build has
 * a phrasing for it.
 */

/**
 * The reason codes of `docs/05-API.md §5`, as `enclave_core::ReasonCode` spells
 * them.
 *
 * Listed in full rather than narrowed to the ones a capability can currently
 * carry. The server's enumeration is deliberately not `#[non_exhaustive]` so
 * that adding a reason forces every mapping to be revisited; mirroring the whole
 * set here means the same edit is visible on this side, instead of a new code
 * silently landing in the fallback.
 */
export const ReasonCode = z.enum([
  'ACCESS_DENIED',
  'DOWNLOAD_BLOCKED_BY_POLICY',
  'EXTERNAL_SHARE_BLOCKED',
  'PREVIEW_ONLY',
  'NETWORK_NOT_ALLOWED',
  'DEVICE_NOT_MANAGED',
  'STEP_UP_REQUIRED',
  'DLP_BLOCKED',
  'DLP_JUSTIFICATION_REQUIRED',
  'DLP_APPROVAL_REQUIRED',
  'CLASSIFICATION_CEILING',
  'LEGAL_HOLD_ACTIVE',
  'RETENTION_BLOCKS_DELETE',
  'RECORD_IMMUTABLE',
  'QUOTA_EXCEEDED',
  'SYNC_NOT_PERMITTED',
  'MALWARE_DETECTED',
  'SESSION_REPLAY',
]);

export type ReasonCode = z.infer<typeof ReasonCode>;

/**
 * `capabilityReasons` as it arrives: capability name → reason code.
 *
 * `z.string()` for the value and not `ReasonCode`, for the reason in the header
 * — an unrecognised code must not fail the parse. The narrowing happens at
 * lookup, where the fallback is available.
 *
 * A key that is not a capability name is simply never asked for. The object is
 * indexed by the caller with the same key it read `capabilities` from, so a
 * stray entry cannot render anything.
 */
export const CapabilityReasons = z.record(z.string(), z.string());

export type CapabilityReasons = z.infer<typeof CapabilityReasons>;

/**
 * The catalog key for every reason code this build can phrase.
 *
 * Written out rather than derived as `` `denial.${code}` ``, because a derived
 * key is invisible to `tools/lint-web.mjs` — it scans for quoted dotted
 * identifiers, so a template literal would make all eighteen keys read as
 * unreferenced *and* let a missing one reach a user as `[missing key]`. Spelling
 * them out makes the catalog check load-bearing in both directions.
 *
 * The keys are camelCase rather than the wire code's `SCREAMING_SNAKE`, which
 * costs the eye a moment here and buys two things. It is the convention every
 * other key in the catalog follows — `docs/14 §4` wants keys that are not
 * derived from displayed text, not keys that mirror a transport spelling — and
 * an underscore is outside the identifier `lint-web.mjs` recognises, so a
 * `SCREAMING_SNAKE` key would be reported as an orphan on every run while being
 * referenced from this very table. This table is where the two spellings are
 * reconciled, once.
 */
const REASON_MESSAGE: Record<ReasonCode, MessageKey> = {
  ACCESS_DENIED: 'denial.accessDenied',
  DOWNLOAD_BLOCKED_BY_POLICY: 'denial.downloadBlockedByPolicy',
  EXTERNAL_SHARE_BLOCKED: 'denial.externalShareBlocked',
  PREVIEW_ONLY: 'denial.previewOnly',
  NETWORK_NOT_ALLOWED: 'denial.networkNotAllowed',
  DEVICE_NOT_MANAGED: 'denial.deviceNotManaged',
  STEP_UP_REQUIRED: 'denial.stepUpRequired',
  DLP_BLOCKED: 'denial.dlpBlocked',
  DLP_JUSTIFICATION_REQUIRED: 'denial.dlpJustificationRequired',
  DLP_APPROVAL_REQUIRED: 'denial.dlpApprovalRequired',
  CLASSIFICATION_CEILING: 'denial.classificationCeiling',
  LEGAL_HOLD_ACTIVE: 'denial.legalHoldActive',
  RETENTION_BLOCKS_DELETE: 'denial.retentionBlocksDelete',
  RECORD_IMMUTABLE: 'denial.recordImmutable',
  QUOTA_EXCEEDED: 'denial.quotaExceeded',
  SYNC_NOT_PERMITTED: 'denial.syncNotPermitted',
  MALWARE_DETECTED: 'denial.malwareDetected',
  SESSION_REPLAY: 'denial.sessionReplay',
};

/**
 * The sentence for a code, or the generic one when the code is absent or
 * unrecognised.
 *
 * The fallback is deliberately a restatement of the boolean — *this action is
 * not available to you* — and never a guess at a reason. It is the same answer
 * `DeniedPanel` gives a denial that arrives without a message, for the same
 * reason: a client that invents an explanation is wrong at exactly the moment
 * it matters, when two different rules could have produced the same `false`.
 */
export function reasonMessage(code: string | undefined): MessageKey {
  const parsed = ReasonCode.safeParse(code);
  return parsed.success ? REASON_MESSAGE[parsed.data] : 'denial.unspecified';
}
