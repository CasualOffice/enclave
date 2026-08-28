import type { MessageKey } from '../../shared/i18n/catalog.ts';
import type { VersionEntry } from '../file/api-model.ts';

/* Truthful progress (`docs/09 §8`), and the one rule that shapes it.
 *
 * ```
 * Queued -> Hashing -> Uploading -> Scanning -> Processing -> Indexing -> Ready
 * ```
 *
 * Failure states: Quarantined, Failed, Aborted, Quota Exceeded, Refused.
 *
 * **`CLAUDE.md` rule 9 is the whole design here.** Nothing is `AVAILABLE`
 * before antivirus completes, and no read path serves `SCANNING` content — so
 * a row may not read *Ready* until the server says the bytes can actually be
 * served. The client does not decide that and does not compute it: the server
 * publishes `isReadable` on every version and this file reads it.
 *
 * ## Why `isReadable` and not `status`
 *
 * This is the trap, and it is live on the development stack. With
 * `antivirus.provider: none` and `unsupported_policy: ALLOW_WITH_FLAG` a
 * completed upload settles at:
 *
 *     status = AVAILABLE     av_status = SKIPPED     isReadable = false
 *
 * `AVAILABLE` there means *the version was published*; it does not mean the
 * content was scanned, and `SKIPPED` is emphatically not `CLEAN`. Verified by
 * hand: that exact version answers `404` on both `/preview` and `/thumbnail`.
 * A client that read `status === 'AVAILABLE'` as *Ready* would put a green tick
 * on a file the product refuses to serve, which is the precise lie rule 9
 * exists to prevent.
 *
 * **Three endpoints answer it now, and this comment used to say one did.**
 * `GET /files/{id}/versions` always has. `GET /files/{id}`'s `currentVersion`
 * gained `avStatus` and `isReadable` with `ENC-825`, and `GET /uploads/{id}`
 * gained the committed version and `fileId` with `ENC-826` — both on
 * 2026-08-28, both named in `docs/05 §7` and `§8.1`. The tray still polls the
 * version listing; that is now a choice rather than the only option, and moving
 * it is `ENC-848`. The sentence is corrected here because a stale justification
 * for a workaround is how the next reader concludes the workaround is still
 * load-bearing.
 *
 * What has **not** changed is the rule: branch on `isReadable`, never on
 * `status === 'AVAILABLE'`, whichever of the three you read it from.
 *
 * ## Hashing is a phase, not a detail
 *
 * `docs/09 §8`'s list starts at `Uploading`, and a large file spends real time
 * being read and digested before a byte is sent. Folding that into `Queued`
 * would leave a row apparently stalled for a minute; folding it into
 * `Uploading` would report bytes as sent that are not. It is its own phase for
 * the same reason every other one is.
 */

export type UploadPhase =
  | 'queued'
  | 'hashing'
  | 'uploading'
  | 'scanning'
  | 'processing'
  | 'indexing'
  | 'ready'
  /** The scanner found something, or refused to admit unscanned content. Terminal. */
  | 'quarantined'
  /** The transfer or a call failed. Retryable. */
  | 'failed'
  /** The user cancelled it. Terminal, and not an error. */
  | 'aborted'
  /** The policy chain refused the upload. Terminal, and **not** a failure (`docs/17 §7`). */
  | 'refused';

/** Phases where work is still happening, so the tray knows whether to keep polling. */
export function isSettled(phase: UploadPhase): boolean {
  return (
    phase === 'ready' ||
    phase === 'quarantined' ||
    phase === 'failed' ||
    phase === 'aborted' ||
    phase === 'refused'
  );
}

/**
 * Whether a phase is one the server is still working through.
 *
 * Distinguished from `isSettled` because *aborted* and *refused* are settled
 * without ever having been in flight, and the tray's aggregate count is about
 * work outstanding rather than about rows that have stopped changing.
 */
export function isActive(phase: UploadPhase): boolean {
  return !isSettled(phase);
}

export const PHASE_LABEL: Record<UploadPhase, MessageKey> = {
  queued: 'upload.phase.queued',
  hashing: 'upload.phase.hashing',
  uploading: 'upload.phase.uploading',
  scanning: 'upload.phase.scanning',
  processing: 'upload.phase.processing',
  indexing: 'upload.phase.indexing',
  ready: 'upload.phase.ready',
  quarantined: 'upload.phase.quarantined',
  failed: 'upload.phase.failed',
  aborted: 'upload.phase.aborted',
  refused: 'upload.phase.refused',
};

/**
 * The tone a phase is drawn in.
 *
 * `refused` is **neutral, not danger** — `docs/17 §7`: a policy denial is a
 * successful request with a refusing answer, and painting it the same red as a
 * transfer failure is how a user learns to read "you may not" as "it broke".
 * `quarantined` is danger because it is a statement about the content.
 */
export type PhaseTone = 'progress' | 'ok' | 'danger' | 'neutral';

export const PHASE_TONE: Record<UploadPhase, PhaseTone> = {
  queued: 'progress',
  hashing: 'progress',
  uploading: 'progress',
  scanning: 'progress',
  processing: 'progress',
  indexing: 'progress',
  ready: 'ok',
  quarantined: 'danger',
  failed: 'danger',
  aborted: 'neutral',
  refused: 'neutral',
};

/**
 * Read a phase off the version the server published.
 *
 * The only place a post-`complete` phase is decided, and it consults
 * `isReadable` rather than reconstructing it from `status` and `avStatus` — the
 * same rule as `capabilities`, and the same reason: two authorities drift, and
 * the drift here would be a green tick on unservable content.
 *
 * `PENDING` maps to `scanning` rather than to a phase of its own: from a user's
 * point of view a version awaiting its first scan and one being scanned are the
 * same wait, and `docs/09 §8`'s vocabulary has no word for the difference.
 */
export function phaseFromVersion(version: VersionEntry): UploadPhase {
  if (version.status === 'QUARANTINED') return 'quarantined';
  if (version.status === 'FAILED') return 'failed';
  if (version.status === 'PROCESSING') return 'processing';
  if (version.status === 'PENDING' || version.status === 'SCANNING') return 'scanning';

  /* `AVAILABLE`. The published-but-unscanned case lands here, and it is the one
   * that must not read as Ready. `isReadable` is the server's own answer to
   * "may these bytes be served", computed from
   * `status = 'AVAILABLE' AND av_status = 'CLEAN'`. */
  return version.isReadable ? 'ready' : 'scanning';
}

/**
 * Why a published version is still not readable, for the row's subtitle.
 *
 * Returns a catalog key or `undefined` when there is nothing extra to say. This
 * is the one place the client explains a *product* condition rather than a
 * policy one, and it is safe to do so because `avStatus` is a fact about
 * processing that the server sent, not a permission being re-derived.
 */
export function unreadableNote(version: VersionEntry): MessageKey | undefined {
  if (version.isReadable) return undefined;
  if (version.status !== 'AVAILABLE') return undefined;
  /* Published, not clean. `SKIPPED` means no engine inspected the content;
   * `ERROR` means one tried and could not. Both are honest to say out loud, and
   * neither is a permission. */
  if (version.avStatus === 'SKIPPED') return 'upload.note.unscanned';
  if (version.avStatus === 'ERROR') return 'upload.note.scanError';
  return 'upload.note.awaitingScan';
}
