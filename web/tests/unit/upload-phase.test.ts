import { describe, expect, it } from 'vitest';
import {
  PHASE_TONE,
  isActive,
  isSettled,
  phaseFromVersion,
  unreadableNote,
} from '../../src/entities/upload/model.ts';
import type { VersionEntry } from '../../src/entities/file/api-model.ts';

/* `CLAUDE.md` rule 9, as a test that can fail.
 *
 * *Nothing is `AVAILABLE` before antivirus completes, and no read path serves
 * `SCANNING` content.* The client's obligation is narrower but sharper: it must
 * never draw a file as **Ready** that the server will refuse to serve.
 *
 * The trap this guards is live on the development stack. With
 * `antivirus.provider: none` and `unsupported_policy: ALLOW_WITH_FLAG` a
 * completed upload settles at `status: AVAILABLE`, `avStatus: SKIPPED`,
 * `isReadable: false` — and both delivery routes answer `404` for it, verified
 * by hand against the running binary. `AVAILABLE` there means *published*, not
 * *scanned*, and `SKIPPED` is not `CLEAN`.
 *
 * So a phase function written as `status === 'AVAILABLE' ? 'ready' : …` would
 * put a green tick on a file the product refuses to open. That is the single
 * most valuable assertion in this file, and it is the one below named
 * "published but unscanned is not ready".
 */

function version(over: Partial<VersionEntry> = {}): VersionEntry {
  return {
    id: 'version-1',
    major: 1,
    minor: 0,
    status: 'AVAILABLE',
    avStatus: 'CLEAN',
    sizeBytes: 165,
    mimeType: 'image/png',
    checksumSha256: 'a'.repeat(64),
    isReadable: true,
    createdBy: 'user-1',
    createdAt: '2026-08-27T21:56:15.359881Z',
    ...over,
  };
}

describe('a version is Ready only when the server says it is readable', () => {
  it('reports ready for AVAILABLE and CLEAN', () => {
    expect(phaseFromVersion(version())).toBe('ready');
  });

  /* The one that matters. The positive control above shares every field with it
   * except the two that decide, so this cannot pass by rendering nothing. */
  it('published but unscanned is not ready', () => {
    const unscanned = version({ status: 'AVAILABLE', avStatus: 'SKIPPED', isReadable: false });
    expect(phaseFromVersion(unscanned)).not.toBe('ready');
    expect(phaseFromVersion(unscanned)).toBe('scanning');
  });

  it('trusts isReadable over the two fields beside it', () => {
    /* A version whose `status` and `avStatus` both read as fine but which the
     * server nonetheless refuses to serve. The client must follow the server's
     * own answer rather than recomputing one — the same rule as `capabilities`,
     * and the same reason: two authorities drift. */
    expect(phaseFromVersion(version({ isReadable: false }))).toBe('scanning');
  });

  it('maps the terminal states', () => {
    expect(phaseFromVersion(version({ status: 'QUARANTINED', isReadable: false }))).toBe(
      'quarantined',
    );
    expect(phaseFromVersion(version({ status: 'FAILED', isReadable: false }))).toBe('failed');
    expect(phaseFromVersion(version({ status: 'PROCESSING', isReadable: false }))).toBe(
      'processing',
    );
    expect(phaseFromVersion(version({ status: 'SCANNING', isReadable: false }))).toBe('scanning');
    expect(phaseFromVersion(version({ status: 'PENDING', isReadable: false }))).toBe('scanning');
  });
});

describe('the unreadable note explains a published version that will not open', () => {
  it('says unscanned for SKIPPED', () => {
    expect(unreadableNote(version({ avStatus: 'SKIPPED', isReadable: false }))).toBe(
      'upload.note.unscanned',
    );
  });

  it('says scan error for ERROR', () => {
    expect(unreadableNote(version({ avStatus: 'ERROR', isReadable: false }))).toBe(
      'upload.note.scanError',
    );
  });

  /* The absence assertion, paired with its positive control above so it cannot
   * pass for free (`docs/17 §10`). */
  it('says nothing at all about a readable version', () => {
    expect(unreadableNote(version())).toBeUndefined();
  });
});

describe('a policy refusal is not a failure', () => {
  /* `docs/17 §7`, expressed in the one place the upload feature could collapse
   * them: the tone table. `refused` drawn in the failure colour would teach a
   * user that "you may not upload here" means "it broke". */
  it('draws refused neutral and failed as a fault', () => {
    expect(PHASE_TONE.refused).toBe('neutral');
    expect(PHASE_TONE.failed).toBe('danger');
    expect(PHASE_TONE.refused).not.toBe(PHASE_TONE.failed);
  });

  it('draws a cancellation neutral too — it is the user’s own doing', () => {
    expect(PHASE_TONE.aborted).toBe('neutral');
  });

  it('draws quarantine as a fault, because it is a statement about the content', () => {
    expect(PHASE_TONE.quarantined).toBe('danger');
  });
});

describe('settled and active partition the phases', () => {
  it('treats every terminal phase as settled and no other', () => {
    for (const phase of ['ready', 'quarantined', 'failed', 'aborted', 'refused'] as const) {
      expect(isSettled(phase), phase).toBe(true);
      expect(isActive(phase), phase).toBe(false);
    }
    for (const phase of [
      'queued',
      'hashing',
      'uploading',
      'scanning',
      'processing',
      'indexing',
    ] as const) {
      expect(isSettled(phase), phase).toBe(false);
      expect(isActive(phase), phase).toBe(true);
    }
  });
});
