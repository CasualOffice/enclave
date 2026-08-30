import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { Button } from '../../src/shared/ui/primitives.tsx';
import { reasonMessage } from '../../src/entities/capability/denial.ts';
import { Item } from '../../src/entities/file/api-model.ts';
import { Library } from '../../src/entities/workspace/api-model.ts';
import { capabilitiesFixture } from '../support/capabilities.ts';

/* `ENC-674` / `docs/05 §7` / `docs/09 §5`: the client renders the *server's*
 * reason for a denied capability and never one of its own.
 *
 * The defect this closes is not a missing sentence. It is a client that,
 * lacking one, writes its own — and a client-authored explanation of a policy
 * decision is a second authority, wrong the moment two rules can produce the
 * same `false`. `CLAUDE.md` forbids re-deriving permissions in the client, and
 * `library-screen.tsx` carried a comment saying exactly why it could not do
 * better, which is what this row was.
 *
 * `docs/12 §1.2`: every assertion about an absence below is paired with one
 * about a presence in the same run, because "no invented sentence appeared" is
 * satisfied for free by a screen that rendered nothing at all.
 */

afterEach(cleanup);

const OBLIGATIONS = { watermark: false, justificationRequired: [], approvalRequired: [] };

/** A wire row, as `content.rs` serializes one — parsed, never hand-built. */
function wireItem(capabilityReasons?: Record<string, string>): unknown {
  return {
    id: 'item-1',
    nodeType: 'FILE',
    name: 'Board Pack.pdf',
    mimeType: 'application/pdf',
    sizeBytes: 4_718_592,
    libraryId: 'lib-1',
    status: 'AVAILABLE',
    revision: 1,
    capabilities: capabilitiesFixture(),
    ...(capabilityReasons === undefined ? {} : { capabilityReasons }),
    obligations: OBLIGATIONS,
    createdAt: '2026-08-20T00:00:00Z',
    modifiedAt: '2026-08-20T00:00:00Z',
  };
}

describe('the wire carries a reason per denied capability', () => {
  it('parses the object the server sends', () => {
    /* Not a shape invented here: `crates/api/src/content.rs` emits exactly this
     * pairing — `PREVIEW_ONLY` on the three egress capabilities that
     * `Obligation::NoDownload` suppresses, and `SYNC_NOT_PERMITTED` on sync,
     * which is the one place that obligation reports its own code. */
    const parsed = Item.parse(
      wireItem({
        download: 'PREVIEW_ONLY',
        print: 'PREVIEW_ONLY',
        export: 'PREVIEW_ONLY',
        shareExternal: 'EXTERNAL_SHARE_BLOCKED',
        sync: 'SYNC_NOT_PERMITTED',
      }),
    );

    expect(parsed.capabilityReasons?.['download']).toBe('PREVIEW_ONLY');
    expect(parsed.capabilityReasons?.['sync']).toBe('SYNC_NOT_PERMITTED');
    // The reasons are keyed by the same names the booleans are, which is what
    // lets a caller index both objects with one key.
    for (const key of Object.keys(parsed.capabilityReasons ?? {})) {
      expect(key in parsed.capabilities).toBe(true);
    }
  });

  it('still parses a row from a server that sends no reasons', () => {
    /* The compatibility half, and the reason this field is optional here while
     * being mandatory on the server. An older build's listing must render, not
     * blank the screen over a sentence. */
    const parsed = Item.parse(wireItem());
    expect(parsed.capabilityReasons).toBeUndefined();
    expect(parsed.capabilities.download).toBe(false);
  });

  it('still refuses a row whose capability *booleans* are incomplete', () => {
    /* The positive control for the leniency above — and the line that keeps the
     * two cases from being confused. A missing reason is a missing sentence; a
     * missing boolean is a missing decision, and `undefined` is falsy, so it
     * would render as a refusal the chain never made. That must still fail.
     *
     * Without this assertion, "the schema tolerates an absent field" could have
     * been implemented by loosening the whole object. */
    const wire = wireItem() as { capabilities: Record<string, boolean> };
    delete wire.capabilities['download'];
    expect(() => Item.parse(wire)).toThrow();
  });

  it('carries the same object on a container', () => {
    const parsed = Library.parse({
      id: 'lib-1',
      workspaceId: 'ws-1',
      name: 'Board Documents',
      slug: 'board',
      revision: 1,
      settings: {
        versioningMode: 'MAJOR_MINOR',
        requireCheckout: false,
        requireApproval: false,
        externalSharing: 'DISABLED',
        aiIndexingEnabled: true,
        mcpVisible: true,
        syncEnabled: true,
      },
      capabilities: {
        read: true,
        create: false,
        update: false,
        delete: false,
        manageMembers: false,
        managePermissions: false,
      },
      capabilityReasons: { create: 'ACCESS_DENIED' },
      obligations: OBLIGATIONS,
      createdAt: '2026-08-20T00:00:00Z',
      updatedAt: '2026-08-20T00:00:00Z',
    });

    expect(parsed.capabilityReasons?.['create']).toBe('ACCESS_DENIED');
  });
});

describe('a code becomes a sentence, and never anything else', () => {
  it('maps every code the server can send to a sentence of its own', () => {
    /* One assertion, two claims. Every code resolves (nothing falls into the
     * fallback by accident), and no two codes resolve to the same key — because
     * a mapping that collapsed `PREVIEW_ONLY` and `DLP_BLOCKED` onto one
     * sentence would be the client flattening a distinction the server drew. */
    const codes = [
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
    ];
    const keys = codes.map((code) => reasonMessage(code));

    expect(keys).toHaveLength(18);
    expect(new Set(keys).size).toBe(18);
    expect(keys).not.toContain('denial.unspecified');
    for (const key of keys) expect(catalog[key].message.length).toBeGreaterThan(0);
  });

  it('falls back rather than guessing for a code it has never heard of', () => {
    /* A newer server naming a reason this build cannot phrase. The answer is a
     * restatement of the refusal, not an approximation of its cause. */
    expect(reasonMessage('SOME_FUTURE_CODE')).toBe('denial.unspecified');
    expect(reasonMessage(undefined)).toBe('denial.unspecified');
    // Positive control: the fallback is not what *every* input returns.
    expect(reasonMessage('PREVIEW_ONLY')).toBe('denial.previewOnly');
  });

  it('cannot name the rule that matched, because no denial sentence interpolates', () => {
    /* `CLAUDE.md` rule 10 and `docs/06 §24`, asserted structurally rather than
     * by vocabulary.
     *
     * A word-list was the first version of this test and it was the wrong
     * shape: it failed on *"a retention policy prevents this item from being
     * deleted"*, which names a **kind** of control and not a policy — precisely
     * the sentence `docs/06 §24` permits, and the same wording the server's own
     * `user_message` uses. A test that bans the word "policy" trains people to
     * reword around it rather than to think about what leaks.
     *
     * What actually leaks is a *value*: this rule, this threshold, this matched
     * string. The messages are fixed literals, so the only route for a value
     * into one is an ICU placeholder — and there are none. That is the property
     * worth holding, it is exhaustive over the set, and it fails the moment
     * someone adds `denial.dlpBlocked: 'blocked by {ruleName}'`. */
    const denials = Object.entries(catalog).filter(([key]) => key.startsWith('denial.'));

    for (const [key, entry] of denials) {
      expect(entry.message, `${key} takes a value`).not.toMatch(/[{}]/);
      // …and it does not promise a retry, which a denial can never honour
      // (`docs/17 §7`): a policy refusal will refuse identically next time.
      expect(entry.message.toLowerCase(), `${key} promises a retry`).not.toContain('try again');
      // The two identifier-shaped words that would be a leak in any phrasing.
      // Neither has a legitimate use in a sentence aimed at a user.
      for (const word of ['acl', 'regex']) {
        expect(entry.message.toLowerCase(), `${key} names the mechanism`).not.toContain(word);
      }
    }

    /* The positive control for the placeholder rule: the catalog *does* contain
     * interpolating messages, so the assertion above is a property of the
     * denial subset rather than of a catalog that never interpolates at all. */
    const interpolating = Object.values(catalog).filter((entry) => /\{\w+/.test(entry.message));
    expect(interpolating.length).toBeGreaterThan(0);
  });

  it('scans a non-empty set of denial keys', () => {
    /* The rule above is an assertion about absence across a filtered loop, so
     * it passes trivially if the filter matches nothing. `ENC-543`'s shape. */
    const denialKeys = Object.keys(catalog).filter((key) => key.startsWith('denial.'));
    expect(denialKeys.length).toBe(19);
  });
});

describe('the denied control shows the server’s sentence', () => {
  it('renders the reason the code named, and associates it for a screen reader', () => {
    /* `docs/09 §15`: `aria-disabled` plus `title` is not a reliable
     * screen-reader path, so the reason is text in the DOM associated by
     * `aria-describedby` rather than a tooltip. */
    const { container } = render(
      <I18nProvider>
        <Button
          label="library.upload"
          state={{ kind: 'denied', reason: catalog[reasonMessage('PREVIEW_ONLY')].message }}
        />
      </I18nProvider>,
    );

    expect(screen.getByText(catalog['denial.previewOnly'].message)).toBeTruthy();

    const button = container.querySelector('button');
    const describedBy = button?.getAttribute('aria-describedby') ?? '';
    expect(describedBy).not.toBe('');
    const reason = [...container.querySelectorAll('[id]')].find((el) => el.id === describedBy);
    expect(reason?.textContent).toContain(catalog['denial.previewOnly'].message);
  });

  it('shows a different sentence for a different code, on the same control', () => {
    /* The assertion that makes the one above mean something. If the control
     * ignored its `reason` and rendered a fixed string, the test above would
     * still pass. Two codes, two sentences, one control. */
    render(
      <I18nProvider>
        <Button
          label="library.upload"
          state={{ kind: 'denied', reason: catalog[reasonMessage('LEGAL_HOLD_ACTIVE')].message }}
        />
      </I18nProvider>,
    );

    expect(screen.getByText(catalog['denial.legalHoldActive'].message)).toBeTruthy();
    expect(screen.queryByText(catalog['denial.previewOnly'].message)).toBeNull();
  });
});
