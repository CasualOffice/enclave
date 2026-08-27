import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { UploadTray } from '../../src/features/upload/upload-tray.tsx';
import { useUploadStore, type UploadRow } from '../../src/entities/upload/store.ts';

/* `docs/17 §10` F3, on the upload tray specifically.
 *
 * *A policy denial renders no retry affordance, and a fetch failure always
 * does.* The tray is where the two sit closest together — one `phase` value
 * apart, in one component — and it is exactly the kind of place a later
 * refactor collapses them into "if it stopped badly, offer retry".
 *
 * Every absence assertion here is paired with its positive control on the very
 * next line, because *"the retry button is not shown"* passes for free against
 * a component that renders nothing at all (`docs/17 §10`).
 */

afterEach(cleanup);

function row(over: Partial<UploadRow> = {}): UploadRow {
  return {
    id: 'row-1',
    name: 'board-pack.png',
    sizeBytes: 165,
    mimeType: 'image/png',
    libraryId: 'lib-1',
    parentId: undefined,
    phase: 'uploading',
    progress: 0.5,
    uploadId: 'upload-1',
    fileId: undefined,
    failure: undefined,
    note: undefined,
    ...over,
  };
}

function seed(rows: readonly UploadRow[]): void {
  useUploadStore.setState({ rows, trayOpen: true });
}

beforeEach(() => {
  useUploadStore.setState({ rows: [], trayOpen: false });
});

function renderTray() {
  return render(
    <I18nProvider>
      <UploadTray />
    </I18nProvider>,
  );
}

const REFUSAL = {
  kind: 'denied' as const,
  code: 'ACCESS_DENIED',
  message: 'You do not have access to this.',
  remediation: 'Ask the library owner for access.',
  requestId: '01a0402d-cb72-76e2-8f0e-ee21277e71e0',
};

const FAULT = {
  kind: 'failed' as const,
  code: 'upload_transfer',
  retryable: true,
  requestId: '01a0402d-cb72-76e2-8f0e-ee21277e71e0',
};

describe('a policy refusal offers no retry; a failure does', () => {
  it('offers retry on a failed transfer', () => {
    seed([row({ phase: 'failed', failure: FAULT })]);
    renderTray();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  });

  it('offers no retry on a policy refusal', () => {
    seed([row({ phase: 'refused', failure: REFUSAL })]);
    renderTray();
    /* The positive control for this absence: the row *is* on screen, carrying
     * the server's own sentence. So "no retry" is a statement about a rendered
     * row rather than about an empty document. */
    expect(screen.getByText('You do not have access to this.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
  });

  it('shows the server’s words on a refusal and composes none of its own', () => {
    seed([row({ phase: 'refused', failure: REFUSAL })]);
    renderTray();
    expect(screen.getByText('You do not have access to this.')).toBeTruthy();
    expect(screen.getByText('Ask the library owner for access.')).toBeTruthy();
  });
});

describe('a handed-off upload is never reported Ready', () => {
  /* `CLAUDE.md` rule 9 at the surface. `POST /complete` answers `202` with
   * `state: "SCANNING"`, and the row must say so — the bytes exist and nothing
   * has inspected them. */
  it('says Scanning, not Ready, immediately after complete', () => {
    seed([row({ phase: 'scanning', progress: 1, fileId: 'file-1' })]);
    renderTray();
    expect(screen.getByText('Scanning')).toBeTruthy();
    expect(screen.queryByText('Ready')).toBeNull();
  });

  it('explains a published version that was never scanned', () => {
    /* `AVAILABLE` / `SKIPPED`: published, not clean, not servable. The tray
     * says so rather than ticking. */
    seed([row({ phase: 'scanning', progress: 1, note: 'upload.note.unscanned' })]);
    renderTray();
    expect(
      screen.getByText('Published, but no scanner inspected it — it cannot be opened yet.'),
    ).toBeTruthy();
    expect(screen.queryByText('Ready')).toBeNull();
  });

  it('does say Ready once the server reports the version readable', () => {
    /* The positive control for the two absences above. Without it, a tray that
     * rendered the word "Ready" nowhere at all would pass them both. */
    seed([row({ phase: 'ready', progress: 1 })]);
    renderTray();
    expect(screen.getByText('Ready')).toBeTruthy();
  });
});

describe('progress claims only what is known', () => {
  it('draws a progress bar while bytes are moving', () => {
    seed([row({ phase: 'uploading', progress: 0.5 })]);
    renderTray();
    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuenow')).toBe('50');
  });

  it('draws no progress bar while scanning, because there is no number', () => {
    /* A bar that kept creeping through a scan would be the product telling a
     * user how long something takes when it does not know. */
    seed([row({ phase: 'scanning', progress: 1 })]);
    renderTray();
    expect(screen.queryByRole('progressbar')).toBeNull();
    /* Positive control: the row is present and says what it is doing. */
    expect(screen.getByText('Scanning')).toBeTruthy();
  });
});

describe('the tray keeps out of the way when there is nothing to say', () => {
  it('renders nothing with an empty queue', () => {
    useUploadStore.setState({ rows: [], trayOpen: true });
    const { container } = renderTray();
    expect(container.querySelector('.upl-tray')).toBeNull();
  });

  it('renders once a row exists', () => {
    seed([row()]);
    const { container } = renderTray();
    expect(container.querySelector('.upl-tray')).toBeTruthy();
  });
});
