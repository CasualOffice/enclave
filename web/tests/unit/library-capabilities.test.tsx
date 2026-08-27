import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { Button } from '../../src/shared/ui/primitives.tsx';
import { GroupedFileList } from '../../src/features/libraries/list/grouped-file-list.tsx';
import { rowFromItem } from '../../src/entities/file/present.ts';
import type { Item } from '../../src/entities/file/api-model.ts';

/* Two contracts that live in the library list, and both are about **not
 * stating things the server never said**.
 *
 * 1. `docs/17 §10` F2: the denied and unbuilt treatments never share a class,
 *    and unbuilt is never focusable (`ENC-673`). The view bar puts them side by
 *    side — Upload can be denied, Filter is unbuilt — which is the single most
 *    likely place for them to drift into looking alike.
 *
 * 2. A folder is not an unclassified zero-byte file. The listing sends
 *    `sizeBytes: 0` and no classification for every folder, and rendering those
 *    produced "0 byte" and "Unclassified" — a measurement and a label, neither
 *    of which the server asserted.
 */

afterEach(cleanup);

const CAPS = {
  metadataRead: true,
  preview: true,
  download: false,
  print: false,
  export: false,
  edit: true,
  share: true,
  shareExternal: false,
  delete: true,
  sync: true,
};

const OBLIGATIONS = { watermark: false, justificationRequired: [], approvalRequired: [] };

function item(over: Partial<Item> = {}): Item {
  return {
    id: 'item-1',
    type: 'FILE',
    name: 'Board Pack.pdf',
    mimeType: 'application/pdf',
    sizeBytes: 4_718_592,
    libraryId: 'lib-1',
    status: 'AVAILABLE',
    revision: 1,
    capabilities: CAPS,
    obligations: OBLIGATIONS,
    createdAt: '2026-08-20T00:00:00Z',
    modifiedAt: '2026-08-20T00:00:00Z',
    ...over,
  } as Item;
}

function renderList(items: readonly Item[]) {
  const rows = items.map(rowFromItem);
  return render(
    <I18nProvider>
      <GroupedFileList
        groups={[{ id: 'all', name: 'All', count: rows.length }]}
        rows={rows}
        collapsed={new Set()}
        onToggleGroup={() => undefined}
      />
    </I18nProvider>,
  );
}

describe('a folder is not an unclassified zero-byte file', () => {
  it('states a file’s size and classification', () => {
    /* The positive control. Both cells are populated for a real file, so the
     * absences below are about folders rather than about a list that renders
     * neither column. */
    renderList([item()]);
    expect(screen.getByText('4.7 MB')).toBeTruthy();
    expect(screen.getAllByText('Unclassified').length).toBeGreaterThan(0);
  });

  it('states neither for a folder', () => {
    renderList([
      item({
        id: 'folder-1',
        type: 'FOLDER',
        name: 'Board Meetings 2026',
        mimeType: 'application/x-directory',
        sizeBytes: 0,
      }),
    ]);
    expect(screen.getByText('Board Meetings 2026')).toBeTruthy();
    /* "0 byte" is a measurement, and a false one — a folder's size is not zero,
     * it is not a quantity the listing carries. */
    expect(screen.queryByText('0 byte')).toBeNull();
    /* "Unclassified" says nobody has labelled it. For a folder the idea does
     * not apply, which is a different statement. */
    expect(screen.queryByText('Unclassified')).toBeNull();
  });
});

describe('denied and unbuilt never look alike', () => {
  function renderPair() {
    return render(
      <I18nProvider>
        <Button label="library.upload" state={{ kind: 'denied', reason: 'Not permitted here.' }} />
        <Button label="library.filter" state={{ kind: 'unbuilt', note: 'library.filter.unbuilt' }} />
      </I18nProvider>,
    );
  }

  it('marks them with different data-state values', () => {
    const { container } = renderPair();
    const denied = container.querySelector('[data-state="denied"]');
    const unbuilt = container.querySelector('[data-state="unbuilt"]');
    expect(denied).toBeTruthy();
    expect(unbuilt).toBeTruthy();
    expect(denied).not.toBe(unbuilt);
  });

  it('keeps the denied control focusable and takes the unbuilt one out of the tab order', () => {
    /* `docs/17 §6`: a denial is focusable *because* the user must be able to
     * reach it to learn why. An unbuilt control has nothing to find out. */
    const { container } = renderPair();
    expect(container.querySelector('[data-state="denied"]')?.getAttribute('tabindex')).not.toBe(
      '-1',
    );
    expect(container.querySelector('[data-state="unbuilt"]')?.getAttribute('tabindex')).toBe('-1');
  });

  it('shows the server’s reason on the denial and a Later chip on the unbuilt one', () => {
    renderPair();
    expect(screen.getByText('Not permitted here.')).toBeTruthy();
    expect(screen.getByText('Later')).toBeTruthy();
  });

  it('never puts a Later chip on the denied control', () => {
    render(
      <I18nProvider>
        <Button label="library.upload" state={{ kind: 'denied', reason: 'Not permitted here.' }} />
      </I18nProvider>,
    );
    expect(screen.getByText('Not permitted here.')).toBeTruthy();
    expect(screen.queryByText('Later')).toBeNull();
  });
});
