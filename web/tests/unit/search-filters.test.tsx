import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import SearchScreen from '../../src/features/search/search-screen.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { renderWithProviders } from '../render.tsx';
import { activeFilters, readFilters, toParams, NO_FILTERS } from '../../src/features/search/filters.ts';

/* `globals: false` in `vite.config.ts`, so Testing Library never registers its own
 * auto-cleanup — it hooks a global `afterEach` that does not exist here. Without
 * this, each render is appended to the same document and every `getBy*` in the
 * second test of a file finds two of everything. */
afterEach(cleanup);

/* `docs/09 §10`: filters are chips that compose and are individually removable,
 * and the active filter set is reflected in the URL so a search is shareable and
 * restorable. `docs/17 §4` says the same from the state-ownership side.
 *
 * The assertion that matters is the round trip through the *real* URL: setting a
 * filter writes it, removing one takes it away, and neither disturbs the query
 * or the filters beside it. A test against component state would pass while the
 * link a user copies stayed wrong, which is the whole failure being prevented.
 */

function goto(search: string) {
  window.history.replaceState(null, '', `/search${search}`);
  // `routes.ts` keeps one snapshot and refreshes it on popstate; without this
  // the module would still be describing the previous test's URL.
  window.dispatchEvent(new PopStateEvent('popstate'));
}

function currentParams(): URLSearchParams {
  return new URLSearchParams(window.location.search);
}

function renderScreen() {
  return renderWithProviders(<SearchScreen />);
}

/* The filter controls, and why these tests replaced four that used to click them.
 *
 * `POST /api/v1/search` declares `workspaceIds`, `libraryIds`, `types`,
 * `classificationMax` and `modifiedAfter` and answers `400` naming the field for
 * every one — `deny_unknown_fields`, deliberately. A narrowing filter that is
 * accepted and then not applied returns MORE than the caller asked for, so the
 * server is right to refuse and the client must not route around it.
 *
 * Filtering client-side over one page of results would be the same lie in a
 * different place: it narrows what is shown without narrowing what was searched,
 * so a document excluded by a chip and absent from the page reads exactly like a
 * document that does not exist.
 *
 * So the chips are gone and one unbuilt control stands in their place. The tests
 * below assert the treatment is the *unbuilt* one and not the denial one, which
 * is `ENC-673`'s F2 and a security contract rather than styling: a user who
 * learns that dimmed means "not written yet" carries the habit to the one screen
 * where dimmed means "DLP refused this".
 */
describe('search filters are unbuilt, not denied', () => {
  beforeEach(() => goto('?q=agreement'));

  it('shows the filter control under the unbuilt treatment', () => {
    const { container } = renderScreen();

    const control = screen.getByRole('button', {
      name: catalog['search.filters.label'].message,
    });
    expect(control.getAttribute('data-state')).toBe('unbuilt');
    expect(control.getAttribute('aria-disabled')).toBe('true');

    // The neutral `Later` chip is the visible marker (D33).
    expect(container.querySelector('.ui-later')).toBeTruthy();
  });

  it('takes the filter control out of the tab order, because there is nothing to find out', () => {
    renderScreen();

    const control = screen.getByRole('button', {
      name: catalog['search.filters.label'].message,
    });
    /* Unbuilt is the one treatment that leaves the tab order. A denied control
     * stays focusable precisely so a keyboard user can reach it and read the
     * reason; an unbuilt one has no reason to read. */
    expect(control.tabIndex).toBe(-1);
  });

  it('never carries the denial treatment', () => {
    const { container } = renderScreen();

    const control = screen.getByRole('button', {
      name: catalog['search.filters.label'].message,
    });
    // Positive control: the button rendered, so the absences below mean something.
    expect(control).toBeTruthy();

    expect(control.getAttribute('data-state')).not.toBe('denied');
    expect(container.querySelector('.ui-denial')).toBeNull();
  });

  it('writes no filter into the URL, because no filter can be applied', () => {
    renderScreen();

    expect(screen.queryByRole('button', { name: /Change the Classification filter/ })).toBeNull();
    expect(currentParams().get('classification')).toBeNull();
  });

  it('keeps the query in the URL as it is typed', () => {
    goto('?q=');
    renderScreen();

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search' }), {
      target: { value: 'termination' },
    });

    expect(currentParams().get('q')).toBe('termination');
  });
});

describe('the URL codec', () => {
  it('omits a filter that is at its default', () => {
    expect(toParams('x', NO_FILTERS)).toEqual({ q: 'x' });
  });

  it('round-trips an active set', () => {
    const params = toParams('x', { ...NO_FILTERS, type: 'pdf', workspace: 'Legal' });
    expect(params).toEqual({ q: 'x', type: 'pdf', workspace: 'Legal' });
    expect(readFilters(new URLSearchParams(params))).toEqual({
      ...NO_FILTERS,
      type: 'pdf',
      workspace: 'Legal',
    });
  });

  it('reports the active set in chip order', () => {
    expect(activeFilters({ ...NO_FILTERS, workspace: 'Legal', type: 'pdf' })).toEqual([
      'type',
      'workspace',
    ]);
  });
});
