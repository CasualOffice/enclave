import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import SearchScreen from '../../src/features/search/search-screen.tsx';
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
  return render(
    <I18nProvider>
      <SearchScreen />
    </I18nProvider>,
  );
}

describe('filter chips and the URL', () => {
  beforeEach(() => goto('?q=agreement'));

  it('writes a chosen filter into the URL, keeping the query', () => {
    renderScreen();

    fireEvent.click(screen.getByRole('button', { name: /Change the Classification filter/ }));
    fireEvent.click(screen.getByRole('menuitemradio', { name: 'Internal' }));

    expect(currentParams().get('classification')).toBe('internal');
    expect(currentParams().get('q')).toBe('agreement');
  });

  it('removes one chip from the URL without disturbing the others', () => {
    goto('?q=agreement&classification=internal&type=pdf');
    renderScreen();

    /* The positive control for the removal: the chip has to be there, and
     * removable by its own name, before its disappearance means anything. */
    const remove = screen.getByRole('button', { name: 'Remove the Classification filter' });
    expect(remove).toBeTruthy();
    expect(currentParams().get('classification')).toBe('internal');

    fireEvent.click(remove);

    expect(currentParams().get('classification')).toBeNull();
    // `replaceParams` replaces the whole query string, so this is the assertion
    // that a chip clearing itself cannot silently drop its neighbours.
    expect(currentParams().get('type')).toBe('pdf');
    expect(currentParams().get('q')).toBe('agreement');
  });

  it('offers no remove control on a chip that is not narrowing anything', () => {
    renderScreen();

    // Positive control: the chip exists and can be opened…
    expect(screen.getByRole('button', { name: /Change the Workspace filter/ })).toBeTruthy();
    // …and only then is its lack of a ✕ meaningful.
    expect(screen.queryByRole('button', { name: 'Remove the Workspace filter' })).toBeNull();
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
