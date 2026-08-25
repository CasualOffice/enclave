import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import SearchScreen from '../../src/features/search/search-screen.tsx';

/* `globals: false` in `vite.config.ts`, so Testing Library never registers its own
 * auto-cleanup — it hooks a global `afterEach` that does not exist here. Without
 * this, each render is appended to the same document and every `getBy*` in the
 * second test of a file finds two of everything. */
afterEach(cleanup);

/* `docs/09 §11`: every surface defines all four states, and a surface that
 * renders `null` while loading has three and fails review (`docs/17 §8`).
 *
 * The prototype draws exactly one of them — a centred "No files match" with a
 * Clear search button, naming no filters — so these are the assertions that the
 * other three exist at all, plus the one that separates the two empty states
 * from each other.
 */

function goto(search: string) {
  window.history.replaceState(null, '', `/search${search}`);
  window.dispatchEvent(new PopStateEvent('popstate'));
}

function renderAt(search: string) {
  goto(search);
  return render(
    <I18nProvider>
      <SearchScreen />
    </I18nProvider>,
  );
}

describe('the four states', () => {
  it('empty (new): nothing searched yet', () => {
    renderAt('');
    expect(screen.getByText(catalog['search.state.new.title'].message)).toBeTruthy();
    // Positive control against the wrong empty state: this is not the
    // no-results one, which would name a query the user has not typed.
    expect(screen.queryByRole('list', { name: 'Search results' })).toBeNull();
  });

  it('empty (filtered): a query that matched nothing, with the filters named', () => {
    renderAt('?q=agreement&workspace=Legal&type=xls&modified=7d');

    expect(
      screen.getByRole('heading', { name: /No results for/ }),
      'the query is quoted back so the user can see what was searched',
    ).toBeTruthy();

    /* `docs/09 §11` asks this state to name the filters, because "no results"
     * and "your filters exclude everything" are different problems. The list is
     * the naming, and it is announced. */
    const named = screen.getByRole('list', {
      name: catalog['search.state.noResults.filterList'].message,
    });
    expect(named.textContent).toContain('Legal');
    expect(named.textContent).toContain('Spreadsheet');
    expect(named.textContent).toContain('Past 7 days');

    expect(
      screen.getByRole('button', { name: catalog['search.state.noResults.clearFilters'].message }),
    ).toBeTruthy();
  });

  it('loading: skeleton rows, announced, never a blank region', () => {
    const { container } = renderAt('?q=agreement&surface=loading');

    const status = screen.getByRole('status', { name: catalog['search.state.loading'].message });
    expect(status).toBeTruthy();
    expect(container.querySelectorAll('.esr-skeleton').length).toBeGreaterThan(0);

    /* The skeleton shares the loaded row's box model so nothing shifts when
     * results land (`docs/09 §11`) — same `.esr-row` element, same height. */
    expect(container.querySelectorAll('.esr-row').length).toBeGreaterThan(0);
  });

  it('error: what failed, a retry, and a copyable request ID', () => {
    renderAt('?q=agreement&surface=error');

    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(catalog['search.state.error.title'].message);
    expect(
      screen.getByRole('button', { name: catalog['search.state.error.retry'].message }),
    ).toBeTruthy();
    expect(alert.querySelector('code')?.textContent ?? '').toMatch(/[A-Z0-9]{10,}/);
  });

  it('success: results, each carrying what docs/09 §10 requires', () => {
    const { container } = renderAt('?q=agreement');

    const list = screen.getByRole('list', { name: 'Search results' });
    expect(list).toBeTruthy();

    const first = container.querySelector('.esr-hit')!;
    expect(first.querySelector('.esr-title')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('.esr-path')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('.esr-workspace')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('.esr-classification')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('.esr-ownername')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('time')?.getAttribute('title') ?? '').not.toBe('');
    expect(first.querySelector('.esr-location')?.textContent ?? '').not.toBe('');
  });

  it('virtualizes: far fewer rows in the DOM than in the result set', () => {
    // A broad query, deliberately: the assertion is only meaningful above the
    // 100-row line `CLAUDE.md` draws, and a search that returns more than a
    // hundred results is ordinary rather than contrived.
    const { container } = renderAt('?q=20');

    const total = Number(
      container.querySelector('[role="listitem"]')?.getAttribute('aria-setsize') ?? '0',
    );
    const rendered = container.querySelectorAll('[role="listitem"]').length;

    expect(total, 'the fixture must return enough rows for this to mean anything').toBeGreaterThan(
      100,
    );
    expect(rendered).toBeLessThan(total);
  });
});

describe('AI answers on this screen are unbuilt, not denied', () => {
  it('shows the answer slot with the Later marker and no answer', () => {
    const { container } = renderAt('?q=agreement');

    /* The positive control that makes the absence below meaningful: the slot is
     * on screen, so "no answer is rendered" is a statement about a surface that
     * exists rather than about one that was never drawn. */
    const slot = container.querySelector('.esr-answer')!;
    expect(slot).toBeTruthy();
    expect(slot.textContent).toContain(catalog['later.chip'].message);
    expect(slot.getAttribute('aria-disabled')).toBe('true');

    // `docs/17 §6`: unbuilt is neutral and never wears the denial treatment.
    // A denial would be focusable and would carry a reason and a remedy.
    expect(slot.querySelector('button')).toBeNull();
    expect(slot.className).not.toContain('denied');
  });
});
