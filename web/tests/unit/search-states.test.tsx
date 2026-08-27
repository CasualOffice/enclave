import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, screen } from '@testing-library/react';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import SearchScreen from '../../src/features/search/search-screen.tsx';
import { renderWithProviders } from '../render.tsx';

/* `globals: false` in `vite.config.ts`, so Testing Library never registers its own
 * auto-cleanup — it hooks a global `afterEach` that does not exist here. Without
 * this, each render is appended to the same document and every `getBy*` in the
 * second test of a file finds two of everything. */
afterEach(cleanup);
afterEach(() => vi.unstubAllGlobals());

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

/* One hit, shaped exactly as `crates/api/src/routes/search.rs` serializes it.
 *
 * Deliberately *not* the shape `docs/05 §11` describes: the implemented route
 * sends no classification, no owner and no modified date. Stubbing the
 * documented shape instead of the real one would let these tests pass against a
 * response the server never sends, which is the failure the fixture-to-network
 * swap was supposed to end. */
function hit(index: number) {
  return {
    fileId: `file-${index}`,
    versionId: `version-${index}`,
    title: `Master Services Agreement ${index}.pdf`,
    path: 'Finance / Contracts',
    workspace: 'Finance',
    mimeType: 'application/pdf',
    score: 0.5,
    excerpt: 'the <em>agreement</em> shall commence',
    capabilities: { preview: true, download: false },
  };
}

/** Answer `POST /api/v1/search` with `count` hits and nothing else. */
function stubSearch(count: number) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      new Response(
        JSON.stringify({
          results: Array.from({ length: count }, (_unused, index) => hit(index)),
          page: { nextCursor: null, hasMore: false },
          diagnostics: { mode: 'lexical', degraded: true },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ),
  );
}

async function renderAt(search: string) {
  goto(search);
  const result = renderWithProviders(<SearchScreen />);
  /* The screen fetches now, so the first paint is the loading state.
   *
   * Several turns, not one: the stubbed `fetch` resolves, then `Response.json`
   * resolves, then Query schedules a React update, and each of those is its own
   * turn of the loop. A single flush passed for some tests and left others
   * asserting against the skeleton — which is worse than failing, because the
   * skeleton is a real state and the test would have been "passing" against the
   * wrong one had the assertion been weaker. */
  for (let turn = 0; turn < 5; turn += 1) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
  return result;
}

describe('the four states', () => {
  it('empty (new): nothing searched yet', async () => {
    stubSearch(0);
    await renderAt('');
    expect(screen.getByText(catalog['search.state.new.title'].message)).toBeTruthy();
    // Positive control against the wrong empty state: this is not the
    // no-results one, which would name a query the user has not typed.
    expect(screen.queryByRole('list', { name: 'Search results' })).toBeNull();
  });

  it('empty (filtered): a query that matched nothing, with the filters named', async () => {
    stubSearch(0);
    await renderAt('?q=agreement&workspace=Legal&type=xls&modified=7d');

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

  it('loading: skeleton rows, announced, never a blank region', async () => {
    stubSearch(0);
    const { container } = await renderAt('?q=agreement&surface=loading');

    const status = screen.getByRole('status', { name: catalog['search.state.loading'].message });
    expect(status).toBeTruthy();
    expect(container.querySelectorAll('.esr-skeleton').length).toBeGreaterThan(0);

    /* The skeleton shares the loaded row's box model so nothing shifts when
     * results land (`docs/09 §11`) — same `.esr-row` element, same height. */
    expect(container.querySelectorAll('.esr-row').length).toBeGreaterThan(0);
  });

  it('error: what failed, a retry, and a copyable request ID', async () => {
    stubSearch(0);
    await renderAt('?q=agreement&surface=error');

    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(catalog['search.state.error.title'].message);
    expect(
      screen.getByRole('button', { name: catalog['search.state.error.retry'].message }),
    ).toBeTruthy();
    expect(alert.querySelector('code')?.textContent ?? '').toMatch(/[A-Z0-9]{10,}/);
  });

  it('success: every field the route actually sends is rendered', async () => {
    stubSearch(1);
    const { container } = await renderAt('?q=agreement');

    const list = screen.getByRole('list', { name: 'Search results' });
    expect(list).toBeTruthy();

    const first = container.querySelector('.esr-hit')!;
    expect(first.querySelector('.esr-title')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('.esr-path')?.textContent ?? '').not.toBe('');
    expect(first.querySelector('.esr-workspace')?.textContent ?? '').not.toBe('');
  });

  /* The other half of the assertion above, and the reason it is a separate test
   * rather than three `toBeNull()`s appended to it.
   *
   * `docs/09 §10` asks every result to show its classification, owner and
   * modified date. The implemented route sends none of the three. The client
   * renders nothing there rather than inventing a value — and an invented
   * classification is the worst of the three by a distance, because the badge is
   * how a user decides whether a document may leave the building.
   *
   * This test exists so that the day the fields arrive on the wire, it fails and
   * someone deletes it deliberately. A silent absence with no test is an absence
   * nobody notices has been fixed. */
  it('renders no classification, owner or date, because the route sends none', async () => {
    stubSearch(1);
    const { container } = await renderAt('?q=agreement');

    // The positive control: the row rendered at all, so the absences below mean
    // something. An assertion about an absence passes for free otherwise.
    expect(container.querySelector('.esr-title')?.textContent ?? '').not.toBe('');

    expect(container.querySelector('.esr-classification')).toBeNull();
    expect(container.querySelector('.esr-ownername')).toBeNull();
    expect(container.querySelector('.esr-when')).toBeNull();
  });

  it('virtualizes: far fewer rows in the DOM than in the result set', async () => {
    // A broad query, deliberately: the assertion is only meaningful above the
    // 100-row line `CLAUDE.md` draws, and a search that returns more than a
    // hundred results is ordinary rather than contrived.
    stubSearch(150);
    const { container } = await renderAt('?q=20');

    const total = Number(
      container.querySelector('[role="listitem"]')?.getAttribute('aria-setsize') ?? '0',
    );
    const rendered = container.querySelectorAll('[role="listitem"]').length;

    expect(total, 'the stub must return enough rows for this to mean anything').toBeGreaterThan(
      100,
    );
    expect(rendered).toBeLessThan(total);
  });
});

describe('AI answers on this screen are unbuilt, not denied', () => {
  it('shows the answer slot with the Later marker and no answer', async () => {
    stubSearch(1);
    const { container } = await renderAt('?q=agreement');

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
