import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { noticeFor, RetrievalNotice } from '../../src/features/search/retrieval-notice.tsx';
import type { SearchDiagnostics } from '../../src/features/search/model.ts';

/* `globals: false` in `vite.config.ts`, so Testing Library never registers its own
 * auto-cleanup — it hooks a global `afterEach` that does not exist here. Without
 * this, each render is appended to the same document and every `getBy*` in the
 * second test of a file finds two of everything. */
afterEach(cleanup);

/* The degraded-search header.
 *
 * `docs/09 §10` requires a degraded search to say so in the results header
 * rather than quietly returning less, and `plans/M5-MVP-GA.md` D37 is why it is
 * reachable at all: M5 ships lexical retrieval.
 *
 * **Every absence here is paired with a positive control** (`docs/12 §1.2`,
 * `docs/17 §10`). "No notice is shown for a healthy search" passes for free
 * against a component that renders nothing, so the healthy case asserts a
 * sentinel sibling is still on screen *and* the same harness shows the notice
 * when retrieval is lexical. Same for the `Later` chip, which must appear on the
 * product-state variant and must not appear on the incident one — asserting only
 * the second would pass against a chip that never renders at all.
 */

const HEAD = catalog['search.retrieval.head'].message;
const LATER = catalog['later.chip'].message;
const SENTINEL = 'sentinel-sibling';

function renderNotice(diagnostics: SearchDiagnostics) {
  return render(
    <I18nProvider>
      <div>
        <RetrievalNotice diagnostics={diagnostics} />
        {/* The positive control for every absence assertion below: if the tree
         * rendered nothing at all, this is missing too and the test fails. */}
        <span>{SENTINEL}</span>
      </div>
    </I18nProvider>,
  );
}

describe('the degraded-search header', () => {
  it('is shown when retrieval was lexical-only', () => {
    renderNotice({ mode: 'lexical', degraded: false });

    expect(screen.getByText(SENTINEL)).toBeTruthy();
    expect(screen.getByText(HEAD)).toBeTruthy();
    expect(screen.getByRole('status')).toBeTruthy();
  });

  it('is not shown when retrieval was hybrid and healthy', () => {
    renderNotice({ mode: 'hybrid', degraded: false });

    // Positive control first: the tree rendered.
    expect(screen.getByText(SENTINEL)).toBeTruthy();
    expect(screen.queryByText(HEAD)).toBeNull();
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('carries the Later chip on the product-state variant and not on the incident one', () => {
    const { unmount } = renderNotice({ mode: 'lexical', degraded: false });
    // `lexical` + not degraded is "this deployment has no dense retrieval" — a
    // roadmap fact, so it wears the D33 marker.
    expect(screen.getByText(LATER)).toBeTruthy();
    unmount();

    renderNotice({ mode: 'lexical', degraded: true });
    expect(screen.getByText(SENTINEL)).toBeTruthy();
    expect(screen.getByText(HEAD)).toBeTruthy();
    // An incident is not a roadmap item. Marking it `Later` would be a lie in
    // the other direction — it says "one day", when the truth is "shortly".
    expect(screen.queryByText(LATER)).toBeNull();
  });

  it('says different things about a product state and an incident', () => {
    const { unmount } = renderNotice({ mode: 'lexical', degraded: false });
    expect(screen.getByText(catalog['search.retrieval.lexical'].message)).toBeTruthy();
    expect(screen.queryByText(catalog['search.retrieval.degraded'].message)).toBeNull();
    unmount();

    renderNotice({ mode: 'lexical', degraded: true });
    expect(screen.getByText(catalog['search.retrieval.degraded'].message)).toBeTruthy();
    expect(screen.queryByText(catalog['search.retrieval.lexical'].message)).toBeNull();
  });

  it('is not an error: no alert role, and no retry affordance', () => {
    renderNotice({ mode: 'lexical', degraded: true });

    /* `docs/17 §7` and `docs/09 §11`: a degraded search is a *successful*
     * request that returned real results by a narrower route. Rendering it with
     * the error state's vocabulary teaches a user the product is broken. */
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByRole('button')).toBeNull();
    expect(screen.queryByText(catalog['search.state.error.retry'].message)).toBeNull();

    // Positive control: the notice itself is on screen, so the absences above
    // are absences within a rendered notice rather than within nothing.
    expect(screen.getByRole('status')).toBeTruthy();
  });

  it('always says what still works before it says what does not', () => {
    renderNotice({ mode: 'lexical', degraded: true });
    const notice = screen.getByRole('status');
    const text = notice.textContent ?? '';

    const reassurance = text.indexOf(catalog['search.retrieval.stillSearched'].message);
    const limit = text.indexOf(catalog['search.retrieval.degraded'].message);

    expect(reassurance).toBeGreaterThanOrEqual(0);
    expect(limit).toBeGreaterThan(reassurance);
  });
});

describe('noticeFor', () => {
  it('treats a degraded fallback as an incident even though the mode is lexical', () => {
    expect(noticeFor({ mode: 'lexical', degraded: true })).toBe('degraded');
    expect(noticeFor({ mode: 'lexical', degraded: false })).toBe('lexical');
    expect(noticeFor({ mode: 'dense', degraded: false })).toBe('lexical');
    expect(noticeFor({ mode: 'hybrid', degraded: false })).toBeNull();
  });

  it('still speaks when a hybrid search degraded', () => {
    // The server reports the mode it *ran*; if it reports hybrid and degraded
    // together, degraded wins. Silence here would be the exact failure D37 names.
    expect(noticeFor({ mode: 'hybrid', degraded: true })).toBe('degraded');
  });
});
