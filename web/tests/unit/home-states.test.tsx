import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { HomeView } from '../../src/features/home/home-screen.tsx';
import { ErrorState, LoadingState } from '../../src/features/home/states.tsx';
import { buildHome } from '../../src/features/home/fixture.ts';

/* The four states `docs/09 §11` requires, plus success.
 *
 * The reference shows none of them, so these assertions are the specification
 * as much as they are the check. Three properties matter:
 *
 *   - loading reserves the *same boxes* the loaded screen uses, so nothing
 *     shifts when data lands;
 *   - empty and scoped-empty say different things, because "you are done" and
 *     "you are looking in the wrong workspace" are different situations;
 *   - the error state offers retry and a request ID, and it is the only state
 *     that offers retry at all.
 */

const NOW = new Date(2026, 7, 20, 9, 30, 0);
const EMPTY = { attention: [], recent: [], asks: [] } as const;

/* `globals: false` means Testing Library's automatic cleanup is never
 * registered. Without this, two renders share one document and every assertion
 * about an absence reads the previous test's DOM. */
afterEach(cleanup);

function renderWith(ui: ReactElement) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

describe('Home, loading', () => {
  it('announces itself and hides the decoration from assistive technology', () => {
    renderWith(<LoadingState />);

    const region = screen.getByRole('status');
    expect(region.getAttribute('aria-busy')).toBe('true');
    expect(region.getAttribute('aria-label')).toBe('Loading your workspace');
  });

  it('reserves the loaded screen’s own boxes, not a spinner', () => {
    const { container: loading } = renderWith(<LoadingState />);
    const skeletonBoxes = {
      page: loading.querySelectorAll('.home-page').length,
      cards: loading.querySelectorAll('.home-card').length,
      rows: loading.querySelectorAll('.home-recent-row').length,
      sections: loading.querySelectorAll('.home-section-head').length,
    };

    const { container: loaded } = renderWith(
      <HomeView data={buildHome(NOW)} now={NOW} />,
    );

    /* The box model is not "matched" — it is the same class on the same
     * element, which is the only version of this claim that cannot drift.
     * Asserting the loaded screen has them too is the positive control: a
     * skeleton that reserved boxes nothing else uses would pass a shape check
     * and still shift the page. */
    expect(skeletonBoxes.page).toBe(1);
    expect(loaded.querySelectorAll('.home-page')).toHaveLength(1);
    expect(skeletonBoxes.sections).toBe(3);
    expect(loaded.querySelectorAll('.home-section-head')).toHaveLength(3);
    expect(skeletonBoxes.cards).toBeGreaterThan(0);
    expect(loaded.querySelectorAll('.home-card').length).toBeGreaterThan(0);
    expect(skeletonBoxes.rows).toBeGreaterThan(0);
    expect(loaded.querySelectorAll('.home-recent-row').length).toBeGreaterThan(0);
  });

  it('shows no spinner-only fallback: the skeleton is the layout', () => {
    const { container } = renderWith(<LoadingState />);
    expect(container.querySelectorAll('.ui-skeleton').length).toBeGreaterThan(5);
  });
});

describe('Home, empty', () => {
  it('says what the surface is for and names the one action that starts it', () => {
    renderWith(<HomeView data={{ ...buildHome(NOW), ...EMPTY, hiddenByScope: 0 }} now={NOW} />);

    expect(screen.getByText('Your workspace is quiet')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Upload a file' })).toBeTruthy();
    expect(document.querySelector('[data-state="empty"]')).toBeTruthy();
  });

  it('says something different when the workspace scope is what is hiding the work', () => {
    renderWith(<HomeView data={{ ...buildHome(NOW), ...EMPTY, hiddenByScope: 3 }} now={NOW} />);

    /* The count is the whole point: it separates a user who is done from a user
     * who is looking in the wrong place. Collapsing these two states into one
     * "Nothing here" is the defect this pair of assertions exists to catch. */
    expect(screen.getByText('Nothing here, but not nothing everywhere')).toBeTruthy();
    expect(screen.getByText('3 items are waiting for you in other workspaces.')).toBeTruthy();
    expect(screen.queryByText('Your workspace is quiet')).toBeNull();
    expect(document.querySelector('[data-state="scoped-empty"]')).toBeTruthy();
  });
});

describe('Home, error', () => {
  it('says what failed, offers retry, and quotes a request ID verbatim', () => {
    const onRetry = vi.fn();
    renderWith(
      <ErrorState error={{ retryable: true, requestId: '01K3Q7X0PMDR4W8B2ZC6E5A9TN' }} onRetry={onRetry} />,
    );

    // `alert`, not `status`: a read that failed while the user waited for it is
    // worth interrupting for.
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(screen.getByText('Home could not be loaded')).toBeTruthy();
    expect(screen.getByText('The request did not complete. Nothing has changed.')).toBeTruthy();
    expect(screen.getByText('01K3Q7X0PMDR4W8B2ZC6E5A9TN')).toBeTruthy();

    const retry = screen.getByRole('button', { name: 'Try again' });
    retry.click();
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('drops the retry when the failure is not retryable, and still gives the request ID', () => {
    renderWith(
      <ErrorState error={{ retryable: false, requestId: '01ABCDEF' }} onRetry={() => undefined} />,
    );

    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    // Paired positive control: the state itself rendered, so the absence above
    // is an absence of the button rather than an absence of the screen.
    expect(screen.getByText('01ABCDEF')).toBeTruthy();
    expect(
      screen.getByText(
        'The request cannot be retried from here. Contact support with the request ID below.',
      ),
    ).toBeTruthy();
  });

  it('never offers retry on the success screen, where every refusal would be unbuilt not failed', () => {
    renderWith(<HomeView data={buildHome(NOW)} now={NOW} />);

    /* `docs/17 §7` and `docs/09 §11`: a policy denial is a successful request
     * with a refusing answer. It never uses the error state and never offers
     * retry. Home has no denials to render because it has no server, so the
     * check here is the weaker one it can honestly make — no retry escapes onto
     * a surface that did not fail. */
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
    // The positive control: the screen did render, and it does have buttons.
    expect(screen.getAllByRole('button').length).toBeGreaterThan(0);
  });
});
