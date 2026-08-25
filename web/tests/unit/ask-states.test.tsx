import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, within } from '@testing-library/react';
import AskScreen from '../../src/features/ask/ask-screen.tsx';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';

/* `docs/09 §11`: every surface defines all four states, and a component that
 * renders `null` while loading has three of them and fails review.
 *
 * Ask is the awkward case, because `unbuilt` is not one of the four — it is a
 * property of the *controls* (`docs/17 §6`), not of the *data surface*. These
 * assert both axes: that all four data states exist and are reachable, and that
 * the composer stays unbuilt across every one of them.
 */

function mount(search: string) {
  window.history.replaceState({}, '', `/ask${search}`);
  return render(
    <I18nProvider>
      <AskScreen />
    </I18nProvider>,
  );
}

afterEach(cleanup);

describe('the four states', () => {
  it('empty (new): says what the surface is for, and marks the missing action', () => {
    const { container, getByRole } = mount('');
    expect(getByRole('heading', { level: 2 }).textContent).toBe(catalog['ask.empty.title'].message);

    /* The `Later` chip sits in the slot where `docs/09 §11`'s "one action that
     * starts it" would be. Both halves are asserted: the marker, and the
     * sentence beside it. */
    const marker = container.querySelector('.ask-marker');
    expect(marker?.textContent).toContain(catalog['later.chip'].message);
    expect(marker?.textContent).toContain(catalog['ask.arrivesInM7'].message);
    expect(container.querySelector('[data-state="unbuilt"]')).not.toBeNull();
  });

  it('empty (new): draws the shape of an answer without any of its content', () => {
    const { container, queryByRole } = mount('');

    // `docs/09 §10`'s promise, present as a shape and stated in prose.
    const shape = container.querySelector('.ask-shape');
    expect(shape).not.toBeNull();
    expect(shape?.textContent).toContain(catalog['ask.shape.body'].message);
    expect(shape?.querySelectorAll('.ask-wire-source')).toHaveLength(2);

    /* And nothing that could be read as an answer: the wireframe is flat, not a
     * skeleton, because a shimmer would say an answer is on its way. */
    expect(container.querySelectorAll('.ui-skeleton')).toHaveLength(0);
    expect(queryByRole('status')).toBeNull();
  });

  it('loading: a busy region with the answer’s box model, not a spinner', () => {
    const { container, getByRole } = mount('?surface=loading');
    const status = getByRole('status');
    expect(status.getAttribute('aria-busy')).toBe('true');
    expect(status.textContent).toContain(catalog['ask.state.loading'].message);

    /* The shimmer is the busy treatment, and it is the one thing that separates
     * busy from unbuilt without reading a word (`docs/17 §6`). */
    expect(container.querySelectorAll('.ui-skeleton').length).toBeGreaterThan(0);
    // …and this state is not also claiming to be the wireframe.
    expect(container.querySelector('.ask-shape')).toBeNull();
  });

  it('empty (filtered): names the count outside scope and offers the way back', () => {
    const { container, getByRole } = mount('?surface=scope-empty');
    expect(getByRole('heading', { level: 2 }).textContent).toBe(
      catalog['ask.state.scopeEmpty.title'].message,
    );

    /* The count is the whole point of the state: it distinguishes an over-narrow
     * scope from an empty workspace. Matched loosely because the digits are
     * `Intl`-grouped and the grouping is the locale's business, not the test's. */
    const body = container.querySelector('.ask-state-body');
    expect(body?.textContent).toMatch(/outside the current scope/);
    expect(body?.textContent).toMatch(/\d/);

    expect(getByRole('button', { name: catalog['ask.state.scopeEmpty.action'].message }));
  });

  it('error: what failed, a retry, and a copyable request ID', () => {
    const { container, getByRole } = mount('?surface=error');
    const alert = getByRole('alert');
    expect(within(alert).getByRole('heading', { level: 2 }).textContent).toBe(
      catalog['ask.state.error.title'].message,
    );
    expect(alert.textContent).toContain(catalog['ask.state.error.body'].message);
    expect(getByRole('button', { name: catalog['ask.state.error.retry'].message }));

    const requestId = container.querySelector('.ask-request-id code');
    expect(requestId?.textContent).toMatch(/^[0-9A-Z]{26}$/);
  });

  it('a failure is not a denial: the error state is the only one with an action', () => {
    /* `docs/09 §11` and `docs/17 §7`. Retry belongs to a request that did not
     * complete and to nothing else — a policy denial that offered retry would
     * teach a user the product is broken rather than that they lack permission.
     *
     * Asserted as a contrast so neither half passes alone. */
    const enabled = (search: string) =>
      [...mount(search).container.querySelectorAll('button')].filter(
        (button) => button.getAttribute('aria-disabled') !== 'true',
      ).length;

    expect(enabled('?surface=error')).toBe(1);
    cleanup();
    expect(enabled('')).toBe(0);
    cleanup();
    expect(enabled('?surface=loading')).toBe(0);
  });
});

describe('the composer', () => {
  it('is present on every state, and unbuilt on every state', () => {
    for (const search of ['', '?surface=loading', '?surface=error', '?surface=scope-empty']) {
      const { container } = mount(search);
      const composer = container.querySelector('.ask-composer');
      expect(composer, search).not.toBeNull();

      const field = composer?.querySelector('input');
      expect(field?.getAttribute('aria-disabled'), search).toBe('true');
      expect(field?.getAttribute('tabindex'), search).toBe('-1');
      /* `readOnly`, not `disabled`: a disabled field loses the description that
       * carries the entire message (`docs/17 §6`). */
      expect(field?.hasAttribute('disabled'), search).toBe(false);
      expect((field as HTMLInputElement | null)?.readOnly, search).toBe(true);
      cleanup();
    }
  });

  it('states the default scope rather than naming a filter it does not apply', () => {
    const { container } = mount('');
    const foot = container.querySelector('.ask-composer-foot');
    expect(foot?.textContent).toContain(catalog['ask.composer.scope.libraries'].message);
    expect(foot?.textContent).toContain(catalog['ask.composer.scope.anyDate'].message);
  });
});
