import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { Button } from '../../src/shared/ui/primitives.tsx';
import { HomeView } from '../../src/features/home/home-screen.tsx';
import { ErrorState } from '../../src/features/home/states.tsx';
import { buildHome } from '../../src/features/home/fixture.ts';

/* The three ways a control can be non-actionable, on the screen that has all of
 * one of them.
 *
 * `docs/17 §6` and `docs/17 §10`'s F2: **denied and unbuilt may never look
 * alike, and unbuilt is never focusable.** This is a security contract. Home has
 * no backend at all, so every action on it is unbuilt — which makes Home
 * exactly the surface where the habit gets taught. A user who learns here that
 * dimmed means "not written yet" carries that reading to the file row where
 * dimmed means "DLP refused this".
 */

const NOW = new Date(2026, 7, 20, 9, 30, 0);

/* `globals: false` means Testing Library's automatic cleanup is never
 * registered, and the id-uniqueness assertion below would otherwise be reading
 * three stacked copies of the screen — which is a duplicate-id finding the
 * product does not have. */
afterEach(cleanup);

function renderWith(ui: ReactElement) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

describe('Home’s controls', () => {
  it('renders every approval action unbuilt: neutral, described, and out of the tab order', () => {
    const { container } = renderWith(<HomeView data={buildHome(NOW)} now={NOW} />);

    const unbuilt = [...container.querySelectorAll('button[data-state="unbuilt"]')];
    /* The positive control first. "No control is focusable" and "nothing is
     * denied" both pass for free against a screen that renders no controls
     * (`docs/17 §10`), so the population is asserted before anything is
     * asserted about it: one action per attention item. */
    expect(unbuilt).toHaveLength(buildHome(NOW).attention.length);
    /* Two approvals on purpose: a real queue repeats a kind, and a repeated
     * catalog label is the case that used to collide two controls onto one
     * `aria-describedby` target. */
    expect(unbuilt.map((node) => node.textContent)).toEqual([
      'Approve',
      'Approve',
      'Review',
      'Sign',
    ]);

    for (const control of unbuilt) {
      // Not focusable: there is nothing to find out and nothing to do.
      expect((control as HTMLButtonElement).tabIndex).toBe(-1);
      expect(control.getAttribute('aria-disabled')).toBe('true');
      // Described by its own neutral note, never by a reason.
      const describedBy = control.getAttribute('aria-describedby');
      expect(describedBy).toBeTruthy();
      /* The description is the sentence, not the chip. Future tense, about the
       * product, and it names no remedy — there is nothing this user can do
       * about a milestone. */
      expect(document.getElementById(describedBy ?? '')?.textContent).toBe(
        'Arrives in a later release',
      );
    }

    // And none of them uses the denial treatment.
    expect(container.querySelectorAll('[data-state="denied"]')).toHaveLength(0);
  });

  it('never lets the unbuilt treatment share an attribute or a class with the denied one', () => {
    const { container } = renderWith(
      <>
        <HomeView data={buildHome(NOW)} now={NOW} />
        {/* Home has no denials of its own to render — it has no server to
         * refuse anything. The denied control is rendered here beside it so
         * the comparison is against a real one rather than against nothing,
         * which is the shape `ENC-673` asserts. */}
        <Button
          label="home.state.error.retry"
          state={{ kind: 'denied', reason: 'A barrier applies to this matter.' }}
        />
      </>,
    );

    const unbuilt = container.querySelector('button[data-state="unbuilt"]');
    const denied = container.querySelector('button[data-state="denied"]');
    expect(unbuilt).toBeTruthy();
    expect(denied).toBeTruthy();

    expect(unbuilt?.getAttribute('data-state')).not.toBe(denied?.getAttribute('data-state'));
    // Denied keeps its place in the tab order so a keyboard user can reach the
    // reason; unbuilt leaves it, because there is no reason to reach.
    expect((denied as HTMLButtonElement).tabIndex).toBe(0);
    expect((unbuilt as HTMLButtonElement).tabIndex).toBe(-1);
  });

  it('keeps a genuinely actionable control genuinely actionable', () => {
    /* The other half of the pair. If everything on this screen were inert, the
     * assertions above would be describing an inert page rather than a
     * deliberate treatment. Retry is a real control: a read that failed can be
     * tried again. */
    renderWith(
      <ErrorState error={{ retryable: true, requestId: '01ABCDEF' }} onRetry={() => undefined} />,
    );

    const retry = screen.getByRole('button', { name: 'Try again' });
    expect(retry.getAttribute('data-state')).toBeNull();
    expect(retry.getAttribute('aria-disabled')).toBeNull();
    expect((retry as HTMLButtonElement).tabIndex).toBe(0);
  });

  it('marks the two record-only sections once, rather than dressing records as controls', () => {
    const { container } = renderWith(<HomeView data={buildHome(NOW)} now={NOW} />);

    /* "Continue working" and "Recent asks" have no backend to open anything
     * with, so they are records rather than controls: no button, no cursor
     * promise, and one neutral chip on the section saying so. */
    expect(container.querySelectorAll('.home-recent button')).toHaveLength(0);
    expect(container.querySelectorAll('.home-asks button')).toHaveLength(0);
    // The positive control: the rows are there to be read.
    expect(container.querySelectorAll('.home-recent-row').length).toBeGreaterThan(0);
    expect(container.querySelectorAll('.home-ask').length).toBeGreaterThan(0);

    expect(screen.getByText('Opening a file from here arrives in a later release.')).toBeTruthy();
    expect(screen.getByText('Re-running an ask arrives with Ask, in a later release.')).toBeTruthy();
  });
});

describe('Home’s DOM ids', () => {
  it('emits no duplicate id and no dangling aria reference', () => {
    const { container } = renderWith(<HomeView data={buildHome(NOW)} now={NOW} />);

    const ids = [...container.querySelectorAll('[id]')].map((node) => node.id);
    /* The positive control: Home does emit ids — the section headings and the
     * `Later` note behind each unbuilt control — so the uniqueness claim below
     * is about a real population. */
    expect(ids.length).toBeGreaterThan(3);
    expect(new Set(ids).size).toBe(ids.length);

    /* `Button` falls back to deriving its note id from the catalog key, so two
     * controls sharing a label emit one id twice unless the caller supplies
     * `describedById` — and their `aria-describedby` then resolves to the same
     * node. That is an axe `duplicate-id-aria` failure, tagged `wcag2a` and in
     * the set `tests/a11y/routes.spec.ts` runs. Home passes an item-keyed id;
     * this is the assertion that keeps a regression from landing quietly, and
     * the fixture's two `Approve` buttons are what make it bite. */
    const references = [...container.querySelectorAll('[aria-describedby], [aria-labelledby]')];
    expect(references.length).toBeGreaterThan(3);
    for (const node of references) {
      const target =
        node.getAttribute('aria-describedby') ?? node.getAttribute('aria-labelledby') ?? '';
      expect(container.querySelectorAll(`[id="${target}"]`)).toHaveLength(1);
    }
  });
});
