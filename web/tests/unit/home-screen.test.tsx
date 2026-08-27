import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { HomeView } from '../../src/features/home/home-screen.tsx';
import { buildHome } from '../../src/features/home/fixture.ts';

/* Home's success state.
 *
 * `docs/12 §1.1` draws the line at our own boundary: whether `Intl` pluralizes
 * English correctly is the platform's problem, and whether react-intl caches
 * formatters is react-intl's. What is ours is that the screen *reaches* for
 * `Intl` at all rather than hand-building `2 h ago` the way the design
 * reference does, that a relative time is never shown without the absolute one
 * a user could quote to support, and that a classification is never carried by
 * colour alone.
 */

/** A fixed local wall clock, so a relative time is a value and not a moving target. */
const MORNING = new Date(2026, 7, 20, 9, 30, 0);
const AFTERNOON = new Date(2026, 7, 20, 14, 0, 0);
const EVENING = new Date(2026, 7, 20, 20, 15, 0);

/* `globals: false` in `vite.config.ts` means Testing Library never registers its
 * automatic afterEach cleanup, so without this each render stacks another copy
 * of the screen into the same document — and every assertion about an absence
 * would then be reading the previous test's DOM and passing for the wrong
 * reason. */
afterEach(cleanup);

function renderWith(ui: ReactElement) {
  return render(<I18nProvider>{ui}</I18nProvider>);
}

describe('Home, success', () => {
  it('greets the user by name and states the date, the workspace and the count', () => {
    const data = buildHome(MORNING);
    renderWith(<HomeView data={data} now={MORNING} />);

    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Good morning, Priya');
    expect(screen.getByText(/Aug 20, 2026 · Finance · 4 things need your attention/)).toBeTruthy();
  });

  it('chooses the greeting from the reader’s own wall clock', () => {
    const data = buildHome(AFTERNOON);

    const { unmount } = renderWith(<HomeView data={data} now={AFTERNOON} />);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Good afternoon, Priya');
    unmount();

    renderWith(<HomeView data={data} now={EVENING} />);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Good evening, Priya');
  });

  it('pluralizes the attention count through ICU rather than by concatenation', () => {
    const data = buildHome(MORNING);
    renderWith(<HomeView data={{ ...data, attention: data.attention.slice(0, 1) }} now={MORNING} />);

    expect(screen.getByText(/1 thing needs your attention/)).toBeTruthy();
    expect(screen.queryByText(/1 things/)).toBeNull();
  });

  it('renders every relative time through Intl, with the absolute value alongside it', () => {
    const data = buildHome(MORNING);
    const { container } = renderWith(<HomeView data={data} now={MORNING} />);

    const times = [...container.querySelectorAll('time')];
    /* The positive control. "No time lacks a title" passes for free against a
     * screen that renders no times at all (`docs/17 §10`), so the count is
     * asserted first: four attention items and four recent files. */
    expect(times).toHaveLength(8);

    for (const time of times) {
      // Machine-readable for a parser, absolute for a support call, relative
      // for a reader — all three, never only the third.
      expect(time.getAttribute('datetime')).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(time.getAttribute('title')).toBeTruthy();
      expect(time.textContent).toBeTruthy();
      expect(time.textContent).not.toBe(time.getAttribute('title'));
    }

    // The oldest attention item is four days back, which `Intl` renders in days
    // rather than in the reference's hand-built "Fri".
    expect(screen.getByText('4 days ago')).toBeTruthy();
    expect(screen.getByText('2 hours ago')).toBeTruthy();
  });

  it('carries every classification as text as well as colour', () => {
    const data = buildHome(MORNING);
    const { container } = renderWith(<HomeView data={data} now={MORNING} />);

    const badges = [...container.querySelectorAll('.home-classification')];
    expect(badges).toHaveLength(data.recent.length);

    const levels = badges.map((badge) => badge.getAttribute('data-level'));
    expect(levels).toEqual(['internal', 'highlyConfidential', 'confidential', 'restricted']);

    // `docs/09 §15`: no information conveyed by colour alone.
    expect(badges.map((badge) => badge.textContent)).toEqual([
      'Internal',
      'Highly confidential',
      'Confidential',
      'Restricted',
    ]);
  });

  it('names each section and puts the sections in reading order', () => {
    renderWith(<HomeView data={buildHome(MORNING)} now={MORNING} />);

    const sections = screen.getAllByRole('heading', { level: 2 }).map((node) => node.textContent);
    expect(sections).toEqual(['Needs your attention', 'Continue working', 'Recent asks']);
  });

  it('falls back to a per-section line when one section is empty and the screen is not', () => {
    const data = buildHome(MORNING);
    renderWith(<HomeView data={{ ...data, asks: [] }} now={MORNING} />);

    expect(screen.getByText('You have not asked anything yet.')).toBeTruthy();
    // The positive control: the rest of the screen is still the success state,
    // not the whole-screen empty state.
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Good morning, Priya');
    expect(screen.queryByText('Your workspace is quiet')).toBeNull();
  });
});
