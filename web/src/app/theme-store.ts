import { create } from 'zustand';

/* Theme, in the one place that owns it.
 *
 * `docs/09 §17`: light and dark are both first-class, both derive from the same
 * token set, theme follows the system preference by default and an explicit
 * override wins. `tokens.css` keys its whole dark ladder off
 * `[data-theme="dark"]` and nothing else, so the resolved answer is written to
 * that attribute rather than duplicated into a media query — a second copy of
 * the palette is a second thing to drift from the reference.
 */

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'enclave.theme';

function systemPreference(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function stored(): Theme | null {
  const value = window.localStorage.getItem(STORAGE_KEY);
  return value === 'dark' || value === 'light' ? value : null;
}

function apply(theme: Theme): void {
  document.documentElement.dataset['theme'] = theme;
}

export interface ThemeState {
  readonly theme: Theme;
  /** True while no explicit choice has been made, so the system preference still rules. */
  readonly followsSystem: boolean;
  setTheme: (theme: Theme) => void;
}

const initialExplicit = typeof window === 'undefined' ? null : stored();
const initial: Theme =
  initialExplicit ?? (typeof window === 'undefined' ? 'light' : systemPreference());

export const useThemeStore = create<ThemeState>((set) => ({
  theme: initial,
  followsSystem: initialExplicit === null,
  setTheme: (theme) => {
    window.localStorage.setItem(STORAGE_KEY, theme);
    apply(theme);
    set({ theme, followsSystem: false });
  },
}));

/**
 * Resolve and paint before React mounts, so a dark-preferring user never sees a
 * light frame first.
 */
export function initTheme(): void {
  apply(useThemeStore.getState().theme);
  // A user who has not chosen keeps following the system, including when it
  // changes under them mid-session.
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (!useThemeStore.getState().followsSystem) return;
    const next = systemPreference();
    apply(next);
    useThemeStore.setState({ theme: next });
  });
}
