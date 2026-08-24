import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './app/app.tsx';
import { I18nProvider } from './shared/i18n/index.tsx';
import './styles/base.css';

/* `docs/09 §17`: theme follows the system preference, with an explicit
 * override. Resolved to the attribute `tokens.css` keys off, before the first
 * paint, so a dark-preferring user never sees a light frame first. */
function resolveTheme(): void {
  const stored = window.localStorage.getItem('enclave.theme');
  const preferred =
    stored === 'dark' || stored === 'light'
      ? stored
      : window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
  document.documentElement.dataset['theme'] = preferred;
}

resolveTheme();

const container = document.getElementById('root');
if (container === null) throw new Error('#root is missing from index.html');

createRoot(container).render(
  <StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </StrictMode>,
);
