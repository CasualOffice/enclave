import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App } from './app/app.tsx';
import { initTheme } from './app/theme-store.ts';
import { I18nProvider } from './shared/i18n/index.tsx';
import './styles/base.css';

/* Theme is resolved and painted before React mounts, so a dark-preferring user
 * never sees a light frame first (`docs/09 §17`). */
initTheme();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      /* `docs/17 §4.1`: **`capabilities` is never cached beyond its request.**
       * It is not a property of a file — it is a property of this user, this
       * action, this moment (`docs/05 §7`), and caching it is how a stale
       * permission renders as an enabled button. Zero is the safe default for
       * every capability-bearing query, and a query that is genuinely static
       * opts *out* of it explicitly rather than inheriting a looser default. */
      staleTime: 0,
      /* A denial is not a failure and retrying it teaches a user the product is
       * broken (`docs/17 §7`). The API client already separates the two; this
       * stops React Query from re-issuing anything the client called final. */
      retry: (failureCount, error) =>
        failureCount < 2 && error instanceof Error && error.name !== 'ApiError',
      refetchOnWindowFocus: false,
    },
  },
});

const container = document.getElementById('root');
if (container === null) throw new Error('#root is missing from index.html');

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <I18nProvider>
        <App />
      </I18nProvider>
    </QueryClientProvider>
  </StrictMode>,
);
