import type { ReactElement, ReactNode } from 'react';
import { render, type RenderResult } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nProvider } from '../src/shared/i18n/index.tsx';

/* The providers a screen needs to mount at all.
 *
 * Screens read the network through TanStack Query now, so `render(<Screen />)`
 * throws "No QueryClient set" — which is a real failure, not test friction: a
 * screen that fetches must be mounted the way the application mounts it.
 *
 * **A fresh client per render.** A shared one would carry one test's cached
 * response into the next, and the tests that would break are precisely the ones
 * asserting an *empty* or *loading* state — they would pass against the previous
 * test's data and fail only when reordered.
 */
export function testQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        /* No retries: a test asserting the error state should reach it on the
         * first answer, not three seconds later. */
        retry: false,
        staleTime: 0,
        gcTime: 0,
      },
    },
  });
}

export function Providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={testQueryClient()}>
      <I18nProvider>{children}</I18nProvider>
    </QueryClientProvider>
  );
}

/** `render`, with the providers the application supplies in `main.tsx`. */
export function renderWithProviders(ui: ReactElement): RenderResult {
  return render(<Providers>{ui}</Providers>);
}
