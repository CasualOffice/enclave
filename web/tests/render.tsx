import type { ReactElement, ReactNode } from 'react';
import { render, type RenderResult } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nProvider, SOURCE_LOCALE } from '../src/shared/i18n/index.tsx';

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

export function Providers({
  children,
  locale = SOURCE_LOCALE,
}: {
  children: ReactNode;
  locale?: string;
}) {
  return (
    <QueryClientProvider client={testQueryClient()}>
      <I18nProvider locale={locale}>{children}</I18nProvider>
    </QueryClientProvider>
  );
}

/**
 * `render`, with the providers the application supplies in `main.tsx`.
 *
 * `locale` is how a screen test runs under `en-XA` or `en-XB` (`docs/14 §9`).
 * It defaults to the source locale, so an existing test asserting English text
 * keeps asserting English text — a pseudo-locale that silently became the
 * default would turn every one of them red for the wrong reason.
 */
export function renderWithProviders(
  ui: ReactElement,
  options: { readonly locale?: string } = {},
): RenderResult {
  return render(<Providers locale={options.locale ?? SOURCE_LOCALE}>{ui}</Providers>);
}
