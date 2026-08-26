import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { FailureState } from '../../src/shared/ui/surface-states.tsx';
import { failureOf } from '../../src/shared/api/failure.ts';
import { ApiError } from '../../src/shared/api/client.ts';

afterEach(cleanup);

/* `docs/17 §10` F3, and the reason it is a permanent test rather than a review
 * note.
 *
 * A policy denial is a *successful* request with a refusing answer. Offering
 * "Try again" on it teaches a user that the product is broken rather than that
 * they lack permission — so they retry, it refuses again, and they file a bug
 * instead of an access request. A failure is the opposite: it may well work on
 * the second attempt, and withholding retry there makes a transient blip look
 * permanent.
 *
 * The two live one branch apart in one component, which is exactly the kind of
 * place a later refactor collapses them.
 */

function renderFailure(error: unknown, onRetry?: () => void) {
  return render(
    <I18nProvider>
      <FailureState failure={failureOf(error)} onRetry={onRetry ?? (() => undefined)} />
    </I18nProvider>,
  );
}

const RETRY = catalog['surface.error.retry'].message;

describe('a denial is not a failure', () => {
  const denial = new ApiError({
    kind: 'denied',
    code: 'ACCESS_DENIED',
    message: 'You do not have access to this.',
    remediation: 'REQUEST_ACCESS',
    requestId: '01a0402d-cb72-76e2-8f0e-ee21277e71e0',
  });

  it('renders the server’s own words, and no retry', () => {
    renderFailure(denial);

    // Positive control: the panel rendered, so the absence below means something.
    expect(screen.getByText('You do not have access to this.')).toBeTruthy();
    expect(screen.getByText('ACCESS_DENIED')).toBeTruthy();

    expect(screen.queryByRole('button', { name: RETRY })).toBeNull();
  });

  it('shows the server’s remediation and composes none of its own', () => {
    renderFailure(denial);

    expect(screen.getByText('REQUEST_ACCESS')).toBeTruthy();
    /* `CLAUDE.md` rule 10: never reveal which rule matched. The client has no
     * rule text to leak because none reaches it — this asserts we did not
     * invent a substitute. */
    expect(screen.queryByText(catalog['surface.denied.noReason'].message)).toBeNull();
  });

  it('says so plainly when the server sent no message, rather than inventing one', () => {
    renderFailure(
      new ApiError({
        kind: 'denied',
        code: 'DLP_BLOCKED',
        message: '',
        remediation: undefined,
        requestId: 'r-1',
      }),
    );

    expect(screen.getByText(catalog['surface.denied.noReason'].message)).toBeTruthy();
    expect(screen.queryByRole('button', { name: RETRY })).toBeNull();
  });
});

describe('a failure is not a denial', () => {
  it('offers retry and a copyable request ID when the failure is retryable', () => {
    renderFailure(
      new ApiError({ kind: 'failed', code: 'http_503', retryable: true, requestId: 'req-503' }),
    );

    expect(screen.getByRole('button', { name: RETRY })).toBeTruthy();
    expect(screen.getByText('req-503')).toBeTruthy();
    expect(screen.getByRole('button', { name: catalog['surface.error.copy'].message })).toBeTruthy();
  });

  it('withholds retry when retrying cannot succeed', () => {
    renderFailure(
      new ApiError({ kind: 'failed', code: 'http_400', retryable: false, requestId: 'req-400' }),
    );

    // Positive control first: the failure panel is on screen.
    expect(screen.getByText(catalog['surface.error.bodyFinal'].message)).toBeTruthy();
    expect(screen.queryByRole('button', { name: RETRY })).toBeNull();
  });

  it('reports an unrecognised throw as a failure, never as a denial', () => {
    /* Guessing "denied" from a `TypeError` in our own code would tell a user
     * they lack permission because we threw. */
    renderFailure(new TypeError('undefined is not a function'));

    expect(screen.getByText(catalog['surface.error.title'].message)).toBeTruthy();
    expect(screen.queryByText(catalog['surface.denied.title'].message)).toBeNull();
  });
});

describe('the two treatments never share a class', () => {
  it('marks a denial and a failure with different tones', () => {
    const denied = renderFailure(
      new ApiError({
        kind: 'denied',
        code: 'ACCESS_DENIED',
        message: 'no',
        remediation: undefined,
        requestId: 'r',
      }),
    );
    const deniedTone = denied.container
      .querySelector('.surface-state')
      ?.getAttribute('data-tone');
    cleanup();

    const failed = renderFailure(
      new ApiError({ kind: 'failed', code: 'http_500', retryable: true, requestId: 'r' }),
    );
    const failedTone = failed.container
      .querySelector('.surface-state')
      ?.getAttribute('data-tone');

    expect(deniedTone).toBeTruthy();
    expect(failedTone).toBeTruthy();
    expect(deniedTone).not.toBe(failedTone);
  });
});
