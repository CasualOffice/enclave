import { afterEach, expect, test, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactElement } from 'react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import SignInScreen from '../../src/features/auth/signin-screen.tsx';

/* Sign-in, tested for the four things that would be security defects rather
 * than bugs (`docs/12 §1.2` — every one of these was watched to fail first).
 *
 *   1. The request carries no tenant identifier of any kind (`CLAUDE.md` rule 3),
 *      paired with a positive control that the request was made at all. An
 *      assertion about an absence passes for free against a component that
 *      sends nothing (`docs/17 §10`).
 *   2. A known address and an unknown address are indistinguishable, even when
 *      the *server* discloses the difference. Account enumeration.
 *   3. The unbuilt affordance is not focusable, is never in the denial
 *      treatment, and offers no remedy (`plans/M5-MVP-GA.md` D33, `docs/17 §6` F2).
 *   4. A failed request offers retry and a request ID; a refused sign-in and a
 *      policy denial offer neither (`docs/17 §7` F3).
 *
 * And one from rule 10: the access token never reaches the DOM.
 */

/** A `Response`-alike, which is all `shared/api/client.ts` touches. */
function respondWith(status: number, body: unknown, requestId = 'REQ-TEST-0001') {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ 'x-request-id': requestId }),
    json: async () => body,
  }));
}

/* Obviously synthetic and assembled from parts, so no gate ever has to decide
 * whether a tracked file contains a credential (`CLAUDE.md` rule 11). */
const PASSWORD = ['not', 'a', 'real', 'password'].join('-');
const ACCESS_TOKEN = ['eyJhbGciOiJFZERTQSJ9', 'not-a-real-token', 'signature'].join('.');
const EMAIL = 'amara@example.com';

const OK_BODY = {
  accessToken: ACCESS_TOKEN,
  tokenType: 'Bearer',
  expiresIn: 600,
  sessionId: '01937f30-0000-0000-0000-000000000001',
  user: { id: '01937f2c-0000-0000-0000-000000000001', displayName: 'Amara Osei', isAdmin: false },
};

function wrap(node: ReactElement) {
  return <I18nProvider>{node}</I18nProvider>;
}

function fillAndSubmit(password = PASSWORD) {
  fireEvent.change(screen.getByLabelText('Email address'), { target: { value: EMAIL } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
}

function card(): HTMLElement {
  const element = document.querySelector<HTMLElement>('[data-signin-state]');
  if (element === null) throw new Error('the sign-in card is not rendered');
  return element;
}

function answerText(): string {
  return document.querySelector('.sgn-answer')?.textContent ?? '';
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------- rule 3

test('the sign-in request carries the credentials and no tenant identifier of any kind', async () => {
  const fetchMock = respondWith(200, OK_BODY);
  vi.stubGlobal('fetch', fetchMock);

  render(wrap(<SignInScreen />));
  fillAndSubmit();

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  const call = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
  const [url, init] = call;

  /* The positive control. Without these four the absence assertions below pass
   * against a component that never called the network at all. */
  expect(url).toBe('/api/v1/auth/login');
  expect(init.method).toBe('POST');
  const body: unknown = JSON.parse(String(init.body));
  expect(body).toEqual({ email: EMAIL, password: PASSWORD });

  // …and now the absence, which means something because of the above.
  const keys = Object.keys(body as Record<string, unknown>);
  expect(keys.sort()).toEqual(['email', 'password']);
  for (const forbidden of [
    'tenant',
    'tenantId',
    'tenant_id',
    'workspace',
    'workspaceId',
    'org',
    'orgId',
    'organization',
    'domain',
    'realm',
    'account',
  ]) {
    expect(keys).not.toContain(forbidden);
  }

  const headerNames = Object.keys(init.headers as Record<string, string>).map((name) =>
    name.toLowerCase(),
  );
  // Positive control on the headers, for the same reason.
  expect(headerNames).toContain('content-type');
  expect(
    headerNames.filter(
      (name) => name.includes('tenant') || name.includes('workspace') || name.includes('org'),
    ),
  ).toEqual([]);

  // Nor in the URL: no query string, so no `?tenant=` either.
  expect(url).not.toContain('?');
});

// ------------------------------------------------------- account enumeration

test('an unknown address and a known address produce the same user-visible outcome', async () => {
  /* Both servers are *deliberately* chatty: one says the account does not
   * exist, the other says the password is wrong. If any of that reached the
   * screen, an attacker could sort a list of addresses into customers and
   * non-customers. The screen must render neither. */
  async function outcomeFor(status: number, body: unknown) {
    vi.stubGlobal('fetch', respondWith(status, body));
    render(wrap(<SignInScreen />));
    fillAndSubmit();
    await waitFor(() => {
      expect(answerText().length).toBeGreaterThan(0);
    });
    const result = { state: card().dataset['signinState'] ?? '', text: answerText() };
    cleanup();
    vi.unstubAllGlobals();
    return result;
  }

  const unknown = await outcomeFor(401, {
    code: 'USER_NOT_FOUND',
    message: `No account exists for ${EMAIL}`,
  });
  const known = await outcomeFor(401, {
    code: 'INVALID_CREDENTIALS',
    message: 'The password is incorrect',
  });

  // Positive control: something was actually rendered in both cases, so the
  // equality below is not two empty strings agreeing with each other.
  expect(unknown.text.length).toBeGreaterThan(0);
  expect(known.text.length).toBeGreaterThan(0);

  // Indistinguishable, in the words a person reads and in the state a test —
  // or a script — can select on.
  expect(unknown.text).toBe(known.text);
  expect(unknown.state).toBe(known.state);
  expect(unknown.state).toBe('refused');

  // And neither server sentence leaked through.
  expect(unknown.text).not.toContain('No account exists');
  expect(unknown.text).not.toContain(EMAIL);
  expect(known.text).not.toContain('password is incorrect');
});

// ---------------------------------------------------------- D33: unbuilt ≠ denied

test('the passkey affordance is unbuilt: not focusable, no remedy, never the denial treatment', () => {
  vi.stubGlobal('fetch', respondWith(200, OK_BODY));
  const { container } = render(wrap(<SignInScreen />));

  const passkey = screen.getByRole('button', { name: 'Continue with a passkey' });
  expect(passkey.getAttribute('tabindex')).toBe('-1');
  expect(passkey.getAttribute('aria-disabled')).toBe('true');
  expect(passkey.dataset['state']).toBe('unbuilt');

  /* The positive control for "not focusable": the working path in the same
   * card IS focusable, so `tabindex="-1"` is a property of this control rather
   * than of every control on the screen. */
  const submit = screen.getByRole('button', { name: 'Sign in' });
  expect(submit.getAttribute('tabindex')).toBeNull();
  expect(submit.getAttribute('aria-disabled')).toBeNull();

  // `ENC-673`: the two treatments never share a state, and nothing here is denied.
  expect(container.querySelectorAll('[data-state="denied"]')).toHaveLength(0);

  // A neutral `Later` chip — the marker D33 asks for…
  expect(container.querySelector('.ui-later')?.textContent).toBe('Later');
  // …a future-tense note about the product…
  expect(container.textContent).toContain('Passkeys arrive in a later release.');
  // …and no remedy, because there is nothing this user can do about a release date.
  expect(container.textContent).not.toContain('Request access');
});

// ------------------------------------------------- failure vs refusal vs denial

test('a failed request is retryable and carries a request ID', async () => {
  vi.stubGlobal('fetch', respondWith(503, { code: 'DEPENDENCY_DEGRADED', message: 'x' }, 'REQ-503'));
  render(wrap(<SignInScreen />));
  fillAndSubmit();

  await waitFor(() => {
    expect(card().dataset['signinState']).toBe('failed');
  });

  expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  expect(answerText()).toContain('REQ-503');
  expect(answerText()).toContain('Sign-in could not be completed');
});

test('a refused sign-in offers no retry and no request ID', async () => {
  vi.stubGlobal('fetch', respondWith(401, { code: 'INVALID_CREDENTIALS', message: 'x' }, 'REQ-401'));
  render(wrap(<SignInScreen />));
  fillAndSubmit();

  await waitFor(() => {
    expect(card().dataset['signinState']).toBe('refused');
  });

  // Positive control: the refusal is on screen, so the absences below are real.
  expect(answerText()).toContain('That email address and password do not match.');
  expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
  expect(answerText()).not.toContain('REQ-401');
  expect(answerText()).not.toContain('Request ID');
});

test('a policy denial renders the server’s own sentence and never a retry', async () => {
  vi.stubGlobal(
    'fetch',
    respondWith(
      403,
      {
        code: 'NETWORK_NOT_ALLOWED',
        message: 'Signing in is not permitted from this network.',
        remediation: 'Connect to the corporate VPN, or ask your security administrator.',
      },
      'REQ-403',
    ),
  );
  render(wrap(<SignInScreen />));
  fillAndSubmit();

  await waitFor(() => {
    expect(card().dataset['signinState']).toBe('denied');
  });

  // The server's words, verbatim — the client composes nothing (`docs/17 §7`).
  expect(answerText()).toContain('Signing in is not permitted from this network.');
  expect(answerText()).toContain('Connect to the corporate VPN');
  // A denial is not a failure: no retry, ever.
  expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull();
});

// ------------------------------------------------------------ loading, success

test('the loading state says what the policy chain is doing', async () => {
  let release: (() => void) | undefined;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      await held;
      return {
        ok: true,
        status: 200,
        headers: new Headers({ 'x-request-id': 'REQ-OK' }),
        json: async () => OK_BODY,
      };
    }),
  );

  render(wrap(<SignInScreen />));
  fillAndSubmit();

  await waitFor(() => {
    expect(card().dataset['signinState']).toBe('submitting');
  });
  expect(document.body.textContent).toContain('Checking your access…');
  expect(screen.getByRole('button', { name: 'Signing in…' }).getAttribute('aria-busy')).toBe('true');

  release?.();
  await waitFor(() => {
    expect(card().dataset['signinState']).toBe('success');
  });
});

test('a successful sign-in never puts the access token in the document', async () => {
  vi.stubGlobal('fetch', respondWith(200, OK_BODY));
  render(wrap(<SignInScreen />));
  fillAndSubmit();

  await waitFor(() => {
    expect(card().dataset['signinState']).toBe('success');
  });

  // Positive control: the success state really did render.
  expect(document.body.textContent).toContain('You’re signed in');
  // Rule 10. `Session` has no `accessToken` field, so there is nothing to leak.
  expect(document.body.innerHTML).not.toContain(ACCESS_TOKEN);
  expect(document.body.innerHTML).not.toContain(PASSWORD);
});
