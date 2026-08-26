import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { ApiError, request, SESSION_ENDED } from '../../src/shared/api/client.ts';
import {
  authorization,
  clearAccessToken,
  hasAccessToken,
  setAccessToken,
} from '../../src/shared/api/session.ts';

/* The session layer, which is the whole reason any screen has data.
 *
 * `crates/api/src/auth.rs` reads `Authorization: Bearer …` and nothing else. A
 * client that does not attach it is a client where every screen is a fixture —
 * which is precisely the state this work found the application in.
 */

const Body = z.object({ ok: z.boolean() });

function json(body: unknown, status = 200, requestId = 'req-1'): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'x-request-id': requestId },
  });
}

/* `vi.fn(async () => …)` infers a zero-argument signature, so reading
 * `calls[0][1]` off it is a type error even though `fetch` is always called with
 * two. Declaring the signature once here keeps the assertions readable and
 * avoids an `as any` the lint gate would refuse anyway. */
type FetchMock = (input: string, init?: RequestInit) => Promise<Response>;

function headersOf(mock: { mock: { calls: Parameters<FetchMock>[] } }, index: number) {
  return (mock.mock.calls[index]?.[1]?.headers ?? {}) as Record<string, string>;
}

function errorBody(code: string) {
  return { error: { code, message: 'nope', remediation: '', requestId: 'req-1', details: [] } };
}

beforeEach(() => {
  clearAccessToken();
  document.cookie = 'enclave_csrf=; Max-Age=0; path=/';
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearAccessToken();
});

describe('the access token', () => {
  it('is attached to every request once held', async () => {
    setAccessToken('tok-abc', 600);
    const fetchMock = vi.fn<FetchMock>(async () => json({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    await request('/me', Body);

    expect(headersOf(fetchMock, 0)['authorization']).toBe('Bearer tok-abc');
  });

  it('is not attached to an anonymous request', async () => {
    setAccessToken('tok-abc', 600);
    const fetchMock = vi.fn<FetchMock>(async () => json({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    await request('/auth/login', Body, { method: 'POST', body: {}, anonymous: true });

    expect(headersOf(fetchMock, 0)['authorization']).toBeUndefined();
  });

  /* The token is held so it can be *sent*, and for no other purpose.
   * `CLAUDE.md` rule 10 forbids rendering or logging a credential, and the
   * cheapest way to honour that is to make it unreachable rather than to rely
   * on everyone remembering. There is deliberately no `getAccessToken()`. */
  it('is reachable only as a header, never as a bare value', () => {
    setAccessToken('tok-secret', 600);

    expect(hasAccessToken()).toBe(true);
    /* The only accessor returns a header object. `hasAccessToken` answers a
     * boolean and never the string. If a `getAccessToken()` is ever added, this
     * module's whole guarantee is gone and this test is where to argue about
     * it. */
    expect(authorization()).toEqual({ authorization: 'Bearer tok-secret' });
    expect(hasAccessToken()).not.toBe('tok-secret');
  });

  it('is dropped on clear', () => {
    setAccessToken('tok', 600);
    clearAccessToken();
    expect(hasAccessToken()).toBe(false);
    expect(authorization()).toEqual({});
  });
});

describe('a 401 is one refresh and one replay, and then the session is over', () => {
  it('refreshes and replays when the refresh succeeds', async () => {
    setAccessToken('stale', 600);
    document.cookie = 'enclave_csrf=csrf-value; path=/';

    const fetchMock = vi
      .fn<FetchMock>()
      /* The original request, rejected. */
      .mockResolvedValueOnce(json(errorBody('SESSION_EXPIRED'), 401))
      /* The refresh. */
      .mockResolvedValueOnce(json({ accessToken: 'fresh', expiresIn: 600 }))
      /* The replay. */
      .mockResolvedValueOnce(json({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(request('/me', Body)).resolves.toEqual({ ok: true });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/api/v1/auth/refresh');
    /* The double-submit half of the CSRF defence: the header must carry the
     * cookie's value, which only same-origin script can read. */
    expect(headersOf(fetchMock, 1)['x-csrf-token']).toBe('csrf-value');
    /* The replay carries the *new* token, not the stale one. */
    expect(headersOf(fetchMock, 2)['authorization']).toBe('Bearer fresh');
  });

  it('ends the session when the refresh itself is refused', async () => {
    setAccessToken('stale', 600);
    document.cookie = 'enclave_csrf=csrf-value; path=/';

    const fetchMock = vi
      .fn<FetchMock>()
      .mockResolvedValueOnce(json(errorBody('SESSION_EXPIRED'), 401))
      .mockResolvedValueOnce(json(errorBody('SESSION_EXPIRED'), 401));
    vi.stubGlobal('fetch', fetchMock);

    await expect(request('/me', Body)).rejects.toMatchObject({
      failure: { code: SESSION_ENDED },
    });
    expect(hasAccessToken()).toBe(false);
  });

  /* A step-up challenge is a prompt, not an expiry. Refreshing against one would
   * burn the refresh token and still not satisfy the challenge — and, worse,
   * would turn "confirm your identity" into "you have been signed out".
   * `docs/17 §7`. */
  it('never refreshes against a step-up challenge', async () => {
    setAccessToken('good', 600);
    document.cookie = 'enclave_csrf=csrf-value; path=/';

    const fetchMock = vi.fn<FetchMock>(async () => json(errorBody('MFA_REQUIRED'), 401));
    vi.stubGlobal('fetch', fetchMock);

    await expect(request('/me', Body)).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(hasAccessToken()).toBe(true);
  });
});

describe('the response', () => {
  it('treats 204 as success with nothing to parse', async () => {
    setAccessToken('tok', 600);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 204 })));

    await expect(request('/auth/logout', z.undefined(), { method: 'POST' })).resolves.toBeUndefined();
  });

  /* `docs/17 §3`: a parse failure is an error state, not a silent default.
   * Catching it into `{}` would give a row every capability `false`, which reads
   * as *policy denied everything* — the wrong story told confidently. */
  it('reports a shape mismatch as a non-retryable failure, not as a denial', async () => {
    setAccessToken('tok', 600);
    vi.stubGlobal('fetch', vi.fn(async () => json({ unexpected: true })));

    await expect(request('/me', Body)).rejects.toMatchObject({
      failure: { kind: 'failed', code: 'response_shape', retryable: false },
    });
  });

  it('classifies a 403 as a denial carrying the server’s words', async () => {
    setAccessToken('tok', 600);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        json(
          {
            error: {
              code: 'ACCESS_DENIED',
              message: 'You do not have access to this.',
              remediation: 'REQUEST_ACCESS',
              requestId: 'req-403',
            },
          },
          403,
          'req-403',
        ),
      ),
    );

    await expect(request('/files/x', Body)).rejects.toMatchObject({
      failure: {
        kind: 'denied',
        code: 'ACCESS_DENIED',
        message: 'You do not have access to this.',
        remediation: 'REQUEST_ACCESS',
      },
    });
  });
});
