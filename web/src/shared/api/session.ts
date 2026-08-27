/* Where the access token lives, and why it lives here.
 *
 * `crates/api/src/auth.rs` reads exactly one thing: `Authorization: Bearer …`.
 * There is no cookie fallback on any route except `POST /auth/refresh`, so a
 * client that does not hold the token cannot call anything. Sign-in used to
 * validate the token and throw it away, which is why every screen was a
 * fixture: there was nothing to authenticate with.
 *
 * **In memory, in a module-private binding, and nowhere else.** Not
 * `localStorage`, not `sessionStorage`, not a cookie this script can read, not
 * React state and not a store — every one of those is readable by any script on
 * the origin and survives the tab, which is the difference between a token
 * stolen by an XSS and a token stolen by an XSS *and still valid tomorrow*. The
 * durable half of the session is the `enclave_rt` cookie, which is `HttpOnly`,
 * `SameSite=Strict` and scoped to `/api/v1/auth` — so it is not attached to
 * ordinary API calls and no handler outside auth ever sees it.
 *
 * The binding is not exported. `authorization()` returns a header object rather
 * than the string, so the only thing any caller can do with the token is send
 * it — `CLAUDE.md` rule 10 forbids rendering or logging a credential, and the
 * cheapest way to honour that is to make the credential unreachable rather than
 * to rely on everyone remembering.
 *
 * A reload therefore starts with no token. That is correct and not a bug: the
 * refresh cookie is still there, `refresh()` exchanges it for a new access
 * token, and the session survives without the credential ever having been
 * written to disk.
 */

import { z } from 'zod';

/** The token itself. Never exported, never logged, never rendered. */
let accessToken: string | null = null;

/**
 * When the held token stops being accepted, as epoch milliseconds.
 *
 * Used to refresh *before* a 401 rather than after one. The reactive path
 * (refresh on 401, replay) exists too and is the one that has to be correct,
 * but a proactive refresh means an expiry mid-session is not paid for by the
 * user in latency on a request that then has to be sent twice.
 */
let expiresAt = 0;

/**
 * The refresh in flight, if any.
 *
 * Six queries mount at once on the shell. Without this, a token that expired
 * while the tab was backgrounded produces six concurrent refreshes — and
 * because `auth.refresh_token.rotation` is on and `reuse_detection` is
 * `REVOKE_FAMILY`, five of them present an already-consumed cookie and the
 * server correctly concludes the token was stolen and revokes the whole family.
 * The user is signed out by their own client. Collapsing to one in-flight
 * promise is what stops rotation from looking like theft.
 */
let inFlight: Promise<boolean> | null = null;

/** A safety margin, so a token does not expire between the check and the send. */
const SKEW_MS = 30_000;

export function setAccessToken(token: string, expiresInSeconds: number): void {
  accessToken = token;
  expiresAt = Date.now() + expiresInSeconds * 1000;
}

export function clearAccessToken(): void {
  accessToken = null;
  expiresAt = 0;
}

/** Whether a token is held at all. Says nothing about whether the server still honours it. */
export function hasAccessToken(): boolean {
  return accessToken !== null;
}

function isExpired(): boolean {
  return accessToken === null || Date.now() >= expiresAt - SKEW_MS;
}

/**
 * The `Authorization` header, or nothing.
 *
 * Returns a header object rather than the token so that no call site ever holds
 * the string. There is deliberately no `getAccessToken()`.
 */
export function authorization(): Record<string, string> {
  return accessToken === null ? {} : { authorization: `Bearer ${accessToken}` };
}

/* ------------------------------------------------------------------ refresh */

/**
 * The double-submit half of the CSRF defence.
 *
 * `enclave_csrf` is deliberately **not** `HttpOnly` — it is the one cookie this
 * script is meant to read, because the server compares it against the
 * `x-csrf-token` header in constant time. An attacker's page can cause the
 * cookie to be *sent* but cannot read it to build the header.
 *
 * `POST /auth/refresh` is the only route that checks this, and that is not an
 * oversight: it is the only route whose authority is ambient. Everything else
 * authenticates with a bearer token, which a cross-origin page cannot attach.
 */
const CSRF_COOKIE = 'enclave_csrf';

function csrfToken(): string | null {
  if (typeof document === 'undefined') return null;
  for (const part of document.cookie.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== CSRF_COOKIE) continue;
    const value = part.slice(eq + 1).trim();
    return value.length > 0 ? value : null;
  }
  return null;
}

/**
 * The subset of `SessionResponse` a refresh is allowed to establish.
 *
 * `user` is present on the wire but the server does not re-read the directory
 * on this path — `displayName` comes back empty and `isAdmin` false. Parsing
 * those would let a refresh silently downgrade a signed-in admin to a
 * non-admin, so the identity of the session is `GET /me`'s to state and this
 * schema does not carry it at all.
 */
const RefreshBody = z.object({
  accessToken: z.string().min(1),
  expiresIn: z.number(),
});

/**
 * Exchange the refresh cookie for a new access token.
 *
 * Resolves `true` when a token was obtained. Every failure resolves `false`
 * rather than throwing: the caller's job is to decide whether to replay a
 * request or fall back to sign-in, and neither is served by an exception that
 * has to be caught in three places.
 *
 * Not routed through `request()` on purpose — that function calls this one, and
 * a refresh that could itself trigger a refresh is an unbounded recursion at
 * exactly the moment the session is least healthy.
 */
export async function refresh(): Promise<boolean> {
  if (inFlight !== null) return inFlight;

  inFlight = (async () => {
    const csrf = csrfToken();
    /* No cookie means no session to refresh — a first visit, or a signed-out
     * one. Attempting the call anyway would answer 401 and read, from the
     * outside, exactly like a rejected session. */
    if (csrf === null) return false;

    try {
      const response = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { accept: 'application/json', 'x-csrf-token': csrf },
        credentials: 'same-origin',
      });
      if (!response.ok) {
        clearAccessToken();
        return false;
      }
      const parsed = RefreshBody.safeParse(await response.json().catch(() => null));
      if (!parsed.success) {
        clearAccessToken();
        return false;
      }
      setAccessToken(parsed.data.accessToken, parsed.data.expiresIn);
      return true;
    } catch {
      /* A network failure is not a signed-out session. Leave whatever token is
       * held in place so a transient outage does not evict the user. */
      return false;
    } finally {
      inFlight = null;
    }
  })();

  return inFlight;
}

/**
 * Refresh if the held token is at or near expiry.
 *
 * Called before every request. When a token is held and healthy this is a
 * comparison against `Date.now()` and nothing else.
 */
export async function ensureFreshToken(): Promise<void> {
  if (!isExpired()) return;
  await refresh();
}
