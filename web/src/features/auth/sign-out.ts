import { z } from 'zod';
import { request } from '../../shared/api/client.ts';
import { clearAccessToken } from '../../shared/api/session.ts';

/* Ending a session, and the order the two halves have to happen in.
 *
 * `POST /api/v1/auth/logout` answers `204` and clears both cookies — the
 * `HttpOnly` refresh cookie and the CSRF cookie. That is the half that matters,
 * because it is the half an attacker holding a stolen refresh token would still
 * be stopped by; dropping the in-memory access token alone would leave a
 * perfectly valid refresh cookie in the browser, and the next reload would sign
 * the user straight back in.
 *
 * The local token is cleared **whatever the server said**. A logout that fails
 * on the network must not leave the user looking signed in: the honest state of
 * a browser whose user has asked to leave is signed out, and the worst case of
 * clearing early is a session row that expires on its own schedule. The
 * opposite mistake — refusing to log out because the request failed — is the
 * one that gets someone's mail read on a shared machine.
 */

/** `204 No Content`: nothing to parse, and the schema says so rather than guessing. */
const NoContent = z.undefined();

export async function signOut(): Promise<void> {
  try {
    await request('/auth/logout', NoContent, { method: 'POST' });
  } finally {
    clearAccessToken();
    /* A full reload rather than a state transition. It is the only way to be
     * certain no component is still holding a rendered copy of the previous
     * user's data — TanStack Query's cache, a Zustand selection set, a memo
     * inside a virtualized list. Clearing them individually is a list somebody
     * eventually forgets to add to. */
    window.location.assign('/');
  }
}
