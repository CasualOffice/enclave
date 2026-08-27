import { z } from 'zod';
import { ApiError, request } from '../../shared/api/client.ts';
import { setAccessToken } from '../../shared/api/session.ts';

/* The one request this screen makes: `POST /api/v1/auth/login` (`docs/05 §3.1`).
 *
 * Two rules shape this file and neither is a style preference.
 *
 * **The body carries two fields and nothing else.** No tenant id, no workspace
 * slug, no domain, no `X-Tenant` header — `CLAUDE.md` rule 3, and the client
 * (`docs/17 §9`) has no tenant parameter anywhere in its signatures precisely so
 * the mistake is unrepresentable rather than merely forbidden. The email's
 * domain is a domain; it is not a tenant selector.
 *
 * **The access token is never parsed into a value this application can render.**
 * `CLAUDE.md` rule 10 forbids logging or rendering a credential, and the
 * cheapest way to honour it is to make the credential absent from the type:
 * Zod validates that the server sent one, then the transform drops it. There is
 * no `accessToken` on `Session`, so no component can put it on screen and no
 * error boundary can serialize it into a report.
 */

/**
 * The wire shape of a successful login (`docs/05 §3.1`).
 *
 * Private on purpose — nothing outside this module gets to hold it, because
 * holding it means holding the token.
 */
const LoginBody = z.object({
  /* Validated as present and non-empty, then discarded by the transform below.
   * Asserting it exists is what stops "signed in" from being a lie; keeping it
   * is what would make rule 10 a matter of everyone remembering. */
  accessToken: z.string().min(1),
  tokenType: z.string(),
  expiresIn: z.number(),
  sessionId: z.string(),
  user: z.object({
    id: z.string(),
    displayName: z.string(),
    isAdmin: z.boolean(),
  }),
});

/**
 * What the screen is allowed to know about a successful sign-in. No token.
 *
 * The transform is also where the token is *kept*, and that placement is the
 * point. `crates/api/src/auth.rs` reads `Authorization: Bearer …` and nothing
 * else, so a sign-in that only validated the token and dropped it left every
 * subsequent request unauthenticated — which is precisely why every screen in
 * this application was reading a fixture. It now hands the token to
 * `shared/api/session`, which holds it in a module-private binding and exposes
 * no reader (only a header builder).
 *
 * So the token is used and still never rendered: it goes from the parsed body
 * straight into a closure the UI cannot reach, and `Session` — the only value
 * that leaves this module — has no field for it. `CLAUDE.md` rule 10 is
 * satisfied by the shape rather than by everyone remembering.
 */
export const Session = LoginBody.transform((body) => {
  setAccessToken(body.accessToken, body.expiresIn);
  return { sessionId: body.sessionId, user: body.user };
});

export type Session = z.infer<typeof Session>;

export interface Credentials {
  readonly email: string;
  readonly password: string;
}

/**
 * The three answers a sign-in attempt can produce, kept apart in the type
 * because a `catch` block that collapses them is exactly the defect
 * `docs/17 §7` describes.
 *
 * - `refused` — the server answered, and the answer is no. **Not an error, and
 *   not retryable-with-a-button**: the form is the retry. Carries no detail at
 *   all, which is the enumeration control (see `outcomeOf`).
 * - `denied` — a `403` from the policy chain, e.g. `NETWORK_NOT_ALLOWED`. A
 *   successful request with a refusing answer. Renders the server's own
 *   user-safe `message` and `remediation` (`docs/05 §5`) and **never** a retry.
 *   The client never composes this sentence itself (`docs/17 §7`).
 * - `failed` — the request did not complete: network, `5xx`, or a response that
 *   did not parse. This is the only one that gets the error state, a retry and
 *   a copyable request ID (`docs/09 §11`).
 */
export type SignInOutcome =
  | { readonly kind: 'refused' }
  | { readonly kind: 'denied'; readonly message: string; readonly remediation: string | undefined }
  | { readonly kind: 'failed'; readonly retryable: boolean; readonly requestId: string };

/**
 * Classify a thrown error into one of the three.
 *
 * **Every refusal collapses to one indistinguishable outcome.** An unknown
 * address, a known address with the wrong password, a locked account and a
 * rejected email format all land on `{ kind: 'refused' }` carrying no code, no
 * message and no request ID — so there is nothing for the screen to vary on
 * even if a later change wanted to. This is the same reasoning as `CLAUDE.md`
 * rule 7: a `403` confirms existence, so cross-tenant denials return `404`.
 * Here, *any* difference in what we render confirms existence, so there is no
 * difference to render.
 *
 * The one non-retryable failure that is **not** a refusal is a response that
 * did not parse: `docs/17 §3` is explicit that a parse failure is an error
 * state rather than a silent default, and telling a user their password is
 * wrong because our schema drifted would be the wrong story told confidently.
 */
export function outcomeOf(error: unknown): SignInOutcome {
  if (!(error instanceof ApiError)) {
    return { kind: 'failed', retryable: false, requestId: '' };
  }

  const { failure } = error;

  if (failure.kind === 'denied') {
    return { kind: 'denied', message: failure.message, remediation: failure.remediation };
  }

  /* A step-up challenge is neither a refusal nor a failure (`docs/17 §7`), and
   * this screen cannot complete one: `ApiError` carries only a code, so the
   * `challengeId` and `methods` that `docs/05 §3.1` returns with
   * `MFA_REQUIRED` never reach us, and there is no `/auth/mfa/verify` surface
   * in M5. It therefore folds into the refusal bucket rather than promising a
   * challenge we cannot run — which is also the enumeration-safe direction,
   * since "your second factor is needed" would confirm the account exists.
   * Recorded as a gap rather than papered over. */
  if (failure.kind === 'stepUp') {
    return { kind: 'refused' };
  }

  if (failure.retryable) {
    return { kind: 'failed', retryable: true, requestId: failure.requestId };
  }
  if (failure.code === 'response_shape') {
    return { kind: 'failed', retryable: false, requestId: failure.requestId };
  }
  return { kind: 'refused' };
}

/**
 * Attempt a sign-in.
 *
 * The body is written out field by field rather than spread from an object, so
 * that adding a field is a visible edit in a security-reviewed file rather than
 * a property that arrived with a wider type. `docs/05 §3.1` also shows an
 * optional `deviceId`; it is omitted because there is no device-identity store
 * in M5 and a per-attempt random one would only pollute `/auth/sessions`.
 */
export async function signIn(credentials: Credentials, signal?: AbortSignal): Promise<Session> {
  return request('/auth/login', Session, {
    method: 'POST',
    body: { email: credentials.email, password: credentials.password },
    /* There is no session yet, so there is nothing to refresh and nothing to
     * replay. Without this, a wrong password would answer `401`, the client
     * would try to refresh against a cookie that does not exist, and the screen
     * would report the refresh's outcome instead of the sign-in's. */
    anonymous: true,
    ...(signal === undefined ? {} : { signal }),
  });
}
