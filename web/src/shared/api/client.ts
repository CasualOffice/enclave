import { z } from 'zod';
import { authorization, clearAccessToken, ensureFreshToken, refresh } from './session.ts';

/* One API client. Every request goes through it (`docs/17 §9`).
 *
 * It owns four cross-cutting concerns so that no feature has to remember them,
 * and one of the four is a security rule rather than a convenience:
 *
 * 1. **Tenant identity is never sent by the client** (`CLAUDE.md` rule 3). It
 *    comes from the verified token or from custom-domain routing at the
 *    gateway. There is no tenant parameter in any signature here, and there
 *    must never be one — the shape makes the mistake unrepresentable rather
 *    than merely forbidden.
 * 2. **Idempotency keys** on every mutation (`docs/05 §…`), generated here.
 * 3. **Step-up interception**: a `401` carrying a step-up challenge is not a
 *    failure, it is a prompt.
 * 4. **Request ID capture** from every response, so the error state can offer a
 *    copyable correlation ID (`docs/09 §11`).
 *
 * And one shape rule: **Zod parses at this boundary and nowhere else**
 * (`docs/17 §3`). Nothing downstream re-validates and nothing downstream sees
 * `unknown`.
 */

/** The stable error envelope from `docs/05 §5`. */
export const ApiErrorBody = z.object({
  code: z.string(),
  /** An English default. The client renders its own localized string keyed by `code` (`docs/14 §5`). */
  message: z.string(),
  remediation: z.string().optional(),
  requestId: z.string().optional(),
  /** Present only on a step-up challenge, and only then. */
  challengeId: z.string().optional(),
  methods: z.array(z.string()).optional(),
});

export type ApiErrorBody = z.infer<typeof ApiErrorBody>;

/**
 * `docs/05 §5` nests it: `{"error": {"code": …}}`.
 *
 * The first version of this parsed `{code: …}` at the top level, which against
 * a real server would have failed every parse and degraded every error to
 * `http_403` / `http_500` — silently discarding `message` and `remediation`, so
 * the *denied* path would have rendered an empty sentence in production while
 * every test passed. Found by the sign-in session reading this against the doc
 * rather than against the fixture. The unwrap accepts the bare shape too, so a
 * handler that has not been updated is not a second failure mode.
 */
const ApiErrorEnvelope = z.union([z.object({ error: ApiErrorBody }), ApiErrorBody]);

function unwrapError(payload: unknown): ApiErrorBody | null {
  const parsed = ApiErrorEnvelope.safeParse(payload);
  if (!parsed.success) return null;
  return 'error' in parsed.data ? parsed.data.error : parsed.data;
}

/**
 * What went wrong, in the only three shapes a surface has to tell apart.
 *
 * `docs/17 §7`: **a denial is not a failure.** A `403` from DLP, a barrier or
 * conditional access is a successful request with a refusing answer. It renders
 * as denied-explained-inline with a reason and a remedy, and it **never offers
 * retry** — retrying a denial is how a user concludes the product is broken
 * rather than that they lack permission. Keeping them separate in the type is
 * what stops a `catch` block from collapsing them.
 */
export type ApiFailure =
  | {
      readonly kind: 'denied';
      readonly code: string;
      readonly message: string;
      readonly remediation?: string | undefined;
      readonly requestId: string;
    }
  | {
      readonly kind: 'stepUp';
      readonly code: string;
      readonly requestId: string;
      /* The challenge has to survive the classification or there is nothing to
       * answer it with. The first version dropped both of these, which made the
       * step-up branch unimplementable — a user with MFA enabled could not have
       * signed in at all. */
      readonly challengeId: string | undefined;
      readonly methods: readonly string[];
    }
  | {
      readonly kind: 'failed';
      readonly code: string;
      readonly retryable: boolean;
      readonly requestId: string;
    };

export class ApiError extends Error {
  readonly failure: ApiFailure;

  constructor(failure: ApiFailure) {
    super(failure.code);
    this.name = 'ApiError';
    this.failure = failure;
  }
}

const REQUEST_ID_HEADER = 'x-request-id';

/** Where the API lives. Same origin by default: the SPA is served by the gateway. */
const BASE = '/api/v1';

export interface RequestOptions {
  readonly method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  readonly body?: unknown;
  readonly signal?: AbortSignal;
  /**
   * Skip the bearer token and the refresh-and-replay path.
   *
   * Exactly one caller wants this — `POST /auth/login`, which by definition has
   * no session yet. Without it, a failed sign-in would answer `401`, trigger a
   * refresh against a cookie that is not there, and report the outcome of the
   * refresh rather than of the sign-in.
   */
  readonly anonymous?: boolean;
  /**
   * Override the `Accept` header.
   *
   * Exactly one class of caller needs this: the delivery routes, which answer
   * image bytes rather than JSON. Asking for `application/json` from
   * `/files/{id}/preview` is asking the server for a representation it does not
   * have, and the honest request says what it will accept.
   */
  readonly accept?: string;
  /**
   * The revision this write believes it is changing, sent as `If-Match`.
   *
   * A number rather than a string: the quoting is an HTTP detail and every
   * caller that had to build `"4"` by hand would be one caller away from
   * sending `4` and getting a `400` nobody could explain from the call site.
   *
   * Narrow, and deliberately not a general `headers` bag. `docs/05-API.md §7`
   * requires `If-Match` on exactly three routes — `PATCH /files/{id}`,
   * `DELETE /files/{id}` and `POST /files/{id}/restore` — and until `ENC-939`
   * this layer could not send a header at all, so **no client code could call
   * any of them**. A general escape hatch would have closed that too, and would
   * also have made the next header somebody wants a matter of adding a key
   * rather than of arguing for one.
   *
   * A stale value is `409`, not `412`: `§4` says so, and the client renders the
   * server's sentence rather than inventing one about revisions.
   */
  readonly ifMatch?: number;
}

/**
 * A session the server no longer honours.
 *
 * Distinct from `denied`: a denial is an answer about *what you may do*, and a
 * `401` after a refresh has already failed is the absence of anyone to ask
 * about. The shell listens for this and returns to sign-in; a feature never has
 * to handle it, which is why it is a separate code rather than a `failed` with
 * a status the caller has to interpret.
 */
export const SESSION_ENDED = 'session_ended';

type SessionListener = () => void;
const sessionListeners = new Set<SessionListener>();

/** Notified when a request proved the session is over. */
export function onSessionEnded(listener: SessionListener): () => void {
  sessionListeners.add(listener);
  return () => sessionListeners.delete(listener);
}

function endSession(): void {
  clearAccessToken();
  for (const listener of sessionListeners) listener();
}

/**
 * A cross-tenant or barrier denial arrives as `404`, not `403` (`CLAUDE.md`
 * rule 7) — a `403` would confirm the resource exists. So a `404` is reported
 * as *not found* and nothing here tries to be cleverer about it.
 */
/** `docs/05` writes error codes in SCREAMING_SNAKE. Matched case-insensitively
 *  because the first version tested `code.startsWith('step_up')` against
 *  `STEP_UP_REQUIRED` and therefore never matched once. */
const STEP_UP_CODES = /^(step_up_required|mfa_required)$/i;

function classify(status: number, body: ApiErrorBody | null, requestId: string): ApiFailure {
  const code = body?.code ?? `http_${status}`;
  if (status === 401 && STEP_UP_CODES.test(code)) {
    return {
      kind: 'stepUp',
      code,
      requestId,
      challengeId: body?.challengeId,
      methods: body?.methods ?? [],
    };
  }
  if (status === 403) {
    return {
      kind: 'denied',
      code,
      message: body?.message ?? '',
      remediation: body?.remediation,
      requestId,
    };
  }
  return {
    kind: 'failed',
    code,
    // 4xx is the caller's problem and will not fix itself; 5xx and network are
    // worth another attempt, and only those get a retry affordance.
    retryable: status >= 500 || status === 0 || status === 408 || status === 429,
    requestId,
  };
}

/**
 * Send once. No retry, no refresh — `request` below owns both.
 *
 * `idempotency-key` is generated here, which means a replayed request carries a
 * *different* key from the attempt that 401'd. That is the correct direction:
 * the first attempt was rejected before any handler ran, so there is no
 * server-side effect for the key to deduplicate against, and reusing it would
 * let a genuinely retried mutation be answered from a cache of the refusal.
 */
async function send(
  path: string,
  options: RequestOptions,
  auth: Record<string, string>,
): Promise<Response> {
  const headers: Record<string, string> = {
    accept: options.accept ?? 'application/json',
    ...auth,
  };

  if (options.ifMatch !== undefined) {
    /* Quoted, because an ETag is a quoted-string and an unquoted one is a
     * malformed header rather than a lenient one. */
    headers['if-match'] = `"${options.ifMatch}"`;
  }

  if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
    // Every mutation is idempotent, so a retry after a timeout cannot double a
    // move, a share or a delete.
    headers['idempotency-key'] = crypto.randomUUID();
  }

  return fetch(`${BASE}${path}`, {
    method: options.method ?? 'GET',
    headers,
    /* The refresh and CSRF cookies ride along on same-origin requests. The
     * refresh cookie is `HttpOnly` and scoped to `/api/v1/auth`, so it is not
     * even attached to the calls below — only `/auth/refresh` ever sees it.
     * There is no tenant field here to forge: the tenant comes from the token,
     * or from the host the gateway routed (`CLAUDE.md` rule 3). */
    credentials: 'same-origin',
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
}

/**
 * Send, and deal with the session — everything up to reading a body.
 *
 * Factored out of `request` so that `requestBlob` gets the *same* proactive
 * refresh, the same refresh-and-replay on `401`, and the same step-up
 * passthrough. A second transport that reimplemented any of those would be a
 * second place for the session rules to be subtly wrong, and the delivery
 * routes are exactly where a silently-expired token would look like a missing
 * file.
 */
async function exchange(path: string, options: RequestOptions): Promise<Response> {
  const anonymous = options.anonymous === true;

  /* Refresh *before* sending when the held token is at or past expiry, so the
   * common expiry case costs one request rather than two. */
  if (!anonymous) await ensureFreshToken();

  let response: Response;
  try {
    response = await send(path, options, anonymous ? {} : authorization());
  } catch {
    throw new ApiError({ kind: 'failed', code: 'network', retryable: true, requestId: '' });
  }

  /* The reactive half. A `401` here means the server rejected the token we
   * believed was good — a rotated signing key, a revoked session, a bumped
   * token epoch, or simply a reload that started with no token at all. One
   * refresh, one replay, and then we believe it.
   *
   * A step-up challenge is explicitly *not* this: `403 STEP_UP_REQUIRED` and
   * `401 MFA_REQUIRED` are prompts, not expiries (`docs/17 §7`), and refreshing
   * against them would burn the refresh token and still not satisfy the
   * challenge. They fall through to `classify` and reach the caller intact. */
  if (response.status === 401 && !anonymous) {
    const body = unwrapError(await response.clone().json().catch(() => null));
    const code = body?.code ?? '';
    if (!STEP_UP_CODES.test(code)) {
      if (await refresh()) {
        try {
          response = await send(path, options, authorization());
        } catch {
          throw new ApiError({ kind: 'failed', code: 'network', retryable: true, requestId: '' });
        }
      }
      /* Still rejected after a successful refresh, or the refresh itself
       * failed: there is no session left to salvage. */
      if (response.status === 401) {
        endSession();
        throw new ApiError({
          kind: 'failed',
          code: SESSION_ENDED,
          retryable: false,
          requestId: response.headers.get(REQUEST_ID_HEADER) ?? '',
        });
      }
    }
  }

  return response;
}

export async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<T> {
  const response = await exchange(path, options);
  const requestId = response.headers.get(REQUEST_ID_HEADER) ?? '';

  if (!response.ok) {
    const body = unwrapError(await response.json().catch(() => null));
    throw new ApiError(classify(response.status, body, requestId));
  }

  /* `204 No Content` is a success with nothing to parse, and several mutations
   * answer with it — approve, reject, delegate, logout, revoke. Handing an
   * empty body to a schema would fail the parse and report a working mutation
   * as a shape error. */
  if (response.status === 204) {
    const parsed = schema.safeParse(undefined);
    if (parsed.success) return parsed.data;
    throw new ApiError({ kind: 'failed', code: 'response_shape', retryable: false, requestId });
  }

  const payload: unknown = await response.json().catch(() => null);
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    /* A parse failure is an error state, not a crash and not a silent default
     * (`docs/17 §3`). Catching it into `{}` would give a row every capability
     * `false`, which reads as *policy denied everything* — the wrong story told
     * confidently. */
    throw new ApiError({
      kind: 'failed',
      code: 'response_shape',
      retryable: false,
      requestId,
    });
  }

  return parsed.data;
}

/**
 * A response whose body is bytes, not JSON.
 *
 * The delivery routes — `GET /files/{id}/preview` and `/thumbnail` — answer an
 * image, and they need the bearer token, which is why they cannot simply be an
 * `<img src>`: the token lives in memory and is never a cookie or a query
 * parameter, so the only way to authenticate a byte read is to fetch it and
 * hand the result to an object URL.
 *
 * Errors are classified through exactly the same `classify` as `request`, so a
 * `403` from these routes is a **denial** carrying the server's reason and a
 * `503` is a retryable **failure** — the distinction `docs/17 §7` requires,
 * arriving here for free rather than being re-derived per caller.
 *
 * Verified against the running binary, which answers all four:
 *
 *   * `200 image/png` — an `AVAILABLE` / `CLEAN` PNG;
 *   * `404` — a version that exists but may not be served (`SKIPPED` or
 *     `QUARANTINED`). That is `CLAUDE.md` rule 9 working, and it is **not** a
 *     missing file;
 *   * `503 DEPENDENCY_UNAVAILABLE` — a media type this deployment has no
 *     renderer for; renditions cover `image/png`, `image/jpeg` and `image/webp`
 *     and nothing else;
 *   * `403 ACCESS_DENIED` — the policy chain refusing this user.
 */
export async function requestBlob(path: string, options: RequestOptions = {}): Promise<Blob> {
  const response = await exchange(path, { accept: 'image/*', ...options });
  const requestId = response.headers.get(REQUEST_ID_HEADER) ?? '';

  if (!response.ok) {
    /* The error body is still JSON even when the success body is not, so the
     * reason and the remediation survive. A `404` carries no useful sentence
     * and is deliberately not dressed up as one — only the caller knows whether
     * the file is absent or merely not yet servable, and telling that story is
     * its job (`features/libraries/peek/preview-tab.tsx`). */
    const body = unwrapError(await response.json().catch(() => null));
    throw new ApiError(classify(response.status, body, requestId));
  }

  return response.blob();
}
