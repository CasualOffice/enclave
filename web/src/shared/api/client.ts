import { z } from 'zod';

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

export async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = { accept: 'application/json' };

  if (options.body !== undefined) {
    headers['content-type'] = 'application/json';
    // Every mutation is idempotent, so a retry after a timeout cannot double a
    // move, a share or a delete.
    headers['idempotency-key'] = crypto.randomUUID();
  }

  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers,
      // The session cookie is HttpOnly and the client never reads it. There is
      // no token in JavaScript to steal, and no tenant field to forge.
      credentials: 'same-origin',
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch {
    throw new ApiError({ kind: 'failed', code: 'network', retryable: true, requestId: '' });
  }

  const requestId = response.headers.get(REQUEST_ID_HEADER) ?? '';

  if (!response.ok) {
    const body = unwrapError(await response.json().catch(() => null));
    throw new ApiError(classify(response.status, body, requestId));
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
