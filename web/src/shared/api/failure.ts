import { ApiError, SESSION_ENDED, type ApiFailure } from './client.ts';

/* One reading of "what went wrong", shared by every surface.
 *
 * `docs/17 §7` splits a request's unhappy outcomes into three that must never
 * be rendered alike, and the split is a security contract rather than a taxonomy
 * for its own sake:
 *
 * - **denied** — the server answered, and the answer is no. A `403` from DLP, a
 *   barrier, conditional access or a missing ACL grant is a *successful*
 *   request with a refusing answer. It gets the reason and one remedy, and it
 *   **never gets a retry button**: retrying a denial teaches a user the product
 *   is broken rather than that they lack permission.
 * - **failed** — the request did not complete. `5xx`, network, or a response
 *   that did not parse. This is the only one that gets retry and a copyable
 *   request ID.
 * - **stepUp** — neither. A challenge to answer, not a refusal and not a fault.
 *
 * Every feature previously classified this for itself, which is how the two
 * collapse: a `catch` block that renders one error panel cannot tell a user
 * whether to try again or to ask someone for access.
 */

export type Failure =
  | {
      readonly kind: 'denied';
      readonly code: string;
      readonly message: string;
      readonly remediation: string | undefined;
      readonly requestId: string;
    }
  | {
      readonly kind: 'failed';
      readonly code: string;
      readonly retryable: boolean;
      readonly requestId: string;
    }
  | {
      readonly kind: 'stepUp';
      readonly code: string;
      readonly challengeId: string | undefined;
      readonly methods: readonly string[];
    };

/**
 * Classify anything thrown by the API client.
 *
 * A non-`ApiError` — a bug in a `queryFn`, a `TypeError` from a bad render — is
 * reported as a **non-retryable failure**, never as a denial. Guessing "denied"
 * from an unrecognised throw would tell a user they lack permission because our
 * own code threw, which is the wrong story told confidently and the exact
 * failure `docs/17 §3` names for parse errors.
 */
export function failureOf(error: unknown): Failure {
  if (!(error instanceof ApiError)) {
    return { kind: 'failed', code: 'unexpected', retryable: false, requestId: '' };
  }

  const failure: ApiFailure = error.failure;

  if (failure.kind === 'denied') {
    return {
      kind: 'denied',
      code: failure.code,
      message: failure.message,
      remediation: failure.remediation,
      requestId: failure.requestId,
    };
  }

  if (failure.kind === 'stepUp') {
    return {
      kind: 'stepUp',
      code: failure.code,
      challengeId: failure.challengeId,
      methods: failure.methods,
    };
  }

  return {
    kind: 'failed',
    code: failure.code,
    retryable: failure.retryable,
    requestId: failure.requestId,
  };
}

/** Whether a failure is the session ending, which the shell handles rather than a surface. */
export function isSessionEnded(failure: Failure): boolean {
  return failure.kind === 'failed' && failure.code === SESSION_ENDED;
}
