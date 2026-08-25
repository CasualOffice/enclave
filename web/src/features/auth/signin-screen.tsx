import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { AccessLoader, Mark } from '../../shared/ui/mark.tsx';
import { Button, READY, type ControlState } from '../../shared/ui/primitives.tsx';
import { outcomeOf, signIn, type SignInOutcome } from './sign-in.ts';
import { oidcStartPath, WORKSPACE_FIXTURE } from './workspace.ts';
import './signin.css';

/* Sign in — the first paint a user of this product ever sees.
 *
 * ## What Q23's closure changed, against what the prototype draws
 *
 * The prototype (`enclave-client-prototype.html`, `data-screen-label="Sign in"`)
 * draws **passkey** as the accent-filled primary, **SSO** as a second full-width
 * button, and email third under an "or" rule with a bare placeholder-labelled
 * input. `plans/M5-MVP-GA.md` Q23 was closed on 2026-08-25 with the finding that
 * that framing was wrong on every count:
 *
 *   - **Email sign-in works in M5.** It is the primary path, so it is first and
 *     it is the accent-filled button. `POST /auth/login` (`docs/05 §3.1`) is a
 *     real endpoint with a real handler.
 *   - **SSO is per-workspace configuration, not a missing primary button.** A
 *     workspace with no federation configured renders no SSO button at all,
 *     rather than a dead one. So it is drawn from configuration and its absence
 *     is a fact rather than a gap (`workspace.ts`).
 *   - **Passkey is the one D33 case here** — genuinely M6. It is therefore
 *     *unbuilt*, not *denied*, which is a security distinction and not a visual
 *     one (see below).
 *
 * The prototype wins on appearance and it keeps it: the 360 px sheet, the
 * masked dot field, the 36 px controls, the rule with "or" through it. What
 * changed is which buttons exist and in what order, and that is behaviour.
 *
 * ## The three things this screen must never do
 *
 * 1. **Never take tenant identity from the client** (`CLAUDE.md` rule 3). There
 *    is no tenant field, no workspace picker and no domain box on this screen,
 *    and the email's domain is not read as a selector. The tenant is resolved
 *    at the gateway from the custom domain before application code runs
 *    (`docs/09 §19`), and the request body carries exactly two keys.
 * 2. **Never reveal whether an account exists.** Every refusal — unknown
 *    address, wrong password, locked account, malformed input — produces the
 *    same sentence, the same element, the same `data-signin-state`, and carries
 *    no code and no request ID. `outcomeOf` collapses them in the model layer so
 *    this component has nothing to vary on. Same reasoning as `CLAUDE.md` rule
 *    7: any difference we render confirms existence.
 * 3. **Never render a credential** (rule 10). `Session` has no `accessToken`
 *    field — the token is validated and dropped at the parse boundary, so there
 *    is nothing on this screen that could put it on screen.
 *
 * ## The four states, and the distinction that matters most
 *
 * `docs/09 §11` wants empty, loading, error and success. This screen has all
 * four, and one more that is none of them:
 *
 * | state | what it means | retry? |
 * |---|---|---|
 * | empty | the resting form | — |
 * | loading | the request is in flight; `AccessLoader` says what the chain is doing | — |
 * | **refused** | the server answered, and the answer is no | **no** — the form is the retry |
 * | **denied** | `403` from the policy chain; the server's own sentence | **never** (`docs/17 §7`) |
 * | error | the request did not complete | **yes**, with a copyable request ID |
 * | success | signed in | — |
 *
 * A failed sign-in **attempt** and a failed **request** are different events and
 * they look different: the first is a refusing answer to a completed request and
 * offers no retry button, no request ID and no diagnosis; the second is neutral,
 * says nothing has changed, and gives the correlation ID support will ask for.
 * Collapsing them would both teach a user that the product is broken when they
 * mistyped a password, and hide a real outage behind "wrong password".
 */

/** The QA/accessibility hook, mirroring `?surface=` on the library list. */
type ForcedState = 'loading' | 'refused' | 'failed' | 'success';

const FORCED_STATES = new Set<ForcedState>(['loading', 'refused', 'failed', 'success']);

/**
 * A fabricated request ID for the forced error state.
 *
 * Not a secret and not a credential — a ULID-shaped correlation token, which is
 * what `docs/05 §1` says `X-Request-Id` carries. It exists so the accessibility
 * run can reach the error state without a server.
 */
const SAMPLE_REQUEST_ID = '01K3Q7X0PMDR4W8B2ZC6E5A9TN';

function forcedState(): ForcedState | undefined {
  if (typeof window === 'undefined') return undefined;
  const value = new URLSearchParams(window.location.search).get('state') ?? '';
  return FORCED_STATES.has(value as ForcedState) ? (value as ForcedState) : undefined;
}

type Phase =
  | { readonly kind: 'idle' }
  | { readonly kind: 'submitting' }
  | { readonly kind: 'answered'; readonly outcome: SignInOutcome }
  | { readonly kind: 'success'; readonly displayName: string };

function phaseFor(forced: ForcedState | undefined): Phase {
  switch (forced) {
    case 'loading':
      return { kind: 'submitting' };
    case 'refused':
      return { kind: 'answered', outcome: { kind: 'refused' } };
    case 'failed':
      return {
        kind: 'answered',
        outcome: { kind: 'failed', retryable: true, requestId: SAMPLE_REQUEST_ID },
      };
    case 'success':
      /* An empty display name renders the greeting without one. Nothing here
       * signs anybody in — the forced states paint, they do not authenticate. */
      return { kind: 'success', displayName: '' };
    default:
      return { kind: 'idle' };
  }
}

/** The `data-signin-state` a test or the axe harness selects on. */
function stateName(phase: Phase): string {
  return phase.kind === 'answered' ? phase.outcome.kind : phase.kind;
}

export default function Screen() {
  const t = useT();
  const workspace = WORKSPACE_FIXTURE;

  const [forced] = useState(forcedState);
  const [phase, setPhase] = useState<Phase>(() => phaseFor(forced));
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const inFlight = useRef(false);

  /* A fresh page load after sign-in, not a client-side route change: the
   * session cookie the server just set has to be picked up by a new bootstrap,
   * and `features/` may not import `app/` anyway (`docs/17 §2` — a module never
   * imports from a layer above it). Deferred so the success state is actually
   * seen, and cleaned up so an unmount does not leave a navigation pending. */
  useEffect(() => {
    if (phase.kind !== 'success' || forced !== undefined) return undefined;
    const timer = window.setTimeout(() => {
      window.location.assign('/');
    }, 900);
    return () => window.clearTimeout(timer);
  }, [phase.kind, forced]);

  async function attempt(): Promise<void> {
    if (inFlight.current) return;

    /* Both fields are required. Focusing the empty one is the whole of the
     * feedback: any message here would have to be composed in this component,
     * and — more to the point — a client-side check that behaved differently
     * for a recognised address would be an enumeration oracle that never
     * reached the network at all. */
    if (email.trim() === '') {
      emailRef.current?.focus();
      return;
    }
    if (password === '') {
      passwordRef.current?.focus();
      return;
    }

    inFlight.current = true;
    setPhase({ kind: 'submitting' });
    try {
      const session = await signIn({ email: email.trim(), password });
      setPhase({ kind: 'success', displayName: session.user.displayName });
      /* Out of memory the moment it is no longer needed. It was never logged,
       * never in a URL and never in an error object. */
      setPassword('');
    } catch (error) {
      const outcome = outcomeOf(error);
      /* Cleared on a refusal because the next attempt retypes it; kept on a
       * failure because *Try again* re-sends the same credentials and asking a
       * user to retype after our outage is punishing them for it. */
      if (outcome.kind === 'refused' || outcome.kind === 'denied') setPassword('');
      setPhase({ kind: 'answered', outcome });
    } finally {
      inFlight.current = false;
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    void attempt();
  }

  /* `<Button>` renders `type="button"` unconditionally, so it cannot be a
   * form's submit control, and a two-field form has no implicit submission
   * without one. Enter is wired here so the keyboard path works anyway. */
  function onFieldKeyDown(event: KeyboardEvent<HTMLInputElement>): void {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    void attempt();
  }

  const submitting = phase.kind === 'submitting';
  const submitState: ControlState = submitting ? { kind: 'busy' } : READY;

  return (
    <main className="sgn">
      <div className="sgn-backdrop" aria-hidden="true" />

      <section className="sgn-card ui-in" data-signin-state={stateName(phase)}>
        {/* 34 px: `Mark` picks the middle optical cut for it, which is the one
         * `logo.svg` is drawn at. The mark is never scaled from another cut
         * (`web/public/BRAND.md`), and it is aria-hidden because the heading
         * beside it already names the product. */}
        <Mark size={34} className="sgn-mark" />

        <h1 className="sgn-title">{t('auth.title', { brand: t('app.brand') })}</h1>
        <p className="sgn-sub">{t('auth.subtitle')}</p>

        {/* Always mounted, so a screen reader announces what lands in it. A
         * region created at the moment it gains content is a region some
         * screen readers never speak (`docs/09 §15`). */}
        <div className="sgn-answer" role="status" aria-live="polite">
          {phase.kind === 'answered' && (
            <Answer outcome={phase.outcome} onRetry={() => void attempt()} />
          )}
        </div>

        {phase.kind === 'success' ? (
          <div className="sgn-success">
            <Icon name="check" size={20} className="sgn-success-mark" />
            <h2 className="sgn-success-title">{t('auth.success.title')}</h2>
            <p className="sgn-success-body">{t('auth.success.body')}</p>
          </div>
        ) : (
          <>
            <form className="sgn-form" onSubmit={onSubmit} noValidate>
              <div className="sgn-field">
                <label className="sgn-label" htmlFor="sgn-email">
                  {t('auth.email.label')}
                </label>
                <input
                  id="sgn-email"
                  ref={emailRef}
                  className="sgn-input"
                  type="email"
                  name="email"
                  inputMode="email"
                  autoComplete="username"
                  autoCapitalize="none"
                  spellCheck={false}
                  required
                  /* A hint, never the label. The label above stays visible
                   * while the field is being filled, which is when it is most
                   * needed, and it is what a voice-control user says. */
                  placeholder={t('auth.email.placeholder')}
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  onKeyDown={onFieldKeyDown}
                />
              </div>

              <div className="sgn-field">
                <label className="sgn-label" htmlFor="sgn-password">
                  {t('auth.password.label')}
                </label>
                <input
                  id="sgn-password"
                  ref={passwordRef}
                  className="sgn-input"
                  type="password"
                  name="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  onKeyDown={onFieldKeyDown}
                />
              </div>

              <div className="sgn-actions">
                <Button
                  label={submitting ? 'auth.submitting' : 'auth.submit'}
                  variant="primary"
                  size="lg"
                  state={submitState}
                  onClick={() => void attempt()}
                />
              </div>
            </form>

            {submitting && (
              <div className="sgn-loading">
                <AccessLoader size={30} />
              </div>
            )}

            {/* The rule with "or" through it, from the prototype. Decorative:
              * it separates the primary path from the alternatives and says
              * nothing a screen reader needs, which the alternatives' own
              * labels already carry. */}
            <div className="sgn-or" aria-hidden="true">
              {t('auth.or')}
            </div>

            <div className="sgn-actions">
              {/* Rendered from configuration. A workspace with no provider
               * shows nothing here, which is the correct answer rather than a
               * gap — Q23. The provider's own display name is tenant data and
               * goes in as an ICU argument so the sentence still localizes. */}
              {workspace.ssoProviders.map((provider) => (
                <Button
                  key={provider.key}
                  label="auth.continueWithSso"
                  values={{ provider: provider.displayName }}
                  size="lg"
                  onClick={() => {
                    window.location.assign(oidcStartPath(provider));
                  }}
                />
              ))}

              {/* **Unbuilt, never denied** (`plans/M5-MVP-GA.md` D33,
               * `docs/17 §6`). `state.kind === 'unbuilt'` takes it out of the
               * tab order, keeps it off the denial colour and hangs a neutral
               * `Later` chip on it. No remedy is offered, because there is
               * nothing this user can do about our release schedule — and
               * offering one is precisely what would make it read as a refusal. */}
              <div className="sgn-later">
                <Button
                  label="auth.continueWithPasskey"
                  icon="shield"
                  size="lg"
                  state={{ kind: 'unbuilt', note: 'later.chip' }}
                />
              </div>
              <p className="sgn-later-note">{t('auth.passkey.later')}</p>
            </div>
          </>
        )}

        <div className="sgn-legal">
          {workspace.supportUrl !== undefined && (
            <a href={workspace.supportUrl}>{t('auth.legal.support')}</a>
          )}
          {workspace.privacyUrl !== undefined && (
            <a href={workspace.privacyUrl}>{t('auth.legal.privacy')}</a>
          )}
          {workspace.termsUrl !== undefined && <a href={workspace.termsUrl}>{t('auth.legal.terms')}</a>}
        </div>
      </section>
    </main>
  );
}

/**
 * Whichever of the three answers applies.
 *
 * They are one component because they occupy one slot, and three `data-kind`
 * values because they are three different things. The refusal is the shortest
 * on purpose: it has nothing to say beyond the one sentence, and anything it
 * added would be a detail that varies with whether the account exists.
 */
function Answer({ outcome, onRetry }: { outcome: SignInOutcome; onRetry: () => void }) {
  const t = useT();

  if (outcome.kind === 'refused') {
    return (
      <div className="sgn-note" data-kind="refused">
        {/* One sentence, identical for every refusal. It names neither the
         * address nor which of the two fields was wrong, because "no such
         * user" and "wrong password" are the same answer to an attacker
         * counting accounts. No retry button: the form below is the retry. */}
        <p>{t('auth.refused')}</p>
      </div>
    );
  }

  if (outcome.kind === 'denied') {
    return (
      <div className="sgn-note" data-kind="denied">
        {/* The server's own user-safe sentence and remedy (`docs/05 §5`),
         * verbatim. The client never composes one from a policy rule
         * (`docs/17 §7`) and never shows which rule matched (rule 10). And
         * never a retry: retrying a policy denial is how a user concludes the
         * product is broken rather than that they are not allowed. */}
        <p>{outcome.message}</p>
        {outcome.remediation !== undefined && outcome.remediation !== '' && (
          <p className="sgn-note-remedy">{outcome.remediation}</p>
        )}
      </div>
    );
  }

  return (
    <div className="sgn-note" data-kind="failed">
      <p>{t('auth.error.title')}</p>
      <p className="sgn-note-body">
        {outcome.retryable ? t('auth.error.body') : t('auth.error.bodyFinal')}
      </p>
      {outcome.retryable && (
        <div className="sgn-note-actions">
          <Button label="auth.error.retry" size="sm" onClick={onRetry} />
        </div>
      )}
      <RequestId value={outcome.requestId} />
    </div>
  );
}

/** The correlation ID `docs/09 §11` requires on a failure, copyable. */
function RequestId({ value }: { value: string }) {
  const t = useT();
  if (value === '') return null;

  return (
    <p className="sgn-request-id">
      <span>{t('auth.error.requestId')}</span>
      <code>{value}</code>
      <Button
        label="auth.error.copy"
        size="sm"
        variant="ghost"
        onClick={() => {
          /* An accelerator, not the only route: the id is `user-select: all`
           * text as well, because a non-secure context and an old browser both
           * have no clipboard API and support still needs the string. */
          const clipboard: Clipboard | undefined = navigator.clipboard;
          if (clipboard === undefined) return;
          void clipboard.writeText(value);
        }}
      />
    </p>
  );
}
