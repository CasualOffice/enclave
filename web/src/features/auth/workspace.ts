/* What the sign-in screen is allowed to know before anyone has signed in.
 *
 * **There is no tenant input on this screen and there must never be one**
 * (`CLAUDE.md` rule 3). Tenant identity comes from the verified token or from
 * custom-domain routing at the gateway, which resolves `workspace.customer.com`
 * to a tenant *before application code runs* (`docs/09 §19`, `docs/02 §21`). The
 * email domain is not a tenant selector and is never treated as one — a client
 * that picks the tenant is a client that can be asked to pick a different one.
 *
 * So everything below is *server-supplied configuration for an already-resolved
 * tenant*, not a choice the visitor makes. Which SSO providers exist is
 * per-workspace configuration (`docs/13 §3.2`, and `plans/M5-MVP-GA.md` Q23:
 * SSO is configuration rather than a missing primary button), and so are the
 * support, privacy and terms URLs (`docs/09 §18`).
 *
 * **This is a fixture and it is one on purpose.** `docs/02 §21` names a
 * "bootstrap/branding API" but `docs/05-API.md` specifies no unauthenticated
 * endpoint that serves it, and inventing a path is worse than admitting there
 * isn't one. When that endpoint is written down, this module becomes a fetch
 * parsed by the schema below and nothing in `signin-screen.tsx` changes shape.
 */

/** One configured federation provider, as `docs/13 §3.2` names them. */
export interface SsoProvider {
  /** The provider `key` from tenant configuration. Goes into `/auth/oidc/{provider}/start`. */
  readonly key: string;
  /**
   * The tenant's own `display_name` for it — "Company SSO". Tenant data rather
   * than product copy, so it is not a catalog key: it arrives translated (or
   * untranslatable, being a company's name) from configuration. It is placed
   * into a catalog message as an ICU argument so the sentence around it still
   * localizes.
   */
  readonly displayName: string;
}

export interface SignInWorkspace {
  /**
   * Empty is a legitimate, common answer: a workspace with no federation
   * configured shows no SSO button at all, rather than a dead one. Q23's point
   * exactly — the absence of an SSO button is configuration, not a gap.
   */
  readonly ssoProviders: readonly SsoProvider[];
  /** `docs/09 §18` tenant configuration. Absent means the link is not rendered. */
  readonly supportUrl?: string;
  readonly privacyUrl?: string;
  readonly termsUrl?: string;
}

/**
 * The stand-in for the bootstrap response.
 *
 * Deliberately carries **no tenant identifier of any kind** — not an id, not a
 * slug, not a domain. Nothing on this screen needs one, and a field nobody
 * needs is a field somebody eventually sends.
 */
export const WORKSPACE_FIXTURE: SignInWorkspace = {
  ssoProviders: [{ key: 'corp-entra', displayName: 'Company SSO' }],
  supportUrl: 'https://support.example.com',
  privacyUrl: 'https://www.example.com/privacy',
  termsUrl: 'https://www.example.com/terms',
};

/**
 * Where a federated sign-in begins (`docs/05 §3`: `GET /auth/oidc/{provider}/start`).
 *
 * A full-page navigation rather than a fetch, because the next hop is the IdP's
 * own authorization endpoint and the authorization-code + PKCE flow needs the
 * browser's address bar, not XHR. The `provider` segment is a configuration key
 * the server gave us; it is not derived from anything the visitor typed.
 */
export function oidcStartPath(provider: SsoProvider): string {
  return `/api/v1/auth/oidc/${encodeURIComponent(provider.key)}/start`;
}
