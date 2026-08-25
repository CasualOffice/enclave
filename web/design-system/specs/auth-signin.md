# auth/signin — implementation spec

> Extracted from `enclave-client-prototype.html` by the spec workflow.
> The prototype stays the reference; this is a reading of it, not a replacement.

## Structure

SURFACE: `/signin` (+ `/signin/callback`). Route: `app/router.tsx` → `features/auth/signin/`. Unauthenticated; the authenticated shell (nav rail, shortcut provider, peek) does NOT mount.

FILES
```
features/auth/signin/
  SignInRoute.tsx        route shell, states machine
  SignInCard.tsx         the card
  MethodButton.tsx       one auth method (denied | unbuilt | busy | ready)
  EmailForm.tsx          email → discover → password/redirect
  SignInSkeleton.tsx     loading state, same box model
  SignInError.tsx        fetch-failure state
  SignInDenied.tsx       policy-refusal state (no retry)
  useBootstrap.ts        TanStack Query, staleTime 0
  signin.css             all geometry, logical properties only
entities/auth/model.ts   Zod: BootstrapPublic, AuthMethod, DiscoverResult
```

ELEMENT TREE — exact geometry. Every value below is copied from the prototype; property NAMES are the logical equivalents.

```
<main class="signin-page">                                    // page
  block-size:100%; display:flex; align-items:center;
  justify-content:center; position:relative; overflow:hidden;
  background:var(--canvas); color:var(--fg);
  font-family:var(--sans); font-size:13px; line-height:1.45;
  letter-spacing:-.006em; -webkit-font-smoothing:antialiased

  ├── <div class="signin-grid" aria-hidden="true">            // dot field
  │     position:absolute; inset:0; opacity:.7;
  │     background-image:radial-gradient(var(--line-strong) 1px,transparent 1px);
  │     background-size:22px 22px;
  │     mask-image:radial-gradient(ellipse at center,#000 30%,transparent 72%);
  │     -webkit-mask-image: same
  │
  └── <section class="signin-card" aria-labelledby="signin-title">
        position:relative;
        inline-size:min(360px, calc(100vw - 32px));
        padding-block:28px 22px; padding-inline:28px;
        border-radius:calc(var(--r-sheet) + 2px);   // = 16px on default brand
        box-shadow:var(--el2); background:var(--sheet);
        animation:encIn 180ms cubic-bezier(.2,.7,.3,1) both
        → content column = 304px at full width

        ├── <div class="signin-mark">                          margin-block-end:18px
        │     <svg class="signin-logo" aria-hidden="true" focusable="false"
        │          viewBox="0 0 48 48"><use href="#logo"/></svg>
        │       inline-size:34px; block-size:34px; color:var(--accent); display:block
        │     // tenant override: <img> from branding.loginLogoUrl (same-origin only),
        │     //   max-block-size:34px; max-inline-size:180px; alt="" (heading carries the name)
        │
        ├── <h1 id="signin-title" tabindex="-1">
        │     margin:0 0 4px; font-family:var(--tight); font-size:20px;
        │     font-weight:600; letter-spacing:-.02em; color:var(--fg)
        │     → rendered box ≈ 29px (20 × 1.45)
        │
        ├── <p class="signin-sub">
        │     margin:0 0 18px; color:var(--fg3); font-size:12.5px
        │     → ≈ 18px
        │
        ├── <div class="signin-live" role="status" aria-live="polite" aria-atomic="true">
        │     // empty in the ready state; occupies 0px until it holds content.
        │     // when it holds a denial/failure: margin-block-end:12px, font-size:12px
        │
        ├── <div class="signin-stack"> display:flex; flex-direction:column; gap:8px
        │   │
        │   ├── MethodButton[primary]  — passkey
        │   │     display:inline-flex; align-items:center; justify-content:center;
        │   │     gap:6px; min-block-size:36px; padding-inline:14px; padding-block:0;
        │   │     border:0; border-radius:calc(var(--r-ctrl) + 2px);
        │   │     font:inherit; font-size:13px; font-weight:500; cursor:pointer;
        │   │     background:var(--accent); color:#fff;
        │   │     transition:filter 120ms ease, background-color 120ms ease
        │   │     :hover → filter:brightness(1.08)
        │   │     <svg aria-hidden="true" focusable="false"><use href="#shield"/></svg>
        │   │       inline-size:14px; block-size:14px; flex:none
        │   │
        │   ├── MethodButton[secondary] — SSO
        │   │     same box; background:var(--sheet); color:var(--fg);
        │   │     box-shadow:var(--hairline)
        │   │     :hover → background:var(--sunken)
        │   │     (no leading icon in the prototype)
        │   │
        │   ├── <div class="signin-divider">
        │   │     display:flex; align-items:center; gap:10px;
        │   │     color:var(--fg4); font-size:11px; margin-block:6px
        │   │     → gap to neighbours = 8 (stack gap) + 6 (margin) = 14px each side
        │   │     ├── <span class="rule" aria-hidden="true"> flex:1; block-size:1px; background:var(--line)
        │   │     ├── {t('auth.signin.divider.or')}
        │   │     └── <span class="rule" aria-hidden="true"> (identical)
        │   │
        │   └── <form class="signin-email" novalidate>
        │         display:contents   // keeps the 8px stack rhythm; form adds no box
        │         ├── <label for="signin-email" class="sr-only">
        │         │     sr-only = position:absolute; inline-size:1px; block-size:1px;
        │         │     padding:0; margin:-1px; overflow:hidden; clip-path:inset(50%);
        │         │     white-space:nowrap; border:0
        │         ├── <input id="signin-email" type="email" name="email"
        │         │          autocomplete="username webauthn" inputmode="email"
        │         │          spellcheck="false" autocapitalize="none"
        │         │          aria-describedby={errorId | undefined}>
        │         │     min-block-size:36px; padding-inline:9px; padding-block:0; border:0;
        │         │     border-radius:var(--r-ctrl); background:var(--sheet);
        │         │     box-shadow:var(--hairline); color:var(--fg);
        │         │     font:inherit; font-size:12.5px; inline-size:100%; box-sizing:border-box
        │         │     :focus-visible → outline:0;
        │         │        box-shadow:0 0 0 1px var(--accent), 0 0 0 4px var(--accent-ring)
        │         ├── <input id="signin-password" type="password" autocomplete="current-password">
        │         │     rendered ONLY when discovery returned next:"password";
        │         │     identical box to the email input; inserted between it and the submit,
        │         │     stack gap keeps 8px so nothing above shifts
        │         └── <button type="submit"> — secondary box, identical to the SSO button
        │
        └── <footer class="signin-footer">
              display:flex; gap:12px; margin-block-start:16px;
              font-size:11px; color:var(--fg4)
              ├── <a> Support   text-decoration:none; :hover → text-decoration:underline
              ├── <a> Privacy
              ├── <a> Terms
              └── <span class="signin-version">
                    margin-inline-start:auto; font-family:var(--mono)
```

VERTICAL RHYTHM (default brand, 100% zoom): 28 · mark 34 · 18 · title 29 · 4 · sub 18 · 18 · [36 · 8 · 36 · 14 · divider 16 · 14 · 36 · 8 · 36] · 16 · footer 16 · 22.

RESPONSIVE (§16): below 400px the card is `calc(100vw - 32px)`; padding, type and control heights are unchanged — the card is already a single column, so no breakpoint rule is required. At 200% font scale nothing clips because every control uses `min-block-size`, not `block-size`.

`/signin/callback`: same page frame, no card. Centred `logo-loader.css` mark (three layers scanning 180ms apart) + `auth.signin.callback.checking` ("Checking your access…") beneath it at 12.5px/var(--fg3). It is an honest indeterminate busy state — no progress bar, no percentage.

## Interactions

See the interactions section above.

## States

This surface's data dependency is `GET /api/v1/bootstrap` (public variant): branding tokens, the ordered `authMethods` list, locale, version, support/privacy/terms URLs. All four states are of that list, plus two response states that are not failures.

1. LOADING (`SignInSkeleton`)
   The identical card box — `min(360px, calc(100vw-32px))`, `padding-block:28px 22px`, `padding-inline:28px`, `border-radius:calc(var(--r-sheet)+2px)`, `box-shadow:var(--el2)`, `background:var(--sheet)` — filled with placeholders that occupy the same boxes, so nothing shifts when data lands:
   - mark: 34×34, `border-radius:8px`, `margin-block-end:18px`
   - title: `inline-size:60%; block-size:20px; margin-block-end:4px`
   - sub: `inline-size:80%; block-size:14px; margin-block-end:18px`
   - three bars at `min-block-size:36px`, `border-radius:calc(var(--r-ctrl)+2px)`, stacked `gap:8px`
   Shimmer: `background:linear-gradient(90deg,var(--sunken) 25%,var(--g150) 37%,var(--sunken) 63%); background-size:200% 100%; animation:encSh 1.4s linear infinite`. Under `prefers-reduced-motion` the animation is dropped and the flat `var(--sunken)` fill remains.
   `aria-busy="true"` on the card; the live region announces `auth.signin.state.loading` once.
   No full-screen spinner (§11).

2. EMPTY (NEW) — bootstrap succeeded, `authMethods` is empty (or every method was filtered out as unrunnable in this browser)
   The card renders mark + `<h1>` unchanged, then:
   - body `auth.signin.empty.noMethods.body` — "No sign-in method is configured for this workspace yet." at 12.5px/`var(--fg3)`
   - one action: a secondary 36px button/link to `branding.supportUrl`, `auth.signin.empty.noMethods.action` ("Contact your administrator"). If no support URL exists, the sentence stands alone with no dead control.
   Neutral colours only. This is a configuration gap, not a refusal.

3. EMPTY (FILTERED) — `POST /auth/idp/discover` returned `next:"none"` for the typed address
   The stack stays exactly as it is; a 12px `var(--fg3)` note appears directly beneath the email input inside the form (`margin-block-start:8px`, wired through `aria-describedby` on the input):
   - `auth.signin.empty.noProvider.body` — "No single sign-on provider matches that address."
   - a clear action rendered as a text button at `font-size:12px; color:var(--accent)`: `auth.signin.empty.noProvider.clear` ("Use a different address") — clears the input, removes the note, returns focus to the input.
   The input keeps its normal hairline; it does **not** take an error ring — nothing the user typed was invalid.

4. ERROR — bootstrap `5xx`, network failure, or a **Zod parse failure**
   The card is replaced by the failure card, same box, same shadow:
   - `<h2>` `auth.signin.error.title` at 15px/var(--tight)/600
   - body `auth.signin.error.body`, 12.5px/var(--fg3), stating what failed and whether it is retryable
   - primary 36px button `auth.signin.error.retry` → re-runs the query (present only when the failure is retryable; a parse failure is not, so it renders no retry)
   - request ID row: `margin-block-start:12px; font-size:11px; color:var(--fg4)`, label from catalog, value in `font-family:var(--mono)`, and a copy button (icon-only, 24×24, `#page` sprite, accessible name `auth.signin.error.copyRequestId`, confirmation announced in the live region via `auth.signin.error.copied`).
   A parse failure must never be caught into `{}` — an empty method list would render state 2 and tell the user "your workspace has no sign-in", which is the wrong story told confidently (`docs/17 §3`).

NOT A STATE OF THE LIST, BUT REQUIRED ON THIS SURFACE — the three non-actionable treatments, which must never look alike:

5. DENIED (policy refusal: `403 NETWORK_NOT_ALLOWED`, `DEVICE_NOT_MANAGED`, `ACCESS_DENIED`)
   Rendered into `.signin-live` above the stack (`role="status"` upgraded to `aria-live="assertive"` for a refusal), `margin-block-end:12px`, `padding:10px 12px`, `border-radius:var(--r-ctrl)`, `background:color-mix(in srgb,var(--danger) 8%,transparent)`, `color:var(--danger)`, `font-size:12px`, with a 14×14 `#block` icon.
   Content: the server's `message`, then the server's `remediation` as a second line at `var(--fg2)`. The stable `code` goes in a `<details>` disclosure at 11px/var(--mono) labelled `auth.signin.error.detailsForSupport` — never as the primary message (§9).
   **No retry button, ever.** The method buttons stay enabled (the user may legitimately try another method); the one that was refused takes `aria-describedby` → the denial node.
   Present tense, about the user. Focusable content.

6. BUSY — as described in interactions: spinner in place of the icon, label unchanged, `aria-busy="true"` + `aria-disabled="true"`, still in the tab order, neutral colour, no denial treatment anywhere near it.

7. UNBUILT — the neutral `Later` chip, `disabled` (not focusable), `aria-describedby` → release note, future tense about the product, and never the `--danger` family.

WORDING SOURCE, reconciling `docs/14 §5` with `docs/17 §7`: prefer the client catalog keyed by the stable `code` (`auth.signin.error.<CODE>`); when no key exists for that code, render the server's `message` and `remediation` verbatim — they arrive localized and user-safe. The client never composes a reason of its own and never shows which rule matched.

## Tokens

- `--canvas — page ground behind the card`
- `--sheet — card background, and the secondary button / input fill`
- `--sunken — secondary button hover, skeleton fill, neutral Later chip`
- `--line — the 1px divider rules (background of .rule)`
- `--line-strong — dot colour in the background radial-gradient`
- `--hairline (= 0 0 0 1px var(--line)) — secondary button and input border, as box-shadow not border`
- `--el2 — card elevation`
- `--fg — heading, input text, secondary button label`
- `--fg2 — remediation line under a denial`
- `--fg3 — subtitle, empty-state body, callback caption, skeleton-adjacent text`
- `--fg4 — footer links, divider label, request-id row, unbuilt label`
- `--accent — logo mark, primary button background, focus outline, inline text actions`
- `--accent-ring — 4px focus halo on inputs`
- `--accent-soft — not used on this surface (listed so it is not reached for by habit)`
- `--r-ctrl — input radius; buttons use calc(var(--r-ctrl) + 2px)`
- `--r-sheet — card radius via calc(var(--r-sheet) + 2px) = 16px on the default brand`
- `--sans — body/UI (Inter)`
- `--tight — h1 and the error h2 (Inter Tight)`
- `--mono — version string, request ID, the code disclosure (JetBrains Mono)`
- `--danger — denial treatment only; never on unbuilt or busy`
- `--g150 — shimmer highlight stop in the skeleton gradient`
- `keyframes: encIn (card enter, 180ms), encSh (skeleton shimmer), encSpin (busy spinner)`
- `brand hooks: data-brand + data-theme on the SPA root; --accent / --accent-soft / --accent-ring / --r-ctrl / --r-surf / --r-sheet are the only values a tenant overrides`

## Technique fixes — the prototype breaks a hard rule here

- PHYSICAL PROPERTY — `margin-left:auto` on the version span. Fix: `margin-inline-start:auto`. Identical in LTR, correct in RTL. Same class of fix everywhere the prototype writes padding/margin shorthands with a directional intent: the button's `padding:0 14px` becomes `padding-block:0; padding-inline:14px`, the card's `padding:28px 28px 22px` becomes `padding-block:28px 22px; padding-inline:28px`, the input's `padding:0 9px` becomes `padding-block:0; padding-inline:9px`. en-XB mirrors in CI and fails on the physical names.
- HARD-CODED CARD RADIUS — `border-radius:16px` bypasses the brand radius scale, so a Meridian tenant (--r-sheet:8px) would get a 16px card against 4px controls. Fix: `calc(var(--r-sheet) + 2px)` — exactly 16px on the default brand (preserving the drawn appearance) and proportional under the other two, mirroring the buttons' existing `calc(var(--r-ctrl) + 2px)`.
- MOTION OVER BUDGET — `animation:encIn .3s` is 300ms; docs/09 §12 caps enter motion at 120–200ms. Fix: `animation:encIn 180ms cubic-bezier(.2,.7,.3,1) both` — same keyframes, same easing, same 4px rise, inside the budget. Add `@media (prefers-reduced-motion:reduce)` keeping the opacity fade and dropping the translate.
- FIXED HEIGHTS CLIP AT 200% ZOOM — `height:36px` on every button and input, against §15's 'user font scaling to 200%'. Fix: `min-block-size:36px`. Pixel-identical at 100%, grows instead of clipping when text does.
- STRING LITERALS — 'Sign in to {{brandName}}', 'Continue with passkey', 'Continue with SSO', 'Continue with email', 'or', 'Support', 'Privacy', 'Terms', 'v2.4.1' and the placeholder are all literals. Fix: `auth.signin.*` ICU keys, each with a translator description. The title is one message with a `{brandName}` placeholder — never concatenated (docs/14 §4). The version renders through `auth.signin.version` = 'v{version}' so the prefix is translatable, with the value from the server or the build constant.
- PLACEHOLDER USED AS A LABEL — the email input has no label at all, and 'name@northwind.example' disappears on typing. Fix: a visually hidden `<label for="signin-email">` (sr-only clip-path technique) plus the same placeholder as an example. Appearance is byte-identical; the field gains an accessible name.
- HEADING LEVEL — `<h3>` is the first and only heading on the page. Fix: `<h1>` carrying the identical type ramp (var(--tight)/20px/600/-.02em). No visual change; the document outline stops starting at level 3.
- BUTTONS WITHOUT A FORM — the email path is three siblings in a div, so Enter in the input does nothing. Fix: wrap input + submit in `<form novalidate>` with `display:contents` so the flex stack's 8px rhythm is untouched, and handle `onSubmit`. Enter now works with no key handler.
- DEAD LINKS — `href="#"` on Support/Privacy/Terms. Fix: real URLs from `branding.*Url`; omit the anchor entirely when a URL is absent. Add `target="_blank" rel="noopener noreferrer"` and a visually hidden 'opens in a new tab' string.
- DECORATIVE `<i>` ELEMENTS as divider rules. Fix: `<span class="rule" aria-hidden="true">` with the same `flex:1; block-size:1px; background:var(--line)`. `<i>` carries an emphasis semantic these are not.
- FOCUS RING BELOW CONTRAST — the global rule is `outline:2px solid var(--accent-ring)`, and --accent-ring is 35% alpha, which will not hold §15's 3:1 against `var(--sheet)` in either theme. Fix: `outline:2px solid var(--accent); outline-offset:1px`, keeping `var(--accent-ring)` as the 4px `box-shadow` halo — which is exactly what the prototype's own input focus style already does (`0 0 0 1px var(--accent), 0 0 0 4px var(--accent-ring)`), so the treatment becomes consistent rather than changed.
- BUSY MUST NOT USE `disabled` — the natural implementation of an in-flight button is the `disabled` attribute, which drops it from the tab order and yanks focus to the body mid-flow. docs/17 §6 requires busy to stay focusable. Fix: `aria-busy="true"` + `aria-disabled="true"` and an early return in the handler. Only the unbuilt treatment uses the real `disabled` attribute.
- ICON `<use>` NEEDS ARIA — every sprite `<svg>` in the prototype is unlabelled and reachable by assistive tech. Fix: `aria-hidden="true" focusable="false"` on every decorative icon; icon-only controls (the copy-request-id button) get a catalog-sourced `aria-label`. No visual change.
- SVG SPRITE VIA `<use href="#id">` — an external sprite file would be a network fetch and would break under the CSP. Fix: inline the symbol set once in `app/`, or import each icon as a React component from a generated module. Either way the paths are the prototype's, unchanged.
- NO CLIENT-SIDE DOMAIN→PROVIDER MAP — the obvious implementation of 'Continue with email' is a lookup table in the bundle. That re-derives an identity decision on the client and publishes the tenant's IdP layout. Fix: POST the address to the server and follow the `next` it returns.
- `?next=` REDIRECT — must be validated as a same-origin relative path before `navigate()`, or the sign-in page is an open redirect that survives a real authentication.
- PROTOTYPE-WIDE, WORTH STATING ONCE: nothing on this screen may be formatted by hand. The only formatted values here are the rate-limit wait (`Intl.RelativeTimeFormat`) and any future attempt counter (`Intl.NumberFormat`). The prototype's '2 h ago' / 'Rs 4.8 Cr' constructions elsewhere are defects, not the house style.

## Backend required

- GET /api/v1/bootstrap — public (unauthenticated) variant. docs/05 §19 lists /bootstrap but does not specify that it is reachable without a token, and the sign-in screen cannot have one. Needs: branding (loginLogoUrl, productName, accent, radii, supportUrl, privacyUrl, termsUrl), locale, version, and an ordered authMethods array. Tenant resolved at the gateway from the custom domain — no tenant parameter in the request.
- authMethods contract (new): [{ kind: 'webauthn'|'oidc'|'saml'|'email', key, displayName, startUrl?, status: 'available'|'unavailable', unavailableReason?, releaseNote? }]. Three fields carry the three non-actionable treatments; without unavailableReason/releaseNote the client would have to invent them, which docs/17 §4.1 and ENC-674 forbid. This is the sign-in analogue of ENC-674's reason-on-a-false-capability.
- POST /api/v1/auth/idp/discover { email } → { next: 'oidc'|'saml'|'password'|'none', startUrl? }. Does not exist today. Required so the domain→provider decision lives on the server; a client-side domain map would be a second authority on identity and would leak the tenant's IdP topology to anyone who loads the page. Must be rate-limited and must not disclose whether the address corresponds to a real user (uniform response timing, no 404 distinction).
- POST /api/v1/auth/webauthn/login/start + /finish — exists (docs/05 §3).
- POST /api/v1/auth/login — exists; accepts Idempotency-Key per §4.
- POST /api/v1/auth/mfa/verify — exists; consumed by the shared/api step-up interceptor, not by this feature.
- GET /api/v1/auth/oidc/{provider}/start + /callback, POST /auth/saml/{provider}/acs — exist; the client uses the server-supplied startUrl verbatim.
- Every response must carry X-Request-Id (docs/05 §1) including the failure paths, or the error state has nothing copyable to offer.
- Crates: auth (WebAuthn ceremony, OIDC/SAML, discovery), config (branding + identity config, secrets by reference only), core (conditional access evaluated at login and at refresh), audit (login success, login failure, denial — inside the policy engine, never the handler; never log the password, the token, the refresh cookie or the assertion), events (session established).
- Open question for the API owner: 'Continue with email' assumes a two-step discovery. There is no magic-link endpoint anywhere in docs/05 or docs/13 — if the intended third path is a magic link rather than password, it needs a contract before this screen can be built as drawn.