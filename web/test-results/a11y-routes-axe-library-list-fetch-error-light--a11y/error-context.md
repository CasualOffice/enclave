# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: a11y/routes.spec.ts >> axe: library list, fetch error (light)
- Location: tests/a11y/routes.spec.ts:197:5

# Error details

```
Error: Channel closed
```

```
Error: page.waitForSelector: Test ended.
Call log:
  - waiting for locator('.surface-state[data-tone="error"]') to be visible

```

# Page snapshot

```yaml
- main [ref=e3]:
  - generic [ref=e4]:
    - heading "Sign in to Enclave" [level=1] [ref=e9]
    - paragraph [ref=e10]: Use your work email address and password.
    - generic [ref=e11]:
      - generic [ref=e12]:
        - generic [ref=e13]: Email address
        - textbox "Email address" [ref=e14]:
          - /placeholder: name@example.com
      - generic [ref=e15]:
        - generic [ref=e16]: Password
        - textbox "Password" [ref=e17]
      - button "Sign in" [ref=e19] [cursor=pointer]
    - generic [ref=e20]: or
    - generic [ref=e21]:
      - button "Continue with Company SSO" [ref=e22] [cursor=pointer]
      - generic [ref=e23]:
        - button "Continue with a passkey" [disabled] [ref=e24]
        - generic [ref=e27]: Later
        - generic [ref=e28]: Later
      - paragraph [ref=e29]: Passkeys arrive in a later release.
    - generic [ref=e30]:
      - link "Support" [ref=e31] [cursor=pointer]:
        - /url: https://support.example.com
      - link "Privacy" [ref=e32] [cursor=pointer]:
        - /url: https://www.example.com/privacy
      - link "Terms" [ref=e33] [cursor=pointer]:
        - /url: https://www.example.com/terms
```

# Test source

```ts
  118 |   { name: 'home, loading', url: '/?home=loading', ready: '[role="status"]' },
  119 |   { name: 'home, empty', url: '/?home=empty', ready: '[data-state="empty"]' },
  120 |   { name: 'home, scoped empty', url: '/?home=scoped-empty', ready: '[data-state="scoped-empty"]' },
  121 |   { name: 'home, fetch error', url: '/?home=error', ready: '[data-state="error"]' },
  122 |   {
  123 |     name: 'home, tasks refused',
  124 |     url: '/',
  125 |     ready: '.surface-state[data-tone="neutral"]',
  126 |     api: { status: 403 },
  127 |   },
  128 | 
  129 |   /* Search. Both retrieval notices are listed: the *lexical* one is a product
  130 |    * state (this deployment has no dense retrieval) and the *degraded* one is an
  131 |    * incident. They say different things and only one carries a `Later` chip, so
  132 |    * both need a run. `degraded` now comes from the server's own diagnostics
  133 |    * rather than from a URL knob, so the stub sets it. */
  134 |   { name: 'search, results (lexical)', url: '/search?q=agreement', ready: '.esr-hit' },
  135 |   {
  136 |     name: 'search, degraded fallback',
  137 |     url: '/search?q=agreement',
  138 |     ready: '[data-notice="degraded"]',
  139 |     api: { degraded: true },
  140 |   },
  141 |   { name: 'search, empty (new)', url: '/search', ready: '[data-state="empty"]' },
  142 |   {
  143 |     name: 'search, no results',
  144 |     url: '/search?q=agreement',
  145 |     ready: '[data-state="filtered-empty"]',
  146 |     api: { results: 0 },
  147 |   },
  148 |   {
  149 |     name: 'search, loading',
  150 |     url: '/search?q=agreement',
  151 |     ready: '.esr-loading',
  152 |     api: { hang: true },
  153 |   },
  154 |   {
  155 |     name: 'search, fetch error',
  156 |     url: '/search?q=agreement',
  157 |     ready: '.surface-state[data-tone="error"]',
  158 |     api: { status: 500 },
  159 |   },
  160 |   {
  161 |     name: 'search, policy denial',
  162 |     url: '/search?q=agreement',
  163 |     ready: '.surface-state[data-tone="neutral"]',
  164 |     api: { status: 403 },
  165 |   },
  166 | 
  167 |   /* Admin — DLP policy. It carries a *fifth* state the other screens do not:
  168 |    * `denied`, which is a policy refusal rather than a failure and shares no
  169 |    * class with the error state (`docs/17 §10` F2/F3). Both are listed, and the
  170 |    * auditor view is listed separately because it is the same screen with every
  171 |    * mutating control removed (`docs/09 §21`) rather than a poorer one. */
  172 |   { name: 'admin dlp, policy builder', url: '/admin?surface=fixture', ready: '.adm-builder' },
  173 |   {
  174 |     name: 'admin dlp, auditor read-only',
  175 |     url: '/admin?surface=fixture&as=auditor',
  176 |     ready: '.adm-builder',
  177 |   },
  178 |   { name: 'admin dlp, loading', url: '/admin?surface=loading', ready: '[role="status"]' },
  179 |   { name: 'admin dlp, empty', url: '/admin?surface=empty', ready: '[data-state="empty"]' },
  180 |   {
  181 |     name: 'admin dlp, filtered empty',
  182 |     url: '/admin?surface=fixture&q=zzzz',
  183 |     ready: '[data-state="filtered-empty"]',
  184 |   },
  185 |   { name: 'admin dlp, fetch error', url: '/admin?surface=error', ready: '[data-state="error"]' },
  186 |   { name: 'admin dlp, denied', url: '/admin?surface=denied', ready: '[data-state="denied"]' },
  187 | ];
  188 | 
  189 | test('the surface list is not empty', () => {
  190 |   /* The `ENC-543`/`ENC-677` assertion, in test form: an accessibility gate that
  191 |    * iterates an empty list passes without looking at anything. */
  192 |   expect(SURFACES.length).toBeGreaterThan(0);
  193 | });
  194 | 
  195 | for (const surface of SURFACES) {
  196 |   for (const theme of ['light', 'dark'] as const) {
  197 |     test(`axe: ${surface.name} (${theme})`, async ({ page }) => {
  198 |       /* Reduced motion, always.
  199 |        *
  200 |        * axe computes contrast from the *composited* pixel, so a run that lands
  201 |        * mid-entrance reads a half-faded colour and fails — measured at 2.12:1
  202 |        * on a line whose settled value is 6.83:1. That is a false negative, and
  203 |        * a suite that fails at random is a suite that gets quarantined.
  204 |        *
  205 |        * It is also the honest configuration rather than a workaround: every
  206 |        * animation in this tree is required to degrade under
  207 |        * `prefers-reduced-motion` (`docs/09 §12`), so this asserts the settled
  208 |        * appearance *and* the reduced-motion path in one run. A screen whose
  209 |        * contrast is only acceptable once an animation finishes is a screen that
  210 |        * fails for a user who has turned animation off. */
  211 |       await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
  212 |       /* Before the first navigation, so the app's own boot requests — the
  213 |        * refresh exchange and `/me` — are answered too. Installed after
  214 |        * navigation, the shell would already have concluded nobody is signed
  215 |        * in. */
  216 |       await stubApi(page, surface.api);
  217 |       await page.goto(surface.url);
> 218 |       await page.waitForSelector(surface.ready, { timeout: 30_000 });
      |                  ^ Error: page.waitForSelector: Test ended.
  219 | 
  220 |       const results = await new AxeBuilder({ page })
  221 |         // WCAG 2.2 AA is the stated target (`docs/09 §15`), so the tag set is
  222 |         // the target rather than axe's defaults.
  223 |         .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
  224 |         .analyze();
  225 | 
  226 |       /* The failure summary is kept because a bare rule id sends the next
  227 |        * reader to the axe docs; the summary names the element, the two colours
  228 |        * and the ratio, which is the whole of the fix. */
  229 |       const violations = results.violations.map((violation) => ({
  230 |         id: violation.id,
  231 |         impact: violation.impact,
  232 |         help: violation.help,
  233 |         nodes: violation.nodes.slice(0, 4).map((node) => ({
  234 |           target: node.target.join(' '),
  235 |           summary: node.failureSummary?.replace(/\s+/g, ' ').slice(0, 300) ?? '',
  236 |         })),
  237 |       }));
  238 | 
  239 |       expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
  240 |     });
  241 |   }
  242 | }
  243 | 
```