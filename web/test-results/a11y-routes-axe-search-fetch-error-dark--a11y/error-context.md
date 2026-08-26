# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: a11y/routes.spec.ts >> axe: search, fetch error (dark)
- Location: tests/a11y/routes.spec.ts:197:5

# Error details

```
Error: [
  {
    "id": "color-contrast",
    "impact": "serious",
    "help": "Elements must meet minimum color contrast ratio thresholds",
    "nodes": [
      {
        "target": ".surface-state-title",
        "summary": "Fix any of the following: Element has insufficient color contrast of 3.32 (foreground color: #c0392b, background color: #161615, font size: 9.8pt (13px), font weight: normal). Expected contrast ratio of 4.5:1"
      }
    ]
  }
]

expect(received).toEqual(expected) // deep equality

- Expected  -  1
+ Received  + 13

- Array []
+ Array [
+   Object {
+     "help": "Elements must meet minimum color contrast ratio thresholds",
+     "id": "color-contrast",
+     "impact": "serious",
+     "nodes": Array [
+       Object {
+         "summary": "Fix any of the following: Element has insufficient color contrast of 3.32 (foreground color: #c0392b, background color: #161615, font size: 9.8pt (13px), font weight: normal). Expected contrast ratio of 4.5:1",
+         "target": ".surface-state-title",
+       },
+     ],
+   },
+ ]
```

# Page snapshot

```yaml
- generic [ref=e3]:
  - navigation "Enclave" [ref=e4]:
    - button "Switch workspace" [ref=e5] [cursor=pointer]:
      - generic [ref=e10]: Enclave
    - link "Search ⌘K" [ref=e14] [cursor=pointer]:
      - /url: /search
      - text: Search
      - generic [ref=e17]: ⌘K
    - generic [ref=e18]:
      - text: Inbox
      - generic [ref=e21]: Later
    - link "Home" [ref=e23] [cursor=pointer]:
      - /url: /
    - link "Ask ⌘J" [ref=e26] [cursor=pointer]:
      - /url: /ask
      - text: Ask
      - generic [ref=e29]: ⌘J
    - generic [ref=e30]: Files
    - link "Files" [ref=e33] [cursor=pointer]:
      - /url: /library
    - generic [ref=e36]:
      - text: Lists
      - generic [ref=e39]: Later
    - generic [ref=e41]:
      - text: Pages
      - generic [ref=e44]: Later
    - generic [ref=e46]:
      - text: Activity
      - generic [ref=e49]: Later
    - generic [ref=e51]: Personal
    - generic [ref=e54]:
      - text: Favorites
      - generic [ref=e57]: Later
    - generic [ref=e59]:
      - text: Shared with me
      - generic [ref=e62]: Later
    - generic [ref=e64]:
      - text: Trash
      - generic [ref=e67]: Later
    - generic [ref=e69]: Administration
    - link "Admin" [ref=e72] [cursor=pointer]:
      - /url: /admin
    - generic [ref=e75]:
      - button "Sign out" [ref=e76] [cursor=pointer]:
        - generic [ref=e77]: AU
        - generic [ref=e78]: Admin User
      - group "Light" [ref=e80]:
        - button "Light" [ref=e81] [cursor=pointer]
        - button "Dark" [pressed] [ref=e82] [cursor=pointer]
  - main [ref=e83]:
    - generic [ref=e84]:
      - heading "Search" [level=1] [ref=e85]
      - generic [ref=e86]:
        - searchbox "Search" [ref=e89]: agreement
        - generic [ref=e90]: Esc
      - generic [ref=e91]:
        - generic [ref=e92]:
          - button "Filters" [disabled] [ref=e93]
          - generic [ref=e96]: Later
          - generic [ref=e97]: Narrowing a search arrives once the API accepts filters
        - generic [ref=e98]: No results
      - generic [ref=e99]:
        - generic [ref=e103]: Answers drawn from these documents, with their sources
        - generic [ref=e104]: Later
        - generic [ref=e105]: Arrives in a later release
      - generic [ref=e106]:
        - paragraph [ref=e107]: This didn’t load
        - paragraph [ref=e108]: Something went wrong on our side. Trying again may work.
        - generic [ref=e109]:
          - button "Try again" [ref=e110] [cursor=pointer]
          - generic [ref=e111]:
            - generic [ref=e112]: Request ID
            - code [ref=e113]: 01a0402d-cb72-76e2-8f0e-ee21277e71e0
            - button "Copy" [ref=e114] [cursor=pointer]
      - generic [ref=e115]:
        - generic [ref=e116]:
          - generic [ref=e117]: ↑↓
          - text: move between results
        - generic [ref=e118]:
          - generic [ref=e119]: ⏎
          - text: open
        - generic [ref=e120]: Results respect your access
```

# Test source

```ts
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
  218 |       await page.waitForSelector(surface.ready, { timeout: 30_000 });
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
> 239 |       expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
      |                                                               ^ Error: [
  240 |     });
  241 |   }
  242 | }
  243 | 
```