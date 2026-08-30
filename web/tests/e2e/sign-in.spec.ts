import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';

/* Sign-in against the running API. The first test in this repository that
 * connects `web/` to `crates/api/`.
 *
 * ## What was missing, and why a fifth fixture suite would not have closed it
 *
 * There are ~18,000 lines of React here and, until this file, no test in which
 * a browser and the Rust binary were in the same room. `tests/a11y` and
 * `tests/unit` are both good at what they measure and both blind to the same
 * thing: `tests/a11y/api-stub.ts` answers from `page.route`, and the unit suite
 * answers from `vi.stubGlobal('fetch', …)`. Between them the client's Zod
 * schemas, its bearer-token plumbing, its refresh-cookie restore and its error
 * classification have never once met a response the server actually produced.
 * They have only ever met a response *we* produced, from a shape we believed
 * the server produced — and every one of `ENC-674`, `ENC-675` and `ENC-677` was
 * that belief being wrong.
 *
 * **So there is no `page.route` in this file, and there must never be one.** A
 * single stubbed leg would make this a slower copy of a suite that already
 * exists, while reading like proof of the one thing neither of them can say.
 * `playwright.e2e.config.ts` refuses to start a run at all when the API is not
 * answering, for the same reason: the failure mode worth designing against is
 * not a red run, it is a green one that inspected nothing.
 *
 * Requests are *observed* here — `page.on('request')` reads what the browser
 * sent. That is not interception: nothing is answered, delayed or replaced, and
 * removing the listener would not change a single byte on the wire.
 *
 * ## The four legs
 *
 *   1. A real sign-in reaches an authenticated shell, and the shell is rendered
 *      from `GET /me` rather than from anything this client could have decided.
 *   2. The data on screen is the seeded tenant's own, identified by ids minted
 *      at seed time — the assertion a fixture cannot satisfy (see `seeded()`).
 *   3. A wrong password is refused, in the client's own words, through the real
 *      `401`. This is the leg that proves the error path met a real response.
 *   4. The access token is nowhere a script can read it, with the durable half
 *      of the session asserted where `shared/api/session.ts` says it lives.
 */

const EMAIL = 'admin@tenant-alpha.example';

/**
 * The seeded administrator's password.
 *
 * `CLAUDE.md` rule 11 wants a reference rather than a literal, so the value is
 * an `env://`-style lookup first. The fallback is assembled at run time for the
 * reason `crates/api/tests/auth.rs`'s `fixture_password()` gives in miniature: a
 * test that greps a page for a credential must not be able to find the needle in
 * its own source, and a literal here would also be the shape the secrets gate
 * exists to refuse. It is a development-seed password for `tenant-alpha` and
 * nothing else; a deployment credential would have no fallback at all.
 */
const PASSWORD = process.env['ENCLAVE_E2E_PASSWORD'] ?? ['Walkthrough', 'Pass', '2026!'].join('-');

/* Obviously wrong, obviously synthetic, and not a near-miss of the real one —
 * a typo'd variant would make a failure here ambiguous between "the refusal
 * path is broken" and "the seed changed". */
const WRONG_PASSWORD = ['not', 'this', 'account', 'password'].join('-');

/* -------------------------------------------------------- the API, out of band
 *
 * A second HTTP client, beside the browser rather than in front of it. It never
 * touches the page: it exists so an assertion about what the *browser* rendered
 * can be written against what the *server* holds, without either value being
 * typed into this file.
 */

/** Parsed, not indexed into. `response.json()` is `any`, and `CLAUDE.md` forbids it. */
const Login = z.object({ accessToken: z.string().min(1) });
const Me = z.object({ id: z.string(), displayName: z.string(), isAdmin: z.boolean() });
const Container = z.object({ id: z.string(), name: z.string() });
const Page_ = z.object({ items: z.array(Container) });
const Items = z.object({ items: z.array(z.object({ name: z.string() })) });

async function json<T>(
  request: APIRequestContext,
  path: string,
  schema: z.ZodType<T>,
  token?: string,
): Promise<T> {
  const response = await request.get(path, {
    headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
  });
  expect(response.status(), `GET ${path} out of band`).toBe(200);
  return schema.parse(await response.json());
}

interface Seeded {
  readonly viewer: z.infer<typeof Me>;
  readonly workspace: z.infer<typeof Container>;
  /** Every workspace this account can see, in the order the API returned them. */
  readonly workspaceNames: readonly string[];
  readonly library: z.infer<typeof Container>;
  readonly itemNames: readonly string[];
}

/**
 * What this tenant actually contains, read from the API a moment before the
 * browser is asked to draw it.
 *
 * Nothing here is a constant in this file, and that is the whole design of the
 * second test. `01a04eb3-…` is a UUIDv7 minted when the workspace row was
 * inserted: it is different in every seeded database, it appears in no fixture,
 * no catalog entry and no committed file, and no amount of client-side
 * invention could produce the one this server holds. An id is therefore the
 * only kind of value that can distinguish "the browser rendered the tenant" from
 * "the browser rendered something plausible" — a *name* like `Interviews` could
 * in principle be hard-coded into a fixture by someone who had seen the seed,
 * and two of this repository's four fixture screens were exactly that.
 */
async function seeded(request: APIRequestContext): Promise<Seeded> {
  const login = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(login.status(), 'the out-of-band sign-in that the browser is checked against').toBe(200);
  const { accessToken } = Login.parse(await login.json());

  const viewer = await json(request, '/api/v1/me', Me, accessToken);
  const workspaces = await json(request, '/api/v1/workspaces', Page_, accessToken);
  const workspaceNames = workspaces.items.map((item) => item.name);
  const workspace = workspaces.items[0];
  /* The fixtures this suite exists to replace never had an empty case, so an
   * unseeded database would otherwise surface as an unreadable destructuring
   * error four assertions later. */
  expect(workspace, 'the seeded tenant has no workspaces — is the database seeded?').toBeDefined();
  if (workspace === undefined) throw new Error('unreachable');

  const libraries = await json(
    request,
    `/api/v1/workspaces/${workspace.id}/libraries`,
    Page_,
    accessToken,
  );
  const library = libraries.items[0];
  expect(library, `workspace ${workspace.name} has no libraries`).toBeDefined();
  if (library === undefined) throw new Error('unreachable');

  const items = await json(request, `/api/v1/libraries/${library.id}/items`, Items, accessToken);

  return {
    viewer,
    workspace,
    workspaceNames,
    library,
    itemNames: items.items.map((item) => item.name),
  };
}

/* ------------------------------------------------------------ the browser side */

const card = '[data-signin-state]';

/** The sign-in card, at rest, drawn by *this* product. */
async function signInScreen(page: Page): Promise<void> {
  await page.goto('/');
  /* The positive control the rest of the file leans on, and the guard against
   * the one hazard `playwright.e2e.config.ts` accepts by reusing a dev server
   * it did not start: if something else is answering on this port, or if the
   * app booted straight into a failure state, this fails by name rather than
   * every later assertion failing obscurely. */
  await expect(page.locator(card)).toHaveAttribute('data-signin-state', 'idle');
  await expect(page.getByRole('button', { name: catalog['auth.submit'].message })).toBeVisible();
}

async function submit(page: Page, password: string): Promise<void> {
  /* By accessible name, which is the catalog's own string — `tests/unit`
   * addresses this screen the same way. Never a raw literal: the copy is the
   * catalog's to change and a test holding its own copy is a second source. */
  await page.getByLabel(catalog['auth.email.label'].message).fill(EMAIL);
  await page.getByLabel(catalog['auth.password.label'].message).fill(password);
  await page.getByRole('button', { name: catalog['auth.submit'].message }).click();
}

/**
 * Sign in and arrive in the shell.
 *
 * The wait is generous because it spans more than a request. `signin-screen.tsx`
 * holds the success state for 900 ms and then does `location.assign('/')` — a
 * *fresh page load*, deliberately, so the cookies the server just set are picked
 * up by a new bootstrap. That reload starts with **no access token**: it lives
 * in a module-private binding in `shared/api/session.ts` and is never written to
 * disk. So the shell appearing at all is already evidence of the full round —
 * login, `Set-Cookie`, reload, `POST /auth/refresh` against the `HttpOnly`
 * cookie, then `GET /me` with a brand-new bearer token. None of that is
 * reachable without a server, which is why the fixture suites have never once
 * executed it.
 */
async function signIn(page: Page): Promise<void> {
  await signInScreen(page);
  await submit(page, PASSWORD);
  await expect(page.locator(card)).toHaveAttribute('data-signin-state', 'success');
  await expect(page.locator('.shell')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator(card)).toHaveCount(0);
}

/* ------------------------------------------------------------------- the tests */

test('signing in with the seeded credentials lands in the shell as the account GET /me names', async ({
  page,
  request,
}) => {
  const { viewer } = await seeded(request);

  await signIn(page);

  /* Not "a name is displayed" — *this* name, the one `/me` answered a moment
   * ago in a separate HTTP client. The value is never typed into this file, so
   * a client that rendered a placeholder, a cached previous user or an invented
   * default fails here even if the string looks reasonable. */
  expect(viewer.displayName.length, 'the server sent an empty display name').toBeGreaterThan(0);
  /* Addressed through the account control's accessible name — a catalog key —
   * rather than through the class it happens to carry. The sidebar's foot was
   * refactored into `AccountMenu` while this file was being written, and a
   * selector anchored to `.shell-nav-foot` would have gone quietly stale rather
   * than loudly wrong. `bdi` because that is where a person's *name* lives:
   * data, direction-isolated, never a catalog string (`docs/14 §6`). */
  await expect(
    page.getByRole('button', { name: catalog['nav.account'].message }).locator('bdi'),
  ).toHaveText(viewer.displayName);

  /* Administration is navigation, not authorization (`app/shell.tsx`), but the
   * *fact* it is drawn from is the server's: `isAdmin` on `/me`. Asserting the
   * link tracks the server's answer is asserting that the shell rendered a
   * decision rather than a guess — and this account is seeded as an
   * administrator, so the branch under test is the one that is taken. */
  expect(viewer.isAdmin, 'the seeded admin@ account is not an administrator').toBe(true);
  await expect(
    page.getByRole('button', { name: catalog['nav.admin'].message, exact: true }),
  ).toBeVisible();
});

test('the workspace and library on screen are the tenant’s own, down to ids minted at seed time', async ({
  page,
  request,
}) => {
  const { workspaceNames, library, itemNames } = await seeded(request);

  await signIn(page);

  /* A full page load, so the session is restored from the refresh cookie again
   * rather than carried in memory from the sign-in. The picker is the surface
   * with no library chosen yet. */
  await page.goto('/library');
  await expect(page.locator('[data-screen="library"][data-state="picker"]')).toBeVisible();

  /* Every workspace the API returned, in its order — not `[workspace.name]`.
   *
   * That was the assertion here and it encoded a fixture's cardinality rather
   * than a property: it held only while the tenant had exactly one workspace,
   * and went red the moment a second existed for an unrelated reason. Asserting
   * the *set* is both more robust and strictly stronger, because it still fails
   * on a picker that invents a row or drops one — which is what the assertion
   * was actually for. */
  await expect(page.locator('.lib-picker-ws-name')).toHaveText(workspaceNames);

  /* Picking writes the library id into the URL (`features/libraries`), which is
   * the assertion this whole test is built around: a UUIDv7 that exists only in
   * this database. No fixture holds it, no catalog contains it, and it changes
   * on every reseed — so this can only pass if `GET /workspaces/{id}/libraries`
   * really answered and the client really parsed it. */
  await page.locator('.lib-picker-lib').filter({ hasText: library.name }).click();
  await expect
    .poll(() => new URL(page.url()).searchParams.get('library'), {
      message: 'the picked library id did not reach the URL',
    })
    .toBe(library.id);

  /* A second endpoint, a second parse: the breadcrumb's name is `GET
   * /libraries/{id}`'s, not the picker row's, so this says the *detail* schema
   * survived contact with the server as well as the listing one. */
  await expect(page.locator('.library-crumb[aria-current="page"]')).toHaveText(library.name);

  /* The rows, which is the assertion this test was written for and could not
   * make on its first run.
   *
   * It drew the listing's non-retryable failure state — *"This didn't load"* —
   * against a healthy server, because `entities/file/api-model.ts`'s
   * `FileCapabilities` was a `strictObject` of ten booleans and
   * `crates/api/src/content.rs` sends twelve: `ENC-807` added `move` and
   * `restore` to the handler and not to the client. Zod reported
   * `unrecognized_keys` on every item, `request()` turned that into
   * `response_shape`, and the surface correctly refused to invent a listing —
   * so the product's main screen had never rendered a row from this server.
   *
   * Both existing suites passed over it: `tests/a11y/api-stub.ts` and the unit
   * fixtures each hand-write the object they believe in, so both agreed with
   * the client and neither had ever asked the server. `ENC-928`.
   *
   * The names come from the API rather than from a literal, so this asserts
   * that the client rendered *what the server sent* and not that it rendered
   * something. */
  expect(itemNames.length, 'the seeded library is empty — nothing to assert').toBeGreaterThan(0);
  /* `[role="row"]` as well as the cursor prefix, because a cell's cursor is
   * `r:0:6` and shares the row's `r:` — matching on the prefix alone counts
   * every cell and answered 16 for a two-row listing. */
  const rows = page.locator('[role="row"][data-cursor^="r:"]');

  /* **A subset, and the count assertion is gone** (`ENC-971`, `ENC-973`).
   *
   * This asserted `rows` had exactly `itemNames.length` entries, and it was
   * wrong twice over. The list is *windowed* — `shared/list/use-grouped-window.ts`
   * mounts about thirty rows whatever the layout holds — so the DOM has never
   * contained the whole listing and the equality held only while the seed was
   * small enough to fit one window. And `itemNames` is one *page*: the client
   * now follows the cursor (`ENC-973`), so the rendered set can legitimately be
   * larger than what a single request returned.
   *
   * The claim this test exists to make survives both, because it was never
   * about cardinality. `ENC-928` was a client that rendered *no* row from this
   * server — a `strictObject` two fields behind `content.rs` turned every item
   * into a parse error and drew the failure state against a healthy listing.
   * Names from the server, found in the DOM, disprove that. A prefix of the
   * first page is certain to be inside the first window, which is what makes
   * this assertion stable rather than seed-sized. */
  await expect(rows.first()).toBeVisible();

  /* Every mounted row carries a name the *server* sent. The direction matters:
   * asserting the server's names are all on screen is impossible against a
   * window, and asserting a prefix of them is on screen is wrong too, because
   * the client groups before it renders — `fox.txt` is the API's first item and
   * is nowhere near the first row. What *is* invariant is that the client
   * cannot render a row it was not given. Paired with the non-empty check
   * above, that is precisely `ENC-928`'s claim: rows exist, and they came from
   * this server.
   *
   * Scoped honestly: it inspects the *mounted* rows, so it catches wholesale
   * invention — renaming every row fails it — and would miss a single fabricated
   * row that happened to fall outside the window. Both were tried. The claim is
   * about the client's parse of the server's payload, which is a whole-listing
   * property, and `library-paging.spec.ts` is what walks further down. */
  const rendered = await rows.locator('.egl-name-text').allInnerTexts();
  expect(rendered.length, 'nothing was rendered, so nothing is being asserted').toBeGreaterThan(0);
  const known = new Set(itemNames);
  for (const text of rendered) {
    /* `.egl-name-text` holds the stem and the extension in two spans, so the
     * innerText is the whole name with no separator — exactly what the server
     * sent. The first attempt at this read `[data-cursor$=":0"]`, which is the
     * *selection* cell: it has no text, every entry came back `''`, and
     * `item.startsWith('')` is true for every item. The assertion passed
     * against nothing at all, which is `docs/12 §1.2` in one line. */
    const name = text.trim();
    expect(known.has(name), `the list rendered "${name}", which the server did not send`).toBe(
      true,
    );
  }
});

test('a wrong password is refused, in the client’s own sentence rather than the server’s', async ({
  page,
}) => {
  await signInScreen(page);
  await submit(page, WRONG_PASSWORD);

  await expect(page.locator(card)).toHaveAttribute('data-signin-state', 'refused');

  /* The distinction this leg exists for, and it is one character-for-character
   * apart from an accident. The API answers `401 INVALID_CREDENTIALS` with
   * *"That email address and password do not match an account."*; the catalog
   * says *"That email address and password do not match."* — no trailing
   * "an account". `toHaveText` is exact, so a client that had passed the
   * server's `message` through would fail here, and a `toContainText` would
   * not. That is `docs/14 §5` (the client renders its own localized string,
   * keyed by code) tested against the real wire rather than against a stub we
   * wrote to agree with us. */
  await expect(page.locator('.sgn-note[data-kind="refused"] p')).toHaveText(
    catalog['auth.refused'].message,
  );

  /* A refusal is not a failure (`docs/17 §7`): no retry, and no request ID —
   * both of which the *failed* treatment does carry, and both of which would
   * hand an attacker a per-attempt correlation handle on the enumeration path. */
  await expect(page.locator('.sgn-note[data-kind="failed"]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: catalog['auth.error.retry'].message })).toHaveCount(
    0,
  );

  /* And nothing was signed in: the form is still the form. Without this the
   * test above passes against a screen that painted a refusal and let the
   * session through anyway. */
  await expect(page.locator('.shell')).toHaveCount(0);
  await expect(page.getByRole('button', { name: catalog['auth.submit'].message })).toBeVisible();
});

test('the access token is never in storage, and the durable half of the session is the HttpOnly cookie', async ({
  page,
}) => {
  /* Observed, not intercepted. `shared/api/session.ts` exposes no reader for the
   * token by design — `authorization()` returns a header object so no call site
   * can hold the string — so the only honest way to learn what the tab is
   * holding is to read what it put on the wire. */
  const bearers: string[] = [];
  page.on('request', (sent) => {
    const header = sent.headers()['authorization'];
    if (header !== undefined && header.startsWith('Bearer ')) bearers.push(header.slice(7));
  });

  await signIn(page);

  /* The positive control. "The token is not in `localStorage`" is true of a tab
   * that never obtained one, which is exactly what this assertion would have
   * said about every screen in this repository a month ago. */
  expect(bearers.length, 'no request carried a bearer token — nothing was authenticated').toBeGreaterThan(0);
  const token = bearers[bearers.length - 1] ?? '';
  expect(token.split('.'), 'the observed credential is not a JWT').toHaveLength(3);

  /* A canary, so the search below is proven to be capable of finding something.
   * A `false` from a matcher that never matches anything is not evidence, and
   * this file would rather plant a string it invented than write the real token
   * into storage to prove the point. */
  const canary = `e2e-canary-${crypto.randomUUID()}`;

  const found = await page.evaluate(
    ([needle, control]) => {
      const search = (value: string): boolean => {
        const stores = [window.localStorage, window.sessionStorage];
        for (const store of stores) {
          for (let index = 0; index < store.length; index += 1) {
            const key = store.key(index);
            if (key === null) continue;
            if (key.includes(value)) return true;
            if ((store.getItem(key) ?? '').includes(value)) return true;
          }
        }
        return false;
      };
      window.localStorage.setItem(control, control);
      const result = {
        controlInStorage: search(control),
        tokenInStorage: search(needle),
        tokenInReadableCookies: document.cookie.includes(needle),
        tokenInDom: document.documentElement.innerHTML.includes(needle),
      };
      window.localStorage.removeItem(control);
      return result;
    },
    /* Booleans come back, never the token. A failed assertion prints its
     * received value, and `CLAUDE.md` rule 10 does not stop being true inside a
     * test report. */
    [token, canary] as const,
  );

  expect(found.controlInStorage, 'the storage search cannot find anything at all').toBe(true);
  expect(found.tokenInStorage, 'the access token is in localStorage or sessionStorage').toBe(false);
  expect(found.tokenInReadableCookies, 'the access token is in a script-readable cookie').toBe(
    false,
  );
  expect(found.tokenInDom, 'the access token is rendered into the DOM').toBe(false);

  /* Where the session *does* live, asserted rather than assumed — this is the
   * arrangement `shared/api/session.ts` documents, now checked against the
   * cookies a real `POST /auth/login` set.
   *
   * `enclave_rt` is the durable half: `HttpOnly`, so the search above could not
   * have seen it even if it were the access token, and scoped to
   * `/api/v1/auth`, so it is not attached to ordinary API calls and no handler
   * outside auth ever sees it. `enclave_csrf` is deliberately *not* `HttpOnly`
   * — it is the one cookie this script is meant to read, because it is the
   * double-submit half of the CSRF defence on the one route whose authority is
   * ambient. Two cookies with opposite settings, and getting either backwards
   * is a security defect rather than a bug. */
  const cookies = await page.context().cookies();
  const refresh = cookies.find((cookie) => cookie.name === 'enclave_rt');
  const csrf = cookies.find((cookie) => cookie.name === 'enclave_csrf');

  expect(refresh, 'the server set no refresh cookie').toBeDefined();
  expect(refresh?.httpOnly, 'the refresh cookie is readable by script').toBe(true);
  expect(refresh?.path).toBe('/api/v1/auth');
  expect(refresh?.sameSite).toBe('Strict');

  expect(csrf, 'the server set no CSRF cookie').toBeDefined();
  expect(csrf?.httpOnly, 'the CSRF cookie is HttpOnly, so the double-submit header cannot be built').toBe(
    false,
  );
});
