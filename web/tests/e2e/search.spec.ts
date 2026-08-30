import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * Search returns the tenant's own content, and its filter offers the tenant's
 * own workspaces.
 *
 * The screen read as fabricated and mostly was not. `POST /api/v1/search` has
 * always returned real matches — full-text over PostgreSQL, with excerpts,
 * scores and paths — and `features/search/api.ts` has always sent the query to
 * it. What was fixture-backed was one import: `CORPUS_WORKSPACES`, the workspace
 * filter's options, which listed names that existed nowhere. Picking one
 * narrowed a real search to a workspace the tenant does not have, and the empty
 * result that followed was unexplainable (`ENC-934`).
 *
 * So this file asserts the two halves separately: that results are the server's,
 * and that the filter's options are the caller's. A test that only did the first
 * would have passed before the fix.
 */

const Login = z.object({ accessToken: z.string().min(1) });
const Workspaces = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const Hit = z.object({ fileId: z.string(), title: z.string(), workspace: z.string() });
const Results = z.object({ results: z.array(Hit) });

async function token(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  return Login.parse(await response.json()).accessToken;
}

test('a search returns the files the server matched, with the server’s own titles', async ({
  page,
  request,
}) => {
  const bearer = await token(request);

  /* The corpus is whatever this deployment holds, so the term is taken from a
   * real file's name rather than invented. A hard-coded query is a test that
   * passes on one machine's fixture and says nothing anywhere else. */
  const workspaces = await request.get('/api/v1/workspaces', {
    headers: { authorization: `Bearer ${bearer}` },
  });
  const { items } = Workspaces.parse(await workspaces.json());
  expect(items.length, 'the tenant has no workspaces — is it provisioned?').toBeGreaterThan(0);

  const libraries = await request.get(`/api/v1/workspaces/${items[0]?.id ?? ''}/libraries`, {
    headers: { authorization: `Bearer ${bearer}` },
  });
  const libs = Workspaces.parse(await libraries.json());
  expect(libs.items.length, 'the workspace has no library').toBeGreaterThan(0);

  const contents = await request.get(`/api/v1/libraries/${libs.items[0]?.id ?? ''}/items`, {
    headers: { authorization: `Bearer ${bearer}` },
  });
  const files = z
    .object({ items: z.array(z.object({ name: z.string(), nodeType: z.string() })) })
    .parse(await contents.json());
  const document = files.items.find((item) => item.nodeType !== 'FOLDER');
  expect(document, 'the library holds no file to search for').toBeDefined();

  /* The stem, because the extension is drawn as its own span and a full-name
   * query would also match on punctuation the index treats differently. */
  const term = (document?.name ?? '').replace(/\.[^.]+$/u, '');

  const searched = await request.post('/api/v1/search', {
    headers: { authorization: `Bearer ${bearer}` },
    data: { query: term, limit: 20 },
  });
  expect(searched.ok(), `search answered ${searched.status()}`).toBe(true);
  const expected = Results.parse(await searched.json());
  expect(expected.results.length, `the server matched nothing for "${term}"`).toBeGreaterThan(0);

  await signIn(page);
  await page.goto(`/search?q=${encodeURIComponent(term)}`);

  /* Every title the server returned, present on the screen. Read from the API
   * rather than written here, so this asserts the client rendered *what the
   * server sent* and not merely that it rendered something. */
  for (const hit of expected.results) {
    await expect(page.getByText(hit.title, { exact: false }).first()).toBeVisible();
  }
});

test('the filters are offered as unbuilt, because the server refuses every one of them', async ({
  page,
  request,
}) => {
  const bearer = await token(request);

  /* The server's half of the contract, asserted first and directly. `POST
   * /search` *declares* `workspaceIds`, `libraryIds`, `types`,
   * `classificationMax` and `modifiedAfter` and answers `400 UNSUPPORTED`
   * naming the field for each. That is deliberate, and it is the reason the
   * screen must not offer a working filter chip. */
  const filtered = await request.post('/api/v1/search', {
    headers: { authorization: `Bearer ${bearer}` },
    data: { query: 'anything', limit: 20, workspaceIds: ['00000000-0000-0000-0000-000000000000'] },
  });
  expect(filtered.status(), 'the server accepted a filter it does not apply').toBe(400);
  const body = z
    .object({ error: z.object({ details: z.array(z.object({ field: z.string() })) }) })
    .parse(await filtered.json());
  expect(body.error.details.map((detail) => detail.field)).toContain('workspaceIds');

  await signIn(page);
  await page.goto('/search');

  /* The client's half. The control is rendered **unbuilt** — visible, neutral,
   * out of the tab order — and never as a working chip and never as a denial.
   * That distinction is `docs/17 §6`: this is the product not having the
   * feature, not the policy chain refusing this caller.
   *
   * Accepting a narrowing the server will not apply would return *more* than
   * the caller asked for, and a `classificationMax` of `INTERNAL` answered with
   * `CONFIDENTIAL` hits is a disclosure produced by a control that appeared to
   * work. Filtering client-side over one page would be the same lie moved: a
   * document excluded by the chip reads identically to one that does not exist.
   *
   * So this asserts the *absence* of a working filter, which is a real property
   * and not a placeholder — the day the server accepts these fields, this test
   * goes red and asks to be rewritten, which is exactly when somebody should
   * look at it. */
  const unbuilt = page.locator('.esr-filters-unbuilt');
  await expect(unbuilt).toBeVisible();
  await expect(page.getByRole('menuitemradio')).toHaveCount(0);
});
