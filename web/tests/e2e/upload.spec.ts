import { expect, test, type APIRequestContext } from '@playwright/test';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * A file chosen in the browser reaches object storage, clears antivirus, and
 * appears in the library — driven through the product, not through `curl`.
 *
 * # Why this did not exist
 *
 * Upload is the oldest path in the product and the least proven from the
 * outside. `tests/unit/upload-put-headers.test.ts` and `upload-phase.test.ts`
 * assert the two pieces most likely to be got wrong in isolation, and
 * `crates/api/tests/uploads.rs` covers the endpoints — but nothing had ever put
 * a real file through the real picker into the real store. The comment in
 * `entities/upload/store.ts` says as much in its own words: moving the poll is
 * *"left to a session that can drive a real upload"*. Nothing could.
 *
 * That is the gap this repository keeps producing — every layer tested, the
 * journey through them untested — and on upload it hides a specific failure:
 * the three legs are a `POST` to us, a `PUT` to the object store, and a second
 * `POST` to us, and only the middle one leaves this codebase. A signature that
 * does not match, a header dropped on the way, or a digest computed over the
 * wrong bytes fails *there* and is invisible to every suite that stubs it.
 *
 * # It waits for readable, not for uploaded
 *
 * `CLAUDE.md` rule 9: nothing is `AVAILABLE` before antivirus completes. So the
 * assertion is not that the transfer finished — that is true seconds before the
 * file is usable — but that the row reaches its ready phase and the name then
 * appears in the listing. A test that stopped at "uploaded" would pass against
 * a product where scanning never ran and no file was ever readable.
 *
 * That also means **this test needs `enclave-worker` running**. Without it the
 * version sits in `SCANNING` for ever, which is correct behaviour and an
 * indefinite wait here.
 */

/* Unique per run: the library is shared with every other e2e, and a fixed name
 * would pass on the first run and match a leftover row on the second — the
 * shape that has already made two checks in this repository lie. */
const NAME = `upload-e2e-${Date.now()}.txt`;


async function accessToken(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  const body: unknown = await response.json();
  const token = (body as { accessToken?: string }).accessToken;
  expect(token, 'no access token in the sign-in response').toBeTruthy();
  return token as string;
}

async function firstLibrary(request: APIRequestContext, token: string): Promise<string> {
  const auth = { Authorization: `Bearer ${token}` };
  const workspaces = await request.get('/api/v1/workspaces', { headers: auth });
  const wsBody = (await workspaces.json()) as { items: { id: string }[] };
  const workspace = wsBody.items[0];
  expect(workspace, 'the tenant has no workspaces').toBeDefined();
  const libraries = await request.get(`/api/v1/workspaces/${workspace?.id}/libraries`, {
    headers: auth,
  });
  const libBody = (await libraries.json()) as { items: { id: string }[] };
  const library = libBody.items[0];
  expect(library, 'the workspace has no libraries').toBeDefined();
  return library?.id as string;
}

async function createFolder(
  request: APIRequestContext,
  token: string,
  library: string,
  name: string,
): Promise<string> {
  const response = await request.post(`/api/v1/libraries/${library}/folders`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { name },
  });
  expect(response.ok(), `folder creation failed: ${response.status()}`).toBe(true);
  const body = (await response.json()) as { id: string };
  return body.id;
}

/* Generous: a real ClamAV scan, through the worker's poll interval. */
test.setTimeout(180_000);

test('a file picked in the browser is stored, scanned and listed', async ({ page, request }) => {
  await signIn(page);

  /* Into a folder created for this run, and the reason is not tidiness.
   *
   * The seeded library holds more rows than one page, and `GET
   * /libraries/{id}/items` answers fifty with `hasMore: true` — which the
   * client parses and **no client code reads** (`ENC-973`). A newly uploaded
   * file sorts to the end and is therefore not in the page at all, so asserting
   * on the library root would be asserting against a defect that has nothing to
   * do with uploading. An empty folder isolates this test to the thing it is
   * about; `ENC-973` is where the ceiling itself is answered.
   *
   * Created over HTTP rather than through the UI because folder creation is not
   * what is being proved here, and a second unproved path in the arrangement is
   * a second way for this test to fail for the wrong reason. */
  const token = await accessToken(request);
  const library = await firstLibrary(request, token);
  const folder = await createFolder(request, token, library, `upload-e2e-${Date.now()}`);

  await page.goto(`/library?library=${library}&folder=${folder}`);
  await expect(page.locator('.library-list')).toBeVisible({ timeout: 30_000 });

  /* Wait for Upload to be *ready* before choosing anything.
   *
   * Not politeness — correctness. `useUploadTarget` is handed the server's
   * `capabilities.create`, and while `GET /libraries/{id}` is in flight that is
   * `false`, so `accept()` drops the files silently. The button says so — it
   * renders `busy`, not `denied`, because not knowing yet is not a refusal —
   * and a real user cannot click through it. A test that sets the hidden input
   * directly can, which is exactly what this one did on its first run: the
   * files went nowhere and the tray never opened.
   *
   * `exact`, because an empty folder also offers *Upload files* in its empty
   * state and the toolbar's *Upload* is a prefix of it. */
  /* `ready` renders *no* `data-state` — `Button` writes the attribute only for
   * the states it has something to say about — so this waits for `busy` to go,
   * rather than for a value to arrive. */
  await expect(
    page.getByRole('button', { name: catalog['library.upload'].message, exact: true }),
  ).not.toHaveAttribute('data-state', 'busy', { timeout: 30_000 });

  /* The real `<input type="file">` the Upload button clicks. Playwright sets
   * the FileList the way the browser would, so `useUploadTarget.accept` runs,
   * the store hashes the bytes, and the three real legs follow. */
  await page.locator('input[type="file"]').setInputFiles({
    name: NAME,
    mimeType: 'text/plain',
    buffer: Buffer.from(`enclave upload e2e ${NAME}\n`),
  });

  /* The tray opens by itself when something is queued. */
  const row = page.locator('.upl-row', { hasText: NAME });
  await expect(row).toBeVisible({ timeout: 30_000 });

  /* Ready, not merely uploaded — see the note above. Generous, because this
   * waits on a real ClamAV scan through the worker's poll interval. */
  await expect(row).toHaveAttribute('data-tone', 'ok', { timeout: 120_000 });

  /* And the file is in the library the browser was looking at. This is the leg
   * that makes the test about the product rather than about the tray: a
   * transfer that succeeds and never appears is what an upload feature failing
   * quietly looks like. */
  await expect(page.locator('[role="row"]', { hasText: NAME })).toBeVisible({ timeout: 60_000 });
});
