import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * A file deleted through the product can be found again and put back.
 *
 * `ENC-939`. `ENC-807` shipped `DELETE /files/{id}` and `POST
 * /files/{id}/restore` and nothing that listed the bin, so the nav carried
 * `Trash` as `unbuilt` — a screen that could not be written, because the
 * endpoint it needed did not exist until `ENC-938`.
 *
 * The round trip is driven entirely through the interface: the file is deleted
 * over HTTP, found on the screen, and restored **by clicking the button on its
 * row**. Nothing here calls `POST /restore` directly, because the thing under
 * test is whether the listing carries what the restore needs — a screen that
 * rendered every row correctly and sent the wrong revision would pass a test
 * that restored out of band, and would fail every real person.
 */

const Login = z.object({ accessToken: z.string().min(1) });
const Page = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const Items = z.object({
  items: z.array(z.object({ id: z.string(), name: z.string(), type: z.string(), revision: z.number() })),
  page: z.object({ nextCursor: z.string().nullish(), hasMore: z.boolean() }),
});

async function token(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  return Login.parse(await response.json()).accessToken;
}

async function get<T>(
  request: APIRequestContext,
  path: string,
  schema: z.ZodType<T>,
  bearer: string,
): Promise<T> {
  const response = await request.get(path, { headers: { authorization: `Bearer ${bearer}` } });
  expect(response.ok(), `${path} answered ${response.status()}`).toBe(true);
  return schema.parse(await response.json());
}


/** Whether the library holds this id, following the cursor to the end. */
async function libraryHolds(
  request: APIRequestContext,
  bearer: string,
  library: string,
  id: string,
): Promise<boolean> {
  let cursor: string | undefined;
  /* Bounded, because an unterminated cursor loop in a test is a hang rather
   * than a failure. Fifty pages is far more than any seed and still finite. */
  for (let page = 0; page < 50; page += 1) {
    const query = cursor === undefined ? '' : `?cursor=${encodeURIComponent(cursor)}`;
    const answer = await get(request, `/api/v1/libraries/${library}/items${query}`, Items, bearer);
    if (answer.items.some((item) => item.id === id)) return true;
    if (!answer.page.hasMore) return false;
    cursor = answer.page.nextCursor ?? undefined;
    if (cursor === undefined) return false;
  }
  throw new Error('the listing did not terminate within fifty pages');
}

test('a file deleted over HTTP is found in Trash and restored from its own row', async ({
  page,
  request,
}) => {
  const bearer = await token(request);

  const workspaces = await get(request, '/api/v1/workspaces', Page, bearer);
  expect(workspaces.items[0], 'the tenant has no workspace').toBeDefined();
  const libraries = await get(
    request,
    `/api/v1/workspaces/${workspaces.items[0]?.id ?? ''}/libraries`,
    Page,
    bearer,
  );
  expect(libraries.items[0], 'the workspace has no library').toBeDefined();
  const library = libraries.items[0]?.id ?? '';
  /* A folder this test creates, rather than whatever the library happens to
   * hold. Two reasons, and the second is the one that bit: deleting a fixture
   * would disturb the specs that assert on it, and *finding* one couples this
   * test to which workspace sorts first — `workspaces.items[0]` is a different
   * library on a machine that has provisioned more than one, and this test
   * failed exactly that way before it created its own subject.
   *
   * A folder rather than an upload because it is a row in `files` like any
   * other, so it exercises the same delete, the same bin and the same restore
   * without needing the worker or antivirus. */
  const stamp = `trash-e2e-${String(Date.now())}`;
  const made = await request.post(`/api/v1/libraries/${library}/folders`, {
    headers: { authorization: `Bearer ${bearer}` },
    data: { name: stamp },
  });
  expect(made.ok(), `could not create the folder to delete: ${made.status()}`).toBe(true);
  const victim = z
    .object({ id: z.string(), name: z.string(), revision: z.number() })
    .parse(await made.json());
  const id = victim.id;
  const name = victim.name;

  const deleted = await request.delete(`/api/v1/files/${id}`, {
    headers: { authorization: `Bearer ${bearer}`, 'if-match': `"${victim.revision}"` },
  });
  expect(deleted.ok(), `the delete this test is about answered ${deleted.status()}`).toBe(true);

  await signIn(page);
  await page.goto('/trash');

  /* The nav entry is a real link now, not a `Later` chip. Asserted because that
   * is half of what this item changed: a person has to be able to get here. */
  await expect(
    page.getByRole('link', { name: catalog['nav.trash'].message }).or(
      page.getByRole('button', { name: catalog['nav.trash'].message }),
    ),
  ).toHaveCount(1);

  const row = page.locator('.trash-row').filter({ hasText: name });
  await expect(row, `the folder just deleted is not in the bin`).toHaveCount(1);

  /* Restored by pressing the button, using whatever revision the row itself
   * carried. This is the assertion the endpoint's `revision` field exists for. */
  await row.getByRole('button', { name: catalog['trash.restore'].message }).click();

  await expect(row, 'a restored file must leave the bin').toHaveCount(0);
  await expect(page.getByText(catalog['trash.restore.failed'].message)).toHaveCount(0);

  /* And it is genuinely back, read from the server rather than from the screen
   * that just claimed it.
   *
   * **Every page of it** (`ENC-973`). This asked for one page and treated it as
   * the library, which held only while the seeded library fitted inside fifty
   * rows. Past that the restored file sorted to the end, this reported *"the row
   * left the bin but the file is not back in its library"*, and the sentence was
   * false: the restore had worked and the assertion was looking at the wrong
   * fifty. A paged endpoint has to be read to the end before an absence means
   * anything. */
  expect(
    await libraryHolds(request, bearer, library, id),
    'the row left the bin but the file is not back in its library',
  ).toBe(true);
});

test('an empty bin says which nothing it is', async ({ page, request }) => {
  const bearer = await token(request);
  const bin = await get(
    request,
    '/api/v1/trash',
    z.object({ items: z.array(z.unknown()), filteredCount: z.number() }),
    bearer,
  );

  await signIn(page);
  await page.goto('/trash');

  /* Which branch runs depends on what this deployment has deleted, so both are
   * asserted rather than one assumed — a test that only ever met the empty case
   * would stay green against a client that had deleted the filtered one. */
  if (bin.items.length === 0) {
    const expected =
      bin.filteredCount > 0
        ? catalog['trash.filtered.heading'].message
        : catalog['trash.empty.heading'].message;
    await expect(page.getByText(expected)).toBeVisible();
  } else {
    await expect(page.locator('.trash-row').first()).toBeVisible();
    await expect(page.getByText(catalog['trash.empty.heading'].message)).toHaveCount(0);
  }
});
