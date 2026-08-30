import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * A library larger than one page can be read to the end (`ENC-973`).
 *
 * # What this is really testing
 *
 * `GET /libraries/{id}/items` has answered fifty rows with `hasMore: true` and
 * a `nextCursor` since it was written, `entities/file/api-model.ts` has parsed
 * both since it was written, and **no code in `web/src` read either**. So a
 * library with more than fifty files showed fifty, in the server's order, with
 * nothing on screen saying anything was missing — a ceiling a real team reaches
 * in its second week.
 *
 * Nothing caught it because nothing had ever *scrolled*. The unit suites hold
 * their own fixtures, and every e2e that touched the listing looked at the top
 * of it.
 *
 * # It asserts on a row the first page cannot contain
 *
 * The target name is read from page **two**, over HTTP, at run time — not a
 * literal, and not something the first request returned. If the client still
 * asked once and kept the answer, this row does not exist on the client at any
 * scroll position, and no amount of waiting produces it.
 *
 * Skipped, not failed, when the seeded library fits in one page: the assertion
 * would then be about nothing, and a test that silently proves nothing is worse
 * than one that says why it stood down.
 */

const Items = z.object({
  items: z.array(z.object({ id: z.string(), name: z.string() })),
  page: z.object({ nextCursor: z.string().nullish(), hasMore: z.boolean() }),
});

async function token(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  const body = (await response.json()) as { accessToken?: string };
  expect(body.accessToken, 'no access token').toBeTruthy();
  return body.accessToken as string;
}

async function get(request: APIRequestContext, path: string, bearer: string) {
  const response = await request.get(path, { headers: { authorization: `Bearer ${bearer}` } });
  expect(response.ok(), `${path} answered ${response.status()}`).toBe(true);
  return Items.parse(await response.json());
}

test('a library longer than one page keeps going when you scroll', async ({ page, request }) => {
  const bearer = await token(request);
  const workspaces = (await request.get('/api/v1/workspaces', {
    headers: { authorization: `Bearer ${bearer}` },
  }).then((r) => r.json())) as { items: { id: string }[] };
  const workspace = workspaces.items[0];
  expect(workspace, 'the tenant has no workspaces').toBeDefined();
  const libraries = (await request.get(`/api/v1/workspaces/${workspace?.id}/libraries`, {
    headers: { authorization: `Bearer ${bearer}` },
  }).then((r) => r.json())) as { items: { id: string; name: string }[] };
  const library = libraries.items[0];
  expect(library, 'the workspace has no libraries').toBeDefined();

  const first = await get(request, `/api/v1/libraries/${library?.id}/items`, bearer);
  test.skip(
    !first.page.hasMore,
    'the seeded library fits in one page, so there is no second page to reach',
  );
  const cursor = first.page.nextCursor;
  expect(cursor, 'hasMore was true and no cursor came with it').toBeTruthy();

  const second = await get(
    request,
    `/api/v1/libraries/${library?.id}/items?cursor=${encodeURIComponent(cursor as string)}`,
    bearer,
  );
  const target = second.items[0];
  expect(target, 'the second page came back empty').toBeDefined();
  /* Not on page one — the property the whole test rests on. */
  expect(first.items.some((item) => item.id === target?.id)).toBe(false);

  await signIn(page);
  await page.goto(`/library?library=${library?.id}`);
  const scroller = page.locator('.egl-scroller');
  await expect(scroller).toBeVisible({ timeout: 30_000 });

  const row = page.locator('.egl-name-text', { hasText: target?.name ?? '' });

  /* Scroll to the end repeatedly. One jump is not enough and should not be:
   * reaching the bottom fetches a page, which makes the list taller, which is
   * the next bottom. Repeating until the row appears is what a reader does. */
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if ((await row.count()) > 0) break;
    await scroller.evaluate((node) => {
      node.scrollTop = node.scrollHeight;
    });
    await page.waitForTimeout(200);
  }

  await expect(
    row.first(),
    'a row from the second page never appeared, however far the list was scrolled',
  ).toBeVisible({ timeout: 15_000 });
});
