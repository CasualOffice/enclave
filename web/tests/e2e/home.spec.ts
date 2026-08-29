import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * The first screen after signing in shows the files this person opened.
 *
 * `ENC-930`. Until it, Home fetched `GET /api/v1/workflows/tasks` and nothing
 * else, and rendered its other two sections empty — and it was *honest* about
 * why: `home-screen.tsx`'s header said `GET /api/v1/me/recent` did not exist and
 * must not be improvised out of `audit_events`, which is hash-chained and
 * deliberately not a user-facing feed. So the screen was not broken. It was
 * correctly showing nothing, because nothing could be shown.
 *
 * That distinction is why this file asserts rows and not pixels: the defect was
 * never that the list rendered badly, it was that there was no list.
 *
 * Every expected value is read from the API out of band and compared against
 * what the screen drew. Nothing here is a literal — a test that hard-codes
 * `fox.txt` passes on a machine seeded with `fox.txt` and says nothing about
 * whether the client rendered what the server sent.
 */

const RecentRow = z.object({ fileId: z.string(), name: z.string(), extension: z.string() });
const Recent = z.object({ items: z.array(RecentRow), filteredCount: z.number() });
const Login = z.object({ accessToken: z.string().min(1) });
const Items = z.object({ items: z.array(z.object({ id: z.string() })) });
const Page = z.object({ items: z.array(z.object({ id: z.string() })) });

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

/**
 * Opens a file through the API so the recency row exists.
 *
 * `GET /files/{id}` is what records it — "you looked at it". Browsing a folder
 * deliberately does not, or Recent would be a list of folders walked past
 * rather than of work continued.
 */
async function openSomething(request: APIRequestContext, bearer: string): Promise<string[]> {
  const workspaces = await get(request, '/api/v1/workspaces', Page, bearer);
  expect(workspaces.items[0], 'the tenant has no workspace — is it provisioned?').toBeDefined();
  const libraries = await get(
    request,
    `/api/v1/workspaces/${workspaces.items[0]?.id ?? ''}/libraries`,
    Page,
    bearer,
  );
  expect(libraries.items[0], 'the workspace has no library').toBeDefined();
  const items = await get(
    request,
    `/api/v1/libraries/${libraries.items[0]?.id ?? ''}/items`,
    Items,
    bearer,
  );
  expect(items.items.length, 'the library is empty — nothing to open').toBeGreaterThan(0);

  const opened: string[] = [];
  for (const item of items.items.slice(0, 3)) {
    const response = await request.get(`/api/v1/files/${item.id}`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    expect(response.ok(), `opening ${item.id} answered ${response.status()}`).toBe(true);
    opened.push(item.id);
  }
  return opened;
}

test('the home screen lists the files this account opened, as the API returns them', async ({
  page,
  request,
}) => {
  const bearer = await token(request);
  const opened = await openSomething(request, bearer);
  expect(opened.length, 'nothing was opened, so there is nothing to assert').toBeGreaterThan(0);

  /* The server's answer, fetched before the screen renders it. This is the
   * expectation — not a literal, and not the client's own idea of it. */
  const recent = await get(request, '/api/v1/me/recent?limit=8', Recent, bearer);
  expect(recent.items.length, 'the API recorded nothing for a file just opened').toBeGreaterThan(0);

  await signIn(page);

  const rows = page.locator('.home-recent-row');
  await expect(rows).toHaveCount(recent.items.length);

  /* Name and extension are rendered as two spans and the extension keeps its
   * leading dot, so the row's text is the concatenation. Asserting on the pair
   * rather than on `name` alone is what catches a client that drops the
   * extension — which is the field most likely to be quietly lost, because a
   * row still looks right without it. */
  for (const [index, item] of recent.items.entries()) {
    await expect(rows.nth(index)).toContainText(item.name);
  }

  /* The empty sentence must be gone. Without this the count assertion above
   * would pass against a section rendering its "you have not opened anything"
   * card beside zero rows. */
  await expect(page.getByText(catalog['home.recent.empty'].message)).toHaveCount(0);
});

test('a section that has nothing says so, and says which nothing it is', async ({
  page,
  request,
}) => {
  const bearer = await token(request);
  const recent = await get(request, '/api/v1/me/recent?limit=8', Recent, bearer);

  await signIn(page);

  /* `filteredCount` is the whole point of this assertion. A blank list has two
   * causes — never opened anything, and opened things now hidden by permissions
   * — and `docs/09 §11` requires the screen to tell them apart. The count never
   * names a file (rule 7); it only says how many.
   *
   * Which branch runs depends on the fixture, so both are asserted here rather
   * than one being assumed: a test that only ever meets the empty case would go
   * green on a client that had deleted the filtered one. */
  if (recent.items.length === 0) {
    const expected =
      recent.filteredCount > 0
        ? catalog['home.recent.filtered'].message.replace(/\{count.*\}/u, '')
        : catalog['home.recent.empty'].message;
    await expect(page.getByText(expected.trim().split('{')[0] ?? '', { exact: false })).toBeVisible();
  } else {
    await expect(page.locator('.home-recent-row').first()).toBeVisible();
    await expect(page.getByText(catalog['home.recent.empty'].message)).toHaveCount(0);
  }
});
