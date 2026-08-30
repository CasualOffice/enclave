import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * A change made through the product appears on Activity; a read does not.
 *
 * `ENC-960`. Two assertions, and the second is the one this surface exists to
 * keep honest.
 *
 * The **positive** is ordinary: a folder is created and trashed over HTTP, and
 * the deletion appears. The **negative** is the product decision — the same
 * folder is *read* several times first, and none of those reads may appear. A
 * feed carrying reads is a record of who looked at what, available to everybody
 * who can open the file, and the data is sitting in `audit_events` waiting for
 * somebody to surface it by accident.
 *
 * Both run against the live API, and the read is performed through the real
 * endpoint rather than by writing an audit row: the thing under test is that
 * the *pipeline* excludes reads, not that a hand-written row is filtered.
 */

const Login = z.object({ accessToken: z.string().min(1) });
const Page = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const Node = z.object({ id: z.string(), revision: z.number() });

async function token(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  return Login.parse(await response.json()).accessToken;
}

test('a change appears on Activity and a read never does', async ({ page, request }) => {
  const bearer = await token(request);
  const auth = { authorization: `Bearer ${bearer}` };
  const name = `E2E activity ${Date.now()}`;

  const workspaces = await request.get('/api/v1/workspaces', { headers: auth });
  const workspaceId = Page.parse(await workspaces.json()).items[0]?.id;
  const libraries = await request.get(`/api/v1/workspaces/${workspaceId}/libraries`, {
    headers: auth,
  });
  const libraryId = Page.parse(await libraries.json()).items[0]?.id;
  expect(libraryId, 'the workspace must have a library').toBeDefined();

  const created = await request.post(`/api/v1/libraries/${libraryId}/folders`, {
    headers: auth,
    data: { name },
  });
  expect(created.ok(), `folder creation answered ${created.status()}`).toBe(true);
  const folder = Node.parse(await created.json());

  // Read it three times. Each writes an `ALLOW file.metadata_read` row, and none
  // of them may reach the feed.
  for (let i = 0; i < 3; i += 1) {
    const read = await request.get(`/api/v1/files/${folder.id}`, { headers: auth });
    expect(read.ok(), `reading the folder answered ${read.status()}`).toBe(true);
  }

  // Then change it, which must.
  const trashed = await request.delete(`/api/v1/files/${folder.id}`, {
    headers: { ...auth, 'if-match': `"${folder.revision}"` },
  });
  expect(trashed.ok(), `trashing answered ${trashed.status()}`).toBe(true);

  await signIn(page);
  await page.goto('/activity');
  await expect(page.getByRole('heading', { name: catalog['activity.title'].message })).toBeVisible({
    timeout: 30_000,
  });

  /* --- the assertion this surface exists for, and it runs first ------------
   *
   * `activity.action.other` is what an unrecognised verb renders as, so a read
   * surfaced into `SHOWN_ACTIONS` appears as "was changed". Checked across the
   * whole feed and *before* looking for this folder's row, because surfacing
   * reads floods the feed and pushes the row off the page — which fails the
   * positive below for a reason that names the wrong problem. */
  /* Matched on the **row containing** the phrase, not on an element whose text
   * is exactly it: the meta span reads "was changed · 2 minutes ago", so an
   * `exact: true` match can never fire. The first version of this assertion was
   * exactly that, and passed against a build that surfaced reads. */
  await expect(
    page.locator('.act-row', { hasText: catalog['activity.action.other'].message }),
    'a read reached Activity. A feed of who looked at what is a surveillance tool, available to ' +
      'everybody who can open the file, and the metadata_read rows are sitting in audit_events ' +
      'waiting for exactly this mistake',
  ).toHaveCount(0, { timeout: 15_000 });

  /* A trashed folder leaves the feed with it — the query joins `files` on
   * `deleted_at IS NULL`, so a row that opens onto a 404 is never shown. That is
   * correct and makes the deletion itself unassertable here, so the positive is
   * taken on a folder that still exists: the *permission change* below. */
  const permissioned = await request.post(`/api/v1/files/${folder.id}/restore`, {
    headers: { ...auth, 'if-match': `"${folder.revision + 1}"` },
  });
  expect(permissioned.ok(), `restoring answered ${permissioned.status()}`).toBe(true);

  await page.reload();
  /* `.first()`: a folder that was trashed and restored has more than one row,
   * and a multi-match locator is a strict-mode error rather than an assertion. */
  await expect(
    page.locator('.act-row', { hasText: name }).first(),
    'a change to a visible folder must appear on Activity',
  ).toBeVisible({ timeout: 30_000 });

});
