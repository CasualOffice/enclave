import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * An administrator writes a retention policy, applies it, and it refuses a delete.
 *
 * `ENC-945`. `ENC-940` built the stage that refuses a governed delete and
 * `ENC-943` built the four endpoints that configure one; **neither was reachable
 * from the product**, which is the failure this repository keeps producing and
 * the reason this test drives the screen rather than the API.
 *
 * The policy is written and applied **by clicking**, and the proof that it
 * worked is taken over HTTP — a `DELETE` that the chain must now refuse. That
 * split is deliberate and is the whole design of the test:
 *
 * * Writing through the API and asserting the screen renders it would pass
 *   against a form that submits nothing.
 * * Writing through the form and asserting the screen shows it would pass
 *   against a client that stored the policy in React state and never called the
 *   server — the exact shape of `ENC-934`, where a screen looked right over a
 *   fixture.
 *
 * Only the round trip closes both: clicked in, and then proved by a refusal
 * that comes from the policy chain and could come from nowhere else.
 *
 * Cleanup withdraws the assignment, because a `TENANT`-scoped hold left behind
 * would refuse every delete in every other suite — including `trash.spec.ts`,
 * which is two files away and would fail for a reason nothing in it names.
 */

const Login = z.object({ accessToken: z.string().min(1) });
const Page = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const Folder = z.object({ id: z.string(), revision: z.number() });

async function token(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  return Login.parse(await response.json()).accessToken;
}

test('a policy written on the admin screen refuses a delete the chain would otherwise allow', async ({
  page,
  request,
}) => {
  const bearer = await token(request);
  const auth = { authorization: `Bearer ${bearer}` };
  const name = `E2E retention ${Date.now()}`;

  /* Somewhere to put a folder. Setup over HTTP: the subject is retention, not
   * workspace creation, which `workspaces.spec` would own. */
  const workspaces = await request.get('/api/v1/workspaces', { headers: auth });
  const workspaceId = Page.parse(await workspaces.json()).items[0]?.id;
  expect(workspaceId, 'the seeded tenant must have a workspace').toBeDefined();
  const libraries = await request.get(`/api/v1/workspaces/${workspaceId}/libraries`, {
    headers: auth,
  });
  const libraryId = Page.parse(await libraries.json()).items[0]?.id;
  expect(libraryId, 'the workspace must have a library').toBeDefined();

  await signIn(page);
  await page.goto('/admin?section=retention');

  await expect(page.getByRole('heading', { name: catalog['admin.retention.title'].message })).toBeVisible({
    timeout: 30_000,
  });

  // --- write the policy, entirely through the form -------------------------
  await page.getByRole('button', { name: catalog['admin.retention.new'].message }).click();
  await page.getByLabel(catalog['admin.retention.form.name'].message).fill(name);
  /* KEEP, and the option text is the server's stored spelling rather than a
   * translated one — the vocabulary arrives on the wire (`ENC-943`) precisely
   * so this list cannot drift from `migrations/0031`. */
  await page.getByLabel(catalog['admin.retention.form.action'].message).selectOption('KEEP');
  await page.getByRole('button', { name: catalog['admin.retention.form.save'].message }).click();

  const card = page.locator('.adm-retcard', { hasText: name });
  await expect(card).toBeVisible({ timeout: 30_000 });
  /* Written and applied nowhere: the screen must say so, because a policy that
   * governs nothing reads as an active control until somebody notices. */
  await expect(card).toContainText(catalog['admin.retention.noScopes'].message);

  // --- apply it to the workspace, through the picker ------------------------
  await card.getByLabel(catalog['admin.retention.applyTo'].message).selectOption('WORKSPACE');
  await card
    .getByLabel(catalog['admin.retention.scope.workspacePicker'].message)
    .selectOption(workspaceId as string);
  await card.getByRole('button', { name: catalog['admin.retention.apply'].message }).click();
  await expect(card.getByText(catalog['admin.retention.live'].message)).toBeVisible({
    timeout: 30_000,
  });

  // --- the proof: a delete the chain now refuses ----------------------------
  const created = await request.post(`/api/v1/libraries/${libraryId}/folders`, {
    headers: auth,
    data: { name: `governed-${Date.now()}` },
  });
  expect(created.ok(), `folder creation answered ${created.status()}`).toBe(true);
  const folder = Folder.parse(await created.json());

  const refused = await request.delete(`/api/v1/files/${folder.id}`, {
    headers: { ...auth, 'if-match': `"${folder.revision}"` },
  });
  expect(
    refused.status(),
    'the folder was deleted; the policy written on the screen never reached the chain',
  ).toBe(403);
  expect(await refused.text()).toContain('RETENTION_BLOCKS_DELETE');

  // --- withdraw, through the screen, and the same delete succeeds -----------
  await card.getByRole('button', { name: catalog['admin.retention.withdraw'].message }).click();
  await expect(card.getByText(catalog['admin.retention.withdrawn'].message)).toBeVisible({
    timeout: 30_000,
  });

  const allowed = await request.delete(`/api/v1/files/${folder.id}`, {
    headers: { ...auth, 'if-match': `"${folder.revision}"` },
  });
  expect(
    allowed.ok(),
    `the delete was still refused after withdrawal: ${allowed.status()} ${await allowed.text()}`,
  ).toBe(true);
});
