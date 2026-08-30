import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * A file shared with somebody appears on their *Shared with me* screen.
 *
 * `ENC-955`. `acl_entries` has had a writer since `ENC-916` and nothing had ever
 * listed what a person was *given*, so a colleague could share a document
 * outside any workspace this user belongs to and the recipient had no way to
 * find it. `ENC-954` built the endpoint; this proves the screen renders what it
 * returns, against the live API.
 *
 * # The share is made through the product, not through SQL
 *
 * `PUT /files/{id}/permissions` is the real grant path, and it runs the whole
 * chain. Writing the ACL row directly would prove this screen can render a row
 * somebody put in a table — which is a weaker claim, and would pass against a
 * product where sharing itself was broken.
 *
 * It also walks the **second deliberate act** `FOUNDING_GRANT` requires: a
 * workspace founder deliberately does not hold `file.manage_permissions`
 * (`crates/api/src/routes/workspaces.rs`, rule 6), so the grant is made through
 * the library ACL first. A test that skipped that would be asserting a
 * permission model this product does not have.
 *
 * # And the negative is in the same run
 *
 * The sharer's own list must **not** contain the file. Without that, "the row
 * appeared" is satisfied by a screen that lists every file in the tenant — and
 * the whole definition of a share is that it is something somebody *else* gave
 * you.
 */

const Login = z.object({ accessToken: z.string().min(1) });
const Page = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const Node = z.object({ id: z.string() });
const Me = z.object({ id: z.string() });

async function token(request: APIRequestContext, email: string): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed for ${email}: ${response.status()}`).toBe(true);
  return Login.parse(await response.json()).accessToken;
}

test('a folder shared through the product appears on the recipient’s Shared with me', async ({
  page,
  request,
}) => {
  const bearer = await token(request, EMAIL);
  const auth = { authorization: `Bearer ${bearer}` };
  const name = `E2E share ${Date.now()}`;

  const me = Me.parse(await (await request.get('/api/v1/me', { headers: auth })).json());

  const workspaces = await request.get('/api/v1/workspaces', { headers: auth });
  const workspaceId = Page.parse(await workspaces.json()).items[0]?.id;
  expect(workspaceId, 'the seeded tenant must have a workspace').toBeDefined();
  const libraries = await request.get(`/api/v1/workspaces/${workspaceId}/libraries`, {
    headers: auth,
  });
  const libraryId = Page.parse(await libraries.json()).items[0]?.id;
  expect(libraryId, 'the workspace must have a library').toBeDefined();

  // The second deliberate act. Without it the grant below is a 404 — which is
  // the designed behaviour, not a bug (rule 6).
  const lift = await request.put(`/api/v1/libraries/${libraryId}/permissions`, {
    headers: auth,
    data: {
      entries: [
        {
          principal: { kind: 'USER', id: me.id },
          action: 'file.manage_permissions',
          effect: 'ALLOW',
        },
      ],
    },
  });
  expect(lift.ok(), `lifting file.manage_permissions answered ${lift.status()}`).toBe(true);

  const created = await request.post(`/api/v1/libraries/${libraryId}/folders`, {
    headers: auth,
    data: { name },
  });
  expect(created.ok(), `folder creation answered ${created.status()}`).toBe(true);
  const folder = Node.parse(await created.json());

  // The recipient. Seeded, and given a password by the CI step beside the
  // admin one — `seed` writes users and never a credential (`ENC-931`), which
  // is why this test went red on `main` the moment it merged: it was verified
  // locally against a password set by hand.
  const recipient = 'member@tenant-alpha.example';
  const recipientId = await (async () => {
    const response = await request.post('/api/v1/auth/login', {
      data: { email: recipient, password: PASSWORD },
    });
    expect(
      response.ok(),
      `the recipient (${recipient}) could not sign in: ${response.status()}. \`seed\` writes ` +
        'users and never a credential (ENC-931), so this account answers 401 until something sets ' +
        'its password — the CI step does, beside the admin one. A local run needs ' +
        '`enclave-cli set-password --tenant tenant-alpha --email member@tenant-alpha.example`.',
    ).toBe(true);
    const theirToken = Login.parse(await response.json()).accessToken;
    const who = await request.get('/api/v1/me', {
      headers: { authorization: `Bearer ${theirToken}` },
    });
    return Me.parse(await who.json()).id;
  })();

  const grant = await request.put(`/api/v1/files/${folder.id}/permissions`, {
    headers: auth,
    data: {
      entries: [
        {
          principal: { kind: 'USER', id: recipientId },
          action: 'file.metadata_read',
          effect: 'ALLOW',
        },
      ],
    },
  });
  expect(grant.ok(), `the share answered ${grant.status()}: ${await grant.text()}`).toBe(true);

  // --- the sharer's own list must not contain it ----------------------------
  await signIn(page);
  await page.goto('/shared');
  await expect(page.getByRole('heading', { name: catalog['shared.title'].message })).toBeVisible({
    timeout: 30_000,
  });
  await expect(
    page.getByText(name, { exact: false }),
    'the sharer must not see their own file here: a share is something somebody else gave you',
  ).toHaveCount(0);

  // --- the recipient's does -------------------------------------------------
  await page.context().clearCookies();
  await page.goto('/');
  await expect(page.locator('[data-signin-state]')).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(catalog['auth.email.label'].message).fill(recipient);
  await page.getByLabel(catalog['auth.password.label'].message).fill(PASSWORD);
  await page.getByRole('button', { name: catalog['auth.submit'].message }).click();
  await expect(page.locator('.shell')).toBeVisible({ timeout: 30_000 });

  await page.goto('/shared');
  await expect(
    page.getByText(name, { exact: false }),
    'the recipient must find the folder that was shared with them; before ENC-954 there was no ' +
      'listing at all and the grant was undiscoverable',
  ).toBeVisible({ timeout: 30_000 });
});
