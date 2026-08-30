import { expect, test, type APIRequestContext } from '@playwright/test';
import { z } from 'zod';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { EMAIL, PASSWORD, signIn } from './support.ts';

/**
 * A task on Home can be approved, and the workflow completes.
 *
 * `ENC-968`. Home has listed tasks since `ENC-739` with its actions rendered
 * `unbuilt` — a task could be *seen* and not acted on. The endpoints always
 * worked; what was missing until `ENC-965` was any way to author a definition,
 * so no task could exist to act on and the chip was honest.
 *
 * The approval is made **by clicking the button on the row**, and the proof is
 * taken over HTTP: the instance must read `COMPLETED`. Either half alone would
 * pass against a broken product — approving over HTTP and checking the screen
 * would pass against a button wired to nothing, and clicking and checking the
 * screen would pass against a client that removed the row locally.
 *
 * The definition sets `allowSelfApproval` because one account both starts the
 * instance and holds the step. That is not a workaround: `ENC-967` was an hour
 * spent misreading the refusal it produces, and stating it here is cheaper than
 * the next person repeating that.
 */

const Login = z.object({ accessToken: z.string().min(1) });
const Page = z.object({ items: z.array(z.object({ id: z.string(), name: z.string() })) });
const Created = z.object({ id: z.string() });
const Me = z.object({ id: z.string() });
const Instance = z.object({ state: z.string() });

async function token(request: APIRequestContext): Promise<string> {
  const response = await request.post('/api/v1/auth/login', {
    data: { email: EMAIL, password: PASSWORD },
  });
  expect(response.ok(), `sign-in failed: ${response.status()}`).toBe(true);
  return Login.parse(await response.json()).accessToken;
}

test('a task on Home is approved by pressing the button, and the workflow completes', async ({
  page,
  request,
}) => {
  const bearer = await token(request);
  const auth = { authorization: `Bearer ${bearer}` };
  const me = Me.parse(await (await request.get('/api/v1/me', { headers: auth })).json());

  const definition = await request.post('/api/v1/workflows/definitions', {
    headers: auth,
    data: {
      name: `E2E decision ${Date.now()}`,
      scopeType: 'TENANT',
      allowSelfApproval: true,
      definition: {
        stages: [{ name: 'Legal', steps: [{ type: 'APPROVAL', assignees: [me.id] }] }],
      },
    },
  });
  expect(
    definition.ok(),
    `writing a definition answered ${definition.status()}: before ENC-965 this endpoint did not ` +
      'exist and no task could ever exist either',
  ).toBe(true);
  const definitionId = Created.parse(await definition.json()).id;

  // A file with a committed version: a workflow starts on content, and a folder
  // has no version to approve.
  const workspaces = await request.get('/api/v1/workspaces', { headers: auth });
  const workspaceId = Page.parse(await workspaces.json()).items[0]?.id;
  const libraries = await request.get(`/api/v1/workspaces/${workspaceId}/libraries`, {
    headers: auth,
  });
  const libraryId = Page.parse(await libraries.json()).items[0]?.id;
  const items = await request.get(`/api/v1/libraries/${libraryId}/items`, { headers: auth });
  const file = z
    .object({ items: z.array(z.object({ id: z.string(), nodeType: z.string() })) })
    .parse(await items.json())
    .items.find((row) => row.nodeType === 'FILE');
  expect(file, 'the seeded library must hold a file to run a workflow against').toBeDefined();

  const started = await request.post(`/api/v1/files/${file?.id}/workflows`, {
    headers: auth,
    data: { definitionId },
  });
  expect(started.ok(), `starting answered ${started.status()}: ${await started.text()}`).toBe(true);
  const instanceId = Created.parse(await started.json()).id;

  // --- approve by pressing the button --------------------------------------
  await signIn(page);
  await page.goto('/');
  const card = page.locator('.home-card').filter({ hasText: 'Legal' }).first();
  await expect(
    card,
    'the started workflow must appear under Needs your attention',
  ).toBeVisible({ timeout: 30_000 });

  await card.getByRole('button', { name: catalog['home.attention.action.approve'].message }).click();

  // --- and the server agrees -----------------------------------------------
  await expect
    .poll(
      async () => {
        const response = await request.get(`/api/v1/workflows/instances/${instanceId}`, {
          headers: auth,
        });
        return Instance.parse(await response.json()).state;
      },
      {
        message:
          'the instance did not complete. The button is not optimistic, so the row leaving the ' +
          'screen would not prove this — only the server does',
        timeout: 30_000,
      },
    )
    .toBe('COMPLETED');
});
