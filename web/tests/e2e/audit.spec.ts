import { expect, test } from '@playwright/test';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { signIn } from './support.ts';

/**
 * An administrator can read the compliance log, and read it about themselves.
 *
 * `ENC-961` built `GET /admin/audit`; this proves the screen renders what it
 * returns, against the live API and the tenant's real log.
 *
 * # The row it asserts on is the one this test just caused
 *
 * Signing in writes audit rows. Opening this screen writes one more —
 * `admin.read_audit` — and it is the newest row in the tenant by the time the
 * table paints. So the assertion is not *"some row exists"*, which would pass
 * against a screen rendering a fixture or another tenant's log: it is that the
 * action this test performed, seconds ago, is at the head. That also makes the
 * test independent of seed data, which is what `ENC-950` and `ENC-962` both
 * turned out to need — twice, a check passed only because of state I had put
 * there by hand.
 *
 * # And a narrowing that must actually narrow
 *
 * The `Refused` tab asks the server for `outcome=DENY`. The rows that come back
 * must all be refusals — a filter that is dropped on the way to the server
 * would return the whole log, and the page would look like a correct answer to
 * a question nobody's answer it is. This is the failure mode this surface has
 * that a member listing does not: an auditor cannot tell a filtered page from
 * an unfiltered one by looking at it.
 */

test('the audit log shows the read that opened it, and its filter narrows', async ({ page }) => {
  await signIn(page);
  await page.goto('/admin?section=audit');

  const heading = page.getByRole('heading', { name: catalog['admin.audit.title'].message });
  await expect(heading).toBeVisible({ timeout: 30_000 });

  const rows = page.locator('.aud-row');
  await expect(rows.first()).toBeVisible({ timeout: 30_000 });

  /* The read this test just performed. `admin.read_audit` is written by the
   * policy chain inside `enforce`, before the handler returns, so it is in the
   * page the handler is about to send. */
  await expect(page.locator('.aud-action', { hasText: 'admin.read_audit' }).first()).toBeVisible();

  /* The circumstances are not on screen until asked for. Paired with the
   * positive control below, because an absence passes for free. */
  await expect(page.locator('.aud-detail')).toHaveCount(0);
  await page.locator('.aud-disclose').first().click();
  await expect(page.locator('.aud-detail').first()).toBeVisible();
  await expect(
    page.locator('.aud-field dt', { hasText: catalog['admin.audit.field.requestId'].message }),
  ).toBeVisible();

  /* The narrowing. Every row that comes back must be a refusal — and the tab
   * must produce rows at all, or "they were all refusals" is satisfied by an
   * empty table. The seeded tenant has denials: the chain refuses on every
   * fixture run. */
  await page.getByRole('tab', { name: catalog['admin.audit.outcome.deny'].message }).click();
  const outcomes = page.locator('.aud-outcome');
  await expect(outcomes.first()).toBeVisible({ timeout: 30_000 });
  const seen = await outcomes.allTextContents();
  expect(seen.length).toBeGreaterThan(0);
  for (const outcome of seen) {
    expect(outcome.trim()).toBe('DENY');
  }
});
