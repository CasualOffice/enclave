import { expect, test } from '@playwright/test';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { signIn } from './support.ts';

/**
 * The account control opens a menu; it does not end the session.
 *
 * `ENC-927`. The foot of the sidebar was a single `<Row>` carrying
 * `onClick={signOut}` and an `aria-label` of "Sign out". Nothing visible said
 * so — it showed an avatar and a name, which is the shape of an account menu in
 * every product a person has used — and the Administration nav item sits
 * directly above it. It was found by a report of *"clicking admin logs me out"*,
 * which is what it looks like from the outside.
 *
 * The `aria-label` was not a mitigation. It told a screen reader the truth and
 * everyone else nothing, which is the inverse of what an accessible name does:
 * it names a control whose purpose is already visible, it does not supply a
 * purpose the control declines to show.
 *
 * These live in the **e2e** suite rather than beside the other a11y specs, and
 * that is itself the finding. `app.tsx` renders `<Shell>` only inside
 * `ViewerProvider`, which needs a session, which needs the API — so the fixture
 * preview the a11y suite runs against never renders the shell at all. The
 * sidebar, this menu, the theme toggle and the upload tray have therefore never
 * been covered by any test, which is how a control that ends the session on a
 * single click survived in the one place every signed-in person looks.
 */
test('the account control announces that it opens a menu, rather than that it acts', async ({
  page,
}) => {
  await signIn(page);
  const account = page.getByRole('button', { name: catalog['nav.account'].message, exact: true });
  await expect(account).toBeVisible();

  /* The two attributes that make it honest. Without `aria-haspopup` this is a
   * button that claims to do something, which is what it used to be. */
  await expect(account).toHaveAttribute('aria-haspopup', 'menu');
  await expect(account).toHaveAttribute('aria-expanded', 'false');

  /* The positive control, and the assertion that fails if the old row comes
   * back: there must be no control named "Sign out" until the menu is open.
   * Without this the test passes against a sidebar that has both. */
  await expect(page.getByRole('button', { name: catalog['nav.signOut'].message })).toHaveCount(0);
});

test('opening it reveals sign out, and Escape closes it without signing out', async ({ page }) => {
  await signIn(page);
  const account = page.getByRole('button', { name: catalog['nav.account'].message, exact: true });

  await account.click();
  await expect(account).toHaveAttribute('aria-expanded', 'true');
  const signOut = page.getByRole('menuitem', { name: catalog['nav.signOut'].message });
  await expect(signOut).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(account).toHaveAttribute('aria-expanded', 'false');
  await expect(signOut).toHaveCount(0);

  /* Still on the app, not on the sign-in screen. This is the whole point: a
   * person who opened the menu to look at it is where they started. */
  await expect(account).toBeVisible();
});

test('a click outside closes the menu', async ({ page }) => {
  await signIn(page);
  const account = page.getByRole('button', { name: catalog['nav.account'].message, exact: true });

  await account.click();
  await expect(account).toHaveAttribute('aria-expanded', 'true');

  /* The main region, which is as far from the menu as this page gets. */
  await page.locator('main').first().click({ position: { x: 10, y: 10 } });
  await expect(account).toHaveAttribute('aria-expanded', 'false');
  await expect(account).toBeVisible();
});
