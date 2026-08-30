import { expect, test } from '@playwright/test';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { signIn } from './support.ts';

/**
 * A file starred from the details panel appears on Favorites, and un-starring removes it.
 *
 * `ENC-959`. The round trip is driven **entirely through the interface**: the
 * star is clicked in the peek panel, the screen is navigated to, and the star on
 * the row is clicked to remove it. Nothing here calls the API directly, because
 * the thing under test is whether the two surfaces agree — a star written over
 * HTTP and a list read over HTTP would pass against a product where neither
 * control was wired to anything.
 *
 * # The empty state is asserted first, and it is not decoration
 *
 * It is the control. "The row appeared" is satisfied by a screen that renders
 * every file in the library, and by a list that was already populated from an
 * earlier run. Starting from empty makes the appearance mean something.
 */
test('a file starred from its details panel appears on Favorites and can be un-starred', async ({
  page,
}) => {
  await signIn(page);

  // --- the control: nothing starred yet ------------------------------------
  await page.goto('/favorites');
  await expect(page.getByRole('heading', { name: catalog['favorites.title'].message })).toBeVisible({
    timeout: 30_000,
  });
  const emptyHeading = page.getByText(catalog['favorites.empty.heading'].message);
  await expect(
    emptyHeading,
    'this test starts from an empty list, or the appearance it asserts proves nothing',
  ).toBeVisible({ timeout: 30_000 });

  // --- star the first file in the library, through its details panel -------
  //
  // `/library` opens the picker: the screen has no library until one is chosen,
  // and the id is a UUIDv7 that exists only in this database. Picking through
  // the interface is also the honest path — a URL assembled from an API call
  // would skip the navigation a person actually performs.
  await page.goto('/library');
  await expect(page.locator('[data-screen="library"][data-state="picker"]')).toBeVisible({
    timeout: 30_000,
  });
  await page.locator('.lib-picker-lib').first().click();
  await expect
    .poll(() => new URL(page.url()).searchParams.get('library'), {
      message: 'picking a library must write its id into the URL',
    })
    .not.toBeNull();

  const firstRow = page.locator('.egl-row').first();
  await expect(firstRow).toBeVisible({ timeout: 30_000 });
  const name = (await firstRow.locator('.egl-name').first().innerText()).trim();
  expect(name.length, 'the library must have a row to star').toBeGreaterThan(0);

  await firstRow.hover();
  await firstRow.getByRole('button', { name: /details/i }).click();
  const star = page.getByRole('button', { name: catalog['favorites.star'].message });
  await expect(star, 'the details panel must offer the star').toBeVisible({ timeout: 30_000 });
  await star.click();

  /* `aria-pressed` flips, and it is asserted rather than the icon: the control
   * is optimistic, so the visual change proves only that the click was handled
   * locally. What follows proves the server agreed. */
  await expect(
    page.getByRole('button', { name: catalog['favorites.starred'].message }),
  ).toBeVisible({ timeout: 30_000 });

  // --- it is on the screen -------------------------------------------------
  await page.goto('/favorites');
  const row = page.locator('.fav-row', { hasText: name });
  await expect(
    row,
    'a starred file must appear on Favorites; the star is optimistic, so this is what proves the ' +
      'write reached the server rather than only the component',
  ).toBeVisible({ timeout: 30_000 });

  // --- and un-starring removes it ------------------------------------------
  await row.getByRole('button').click();
  await expect(
    page.locator('.fav-row', { hasText: name }),
    'un-starring must remove the row: a star that cannot be undone is a list that only grows',
  ).toHaveCount(0, { timeout: 30_000 });
  await expect(emptyHeading).toBeVisible({ timeout: 30_000 });
});
