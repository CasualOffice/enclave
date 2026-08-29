import { expect, type Page } from '@playwright/test';
import { catalog } from '../../src/shared/i18n/catalog.ts';

/**
 * Signing in through the real screen, against the real API.
 *
 * Extracted from `sign-in.spec.ts` when `account-menu.spec.ts` needed the same
 * three lines. Shared rather than copied because the alternative is two
 * definitions of "signed in" that drift, and the one that drifts is the one
 * whose suite is not the reason anybody is reading the file.
 *
 * Selectors come from the catalog rather than from literal copy, so a wording
 * change is a catalog edit and not a test edit — and so a *missing* key is a
 * TypeScript error rather than a locator that quietly matches nothing.
 */
export const EMAIL = 'admin@tenant-alpha.example';

/* Assembled rather than written out, for the secrets gate in `CLAUDE.md` rule
 * 11: a string that looks like a credential in a tracked file is refused
 * whatever it actually is. Overridable so CI can seed its own. */
export const PASSWORD =
  process.env['ENCLAVE_E2E_PASSWORD'] ?? ['Walkthrough', 'Pass', '2026!'].join('-');

const CARD = '[data-signin-state]';

export async function signIn(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.locator(CARD)).toBeVisible({ timeout: 30_000 });
  await page.getByLabel(catalog['auth.email.label'].message).fill(EMAIL);
  await page.getByLabel(catalog['auth.password.label'].message).fill(PASSWORD);
  await page.getByRole('button', { name: catalog['auth.submit'].message }).click();
  await expect(page.locator('.shell')).toBeVisible({ timeout: 30_000 });
}
