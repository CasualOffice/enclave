import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import AskScreen from '../../src/features/ask/ask-screen.tsx';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';
import { Button } from '../../src/shared/ui/primitives.tsx';

/* `ENC-673` / `docs/17 §10` F2, on the surface most likely to erode it.
 *
 * Ask is entirely unbuilt, so it is the largest single population of dimmed
 * controls in the product — which makes it the place the *dimmed means later*
 * habit would be learned, and carried to the one place dimmed means *DLP
 * refused this*. These are the assertions that stop that.
 *
 * `docs/12 §1.2`: an assertion about an absence passes for free. Every "the Ask
 * screen has none of X" below is paired with a probe that *does* have X, so a
 * component rendering nothing at all could not pass.
 */

/* `process.cwd()`, not `import.meta.url`: under the jsdom environment
 * `import.meta.url` is an `http://` URL served by Vite, and the stylesheets have
 * to be read as text rather than imported — importing a `.css` file gets the
 * empty module Vite substitutes in a test run, which would make every selector
 * scan below silently vacuous. Vitest's root is `web/`. */
const WEB_ROOT = process.cwd();

function css(relativePath: string): string {
  // Comments first: `primitives.css` explains the denial treatment in prose,
  // and a scan that reads its own documentation finds "denied" everywhere.
  return readFileSync(`${WEB_ROOT}/${relativePath}`, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
}

const STYLESHEETS = ['src/shared/ui/primitives.css', 'src/features/ask/ask.css']
  .map(css)
  .join('\n');

/**
 * Every selector in the shipped stylesheets that mentions a token, with the
 * interaction pseudo-classes removed so jsdom can evaluate them.
 *
 * Selectors rather than class names, because the treatments are not carried by
 * classes alone — `denied` and `unbuilt` are both states of `.ui-btn`, so
 * comparing `className` strings would find them identical and prove nothing.
 * What actually differs is which CSS rules apply, and that is checkable.
 */
function selectorsMentioning(token: string): string[] {
  const found = new Set<string>();
  for (const block of STYLESHEETS.split('}')) {
    const head = block.slice(0, block.indexOf('{'));
    if (head === '') continue;
    for (const selector of head.split(',')) {
      const clean = selector.replace(/:(hover|active|focus|focus-visible|focus-within)\b/g, '').trim();
      if (clean.includes(token)) found.add(clean);
    }
  }
  return [...found];
}

const DENIAL_SELECTORS = selectorsMentioning('denied');
const UNBUILT_SELECTORS = selectorsMentioning('unbuilt').concat('.ui-later');

function matching(root: HTMLElement, selectors: readonly string[]): Element[] {
  return [...root.querySelectorAll('*')].filter((element) =>
    selectors.some((selector) => element.matches(selector)),
  );
}

/** Everything a keyboard would stop on, by the same rules a browser uses. */
function tabbable(root: HTMLElement): Element[] {
  return [...root.querySelectorAll('a[href], button, input, select, textarea, [tabindex]')].filter(
    (element) => {
      const index = element.getAttribute('tabindex');
      if (index !== null) return Number(index) >= 0;
      return !element.hasAttribute('disabled');
    },
  );
}

function mount(search: string) {
  window.history.replaceState({}, '', `/ask${search}`);
  return render(
    <I18nProvider>
      <AskScreen />
    </I18nProvider>,
  ).container;
}

/** The positive control for every denial assertion: a control policy refused. */
function mountDenied() {
  return render(
    <I18nProvider>
      <Button
        label="ask.composer.send"
        /* The server's sentence, verbatim. A test may hold a literal; `web/src`
         * may not (`CLAUDE.md` rule 12), and the reason is server-supplied
         * precisely so the client never composes one (`docs/09 §5`). */
        state={{ kind: 'denied', reason: 'Blocked off-network.', remedy: 'ask.state.error.retry' }}
      />
    </I18nProvider>,
  ).container;
}

afterEach(cleanup);

describe('the unbuilt treatment is never the denial treatment', () => {
  it('the stylesheets define a denial treatment at all', () => {
    /* Without this the next test passes against a product that has no denial
     * styling — the `ENC-543` vacuous-gate shape, in miniature. */
    expect(DENIAL_SELECTORS.length).toBeGreaterThan(0);
    expect(UNBUILT_SELECTORS.length).toBeGreaterThan(0);
  });

  it('a denied control matches the denial rules and none of the unbuilt rules', () => {
    const denied = mountDenied();
    expect(matching(denied, DENIAL_SELECTORS)).not.toHaveLength(0);
    expect(matching(denied, UNBUILT_SELECTORS)).toHaveLength(0);
  });

  it('the Ask screen matches the unbuilt rules and none of the denial rules', () => {
    const ask = mount('');
    // Positive half: the screen is marked at all.
    expect(matching(ask, UNBUILT_SELECTORS)).not.toHaveLength(0);
    // The assertion this file exists for.
    expect(matching(ask, DENIAL_SELECTORS)).toHaveLength(0);
  });

  it('no element on the Ask screen carries the denied state token', () => {
    expect(mount('').querySelector('[data-state="denied"]')).toBeNull();
    // Positive control for the query itself.
    expect(mountDenied().querySelector('[data-state="denied"]')).not.toBeNull();
  });
});

describe('an unbuilt control is not in the tab order', () => {
  it('the unbuilt Ask screen puts nothing in the tab order', () => {
    const ask = mount('');
    /* The composer's field and send button are both present and both reachable
     * by `querySelectorAll` — they are simply not tabbable. Asserting on the
     * raw count first means this cannot pass by rendering nothing. */
    expect(ask.querySelectorAll('button, input')).not.toHaveLength(0);
    expect(tabbable(ask)).toHaveLength(0);
  });

  it('a denied control stays in the tab order, and so does its remedy', () => {
    /* The other half of D33, and the reason the first assertion means anything:
     * a denial is focusable *on purpose*, so a keyboard user can reach it and
     * hear why. If `tabbable()` simply never found anything, this would fail.
     *
     * Two, not one: `docs/09 §5` says *offer the remediation as an action where
     * one exists*, so a denial carrying a remedy is a control plus a way out.
     * This asserted 1 while `Button` silently dropped every remedy it was
     * given — the count was right about the DOM and wrong about the contract. */
    const denied = mountDenied();
    expect(tabbable(denied)).toHaveLength(2);
    expect(denied.querySelector('.ui-denial-remedy')).not.toBeNull();
  });

  it('a genuine failure does put its retry in the tab order', () => {
    /* A second positive control, on this screen rather than on a probe.
     *
     * Two, not one: the shared error state carries a *Copy* button beside the
     * request ID (`docs/09 §11`), and both are keyboard-reachable on purpose.
     * The claim is unchanged — a failed request is actionable and an unbuilt
     * surface is not. */
    expect(tabbable(mount('?surface=error'))).toHaveLength(2);
  });
});

describe('an unbuilt control offers no remedy', () => {
  it('every control on the unbuilt Ask screen is inert, and none is a link', () => {
    const ask = mount('');
    const buttons = [...ask.querySelectorAll('button')];
    expect(buttons).not.toHaveLength(0);
    for (const button of buttons) {
      expect(button.getAttribute('aria-disabled')).toBe('true');
    }
    // No "Request access", no "Contact an admin", no anchor to anywhere.
    expect(ask.querySelectorAll('a')).toHaveLength(0);
  });

  it('a genuine failure offers retry and a way to quote the failure, and nothing else', () => {
    /* The positive control. Without it, "the unbuilt screen offers no action"
     * would pass against a screen that renders no actions anywhere, which is a
     * different and much weaker claim.
     *
     * Named rather than counted, so the assertion says *which* two actions a
     * failure offers: retry, and copying the request ID. Neither is available
     * on a denial (`docs/17 §7`), and a third would be a regression. */
    const errored = mount('?surface=error');
    const actionable = [...errored.querySelectorAll('button')]
      .filter((button) => button.getAttribute('aria-disabled') !== 'true')
      .map((button) => button.textContent);

    expect(actionable).toEqual([
      catalog['ask.state.error.retry'].message,
      catalog['surface.error.copy'].message,
    ]);
  });

  it('the release note is future tense about the product, and is what the controls point at', () => {
    const ask = mount('');
    /* The copy rule from D33, held by the catalog rather than by prose in a
     * component: the note the composer describes itself with is the product's
     * roadmap sentence, not a user-directed refusal. */
    const field = ask.querySelector('input');
    const noteId = field?.getAttribute('aria-describedby') ?? '';
    expect(noteId).not.toBe('');

    /* This also pins the coupling to `<Button>`'s `${label}-note` id scheme. If
     * the primitive changes it, the field's description silently points at
     * nothing — and this fails instead. */
    /* `getElementById`, not a `#id` selector: the id contains dots (it is a
     * catalog key) and jsdom has no `CSS.escape` to quote them with. */
    const note = [...ask.querySelectorAll('[id]')].find((el) => el.id === noteId);
    expect(note?.textContent).toBe(catalog['ask.arrivesInM7'].message);
  });
});
