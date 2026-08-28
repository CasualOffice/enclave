import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { Button, IconButton, type ControlState } from '../../src/shared/ui/primitives.tsx';
import { Row } from '../../src/shared/ui/layout.tsx';
import { catalog } from '../../src/shared/i18n/catalog.ts';

afterEach(cleanup);

/* The tests that keep the design system a system.
 *
 * A component library holds only while nothing quietly re-implements a piece of
 * it, and "nothing quietly re-implements it" is not a property any single
 * component test can see. These assertions read the tree instead: they are
 * about *where* a declaration is allowed to appear, which is the only form in
 * which "one implementation" is checkable.
 *
 * Two of them are security assertions rather than tidiness ones, and are
 * marked as such below.
 */

/* `process.cwd()` is `web/`, because that is where Vitest is invoked and where
 * `vite.config.ts` roots the project. `import.meta.url` is the obvious
 * alternative and does not survive the jsdom environment. */
const SRC = join(process.cwd(), 'src') + '/';

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path, out);
    else out.push(path);
  }
  return out;
}

const ALL = walk(SRC);
const CSS = ALL.filter((path) => path.endsWith('.css'));
const FEATURE_CSS = CSS.filter((path) => path.includes('/features/'));
const rel = (path: string) => path.slice(SRC.length);
const read = (path: string) => readFileSync(path, 'utf8');

/** Comments carry prose about the rules; only declarations are being asserted on. */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '');
}

describe('the token layer is where geometry and motion live', () => {
  it('defines a motion language at all', () => {
    /* The gap this whole layer was built to close: before it,
     * `grep -c "transition\|--motion\|cubic-bezier" src/styles/tokens.css`
     * returned 0 while the prototype ran eight keyframes and three stagger
     * steps. A design system without motion tokens is one where every screen
     * re-derives an easing curve. */
    const motion = read(join(SRC, 'styles/motion.css'));
    for (const token of [
      '--ease-enter',
      '--ease-standard',
      '--dur-fade',
      '--dur-pop',
      '--dur-panel',
      '--dur-row',
      '--dur-card',
      '--stagger-row',
      '--stagger-cap',
      '--travel-in',
      '--icon-flip',
    ]) {
      expect(motion, `${token} is missing from styles/motion.css`).toContain(`${token}:`);
    }
  });

  it('carries the prototype’s signature easing, exactly', () => {
    /* `cubic-bezier(.2,.7,.3,1)` is the reference's own curve. A rounded or
     * "close enough" variant is a different curve, and the whole point of
     * extracting values rather than eyeballing them is that this is checkable. */
    const motion = withoutComments(read(join(SRC, 'styles/motion.css')));
    expect(motion).toMatch(/--ease-enter:\s*cubic-bezier\(0?\.2,\s*0?\.7,\s*0?\.3,\s*1\)/);
  });

  it('answers prefers-reduced-motion in exactly one place', () => {
    /* There were eight per-file blocks, which is eight chances for a new
     * animation to ship without one. The single block rewrites the motion
     * tokens, so a component that uses `var(--dur-*)` degrades whether or not
     * its author remembered the media query existed. */
    const owners = CSS.filter((path) =>
      withoutComments(read(path)).includes('prefers-reduced-motion'),
    ).map(rel);

    expect(owners).toEqual(['styles/motion.css']);
  });

  it('keeps keyframes out of features', () => {
    /* Three separately-declared shimmer keyframes were the same six lines under
     * three names. A keyframe in a feature is a motion decision made where
     * nobody will find it again. */
    const offenders = FEATURE_CSS.filter((path) =>
      withoutComments(read(path)).includes('@keyframes'),
    ).map(rel);

    expect(offenders).toEqual([]);
  });
});

describe('the reference’s numbers are read by a test', () => {
  /* **A number in a spec that no test reads is a number that drifts.**
   *
   * `web/design-system/specs/library.md` states this screen's geometry exactly —
   * 36px rows, 30 compact, a 28px group header, a 30px sticky header, a 38px
   * location bar, 26px controls, a 232px sidebar, a 372px peek panel clamped to
   * 320–520 — and until the token layer existed those numbers lived as
   * literals in ten stylesheets, where nothing could compare them to anything.
   *
   * The table below is the specification, restated as an assertion. It is
   * deliberately in the *unit* gate rather than the browser one: this asserts
   * the declared value, which is the thing a person edits, and the rendered
   * value is asserted separately in `tests/a11y/geometry.spec.ts` — where real
   * Chromium computes it and can catch a token that is correct and unread.
   *
   * The two halves matter for different reasons. A wrong token is a design
   * regression. A correct token nobody reads is `ENC-757`'s failure: every web
   * gate was green while the peek panel did not exist.
   */

  const DECLARED: ReadonlyArray<readonly [string, string, string]> = [
    // token, value, where the reference says so
    ['--shell-nav-w', '232px', 'prototype shell, measured: grid-template-columns 232px 1fr'],
    ['--peek-w', '372px', 'specs/library.md §4 — minmax(320px, var(--peek-w, 372px))'],
    ['--peek-w-min', '320px', 'specs/library.md §4B — clamped 320–520'],
    ['--peek-w-max', '520px', 'specs/library.md §4B'],
    ['--row-h', '36px', 'docs/09 §13 Default density; specs/library.md §4A.3'],
    ['--row-h-head', '30px', 'specs/library.md §4A.1 sticky column header'],
    ['--row-h-group', '28px', 'specs/library.md §4A.2 group header'],
    ['--bar-h', '38px', 'specs/library.md §1 LocationBar min-block-size'],
    ['--ctl-h-sm', '24px', 'specs/library.md §1.3 Share, §2.2 New, §4B.5 Open preview'],
    ['--ctl-h', '26px', 'specs/library.md §2.2 Filter/Display/Upload; 63 uses in the prototype'],
    ['--ctl-h-lg', '28px', 'the segmented tab'],
    ['--icon', '14px', 'specs/library.md §1.3; 45 uses in the prototype'],
    ['--icon-stroke', '1.8', 'the prototype sprite’s stroke-width on 30 of its symbols'],
    ['--fs-sm', '11px', 'specs/library.md §4A.1 column headers'],
    ['--fs-body', '12.5px', 'the prototype’s commonest size, 61 uses'],
    ['--fs-row', '13px', 'specs/library.md §4A.3 row font-size; the document’s own size'],
    ['--r-pill', '999px', '25 uses in the prototype'],
  ];

  const MOTION: ReadonlyArray<readonly [string, string, string]> = [
    ['--dur-row', '220ms', 'specs/library.md §4A.3 — encIn .22s'],
    ['--dur-panel', '180ms', 'specs/library.md §4B — encPeek .18s'],
    ['--dur-pop', '160ms', 'specs/library.md §5 — encPop .16s'],
    ['--stagger-row', '20ms', 'the prototype’s Math.min(i, 12) * 0.02s'],
    ['--stagger-cap', '12', 'the same expression’s cap'],
    ['--stagger-card', '30ms', 'the prototype’s i * 0.03s on search hits'],
    ['--stagger-tile', '50ms', 'the prototype’s i * 0.05s on stat tiles'],
    ['--travel-in', '4px', 'encIn translateY(4px)'],
    ['--travel-panel', '14px', 'encPeek translateX(14px)'],
    ['--travel-pop', '8px', 'encPop translateY(8px)'],
    ['--scale-pop', '0.97', 'encPop scale(.97)'],
  ];

  function declaredIn(file: string, token: string): string | undefined {
    const source = withoutComments(read(join(SRC, file)));
    /* The first declaration wins, which is the `:root` one — the density and
     * direction overrides further down are variants, not the base value. */
    const match = new RegExp(`${token}:\\s*([^;\\n}]+)`).exec(source);
    return match?.[1]?.trim();
  }

  for (const [token, value, source] of DECLARED) {
    it(`${token} is ${value} — ${source}`, () => {
      expect(declaredIn('styles/scale.css', token)).toBe(value);
    });
  }

  for (const [token, value, source] of MOTION) {
    it(`${token} is ${value} — ${source}`, () => {
      expect(declaredIn('styles/motion.css', token)).toBe(value);
    });
  }

  it('offers the second density docs/09 §13 names, and only by changing the row', () => {
    /* `docs/09 §13`: two densities, Default 36px and Compact 30px. One
     * declaration, because every list in the tree reads `--row-h`. The group and
     * sticky headers deliberately do not shrink — a 24px group header stops
     * reading as a heading. */
    const scale = withoutComments(read(join(SRC, 'styles/scale.css')));
    const compact = /:root\[data-density='compact'\]\s*\{([^}]*)\}/.exec(scale);
    expect(compact, "no [data-density='compact'] block in styles/scale.css").not.toBeNull();
    expect(compact?.[1]?.trim()).toBe('--row-h: 30px;');
  });
});

describe('the classification palette is locked, and read in one place', () => {
  it('is referenced only by the classification chip', () => {
    /* **A security assertion.** `docs/09 §16a` locks `--c-pub … --c-restr` so a
     * user reads Restricted identically everywhere. Four hand-maintained copies
     * of the badge defeat that from the inside — and they had already drifted to
     * four heights, four dot sizes and three different type sizes before this
     * was extracted. Locking the token and duplicating the component locks
     * nothing. */
    const readers = CSS.filter((path) =>
      /var\(--c-(pub|int|conf|hconf|restr)\)/.test(withoutComments(read(path))),
    ).map(rel);

    expect(readers).toEqual(['entities/classification/chip.css']);
  });
});

describe('denied, unbuilt and busy are distinguishable by construction', () => {
  /* **A security assertion** — `docs/17 §6` / `ENC-673`, and F2 of `docs/17 §10`.
   *
   * The cost of letting these blur is specific: the denial treatment is how a
   * user learns that DLP, a barrier or conditional access stopped them. If most
   * dimmed controls in the product mean "not written yet", users learn that
   * dimmed is background noise — on harmless surfaces — and then carry the habit
   * to the one that matters.
   */

  function renderButton(state: ControlState) {
    return render(
      <I18nProvider>
        <Button label="surface.error.retry" state={state} />
      </I18nProvider>,
    );
  }

  it('gives the three states three different markers, sharing none', () => {
    const markers = new Set<string>();
    const states: readonly ControlState[] = [
      { kind: 'denied', reason: 'Refused by policy.' },
      { kind: 'unbuilt', note: 'later.arrivesLater' },
      { kind: 'busy' },
    ];
    for (const state of states) {
      const { container } = renderButton(state);
      const button = container.querySelector('.ui-btn');
      markers.add(button?.getAttribute('data-state') ?? '');
      cleanup();
    }

    expect(markers.size).toBe(3);
    expect(markers.has('')).toBe(false);
  });

  it('keeps the two vocabularies apart in the copy, not only in the markup', () => {
    /* **The other half of the same security assertion**, and the half that only
     * became reachable with `ENC-674`.
     *
     * D33 separates the two treatments structurally — different `data-state`,
     * different selectors, different focus behaviour — and every assertion in
     * this block so far is about the markup. But a user does not read
     * `data-state`; they read the sentence. Two treatments that look different
     * and *say* the same kind of thing have not actually been separated, and
     * until this milestone the product had almost no denial copy to get this
     * wrong with. It now has nineteen sentences.
     *
     * The rule is a tense and a subject. `later.*` is future tense about the
     * **product** — it must never assert anything about this user's
     * permissions. `denial.*` is present tense about this **user** — it must
     * never talk about a release, because "you may not do this yet" invites a
     * user to wait for something that is not coming.
     *
     * Both directions are asserted, because banning roadmap words from denials
     * alone would pass against a product with no roadmap copy at all. */
    const laterKeys = Object.keys(catalog).filter((key) => key.startsWith('later.'));
    const denialKeys = Object.keys(catalog).filter((key) => key.startsWith('denial.'));

    // Neither set is empty, so neither loop below is vacuous (`§1.2`).
    expect(laterKeys.length).toBeGreaterThan(0);
    expect(denialKeys.length).toBeGreaterThan(0);

    /* A roadmap note may not tell a user what they are permitted to do. The
     * words are the ones that make a sentence about *access* rather than about
     * *availability*. */
    for (const key of laterKeys) {
      const message = catalog[key as keyof typeof catalog].message.toLowerCase();
      for (const word of ['permission', 'not allowed', 'denied', 'restricted', 'blocked']) {
        expect(message, `${key} reads as a refusal`).not.toContain(word);
      }
    }

    /* …and a refusal may not read as a roadmap item. `denial.*` is about now. */
    for (const key of denialKeys) {
      const message = catalog[key as keyof typeof catalog].message.toLowerCase();
      for (const word of ['later release', 'arrives', 'coming soon', 'not yet', 'in a future']) {
        expect(message, `${key} reads as a roadmap note`).not.toContain(word);
      }
    }

    /* The positive control for the second loop: the product does contain
     * roadmap copy using exactly those words, so "no denial says `arrives`" is
     * a fact about the denial set and not about a vocabulary nobody uses. */
    const roadmapCopy = laterKeys.filter((key) =>
      /arrives|later release/i.test(catalog[key as keyof typeof catalog].message),
    );
    expect(roadmapCopy.length).toBeGreaterThan(0);
  });

  it('keeps a denial focusable and an unbuilt control out of the tab order', () => {
    /* Focusability is the difference that matters most. A denied control must be
     * reachable, because reaching it is how a keyboard user discovers *why* —
     * which is the entire reason it is shown rather than hidden. An unbuilt one
     * has nothing to find out. */
    renderButton({ kind: 'denied', reason: 'Refused by policy.' });
    expect(document.querySelector('.ui-btn')?.getAttribute('tabindex')).toBeNull();
    cleanup();

    renderButton({ kind: 'unbuilt', note: 'later.arrivesLater' });
    expect(document.querySelector('.ui-btn')?.getAttribute('tabindex')).toBe('-1');
  });

  it('never uses the disabled attribute for a denial', () => {
    /* `disabled` removes a control from the tab order, so the reason beside it
     * becomes unreachable — `docs/09 §5`, `docs/06 §24`. */
    renderButton({ kind: 'denied', reason: 'Refused by policy.' });
    const button = document.querySelector('.ui-btn');
    expect(button?.hasAttribute('disabled')).toBe(false);
    expect(button?.getAttribute('aria-disabled')).toBe('true');
  });

  it('renders an unbuilt row as a non-control, not a button nobody can reach', () => {
    /* A `<button tabindex="-1">` is still announced as a button and is still
     * reachable through a screen reader's control rotor, which does not consult
     * `tabindex`. Announcing "button" for something that will never do anything
     * is the same lie as rendering it enabled. */
    const { container } = render(
      <I18nProvider>
        <Row unbuilt>{'x'}</Row>
      </I18nProvider>,
    );

    const row = container.querySelector('.ui-row');
    expect(row?.tagName).toBe('SPAN');
    expect(row?.getAttribute('aria-disabled')).toBe('true');
    // Positive control: a built row *is* a button, so the assertion above is
    // about `unbuilt` rather than about `Row` never rendering one.
    cleanup();
    const built = render(
      <I18nProvider>
        <Row>{'x'}</Row>
      </I18nProvider>,
    );
    expect(built.container.querySelector('.ui-row')?.tagName).toBe('BUTTON');
  });

  it('neutralises the variant an unbuilt control was applied to', () => {
    /* The bug this catches, and why no gate did.
     *
     * `data-state="unbuilt"` did not reset `background`, so an unbuilt
     * `variant="primary"` kept `var(--accent)` and `opacity: .45` faded the
     * whole plate — washed-out `--on-accent` text on a washed-out accent, which
     * was the least readable thing on the library's view bar in both themes.
     *
     * **axe cannot see it.** The control is `aria-disabled`, and WCAG exempts
     * disabled controls from the contrast requirement, so all 94 accessibility
     * surfaces passed over it. That exemption is why this is a source-level
     * assertion rather than a rendered one.
     *
     * It is also `docs/17 §6` rather than only legibility: unbuilt must be
     * *neutral*, and a faded brand colour is not. A user calibrating on "dimmed
     * means not written yet" must not learn two appearances for one meaning
     * depending on which variant the author happened to reach for. */
    const css = withoutComments(read(join(SRC, 'shared/ui/primitives.css')));
    const rule = css
      .split('}')
      .find((block) => block.includes(".ui-btn[data-state='unbuilt']") && block.includes('opacity'));

    expect(rule, "no .ui-btn[data-state='unbuilt'] rule found").toBeDefined();
    expect(rule).toMatch(/background:\s*var\(--sheet\)/);
    expect(rule).not.toMatch(/--accent/);
  });

  it('does not dim an unbuilt row, and never tints it with danger', () => {
    /* The rule the three copies of this treatment had already broken: one of
     * them added `opacity: .5` and the other two deliberately did not. The
     * unbuilt treatment may not vary by screen, because a user calibrates on
     * it. */
    const layout = withoutComments(read(join(SRC, 'shared/ui/layout.css')));
    const unbuiltRules = layout
      .split('}')
      .filter((rule) => rule.includes(".ui-row[data-unbuilt]"))
      .join('\n');

    expect(unbuiltRules).not.toMatch(/opacity/);
    expect(unbuiltRules).not.toMatch(/--danger/);
  });
});

describe('a toggle’s appearance and its announcement cannot disagree', () => {
  it('styles the pressed state from aria-pressed itself', () => {
    /* A second icon button had grown in `features/libraries` for want of this
     * one rule. Keying the appearance off the accessible attribute means there
     * is no second source of truth to fall out of step. */
    render(
      <I18nProvider>
        <IconButton name="side" label="library.peek.close" pressed />
      </I18nProvider>,
    );
    expect(screen.getByRole('button').getAttribute('aria-pressed')).toBe('true');

    const css = withoutComments(read(join(SRC, 'shared/ui/primitives.css')));
    expect(css).toContain(".ui-iconbtn[aria-pressed='true']");
  });
});
