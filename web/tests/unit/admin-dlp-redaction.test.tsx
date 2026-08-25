import type { ReactNode } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { PolicyEditor } from '../../src/features/admin/dlp/policy-editor.tsx';
import { DenialPreview } from '../../src/features/admin/dlp/sentence.tsx';
import { SimulationPanel } from '../../src/features/admin/dlp/simulation.tsx';
import {
  DlpRule,
  SimulationResult,
  type DlpRule as DlpRuleType,
} from '../../src/features/admin/dlp/model.ts';
import { SIMULATION } from '../../src/features/admin/dlp/fixture.ts';

/* `CLAUDE.md` rule 10, on the one screen where a matched value would look useful.
 *
 * "Never log passwords, tokens, refresh cookies, DLP match values or file
 * content" is a rule about what this screen *renders* as much as about what the
 * server writes, and `docs/09 §9` says what to render instead: the category
 * term — "contains payment card numbers" — never the number.
 *
 * `docs/12 §1.2`: **an assertion about an absence passes for free.** "No match
 * value is rendered" passes against a component that renders nothing at all. So
 * every absence below is paired with a positive control on the same render: the
 * category term must be *present* in the same DOM the value must be missing
 * from, which a blank component could not satisfy.
 *
 * The leaked field is fed in the way it would really arrive — through the Zod
 * schema, from a server payload that carries it. That is the boundary
 * `docs/17 §3` puts the guarantee at, and testing it there rather than by
 * hand-building a typed object is what makes the test about our code.
 */

/** A value that must never reach the DOM. Not a real card number: 4111… is the test PAN. */
const MATCH_VALUE = '4111 1111 1111 1111';

function Wrapper({ children }: { children: ReactNode }) {
  return <I18nProvider>{children}</I18nProvider>;
}

afterEach(cleanup);

describe('a simulation result never renders a matched value', () => {
  /* A server that leaked. `sample`, `excerpt` and `match` are the three field
   * names such a payload would plausibly use, and none of them is in the
   * schema — Zod strips unknown keys, so they are dropped here rather than
   * downstream where a component could reach one. */
  const leaky = {
    ...SIMULATION,
    events: SIMULATION.events.map((event) => ({
      ...event,
      sample: MATCH_VALUE,
      excerpt: `Card on file: ${MATCH_VALUE}`,
      match: MATCH_VALUE,
    })),
  };

  it('renders the category term and not the value', () => {
    const parsed = SimulationResult.parse(leaky);

    const { container } = render(
      <Wrapper>
        <SimulationPanel result={parsed} stale={false} onRun={() => undefined} readOnly={false} />
      </Wrapper>,
    );

    const text = container.textContent ?? '';

    // Positive control: the category term IS there, so the assertions below are
    // about a component that rendered something.
    expect(text).toContain('payment card numbers');
    expect(text).toContain('Aadhaar numbers');
    expect(text).toContain('API keys');

    // And the value is not, in any of the shapes it arrived in.
    expect(text).not.toContain(MATCH_VALUE);
    expect(text).not.toContain('4111');
    expect(text).not.toContain('Card on file');
  });

  it('drops the leaked fields at the schema boundary, not in the component', () => {
    const parsed = SimulationResult.parse(leaky);
    const first = parsed.events[0];
    expect(first).toBeDefined();
    // Positive control: the fields we *do* keep survived the parse.
    expect(first?.categories).toEqual(['PAYMENT_CARD']);
    expect(first?.resource).toBe('Helios MSA');
    // The leaked ones did not.
    expect(JSON.stringify(parsed)).not.toContain('4111');
    expect(Object.keys(first ?? {})).not.toContain('sample');
  });
});

describe('the JSON view cannot carry a leaked field into the DOM', () => {
  it('shows the stored vocabulary and not an unknown field the server sent', () => {
    /* The JSON view is the likeliest leak on this screen: stringifying the raw
     * server object rather than the parsed one would put anything the server
     * sent straight into the DOM. */
    const rule = DlpRule.parse({
      id: 'r-leak',
      name: 'Block restricted external sharing',
      priority: 100,
      scope: ['external_sharing'],
      conditions: [{ category_at_least: { category: 'PAYMENT_CARD', count: 1 } }],
      action: 'BLOCK',
      decodes: true,
      example_match: MATCH_VALUE,
      last_match_excerpt: MATCH_VALUE,
    });

    const { container } = render(
      <Wrapper>
        <PolicyEditor
          baseline={rule}
          initial={rule}
          simulate={() => Promise.resolve(SIMULATION)}
          readOnly
        />
      </Wrapper>,
    );

    const json = container.querySelector('.adm-json')?.textContent ?? '';
    // Positive control: the view rendered a real rule in the stored vocabulary.
    expect(json).toContain('category_at_least');
    expect(json).toContain('external_sharing');
    // And nothing the schema did not name.
    expect(json).not.toContain('4111');
    expect(json).not.toContain('example_match');
  });
});

describe('a denial never names the policy that produced it', () => {
  /* `docs/06 §24`: a stable reason code, a user-safe sentence, a remediation,
   * and never which policy matched, its conditions or its thresholds. The
   * preview is what an administrator reads to know that, so it has to obey it. */
  const rule: DlpRuleType = {
    id: 'r-secret-name',
    name: 'Deal room lockdown — Project Marlin',
    priority: 100,
    scope: ['external_sharing'],
    conditions: [
      { classification_at_least: { classification: 'restricted' } },
      { category_at_least: { category: 'PAYMENT_CARD', count: 7 } },
    ],
    action: 'BLOCK',
    decodes: true,
  };

  it('shows the code, the sentence and one remedy, and not the rule', () => {
    const { container } = render(
      <Wrapper>
        <DenialPreview rule={rule} />
      </Wrapper>,
    );

    const text = container.textContent ?? '';

    // Positive control: all three things a denial *must* carry are present.
    expect(text).toContain('DLP_BLOCKED');
    expect(text).toContain('This action is not permitted on this file.');
    expect(text).toContain('request an exception from your security administrator');

    // And none of the four things it must never carry.
    expect(text).not.toContain('Project Marlin');
    expect(text).not.toContain('Deal room lockdown');
    expect(text).not.toContain('Restricted');
    expect(text).not.toContain('7');
  });
});

describe('the effect decides the denial, so the wording cannot be authored per policy', () => {
  it('renders no denial at all for an effect that refuses nothing', () => {
    const watermark: DlpRuleType = {
      id: 'r-watermark',
      name: 'Watermark restricted previews',
      priority: 100,
      scope: ['exposes_content'],
      conditions: [],
      action: 'WATERMARK',
      decodes: true,
    };

    render(
      <Wrapper>
        <DenialPreview rule={watermark} />
      </Wrapper>,
    );

    // Positive control: the panel rendered, and said why there is nothing to show.
    expect(
      screen.getByText(/changes the request rather than refusing it/),
    ).toBeDefined();
    expect(screen.queryByText('DLP_BLOCKED')).toBeNull();
  });
});
