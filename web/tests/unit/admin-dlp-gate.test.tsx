import type { ReactNode } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { PolicyEditor } from '../../src/features/admin/dlp/policy-editor.tsx';
import { DRAFT, SIMULATION } from '../../src/features/admin/dlp/fixture.ts';
import type { DlpRule } from '../../src/features/admin/dlp/model.ts';

/* Two rules meet in this file and neither is styling.
 *
 * **`docs/06 §9`:** "Simulation is mandatory before enforcement for any policy
 * whose effect is `BLOCK` or `QUARANTINE`. The admin UI refuses to enable
 * enforcement on a policy that has never been simulated." Plus `docs/09 §21`'s
 * *diff before save*. So a blocking policy cannot reach the write path without
 * rehearsal **and** confirmation, in that order.
 *
 * **`docs/17 §6` / `ENC-673`:** when it does reach it, the control is `unbuilt`
 * and not `denied` — the step-up flow is unwritten, which is a fact about the
 * product rather than a refusal aimed at this administrator. Not focusable, a
 * neutral `Later` chip, and **no remedy**, because *Request access* would be a
 * lie.
 *
 * `docs/12 §1.2` again: the "no such control" assertions are paired with the
 * render in which the control *does* appear, so a component that rendered
 * nothing could not pass them.
 */

const ENABLE = 'Put this policy in force';
const RUN = /Test against the last/;
const CONFIRM = 'I have read every row above.';

function Wrapper({ children }: { children: ReactNode }) {
  return <I18nProvider>{children}</I18nProvider>;
}

function mount(rule: DlpRule, readOnly = false) {
  return render(
    <Wrapper>
      <PolicyEditor
        baseline={undefined}
        initial={rule}
        simulate={() => Promise.resolve(SIMULATION)}
        readOnly={readOnly}
      />
    </Wrapper>,
  );
}

afterEach(cleanup);

describe('a blocking policy cannot be enabled without simulate-then-diff', () => {
  it('offers no enable control until both steps are behind it', async () => {
    mount(DRAFT);

    // Nothing to enable yet — and the checklist says which step is outstanding,
    // which is the positive control that the gate rendered at all.
    expect(screen.queryByRole('button', { name: ENABLE })).toBeNull();
    expect(screen.getByText('Rehearse it against recent activity')).toBeDefined();
    expect(screen.getAllByText('Outstanding').length).toBe(2);

    // Rehearse. Still not enough: the diff has not been confirmed.
    fireEvent.click(screen.getByRole('button', { name: RUN }));
    await waitFor(() => expect(screen.getByText(/Rehearsed against the last/)).toBeDefined());
    expect(screen.queryByRole('button', { name: ENABLE })).toBeNull();
    expect(screen.getAllByText('Outstanding').length).toBe(1);

    // Confirm the diff. Now, and only now, the control exists.
    fireEvent.click(screen.getByLabelText(CONFIRM));
    expect(screen.getByRole('button', { name: ENABLE })).toBeDefined();
    expect(screen.queryByText('Outstanding')).toBeNull();
  });

  it('reopens the gate when the policy is edited after being rehearsed', async () => {
    mount(DRAFT);

    fireEvent.click(screen.getByRole('button', { name: RUN }));
    await waitFor(() => expect(screen.getByText(/Rehearsed against the last/)).toBeDefined());
    fireEvent.click(screen.getByLabelText(CONFIRM));
    expect(screen.getByRole('button', { name: ENABLE })).toBeDefined();

    /* A rehearsal is a statement about one exact rule. Widening the scope after
     * confirming makes both the result and the confirmation describe something
     * that is no longer on screen. */
    fireEvent.change(screen.getByLabelText('Add an action to govern'), {
      target: { value: 'download' },
    });

    expect(screen.queryByRole('button', { name: ENABLE })).toBeNull();
    expect(screen.getByText(/describes the policy as it was before your last edit/)).toBeDefined();
  });

  it('does not require a rehearsal for an effect that refuses nothing', () => {
    /* `docs/06 §9` binds the mandatory rehearsal to `BLOCK` and `QUARANTINE`.
     * An `AUDIT` policy turns nobody away, so the step is already satisfied —
     * and the checklist says so rather than silently dropping the row. */
    mount({ ...DRAFT, action: 'AUDIT' });

    expect(screen.getByText(/refuses nothing, so a rehearsal is not required/)).toBeDefined();
    expect(screen.queryByRole('button', { name: ENABLE })).toBeNull();

    fireEvent.click(screen.getByLabelText(CONFIRM));
    expect(screen.getByRole('button', { name: ENABLE })).toBeDefined();
  });
});

describe('the write path is unbuilt, not denied', () => {
  async function reachTheControl() {
    mount(DRAFT);
    fireEvent.click(screen.getByRole('button', { name: RUN }));
    await waitFor(() => expect(screen.getByText(/Rehearsed against the last/)).toBeDefined());
    fireEvent.click(screen.getByLabelText(CONFIRM));
    return screen.getByRole('button', { name: ENABLE });
  }

  it('is not focusable and carries the neutral marker', async () => {
    const button = await reachTheControl();

    // Positive control: it is on screen and it is the right control.
    expect(button.textContent).toContain(ENABLE);
    expect(button.getAttribute('data-state')).toBe('unbuilt');
    // Out of the tab order: there is nothing to find out and nothing to do.
    expect(button.getAttribute('tabindex')).toBe('-1');
    expect(button.getAttribute('aria-disabled')).toBe('true');

    const note = document.getElementById(button.getAttribute('aria-describedby') ?? '');
    expect(note?.textContent).toBe('Arrives in a later release');
    expect(note?.className).toBe('ui-later-note');
  });

  it('offers no remedy and never wears the denial treatment', async () => {
    const button = await reachTheControl();

    expect(button.getAttribute('data-state')).not.toBe('denied');

    /* The three shapes a remedy takes in this product. None of them may appear
     * on an unbuilt control: a remedy implies there is something this
     * administrator could do, and there is not. */
    const text = document.body.textContent ?? '';
    expect(text).not.toContain('Request access');
    expect(text).not.toContain('Request an exception');
    expect(text).not.toContain('Contact your administrator');

    // Positive control for the pair: the *denial preview* on the same screen
    // does carry a remedy, so "no remedy anywhere" is not passing for free.
    expect(text).toContain('request an exception from your security administrator');
  });

  it('is a step-up requirement stated in the future tense, about the product', async () => {
    await reachTheControl();
    const step = screen.getByText('Re-authenticate with a second factor');
    expect(step.getAttribute('aria-disabled')).toBe('true');
    // The neutral chip, not a refusal.
    expect(screen.getAllByText('Later').length).toBeGreaterThan(0);
  });
});

describe('auditor mode renders the same screen without its mutating controls', () => {
  it('keeps the policy readable and removes every control that changes it', () => {
    mount(DRAFT, true);

    // Positive control: the policy itself is fully rendered.
    expect(screen.getByText(/The file is classified/)).toBeDefined();
    // The effect and the threshold appear in the sentence and again in the
    // diff, which is the point of auditor mode: the same screen, all of it.
    expect(screen.getAllByText('Block').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Restricted').length).toBeGreaterThan(0);

    // And nothing that would change it.
    expect(screen.queryByRole('button', { name: RUN })).toBeNull();
    expect(screen.queryByLabelText(CONFIRM)).toBeNull();
    expect(screen.queryByLabelText('Policy name')).toBeNull();
    expect(screen.queryByLabelText('Add a detector category')).toBeNull();
    expect(screen.queryByRole('button', { name: ENABLE })).toBeNull();
  });
});
