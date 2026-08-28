import { useState } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';
import { Button, LaterChip, Pill } from '../../../shared/ui/primitives.tsx';
import { Eyebrow, Push } from '../../../shared/ui/layout.tsx';
import { Icon } from '../../../shared/ui/icon-sprite.tsx';
import { PolicyDiff } from './diff.tsx';
import { DenialPreview, PolicySentence } from './sentence.tsx';
import { SimulationEmpty, SimulationPanel, SimulationSkeleton } from './simulation.tsx';
import {
  fingerprint,
  requiresSimulation,
  toWire,
  type DlpRule,
  type SimulationResult,
} from './model.ts';

/* The editor, and the gate that stands between it and enforcement.
 *
 * Three of `docs/09 §21`'s six standards meet here and the order matters:
 *
 *   simulate → diff → step-up → in force
 *
 * **Simulate is not advice.** `docs/06 §9`: "Simulation is mandatory before
 * enforcement for any policy whose effect is `BLOCK` or `QUARANTINE`. The admin
 * UI refuses to enable enforcement on a policy that has never been simulated."
 * So the control that would put the policy in force **does not exist** until the
 * rehearsal and the confirmation are behind it. It is not rendered and disabled:
 * a disabled control with a reason is the *denial* treatment, and this is not a
 * denial — nobody has refused this administrator anything. It is a path with
 * steps left in it, and the checklist is what says so.
 *
 * **The rehearsal is about one exact rule.** Editing after simulating leaves a
 * result on screen describing a policy that is no longer the one on screen, so
 * the fingerprint is compared and the gate reopens. The same applies to the
 * confirmation: a diff confirmed and then edited underneath is a confirmation of
 * nothing.
 *
 * **The last step is `unbuilt`, not denied.** `docs/05 §14.2`: writing a rule
 * requires recent multi-factor authentication. That flow does not exist yet, so
 * the final control carries the neutral `Later` chip, sits outside the tab
 * order, and offers no remedy — because there is nothing this administrator can
 * do about it and *Request access* would be a lie (`docs/17 §6`).
 */

/* A call signature rather than an arrow alias: the i18n gate scans for JSX
 * text between angle brackets, and `=> Promise<…>` reads as exactly that. */
interface SimulateFn {
  (rule: DlpRule): Promise<SimulationResult>;
}

interface GateStep {
  readonly label: MessageKey;
  readonly why: MessageKey;
  readonly state: 'done' | 'outstanding' | 'unbuilt';
}

function GateList({ steps }: { steps: readonly GateStep[] }) {
  const t = useT();
  return (
    <ol className="adm-gate">
      {steps.map((step) => (
        <li className="adm-gate-step" key={step.label} data-state={step.state}>
          <span className="adm-gate-mark" aria-hidden="true">
            <Icon name={step.state === 'done' ? 'check' : 'clock'} size={12} />
          </span>
          <span className="adm-gate-text">
            <span
              className={step.state === 'unbuilt' ? 'adm-clause-unbuilt' : undefined}
              aria-disabled={step.state === 'unbuilt' ? true : undefined}
            >
              {t(step.label)}
            </span>
            <span className="adm-muted">{t(step.why)}</span>
          </span>
          <Push />
          {step.state === 'unbuilt' ? (
            <LaterChip note="later.chip" />
          ) : (
            <span className="adm-gate-status" data-state={step.state}>
              {t(step.state === 'done' ? 'admin.dlp.gate.done' : 'admin.dlp.gate.outstanding')}
            </span>
          )}
        </li>
      ))}
    </ol>
  );
}

export interface PolicyEditorProps {
  /** The rule as it stands in force, or `undefined` for a policy never written. */
  readonly baseline: DlpRule | undefined;
  readonly initial: DlpRule;
  /** Injected so a test can settle it synchronously; there is no endpoint yet either way. */
  readonly simulate: SimulateFn;
  /** `docs/09 §21`: the same screen, without its mutating controls. */
  readonly readOnly: boolean;
}

export function PolicyEditor({ baseline, initial, simulate, readOnly }: PolicyEditorProps) {
  const t = useT();
  const [draft, setDraft] = useState<DlpRule>(initial);
  const [running, setRunning] = useState(false);
  const [rehearsal, setRehearsal] = useState<{ result: SimulationResult; of: string } | null>(null);
  const [confirmedOf, setConfirmedOf] = useState<string | null>(null);

  const print = fingerprint(draft);
  const stale = rehearsal !== null && rehearsal.of !== print;
  const simulationNeeded = requiresSimulation(draft.action);
  const simulated = rehearsal !== null && !stale;
  const confirmed = confirmedOf === print;
  const gateOpen = (simulated || !simulationNeeded) && confirmed;

  const run = () => {
    if (readOnly) return;
    setRunning(true);
    const of = fingerprint(draft);
    void simulate(draft).then((result) => {
      setRunning(false);
      setRehearsal({ result, of });
    });
  };

  const steps: readonly GateStep[] = [
    {
      label: 'admin.dlp.gate.simulate',
      why: simulationNeeded ? 'admin.dlp.gate.simulateWhy' : 'admin.dlp.gate.simulateOptional',
      state: simulated || !simulationNeeded ? 'done' : 'outstanding',
    },
    {
      label: 'admin.dlp.gate.diff',
      why: 'admin.dlp.gate.diffWhy',
      state: confirmed ? 'done' : 'outstanding',
    },
    { label: 'admin.dlp.gate.stepUp', why: 'admin.dlp.gate.stepUpWhy', state: 'unbuilt' },
  ];

  return (
    <div className="adm-editor">
      <nav className="adm-crumbs" aria-label={t('admin.crumb.label')}>
        <span>{t('admin.nav.security')}</span>
        <Icon name="chevr" size={11} />
        <span>{t('admin.nav.dlp')}</span>
        <Icon name="chevr" size={11} />
        <b>{draft.name}</b>
      </nav>

      <div className="adm-head">
        <h1 className="adm-h1">{t('admin.dlp.pageTitle')}</h1>
        {baseline === undefined ? (
          <Pill label="admin.dlp.status.draft" tone="outline" />
        ) : (
          <Pill label="admin.dlp.status.inForce" tone="ok" icon="check" />
        )}
        {readOnly && <Pill label="admin.auditor.pill" tone="info" icon="eye" />}
        <Push />
        {gateOpen && !readOnly && (
          /* Reached only once the rehearsal and the confirmation are behind it,
           * and *still* not actionable: the step-up flow is unwritten. Neutral,
           * out of the tab order, no remedy (`docs/17 §6`). */
          <Button
            label="admin.dlp.commit.putInForce"
            variant="primary"
            state={{ kind: 'unbuilt', note: 'later.arrivesLater' }}
          />
        )}
      </div>

      {/* `docs/05 §14.2`: there is no `mode` field on a DLP rule, by
       * construction — the mode is deployment configuration, and a per-policy
       * "Simulation / Enforce" switch would be an administrator believing a rule
       * rehearses while it decides. The prototype draws that switch; this says
       * why it is not here. */}
      <p className="adm-muted adm-modenote">{t('admin.dlp.modeNote')}</p>

      {readOnly && <p className="adm-muted">{t('admin.auditor.note')}</p>}

      <PolicySentence rule={draft} onChange={setDraft} readOnly={readOnly} />

      <DenialPreview rule={draft} />

      <section className="ui-card adm-panel" data-padded="" aria-label={t('admin.dlp.sim.heading')}>
        <Eyebrow label="admin.dlp.sim.heading" />
        {running ? (
          <SimulationSkeleton />
        ) : rehearsal === null ? (
          <SimulationEmpty onRun={run} readOnly={readOnly} />
        ) : (
          <SimulationPanel
            result={rehearsal.result}
            stale={stale}
            onRun={run}
            readOnly={readOnly}
          />
        )}
      </section>

      <PolicyDiff
        baseline={baseline}
        draft={draft}
        confirmed={confirmed}
        onConfirm={(next) => setConfirmedOf(next ? print : null)}
        readOnly={readOnly}
      />

      <section className="ui-card adm-panel" data-padded="" aria-label={t('admin.dlp.gate.title')}>
        <Eyebrow label="admin.dlp.gate.title" />
        <GateList steps={steps} />
      </section>

      {/* The JSON view `docs/09 §21` asks for: for power users, and for copying
       * a policy between tenants. It renders `toWire(draft)` — the same object
       * the builder edits and the same body `POST /admin/dlp/rules` takes — so
       * the two cannot drift. Read-only, because a second editor would be a
       * second parser and `docs/05 §14.2` refuses a rule that lost a clause. */}
      <section className="ui-card adm-panel" data-padded="" aria-label={t('admin.dlp.json.title')}>
        <Eyebrow label="admin.dlp.json.title" />
        <p className="adm-muted">{t('admin.dlp.json.note')}</p>
        <pre className="adm-json" tabIndex={0} aria-label={t('admin.dlp.json.label')}>
          {JSON.stringify(toWire(draft), null, 2)}
        </pre>
      </section>
    </div>
  );
}
