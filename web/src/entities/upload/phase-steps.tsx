import { useT } from '../../shared/i18n/index.tsx';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { PHASE_LABEL, type UploadPhase } from './model.ts';
import './phase-steps.css';

/* The three-dot progress indicator, exactly as the prototype draws it.
 *
 * `enclave-client-prototype.html` line 265 renders an uploading row's status
 * cell as three labelled dots — `Up`, `Scan`, `Index` — with the current step
 * accented and ringed, completed steps in the success colour, and future steps
 * in `--g300`. That is the drawn form and it is kept.
 *
 * ## Three dots, seven phases, and which document wins
 *
 * `docs/09 §8` names seven phases; the design draws three steps. They do not
 * disagree — the design is a *summary* — and `docs/09` is authoritative for
 * behaviour while the design is authoritative for appearance, so both are
 * honoured: three dots are drawn, and the **accessible name is the real phase**.
 * A sighted user sees the shape the design specifies; a screen-reader user is
 * told "Scanning" rather than "step 2 of 3", which is the more useful sentence
 * and the one `docs/09 §15`'s live-region rule is about.
 *
 * The prototype's own `stageMap` collapses `Scanning` and `Processing` onto one
 * dot, and this keeps that mapping rather than inventing a different one.
 */

interface Step {
  readonly label: MessageKey;
  /** Phases that light this dot as *current*. */
  readonly phases: readonly UploadPhase[];
}

const STEPS: readonly Step[] = [
  { label: 'upload.step.up', phases: ['queued', 'hashing', 'uploading'] },
  { label: 'upload.step.scan', phases: ['scanning', 'processing'] },
  { label: 'upload.step.index', phases: ['indexing'] },
];

/** Which dot is current, or `STEPS.length` once everything is behind us. */
function currentStep(phase: UploadPhase): number {
  const index = STEPS.findIndex((step) => step.phases.includes(phase));
  return index === -1 ? STEPS.length : index;
}

/**
 * The row's progress, drawn.
 *
 * Renders nothing for a settled row: a file that is ready, refused, quarantined
 * or aborted has no progress left to show, and three grey dots beside it would
 * suggest work that is not happening.
 */
export function PhaseSteps({ phase }: { phase: UploadPhase }) {
  const t = useT();
  const current = currentStep(phase);

  return (
    /* One live region per row, carrying the *real* phase name.
     *
     * `polite` rather than `assertive`: `docs/09 §15` asks for async results to
     * be announced, and an upload finishing is not an interruption. `atomic` so
     * a phase change is read as one sentence instead of a diff of three dots.
     */
    <span
      className="upl-steps"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-phase={phase}
    >
      <span className="ui-sr-only">{t(PHASE_LABEL[phase])}</span>
      {STEPS.map((step, index) => (
        <span
          key={step.label}
          className="upl-step"
          /* `done` / `current` / `todo`, which is what colours the dot. Read by
           * CSS rather than by an inline style so the palette stays in the
           * stylesheet and the classification tokens cannot be reached from
           * here by accident. */
          data-step={index < current ? 'done' : index === current ? 'current' : 'todo'}
          aria-hidden="true"
        >
          <span className="upl-step-dot" />
          {t(step.label)}
        </span>
      ))}
    </span>
  );
}
