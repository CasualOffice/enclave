/* The upload domain's public surface.
 *
 * It sits in `entities/` rather than `features/upload/` for the reason
 * `docs/17 §2` gives: **two features need it**, and a feature may never import
 * another feature. `features/libraries` renders an upload as a row in its list,
 * exactly as the prototype draws it, and `features/upload` owns the tray and
 * the drop target. When two features need the same thing it moves down — so it
 * did, rather than one importing the other or both keeping a copy that drifts.
 *
 * The UI that knows what an upload *is* lives here too (`phase-steps.tsx`),
 * which is the same placement rule `docs/17 §11` states for classification:
 * `shared/ui` holds primitives with no domain knowledge, and a component that
 * understands a phase is not one of those.
 */

export {
  PHASE_LABEL,
  PHASE_TONE,
  isActive,
  isSettled,
  phaseFromVersion,
  unreadableNote,
  type PhaseTone,
  type UploadPhase,
} from './model.ts';

export { useUploadStore, type UploadRow } from './store.ts';

export { PhaseSteps } from './phase-steps.tsx';
