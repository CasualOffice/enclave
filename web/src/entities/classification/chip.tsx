import { useT } from '../../shared/i18n/index.tsx';
import { CLASSIFICATION_KEY, type ClassificationLevel } from './model.ts';
import './chip.css';

/* The classification badge. **One implementation, and it must stay one.**
 *
 * There were four — `.egl-classification`, `.home-classification`,
 * `.esr-classification`, `.adm-classification` — each repeating the pill, the
 * dot, the five `--cc` bindings and the `color-mix` recipe. Roughly 200 lines
 * of CSS for one 20px chip, and they had already drifted: the block sizes were
 * 20, 20, 18 and 22px, the dots 6, 6, 5 and 6px, the type 11, 11, 10.5 and 11px,
 * and three of the four carried an `unclassified` branch while the fourth did
 * not.
 *
 * That drift is the argument. `docs/09 §16a` locks the classification palette
 * because *"a tenant recolouring Restricted to match its palette is a tenant
 * whose users misread sensitivity at a glance"* — and four copies of the badge
 * is the same failure arriving from inside: a user who learns Restricted's
 * exact shade on the library list should read it identically on search results
 * and on the admin screen, and four hand-maintained copies cannot promise that.
 * Locking the token and duplicating the component locks nothing.
 *
 * It lives in `entities/classification` and not in `shared/ui` because it knows
 * what a classification is (`docs/17 §11`).
 *
 * ## Colour is never the only carrier
 *
 * `docs/09 §15`: the chip always renders its label as text. The dot reinforces
 * a word that is already readable without it — remove the colour and the badge
 * still says "Restricted". There is no icon-only or dot-only variant and one
 * may not be added.
 */

export function ClassificationChip({
  level,
  size = 'sm',
}: {
  readonly level: ClassificationLevel;
  /**
   * `sm` is the 20px row and location-bar chip; `md` the 22px form for a peek
   * panel's pill row, where it sits beside status pills at the same height.
   *
   * Two sizes and no more. The four copies this replaces had arrived at four
   * heights by accident rather than by choice, which is the outcome an open
   * size prop reproduces.
   */
  readonly size?: 'sm' | 'md';
}) {
  const t = useT();
  return (
    <span className="ui-classification" data-level={level} data-size={size}>
      {t(CLASSIFICATION_KEY[level])}
    </span>
  );
}
