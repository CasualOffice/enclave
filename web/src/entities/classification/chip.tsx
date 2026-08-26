import { useT } from '../../shared/i18n/index.tsx';
import { CLASSIFICATION_KEY, type ClassificationLevel } from './model.ts';
import './chip.css';

/* The sensitivity badge, in one place.
 *
 * It lived in three (`ENC-703`): the list drew `.egl-classification`, search
 * drew `.esr-classification` and home drew `.home-classification`, each with its
 * own copy of the same `color-mix` percentages. Three copies of a **locked**
 * palette is three chances for one of them to drift, and `docs/09 §16a` is
 * explicit that a tenant may not recolour Restricted — which is a promise the
 * product can only keep if there is one place the colour is written.
 *
 * The list is repointed here with this change. Search and home are `ENC-703`'s
 * to move; adding a fourth copy for the location bar and the peek panel is what
 * this component exists to avoid.
 *
 * Colour is never the only carrier (`docs/09 §15`): the label text is always
 * rendered, and the level is turned into words through `CLASSIFICATION_KEY` so
 * no component can name a level with a literal.
 */
export function ClassificationChip({
  level,
  className,
}: {
  readonly level: ClassificationLevel;
  /** For a caller that owns the cell the chip sits in — never for restyling it. */
  readonly className?: string;
}) {
  const t = useT();
  return (
    <span
      className={className === undefined ? 'cls-chip' : `cls-chip ${className}`}
      data-level={level}
    >
      {t(CLASSIFICATION_KEY[level])}
    </span>
  );
}
