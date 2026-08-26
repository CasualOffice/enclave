import { useT } from '../../shared/i18n/index.tsx';
import { useRichT } from '../../shared/i18n/rich-text.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import type { ActiveFilter } from './model.ts';

/* The applied-filter row. Rendered only when a filter is active — an empty chip
 * row is 32 px of chrome saying nothing, and idle is zero chrome.
 *
 * Each chip is three segments (key · value · remove) with 1 px dividers drawn by
 * a pseudo-element rather than `border-inline-end`: a border consumes layout
 * width and would shift the 24 px chip's text by a pixel, which the prototype's
 * inset shadow did not (`specs/library.md`, technique fix #2).
 */

export interface FilterChipRowProps {
  readonly filters: readonly ActiveFilter[];
  readonly onRemove: (id: string) => void;
  /** The server's rendering of the current grouping and sort. Data, not messages. */
  readonly groupBy: string;
  readonly sortBy: string;
}

export function FilterChipRow({ filters, onRemove, groupBy, sortBy }: FilterChipRowProps) {
  const t = useT();
  const rich = useRichT();
  if (filters.length === 0) return null;

  return (
    <div className="lib-chiprow">
      {filters.map((filter) => (
        <span key={filter.id} className="lib-chip">
          <span className="lib-chip-seg lib-chip-key">{t(filter.facet)}</span>
          <span className="lib-chip-seg lib-chip-value" dir="auto">
            {filter.value}
          </span>
          <button
            type="button"
            className="lib-chip-remove"
            aria-label={t('library.filters.remove', { facet: t(filter.facet) })}
            onClick={() => onRemove(filter.id)}
          >
            {/* The sprite `×`, not the character: a glyph in markup becomes a
             * translatable string and does not inherit `currentColor`. */}
            <Icon name="x" size={10} />
          </button>
        </span>
      ))}

      {/* One ICU message with two placeholders — never `'Group by ' + groupBy`,
       * which fixes English word order into the code. The emphasised parts are
       * nodes, so the translator moves them and the styling follows. */}
      <span className="lib-chip-summary">
        {rich('library.viewSummary', {
          groupBy: <b key="g">{groupBy}</b>,
          sortBy: <b key="s">{sortBy}</b>,
        })}
      </span>
    </div>
  );
}
