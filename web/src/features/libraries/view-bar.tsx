import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import type { SavedView } from './model.ts';

/* The view bar — 42 px, and the whole of the surface's idle chrome.
 *
 * `docs/09 §3` after `ENC-676` retired the top bar: there is no persistent
 * command bar anywhere in this product. Every action a folder offers is here,
 * in the row menu, or in the selection bar that exists only while something is
 * selected. That is the prototype's "idle is zero chrome", and it is the reason
 * `Upload` and `New` sit beside the content they create rather than above it.
 *
 * Geometry from `web/design-system/specs/library.md §2`.
 */

export interface ViewBarProps {
  readonly views: readonly SavedView[];
  readonly activeView: string;
  readonly onSelectView: (id: string) => void;
  readonly onUpload: () => void;
}

export function ViewBar({ views, activeView, onSelectView, onUpload }: ViewBarProps) {
  const t = useT();
  const formatters = useFormatters();

  return (
    <div className="lib-viewbar">
      <div className="lib-views" role="tablist" aria-label={t('library.views.label')}>
        {views.map((view) => (
          <button
            key={view.id}
            type="button"
            role="tab"
            className="lib-view"
            aria-selected={view.id === activeView}
            onClick={() => onSelectView(view.id)}
          >
            {t(view.label)}
            {/* Locale-grouped, because `1,284` is a locale decision and the
             * comma is wrong in most of Europe (`docs/14 §6`). */}
            <span className="lib-view-count">{formatters.count(view.count)}</span>
          </button>
        ))}
      </div>

      <div className="lib-viewbar-end">
        <button type="button" className="lib-toolbtn" aria-haspopup="dialog" aria-expanded={false}>
          <Icon name="filter" />
          {t('library.action.filter')}
        </button>
        <button type="button" className="lib-toolbtn" aria-haspopup="dialog" aria-expanded={false}>
          <Icon name="sliders" />
          {t('library.action.display')}
        </button>
        <button type="button" className="lib-toolbtn" onClick={onUpload}>
          <Icon name="up" />
          {t('library.action.upload')}
        </button>
        <button type="button" className="lib-newbtn" aria-haspopup="menu" aria-expanded={false}>
          <Icon name="plus" size={12} />
          {t('library.action.new')}
        </button>
      </div>
    </div>
  );
}
