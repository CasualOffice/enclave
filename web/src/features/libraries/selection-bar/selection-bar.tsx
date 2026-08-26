import { useT } from '../../../shared/i18n/index.tsx';
import { Icon, type IconName } from '../../../shared/ui/icon-sprite.tsx';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';

/* The floating selection bar.
 *
 * This is what "idle is zero chrome" costs: there is no persistent command bar
 * anywhere in the product, so every action on a set of files lives here, and
 * the bar exists **only** while something is selected. `docs/09 §3`, and the
 * prototype's whole shape.
 *
 * Two things about it are not styling.
 *
 * **Centring.** `inset-inline:0; margin-inline:auto; inline-size:max-content`,
 * never the prototype's `left:50%` + `translateX(-50%)`. That pairing is doubly
 * wrong under RTL — `inset-inline-start:50%` measures from the opposite edge
 * while the transform still pulls toward physical left — and it also fights the
 * entrance animation, which then has to carry the centring in every keyframe.
 *
 * **Download is DENIED, not dimmed.** The prototype renders it at `opacity:.4`
 * with `cursor:not-allowed` and a `title` explaining the policy. That is wrong
 * three times: it borrows the unbuilt visual for a refusal (`ENC-673`), the
 * sentence is invented client side when only the server may author a policy
 * explanation (`docs/17 §1`), and a `title` is unreachable by keyboard. Until
 * `ENC-674` attaches a reason to each false capability, it renders in the denied
 * treatment with **no sentence at all** — `docs/09 §5` is explicit that an
 * invented explanation is worse than none.
 */

export interface SelectionAction {
  readonly id: string;
  readonly label: MessageKey;
  readonly icon?: IconName;
  readonly shortcut?: MessageKey;
  /**
   * `false` when the intersection of the selection's server-sent capabilities
   * says so. An AND over booleans the server sent is not re-deriving a
   * permission; inferring one from a role would be.
   */
  readonly allowed: boolean;
}

export interface SelectionBarProps {
  readonly count: number;
  readonly actions: readonly SelectionAction[];
  readonly onClear: () => void;
}

export function SelectionBar({ count, actions, onClear }: SelectionBarProps) {
  const t = useT();
  if (count === 0) return null;

  return (
    <div className="selbar" role="toolbar" aria-label={t('library.selection.toolbar')}>
      <span className="selbar-count">
        {/* An ICU plural, not `${n} file${n>1?'s':''}`. Languages with three or
         * more plural categories break the ternary outright (`docs/14 §4`). */}
        {t('library.selection.count', { count })}
        <i className="selbar-divider" aria-hidden="true" />
      </span>

      {actions.map((action) => (
        <button
          key={action.id}
          type="button"
          className="selbar-action"
          /* Never the `disabled` attribute: a disabled control leaves the tab
           * order, so a keyboard user cannot reach it to find out why — which is
           * the entire reason a denied action is shown rather than hidden. */
          data-state={action.allowed ? undefined : 'denied'}
          aria-disabled={action.allowed ? undefined : true}
        >
          {action.icon !== undefined && <Icon name={action.icon} />}
          {t(action.label)}
          {action.shortcut !== undefined && (
            <span className="selbar-kbd">{t(action.shortcut)}</span>
          )}
          {/* The denial marker. No sentence — `ENC-674` owns the reason field,
           * and until it lands an invented one would be a second authority. */}
          {!action.allowed && <Icon name="block" size={11} />}
        </button>
      ))}

      <button
        type="button"
        className="selbar-action selbar-clear"
        aria-label={t('library.selection.clear')}
        onClick={onClear}
      >
        <Icon name="x" />
      </button>
    </div>
  );
}
