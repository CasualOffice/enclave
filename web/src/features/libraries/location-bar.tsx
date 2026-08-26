import { useT } from '../../shared/i18n/index.tsx';
import { Avatar, AvatarStack, IconButton } from '../../shared/ui/primitives.tsx';
import { ClassificationChip } from '../../entities/classification/chip.tsx';
import type { ClassificationLevel } from '../../entities/classification/model.ts';
import type { Crumb, PresenceMember } from './model.ts';

/* The location bar — the first 38 px of the sheet.
 *
 * `web/design-system/specs/library.md §1`, read against the rendered prototype:
 * breadcrumb, the folder's classification chip, then a trailing cluster of
 * presence avatars, `Share`, the details toggle and the folder overflow.
 *
 * It answers "where am I and how sensitive is it" before the user reads a
 * single row, which is why the classification chip is here and not only on the
 * rows: a folder inherits a label and the rows may each carry a different one.
 */

export interface LocationBarProps {
  readonly crumbs: readonly Crumb[];
  readonly classification: ClassificationLevel;
  readonly presence: readonly PresenceMember[];
  readonly peekOpen: boolean;
  readonly onTogglePeek: () => void;
}

/** How many avatars fit before the stack collapses to `+N` (`specs §1.3`). */
const PRESENCE_SHOWN = 3;

export function LocationBar({
  crumbs,
  classification,
  presence,
  peekOpen,
  onTogglePeek,
}: LocationBarProps) {
  const t = useT();
  const shown = presence.slice(0, PRESENCE_SHOWN);
  const overflow = presence.length - shown.length;

  return (
    <div className="lib-locationbar">
      <nav aria-label={t('library.breadcrumb.label')}>
        <ol className="lib-crumbs">
          {crumbs.map((crumb, index) => (
            <li key={crumb.id}>
              {index === crumbs.length - 1 ? (
                /* The current folder is not a link — there is nowhere to go —
                 * and `aria-current` is what tells a screen reader which of the
                 * crumbs it is standing in. */
                <span aria-current="page" dir="auto">
                  {crumb.name}
                </span>
              ) : (
                <a href="#" dir="auto">
                  {crumb.name}
                </a>
              )}
            </li>
          ))}
        </ol>
      </nav>

      <ClassificationChip level={classification} className="lib-crumb-chip" />

      <div className="lib-locationbar-end">
        {presence.length > 0 && (
          <AvatarStack>
            {shown.map((member) => (
              <Avatar key={member.id} initials={member.initials} tone={member.tone} />
            ))}
          </AvatarStack>
        )}
        {/* The count, not the initials: `+2` is a number and goes through
         * `Intl` in the message rather than being pasted next to a `+`. */}
        {overflow > 0 && (
          <span className="lib-presence-more">
            {t('library.presence.more', { count: overflow })}
          </span>
        )}

        <button type="button" className="lib-textbtn">
          {t('library.action.share')}
        </button>

        <IconButton
          name="side"
          label="library.action.toggleDetails"
          aria-pressed={peekOpen}
          onClick={onTogglePeek}
        />
        <IconButton name="more" label="library.action.folderMenu" />
      </div>
    </div>
  );
}
