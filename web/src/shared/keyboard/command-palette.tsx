import { useEffect, useMemo, useRef, useState } from 'react';
import { useT } from '../i18n/index.tsx';
import type { MessageKey } from '../i18n/catalog.ts';
import { Kbd, LaterChip } from '../ui/primitives.tsx';
import { Icon, type IconName } from '../ui/icon-sprite.tsx';
import './keyboard.css';

/* `⌘K` — the command palette (`docs/09 §5`).
 *
 * ## What it holds, and what it does not
 *
 * §5 says the palette spans "navigation, actions on the current selection,
 * recent files and search". Two of those four exist today and two do not, and
 * the palette says which is which rather than quietly shipping half a feature:
 *
 *   - **navigation** — the six routes `app/routes.ts` registers. Real.
 *   - **search** — the query is handed to `/search`, which is a built screen
 *     against a built endpoint. Real.
 *   - **actions on the selection** — rename, move, copy, share and trash have
 *     no endpoint (`bindings.ts`). They appear under the unbuilt treatment with
 *     their shortcut, because §5's other requirement is that "every command in
 *     the palette shows its keyboard shortcut, which is how users learn them",
 *     and a command hidden until it works teaches nobody anything.
 *   - **recent files** — no endpoint returns them. Absent rather than faked; a
 *     list of recent files assembled client-side from whatever happens to be in
 *     the query cache is a different claim from "these are your recent files".
 *
 * ## Why the commands are a prop
 *
 * This component lives in `shared/` and navigation lives in `app/`
 * (`docs/17 §2`: imports go downward only). The palette therefore knows how to
 * *present* and *filter* commands and nothing about where they go; `app/`
 * supplies the list. That is also what makes it testable without a router.
 *
 * ## The states
 *
 * Resting (every command), filtered (the matches), and no-match — which is a
 * real empty state with the one action that still applies, searching the corpus
 * for what was typed. There is no loading or error state because the palette
 * issues no request: filtering is a substring test over an array that is
 * already in memory. Inventing a spinner for it would be the same untruth as an
 * error state that cannot fire.
 */

export interface Command {
  readonly id: string;
  readonly label: MessageKey;
  readonly icon: IconName;
  /** The shortcut to advertise, if this command has one (`docs/09 §5`). */
  readonly shortcut?: MessageKey;
  /** `undefined` means the command is not built; the palette shows it, disabled. */
  readonly run?: (() => void) | undefined;
  /** Why it is not built. Read only when `run` is undefined. */
  readonly note?: MessageKey;
}

export function CommandPalette({
  commands,
  onClose,
  onSearch,
}: {
  commands: readonly Command[];
  onClose: () => void;
  /** Run a full search for the typed text — the fallback when nothing matches. */
  onSearch: (query: string) => void;
}) {
  const t = useT();
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  /* Matched on the **rendered** label rather than on the catalog key.
   *
   * A user types what they can see. Filtering on `nav.files` would match "nav"
   * and would not match "Fichiers" in French — the palette would be searchable
   * only in English, by people who had read the source. `useT` is the one way a
   * string reaches a component, so it is also the only honest thing to match. */
  const matches = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    if (needle.length === 0) return commands;
    return commands.filter((command) => t(command.label).toLocaleLowerCase().includes(needle));
  }, [commands, query, t]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  const runActive = () => {
    const command = matches[active];
    if (command?.run !== undefined) {
      command.run();
      onClose();
      return;
    }
    /* Nothing matched, or the highlighted command is not built. Either way the
     * typed text is still a search, which is the one thing the palette can
     * always do with it. */
    if (command === undefined && query.trim().length > 0) {
      onSearch(query.trim());
      onClose();
    }
  };

  return (
    <div className="kbd-scrim" data-surface="palette">
      <div
        className="kbd-palette enc-enter-pop"
        role="dialog"
        aria-modal="true"
        aria-label={t('palette.label')}
        ref={dialogRef}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            onClose();
          } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            setActive((current) => Math.min(current + 1, Math.max(0, matches.length - 1)));
          } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            setActive((current) => Math.max(0, current - 1));
          } else if (event.key === 'Enter') {
            event.preventDefault();
            runActive();
          }
        }}
      >
        {/* A combobox over a listbox, which is what this is: the field owns
          * focus the whole time and `aria-activedescendant` moves the *virtual*
          * cursor, so `↑`/`↓` select a command without taking focus out of the
          * text the user is still typing. Moving real DOM focus to the option
          * would stop the next keystroke reaching the field. */}
        <input
          ref={inputRef}
          className="kbd-palette-input"
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-list"
          aria-autocomplete="list"
          aria-activedescendant={matches[active] === undefined ? undefined : `palette-${matches[active].id}`}
          aria-label={t('palette.input.label')}
          placeholder={t('palette.input.placeholder')}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />

        <ul className="kbd-palette-list" role="listbox" id="palette-list" aria-label={t('palette.label')}>
          {matches.map((command, index) => {
            const built = command.run !== undefined;
            return (
              <li
                key={command.id}
                id={`palette-${command.id}`}
                role="option"
                aria-selected={index === active}
                aria-disabled={built ? undefined : true}
                data-state={built ? 'ready' : 'later'}
                className="kbd-palette-item"
                onClick={() => {
                  if (built) {
                    command.run?.();
                    onClose();
                  }
                }}
              >
                <Icon name={command.icon} />
                <span className="kbd-palette-label">{t(command.label)}</span>
                {!built && (
                  <>
                    <LaterChip note="later.chip" />
                    {command.note !== undefined && (
                      <span className="ui-sr-only">{t(command.note)}</span>
                    )}
                  </>
                )}
                {command.shortcut !== undefined && (
                  <span className="kbd-palette-key">
                    <Kbd>{t(command.shortcut)}</Kbd>
                  </span>
                )}
              </li>
            );
          })}
        </ul>

        {/* The empty state. Not "no results" and stop: what the user typed is
          * still a search, and offering it is the one action `docs/09 §11`
          * asks an empty state to carry. */}
        {matches.length === 0 && (
          <div className="kbd-palette-empty" data-state="filtered-empty">
            <p>{t('palette.empty', { query: query.trim() })}</p>
            <button
              type="button"
              className="ui-btn"
              onClick={() => {
                onSearch(query.trim());
                onClose();
              }}
            >
              {t('palette.empty.search')}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
