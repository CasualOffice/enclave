import { useCallback, useMemo, useRef, useState } from 'react';
import { BUILT, type BindingId } from '../shared/keyboard/bindings.ts';
import { requestFocus } from '../shared/keyboard/focus-bus.ts';
import { useKeyBindings } from '../shared/keyboard/use-key-bindings.ts';
import { CommandPalette, type Command } from '../shared/keyboard/command-palette.tsx';
import { ShortcutSheet } from '../shared/keyboard/shortcut-sheet.tsx';
import { navigate } from './routes.ts';

/* The bindings that belong to no screen: `⌘K`, `/`, `?` and the registered-but
 * -inert `⌘J`.
 *
 * The grid owns `↑ ↓ → ← Enter Space J K ⌘A` because they only mean something
 * inside it (`shared/list/use-grid-keyboard.ts`), and the library screen owns
 * `I`, `⌘\` and `Esc` because those act on the details panel, whose state it
 * holds. The split is not tidiness: a global `↑` handler steals the arrow keys
 * from every combo box and text field on the page, and a global `I` handler
 * could only reach the panel by writing a sentinel into a URL that
 * `docs/09 §3` promises is shareable.
 *
 * Nothing here is dispatched for a binding `bindings.ts` marks unbuilt — the
 * table is the single source, so deferring a binding is one edit and cannot
 * leave a handler behind.
 */

const built = (id: BindingId): boolean => BUILT.has(id);

/**
 * The two dialogs, and the commands the palette offers.
 *
 * Rendered by the shell so they survive a route change: a palette that
 * unmounted itself on navigation would close halfway through the navigation it
 * had just started.
 */
export function KeyboardSurfaces() {
  const [palette, setPalette] = useState(false);
  const [shortcuts, setShortcuts] = useState(false);
  /** Where focus was when a dialog opened — `docs/09 §6`'s last paragraph. */
  const opener = useRef<HTMLElement | null>(null);

  const open = useCallback((which: 'palette' | 'shortcuts') => {
    opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (which === 'palette') setPalette(true);
    else setShortcuts(true);
  }, []);

  /* "Focus returns to the triggering element when a dialog closes"
   * (`docs/09 §6`). Without it, closing the palette drops the user on `<body>`
   * and their next `Tab` restarts from the top of the page — the same ejection
   * the grid's `onBlur` rescue prevents, one layer up. `isConnected` because
   * the element that opened the dialog may have been a row that has since been
   * scrolled out of the window. */
  const restore = useCallback(() => {
    const node = opener.current;
    opener.current = null;
    if (node !== null && node.isConnected) node.focus();
  }, []);

  const closePalette = useCallback(() => {
    setPalette(false);
    restore();
  }, [restore]);

  const closeShortcuts = useCallback(() => {
    setShortcuts(false);
    restore();
  }, [restore]);

  useKeyBindings(
    useMemo(
      () => ({
        'mod+k': (event: KeyboardEvent) => {
          if (!built('palette')) return;
          event.preventDefault();
          open('palette');
        },
        /* `?` — the shortcut reference. The *character* is matched rather than
         * the physical key, so it works on a layout where `?` is unshifted. */
        '?': (event: KeyboardEvent) => {
          if (!built('help')) return;
          event.preventDefault();
          open('shortcuts');
        },
        /* `/` — focus search. On the search screen the field is already there;
         * anywhere else the screen has to exist before it can be focused, so
         * this navigates and the field claims focus on mount. `requestFocus`
         * reports whether anything was listening, which is what tells those two
         * cases apart — a silent no-op would make `/` work on one route of six.
         */
        '/': (event: KeyboardEvent) => {
          if (!built('focusSearch')) return;
          event.preventDefault();
          if (!requestFocus('search')) navigate('search');
        },
        /* `⌘J` — Ask, **registered and disabled until M7** (`docs/09 §6`,
         * `plans/M5-MVP-GA.md` D33). Present so the table has a handler slot
         * for it and so a reader can see the decision, and deliberately
         * *without* `preventDefault`: swallowing a key in order to do nothing
         * takes it from the browser as well as from the product. */
        'mod+j': () => undefined,
      }),
      [open],
    ),
  );

  const commands = useMemo<readonly Command[]>(
    () => [
      { id: 'nav-home', label: 'nav.home', icon: 'home', run: () => navigate('home') },
      { id: 'nav-files', label: 'nav.files', icon: 'folder', run: () => navigate('library') },
      {
        id: 'nav-search',
        label: 'nav.search',
        icon: 's',
        shortcut: 'key.slash',
        run: () => navigate('search'),
      },
      { id: 'nav-admin', label: 'nav.admin', icon: 'shield', run: () => navigate('admin') },
      {
        id: 'shortcuts',
        label: 'kbd.action.help',
        icon: 'info',
        shortcut: 'key.question',
        run: () => open('shortcuts'),
      },
      /* `docs/09 §5` puts "actions on the current selection" in the palette.
       * The endpoints do not exist, so they are listed **disabled, with their
       * shortcut**, rather than omitted: §5's other sentence is that the
       * palette is how users learn the shortcuts, and a command that appears
       * only once it works teaches nobody. An undefined `run` is the unbuilt
       * treatment — never the denial one, because nothing has been refused. */
      {
        id: 'file-actions',
        label: 'kbd.action.fileActions',
        icon: 'more',
        shortcut: 'key.rmcs',
        note: 'kbd.note.fileActions',
      },
      {
        id: 'trash',
        label: 'kbd.action.trash',
        icon: 'trash',
        shortcut: 'key.delete',
        note: 'kbd.note.trash',
      },
      {
        id: 'ask',
        label: 'kbd.action.ask',
        icon: 'spark',
        shortcut: 'key.commandJ',
        note: 'kbd.note.ask',
      },
    ],
    [open],
  );

  return (
    <>
      {palette && (
        <CommandPalette
          commands={commands}
          onClose={closePalette}
          onSearch={(query) => navigate('search', { q: query })}
        />
      )}
      {shortcuts && <ShortcutSheet onClose={closeShortcuts} />}
    </>
  );
}
