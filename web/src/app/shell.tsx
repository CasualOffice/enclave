import type { ReactNode } from 'react';
import { useLocale, useT } from '../shared/i18n/index.tsx';
import { initialsOf, toneOf } from '../entities/user/model.ts';
import { signOut } from '../features/auth/sign-out.ts';
import { UploadTray } from '../features/upload/upload-tray.tsx';
import { useViewer } from '../entities/user/viewer.tsx';
import { Icon, type IconName } from '../shared/ui/icon-sprite.tsx';
import { Mark } from '../shared/ui/mark.tsx';
import { Avatar, Kbd, LaterChip } from '../shared/ui/primitives.tsx';
import { Push, Row, Truncate } from '../shared/ui/layout.tsx';
import type { MessageKey } from '../shared/i18n/catalog.ts';
import { navigate, useRoute, type RouteName } from './routes.ts';
import { useThemeStore } from './theme-store.ts';
import './shell.css';

/* The shell: a 232 px borderless sidebar on the canvas, and one raised sheet.
 *
 * `docs/09 §3` after `ENC-676`: **there is no top bar.** The workspace
 * switcher, search and the user chip are in the sidebar; `+ New` is in the view
 * bar beside the content it creates.
 *
 * The shell persists across navigation and only the sheet's contents swap, so
 * scroll position, selection and expansion survive back/forward — which is a
 * requirement (`docs/09 §3`) and the reason those three live in a store outside
 * the component tree rather than in `useState`.
 */

interface NavItem {
  readonly label: MessageKey;
  readonly icon: IconName;
  readonly route?: RouteName;
  /** A keyboard shortcut, shown so users learn it (`docs/09 §5`). A catalog key:
   *  a key cap reads 'Ctrl+K' on Windows and the modifier glyph is not universal. */
  readonly shortcut?: MessageKey;
  readonly trailing?: string;
  /**
   * `docs/09 §5` and `plans/M5-MVP-GA.md` D33: a surface the product does not
   * have yet is shown, **not focusable**, and marked with a neutral `Later`
   * chip. It never uses the denial treatment, because a user who learns that
   * dimmed means "not written yet" stops reading the one place it means "DLP
   * refused this".
   */
  readonly unbuilt?: boolean;
  readonly nested?: boolean;
  /** A library's classification dot. Reinforcement only; the row badges carry text. */
  readonly dot?: string;
}

/* The signed-in user now comes from `GET /api/v1/me` through `useViewer()`.
 *
 * The fixture that used to sit here read `Priya Nair`, and it was the last
 * thing in the shell that was not a fact. Initials are derived with
 * `Intl.Segmenter` in `entities/user/model.ts` rather than by splitting on
 * whitespace, because name order is not universal (`docs/14 §6`): splitting
 * yields "NP" for one culture and "PN" for another for the same person, and it
 * produces nonsense for scripts that do not use spaces at all.
 */

const PRIMARY: readonly NavItem[] = [
  { label: 'nav.search', icon: 's', route: 'search', shortcut: 'key.commandK' },
  { label: 'nav.inbox', icon: 'inbox', unbuilt: true },
  { label: 'nav.home', icon: 'home', route: 'home' },
  { label: 'nav.ask', icon: 'spark', route: 'ask', shortcut: 'key.commandJ' },
];

const WORKSPACE: readonly NavItem[] = [
  { label: 'nav.files', icon: 'folder', route: 'library' },
  { label: 'nav.lists', icon: 'list', unbuilt: true },
  { label: 'nav.pages', icon: 'page', unbuilt: true },
  { label: 'nav.activity', icon: 'act', unbuilt: true },
];

const PERSONAL: readonly NavItem[] = [
  { label: 'nav.favorites', icon: 'star', unbuilt: true },
  { label: 'nav.shared', icon: 'share', unbuilt: true },
  { label: 'nav.trash', icon: 'trash', unbuilt: true },
];

function NavLink({ item }: { item: NavItem }) {
  const t = useT();
  const route = useRoute();
  const current = item.route !== undefined && route.name === item.route;
  const label = t(item.label);

  if (item.unbuilt === true) {
    return (
      /* Not focusable, and `Row` renders it as a `<span>` rather than as a
       * `<button tabindex="-1">` — the honest form, because a button taken out
       * of the tab order is still announced as a control and is still reachable
       * through a screen reader's rotor, which does not consult `tabindex`.
       *
       * There is no `opacity` here and no danger tint. This copy carried
       * `style={{ opacity: 0.5 }}` inline while the two other copies of the same
       * treatment deliberately did not, which is precisely the drift
       * `docs/17 §6` forbids: the unbuilt treatment may not vary by screen. */
      <Row unbuilt indent={item.nested === true}>
        <Icon name={item.icon} />
        <Truncate>{label}</Truncate>
        <Push />
        <LaterChip note="later.chip" />
      </Row>
    );
  }

  return (
    <Row
      current={current}
      indent={item.nested === true}
      onClick={() => {
        if (item.route !== undefined) navigate(item.route);
      }}
    >
      {item.dot === undefined ? (
        <Icon name={item.icon} />
      ) : (
        <span className="shell-lib-dot" style={{ background: item.dot }} aria-hidden="true" />
      )}
      <Truncate>{label}</Truncate>
      {item.shortcut !== undefined && (
        <>
          <Push />
          <span className="shell-navlink-trailing">
            <Kbd>{t(item.shortcut)}</Kbd>
          </span>
        </>
      )}
      {item.trailing !== undefined && (
        <>
          <Push />
          <span className="shell-navlink-trailing">{item.trailing}</span>
        </>
      )}
    </Row>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const t = useT();
  const viewer = useViewer();
  const locale = useLocale();
  const theme = useThemeStore((state) => state.theme);
  const setTheme = useThemeStore((state) => state.setTheme);
  const initials = initialsOf(viewer.displayName, locale);

  return (
    <div className="shell">
      <nav className="shell-nav" aria-label={t('app.brand')}>
        <div className="shell-brand">
          <Row aria-label={t('nav.workspaceSwitcher')}>
            <Mark size={18} />
            <span className="shell-brand-name">{t('app.brand')}</span>
            <Push />
            <Icon name="updown" />
          </Row>
        </div>

        {PRIMARY.map((item) => (
          <NavLink key={item.label} item={item} />
        ))}

        <div className="shell-navgroup">
          <Icon name="chev" size={10} />
          {t('nav.files')}
        </div>
        {WORKSPACE.map((item) => (
          <NavLink key={item.label} item={item} />
        ))}

        <div className="shell-navgroup">
          <Icon name="chev" size={10} />
          {t('nav.section.personal')}
        </div>
        {PERSONAL.map((item) => (
          <NavLink key={item.label} item={item} />
        ))}

        {/* Administration, shown to administrators.
         *
         * **This is navigation, not authorization.** `docs/17 §1`: the server
         * decides. Every admin route runs the policy chain and answers `403` or
         * `STEP_UP_REQUIRED` on its own authority, so hiding the entry from a
         * non-admin is a courtesy — it keeps a door out of sight that would not
         * open — and showing it to one would not be a vulnerability. The
         * distinction matters because the moment this reads as *enforcement*,
         * someone will be tempted to drop the server-side check it duplicates. */}
        {viewer.isAdmin && (
          <>
            <div className="shell-navgroup">
              <Icon name="chev" size={10} />
              {t('nav.section.admin')}
            </div>
            <NavLink item={{ label: 'nav.admin', icon: 'shield', route: 'admin' }} />
          </>
        )}

        <div className="shell-nav-foot">
          <Row
            aria-label={t('nav.signOut')}
            onClick={() => {
              void signOut();
            }}
          >
            <Avatar initials={initials} tone={toneOf(viewer.id)} />
            {/* A person's name is data, not a message. `docs/14 §6`: display the
             * full name as provided, never assume given-name-first ordering and
             * never split on whitespace — which also means it never goes in the
             * catalog, because there is nothing to translate. */}
            <Truncate>
              <bdi dir="auto">{viewer.displayName}</bdi>
            </Truncate>
          </Row>
          <div className="shell-prefs">
            {/* `.ui-tab` for the pill, `aria-pressed` for the semantics. The
              * third copy of this toggle's 16 lines is gone; what it is *not*
              * is a `<Tab>`, because nothing here controls a tabpanel and
              * announcing "tab" for a theme switch would be untrue. */}
            <span className="shell-seg" role="group" aria-label={t('theme.light')}>
              <button
                type="button"
                className="ui-tab"
                aria-pressed={theme === 'light'}
                onClick={() => setTheme('light')}
              >
                {t('theme.light')}
              </button>
              <button
                type="button"
                className="ui-tab"
                aria-pressed={theme === 'dark'}
                onClick={() => setTheme('dark')}
              >
                {t('theme.dark')}
              </button>
            </span>
          </div>
        </div>
      </nav>

      <main className="shell-sheet">
        {children}
        {/* The tray lives in the shell, not in the library screen.
         *
         * `docs/09 §8`: uploads keep running across navigation. A tray rendered
         * by the screen that started it would vanish the moment the user opened
         * Search, and the transfer would continue with nothing on screen saying
         * so. It renders nothing when the queue is empty. */}
        <UploadTray />
      </main>
    </div>
  );
}
