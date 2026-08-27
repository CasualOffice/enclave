import type { ReactNode } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';
import { Icon } from '../../../shared/ui/icon-sprite.tsx';
import { Kbd, LaterChip, Skeleton } from '../../../shared/ui/primitives.tsx';
import { PreviewTab } from './preview-tab.tsx';
import { FailureState } from '../../../shared/ui/surface-states.tsx';
import { failureOf } from '../../../shared/api/failure.ts';
import type {
  CapabilityName,
  FileDetail,
  VersionPage,
} from '../../../entities/file/api-model.ts';

/* The peek panel — `docs/09 §7`'s preview-before-open.
 *
 * 372 px at rest, floor 320, ceiling 520, and it is a **query parameter rather
 * than a route** (`docs/17 §5`): opening it must not unmount the list, because
 * a nested route would throw away the scroll position and the virtualization
 * window, which is the whole point of peeking instead of opening.
 *
 * It is deliberately **not a dialog**. No focus trap, no `role="dialog"`, no
 * inert background: the list stays interactive behind it, and walking rows
 * swaps the panel's content in place.
 */

/* The five tabs `docs/09 §7` names, and which of them the API can fill.
 *
 * Rendered **as drawn, under the unbuilt treatment** rather than omitted. A tab
 * strip missing three of its five tabs tells a user the product does not have
 * those ideas; a strip whose three are marked `Later` tells them it does not
 * have them *yet*, which is the true statement and the one D33 asks for.
 *
 * - `details`  — `GET /files/{id}`. Real.
 * - `versions` — `GET /files/{id}/versions`. Real.
 * - `preview`  — `GET /files/{id}/preview`. **Now real.** The binary composes
 *                an object store when `storage:` is configured, and the route
 *                answers PNG bytes for a readable `image/png|jpeg|webp`. It
 *                also answers 404 for a version rule 9 will not serve and 503
 *                for a media type with no renderer, and `preview-tab.tsx`
 *                tells those two apart rather than collapsing them into one
 *                error.
 * - `access`   — no ACL read endpoint is registered.
 * - `activity` — blocked on `docs/17` Q24: `audit_events` is hash-chained and
 *                deliberately not a user-facing feed (`CLAUDE.md` rule 10), so
 *                the tab cannot be built on it and must not be faked from it.
 */
const TABS = [
  { id: 'preview', label: 'library.peek.tab.preview', built: true },
  { id: 'details', label: 'library.peek.tab.details', built: true },
  { id: 'access', label: 'library.peek.tab.access', built: false },
  { id: 'versions', label: 'library.peek.tab.versions', built: true },
  { id: 'activity', label: 'library.peek.tab.activity', built: false },
] as const satisfies readonly { id: string; label: MessageKey; built: boolean }[];

type TabId = (typeof TABS)[number]['id'];

/** The tab ids, for validating the one that arrives from the URL. */
const TAB_IDS: readonly TabId[] = TABS.map((entry) => entry.id);

/** The unbuilt note for each tab that has no endpoint, naming *why* rather than shrugging. */
const UNBUILT_NOTE: Record<string, MessageKey> = {
  access: 'library.peek.tab.access.unbuilt',
  activity: 'library.peek.tab.activity.unbuilt',
};

/** The nine actions worth naming, in the order a user thinks about them. */
const CAPABILITY_LABELS: readonly (readonly [CapabilityName, MessageKey])[] = [
  ['preview', 'library.peek.cap.preview'],
  ['download', 'library.peek.cap.download'],
  ['print', 'library.peek.cap.print'],
  ['export', 'library.peek.cap.export'],
  ['edit', 'library.peek.cap.edit'],
  ['share', 'library.peek.cap.share'],
  ['shareExternal', 'library.peek.cap.shareExternal'],
  ['delete', 'library.peek.cap.delete'],
  ['sync', 'library.peek.cap.sync'],
];

export interface PeekNavigation {
  readonly onPrevious: () => void;
  readonly onNext: () => void;
  readonly hasPrevious: boolean;
  readonly hasNext: boolean;
}

function PeekChrome({
  title,
  onClose,
  navigation,
  children,
}: {
  title: string;
  onClose: () => void;
  navigation?: PeekNavigation | undefined;
  children: ReactNode;
}) {
  const t = useT();
  return (
    <aside className="library-peek" aria-label={t('library.peek.label')}>
      <div className="library-peek-head">
        {/* The Esc hint, shown so the shortcut is learned rather than
         * discovered. A key cap reads differently per platform, so the glyph
         * is a catalog string and not a literal. */}
        <span className="library-peek-hint">
          <Kbd>{t('key.escape')}</Kbd>
          {t('library.peek.escHint')}
        </span>
        <span className="library-peek-head-actions">
          {/* Previous and next walk the rows the list already has.
           *
           * This is **not** a permission decision and never consults
           * `capabilities`: it moves a query parameter across rows the server
           * has already returned and already filtered. Being at the end of the
           * list is a neutral disabled state, and it must not borrow the denial
           * treatment — there is nothing the user lacks permission to do. */}
          <button
            type="button"
            className="library-iconbtn"
            aria-label={t('library.peek.previous')}
            aria-disabled={navigation?.hasPrevious === false ? true : undefined}
            onClick={navigation?.hasPrevious === false ? undefined : navigation?.onPrevious}
          >
            <Icon name="chev" className="library-peek-chev-prev" />
          </button>
          <button
            type="button"
            className="library-iconbtn"
            aria-label={t('library.peek.next')}
            aria-disabled={navigation?.hasNext === false ? true : undefined}
            onClick={navigation?.hasNext === false ? undefined : navigation?.onNext}
          >
            <Icon name="chev" />
          </button>
          <button
            type="button"
            className="library-iconbtn"
            aria-label={t('library.peek.close')}
            onClick={onClose}
          >
            <Icon name="x" />
          </button>
        </span>
      </div>
      {/* `aria-live="polite"` on the title, so walking rows announces what the
       * panel now describes. Without it the panel changes silently and a
       * screen-reader user has no idea the content moved. */}
      <div className="library-peek-title">
        <h3 aria-live="polite">{title}</h3>
      </div>
      {children}
    </aside>
  );
}

/** The Versions tab, from `GET /files/{id}/versions`. */
function VersionList({ versions }: { versions: VersionPage | undefined }) {
  const t = useT();
  const formatters = useFormatters();

  if (versions === undefined) {
    return (
      <p className="library-peek-note" role="status" aria-busy="true">
        <Skeleton width="60%" />
      </p>
    );
  }

  if (versions.items.length === 0) {
    return <p className="library-peek-note">{t('library.peek.versions.none')}</p>;
  }

  return (
    <ul className="library-peek-versions">
      {versions.items.map((version) => {
        const created = new Date(version.createdAt);
        return (
          <li key={version.id} className="library-peek-version">
            <span className="library-peek-version-no">
              {t('library.peek.versions.number', { major: version.major, minor: version.minor })}
            </span>
            <span className="library-peek-version-meta">{formatters.bytes(version.sizeBytes)}</span>
            <time dateTime={created.toISOString()} className="library-peek-version-when">
              {formatters.relative(created)}
            </time>
            {/* `isReadable` is the server's answer to rule 9 — `AVAILABLE` and
             * `CLEAN` — and the client shows it rather than recomputing it from
             * the two status fields beside it. */}
            {!version.isReadable && (
              <span className="library-peek-version-unreadable">
                {t('library.peek.versions.unreadable')}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function DetailsTab({ detail }: { detail: FileDetail }) {
  const t = useT();
  const formatters = useFormatters();
  const modified = new Date(detail.modifiedAt);
  const created = new Date(detail.createdAt);

  return (
    <>
      <dl className="library-peek-facts">
        <dt>{t('library.peek.fact.status')}</dt>
        <dd>{t(`library.status.${detail.status}` as MessageKey)}</dd>

        <dt>{t('library.peek.fact.type')}</dt>
        <dd>{detail.mimeType}</dd>

        <dt>{t('library.peek.fact.size')}</dt>
        <dd>{formatters.bytes(detail.sizeBytes)}</dd>

        <dt>{t('library.peek.fact.modified')}</dt>
        <dd>
          <time dateTime={modified.toISOString()}>{formatters.dateTime(modified)}</time>
        </dd>

        <dt>{t('library.peek.fact.created')}</dt>
        <dd>
          <time dateTime={created.toISOString()}>{formatters.dateTime(created)}</time>
        </dd>

        <dt>{t('library.peek.fact.governance')}</dt>
        <dd>
          {t(
            detail.governance.onLegalHold
              ? 'library.peek.governance.hold'
              : detail.governance.isRecord
                ? 'library.peek.governance.record'
                : 'library.peek.governance.none',
          )}
        </dd>
      </dl>

      {/* **The capability list, rendered from the server's object and nothing
        * else.** No `isAdmin` check, no inference from `status`, no "an editor
        * can obviously download" — `docs/17 §1`, and `CLAUDE.md` rule 6 is why
        * it matters here specifically: preview, download, print, export and
        * sync are five permissions that look like one, and this is the surface
        * where a user finds out they are not.
        *
        * A `false` renders as refused **without an invented reason**. The
        * capability object is ten bare booleans today; `ENC-674` is the row that
        * turns each into `{allowed, reasonCode, reasonText, remediation}`. Until
        * it lands, the honest rendering is "you cannot" with no explanation,
        * because a client-composed one is forbidden (`docs/09 §5`). */}
      <div className="library-peek-section">
        <h4>{t('library.peek.capabilities')}</h4>
        <ul className="library-peek-caps">
          {CAPABILITY_LABELS.map(([name, label]) => {
            const allowed = detail.capabilities[name];
            return (
              <li key={name} className="library-peek-cap" data-allowed={allowed ? 'true' : 'false'}>
                <span className="library-peek-cap-mark" aria-hidden="true" />
                {t(label)}
                {/* The state in words as well as in colour and position, so the
                 * row is unambiguous to a screen reader and to anyone who cannot
                 * separate the two greys. */}
                <span className="ui-sr-only">
                  {t(allowed ? 'library.peek.cap.allowed' : 'library.peek.cap.refused')}
                </span>
              </li>
            );
          })}
        </ul>
      </div>

      {/* Obligations: what must happen *as well as* the action being allowed
       * (`CLAUDE.md` rule 8). Shown only when there are any, because an empty
       * heading reads as a surface that failed to load. */}
      {(detail.obligations.watermark ||
        detail.obligations.justificationRequired.length > 0 ||
        detail.obligations.approvalRequired.length > 0) && (
        <div className="library-peek-section">
          <h4>{t('library.peek.obligations')}</h4>
          <ul className="library-peek-caps">
            {detail.obligations.watermark && (
              <li className="library-peek-cap">{t('library.peek.obligation.watermark')}</li>
            )}
            {detail.obligations.justificationRequired.length > 0 && (
              <li className="library-peek-cap">
                {t('library.peek.obligation.justification', {
                  count: detail.obligations.justificationRequired.length,
                })}
              </li>
            )}
            {detail.obligations.approvalRequired.length > 0 && (
              <li className="library-peek-cap">
                {t('library.peek.obligation.approval', {
                  count: detail.obligations.approvalRequired.length,
                })}
              </li>
            )}
          </ul>
        </div>
      )}
    </>
  );
}

export function PeekPanel({
  fileId,
  detail,
  versions,
  isLoading,
  error,
  onClose,
  onRetry,
  activeTab,
  onTabChange,
  navigation,
}: {
  fileId: string | undefined;
  detail: FileDetail | undefined;
  versions: VersionPage | undefined;
  isLoading: boolean;
  error: unknown;
  onClose: () => void;
  onRetry: () => void;
  /** The open tab, from the route. */
  activeTab: string;
  onTabChange: (tab: TabId) => void;
  navigation?: PeekNavigation | undefined;
}) {
  const t = useT();
  /* Both hooks before any early return. `useFormatters()` used to be called
   * inline in the meta line below, which sits after three `return`s — so on the
   * loading and error paths React saw a different hook sequence, which is the
   * "rendered fewer hooks than expected" crash rather than a style point. */
  const formatters = useFormatters();
  /* The open tab is **URL state**, not component state (`docs/17 §4`).
   *
   * It was `useState` and that made a peek unshareable at the tab a colleague
   * needs: "look at the versions of this file" had to be said in words beside
   * the link. It is exactly the class of thing `docs/09 §3` puts in the route —
   * addressable, survives reload, survives back/forward — and it costs one
   * parameter. The screen owns the parameter and passes it down, so the panel
   * stays a controlled component with no route knowledge of its own. */
  const tab: TabId = TAB_IDS.includes(activeTab as TabId) ? (activeTab as TabId) : 'details';

  /* Pinned open with nothing selected. A real state, not a gap: the panel keeps
   * its width so the list does not reflow when a row is picked. */
  if (fileId === undefined) {
    return (
      <aside className="library-peek" aria-label={t('library.peek.label')}>
        <p className="library-peek-empty">{t('library.peek.none')}</p>
      </aside>
    );
  }

  if (error !== null && error !== undefined) {
    return (
      <PeekChrome title={t('library.peek.unavailable')} onClose={onClose} navigation={navigation}>
        <div className="library-peek-body">
          <FailureState failure={failureOf(error)} onRetry={onRetry} />
        </div>
      </PeekChrome>
    );
  }

  if (isLoading || detail === undefined) {
    /* The skeleton reserves the loaded panel's box — same title block, same tab
     * strip, same facts grid — so nothing moves when the data lands
     * (`docs/09 §11`). */
    return (
      <aside
        className="library-peek"
        aria-label={t('library.peek.label')}
        aria-busy="true"
        role="status"
      >
        <div className="library-peek-head" />
        <div className="library-peek-title" aria-hidden="true">
          <Skeleton width="72%" />
          <div className="library-peek-meta">
            <Skeleton width="54%" />
          </div>
        </div>
        <div className="library-peek-body" aria-hidden="true">
          <Skeleton width="100%" />
        </div>
      </aside>
    );
  }

  const modified = new Date(detail.modifiedAt);

  return (
    <PeekChrome title={detail.name} onClose={onClose} navigation={navigation}>
      <div className="library-peek-title">
        {/* One ICU message with named placeholders, not four fragments joined
         * with ' · ' in JavaScript. A translator controls both the order and the
         * separator; concatenation lets them control neither. */}
        <div className="library-peek-meta">
          {t('library.peek.meta', {
            version:
              detail.currentVersion === undefined
                ? t('library.peek.noVersion')
                : `${detail.currentVersion.major}.${detail.currentVersion.minor}`,
            size: formatters.bytes(detail.sizeBytes),
            modified: formatters.relative(modified),
          })}
        </div>
      </div>

      <div className="library-peek-tabs" role="tablist" aria-label={t('library.peek.tabs')}>
        {TABS.map((entry) => {
          const selected = entry.built && tab === entry.id;
          if (!entry.built) {
            /* Not focusable, neutral, no remedy — and never the denial
             * treatment (`docs/17 §6`, `ENC-673`). The note behind
             * `aria-describedby` names the actual blocker rather than shrugging. */
            const noteId = `peek-tab-${entry.id}-note`;
            return (
              <span
                key={entry.id}
                className="library-peek-tab"
                role="tab"
                aria-selected={false}
                aria-disabled="true"
                tabIndex={-1}
                aria-describedby={noteId}
              >
                {t(entry.label)}
                <LaterChip note="later.chip" />
                <span id={noteId} className="ui-later-note">
                  {t(UNBUILT_NOTE[entry.id] ?? 'later.arrivesLater')}
                </span>
              </span>
            );
          }
          return (
            <button
              key={entry.id}
              type="button"
              className="library-peek-tab"
              role="tab"
              aria-selected={selected}
              onClick={() => {
                onTabChange(entry.id);
              }}
            >
              {t(entry.label)}
            </button>
          );
        })}
      </div>

      <div className="library-peek-body">
        {tab === 'preview' ? (
          /* The Preview tab reads `versions` too, because `isReadable` is the
           * only field that answers whether bytes may be served and it lives
           * there rather than on `FileDetail` (`ENC-825`). Passing the page in
           * rather than fetching it again keeps one request behind two tabs.
           *
           * `detail` is awaited rather than defaulted. A placeholder
           * `capabilities` of all-`false` would render *preview refused* — a
           * denial the policy chain never issued, shown with the confidence of
           * a real one, which is the exact failure `docs/17 §3` names. */
          detail === undefined ? (
            <div className="peek-preview" role="status" aria-busy="true">
              <Skeleton width="100%" />
            </div>
          ) : (
            <PreviewTab
              fileId={fileId}
              name={detail.name}
              mimeType={detail.mimeType}
              capabilities={detail.capabilities}
              versions={versions}
              versionsPending={versions === undefined}
            />
          )
        ) : tab === 'versions' ? (
          <VersionList versions={versions} />
        ) : (
          <DetailsTab detail={detail} />
        )}
      </div>
    </PeekChrome>
  );
}
