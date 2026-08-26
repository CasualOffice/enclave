import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';
import { Icon } from '../../../shared/ui/icon-sprite.tsx';
import { Skeleton } from '../../../shared/ui/primitives.tsx';
import { FailureState } from '../../../shared/ui/surface-states.tsx';
import { failureOf } from '../../../shared/api/failure.ts';
import type { CapabilityName, FileDetail } from '../../../entities/file/api-model.ts';

/* The peek panel — `docs/09 §7`'s preview-before-open.
 *
 * 372 px at rest, floor 320, ceiling 520, and it is a **query parameter rather
 * than a route** (`docs/17 §5`): opening it must not unmount the list, because
 * a nested route would throw away the scroll position and the virtualization
 * window, which is the whole point of peeking instead of opening.
 *
 * It is deliberately **not a dialog**. No focus trap, no `role="dialog"`, no
 * inert background: the list stays interactive behind it, and `J`/`K` walk the
 * selection with the panel swapping content in place.
 *
 * ## What this panel shows, and what the prototype shows that it cannot
 *
 * The prototype draws five tabs — Preview, Details, Access, Versions, Activity
 * — a rendered preview page, an owner, a classification chip, a value in
 * rupees, and an indexing summary. `GET /api/v1/files/{id}` sends none of those
 * except the file's own facts and its capabilities:
 *
 * - **Preview** needs `GET /files/{id}/preview`, which returns rendition bytes
 *   and answers `404` when no rendition exists — and nothing renders one,
 *   because `crates/api/src/main.rs` binds `Delivery::unconfigured()`.
 * - **Access** needs an ACL read endpoint. None is registered.
 * - **Activity** is blocked on `docs/17` Q24: `audit_events` is hash-chained and
 *   deliberately *not* a user-facing feed (`CLAUDE.md` rule 10), so the tab
 *   cannot be built on it and must not be faked from it.
 * - **Classification** is not on the wire at all.
 *
 * So the panel shows what the server actually says, and the rest is absent
 * rather than mocked. Drawing a tab strip whose tabs do nothing would be the
 * "screen is a promise" failure this milestone exists to avoid.
 */

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

function PeekChrome({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const t = useT();
  return (
    <aside className="library-peek" aria-label={t('library.peek.label')}>
      <div className="library-peek-head">
        <span className="library-peek-head-actions">
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
      {/* `aria-live="polite"` on the title, so walking rows with J/K announces
       * what the panel now describes. Without it the panel changes silently and
       * a screen-reader user has no idea the content moved. */}
      <div className="library-peek-title">
        <h3 aria-live="polite">{title}</h3>
      </div>
      {children}
    </aside>
  );
}

export function PeekPanel({
  fileId,
  detail,
  isLoading,
  error,
  onClose,
  onRetry,
}: {
  fileId: string | undefined;
  detail: FileDetail | undefined;
  isLoading: boolean;
  error: unknown;
  onClose: () => void;
  onRetry: () => void;
}) {
  const t = useT();
  const formatters = useFormatters();

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
      <PeekChrome title={t('library.peek.unavailable')} onClose={onClose}>
        <div className="library-peek-body">
          <FailureState failure={failureOf(error)} onRetry={onRetry} />
        </div>
      </PeekChrome>
    );
  }

  if (isLoading || detail === undefined) {
    /* The skeleton reserves the loaded panel's box — same title block, same
     * chip row, same facts grid — so nothing moves when the data lands
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
  const created = new Date(detail.createdAt);

  return (
    <PeekChrome title={detail.name} onClose={onClose}>
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

      <div className="library-peek-body">
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
          * can obviously download" — `docs/17 §1`, and `CLAUDE.md` rule 6 is the
          * reason it matters here specifically: preview, download, print,
          * export and sync are five permissions that look like one, and this is
          * the surface where a user finds out they are not.
          *
          * A `false` renders as refused **without an invented reason**. The
          * capability object is nine bare booleans today; `ENC-674` is the row
          * that turns each into `{allowed, reasonCode, reasonText, remediation}`.
          * Until it lands, the honest rendering is "you cannot" with no
          * explanation, because a client-composed one is forbidden
          * (`docs/09 §5`) and a guessed one would be wrong. */}
        <div className="library-peek-section">
          <h4>{t('library.peek.capabilities')}</h4>
          <ul className="library-peek-caps">
            {CAPABILITY_LABELS.map(([name, label]) => {
              const allowed = detail.capabilities[name];
              return (
                <li
                  key={name}
                  className="library-peek-cap"
                  data-allowed={allowed ? 'true' : 'false'}
                >
                  <span className="library-peek-cap-mark" aria-hidden="true" />
                  {t(label)}
                  {/* The state in words as well as in colour and position, so
                   * the row is unambiguous to a screen reader and to anyone who
                   * cannot separate the two greys. */}
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
      </div>
    </PeekChrome>
  );
}
