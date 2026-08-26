import { useCallback, useRef } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import { Icon } from '../../../shared/ui/icon-sprite.tsx';
import { IconButton, Kbd, LaterChip, Pill } from '../../../shared/ui/primitives.tsx';
import { ClassificationChip } from '../../../entities/classification/chip.tsx';
import {
  PEEK_TAB_KEY,
  PEEK_TABS,
  PEEK_WIDTH_MAX,
  PEEK_WIDTH_MIN,
  clampPeekWidth,
  type PeekFile,
  type PeekTab,
} from '../model.ts';

/* The peek panel — 372 px, 320–520.
 *
 * `docs/09 §7` and D34 both specify it, `ENC-676` settled it in the design's
 * favour, and it was absent from `web/src` entirely: not narrow, not stubbed,
 * not there. It is the reason a library row can be inspected without leaving
 * the list, which is the whole "peek before open" pattern.
 *
 * It is **not a dialog**. It does not trap focus and the list stays interactive
 * behind it (`specs/library.md`, ARIA). `aria-live="polite"` on the title is
 * what makes a J/K walk audible without stealing focus.
 *
 * Two states here are deliberately UNBUILT rather than denied (`ENC-673`): the
 * Activity tab, which is blocked on a user-facing read model because
 * `audit_events` is hash-chained and is not a feed, and the Ask composer, which
 * is M7. Neither may carry a danger tint — a user who learns that dimmed means
 * "not written yet" stops reading the one place it means "DLP refused this".
 */

export interface PeekPanelProps {
  readonly file: PeekFile;
  readonly tab: PeekTab;
  readonly onSelectTab: (tab: PeekTab) => void;
  readonly width: number;
  readonly onResize: (width: number) => void;
  readonly onClose: () => void;
  readonly onPrevious: () => void;
  readonly onNext: () => void;
}

/** ← / → move the divider by this much. Home/End snap to the bounds. */
const KEYBOARD_STEP = 16;

function PreviewWell({ file }: { file: PeekFile }) {
  const t = useT();
  return (
    <div className="peek-preview">
      {/* A placeholder page, not a fake render: nothing here claims to be the
       * document's content. The real preview arrives from a policy-mediated
       * endpoint and never from an object-storage URL (`CLAUDE.md` rule 6). */}
      <div className="peek-page" aria-hidden="true">
        <i className="peek-page-title" />
        <i />
        <i />
        <i />
        <i className="peek-page-short" />
        <i />
        <i />
        <i />
        <i className="peek-page-shorter" />
      </div>

      {file.watermarked && (
        /* Server-rendered text in the real thing: identity, timestamp, label and
         * hash are composed server side (`docs/09 §9`) and the client
         * interpolates nothing. Hidden from assistive technology because it is
         * an artefact of the image, not information about the file. */
        <div className="peek-watermark" aria-hidden="true" />
      )}

      <button type="button" className="peek-openbtn">
        {t('library.peek.openPreview')}
      </button>
    </div>
  );
}

export function PeekPanel({
  file,
  tab,
  onSelectTab,
  width,
  onResize,
  onClose,
  onPrevious,
  onNext,
}: PeekPanelProps) {
  const t = useT();
  const formatters = useFormatters();
  const asideRef = useRef<HTMLElement | null>(null);

  const resizeFromPointer = useCallback(
    (clientX: number) => {
      const aside = asideRef.current;
      if (aside === null) return;
      const box = aside.getBoundingClientRect();
      /* Measured from the panel's own inline-end edge rather than from the
       * viewport's leading edge, so the arithmetic is the same under RTL — the
       * edge the handle sits on is the inline-start one in both directions. */
      const next = box.right - clientX;
      onResize(clampPeekWidth(next));
    },
    [onResize],
  );

  const onHandlePointerDown = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      event.currentTarget.setPointerCapture(event.pointerId);
      const move = (moveEvent: PointerEvent) => resizeFromPointer(moveEvent.clientX);
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    },
    [resizeFromPointer],
  );

  const onHandleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      /* Mapped through the element's resolved direction rather than hardcoded:
       * under RTL the panel is on the leading edge and `ArrowLeft` grows it. */
      const rtl = getComputedStyle(event.currentTarget).direction === 'rtl';
      const grow = rtl ? 'ArrowRight' : 'ArrowLeft';
      const shrink = rtl ? 'ArrowLeft' : 'ArrowRight';
      if (event.key === grow) onResize(clampPeekWidth(width + KEYBOARD_STEP));
      else if (event.key === shrink) onResize(clampPeekWidth(width - KEYBOARD_STEP));
      else if (event.key === 'Home') onResize(PEEK_WIDTH_MAX);
      else if (event.key === 'End') onResize(PEEK_WIDTH_MIN);
      else return;
      event.preventDefault();
    },
    [onResize, width],
  );

  const modified = new Date(file.modifiedAt);

  return (
    <aside className="peek" aria-label={t('library.peek.label')} ref={asideRef}>
      <div
        className="peek-handle"
        role="separator"
        aria-orientation="vertical"
        aria-label={t('library.peek.resize')}
        aria-valuenow={width}
        aria-valuemin={PEEK_WIDTH_MIN}
        aria-valuemax={PEEK_WIDTH_MAX}
        tabIndex={0}
        onPointerDown={onHandlePointerDown}
        onKeyDown={onHandleKeyDown}
      />

      <div className="peek-head">
        <Kbd>{t('key.escape')}</Kbd>
        <span className="peek-head-hint">{t('library.peek.escHint')}</span>
        <div className="peek-head-end">
          <IconButton
            name="chev"
            label="library.peek.previous"
            className="peek-prev"
            onClick={onPrevious}
          />
          <IconButton name="chev" label="library.peek.next" onClick={onNext} />
          <IconButton name="ext" label="library.peek.openFull" />
          <IconButton name="x" label="library.peek.close" onClick={onClose} />
        </div>
      </div>

      <div className="peek-title">
        {/* Polite, not assertive: J/K through the list should be audible without
         * interrupting whatever the user is already hearing. */}
        <h3 aria-live="polite" dir="auto">
          {file.name}
          <span className="peek-ext">{file.extension}</span>
        </h3>
        <div className="peek-meta">
          {/* One ICU message with four named placeholders and the separator in
           * the catalog, so a locale can reorder the whole line. Never
           * `${ver} · ${size} · ${who} · ${when}` (`specs/library.md §4B.2`). */}
          {t('library.peek.meta', {
            version: file.version,
            size: formatters.bytes(file.sizeBytes),
            owner: file.owner,
            modified: formatters.relative(modified),
          })}
        </div>
      </div>

      <div className="peek-pills">
        <ClassificationChip level={file.classification} />
        {file.pills.map((pill) => (
          <Pill key={pill.label} label={pill.label} tone={pill.tone} icon={pill.icon} />
        ))}
      </div>

      <div className="peek-tabs" role="tablist" aria-label={t('library.peek.tabs')}>
        {PEEK_TABS.map((name) => (
          <button
            key={name}
            type="button"
            role="tab"
            className="peek-tab"
            aria-selected={name === tab}
            /* Activity is not focusable, because there is nothing to find out
             * and nothing to do — the unbuilt contract, not the denied one. */
            tabIndex={name === 'activity' ? -1 : 0}
            aria-disabled={name === 'activity' ? true : undefined}
            onClick={name === 'activity' ? undefined : () => onSelectTab(name)}
          >
            {t(PEEK_TAB_KEY[name])}
            {name === 'activity' && <LaterChip note="later.chip" />}
          </button>
        ))}
      </div>

      <div className="peek-body">
        <PreviewWell file={file} />

        {file.watermarked && (
          /* The policy notice. Body and remediation are the server's; the
           * client never composes the sentence and never offers a retry
           * (`docs/06 §24`). */
          <div className="peek-notice">
            <Icon name="info" size={16} />
            <div>{t('library.peek.watermarkNotice')}</div>
          </div>
        )}

        <dl className="peek-facts">
          {file.facts.map((fact) => (
            <div key={fact.key} className="peek-fact">
              <dt>{t(fact.key)}</dt>
              <dd dir="auto">{fact.value}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="peek-ask">
        {/* Ask is M7. The whole composer renders unbuilt — never denied, which
         * stays reserved for policy (`ENC-673`). */}
        <div className="peek-ask-card" aria-disabled="true">
          <span className="peek-ask-placeholder">{t('library.peek.askPlaceholder')}</span>
          <div className="peek-ask-foot">
            <Pill label="library.peek.askScope" tone="outline" icon="file" />
            <span className="peek-ask-spacer" />
            <LaterChip note="later.chip" id="peek-ask-note" />
          </div>
        </div>
        <span className="ui-later-note" id="peek-ask-release">
          {t('library.peek.askLater')}
        </span>
      </div>
    </aside>
  );
}
