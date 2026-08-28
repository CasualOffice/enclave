import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Button, IconButton } from '../../shared/ui/primitives.tsx';
import { Bar, Popover, Push } from '../../shared/ui/layout.tsx';
import { DeniedPanel } from '../../shared/ui/surface-states.tsx';
import { PhaseSteps } from '../../entities/upload/phase-steps.tsx';
import {
  PHASE_LABEL,
  PHASE_TONE,
  isActive,
  isSettled,
  type UploadRow,
} from '../../entities/upload/index.ts';
import { useUploadStore } from '../../entities/upload/store.ts';
import './upload-tray.css';

/* The upload tray: aggregate progress, and the place a transfer lives once the
 * user has navigated away from the library that started it.
 *
 * `docs/09 §8` asks for four things this surface exists to provide — per-file
 * *and* aggregate progress, retry of individual files, cancellation, and
 * uploads that keep running across navigation. The last one is why there is a
 * tray at all rather than only the inline row the prototype draws: an upload
 * rendered solely as a row in one library's list has nowhere to be while the
 * user is reading Search, and `docs/09` requires it to still be running.
 *
 * The inline row is drawn too, in the list, exactly as the prototype has it.
 * The two read the same store, so they can never disagree about a phase.
 */

function UploadRowView({ row }: { row: UploadRow }) {
  const t = useT();
  const formatters = useFormatters();
  const cancel = useUploadStore((state) => state.cancel);
  const retry = useUploadStore((state) => state.retry);
  const dismiss = useUploadStore((state) => state.dismiss);

  return (
    <li className="upl-row" data-tone={PHASE_TONE[row.phase]}>
      <div className="upl-row-head">
        <bdi className="upl-row-name" dir="auto">
          {row.name}
        </bdi>
        <Push />
        <span className="upl-row-size">{formatters.bytes(row.sizeBytes)}</span>
      </div>

      {/* The progress bar, and the one thing it must never claim.
       *
       * It fills during hashing and uploading, where a real fraction is known,
       * and pins at full once the bytes are handed off. It does **not** keep
       * creeping through `scanning` — there is no progress number for a scan,
       * and an invented one would be the product telling a user how long
       * something will take when it does not know. */}
      {(row.phase === 'hashing' || row.phase === 'uploading') && (
        <div
          className="upl-bar"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(row.progress * 100)}
          aria-label={t(PHASE_LABEL[row.phase])}
        >
          <span className="upl-bar-fill" style={{ inlineSize: `${row.progress * 100}%` }} />
        </div>
      )}

      <div className="upl-row-foot">
        <PhaseSteps phase={row.phase} />

        {/* A published-but-unscanned version says so, in words.
         *
         * This is the `AVAILABLE` / `SKIPPED` case, and it is the whole reason
         * the tray does not simply tick when `complete` answers `202`. The
         * sentence is about processing, not permission. */}
        {row.note !== undefined && <span className="upl-row-note">{t(row.note)}</span>}

        <Push />
        <span className="upl-row-actions">
          {isActive(row.phase) && (
            <Button label="upload.cancel" variant="ghost" size="sm" onClick={() => cancel(row.id)} />
          )}
          {/* Retry appears for a *failure* and never for a refusal.
           *
           * `docs/17 §7`: retrying a policy denial teaches a user the product is
           * broken rather than that they lack permission. `refused` is filtered
           * out here deliberately, and the test that proves it is paired with a
           * positive control so the assertion cannot pass by rendering nothing. */}
          {row.phase === 'failed' && (
            <Button label="upload.retry" variant="ghost" size="sm" onClick={() => retry(row.id)} />
          )}
          {isSettled(row.phase) && (
            <IconButton name="x" label="upload.dismiss" onClick={() => dismiss(row.id)} />
          )}
        </span>
      </div>

      {/* A refusal renders the server's own words, with no retry anywhere near
       * it. Nothing on this path is composed by the client (`docs/17 §1`). */}
      {row.failure?.kind === 'denied' && <DeniedPanel failure={row.failure} />}

      {/* A failure gets its code and its request id — the two things that make a
       * support ticket answerable (`docs/09 §11`). */}
      {row.failure?.kind === 'failed' && (
        <p className="upl-row-error">
          <code>{row.failure.code}</code>
          {row.failure.requestId.length > 0 && <code>{row.failure.requestId}</code>}
        </p>
      )}
    </li>
  );
}

export function UploadTray() {
  const t = useT();
  const rows = useUploadStore((state) => state.rows);
  const trayOpen = useUploadStore((state) => state.trayOpen);
  const setTrayOpen = useUploadStore((state) => state.setTrayOpen);
  const clearSettled = useUploadStore((state) => state.clearSettled);

  if (rows.length === 0 || !trayOpen) return null;

  const active = rows.filter((row) => isActive(row.phase)).length;

  return (
    /* A floating surface, so it is the shared one: `--z-popover` from the named
     * ladder rather than the hand-written `z-index: 20` two files had
     * independently arrived at, plus one elevation, one radius and one
     * entrance. `role="dialog"` because it is a named region with controls in
     * it, not a menu of choices — and non-modal, because an upload must not
     * stop the user reading the list behind it. */
    <Popover className="upl-tray" label="upload.tray.label" role="dialog">
      <Bar size="sm" as="header" className="upl-tray-head">
        <h2 className="upl-tray-title">
          {/* Aggregate progress, as a count rather than a percentage. Summing
           * per-file fractions into one bar implies the total is known, and a
           * queue that grows while it runs makes that a moving denominator. */}
          {t(active > 0 ? 'upload.tray.active' : 'upload.tray.done', {
            active,
            total: rows.length,
          })}
        </h2>
        <Push />
        <span className="upl-tray-head-actions">
          {rows.some((row) => isSettled(row.phase)) && (
            <Button label="upload.clearDone" variant="ghost" size="sm" onClick={clearSettled} />
          )}
          <IconButton name="x" label="upload.tray.hide" onClick={() => setTrayOpen(false)} />
        </span>
      </Bar>

      <ul className="upl-tray-list">
        {rows.map((row) => (
          <UploadRowView key={row.id} row={row} />
        ))}
      </ul>
    </Popover>
  );
}
