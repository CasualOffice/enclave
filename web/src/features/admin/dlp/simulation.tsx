import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import { Avatar, Button, Skeleton } from '../../../shared/ui/primitives.tsx';
import { useListFormat, useRichT } from '../rich-text.tsx';
import { CATEGORY_KEY, SCOPE_KEY, type SimulationResult } from './model.ts';

/* Simulate before enforce (`docs/09 §21`, `docs/06 §9`).
 *
 * "Any policy with a blocking effect offers *Test against last 30 days* and
 * shows what would have been blocked, by whom, and how often." All three are
 * here, plus the blast radius `§21` asks for separately — *"This affects 1 240
 * files across 3 libraries"* — stated **before** applying rather than after.
 *
 * **The rule this panel exists to not break.** `CLAUDE.md` rule 10: never a DLP
 * match value, anywhere, including in a simulation result. `docs/09 §9` says
 * what to show instead — the category term, "contains payment card numbers",
 * never the number. The type in `model.ts` has no field a value could occupy and
 * Zod strips unknown keys at the boundary, so a server that started leaking one
 * would not reach this file. The test is `admin-dlp-redaction.test.tsx` and it
 * pairs the absence with a positive control, because an assertion about an
 * absence passes for free against a component that renders nothing.
 *
 * Every number here is `Intl`, via `useFormatters()`. The prototype hand-builds
 * `₹ 4.8 Cr` and `2 h ago`; both are defects in the reference (`docs/17 §8`),
 * and Indian digit grouping — `12,34,567` — is the specific thing a naive
 * formatter gets wrong (`docs/14 §6`).
 */

/* `docs/09 §21` names the affordance in its own words — "Test against last 30
 * days" — so the window is a product decision rather than a tunable, and it
 * reaches the label as an ICU value so the plural category is the locale's. */
const WINDOW_DAYS = 30;

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div className="adm-stat">
      <b className="adm-stat-value">{value}</b>
      <span className="adm-stat-label">{label}</span>
    </div>
  );
}

export function SimulationSkeleton() {
  const t = useT();
  return (
    <div role="status" aria-busy="true" aria-label={t('admin.dlp.sim.running')}>
      {/* The loaded panel's box model, not a spinner: same four stat cards at the
       * same height, so nothing shifts when the result lands (`docs/09 §11`). */}
      <div className="adm-stats" aria-hidden="true">
        {[0, 1, 2, 3].map((index) => (
          <div className="adm-stat" key={index}>
            <span className="adm-stat-value">
              <Skeleton width="48px" />
            </span>
            <span className="adm-stat-label">
              <Skeleton width="80%" />
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SimulationEmpty({
  onRun,
  readOnly,
}: {
  onRun: () => void;
  readOnly: boolean;
}) {
  const t = useT();
  return (
    <div className="adm-sim-empty">
      <p className="adm-state-title">{t('admin.dlp.sim.empty.title')}</p>
      <p className="adm-muted">{t('admin.dlp.sim.empty.body')}</p>
      {!readOnly && (
        <Button
          label="admin.dlp.sim.run"
          values={{ days: WINDOW_DAYS }}
          variant="primary"
          icon="clock"
          onClick={onRun}
        />
      )}
    </div>
  );
}

export function SimulationPanel({
  result,
  stale,
  onRun,
  readOnly,
}: {
  result: SimulationResult;
  /** The rule changed after the rehearsal, so the result describes something else. */
  stale: boolean;
  onRun: () => void;
  readOnly: boolean;
}) {
  const t = useT();
  const format = useFormatters();
  const rich = useRichT();
  const and = useListFormat('conjunction');
  const peak = Math.max(1, ...result.byWorkspace.map((row) => row.count));

  return (
    <div className="adm-sim">
      <div className="adm-sim-head">
        <h3 className="adm-panel-title">
          {t('admin.dlp.sim.title', { days: result.windowDays })}
        </h3>
        <span className="adm-spacer" />
        <span
          className="adm-muted"
          title={format.dateTime(new Date(result.ranAt))}
        >
          {t('admin.dlp.sim.ranAt', { when: format.relative(new Date(result.ranAt)) })}
        </span>
        {!readOnly && <Button label="admin.dlp.sim.rerun" variant="ghost" size="sm" onClick={onRun} />}
      </div>

      {stale && (
        /* Not an error and not a denial: the rehearsal is simply about a
         * different rule than the one on screen now. Saying so is the whole
         * value of having simulated. */
        <p className="adm-sim-stale" role="status">
          {t('admin.dlp.sim.stale')}
        </p>
      )}

      <div className="adm-stats">
        <Stat
          value={format.count(result.wouldRefuse)}
          label={t('admin.dlp.sim.stat.wouldRefuse')}
        />
        <Stat value={format.count(result.attempts)} label={t('admin.dlp.sim.stat.attempts')} />
        <Stat value={format.count(result.people)} label={t('admin.dlp.sim.stat.people')} />
        <Stat value={format.count(result.files)} label={t('admin.dlp.sim.stat.files')} />
      </div>

      {/* The blast radius, in one ICU message with two plural categories — not a
       * count glued to a noun (`docs/14 §4`). */}
      <p className="adm-blast">
        {t('admin.dlp.sim.blastRadius', {
          files: result.files,
          libraries: result.libraries,
        })}
      </p>

      <div className="adm-sim-grid">
        <section className="adm-panel" aria-labelledby="adm-sim-workspaces">
          <h4 className="adm-panel-title" id="adm-sim-workspaces">
            {t('admin.dlp.sim.byWorkspace')}
          </h4>
          <ul className="adm-bars">
            {result.byWorkspace.map((row) => (
              <li className="adm-bar-row" key={row.workspace}>
                {/* The workspace name is data; the sentence a screen reader hears
                 * is one message with the share as a percent placeholder. */}
                <span className="adm-bar-label">{row.workspace}</span>
                <span
                  className="adm-bar"
                  aria-hidden="true"
                  style={{ inlineSize: `${Math.round((row.count / peak) * 100)}%` }}
                />
                <span className="adm-bar-count">{format.count(row.count)}</span>
                <span className="ui-sr-only">
                  {t('admin.dlp.sim.barRow', {
                    workspace: row.workspace,
                    count: row.count,
                    share: result.attempts === 0 ? 0 : row.count / result.attempts,
                  })}
                </span>
              </li>
            ))}
          </ul>
        </section>

        <section className="adm-panel" aria-labelledby="adm-sim-events">
          <h4 className="adm-panel-title" id="adm-sim-events">
            {t('admin.dlp.sim.events')}
          </h4>
          <ul className="adm-events">
            {result.events.map((event) => (
              <li className="adm-event" key={`${event.actorName}-${event.at}`}>
                <Avatar initials={event.actorInitials} tone={event.actorTone} />
                <span className="adm-event-text">
                  {t('admin.dlp.sim.event', {
                    person: event.actorName,
                    action: t(SCOPE_KEY[event.scope]),
                    resource: event.resource,
                  })}
                </span>
                <span className="adm-event-when" title={format.dateTime(new Date(event.at))}>
                  {format.date(new Date(event.at))}
                </span>
                {/* Categories, never values. This is `docs/09 §9`'s "explain in
                 * category terms" and `CLAUDE.md` rule 10's floor, in the one
                 * place on the screen where a value could plausibly be useful
                 * and must still never appear. */}
                <span className="adm-event-cats">
                  {rich('admin.dlp.sim.eventCategories', {
                    categories: and(
                      event.categories.map((category) => (
                        <span className="adm-chip adm-chip-sm" key={category}>
                          {t(CATEGORY_KEY[category])}
                        </span>
                      )),
                    ),
                  })}
                </span>
              </li>
            ))}
          </ul>
          <p className="adm-muted">{t('admin.dlp.sim.noValues')}</p>
        </section>
      </div>
    </div>
  );
}
