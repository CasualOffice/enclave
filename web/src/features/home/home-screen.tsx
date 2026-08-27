import { useState } from 'react';
import { CLASSIFICATION_KEY } from '../../entities/classification/model.ts';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import {
  Avatar,
  Button,
  LaterChip,
  ScreenReaderOnly,
  type ControlState,
} from '../../shared/ui/primitives.tsx';
import { attentionFromTask, useTasks } from './api.ts';
import { useViewer } from '../../entities/user/viewer.tsx';
import { FailureState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import type { AttentionKind, HomeData, HomeError } from './model.ts';
import { EmptyState, ErrorState, LoadingState, ScopedEmptyState } from './states.tsx';
import './home.css';

/* Home.
 *
 * The landing surface: what is waiting on you, what you were last working on,
 * what you have asked. Laid out from the `data-screen-label="Home"` block of
 * `web/design-system/enclave-client-prototype.html`, which is authoritative for
 * appearance, and governed by `docs/09` for behaviour where the two disagree.
 *
 * Three places they disagree, all of them the prototype's known defects:
 *
 *   1. It hand-builds relative time (`2 h ago`) and hand-builds the date line
 *      (`Thursday, August 20`). Both go through `useFormatters()` here, and
 *      every relative time carries its absolute value in a `title` — a relative
 *      time alone is unquotable to support and ages badly in a screenshot
 *      (`docs/14 §6`).
 *   2. Its classification badge mixes text at 82% of the level colour. That
 *      measures 3.68:1 and axe fails it; the badge here uses the 70% recipe
 *      `features/libraries/list` already ships, so one label is one colour
 *      across the product.
 *   3. Every one of its eight controls is a live button. **None of them have a
 *      backend.** `docs/05-API.md` defines no Home resource, no approvals
 *      resource and no Ask resource, so the approval actions render *unbuilt* —
 *      neutral, out of the tab order, carrying a `Later` chip — and the recent
 *      files and recent asks render as records rather than as controls, with
 *      the chip once on the section. That distinction is a security contract,
 *      not styling (`docs/17 §6`): a user who learns that dimmed means "not
 *      written yet" on five harmless surfaces carries the habit to the one
 *      where it means "DLP refused this".
 *
 * There is no `capabilities` object anywhere in this file, and that is
 * deliberate. `docs/17 §1` — the server decides, the client renders the
 * decision. Home has no server yet, so it has no decision to render, and a
 * client-invented `{ approve: true }` would be the second authority the whole
 * document exists to prevent.
 */

/**
 * Home's own actions are unbuilt: the milestone has not reached them. Never denied.
 *
 * `note` is the sentence `aria-describedby` points at; the one-word chip beside
 * the control defaults to `later.chip`. Both, because D33 wants a marker short
 * enough to sit in a card row and an explanation long enough to be an
 * explanation.
 */
const UNBUILT: ControlState = { kind: 'unbuilt', note: 'later.arrivesLater' };

/** A kind of waiting work to the verb that clears it. No component maps this to a literal. */
const ACTION_KEY: Record<AttentionKind, MessageKey> = {
  approve: 'home.attention.action.approve',
  review: 'home.attention.action.review',
  sign: 'home.attention.action.sign',
};

/**
 * Which greeting to use, from the reader's own wall clock.
 *
 * Three separate catalog keys rather than one with a placeholder, because the
 * boundaries and the number of greetings are both language-specific and a
 * translator has to be able to collapse or split them. The hours are the
 * reader's, not the server's — `getHours()` is local time by definition, which
 * is the one thing this needs to be right.
 */
function greetingKey(now: Date): MessageKey {
  const hour = now.getHours();
  if (hour < 12) return 'home.greeting.morning';
  if (hour < 18) return 'home.greeting.afternoon';
  return 'home.greeting.evening';
}

/**
 * A relative time that can still be quoted.
 *
 * `docs/14 §6`: the absolute value always rides along in a `title`, and the
 * machine-readable value in `dateTime`, so the row is useful to a support call
 * and to a parser as well as to a reader.
 */
function When({
  at,
  now,
  className,
}: {
  at: number;
  now: Date;
  className?: string | undefined;
}) {
  const f = useFormatters();
  const value = new Date(at);
  return (
    <time className={className} dateTime={value.toISOString()} title={f.dateTime(value)}>
      {f.relative(value, now)}
    </time>
  );
}

function SectionHead({
  titleKey,
  titleId,
  laterKey,
}: {
  titleKey: MessageKey;
  titleId: string;
  /** Present when the section is readable but not yet actionable. */
  laterKey?: MessageKey | undefined;
}) {
  const t = useT();
  return (
    <div className="home-section-head">
      <h2 className="home-section-title" id={titleId}>
        {t(titleKey)}
      </h2>
      {laterKey !== undefined && (
        <>
          {/* The same neutral marker the sidebar uses for a surface that does
           * not exist yet — the shared component rather than a hand-written
           * span, so this copy cannot drift into a semantic colour. It never
           * uses the denial treatment and it offers no remedy, because there is
           * nothing this user can do about a milestone. */}
          <LaterChip note="later.chip" />
          <ScreenReaderOnly>{t(laterKey)}</ScreenReaderOnly>
        </>
      )}
    </div>
  );
}

function AttentionSection({ data, now }: { data: HomeData; now: Date }) {
  const t = useT();
  return (
    <section className="home-in" data-step="1" aria-labelledby="home-attention-title">
      <SectionHead titleKey="home.attention.title" titleId="home-attention-title" />
      {data.attention.length === 0 ? (
        <p className="home-section-empty">{t('home.attention.empty')}</p>
      ) : (
        <ul className="home-attention">
          {data.attention.map((item) => (
            <li className="home-card" key={item.id}>
              <Avatar initials={item.requesterInitials} tone={item.requesterTone} size="lg" />
              <div className="home-card-main">
                <div className="home-card-title">{item.subject}</div>
                <div className="home-card-sub">
                  <span className="home-card-sub-who">
                    {t('home.attention.requestedBy', { name: item.requesterName })}
                  </span>
                  <When at={item.requestedAt} now={now} />
                </div>
              </div>
              <div className="home-card-actions">
                {/* Neutral, not accent-filled: `unbuilt` must never look like a
                 * control that is one click from working, and it must never
                 * look like a refusal either.
                 *
                 * `describedById` is keyed on the *item*, not on the label.
                 * `Button` otherwise derives the note's id from the catalog key,
                 * and a real attention list has two approvals in it far more
                 * often than it has one of each kind — two controls sharing a
                 * label would then emit one id twice and their
                 * `aria-describedby` would resolve to the same node. That is an
                 * axe `duplicate-id-aria` failure, tagged `wcag2a`. */}
                <Button
                  label={ACTION_KEY[item.kind]}
                  state={UNBUILT}
                  describedById={`home-attention-${item.id}-note`}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RecentSection({ data, now }: { data: HomeData; now: Date }) {
  const t = useT();
  return (
    <section className="home-in" data-step="2" aria-labelledby="home-recent-title">
      <SectionHead
        titleKey="home.recent.title"
        titleId="home-recent-title"
        laterKey="home.recent.laterNote"
      />
      {data.recent.length === 0 ? (
        <p className="home-section-empty">{t('home.recent.empty')}</p>
      ) : (
        <ul className="home-recent">
          {data.recent.map((file) => (
            <li className="home-recent-row" key={file.id}>
              <span className="home-file-icon" data-kind={file.kind} aria-hidden="true">
                <Icon name="file" size={16} />
              </span>
              <span className="home-recent-name">
                {file.name}
                <span className="home-recent-ext">{file.extension}</span>
              </span>
              {/* Colour is never the only carrier: the badge says the level in
               * words as well (`docs/09 §15`), and the words come from
               * `entities/classification` so no component owns a second copy. */}
              <span className="home-classification" data-level={file.classification}>
                {t(CLASSIFICATION_KEY[file.classification])}
              </span>
              <When at={file.openedAt} now={now} className="home-recent-when" />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function AsksSection({ data }: { data: HomeData }) {
  const t = useT();
  return (
    <section className="home-in" data-step="3" aria-labelledby="home-asks-title">
      <SectionHead
        titleKey="home.asks.title"
        titleId="home-asks-title"
        laterKey="home.asks.laterNote"
      />
      {data.asks.length === 0 ? (
        <p className="home-section-empty">{t('home.asks.empty')}</p>
      ) : (
        <ul className="home-asks">
          {data.asks.map((ask) => (
            <li className="home-ask" key={ask.id}>
              <Icon name="spark" size={12} className="home-ask-icon" />
              <span className="home-ask-text">{ask.text}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export interface HomeViewProps {
  readonly data: HomeData;
  /** Passed in rather than read from the clock, so a relative time is assertable. */
  readonly now: Date;
}

/**
 * Home's success state, and the two whole-screen empties it collapses into.
 *
 * Exported so the states can be rendered under test without a fixture and
 * without a clock. The default export below is the router's entry point.
 */
export function HomeView({ data, now }: HomeViewProps) {
  const t = useT();
  const f = useFormatters();

  const nothingAtAll =
    data.attention.length === 0 && data.recent.length === 0 && data.asks.length === 0;

  /* Two different sentences for two different situations. A user with three
   * approvals waiting in another workspace must not be told their workspace is
   * quiet — that is the same defect as telling someone their library is empty
   * when a filter is hiding it. */
  if (nothingAtAll && data.hiddenByScope > 0) {
    return <ScopedEmptyState hiddenCount={data.hiddenByScope} />;
  }
  if (nothingAtAll) {
    return <EmptyState />;
  }

  return (
    <div className="home">
      <div className="home-page">
        <header className="home-in">
          <h1 className="home-greeting">{t(greetingKey(now), { name: data.givenName })}</h1>
          {/* One message, not four fragments concatenated: the separator, the
           * order and the plural category are all the translator's to move. */}
          <p className="home-subline">
            {t('home.subline', {
              date: f.date(now),
              workspace: data.workspaceName,
              attention: data.attention.length,
            })}
          </p>
        </header>

        <AttentionSection data={data} now={now} />
        <RecentSection data={data} now={now} />
        <AsksSection data={data} />
      </div>
    </div>
  );
}

/** The surfaces a URL can force, so the a11y and visual runs can reach all of them. */
type Surface = 'ready' | 'loading' | 'error' | 'empty' | 'scoped-empty';

const SURFACES = new Set<Surface>(['ready', 'loading', 'error', 'empty', 'scoped-empty']);

/* `home=` rather than `surface=`: the library screen already reads `surface=`
 * from the same query string, and two screens answering one parameter is how a
 * URL stops meaning one thing. */
function readSurface(search: string): Surface {
  const value = new URLSearchParams(search).get('home') ?? 'ready';
  return SURFACES.has(value as Surface) ? (value as Surface) : 'ready';
}

const FIXTURE_ERROR: HomeError = { retryable: true, requestId: '01K3Q7X0PMDR4W8B2ZC6E5A9TN' };

/**
 * Home, as the router mounts it.
 *
 * **The attention section is real**: `GET /api/v1/workflows/tasks`, through
 * `api.ts`. The other two sections have no endpoint and are rendered empty —
 * `GET /api/v1/me/recent` does not exist and must not be improvised out of
 * `audit_events` (hash-chained, deliberately not a feed: `CLAUDE.md` rule 10),
 * and Recent asks is M7.
 *
 * The greeting's name and workspace come from `/me`, which carries a
 * `displayName` and — deliberately noted rather than worked around — **no
 * workspace name and no time zone**. `specs/home.md` wants the greeting bucket
 * chosen from `me.timeZone`; with none on the wire the browser's own zone is
 * used, which is right for everyone who is not travelling and wrong quietly for
 * everyone who is. Recorded, not guessed at.
 */
export default function Screen() {
  const [forced] = useState(() => readSurface(window.location.search));
  /* One clock for the whole render. Reading `new Date()` per row would let two
   * timestamps on the same screen disagree about what "now" is. */
  const [now] = useState(() => new Date());
  const [retried, setRetried] = useState(false);
  const viewer = useViewer();
  const tasks = useTasks();

  if (forced === 'loading') return <LoadingState />;

  if (forced === 'error' && !retried) {
    return <ErrorState error={FIXTURE_ERROR} onRetry={() => setRetried(true)} />;
  }

  /* A denial is not a failure and gets no retry; a fault gets one and a request
   * ID (`docs/17 §7`). `FailureState` owns that branch. */
  if (tasks.isError) {
    return (
      <div className="home">
        <div className="home-page">
          <FailureState failure={failureOf(tasks.error)} onRetry={() => void tasks.refetch()} />
        </div>
      </div>
    );
  }

  if (tasks.isPending) return <LoadingState />;

  const data: HomeData = {
    /* The display name as given. Never split on whitespace to find a "first"
     * name — name order is not universal (`docs/14 §6`). */
    givenName: viewer.displayName,
    /* Not on the wire. `/me` carries no workspace, and there is no endpoint
     * that enumerates them, so the subtitle names the tenant's own address
     * rather than inventing a workspace called something. */
    workspaceName: viewer.email,
    attention: tasks.data.items.map(attentionFromTask),
    recent: [],
    asks: [],
    hiddenByScope: 0,
  };

  if (forced === 'empty') {
    return <HomeView data={{ ...data, attention: [], recent: [], asks: [] }} now={now} />;
  }
  if (forced === 'scoped-empty') {
    return (
      <HomeView
        data={{ ...data, attention: [], recent: [], asks: [], hiddenByScope: 3 }}
        now={now}
      />
    );
  }

  return <HomeView data={data} now={now} />;
}
