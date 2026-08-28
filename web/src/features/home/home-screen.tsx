import { useState, type CSSProperties } from 'react';
import { ClassificationChip } from '../../entities/classification/chip.tsx';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Card, Eyebrow, Push, Truncate } from '../../shared/ui/layout.tsx';
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
 *      measures 3.68:1 and axe fails it. The badge is no longer this screen's
 *      to get right: it is `entities/classification`'s `ClassificationChip`,
 *      the **only** implementation in the tree, and `design-system.test.tsx`
 *      asserts that the locked `--c-*` palette is read from exactly one
 *      stylesheet. This file was the second reader.
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
 * A row's index, handed to the shared stagger.
 *
 * `.enc-stagger-card` reads `--i` and caps it at `--stagger-cap`, so the delay
 * is the token layer's decision and the row only supplies its position. Typed as
 * an intersection rather than cast through `any`: a custom property is a legal
 * `style` entry that `CSSProperties` does not model, and widening the whole
 * object would take the type-checking off every other declaration in it.
 */
type StaggerStyle = CSSProperties & Record<'--i', number>;

function stagger(index: number): StaggerStyle {
  return { '--i': index };
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

/**
 * A section's eyebrow, and the neutral marker beside it where one is owed.
 *
 * The chip is a **sibling** of the `<h2>` rather than a child of it: `Eyebrow`
 * renders the heading, and folding the chip inside would make "Continue
 * working" announce as "Continue working Later". The uppercase belongs to
 * `Eyebrow`, behind a `:lang()` allowlist — the catalog holds the sentence-case
 * original, because `text-transform: uppercase` is wrong in Turkish, strips
 * accents in Greek and means nothing in scripts without case (`docs/14`).
 */
function SectionHead({
  titleKey,
  laterKey,
}: {
  titleKey: MessageKey;
  /** Present when the section is readable but not yet actionable. */
  laterKey?: MessageKey | undefined;
}) {
  const t = useT();
  return (
    <div className="home-section-head">
      <Eyebrow label={titleKey} />
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
    <section aria-label={t('home.attention.title')}>
      <SectionHead titleKey="home.attention.title" />
      {data.attention.length === 0 ? (
        <Card className="home-section-empty">{t('home.attention.empty')}</Card>
      ) : (
        <ul className="home-attention">
          {/* The entrance is the shared one, staggered by position, and it sits
           * on the `<li>` rather than on the card so the animated box and the
           * card's own box are not the same node — a transform on a
           * `box-shadow`ed surface repaints the shadow every frame.
           * `docs/09 §12` allows motion on enter and forbids it on a data
           * update in place; this runs once, when the row arrives. */}
          {data.attention.map((item, index) => (
            <li className="enc-enter enc-stagger-card" key={item.id} style={stagger(index)}>
              <Card className="home-card" padded={false}>
                <Avatar initials={item.requesterInitials} tone={item.requesterTone} size="md" />
                <div className="home-card-main">
                  <div className="home-card-title">
                    <Truncate>{item.subject}</Truncate>
                  </div>
                  <div className="home-card-sub">
                    <Truncate>
                      {t('home.attention.requestedBy', { name: item.requesterName })}
                    </Truncate>
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
              </Card>
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
    <section aria-label={t('home.recent.title')}>
      <SectionHead titleKey="home.recent.title" laterKey="home.recent.laterNote" />
      {data.recent.length === 0 ? (
        <Card className="home-section-empty">{t('home.recent.empty')}</Card>
      ) : (
        <Card className="home-recent" padded={false}>
          <ul className="home-recent-list">
            {data.recent.map((file, index) => (
              <li
                className="home-recent-row enc-enter enc-stagger-card"
                key={file.id}
                style={stagger(index)}
              >
                <span className="home-file-icon" data-kind={file.kind} aria-hidden="true">
                  <Icon name="file" size={16} />
                </span>
                <span className="home-recent-name">
                  <Truncate>
                    {file.name}
                    <span className="home-recent-ext">{file.extension}</span>
                  </Truncate>
                </span>
                {/* Colour is never the only carrier: the chip says the level in
                 * words as well (`docs/09 §15`), and it is the product's single
                 * implementation of that badge rather than this screen's copy. */}
                <ClassificationChip level={file.classification} />
                <Push />
                <When at={file.openedAt} now={now} className="home-recent-when" />
              </li>
            ))}
          </ul>
        </Card>
      )}
    </section>
  );
}

function AsksSection({ data }: { data: HomeData }) {
  const t = useT();
  return (
    <section aria-label={t('home.asks.title')}>
      <SectionHead titleKey="home.asks.title" laterKey="home.asks.laterNote" />
      {data.asks.length === 0 ? (
        <Card className="home-section-empty">{t('home.asks.empty')}</Card>
      ) : (
        <ul className="home-asks">
          {data.asks.map((ask) => (
            <li className="home-ask" key={ask.id}>
              <Icon name="spark" size={12} className="home-ask-icon" />
              <Truncate>{ask.text}</Truncate>
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
        {/* The header does **not** animate, and that is a measured decision
         * rather than an omission. axe computes contrast from the composited
         * pixel, so a run landing inside an opacity ramp read `--fg2` on this
         * date line as 2.12:1 against a settled 6.83:1. The entrance now
         * belongs to the rows, whose text sits on a card and arrives with it. */}
        <header>
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
          <FailureState failure={failureOf(tasks.error)} onRetry={() => void tasks.refetch()} fill />
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
