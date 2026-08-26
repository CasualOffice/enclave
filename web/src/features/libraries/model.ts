import type { MessageKey } from '../../shared/i18n/catalog.ts';
import type { AvatarTone } from '../../shared/ui/primitives.tsx';
import type { PillTone } from '../../shared/ui/primitives.tsx';
import type { ClassificationLevel } from '../../entities/classification/model.ts';

/* The library surface's view models.
 *
 * None of this is the API shape. `docs/05-API.md` owns that and the Zod schema
 * it is parsed from lands with the first real fetch (`docs/17 §3`); these are
 * what the components take, so the components do not change when it does.
 *
 * Two fields are deliberately catalog keys rather than strings — the saved-view
 * labels and the filter facet names — because the endpoints behind them
 * (`GET /libraries/{id}/views`, `/facets`) do not exist yet and the alternative
 * is a literal in `web/src`, which `CLAUDE.md` rule 12 forbids. When the server
 * starts sending localized labels these become `string` and the fixture goes.
 */

/** One breadcrumb ancestor. `name` is server data and is never translated. */
export interface Crumb {
  readonly id: string;
  readonly name: string;
}

/**
 * A saved view: the four pills in the prototype are data, not constants
 * (`web/design-system/specs/library.md §2.1`).
 */
export interface SavedView {
  readonly id: string;
  readonly label: MessageKey;
  readonly count: number;
}

/** Who is in this folder now. From presence, not from the listing. */
export interface PresenceMember {
  readonly id: string;
  /** Carried, never derived by splitting a name — name order is not universal. */
  readonly initials: string;
  readonly tone: AvatarTone;
}

/** One applied facet, as the three-segment chip renders it. */
export interface ActiveFilter {
  readonly id: string;
  readonly facet: MessageKey;
  /** The server's rendering of the chosen values. Data, not a message. */
  readonly value: string;
}

/** A status/obligation pill on a row or in the peek panel. */
export interface StatusPillSpec {
  readonly tone: PillTone;
  readonly label: MessageKey;
  readonly icon?: 'block' | 'check' | 'clock' | 'lock';
}

/** One fact in the peek panel's `<dl>`. */
export interface PeekFact {
  readonly key: MessageKey;
  readonly value: string;
}

/** The peek payload — a separate endpoint from the listing, so it can prefetch. */
export interface PeekFile {
  readonly id: string;
  readonly name: string;
  readonly extension: string;
  readonly classification: ClassificationLevel;
  readonly version: string;
  readonly sizeBytes: number;
  readonly owner: string;
  readonly modifiedAt: number;
  readonly pills: readonly StatusPillSpec[];
  readonly facts: readonly PeekFact[];
  /**
   * The server decided the preview is watermarked and says so.
   *
   * A flag, not a composed sentence: the watermark's text is rendered server
   * side (`docs/09 §9`), and the notice beside it carries the server's message.
   * The client interpolates nothing into either.
   */
  readonly watermarked: boolean;
}

/** The five peek tabs of `docs/09 §7`. Exactly five, in this order. */
export const PEEK_TABS = ['preview', 'details', 'access', 'versions', 'activity'] as const;
export type PeekTab = (typeof PEEK_TABS)[number];

export const PEEK_TAB_KEY: Record<PeekTab, MessageKey> = {
  preview: 'library.peek.tab.preview',
  details: 'library.peek.tab.details',
  access: 'library.peek.tab.access',
  versions: 'library.peek.tab.versions',
  activity: 'library.peek.tab.activity',
};

/** The peek panel's width bounds. The prototype opens at 372 (`specs/library.md §4`). */
export const PEEK_WIDTH_DEFAULT = 372;
export const PEEK_WIDTH_MIN = 320;
export const PEEK_WIDTH_MAX = 520;

export function clampPeekWidth(width: number): number {
  return Math.min(PEEK_WIDTH_MAX, Math.max(PEEK_WIDTH_MIN, Math.round(width)));
}
