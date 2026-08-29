import type { ClassificationLevel } from '../../entities/classification/model.ts';
import type { FileCapabilities } from '../../entities/file/api-model.ts';
import type { FileKind } from '../../entities/file/model.ts';
import type { AvatarTone } from '../../shared/ui/primitives.tsx';

/* What Home renders, as the client holds it.
 *
 * Flat, primitive-valued, and carrying epoch milliseconds rather than anything
 * pre-formatted — every date in this product is formatted at render through
 * `Intl` (`docs/14 §6`), never stored formatted.
 *
 * **One of Home's three sections now has a server and two still do not**, and
 * the difference is visible in the types rather than smoothed over:
 *
 * - *Needs your attention* is `GET /workflows/tasks`, mapped in `api.ts`.
 * - *Continue working* is `GET /me/recent`, mapped in `api.ts`, and it is the
 *   only part of this file that carries a `capabilities` object.
 * - *Recent asks* is M7 and still has a fixture behind it.
 *
 * These stay hand-declared rather than `z.infer`red from the wire schemas
 * because two of the three have no wire. What `docs/17 §3` actually requires is
 * that the *parsed* shape is never re-declared — that is `api.ts`'s job, and
 * nothing there declares a type beside a schema.
 *
 * The `capabilities` object below is the server's decision, never the client's
 * (`docs/17 §1`). A fixture that shipped `{ approve: true }` would be a
 * client-invented permission, which is the one thing this layer may never do —
 * so `fixture.ts` ships none at all, and the rows it produces render as records
 * rather than as links. That is the same rule, not an exception to it.
 */

/** What kind of thing is waiting on you. Chooses the action's catalog key. */
export type AttentionKind = 'approve' | 'review' | 'sign';

export interface AttentionItem {
  readonly id: string;
  readonly kind: AttentionKind;
  /** The thing waiting. User data — never translated, never truncated in code. */
  readonly subject: string;
  readonly requesterName: string;
  /** Already-computed initials: name order is not universal (`docs/14 §6`). */
  readonly requesterInitials: string;
  readonly requesterTone: AvatarTone;
  /** Epoch milliseconds. */
  readonly requestedAt: number;
}

/**
 * Where a recent row opens, and what this caller may do when it gets there.
 *
 * The three coordinates travel together because they are only useful together:
 * `/library?library=…&folder=…&peek=…` needs the first two to address the
 * container and `capabilities` to decide whether to offer the link at all. Kept
 * as one optional object rather than three optional fields so there is no
 * representable state in which the row knows where it lives but not what may be
 * done with it — which is the state a client would have to guess its way out of.
 *
 * Absent means *no server said*. `fixture.ts` is the only producer of such a
 * row, and it is right that it cannot produce a link: an id it invented would
 * address nothing, and a capability it invented would be the second authority
 * `docs/17` exists to prevent.
 */
export interface RecentLocation {
  readonly libraryId: string;
  /** `null` for a file at the library root, which links to the library itself. */
  readonly folderId: string | null;
  /**
   * The same twelve-key object `GET /files/{id}` and every listing row carry.
   *
   * Imported rather than restated: `ENC-929` is what a second copy costs — a UI
   * that changes its mind about what a user may do depending on which screen it
   * read the file from.
   */
  readonly capabilities: FileCapabilities;
}

export interface RecentFile {
  readonly id: string;
  /** The stem, with `extension` carrying the rest. Split by `entities/file`'s one splitter. */
  readonly name: string;
  /** Including the leading dot, or empty for an extensionless file. */
  readonly extension: string;
  readonly kind: FileKind;
  /**
   * The label on the file's own row, or `null` for none.
   *
   * `null` is **not** `unclassified`. `GET /me/recent` sends the file's own
   * label and deliberately not the inherited chain maximum, so an absent label
   * means *this row has nothing to display* rather than *nobody has labelled
   * this*. Drawing `Unclassified` on a document inheriting `RESTRICTED` from its
   * folder is precisely the disclosure the badge exists to prevent, so a `null`
   * draws no badge at all.
   */
  readonly classification: ClassificationLevel | null;
  /** Epoch milliseconds. */
  readonly openedAt: number;
  /** Present for a row the server placed; absent for a row nothing served. */
  readonly location?: RecentLocation | undefined;
}

export interface RecentAsk {
  readonly id: string;
  /** The question the user asked, in their words. User data. */
  readonly text: string;
}

export interface HomeData {
  /** The greeting is addressed to a person, so it needs the form they are called by. */
  readonly givenName: string;
  readonly workspaceName: string;
  readonly attention: readonly AttentionItem[];
  readonly recent: readonly RecentFile[];
  /**
   * How many *Continue working* candidates the policy chain dropped.
   *
   * The whole reason `GET /me/recent` returns a count rather than a bare list.
   * An empty list with a count above zero is *"some of what you opened is no
   * longer yours to open"*; an empty list with a count of zero is *"you have
   * not opened anything"*. `docs/09 §11` requires those to read differently,
   * and the server refuses to collapse them either — `MIN_LIMIT` in
   * `crates/api/src/routes/recent.rs` exists so that `limit=0` cannot forge the
   * second response out of the first.
   *
   * Absent rather than zero when nothing was fetched. `fixture.ts` has no
   * policy chain behind it, so it filtered nothing and knows nothing; a
   * hard-coded `0` there would be a fixture asserting a policy outcome.
   */
  readonly recentFilteredCount?: number | undefined;
  /**
   * Whether the recency request itself failed.
   *
   * A surface state on a data object, which is a compromise worth naming: the
   * alternative was threading a second prop through `HomeView` to one of its
   * three sections. It is here because a *blank* list has three causes — never
   * opened anything, opened things now filtered, and could not ask — and a
   * screen that draws the same sentence for all three is lying about two of
   * them.
   */
  readonly recentFailed?: boolean | undefined;
  readonly asks: readonly RecentAsk[];
  /**
   * How many attention items the current workspace scope is hiding.
   *
   * Home has no filter bar, but it *is* scoped — to one workspace — and that
   * scope can empty it while the user still has work elsewhere. This count is
   * what separates "you are done" from "you are looking in the wrong place",
   * which is the same distinction `files.state.filtered.body` exists to make.
   */
  readonly hiddenByScope: number;
}

/** What the screen is doing. `docs/09 §11` requires all of these, plus success. */
export type HomeStatus = 'ready' | 'loading' | 'error';

export interface HomeError {
  readonly retryable: boolean;
  /** The correlation ID from the API. Not translated, and quoted verbatim. */
  readonly requestId: string;
}
