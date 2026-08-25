import type { ClassificationLevel } from '../../entities/classification/model.ts';
import type { FileKind } from '../../entities/file/model.ts';
import type { AvatarTone } from '../../shared/ui/primitives.tsx';

/* What Home renders, as the client holds it.
 *
 * **There is no Home endpoint.** `docs/05-API.md` defines none, and inventing a
 * path here would put a URL in the tree that nobody can call and that the next
 * reader would take for a contract. So this is a view model with a local
 * fixture behind it (`fixture.ts`), shaped the way the real payload will have
 * to be: flat, primitive-valued, and carrying epoch milliseconds rather than
 * anything pre-formatted — every date in this product is formatted at render
 * through `Intl` (`docs/14 §6`), never stored formatted.
 *
 * When the endpoint lands it is fetched through TanStack Query and parsed by a
 * Zod schema at the boundary (`docs/17 §3`), at which point these interfaces are
 * inferred from the schema rather than declared here, and nothing else on the
 * screen changes.
 *
 * What is deliberately **absent** is a `capabilities` object. `docs/17 §1`: the
 * server decides and the client renders the decision. Home has no server, so it
 * has no decision to render — every action on it is *unbuilt*, which is a
 * statement about the product's milestone and not about this user's permissions
 * (`docs/17 §6`). A fixture that shipped `{ approve: true }` would be a
 * client-invented permission, which is the one thing this layer may never do.
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

export interface RecentFile {
  readonly id: string;
  readonly name: string;
  /** Including the leading dot, or empty for an extensionless file. */
  readonly extension: string;
  readonly kind: FileKind;
  readonly classification: ClassificationLevel;
  /** Epoch milliseconds. */
  readonly openedAt: number;
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
