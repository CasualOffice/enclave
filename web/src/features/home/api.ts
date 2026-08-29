import { z } from 'zod';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import type { ClassificationLevel } from '../../entities/classification/model.ts';
import { FileCapabilities } from '../../entities/file/api-model.ts';
import { kindOf, splitName } from '../../entities/file/present.ts';
import { request } from '../../shared/api/client.ts';
import type { AttentionItem, AttentionKind, RecentFile } from './model.ts';

/* Home's two real reads: `GET /api/v1/workflows/tasks` and `GET /api/v1/me/recent`.
 *
 * ## Which of the three sections has a server
 *
 * `specs/home.md` designs three independent sections, each with its own four
 * states. Two of the three now have an endpoint:
 *
 * - **Needs your attention** — `GET /api/v1/workflows/tasks`, registered and
 *   implemented.
 * - **Continue working** — `GET /api/v1/me/recent`, implemented in
 *   `crates/api/src/routes/recent.rs` over the purpose-built `recent_files`
 *   read model. It is *not* a query over `audit_events`, which is hash-chained
 *   and deliberately not a user-facing feed (`CLAUDE.md` rule 10) — that is why
 *   this section waited for a table rather than being improvised out of one
 *   that was already there.
 * - **Recent asks** — M7. Still unbuilt.
 *
 * ## What the task payload does not carry
 *
 * `TaskView` is `{stepId, instanceId, fileId, versionId, stepType, stage,
 * stageName, delegated, dueAt?}`. It carries **no subject title, no requester
 * and no capabilities** — `specs/home.md` asks for all three, because the card
 * is drawn as "Priya asked you to approve <document>" with an Approve button
 * rendered from `task.capabilities.approve`.
 *
 * The file's name would need a second request per row; the requester is not on
 * the wire at all; and with no capability object the Approve button cannot be
 * rendered from one. `docs/17 §1` leaves exactly one honest option: show what
 * the server said, and leave the rest absent.
 */

const TaskView = z.object({
  stepId: z.string(),
  instanceId: z.string(),
  fileId: z.string(),
  versionId: z.string(),
  stepType: z.enum(['APPROVAL', 'REVIEW', 'SIGNATURE', 'TASK']),
  stage: z.number(),
  stageName: z.string(),
  delegated: z.boolean(),
  dueAt: z.string().optional(),
});

const TaskList = z.object({
  items: z.array(TaskView),
  page: z.object({
    nextCursor: z.string().nullish(),
    hasMore: z.boolean(),
  }),
});

export type TaskList = z.infer<typeof TaskList>;

/** The three step types Home draws differently. `TASK` is shown as a review. */
const KIND: Record<z.infer<typeof TaskView>['stepType'], AttentionKind> = {
  APPROVAL: 'approve',
  REVIEW: 'review',
  SIGNATURE: 'sign',
  TASK: 'review',
};

/**
 * One task, as the attention card wants it.
 *
 * `requesterName` and `requesterInitials` are **empty**, and the card draws no
 * avatar rather than a circle with two characters of a UUID in it. The subject
 * is the workflow stage's own name — the only human-readable string in the
 * payload — rather than a filename the endpoint does not send.
 */
export function attentionFromTask(task: z.infer<typeof TaskView>): AttentionItem {
  return {
    id: task.stepId,
    kind: KIND[task.stepType],
    subject: task.stageName,
    requesterName: '',
    requesterInitials: '',
    requesterTone: 'a',
    /* `dueAt` is a deadline, not an origin. Absent means the card shows no
     * timestamp — better than showing "now", which would say the request had
     * just arrived when nobody knows when it arrived. */
    requestedAt: task.dueAt === undefined ? 0 : Date.parse(task.dueAt),
  };
}

export function useTasks(): UseQueryResult<TaskList> {
  return useQuery({
    queryKey: ['workflows', 'tasks'],
    queryFn: ({ signal }) => request('/workflows/tasks', TaskList, { signal }),
    staleTime: 0,
    retry: false,
  });
}

/* ------------------------------------------------------------ continue working */

/**
 * A sensitivity label as `GET /me/recent` sends it.
 *
 * `key` is `z.string()` and **not** an enum, which is the opposite call from
 * `capabilities` two fields down, and the asymmetry is deliberate.
 * `migrations/0022_classifications.sql` puts no `CHECK` on `classifications.key`
 * on purpose — *"the label set is tenant-defined, and a vocabulary constraint
 * here would be the one place a tenant with six labels could not express its
 * sixth"*. An enum here would therefore make a tenant's own sixth label an
 * `invalid_enum_value`, which `request()` turns into `response_shape`, which
 * blanks the entire list. A tenant vocabulary the client has no word for is a
 * display gap; it is not a reason to refuse to draw the other seven rows.
 *
 * `rank` is parsed and not rendered. It is the ordinal every sensitivity
 * comparison is made against, and stating it here is how the next reader learns
 * the server sends it — a field silently dropped from a schema is a field the
 * next feature re-requests.
 */
const RecentClassification = z.object({
  key: z.string(),
  label: z.string(),
  rank: z.number(),
});

/**
 * One row of `GET /api/v1/me/recent`.
 *
 * `capabilities` is `entities/file`'s `FileCapabilities` — the same strict
 * twelve-key object `GET /files/{id}` and every listing row are parsed through.
 * Declaring a second one here is exactly `ENC-929`: two schemas for one server
 * object drift, and the drift shows up as a UI that changes its mind about what
 * a user may do depending on which screen it read the file from. `ENC-807` is
 * what that costs when it happens — the server grew `move` and `restore`, one
 * copy of the schema learned about them, and the product's main listing
 * rendered its failure state against a healthy server for a month.
 */
const RecentItem = z.object({
  fileId: z.string(),
  name: z.string(),
  /** Without the leading dot, and `null` for a name with no dot in it. */
  extension: z.string().nullable(),
  mimeType: z.string(),
  classification: RecentClassification.nullable(),
  lastAccessedAt: z.string(),
  libraryId: z.string(),
  /** `null` at a library root. */
  parentFolderId: z.string().nullable(),
  capabilities: FileCapabilities,
});

/**
 * The page, and the count that makes an empty one legible.
 *
 * `filteredCount` is **required**, and it is the one field here worth refusing a
 * response over. `docs/09 §11` renders two different empty states from it, and
 * defaulting a missing count to `0` would collapse *"some of what you opened is
 * no longer yours to open"* into *"you have not opened anything"* — silently,
 * confidently, and in the direction that hides a policy decision from the person
 * it was made about.
 */
const RecentPage = z.object({
  items: z.array(RecentItem),
  filteredCount: z.number(),
});

export type RecentPage = z.infer<typeof RecentPage>;

/**
 * The tenant-vocabulary keys this build has a word for.
 *
 * A lookup rather than an exhaustive map, because the column it reads is
 * deliberately open (see `RecentClassification`). A key that is not here draws
 * no badge: the chip's contract is that colour is never the only carrier
 * (`docs/09 §15`), so a level the catalog cannot name in words is a level this
 * client may not draw in colour either.
 *
 * `features/search/model.ts` holds the same six pairs as a closed `z.enum`,
 * which is a second copy and should not stay one — a feature may not import
 * another feature (`docs/17 §2`), so the shared home is
 * `entities/classification`. Noted rather than reached for.
 */
const LEVEL: Record<string, ClassificationLevel> = {
  PUBLIC: 'public',
  INTERNAL: 'internal',
  CONFIDENTIAL: 'confidential',
  HIGHLY_CONFIDENTIAL: 'highlyConfidential',
  RESTRICTED: 'restricted',
  UNCLASSIFIED: 'unclassified',
};

/**
 * One recent row, as the *Continue working* list wants it.
 *
 * The name is split by `entities/file`'s `splitName` rather than by the
 * server's `extension`, and both values are honest — they just answer different
 * questions. The server sends `txt`; the row draws `.txt` in a dimmer span
 * inside the name, so it needs the stem and the suffix *as one split of one
 * string*. Re-deriving that from `name.slice(0, name.length - extension.length)`
 * would be a second splitting rule in the tree, and `splitName` exists because
 * there were once fourteen.
 *
 * The icon tint comes from `mimeType` and never from the extension, for
 * `present.ts`'s reason: the extension is user-supplied text and the MIME type
 * is the server's own reading of the bytes.
 */
export function recentFromItem(item: z.infer<typeof RecentItem>): RecentFile {
  const { stem, extension } = splitName(item.name);
  return {
    id: item.fileId,
    name: stem,
    extension,
    kind: kindOf(item.mimeType),
    classification: item.classification === null ? null : (LEVEL[item.classification.key] ?? null),
    openedAt: Date.parse(item.lastAccessedAt),
    location: {
      libraryId: item.libraryId,
      folderId: item.parentFolderId,
      capabilities: item.capabilities,
    },
  };
}

/**
 * Eight, because the server caps there and says so.
 *
 * `routes::recent::MAX_LIMIT` is `8` and clamps anything larger, so asking for
 * more would be a request that quietly gets a different answer than it made.
 * The list is unvirtualized for the same reason (`specs/home.md` §C) — a hard
 * cap of eight is what makes that safe rather than a bet.
 */
const RECENT_LIMIT = 8;

export function useRecent(): UseQueryResult<RecentPage> {
  return useQuery({
    queryKey: ['me', 'recent'],
    queryFn: ({ signal }) => request(`/me/recent?limit=${RECENT_LIMIT}`, RecentPage, { signal }),
    /* Recency changes on every file this person opens, and Home is where they
     * come back to after opening one. A cached page here is the specific thing
     * that makes the section look broken. */
    staleTime: 0,
    retry: false,
  });
}
