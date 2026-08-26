import type { FileRow } from '../../entities/file/model.ts';
import type {
  ActiveFilter,
  Crumb,
  PeekFile,
  PresenceMember,
  SavedView,
  StatusPillSpec,
} from './model.ts';

/* The library chrome's fixture.
 *
 * Everything here is a stand-in for an endpoint that does not exist yet —
 * `GET /libraries/{id}/views`, `/facets`, `/breadcrumb`, presence, and the peek
 * payload (`specs/library.md`, "Backend required"). It is a fixture rather than
 * markup so that the components already take the shape the server will send,
 * and swapping the source is a change to this file and to nothing else.
 *
 * The saved-view labels and facet names are catalog keys rather than strings
 * because there is no server sending localized ones yet, and a literal in
 * `web/src` is `CLAUDE.md` rule 12. Names of *things* — a folder, a vendor, a
 * person — are data and are never translated.
 */

export const BREADCRUMB: readonly Crumb[] = [
  { id: 'ws', name: 'Finance' },
  { id: 'lib', name: 'Contracts' },
  { id: 'folder', name: '2026' },
];

export const PRESENCE: readonly PresenceMember[] = [
  { id: 'u-pn', initials: 'PN', tone: 'a' },
  { id: 'u-ak', initials: 'AK', tone: 'b' },
  { id: 'u-rs', initials: 'RS', tone: 'c' },
];

export const SAVED_VIEWS: readonly SavedView[] = [
  { id: 'all', label: 'library.view.all', count: 8 },
  { id: 'expiring', label: 'library.view.expiring', count: 2 },
  { id: 'approval', label: 'library.view.needsApproval', count: 1 },
  { id: 'restricted', label: 'library.view.restricted', count: 2 },
];

export const ACTIVE_FILTERS: readonly ActiveFilter[] = [
  { id: 'type', facet: 'library.facet.type', value: 'PDF, Word' },
  { id: 'modified', facet: 'library.facet.modified', value: 'Last 30 days' },
];

/** What the group-by and sort controls currently read. Server-rendered values. */
export const VIEW_SUMMARY = { groupBy: 'Vendor', sortBy: 'Modified' };

/**
 * Status pills, by row id.
 *
 * Keyed rather than carried on `FileRow` on purpose: the tone and the label both
 * come from the server row (`row.status.{tone,code}`) and the client never picks
 * a tone from a permission it inferred. Until the listing endpoint sends them,
 * this map stands in for that field and the row model stays unchanged.
 */
const PILLS: readonly StatusPillSpec[] = [
  { tone: 'warn', label: 'fileStatus.noDownload', icon: 'block' },
  { tone: 'ok', label: 'fileStatus.approved' },
  { tone: 'neutral', label: 'fileStatus.checkedOut' },
  { tone: 'neutral', label: 'fileStatus.retain7y' },
  { tone: 'danger', label: 'fileStatus.legalHold' },
];

/**
 * A deterministic pill for a row, or none.
 *
 * Most rows carry none — the prototype's status column is mostly empty, and a
 * column where every row has a badge is a column nobody reads.
 */
export function pillFor(row: FileRow): StatusPillSpec | undefined {
  const digits = row.id.replace(/\D/g, '');
  if (digits.length === 0) return undefined;
  const seed = Number(digits.slice(-3));
  if (seed % 4 !== 0) return undefined;
  return PILLS[(seed / 4) % PILLS.length];
}

/** The peek payload for a row, as `GET /files/{id}` will send it. */
export function peekFor(row: FileRow): PeekFile {
  const pill = pillFor(row);
  const restricted = row.classification === 'restricted';
  return {
    id: row.id,
    name: row.name,
    extension: row.extension,
    classification: row.classification,
    version: 'v3.2',
    sizeBytes: row.sizeBytes,
    owner: row.modifiedByInitials,
    modifiedAt: row.modifiedAt,
    pills: [
      ...(pill === undefined ? [] : [pill]),
      ...(restricted
        ? ([
            { tone: 'neutral', label: 'fileStatus.watermarked' },
            { tone: 'neutral', label: 'fileStatus.retain7y' },
          ] as const)
        : []),
    ],
    facts: [
      { key: 'library.peek.fact.owner', value: row.modifiedByInitials },
      { key: 'library.peek.fact.location', value: 'Finance / Contracts / 2026' },
      { key: 'library.peek.fact.retention', value: '7 years' },
      { key: 'library.peek.fact.indexed', value: 'Ready' },
    ],
    /* The server decides this, and in the real payload it arrives with the
     * watermark text already composed. Restricted content is watermarked on
     * preview (`docs/09 §9`), which is why the flag tracks the label here. */
    watermarked: restricted,
  };
}
