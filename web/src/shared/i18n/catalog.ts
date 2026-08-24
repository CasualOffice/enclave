/* The message catalog.
 *
 * `CLAUDE.md` rule 12 and `docs/14 §8` between them say: no user-facing string
 * literal outside a catalog, every key namespaced and stable, and every key
 * carrying a translator description. The catalog is a single object rather than
 * a JSON file so that `MessageKey` below is a union type — a mistyped key is a
 * compile error rather than a `[missing key]` rendered at a customer.
 *
 * Locale negotiation, lazy per-locale bundles and the `en-XA`/`en-XB`
 * pseudo-locales are M5 step 5 and deliberately absent here: this file
 * establishes the pattern the first component is written against so nothing
 * has to be retrofitted, and stops short of the scaffolding that owns the rest.
 *
 * Keys are never derived from English text (`docs/14 §4`) — rewording
 * "Restricted" must not orphan five translations.
 */

export interface CatalogEntry {
  /** The `en-US` source string, in ICU MessageFormat. Never concatenated. */
  readonly message: string;
  /** Where it appears and what each placeholder means. Required, per `docs/14 §8` rule 5. */
  readonly description: string;
}

export const catalog = {
  'files.list.label': {
    message: 'Files',
    description: 'Accessible name of the file list grid. Announced by a screen reader on entry.',
  },
  'files.list.rowCount': {
    message:
      '{shown, plural, one {# item} other {# items}} of {total, plural, one {# item} other {# items}}',
    description:
      'Polite live-region summary of the virtualized list. "shown" counts rows inside expanded groups; "total" counts every row including collapsed ones.',
  },
  'files.column.name': {
    message: 'Name',
    description: 'File list column header: the file name.',
  },
  'files.column.modified': {
    message: 'Modified',
    description: 'File list column header: who last changed the file and when.',
  },
  'files.column.classification': {
    message: 'Classification',
    description:
      'File list column header: the sensitivity label (Public through Restricted). Not a status.',
  },
  'files.column.status': {
    message: 'Status',
    description:
      'File list column header: effect pills such as a retention period or a download restriction. Empty for most rows.',
  },
  'files.column.size': {
    message: 'Size',
    description: 'File list column header: the file size on disk.',
  },
  'files.group.expand': {
    message: 'Expand {group}',
    description:
      'Accessible name of the collapsed group header button. "group" is the group name, e.g. a folder or a customer.',
  },
  'files.group.collapse': {
    message: 'Collapse {group}',
    description: 'Accessible name of the expanded group header button. "group" is the group name.',
  },
  'files.group.count': {
    message: '{count, plural, one {# item} other {# items}}',
    description:
      'Item count shown beside a group name in the group header, expanded or collapsed. Also the collapsed group’s only clue to what it hides, so it is never omitted.',
  },
  'files.row.checkbox': {
    message: 'Select {name}',
    description: 'Accessible name of a file row’s selection checkbox. "name" is the file name.',
  },

  'classification.public': {
    message: 'Public',
    description:
      'Sensitivity label, lowest of five. Shown as a badge with a locked colour; the text is what carries the meaning (docs/09 §15).',
  },
  'classification.internal': {
    message: 'Internal',
    description: 'Sensitivity label, second of five.',
  },
  'classification.confidential': {
    message: 'Confidential',
    description: 'Sensitivity label, third of five.',
  },
  'classification.highlyConfidential': {
    message: 'Highly confidential',
    description:
      'Sensitivity label, fourth of five. Abbreviate in translation if the column would clip; the badge is 108px wide.',
  },
  'classification.restricted': {
    message: 'Restricted',
    description: 'Sensitivity label, highest of five.',
  },
  'classification.unclassified': {
    message: 'Unclassified',
    description:
      'Shown for a file that has no sensitivity label yet. Not a sixth level — an absence.',
  },

  'files.state.loading': {
    message: 'Loading files',
    description:
      'Announced while the skeleton rows are on screen. The skeleton itself is decorative.',
  },
  'files.state.empty.title': {
    message: 'Nothing here yet',
    description: 'Heading of the empty state for a library that has never had a file in it.',
  },
  'files.state.empty.body': {
    message: 'Upload a file, or create a folder to organise one into.',
    description:
      'Body of the new-empty state. Says what the surface is for and names the one action that starts it (docs/09 §11).',
  },
  'files.state.empty.action': {
    message: 'Upload files',
    description: 'Primary action on the new-empty state.',
  },
  'files.state.filtered.title': {
    message: 'No files match these filters',
    description: 'Heading of the empty state when filters are active and exclude everything.',
  },
  'files.state.filtered.body': {
    message:
      '{count, plural, one {# file is hidden by the active filters.} other {# files are hidden by the active filters.}}',
    description:
      'Body of the filtered-empty state. "count" is how many rows the unfiltered query would return, so the user can tell an empty library from an over-narrow filter.',
  },
  'files.state.filtered.action': {
    message: 'Clear filters',
    description: 'Action on the filtered-empty state. Restores the unfiltered list.',
  },
  'files.state.error.title': {
    message: 'This list could not be loaded',
    description:
      'Heading of the fetch-error state. Says what failed, not why — the reason belongs in the detail disclosure.',
  },
  'files.state.error.body': {
    message: 'The request did not complete. Nothing has changed.',
    description:
      'Body of the retryable fetch-error state. Reassures that a failed read changed nothing.',
  },
  'files.state.error.bodyFinal': {
    message: 'The request cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of the fetch-error state when the failure is not retryable.',
  },
  'files.state.error.retry': {
    message: 'Try again',
    description: 'Retry action on the fetch-error state. Present only when the error is retryable.',
  },
  'files.state.error.requestId': {
    message: 'Request ID',
    description:
      'Label for the copyable correlation ID on the error state (docs/09 §11). The value is not translated.',
  },
  'files.state.error.copy': {
    message: 'Copy request ID',
    description: 'Accessible name of the button that copies the request ID to the clipboard.',
  },
} as const satisfies Record<string, CatalogEntry>;

export type MessageKey = keyof typeof catalog;

/** The shape `react-intl` wants: key to ICU string, descriptions dropped. */
export function messagesFor(source: typeof catalog): Record<string, string> {
  return Object.fromEntries(Object.entries(source).map(([key, entry]) => [key, entry.message]));
}
