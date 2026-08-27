import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { CLASSIFICATION_KEY } from '../../entities/classification/model.ts';

/* Filters, and the one property that makes them worth having.
 *
 * `docs/09 §10`: filters are chips that compose and are individually removable,
 * and **the active filter set is reflected in the URL so a search is shareable
 * and restorable**. `docs/17 §4` puts filters in the URL for the same reason and
 * adds the negative one — a filtered view a colleague cannot open is a worse
 * product, and a filter kept in a store is exactly that view.
 *
 * So the URL is the state, not a copy of it. This module is the codec between
 * the two, and it is pure: everything here is testable without a DOM, which is
 * how the "removing a chip changes the URL" assertion stays about behaviour
 * rather than about React.
 *
 * A filter at its default is **absent** from the query string rather than
 * present as `any`. A shared link should carry what the sender chose and
 * nothing else; `?q=x` and `?q=x&type=any&modified=any&workspace=any` describe
 * the same search and only one of them is readable.
 */

export type FilterId = 'type' | 'classification' | 'modified' | 'workspace';

export const FILTER_IDS: readonly FilterId[] = ['type', 'classification', 'modified', 'workspace'];

/** The value every filter carries when it is not narrowing anything. */
export const ANY = 'any';

/**
 * One choice in a filter's menu.
 *
 * Two shapes because two kinds of label exist and conflating them is how a
 * server-supplied name ends up needing a translation. `label` is a catalog key —
 * "Any", "PDF", "Restricted". `text` is data the server owns, such as a
 * workspace name, which is rendered as it arrives with `dir="auto"` and is never
 * translated (`docs/14 §6`).
 */
export type FilterOption =
  | { readonly value: string; readonly label: MessageKey }
  | { readonly value: string; readonly text: string };

export interface FilterDef {
  readonly id: FilterId;
  /** The chip's leading half: what this filter is. Always a catalog key. */
  readonly label: MessageKey;
  readonly options: readonly FilterOption[];
}

export type FilterState = Readonly<Record<FilterId, string>>;

export const NO_FILTERS: FilterState = {
  type: ANY,
  classification: ANY,
  modified: ANY,
  workspace: ANY,
};

/** File-type buckets, matching `entities/file`'s icon tints. */
const TYPE_OPTIONS: readonly FilterOption[] = [
  { value: ANY, label: 'search.filter.any' },
  { value: 'pdf', label: 'search.filter.type.pdf' },
  { value: 'doc', label: 'search.filter.type.doc' },
  { value: 'xls', label: 'search.filter.type.xls' },
  { value: 'ppt', label: 'search.filter.type.ppt' },
];

/* The sensitivity ceiling, not an equality: `classificationMax` in
 * `docs/05 §11`. "Confidential" means *at most* Confidential, which is the
 * question a user actually has — "show me what I can circulate" — and the names
 * come from `entities/classification` so no component maps a level to a word. */
const CLASSIFICATION_OPTIONS: readonly FilterOption[] = [
  { value: ANY, label: 'search.filter.any' },
  { value: 'public', label: CLASSIFICATION_KEY.public },
  { value: 'internal', label: CLASSIFICATION_KEY.internal },
  { value: 'confidential', label: CLASSIFICATION_KEY.confidential },
  { value: 'highlyConfidential', label: CLASSIFICATION_KEY.highlyConfidential },
  { value: 'restricted', label: CLASSIFICATION_KEY.restricted },
];

const MODIFIED_OPTIONS: readonly FilterOption[] = [
  { value: ANY, label: 'search.filter.modified.any' },
  { value: '7d', label: 'search.filter.modified.week' },
  { value: '30d', label: 'search.filter.modified.month' },
  { value: '1y', label: 'search.filter.modified.year' },
];

/** How far back each `modified` value reaches, in milliseconds. */
export const MODIFIED_WINDOW_MS: Readonly<Record<string, number>> = {
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
  '1y': 365 * 24 * 60 * 60 * 1000,
};

/**
 * The four filters, given the workspaces this tenant has.
 *
 * Workspaces are data, so the list is a parameter rather than a constant: in the
 * shipped product it comes from the same response the results do, and here it
 * comes from the fixture. Nothing about the chip changes.
 */
export function filterDefs(workspaces: readonly string[]): readonly FilterDef[] {
  return [
    { id: 'type', label: 'search.filter.type', options: TYPE_OPTIONS },
    { id: 'classification', label: 'search.filter.classification', options: CLASSIFICATION_OPTIONS },
    { id: 'modified', label: 'search.filter.modified', options: MODIFIED_OPTIONS },
    {
      id: 'workspace',
      label: 'search.filter.workspace',
      options: [
        { value: ANY, label: 'search.filter.any' },
        ...workspaces.map((name) => ({ value: name, text: name })),
      ],
    },
  ];
}

export function readFilters(params: URLSearchParams): FilterState {
  return {
    type: params.get('type') ?? ANY,
    classification: params.get('classification') ?? ANY,
    modified: params.get('modified') ?? ANY,
    workspace: params.get('workspace') ?? ANY,
  };
}

/** Which filters are narrowing the query, in chip order. */
export function activeFilters(filters: FilterState): readonly FilterId[] {
  return FILTER_IDS.filter((id) => filters[id] !== ANY);
}

/**
 * The whole query string for a query and a filter set.
 *
 * Whole, because `replaceParams` in `app/routes.ts` replaces the search string
 * rather than merging into it — so a caller that passed only the changed key
 * would silently drop the others. Building the complete set here is what makes
 * that impossible to get wrong from a chip's `onClear`.
 */
export function toParams(query: string, filters: FilterState): Record<string, string> {
  const params: Record<string, string> = {};
  if (query.length > 0) params['q'] = query;
  for (const id of FILTER_IDS) {
    const value = filters[id];
    if (value !== ANY) params[id] = value;
  }
  return params;
}
