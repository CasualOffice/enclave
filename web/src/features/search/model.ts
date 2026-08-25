import { z } from 'zod';
import type { ClassificationLevel } from '../../entities/classification/model.ts';
import type { FileKind } from '../../entities/file/model.ts';

/* The search contract, as `docs/05-API.md §11` writes it.
 *
 * `POST /api/v1/search` is specified there and **is not implemented** — there is
 * no search route in `crates/api/src/`, only `health` and `metrics_listener`. So
 * this screen reads `fixture.ts` rather than the network, exactly as the library
 * list still reads `fixtures/library.ts`. The schema below is nonetheless the
 * documented response shape and the fixture is parsed *through* it at module
 * load, so the fixture cannot drift from the contract and the swap to
 * `request('/search', SearchResponse, { method: 'POST', body })` is one line.
 *
 * Two things the schema says that are worth reading twice:
 *
 * 1. **`excerpt` is nullable, and its absence is not a failure.** `docs/05 §11`:
 *    a metadata-only caller gets no excerpt, and the lexical path emits none when
 *    it cannot locate the matched term. A row without one is a normal row.
 * 2. **`diagnostics` is two independent facts, not one.** `mode` says which
 *    retrieval path answered; `degraded` says whether the vector store was
 *    unreachable. `lexical` + `degraded: false` is a deployment without dense
 *    retrieval — a product state. `degraded: true` is an incident. They read
 *    differently to a user and `retrieval-notice.tsx` renders them differently.
 */

/** Sensitivity as the API spells it (`docs/04 §…`: `PUBLIC, INTERNAL, CONFIDENTIAL, …`). */
const API_CLASSIFICATION = {
  PUBLIC: 'public',
  INTERNAL: 'internal',
  CONFIDENTIAL: 'confidential',
  HIGHLY_CONFIDENTIAL: 'highlyConfidential',
  RESTRICTED: 'restricted',
  UNCLASSIFIED: 'unclassified',
} as const satisfies Record<string, ClassificationLevel>;

export const ApiClassification = z
  .enum(Object.keys(API_CLASSIFICATION) as [keyof typeof API_CLASSIFICATION])
  .transform((value): ClassificationLevel => API_CLASSIFICATION[value]);

/**
 * Where in the document the hit is, so the row can deep-link into the preview at
 * that location (`docs/09 §10`).
 *
 * Every field is optional because not every format has every coordinate: a
 * spreadsheet has a sheet and no page, a Markdown file has neither.
 */
export const SearchLocation = z.object({
  page: z.number().int().positive().optional(),
  sheet: z.string().optional(),
  sectionPath: z.string().optional(),
});

export type SearchLocation = z.infer<typeof SearchLocation>;

export const SearchResult = z.object({
  fileId: z.string(),
  versionId: z.string(),
  title: z.string(),
  /** Human-readable ancestry, already joined by the API. */
  path: z.string(),
  workspace: z.string(),
  mimeType: z.string(),
  classification: ApiClassification,
  score: z.number(),
  /* `docs/09 §10` requires every result to show its owner and modified date.
   * `docs/05 §11`'s example response carries neither — reported rather than
   * quietly invented, and modelled here as the shape this screen needs. */
  ownerName: z.string(),
  ownerInitials: z.string(),
  ownerTone: z.enum(['a', 'b', 'c', 'd']),
  /** Epoch milliseconds. Formatted through `Intl` at render, never stored formatted. */
  modifiedAt: z.number(),
  /** Bounded at 240 characters plus elision marks, `<em>`-marked on the lexical path only. */
  excerpt: z.string().nullable(),
  location: SearchLocation.optional(),
  capabilities: z.object({ preview: z.boolean(), download: z.boolean() }),
});

export type SearchResult = z.infer<typeof SearchResult>;

/** Which retrieval path answered. `docs/07 §6`. */
export const RetrievalMode = z.enum(['hybrid', 'lexical', 'dense']);
export type RetrievalMode = z.infer<typeof RetrievalMode>;

export const SearchDiagnostics = z.object({
  mode: RetrievalMode,
  /** True when the vector store was unavailable and the query fell back to lexical-only. */
  degraded: z.boolean(),
});

export type SearchDiagnostics = z.infer<typeof SearchDiagnostics>;

export const SearchResponse = z.object({
  results: z.array(SearchResult),
  page: z.object({ nextCursor: z.string().nullable(), hasMore: z.boolean() }),
  /** How many results the query has in total, so the header can say so honestly. */
  total: z.number().int().nonnegative(),
  diagnostics: SearchDiagnostics,
});

export type SearchResponse = z.infer<typeof SearchResponse>;

/* ------------------------------------------------------------------ excerpts */

/**
 * One piece of an excerpt: the document's own text, and whether the API marked
 * it as a matched term.
 *
 * The API delivers the marking as `<em>` inside the `excerpt` string
 * (`docs/05 §11`), applied at the API layer from retrieval's offsets. **It is
 * never interpolated back into the DOM as markup.** `segmentExcerpt` reads the
 * two tags and returns text, which React then escapes on the way out — so a
 * document containing `<script>` is a document containing the characters
 * `<script>`, which is the only correct reading of a verbatim quotation.
 */
export interface ExcerptSegment {
  readonly text: string;
  readonly matched: boolean;
}

const EM_TAG = /<\/?em>/g;

/**
 * Split an excerpt on `<em>` … `</em>`.
 *
 * Deliberately not a parser. The only markup the API produces in this field is
 * `<em>` (`docs/07 §6.2.1`: "No markup is produced by retrieval"), so anything
 * else in the string is document text and stays document text. An unbalanced or
 * missing tag degrades to unmarked text rather than to an exception — a dense
 * hit arrives unmarked by design and a client must not read that as a failure.
 */
export function segmentExcerpt(excerpt: string): readonly ExcerptSegment[] {
  const segments: ExcerptSegment[] = [];
  let cursor = 0;
  let matched = false;
  EM_TAG.lastIndex = 0;

  for (let tag = EM_TAG.exec(excerpt); tag !== null; tag = EM_TAG.exec(excerpt)) {
    if (tag.index > cursor) segments.push({ text: excerpt.slice(cursor, tag.index), matched });
    matched = tag[0] === '<em>';
    cursor = tag.index + tag[0].length;
  }
  if (cursor < excerpt.length) segments.push({ text: excerpt.slice(cursor), matched });

  return segments;
}

/* ---------------------------------------------------------------- file kinds */

/** Icon tint buckets, from the MIME type the API returns. */
const MIME_KIND: readonly (readonly [string, FileKind])[] = [
  ['application/pdf', 'pdf'],
  ['application/vnd.openxmlformats-officedocument.wordprocessingml', 'doc'],
  ['application/msword', 'doc'],
  ['application/vnd.openxmlformats-officedocument.spreadsheetml', 'xls'],
  ['application/vnd.ms-excel', 'xls'],
  ['application/vnd.openxmlformats-officedocument.presentationml', 'ppt'],
  ['application/vnd.ms-powerpoint', 'ppt'],
];

export function kindForMime(mimeType: string): FileKind {
  for (const [prefix, kind] of MIME_KIND) {
    if (mimeType.startsWith(prefix)) return kind;
  }
  return 'other';
}
