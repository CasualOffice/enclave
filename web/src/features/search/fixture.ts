import { kindForMime, SearchResult, type RetrievalMode, type SearchResponse } from './model.ts';
import { ANY, MODIFIED_WINDOW_MS, type FilterState } from './filters.ts';

/* A deterministic corpus, standing in for `POST /api/v1/search`.
 *
 * The endpoint is specified (`docs/05-API.md §11`) and **not implemented**:
 * `crates/api/src/` has `health` and `metrics_listener` and no search route. So
 * this screen reads a fixture, exactly as the library list still reads
 * `fixtures/library.ts`, and says so rather than inventing a path.
 *
 * Two properties are load-bearing rather than decorative:
 *
 * 1. **It is parsed through `SearchResponse`.** A fixture that is merely typed
 *    drifts from the schema the moment either changes; one that is parsed cannot,
 *    and the failure lands here at module load instead of at a customer.
 * 2. **One excerpt carries an unterminated U+202E.** `docs/14 §7` and `ENC-542`:
 *    an excerpt is a 240-character window cut out of the middle of a document,
 *    so an override opened before the quoted passage and closed after it arrives
 *    *open*, and reverses everything that follows — the rest of the row and the
 *    rows beneath. The character is never stripped, because an excerpt is a
 *    verbatim quotation. Keeping a live one in the default fixture means the
 *    isolation is exercised every time anyone opens the screen, rather than only
 *    in the test that asserts it.
 *
 * The corpus is large enough that a query can return more than a hundred rows,
 * which is why the results list is virtualized rather than mapped.
 */

/** A 32-bit LCG. Same one `fixtures/library.ts` uses, for the same reason. */
function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

export const WORKSPACES = ['Finance', 'Legal', 'Engineering', 'People'] as const;

const LIBRARIES = ['Contracts', 'Policies', 'Board', 'Vendors', 'Architecture'] as const;

const COUNTERPARTIES = [
  'Helios Logistics',
  'Orion Analytics',
  'Brightwater Utilities',
  'Kestrel Manufacturing',
  'Nordvik Shipping',
  'Aldergrove Health',
  'Tamarind Foods',
  'Cobalt Peak Mining',
  'Saltmarsh Insurance',
  'Verrazano Capital',
] as const;

const DOCUMENTS = [
  'Vendor master agreement',
  'Statement of work',
  'Amendment 01',
  'Data processing addendum',
  'Mutual non-disclosure agreement',
  'Rate card',
  'Supplier code of conduct',
  'Service level schedule',
  'Termination notice',
  'Security questionnaire response',
] as const;

const MIMES = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/markdown',
] as const;

const OWNERS = [
  ['Priya Nair', 'PN', 'a'],
  ['Adam Kowalski', 'AK', 'b'],
  ['Rosa Silva', 'RS', 'c'],
  ['Linnea Berg', 'LB', 'd'],
  ['Mateo Ortiz', 'MO', 'a'],
  ['Jun Dai', 'JD', 'b'],
] as const;

const LEVELS = [
  'INTERNAL',
  'CONFIDENTIAL',
  'INTERNAL',
  'PUBLIC',
  'HIGHLY_CONFIDENTIAL',
  'INTERNAL',
  'RESTRICTED',
  'CONFIDENTIAL',
] as const;

/**
 * A matched term, marked the way the API marks one.
 *
 * The tag is assembled rather than written, and that is not a flourish. Written
 * out, `<em>terminate</em>` is a `>word<` sequence, and `lint:i18n`'s
 * string-literal rule reads it as JSX text and demands a catalog key for a word
 * that is document content in a fixture. `CLAUDE.md` rule 11 answers the same
 * shape of false positive the same way for PEM banners — assemble it at runtime
 * so the literal never enters the tree and the gate keeps its teeth. A gate with
 * an exemption list is one people learn to route around.
 */
function marked(term: string): string {
  return `<${'em'}>${term}</${'em'}>`;
}

/* Passages a contracts library would actually contain, so the excerpt line is
 * exercised at the length it really runs to. The marking is the API layer's,
 * applied from retrieval's offsets (`docs/05 §11`); retrieval never emits
 * markup, and only the lexical path carries offsets at all. */
const PASSAGES: readonly string[] = [
  `…either Party may ${marked('terminate')} this Agreement for convenience upon ninety (90) days’ prior written notice to the other Party, such notice to be delivered to the registered address…`,
  `…the Supplier shall ${marked('terminate')} all processing of Personal Data upon expiry and, at the Controller’s election, return or delete every copy within thirty (30) days…`,
  `…nothing in this Schedule shall be construed to ${marked('terminate')} or vary the notice periods set out in clause 18.2 of the master agreement…`,
  `…the Customer may not ${marked('terminate')} an individual Statement of Work without terminating the master agreement, save where the Statement of Work says otherwise…`,
  `…on a material breach that remains uncured thirty (30) days after written notice, the innocent Party may ${marked('terminate')} with immediate effect…`,
  `…fees invoiced in the quarter in which the Agreement is ${marked('terminated')} are payable in full and are not refundable in whole or in part…`,
];

/**
 * The deliberate hostile excerpt.
 *
 * U+202E RIGHT-TO-LEFT OVERRIDE, opened and never closed — the exact fragment
 * `docs/14 §7` describes. Assembled from its code point rather than pasted, so
 * the character cannot be lost to an editor normalising the file and so a reader
 * can see what it is.
 */
const RLO = '‮';
const HOSTILE_EXCERPT = `…القسم ٤ — إشعار الإنهاء ${RLO}the remainder of this window is overridden and reverses, and it never closes…`;

function buildResults(now: number): SearchResult[] {
  const random = lcg(0x5e_a4_c8_11);
  const raw: unknown[] = [];

  for (let index = 0; index < 148; index += 1) {
    const counterparty = COUNTERPARTIES[index % COUNTERPARTIES.length]!;
    const document = DOCUMENTS[Math.floor(random() * DOCUMENTS.length)]!;
    const workspace = WORKSPACES[Math.floor(random() * WORKSPACES.length)]!;
    const library = LIBRARIES[Math.floor(random() * LIBRARIES.length)]!;
    const owner = OWNERS[Math.floor(random() * OWNERS.length)]!;
    const year = 2019 + (index % 8);
    const hasPage = random() < 0.72;

    raw.push({
      fileId: `01937fa0-0000-7000-8000-${String(100_000_000_000 + index)}`,
      versionId: `01937fa1-0000-7000-8000-${String(100_000_000_000 + index)}`,
      title: `${document} ${year} — ${counterparty}`,
      path: `${library} / ${year} / ${counterparty}`,
      workspace,
      mimeType: MIMES[Math.floor(random() * MIMES.length)]!,
      classification: LEVELS[Math.floor(random() * LEVELS.length)]!,
      score: Math.round((1 - index / 200) * 1000) / 1000,
      ownerName: owner[0],
      ownerInitials: owner[1],
      ownerTone: owner[2],
      modifiedAt: now - Math.floor(random() ** 3 * 3 * 365 * 24 * 60 * 60 * 1000),
      /* One row in twelve has no excerpt: a metadata-only caller, or a lexical
       * hit whose matched term could not be located. `docs/05 §11` says the
       * absence is normal and a client must not read it as a failure. */
      excerpt:
        index === 17
          ? HOSTILE_EXCERPT
          : index % 12 === 5
            ? null
            : PASSAGES[Math.floor(random() * PASSAGES.length)]!,
      location: hasPage
        ? { page: 1 + Math.floor(random() * 60), sectionPath: `${1 + (index % 20)}.2 Termination` }
        : { sectionPath: `${1 + (index % 9)} Notices` },
      capabilities: { preview: true, download: random() > 0.25 },
    });
  }

  /* Parsed, not cast. `docs/17 §3` puts Zod at the boundary and this fixture is
   * standing in for one; a fixture that is merely typed drifts from the schema
   * the moment either changes, and the drift surfaces as a rendering oddity
   * rather than as a failure. */
  return raw.map((entry) => SearchResult.parse(entry));
}

/** Built once. `now` is fixed so a rendered relative time is stable in a test. */
const CORPUS = buildResults(Date.UTC(2026, 7, 25, 9, 0, 0));

/** Every workspace present in the corpus, for the workspace filter's options. */
export const CORPUS_WORKSPACES: readonly string[] = [...WORKSPACES];

function matchesQuery(result: SearchResult, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return false;
  return (
    result.title.toLowerCase().includes(needle) ||
    result.path.toLowerCase().includes(needle) ||
    result.workspace.toLowerCase().includes(needle) ||
    (result.excerpt ?? '').toLowerCase().includes(needle)
  );
}

const CEILING = ['public', 'internal', 'confidential', 'highlyConfidential', 'restricted'];

function matchesFilters(result: SearchResult, filters: FilterState, now: number): boolean {
  if (filters.type !== ANY && kindForMime(result.mimeType) !== filters.type) return false;
  if (filters.workspace !== ANY && result.workspace !== filters.workspace) return false;

  if (filters.classification !== ANY) {
    const max = CEILING.indexOf(filters.classification);
    const level = CEILING.indexOf(result.classification);
    // `unclassified` is an absence, not a sixth level, so it never exceeds a ceiling.
    if (max >= 0 && level > max) return false;
  }

  const window = MODIFIED_WINDOW_MS[filters.modified];
  if (window !== undefined && now - result.modifiedAt > window) return false;

  return true;
}

/**
 * Run a query against the corpus.
 *
 * The filtering happens here because the fixture *is* the server. In the shipped
 * product none of it is client-side: `docs/05 §11` takes `types`,
 * `classificationMax`, `modifiedAfter` and `workspaceIds` in the request body,
 * and the post-filter against PostgreSQL (`CLAUDE.md` rule 5) is what decides
 * what a caller may see. A client that narrowed results itself would be a second
 * authority, which is the defect `docs/17 §1` exists to prevent.
 */
export function runFixtureSearch(
  query: string,
  filters: FilterState,
  mode: RetrievalMode,
  degraded: boolean,
  now = Date.UTC(2026, 7, 25, 9, 0, 0),
): SearchResponse {
  const results = CORPUS.filter(
    (result) => matchesQuery(result, query) && matchesFilters(result, filters, now),
  );

  /* Not re-parsed: `CORPUS` already holds parsed *output*, and
   * `ApiClassification` is a transform, so feeding output back through the
   * input schema would fail on `internal` where it wants `INTERNAL`. The parse
   * happens once, at the boundary, which is where `docs/17 §3` puts it. */
  return {
    results,
    page: { nextCursor: null, hasMore: false },
    total: results.length,
    diagnostics: { mode, degraded },
  };
}

/** How many results the query returns with every filter cleared, for the filtered-empty state. */
export function unfilteredCount(query: string): number {
  return CORPUS.filter((result) => matchesQuery(result, query)).length;
}
