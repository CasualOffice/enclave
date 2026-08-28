import { z } from 'zod';
import { useQuery, type UseQueryResult } from '@tanstack/react-query';
import { request } from '../../shared/api/client.ts';
import type { RetrievalMode, SearchResult } from './model.ts';


/* `POST /api/v1/search`, as the route actually answers it.
 *
 * ## Why this schema is not `model.ts`'s
 *
 * `model.ts` describes what the *screen* renders; this describes what the
 * *server* sends, and the two are not the same shape. Keeping them apart is the
 * difference between a parse failure and a silent mis-render: if the wire schema
 * were relaxed until the view model fitted, a genuinely missing `title` would
 * arrive as `undefined` and be drawn as an empty row.
 *
 * ## The filters this route refuses
 *
 * `SearchRequest` on the server is `deny_unknown_fields`, and every narrowing
 * filter it declares — `workspaceIds`, `libraryIds`, `types`,
 * `classificationMax`, `modifiedAfter`, `cursor` — answers `400` naming the
 * field rather than being accepted and ignored.
 *
 * That refusal is correct and worth understanding, because it is tempting to
 * read it as a bug: a narrowing filter that is accepted and then not applied
 * returns **more** than the caller asked for. A `classificationMax` of
 * `INTERNAL` answered with `CONFIDENTIAL` hits is a disclosure produced by a
 * field that read as working. So the client sends `query`, `mode` and `limit`
 * and nothing else, and the filter controls render as unbuilt rather than
 * sending something that will 400.
 */

const WireHit = z.object({
  fileId: z.string(),
  versionId: z.string().optional(),
  title: z.string(),
  path: z.string(),
  workspace: z.string(),
  mimeType: z.string(),
  score: z.number(),
  excerpt: z.string().nullable(),
  capabilities: z.object({ preview: z.boolean(), download: z.boolean() }),
});

const WireResponse = z.object({
  results: z.array(WireHit),
  page: z.object({
    nextCursor: z.string().nullish(),
    hasMore: z.boolean(),
  }),
  diagnostics: z.object({
    mode: z.string(),
    /**
     * Whether recall was reduced.
     *
     * **This is now a decision, not a constant** (`ENC-698`). It used to be
     * `true` on every request, and honestly so — the API process held no vector
     * index, so from here the store was not merely empty but unreachable. It
     * holds one now, so `degraded: true` means the store was reachable once and
     * is not now, and `false` means retrieval ran as configured.
     *
     * The field kept its meaning while the value stopped being fixed, which is
     * why nothing in this schema changed. What did have to change is
     * `retrieval-notice.tsx`: it read anything-but-hybrid as *lexical* and so
     * told a user semantic search was unavailable while semantic search was
     * answering them (`ENC-675`).
     */
    degraded: z.boolean(),
  }),
});

export interface SearchOutcome {
  readonly results: readonly SearchResult[];
  readonly diagnostics: { readonly mode: RetrievalMode; readonly degraded: boolean };
  readonly hasMore: boolean;
}

function modeOf(wire: string): RetrievalMode {
  return wire === 'hybrid' ? 'hybrid' : wire === 'semantic' ? 'dense' : 'lexical';
}

export async function search(
  query: string,
  limit: number,
  signal?: AbortSignal,
): Promise<SearchOutcome> {
  const body = await request('/search', WireResponse, {
    method: 'POST',
    /* Three fields. Adding a fourth is a `400`, by design — see the header. */
    body: { query, limit },
    ...(signal === undefined ? {} : { signal }),
  });

  return {
    /* The mapping is a widening, not a filling-in: every field the screen wants
     * and the server does not send is left `undefined` so the row draws nothing
     * there. See `model.ts` for why a default would be worse than an absence. */
    results: body.results.map((hit) => ({
      fileId: hit.fileId,
      ...(hit.versionId === undefined ? {} : { versionId: hit.versionId }),
      title: hit.title,
      path: hit.path,
      workspace: hit.workspace,
      mimeType: hit.mimeType,
      score: hit.score,
      excerpt: hit.excerpt,
      capabilities: hit.capabilities,
    })),
    diagnostics: { mode: modeOf(body.diagnostics.mode), degraded: body.diagnostics.degraded },
    hasMore: body.page.hasMore,
  };
}

/** How many results one request asks for. The server clamps anything above 50. */
const LIMIT = 50;

export function useSearch(query: string): UseQueryResult<SearchOutcome> {
  return useQuery({
    queryKey: ['search', query],
    queryFn: ({ signal }) => search(query, LIMIT, signal),
    /* An empty box is not a search. Without this the screen would fire a request
     * on mount and render "no results" before anyone had typed — which reads as
     * an empty corpus rather than as an empty query. */
    enabled: query.trim().length > 0,
    /* Each row carries `capabilities`, so nothing here is served stale
     * (`docs/17 §4.1`). */
    staleTime: 0,
    retry: false,
  });
}
