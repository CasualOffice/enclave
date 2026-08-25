import type { DlpRule, SimulationResult } from './model.ts';

/* Review fixtures, and one of them is a fixture on purpose rather than for want
 * of a server.
 *
 * `RULES` stands in for `GET /admin/dlp/rules` until a gateway is running in
 * front of this build; the schema and the path it will be parsed with are real
 * (`api.ts`), so swapping the source changes one call site.
 *
 * `SIMULATION` is different: `docs/05 §14` names `/admin/dlp/simulate` and
 * describes what it does, but **no request or response shape is written down**
 * for it anywhere in the pack. Inventing one in `api.ts` would create a second
 * contract for somebody to implement against by accident, so the shape lives in
 * `model.ts` as a local type and the data lives here, clearly a fixture.
 *
 * Nothing here carries a matched value, and there is no field one could go in.
 * `docs/09 §9` — explain in category terms, never echo the sensitive value.
 */

export const RULES: readonly DlpRule[] = [
  {
    id: 'r-ext-restricted',
    name: 'Block restricted external sharing',
    priority: 100,
    scope: ['external_sharing', 'public_link'],
    conditions: [
      { classification_at_least: { classification: 'restricted' } },
      { category_at_least: { category: 'PAYMENT_CARD', count: 1 } },
      { category_at_least: { category: 'AADHAAR', count: 1 } },
      { category_at_least: { category: 'API_KEY', count: 1 } },
    ],
    action: 'BLOCK',
    decodes: true,
  },
  {
    id: 'r-card-download',
    name: 'Justify downloads of payment data',
    priority: 200,
    scope: ['download', 'export'],
    conditions: [{ category_at_least: { category: 'PAYMENT_CARD', count: 5 } }],
    action: 'REQUIRE_JUSTIFICATION',
    decodes: true,
  },
  {
    id: 'r-secrets-audit',
    name: 'Watch for credentials leaving the tenant',
    priority: 300,
    scope: ['exposes_content'],
    conditions: [{ category_at_least: { category: 'CREDENTIAL', count: 1 } }],
    action: 'AUDIT',
    decodes: true,
  },
];

/** The rule the prototype draws, as it would exist before it is written. */
export const DRAFT: DlpRule = {
  id: 'draft',
  name: 'Block restricted external sharing',
  priority: 100,
  scope: ['external_sharing', 'public_link'],
  conditions: [
    { classification_at_least: { classification: 'restricted' } },
    { category_at_least: { category: 'PAYMENT_CARD', count: 1 } },
    { category_at_least: { category: 'AADHAAR', count: 1 } },
    { category_at_least: { category: 'API_KEY', count: 1 } },
  ],
  action: 'BLOCK',
  decodes: true,
};

/** What the rehearsal would have said. Categories, counts and people — no values. */
export const SIMULATION: SimulationResult = {
  windowDays: 30,
  ranAt: '2026-08-18T09:20:00.000Z',
  wouldRefuse: 37,
  attempts: 214,
  people: 19,
  files: 1240,
  libraries: 3,
  byWorkspace: [
    { workspace: 'Finance', count: 22 },
    { workspace: 'Legal', count: 9 },
    { workspace: 'Sales', count: 5 },
    { workspace: 'People ops', count: 1 },
  ],
  events: [
    {
      actorName: 'Priya Nair',
      actorInitials: 'PN',
      actorTone: 'a',
      scope: 'public_link',
      resource: 'Helios MSA',
      at: '2026-08-15T11:04:00.000Z',
      categories: ['PAYMENT_CARD'],
    },
    {
      actorName: 'Rahul Shah',
      actorInitials: 'RS',
      actorTone: 'c',
      scope: 'external_sharing',
      resource: 'Board pack',
      at: '2026-08-12T16:41:00.000Z',
      categories: ['PAYMENT_CARD', 'AADHAAR'],
    },
    {
      actorName: 'Anita Kulkarni',
      actorInitials: 'AK',
      actorTone: 'b',
      scope: 'external_sharing',
      resource: 'Rate card',
      at: '2026-08-09T08:12:00.000Z',
      categories: ['API_KEY'],
    },
  ],
};
