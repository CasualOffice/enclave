import type { HomeData } from './model.ts';

/* Home's data, until Home has an endpoint.
 *
 * **This is a fixture, not a client.** `docs/05-API.md` defines no Home
 * resource, so there is no path to call and none is invented here — a URL in
 * the tree that nobody can serve is read as a contract by the next person, and
 * `shared/api/client.ts` is deliberately left untouched by this screen.
 *
 * It takes `now` rather than reading the clock, for the reason `fixtures/
 * library.ts` is seeded: a relative time measured against a moving origin
 * cannot be asserted, and "2 hours ago" is exactly the kind of value a test
 * should be able to pin.
 *
 * The content is drawn from the workspace the prototype shows — a finance team
 * mid-quarter — because a fixture of `file-1.pdf` hides every layout problem
 * this screen actually has: names long enough to reach the ellipsis, a
 * classification mix weighted the way a real tenant's is, and a question long
 * enough to test what a pill does when it cannot fit.
 *
 * **Two of the four attention items are approvals, and that is deliberate.** A
 * real queue repeats a kind far more often than it holds one of each, and two
 * controls carrying the same catalog label is precisely the case that used to
 * emit one DOM id twice and collide their `aria-describedby` — an axe
 * `duplicate-id-aria` failure, tagged `wcag2a`. `Button`'s `describedById` now
 * takes an id keyed on the item instead, so the fixture exercises the case that
 * would otherwise only appear in production, and
 * `tests/unit/home-controls.test.tsx` holds the line.
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function buildHome(now: Date): HomeData {
  const t = now.getTime();
  return {
    givenName: 'Priya',
    workspaceName: 'Finance',
    attention: [
      {
        id: 'attn-1',
        kind: 'approve',
        subject: 'Q3 vendor renewal — Helios Logistics',
        requesterName: 'Devika Rao',
        requesterInitials: 'DR',
        requesterTone: 'b',
        requestedAt: t - 2 * HOUR,
      },
      {
        id: 'attn-2',
        kind: 'approve',
        subject: 'Capital expenditure request CX-1180 — Ferngate Chemicals',
        requesterName: 'Marcus Whitfield',
        requesterInitials: 'MW',
        requesterTone: 'c',
        requestedAt: t - 27 * HOUR,
      },
      {
        id: 'attn-3',
        kind: 'review',
        subject: 'Statement of work 2026-0448 — Orion Analytics',
        requesterName: 'Sofia Okonkwo',
        requesterInitials: 'SO',
        requesterTone: 'a',
        requestedAt: t - 2 * DAY,
      },
      {
        id: 'attn-4',
        kind: 'sign',
        subject: 'Data processing addendum — Brightwater Utilities',
        requesterName: 'Anneke Vermeer',
        requesterInitials: 'AV',
        requesterTone: 'd',
        requestedAt: t - 4 * DAY,
      },
    ],
    recent: [
      {
        id: 'file-1',
        name: 'FY26 close checklist',
        extension: '.xlsx',
        kind: 'xls',
        classification: 'internal',
        openedAt: t - 35 * MINUTE,
      },
      {
        id: 'file-2',
        name: 'Board pack — treasury exposure and hedging position',
        extension: '.pptx',
        kind: 'ppt',
        classification: 'highlyConfidential',
        openedAt: t - 6 * HOUR,
      },
      {
        id: 'file-3',
        name: 'Helios Logistics master services agreement',
        extension: '.pdf',
        kind: 'pdf',
        classification: 'confidential',
        openedAt: t - 2 * DAY,
      },
      {
        id: 'file-4',
        name: 'Payroll variance notes',
        extension: '.docx',
        kind: 'doc',
        classification: 'restricted',
        openedAt: t - 9 * DAY,
      },
    ],
    asks: [
      { id: 'ask-1', text: 'Which contracts renew before the end of the quarter?' },
      { id: 'ask-2', text: 'Summarise the Orion pricing schedule' },
      { id: 'ask-3', text: 'Who approved the Brightwater DPA?' },
    ],
    hiddenByScope: 0,
  };
}
