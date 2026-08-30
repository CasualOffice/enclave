import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { AuditScreen } from '../../src/features/admin/audit/audit-screen.tsx';
import { AuditPage } from '../../src/features/admin/audit/model.ts';

/* The audit screen (`ENC-961`).
 *
 * `docs/12 §1.2`: **an assertion about an absence passes for free.** Two of the
 * four tests below are absences — an identifier that must not be rendered, and
 * circumstances that must not be on screen until asked for — so each is paired
 * with a positive control in the same render that a blank component could not
 * satisfy.
 *
 * Every row is fed through the Zod schema, the way one really arrives, rather
 * than hand-built as a typed object: that is the boundary the guarantee lives
 * at (`docs/17 §3`), and it is what makes these tests about our code.
 */

/** A UUID that must never reach the DOM as a name. */
const MACHINE_ID = '9c1f52f0-1d3a-4c77-9c9e-4e0d0c4b2a11';
/** An address that must not be on screen until somebody asks for it. */
const ADDRESS = '198.51.100.24';

function row(over: Record<string, unknown> = {}) {
  return {
    id: '01a0532c-3a10-7d60-ae53-9c10030eee8e',
    sequence: 4089,
    occurredAt: '2026-08-30T14:56:42.512078Z',
    actorType: 'user',
    actorId: '6f1d7ad4-4b1e-4d55-9a2f-4c9a7b2e1d33',
    actorName: 'Ada Lovelace',
    onBehalfOf: null,
    action: 'file.download',
    resourceType: 'file',
    resourceId: 'e2d1b6a4-0c31-4a55-8b2f-1c9a7b2e1d44',
    workspaceId: null,
    outcome: 'ALLOW',
    reasonCode: null,
    policyRefs: [],
    requestId: '01a0532b-b595-79a2-9d1c-c21e01536bb1',
    sessionId: null,
    clientType: 'web',
    deviceId: null,
    ip: ADDRESS,
    country: null,
    userAgent: null,
    detail: {},
    previousHash: null,
    eventHash: null,
    ...over,
  };
}

/** Serves one page, and records what was asked for. */
function serve(items: unknown[], asked: string[] = []) {
  return async (input: RequestInfo | URL) => {
    const url = String(input);
    asked.push(url);
    const body = AuditPage.parse({ items, nextCursor: null });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <I18nProvider>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </I18nProvider>
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('the audit screen', () => {
  /* `ENC-958`, one surface later. Two screens could say when something happened
   * and not who did it, because the id was on the wire and the name was not. An
   * audit table is the worst place to repeat it: an investigation is a question
   * about people, and a column of UUIDs answers it only for somebody who
   * already has a second window open. */
  it('names an actor it can name, and never prints an identifier for one it cannot', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(serve([row(), row({ id: '01a0532c-3a10-7d60-ae53-9c10030eee8f', actorId: MACHINE_ID, actorName: null, actorType: 'service' })])),
    );
    render(<AuditScreen />, { wrapper: Wrapper });

    /* The positive control, on the same render: a blank table would satisfy the
     * absence below without it. */
    expect(await screen.findByText('Ada Lovelace')).toBeTruthy();
    expect(screen.getAllByText('somebody').length).toBe(1);
    expect(document.body.textContent).not.toContain(MACHINE_ID);
  });

  /* The circumstances are what separate this surface from `/me/activity` and
   * are the reason it needs `ReadAudit`. Being allowed to see somebody's
   * address is not a reason to put it on screen before anybody asked. */
  it('keeps the actor’s circumstances behind a disclosure', async () => {
    vi.stubGlobal('fetch', vi.fn(serve([row()])));
    render(<AuditScreen />, { wrapper: Wrapper });

    /* Awaited on the disclosure rather than on the action: `file.download` is
     * also the filter's placeholder, so awaiting it resolves against the
     * loading state and the assertion below passes against a table that never
     * rendered. That is exactly the vacuous pass `docs/12 §1.2` warns about,
     * and this test had it. */
    expect(await screen.findByText('Details')).toBeTruthy();
    expect(document.body.textContent).not.toContain(ADDRESS);

    fireEvent.click(screen.getByText('Details'));
    /* The control that stops this being an assertion about a disclosure that
     * does nothing: the address must actually appear once it is opened. */
    await waitFor(() => expect(document.body.textContent).toContain(ADDRESS));
  });

  /* A cursor is a position in one filtered sequence and means nothing in
   * another. Carrying it across a change of narrowing pages into the middle of
   * a result set the auditor has not seen the start of — and the page looks
   * like the whole answer, which is the failure an audit surface must not have. */
  it('returns to the head of the log whenever a narrowing changes', async () => {
    const asked: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        asked.push(url);
        const body = AuditPage.parse({ items: [row()], nextCursor: '4000' });
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
    render(<AuditScreen />, { wrapper: Wrapper });
    /* A row's own content, not the placeholder — see the note in the test above. */
    expect(await screen.findByText('Ada Lovelace')).toBeTruthy();

    fireEvent.click(screen.getByText('Older'));
    await waitFor(() => expect(asked.some((url) => url.includes('before=4000'))).toBe(true));

    fireEvent.click(screen.getByText('Refused'));
    await waitFor(() => expect(asked.some((url) => url.includes('outcome=DENY'))).toBe(true));

    const narrowed = asked.filter((url) => url.includes('outcome=DENY'));
    expect(narrowed.length).toBeGreaterThan(0);
    for (const url of narrowed) {
      expect(url).not.toContain('before=');
    }
  });

  /* A refusal is the chain working, thousands of times a day, and it is also
   * the row an investigation is looking for. It has to be findable without the
   * page reading as an incident — so `warn`, and `danger` reserved for `ERROR`,
   * which is the outcome that actually means something went wrong. */
  it('marks a refusal apart from a failure', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        serve([
          row({ outcome: 'DENY', reasonCode: 'ACCESS_DENIED' }),
          row({ id: '01a0532c-3a10-7d60-ae53-9c10030eee90', outcome: 'ERROR' }),
        ]),
      ),
    );
    render(<AuditScreen />, { wrapper: Wrapper });

    const deny = await screen.findByText('DENY');
    const error = screen.getByText('ERROR');
    expect(deny.getAttribute('data-tone')).toBe('warn');
    expect(error.getAttribute('data-tone')).toBe('danger');
  });
});
