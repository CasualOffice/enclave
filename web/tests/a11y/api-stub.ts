import type { Page, Route } from '@playwright/test';

/* The API, stubbed at the browser's network layer for the accessibility run.
 *
 * ## Why this exists now and did not before
 *
 * Every screen used to read a local fixture, so `npm run preview` served a
 * fully-populated product with no server behind it and axe could walk it. The
 * screens read the real API now, and the preview server has no API — so without
 * this every route would render the sign-in screen and the gate would check one
 * page fifty times while reporting fifty passes. That is the `ENC-677` failure
 * shape exactly, and it is the reason the surface list has an emptiness
 * assertion in the first place.
 *
 * ## Why stubbing here is not the thing this milestone was fixing
 *
 * The objection to fixtures was that the *product* shipped them: a user signed
 * in and saw invented files. Nothing here ships. `web/src` contains no fixture
 * import on any wired screen, and these responses exist only inside a Playwright
 * process. What is being tested is the rendering — contrast, focus order, names,
 * roles — which is a property of the markup and not of where the bytes came
 * from.
 *
 * The responses below are the **real wire shapes**, taken from
 * `crates/api/src/content.rs`, `routes/search.rs` and `workflows.rs`. Stubbing a
 * shape the server does not send would let the gate pass against markup the
 * product can never render.
 */

export interface ApiPlan {
  /** `false` makes `/me` and the refresh unauthenticated, so the app shows sign-in. */
  readonly signedIn?: boolean;
  /** How many rows `GET /libraries/{id}/items` returns. */
  readonly items?: number;
  /** How many results `POST /search` returns. */
  readonly results?: number;
  /** How many rows `GET /workflows/tasks` returns. */
  readonly tasks?: number;
  /** Force one status for every data route, so the failure and denial states can be reached. */
  readonly status?: 403 | 500;
  /** Never answer, so the loading state stays on screen for axe to read. */
  readonly hang?: boolean;
  /** `diagnostics.degraded` on the search response. */
  readonly degraded?: boolean;
}

const VIEWER = {
  id: '11111111-1111-4111-8111-111111111111',
  tenantId: '22222222-2222-4222-8222-222222222222',
  email: 'admin@tenant-alpha.example',
  displayName: 'Admin User',
  isAdmin: true,
  capabilities: { readSelf: true },
};

/** The ten-field capability object, as `content.rs` serializes it. */
function capabilities(index: number) {
  /* Not all `true`. A row where every action is permitted would let markup that
   * ignores `capabilities` entirely pass this gate, and the refused treatment
   * would never be rendered for axe to check its contrast. */
  const restricted = index % 3 === 0;
  return {
    metadataRead: true,
    preview: true,
    download: !restricted,
    print: !restricted,
    export: !restricted,
    edit: true,
    share: true,
    shareExternal: false,
    delete: !restricted,
    sync: !restricted,
  };
}

const OBLIGATIONS = { watermark: false, justificationRequired: [], approvalRequired: [] };

const NAMES = [
  'FY26 Board Pack.pdf',
  'Treasury Position.xlsx',
  'Remuneration Committee.docx',
  'Investor Update Q3.pptx',
  'Cash Flow Forecast.xlsx',
  'Statutory Accounts 2025.pdf',
  'Bank Covenants.pdf',
  'Risk Register.xlsx',
];

const MIMES = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
];

function item(index: number) {
  const modified = new Date(Date.UTC(2026, 7, 20) - index * 3_600_000).toISOString();
  return {
    id: `file-${index}`,
    type: index < 3 ? 'FOLDER' : 'FILE',
    name: index < 3 ? `Folder ${index + 1}` : `${NAMES[index % NAMES.length]}`,
    mimeType: index < 3 ? 'application/x-directory' : (MIMES[index % MIMES.length] ?? 'text/plain'),
    sizeBytes: index < 3 ? 0 : 100_000 + index * 977,
    libraryId: 'lib-1',
    status: 'AVAILABLE',
    revision: 1,
    capabilities: capabilities(index),
    obligations: OBLIGATIONS,
    createdAt: modified,
    modifiedAt: modified,
  };
}

function hit(index: number) {
  return {
    fileId: `file-${index}`,
    versionId: `version-${index}`,
    title: NAMES[index % NAMES.length] ?? 'Document.pdf',
    path: 'Finance / Board Documents',
    workspace: 'Finance',
    mimeType: MIMES[index % MIMES.length] ?? 'application/pdf',
    score: 0.9 - index * 0.001,
    excerpt: 'the <em>agreement</em> shall commence on the first of the month',
    capabilities: { preview: true, download: index % 3 !== 0 },
  };
}

function task(index: number) {
  return {
    stepId: `step-${index}`,
    instanceId: `instance-${index}`,
    fileId: `file-${index}`,
    versionId: `version-${index}`,
    stepType: (['APPROVAL', 'REVIEW', 'SIGNATURE'] as const)[index % 3],
    stage: 1,
    stageName: ['Finance approval', 'Legal review', 'Board signature'][index % 3],
    delegated: false,
    dueAt: new Date(Date.UTC(2026, 7, 28)).toISOString(),
  };
}

async function json(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'x-request-id': '01a0402d-cb72-76e2-8f0e-ee21277e71e0' },
    body: JSON.stringify(body),
  });
}

const DENIAL = {
  error: {
    code: 'ACCESS_DENIED',
    message: 'You do not have access to this.',
    remediation: 'Ask the library owner for access.',
    requestId: '01a0402d-cb72-76e2-8f0e-ee21277e71e0',
    details: [],
  },
};

const FAULT = {
  error: {
    code: 'INTERNAL',
    message: 'Something went wrong.',
    remediation: '',
    requestId: '01a0402d-cb72-76e2-8f0e-ee21277e71e0',
    details: [],
  },
};

/** Install the stub. Call once per page, before the first navigation. */
export async function stubApi(page: Page, plan: ApiPlan = {}): Promise<void> {
  const signedIn = plan.signedIn !== false;
  const items = plan.items ?? 400;
  const results = plan.results ?? 40;
  const tasks = plan.tasks ?? 3;

  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace('/api/v1', '');

    /* `/me` decides whether the shell renders at all, so it is answered before
     * any forced status: a `500` on every route would otherwise stop the app at
     * the boot-failure screen and no feature state would be reachable. */
    if (path === '/me') {
      if (!signedIn) return json(route, DENIAL, 401);
      return json(route, VIEWER);
    }

    if (path === '/auth/refresh') {
      if (!signedIn) return json(route, DENIAL, 401);
      return json(route, { accessToken: 'stub-token', expiresIn: 600 });
    }

    /* Never answers. The screen stays in its loading state, which is a state
     * `docs/09 §11` requires and axe has to be able to read. */
    if (plan.hang === true) return new Promise(() => undefined);

    if (plan.status === 403) return json(route, DENIAL, 403);
    if (plan.status === 500) return json(route, FAULT, 500);

    if (path.endsWith('/items')) {
      return json(route, {
        items: Array.from({ length: items }, (_unused, index) => item(index)),
        page: { hasMore: false, limit: 50 },
      });
    }

    if (path === '/search') {
      return json(route, {
        results: Array.from({ length: results }, (_unused, index) => hit(index)),
        page: { nextCursor: null, hasMore: false },
        diagnostics: { mode: 'lexical', degraded: plan.degraded ?? false },
      });
    }

    if (path === '/workflows/tasks') {
      return json(route, {
        items: Array.from({ length: tasks }, (_unused, index) => task(index)),
        page: { nextCursor: null, hasMore: false },
      });
    }

    if (path.startsWith('/files/')) {
      return json(route, {
        ...item(3),
        id: path.slice('/files/'.length),
        currentVersion: { id: 'version-3', major: 1, minor: 0, status: 'AVAILABLE' },
        aclRevision: 1,
        governance: { onLegalHold: false, isRecord: false },
      });
    }

    if (path === '/admin/dlp/rules') {
      return json(route, { items: [], page: { nextCursor: null, hasMore: false } });
    }

    return json(route, { items: [], page: { nextCursor: null, hasMore: false } });
  });
}
