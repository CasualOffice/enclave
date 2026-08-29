import { execFileSync } from 'node:child_process';
import { defineConfig, devices } from '@playwright/test';

/* The browser suite that talks to the **real** API.
 *
 * ## Why this is a second config rather than a third project in the first one
 *
 * `playwright.config.ts` runs `npm run build && npm run preview` and serves a
 * static bundle with nothing behind it, so every screen there reaches an origin
 * with no `/api` at all and `tests/a11y/api-stub.ts` supplies the responses.
 * That is the correct arrangement for what it measures — contrast, focus order,
 * names and roles are properties of the markup, not of where the bytes came
 * from — and it must not change. But it means the whole existing suite runs at a
 * `baseURL` with no server and a `webServer` that would fight this one for a
 * port. Adding a project to that file would have made both facts conditional on
 * `--project`, which is how a config grows a branch that nobody can read.
 *
 * So: separate file, separate `baseURL`, separate `webServer`, and
 * `playwright.config.ts` untouched.
 *
 * ## The origin, and why it is not `127.0.0.1`
 *
 * `CLAUDE.md` rule 3 and the long comment in `vite.config.ts`: the tenant is the
 * first label of the `Host` the API was reached on. `tenant-alpha.localhost`
 * *is* the tenant claim; plain `localhost` has no tenant and is refused before a
 * handler runs. The proxy sets `changeOrigin: false` precisely so the browser's
 * own `Host` survives, so this suite has to drive a browser at that host or it
 * would be testing an origin the real gateway rejects.
 */

const DEV_HOST = process.env['ENCLAVE_DEV_HOST'] ?? 'tenant-alpha.localhost';
const DEV_PORT = process.env['ENCLAVE_DEV_PORT'] ?? '5173';
/* The same two variables `vite.config.ts` reads, with the same defaults. If the
 * proxy target and the address probed below could disagree, the preflight would
 * be able to pass against an API the browser never reaches. */
const API_TARGET = process.env['ENCLAVE_API_TARGET'] ?? 'http://127.0.0.1:8080';

const BASE_URL = `http://${DEV_HOST}:${DEV_PORT}`;

/* `crates/api/src/lib.rs` puts `/health/live` and `/health/ready` outside
 * `/api/v1` and on the policy-routing allowlist: no tenant, no actor, no
 * resource. `ready` rather than `live` because a process that is listening but
 * has no database behind it would answer every test with a 500 and the report
 * would read as a client defect. Probed directly rather than through the Vite
 * proxy because the proxy only forwards `/api`, so `/health/ready` 404s there —
 * and because this has to run before the dev server is known to exist. */
const READY_URL = `${API_TARGET}/health/ready`;

/**
 * Refuse to start a run the API cannot serve.
 *
 * This is the whole reason the suite exists, so it is a hard failure at config
 * load and there is no fallback anywhere: no stub, no fixture, no skip, no
 * `test.fixme`. A suite that quietly degrades to fixtures when the server is
 * down is a more expensive copy of `tests/a11y` wearing this one's name, and it
 * would report green on exactly the days it matters — which is the "green gate
 * proving nothing" shape this file was written to close.
 *
 * Synchronous, in a subprocess, because a Playwright config is evaluated
 * synchronously and cannot `await`. `execFileSync` throws on a non-zero exit, so
 * an unreachable API, a non-2xx `ready` and a ten-second hang all land in the
 * same `catch` and produce the same named error before a browser is launched.
 */
function requireReachableApi(): void {
  try {
    execFileSync(
      process.execPath,
      [
        '-e',
        'fetch(process.argv[1]).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))',
        READY_URL,
      ],
      { timeout: 10_000, stdio: 'ignore' },
    );
  } catch {
    throw new Error(
      `The end-to-end suite needs a live API and ${READY_URL} did not answer 2xx.\n` +
        'These tests exist to prove the client and the server agree; there is no fixture\n' +
        'fallback and there must never be one. Start the stack (PostgreSQL, MinIO, Redis,\n' +
        'NATS and enclave-api), seed tenant-alpha, and run this again. Point it elsewhere\n' +
        'with ENCLAVE_API_TARGET, which is the same variable vite.config.ts proxies to.',
    );
  }
}

requireReachableApi();

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  forbidOnly: process.env['CI'] !== undefined,
  reporter: process.env['CI'] !== undefined ? [['github'], ['list']] : [['list']],
  /* One worker. The tests sign in as the one seeded administrator, and
   * `auth.refresh_token.rotation` is on with `reuse_detection: REVOKE_FAMILY`
   * (`shared/api/session.ts`) — parallel workers holding cookies from the same
   * account are a family-revocation race waiting to be blamed on the client. */
  workers: 1,
  /* No retries, deliberately, and this is the opposite call from `a11y`.
   *
   * There the retry absorbs a compositor timing read; here every test is a
   * round trip to a real server, so a failure that passes on the second attempt
   * is a *finding* — a session that did not survive, a refresh that raced, a
   * seed that was not ready. Retrying would turn the one class of defect this
   * suite is built to surface into a green run with a footnote. */
  retries: 0,
  webServer: {
    command: 'npm run dev',
    url: BASE_URL,
    /* **Reuse, unlike `playwright.config.ts`** — and the difference is the
     * point rather than an inconsistency.
     *
     * That file must never reuse because its command is
     * `npm run build && npm run preview`: a preview left running from an
     * earlier build keeps serving *that* build, so the suite reports green
     * against code no longer in the tree. Twice that cost a session.
     *
     * `npm run dev` has no such artifact. Vite transforms each module from disk
     * on request and its watcher invalidates on write, so a dev server started
     * an hour ago serves the file as it is now. The stale-build hazard is a
     * property of the build step, not of reuse, and importing the rule without
     * its reason would cost a full dev-server boot per local run while
     * protecting against nothing.
     *
     * Two guards make the reuse honest. `strictPort` in `vite.config.ts` means
     * a second server cannot quietly land on another port and be tested while
     * the first serves the browser. And if something *else* is answering on
     * this port, the first assertion in `tests/e2e/sign-in.spec.ts` is that the
     * product's own sign-in card is on screen — so a foreign server fails the
     * run by name rather than being mistaken for this one. */
    reuseExistingServer: true,
    /* A cold `npm run dev` pre-bundles dependencies on first boot. */
    timeout: 120_000,
  },
  use: {
    baseURL: BASE_URL,
    /* Every request in this suite reaches a real handler, a real policy chain
     * and a real database, so the per-action default is generous where the
     * fixture suites can afford to be strict. */
    actionTimeout: 15_000,
  },
  projects: [
    {
      name: 'e2e',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
  ],
});
