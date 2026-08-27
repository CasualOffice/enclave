import { defineConfig, devices } from '@playwright/test';

/* Two projects, one browser.
 *
 * `a11y` is the `test:a11y` gate: axe against every primary route, in real
 * Chromium rather than in jsdom, because half of what `docs/09 §15` commits to
 * — 4.5:1 text contrast, 3:1 for UI components, visible focus at 3:1 — depends
 * on computed style and layout, and jsdom has neither. A jsdom axe run would
 * pass while enforcing the half that does not matter, which is the shape of
 * defect this whole task exists to stop repeating.
 *
 * `bench` is the performance measurement for `docs/09 §2`. It is a separate
 * project because it is slow, it is not a pass/fail gate, and it must not be
 * retried — a retried timing is an averaged timing.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: process.env['CI'] !== undefined,
  reporter: process.env['CI'] !== undefined ? [['github'], ['list']] : [['list']],
  webServer: {
    command: 'npm run build && npm run preview',
    url: 'http://127.0.0.1:4174',
    /* Never reuse, not even locally.
     *
     * The default is to reuse a running dev server off CI, and it cost two
     * sessions real time: `npm run build && npm run preview` is the command,
     * so a preview left running from an earlier build keeps serving *that*
     * build, and the suite reports green against code that is no longer in the
     * tree. Both a deliberately broken virtualizer and a deliberately broken
     * scroll restore passed that way before anyone noticed the server was
     * stale — which is the same "reads as passing while inspecting nothing"
     * failure this whole milestone is about, one layer down in the harness.
     *
     * The cost is about a second of rebuild per run. That is cheaper than one
     * misleading result. */
    reuseExistingServer: false,
    timeout: 180_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4174',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\/.*\.spec\.ts/,
      retries: 1,
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'bench',
      testMatch: /bench\/.*\.spec\.ts/,
      retries: 0,
      timeout: 180_000,
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1440, height: 900 },
        launchOptions: {
          args: [
            // Without this the compositor caps at the display's refresh rate and
            // every frame reads as exactly 16.7 ms whatever the work costs, so
            // the measurement would describe the monitor rather than the list.
            '--disable-frame-rate-limit',
            '--disable-gpu-vsync',
          ],
        },
      },
    },
  ],
});
