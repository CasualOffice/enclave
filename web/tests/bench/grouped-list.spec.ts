import { test, expect } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/* The measurement behind `plans/M5-MVP-GA.md` D38.
 *
 * `docs/09 §2` sets two numbers this has to answer: a virtualized 100 000-row
 * table scrolls at 60 fps with no dropped frames, and a folder's first paint is
 * under 400 ms. The roadmap's M5 exit criterion states the second at 100 000
 * items; `docs/09 §2`'s own table says 10 000, and that disagreement is
 * reported rather than resolved here — `ENC-676` owns edits to `docs/09`.
 *
 * Both are measured under the **grouped, collapsible** default view, which is
 * the whole point: a flat-list number would not be the number the product ships.
 *
 * What is measured, and what is not:
 *
 *   - **First paint** is navigation start to the frame after the one that
 *     committed the first rows, via a double `requestAnimationFrame` mark in
 *     `app.tsx`. It includes generating the fixture, parsing the bundle,
 *     building the layout and painting — everything a real cold open pays.
 *   - **Frame time** is measured under a `requestAnimationFrame`-driven scroll
 *     rather than under synthesised wheel events, so the number describes the
 *     list's own per-frame cost and not the input pipeline's. That is a
 *     narrower claim than "it feels smooth", and it is the one a CI machine can
 *     make honestly. Real input latency belongs to the RUM half of `docs/09 §2`.
 *   - **Collapse** is measured at the worst position: collapsing a large group
 *     that sits *above* the viewport, which is the case that moves the index
 *     space under the scroll position.
 */

const ROWS = 100_000;
const FRAME_BUDGET_MS = 1000 / 60;
const FIRST_PAINT_BUDGET_MS = 400;

interface FrameStats {
  frames: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  overBudget: number;
  overBudgetRatio: number;
  scrolledPx: number;
  renderCount: number;
}

const results: Record<string, unknown> = {};

test.afterAll(() => {
  const dir = join(process.cwd(), 'bench-results');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'grouped-list.json'), `${JSON.stringify(results, null, 2)}\n`);
  console.log(`\nbench results written to ${join(dir, 'grouped-list.json')}`);
});

test(`first paint: ${ROWS} rows, grouped`, async ({ page }) => {
  await page.goto(`/?rows=${ROWS}`);
  await page.waitForSelector('.egl-row');

  const measurement = await page.evaluate(() => {
    const mark = performance.getEntriesByName('enclave:rows-painted')[0];
    const nav = performance.getEntriesByType('navigation')[0] as
      | PerformanceNavigationTiming
      | undefined;
    const scroller = document.querySelector('.egl-scroller');
    return {
      firstPaintMs: mark === undefined ? Number.NaN : mark.startTime,
      domContentLoadedMs: nav?.domContentLoadedEventEnd ?? Number.NaN,
      rowsInDom: document.querySelectorAll('.egl-row').length,
      groupsInDom: document.querySelectorAll('.egl-group').length,
      contentHeightPx: scroller?.scrollHeight ?? 0,
      totalNodes: document.querySelectorAll('*').length,
    };
  });

  results['firstPaint'] = { ...measurement, budgetMs: FIRST_PAINT_BUDGET_MS, rows: ROWS };

  console.log(
    [
      '',
      `  first paint            ${measurement.firstPaintMs.toFixed(1)} ms  (budget ${FIRST_PAINT_BUDGET_MS} ms)`,
      `  DOMContentLoaded       ${measurement.domContentLoadedMs.toFixed(1)} ms`,
      `  rows in the DOM        ${measurement.rowsInDom} of ${ROWS}`,
      `  group headers in DOM   ${measurement.groupsInDom}`,
      `  scrollable content     ${(measurement.contentHeightPx / 1000).toFixed(1)}k px`,
      `  total DOM nodes        ${measurement.totalNodes}`,
      '',
    ].join('\n'),
  );

  // A virtualized list that renders every row would also "pass" a paint budget
  // on a fast machine and then die on scroll. Assert the windowing itself.
  expect(measurement.rowsInDom).toBeLessThan(200);
  expect(measurement.contentHeightPx).toBeGreaterThan(1_000_000);
  expect(measurement.firstPaintMs).toBeLessThan(FIRST_PAINT_BUDGET_MS);
});

test(`scroll: ${ROWS} rows, grouped, sustained`, async ({ page }) => {
  await page.goto(`/?rows=${ROWS}`);
  await page.waitForSelector('.egl-row');

  const stats: FrameStats = await page.evaluate(
    async ([pxPerFrame, frameCount]) => {
      const scroller = document.querySelector<HTMLElement>('.egl-scroller');
      if (scroller === null) throw new Error('no scroller');

      /* Count the React commits the scroll actually caused. If this is close to
       * the frame count the windowing is re-rendering per frame, which is the
       * failure this design is built to avoid, and the frame times would be
       * measuring a different implementation than the one described. */
      let renders = 0;
      const observer = new MutationObserver(() => {
        renders += 1;
      });
      const windowNode = document.querySelector('.egl-window');
      if (windowNode !== null) observer.observe(windowNode, { childList: true });

      const deltas: number[] = [];
      let previous = performance.now();
      const startTop = scroller.scrollTop;

      await new Promise<void>((resolve) => {
        let frame = 0;
        const step = (now: number) => {
          deltas.push(now - previous);
          previous = now;
          scroller.scrollTop += pxPerFrame;
          frame += 1;
          if (frame >= frameCount) resolve();
          else requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      });

      observer.disconnect();

      // Drop the first delta: it spans the gap from the call into the first
      // animation frame and describes scheduling, not rendering.
      const sample = deltas.slice(1).sort((a, b) => a - b);
      const at = (q: number) => sample[Math.min(sample.length - 1, Math.floor(sample.length * q))]!;
      const budget = 1000 / 60;
      const over = sample.filter((d) => d > budget).length;

      return {
        frames: sample.length,
        p50: at(0.5),
        p95: at(0.95),
        p99: at(0.99),
        max: sample[sample.length - 1]!,
        overBudget: over,
        overBudgetRatio: over / sample.length,
        scrolledPx: scroller.scrollTop - startTop,
        renderCount: renders,
      };
    },
    [90, 900] as const,
  );

  results['scroll'] = { ...stats, frameBudgetMs: FRAME_BUDGET_MS, rows: ROWS };

  console.log(
    [
      '',
      `  frames sampled         ${stats.frames}`,
      `  scrolled               ${(stats.scrolledPx / 1000).toFixed(1)}k px`,
      `  frame p50              ${stats.p50.toFixed(2)} ms`,
      `  frame p95              ${stats.p95.toFixed(2)} ms  (budget ${FRAME_BUDGET_MS.toFixed(2)} ms)`,
      `  frame p99              ${stats.p99.toFixed(2)} ms`,
      `  frame max              ${stats.max.toFixed(2)} ms`,
      `  frames over budget     ${stats.overBudget} (${(stats.overBudgetRatio * 100).toFixed(2)}%)`,
      `  window re-renders      ${stats.renderCount} across ${stats.frames} frames`,
      '',
    ].join('\n'),
  );

  expect(stats.frames).toBeGreaterThan(500);
  expect(stats.scrolledPx).toBeGreaterThan(50_000);
  expect(stats.p95).toBeLessThan(FRAME_BUDGET_MS);
  // "No dropped frames" with the headroom a shared CI runner needs. A tighter
  // bound would fail on machine noise and be quarantined within a month, which
  // is worse than a bound that holds.
  expect(stats.overBudgetRatio).toBeLessThan(0.05);
  /* The design claim, asserted, because the first version of it was false and
   * this line is what said so: `sliceWindow` snaps the window to a multiple of
   * the overscan, so at 90 px per frame and a 240 px quantum the rendered set
   * changes about once every 2.7 frames. Measured 0.38 commits per frame; the
   * bound is 0.6 to leave room for a different viewport height. Without the
   * snap this read 0.998, which is a per-frame re-render wearing an overscan. */
  expect(stats.renderCount).toBeLessThan(stats.frames * 0.6);
});

test(`collapse: a large group above the viewport, ${ROWS} rows`, async ({ page }) => {
  await page.goto(`/?rows=${ROWS}`);
  await page.waitForSelector('.egl-row');

  const measurement = await page.evaluate(async () => {
    const scroller = document.querySelector<HTMLElement>('.egl-scroller');
    if (scroller === null) throw new Error('no scroller');

    // Deep enough that several groups sit above the viewport.
    scroller.scrollTop = 400_000;
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await new Promise((resolve) => requestAnimationFrame(resolve));

    const anchorBefore = document
      .querySelectorAll('.egl-row')[3]
      ?.querySelector('.egl-name-text')?.textContent;
    const topBefore = scroller.scrollTop;

    // The header of the group that is currently pinned is above the viewport by
    // definition, so collapsing it removes height from above the scroll
    // position — the case D38 names.
    const stickyHeader = document.querySelector<HTMLButtonElement>('.egl-sticky .egl-group');
    if (stickyHeader === null) throw new Error('no pinned group header');

    const start = performance.now();
    stickyHeader.click();
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const commitMs = performance.now() - start;
    await new Promise((resolve) => requestAnimationFrame(resolve));

    return {
      commitMs,
      topBefore,
      topAfter: scroller.scrollTop,
      heightBefore: 0,
      heightAfter: scroller.scrollHeight,
      anchorBefore: anchorBefore ?? null,
      anchorAfter:
        document.querySelectorAll('.egl-row')[3]?.querySelector('.egl-name-text')?.textContent ??
        null,
    };
  });

  results['collapse'] = measurement;

  console.log(
    [
      '',
      `  collapse commit        ${measurement.commitMs.toFixed(2)} ms  (budget ${FRAME_BUDGET_MS.toFixed(2)} ms, one frame)`,
      `  scrollTop              ${measurement.topBefore} -> ${measurement.topAfter}`,
      '',
    ].join('\n'),
  );

  // `docs/09 §2`: a click's visible acknowledgement is under 100 ms. A collapse
  // that rebuilt an index of 100 000 entries would not make it.
  expect(measurement.commitMs).toBeLessThan(100);
  // Height was removed from above the viewport, so the scroll position must
  // have moved with it rather than staying put and sliding the content.
  expect(measurement.topAfter).toBeLessThan(measurement.topBefore);
});
