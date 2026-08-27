import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

/* Unmount between tests.
 *
 * Testing Library auto-cleans only when Vitest's `globals` is on, and it is
 * deliberately off here — an implicit global `expect` is exactly the kind of
 * thing that makes a test file readable only to someone who already knows the
 * harness. The cost is that this has to be wired by hand, and until it was,
 * **renders stacked**: every `render()` appended to the same `document.body`,
 * so a query for "the disabled button" saw the previous test's DOM as well as
 * its own.
 *
 * Found by the Home session, which watched nine of its tests pass and fail
 * against a document assembled by their predecessors. That is the worst kind of
 * defect in a test harness: it does not make tests fail, it makes them
 * *unreliable*, and an unreliable green is the thing this project keeps paying
 * for. Every absence assertion in the tree — "no denied control is rendered",
 * "nothing is in the tab order" — was being evaluated against a document that
 * might contain another test's controls.
 */
afterEach(() => {
  cleanup();
});

/* `Blob.arrayBuffer()`, which jsdom does not implement.
 *
 * It has been in the File API standard since 2019 and every browser has it;
 * jsdom's `Blob` simply predates it. The upload digest reads a file through it,
 * so without this the digest tests fail on the environment rather than on the
 * code — and the tempting "fix" is to rewrite `digest.ts` around `FileReader`,
 * which would make the shipped code worse to satisfy a test harness.
 *
 * Polyfilled through `FileReader`, which jsdom *does* implement, so the bytes
 * still travel jsdom's own Blob machinery and a bug in the chunked read would
 * still be caught.
 *
 * The real path is exercised for real in `tests/a11y`, which runs in Chromium
 * where none of this applies.
 */
if (typeof Blob !== 'undefined' && typeof Blob.prototype.arrayBuffer !== 'function') {
  Blob.prototype.arrayBuffer = function arrayBuffer(this: Blob): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(this);
    });
  };
}
