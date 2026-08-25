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
