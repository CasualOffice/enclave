import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { ResultRow } from '../../src/features/search/result-row.tsx';
import { segmentExcerpt, SearchResult } from '../../src/features/search/model.ts';

/* `globals: false` in `vite.config.ts`, so Testing Library never registers its own
 * auto-cleanup — it hooks a global `afterEach` that does not exist here. Without
 * this, each render is appended to the same document and every `getBy*` in the
 * second test of a file finds two of everything. */
afterEach(cleanup);

/* `ENC-542` and `docs/14 §7`: search excerpts are isolated at render.
 *
 * An excerpt is a 240-character window cut out of the middle of a document, so a
 * U+202E opened before the quoted passage and closed after it arrives **open**.
 * An unterminated override reverses everything that follows it — in a result
 * list that is the rest of the row and the rows beneath, which means the damage
 * appears in the surrounding interface and does not look like a bug in the
 * excerpt at all. The controls are deliberately not stripped at any layer,
 * because an excerpt is a verbatim quotation, so isolation at render is the
 * whole of the remedy.
 *
 * jsdom does no bidi layout, so these assert the mechanism rather than the
 * pixels: the character sits inside an element that isolates, and nothing else
 * in the row does. Swapping the `<bdi>` for a `<span>` fails them by name.
 */

/** U+202E RIGHT-TO-LEFT OVERRIDE, assembled rather than pasted. */
const RLO = String.fromCodePoint(0x202e);

function makeResult(excerpt: string | null): SearchResult {
  return SearchResult.parse({
    fileId: 'f1',
    versionId: 'v1',
    title: 'Vendor master agreement 2026',
    path: 'Contracts / 2026 / Helios Logistics',
    workspace: 'Legal',
    mimeType: 'application/pdf',
    classification: 'CONFIDENTIAL',
    score: 0.9,
    ownerName: 'Priya Nair',
    ownerInitials: 'PN',
    ownerTone: 'a',
    modifiedAt: Date.UTC(2026, 6, 1),
    excerpt,
    location: { page: 14, sectionPath: '18.2 Termination' },
    capabilities: { preview: true, download: false },
  });
}

function renderRows(excerpt: string | null) {
  return render(
    <I18nProvider>
      <div role="list">
        <ResultRow
          result={makeResult(excerpt)}
          position={1}
          setSize={2}
          index={0}
          active
          onActivate={() => undefined}
        />
        {/* The row beneath — the thing an unterminated override would reverse.
         * It is the positive control for the isolation assertion: the test
         * proves the control character is *not* an ancestor-sharing sibling of
         * this text without an isolating boundary between them. */}
        <ResultRow
          result={{ ...makeResult('a later passage'), fileId: 'f2', title: 'The row beneath' }}
          position={2}
          setSize={2}
          index={1}
          active={false}
          onActivate={() => undefined}
        />
      </div>
    </I18nProvider>,
  );
}

/** The text node holding `needle`, found by walking rather than by querying. */
function textNodeContaining(root: Node, needle: string): Text | null {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
    if ((node.textContent ?? '').includes(needle)) return node as Text;
  }
  return null;
}

/**
 * The nearest ancestor between `node` and `stopAt` that establishes a
 * bidirectional isolate — a `<bdi>`, or an element carrying
 * `unicode-bidi: isolate`. `null` means the character is free to reorder
 * everything up to `stopAt`.
 */
function isolatingAncestor(node: Node, stopAt: Element): HTMLElement | null {
  let current: Node | null = node.parentNode;
  while (current !== null && current !== stopAt) {
    if (current instanceof HTMLElement) {
      if (current.tagName === 'BDI') return current;
      if (current.style.unicodeBidi === 'isolate') return current;
    }
    current = current.parentNode;
  }
  return null;
}

describe('search excerpts are isolated', () => {
  it('wraps an excerpt carrying an unterminated U+202E in an isolate', () => {
    const { container } = renderRows(`…notice of termination ${RLO}and everything after it…`);
    const list = container.querySelector('[role="list"]')!;

    const node = textNodeContaining(list, RLO);
    expect(node, 'the override must survive to the DOM — it is never stripped').not.toBeNull();

    const isolate = isolatingAncestor(node!, list);
    expect(
      isolate,
      'an excerpt containing a bidi control must sit inside <bdi> or unicode-bidi: isolate',
    ).not.toBeNull();
    expect(isolate!.getAttribute('dir')).toBe('auto');
  });

  it('leaves the surrounding row and the row beneath outside that isolate', () => {
    const { container } = renderRows(`…notice ${RLO}reversed from here…`);
    const list = container.querySelector('[role="list"]')!;
    const isolate = isolatingAncestor(textNodeContaining(list, RLO)!, list)!;

    /* Positive control, so this is not an assertion about an absence: both of
     * these texts must actually be on screen. Only then does "and they are not
     * inside the isolate" mean anything. */
    const ownTitle = screen.getByText('Vendor master agreement 2026');
    const rowBeneath = screen.getByText('The row beneath');
    expect(ownTitle).toBeTruthy();
    expect(rowBeneath).toBeTruthy();

    expect(isolate.contains(ownTitle)).toBe(false);
    expect(isolate.contains(rowBeneath)).toBe(false);
    expect(isolate.textContent).toContain(RLO);
  });

  it('renders <em> as a mark element and never as markup', () => {
    const { container } = renderRows('…may <em>terminate</em> for convenience…');

    const mark = container.querySelector('mark');
    expect(mark, 'the API marks matched terms with <em>; the row renders a <mark>').not.toBeNull();
    expect(mark!.textContent).toBe('terminate');

    /* The excerpt string is document content with one known tag in it. It is
     * read, never injected — a document containing `<script>` must render as
     * the characters, so no textContent anywhere may hold a literal tag. */
    expect(container.textContent).not.toContain('<em>');
    expect(container.innerHTML).not.toContain('&lt;em&gt;');
  });

  it('says so plainly when there is no excerpt, rather than rendering an empty line', () => {
    // `docs/05 §11`: a metadata-only caller gets no excerpt and the lexical path
    // emits none when it cannot locate the matched term. Both are normal.
    const { container } = renderRows(null);
    expect(container.querySelector('.esr-no-excerpt')).not.toBeNull();
  });
});

describe('segmentExcerpt', () => {
  it('never strips a bidirectional control', () => {
    const segments = segmentExcerpt(`before ${RLO} after`);
    expect(segments.map((segment) => segment.text).join('')).toBe(`before ${RLO} after`);
  });

  it('splits on <em> and marks only what was inside it', () => {
    expect(segmentExcerpt('a <em>b</em> c')).toEqual([
      { text: 'a ', matched: false },
      { text: 'b', matched: true },
      { text: ' c', matched: false },
    ]);
  });

  it('treats an unmarked excerpt as one unmatched run', () => {
    // A dense hit arrives unmarked by design (`docs/07 §6.2.1`); a client must
    // not read the absence of <em> as a failure.
    expect(segmentExcerpt('nothing marked here')).toEqual([
      { text: 'nothing marked here', matched: false },
    ]);
  });
});
