import { memo } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { FileIcon } from '../../shared/ui/icons.tsx';
import { CLASSIFICATION_KEY } from '../../entities/classification/model.ts';
import { kindForMime, segmentExcerpt, type SearchResult } from './model.ts';

/* One result.
 *
 * `docs/09 §10` lists what a result shows and the list is not negotiable: title,
 * path, workspace, matched excerpt, file type, owner, modified date,
 * classification badge, and the page/sheet/section location. All nine are here,
 * in three lines of a fixed 80 px box — fixed because the list is virtualized
 * and a variable row height is a second, harder geometry problem for no gain
 * (`geometry.ts` is documented for the uniform case).
 *
 * The three lines are ordered by what a scanning eye needs first: what it is,
 * where it is, what it said.
 */

/* ------------------------------------------------------------------ excerpt */

/**
 * The excerpt, isolated.
 *
 * `docs/14 §7` and `ENC-542`, and this is the whole of the remedy. An excerpt is
 * a 240-character window cut out of the middle of a document, so a U+202E opened
 * before the quoted passage and closed after it arrives **open** — and an
 * unterminated override reverses everything that follows it, which in a result
 * list is the rest of this row and every row beneath. The failure appears in the
 * surrounding interface rather than in the snippet, so it does not read as a
 * rendering bug in the excerpt at all.
 *
 * The controls are deliberately **not stripped** at any layer: an excerpt is a
 * verbatim quotation, a caller shown one must be able to find it in the file,
 * and direction marks can be load-bearing in the source. `crates/search` has a
 * test that fails if a sanitizer is ever added there. So isolation at render is
 * the entire defence, and it is two attributes:
 *
 *   - `<bdi>`, which is `unicode-bidi: isolate` that cannot be removed by a
 *     stylesheet — the CSS below repeats it, but the element is the guarantee;
 *   - `dir="auto"`, so the fragment's own first strong character sets its base
 *     direction instead of inheriting the interface's.
 *
 * The `<em>` marking arrives inside the excerpt string (`docs/05 §11`, applied
 * at the API layer from retrieval's offsets). It is **read**, never injected:
 * `segmentExcerpt` returns text and React escapes it, so a document containing
 * `<script>` renders as the characters a document containing `<script>` should.
 * There is no `dangerouslySetInnerHTML` on this path and there must never be.
 */
function Excerpt({ excerpt }: { excerpt: string }) {
  return (
    <bdi className="esr-excerpt" dir="auto">
      {segmentExcerpt(excerpt).map((segment, index) =>
        segment.matched ? (
          <mark key={index} className="esr-match">
            {segment.text}
          </mark>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </bdi>
  );
}

/* --------------------------------------------------------------------- row */

export interface ResultRowProps {
  readonly result: SearchResult;
  /** 1-based position, for `aria-posinset` on a list most of which is not in the DOM. */
  readonly position: number;
  readonly setSize: number;
  readonly active: boolean;
  readonly index: number;
  readonly onActivate: (index: number) => void;
}

export const ResultRow = memo(function ResultRow({
  result,
  position,
  setSize,
  active,
  index,
  onActivate,
}: ResultRowProps) {
  const t = useT();
  const formatters = useFormatters();
  /* Absent for a real API result: `Hit` carries no modified date. Rendering
   * `new Date(undefined)` would print "Invalid Date" at the user. */
  const modified = result.modifiedAt === undefined ? null : new Date(result.modifiedAt);

  /* The page/sheet/section location `docs/09 §10` requires on every result, as
   * one short string. ICU does the joining, so a locale that abbreviates "page"
   * differently or orders the two the other way can; concatenating `'p.' + n`
   * here is the defect `docs/14 §6` names. A sheet name and a bare section path
   * are the document's own words and are rendered as they arrive. */
  const at = result.location;
  const location =
    at === undefined
      ? ''
      : at.page !== undefined
        ? at.sectionPath === undefined
          ? t('search.result.locationPage', { page: at.page })
          : t('search.result.locationPageSection', { page: at.page, section: at.sectionPath })
        : (at.sheet ?? at.sectionPath ?? '');

  return (
    <div
      className="esr-row"
      role="listitem"
      data-active={active || undefined}
      /* The list is virtualized, so thirty of two hundred rows are in the DOM
       * and the accessibility tree cannot count them. Position and size are
       * stated rather than inferred, the same way the file list states its row
       * count instead of letting a screen reader tally what it can see. */
      aria-posinset={position}
      aria-setsize={setSize}
    >
      {/* An anchor, because it goes somewhere: `docs/17 §5` addresses the peek
       * panel as a query parameter over the library route, so a result is a
       * link a user can middle-click, copy and share — not a div with a click
       * handler. The deep link into the preview *at the location* is the peek
       * panel's to honour; the URL is the documented contract either way. */}
      <a
        className="esr-hit"
        href={`/library?peek=${encodeURIComponent(result.fileId)}`}
        data-result-index={index}
        tabIndex={active ? 0 : -1}
        onFocus={() => onActivate(index)}
      >
        <span className="esr-line esr-line-title">
          <FileIcon className="esr-icon" kind={kindForMime(result.mimeType)} />
          {/* `dir="auto"` and isolation on the title too: a file name mixing
           * scripts must not rearrange the row around it (`docs/14 §7`). */}
          <bdi className="esr-title" dir="auto">
            {result.title}
          </bdi>
          {/* No badge when the server sent no classification. An invented
            * `Unclassified` on a document somebody labelled `RESTRICTED` in the
            * database is the disclosure this badge exists to prevent. */}
          {result.classification !== undefined && (
            <span className="esr-classification" data-level={result.classification}>
              {t(CLASSIFICATION_KEY[result.classification])}
            </span>
          )}
          {location.length > 0 && (
            <span className="esr-location">
              <bdi dir="auto">{location}</bdi>
            </span>
          )}
        </span>

        <span className="esr-line esr-line-meta">
          <bdi className="esr-workspace" dir="auto">
            {result.workspace}
          </bdi>
          <span className="esr-sep" aria-hidden="true" />
          <bdi className="esr-path" dir="auto">
            {result.path}
          </bdi>
          {/* The owner is not on the wire either. The separator goes with it:
            * a dangling ' · ' reads as a value that failed to load. */}
          {result.ownerName !== undefined && (
            <>
              <span className="esr-sep" aria-hidden="true" />
              <span className="esr-owner" data-tone={result.ownerTone} aria-hidden="true">
                {result.ownerInitials}
              </span>
              <bdi className="esr-ownername" dir="auto">
                {result.ownerName}
              </bdi>
            </>
          )}
          {modified !== null && <span className="esr-sep" aria-hidden="true" />}
          {/* `Intl.RelativeTimeFormat` with the absolute value in the `title`.
           * The prototype hand-builds "2 h ago"; `docs/17 §8` records that as a
           * defect in the reference rather than a pattern to copy. */}
          {modified !== null && (
            <time
              className="esr-when"
              dateTime={modified.toISOString()}
              title={formatters.dateTime(modified)}
            >
              {formatters.relative(modified)}
            </time>
          )}
        </span>

        {result.excerpt === null ? (
          /* No excerpt is a normal result, not a broken one: `docs/05 §11` says
           * a metadata-only caller gets none, and the lexical path emits none
           * when it cannot locate the matched term. Saying so is better than an
           * empty line, which reads as a rendering failure. */
          <span className="esr-line esr-line-excerpt esr-no-excerpt">
            {t('search.result.noExcerpt')}
          </span>
        ) : (
          <span className="esr-line esr-line-excerpt">
            <Excerpt excerpt={result.excerpt} />
          </span>
        )}
      </a>
    </div>
  );
});
