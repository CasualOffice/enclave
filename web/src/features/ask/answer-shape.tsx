import { useT } from '../../shared/i18n/index.tsx';
import { useFormatters } from '../../shared/i18n/format.ts';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Push } from '../../shared/ui/layout.tsx';

/* The shape of an answer, with none of its content.
 *
 * This is the design problem of the whole screen. `docs/09 §10` is binding even
 * while Ask is unbuilt — *"AI answers always expose their source documents and
 * chunks, with the same deep links"* — and a future session fills this in, so
 * the shape is the promise. But `plans/M5-MVP-GA.md` D33 is equally binding the
 * other way: there is no AI backend, and rendering a fluent paragraph with a
 * footnote pointing at "Vendor master agreement — Helios Logistics.pdf, p.14
 * §18.2" would be a fabricated answer with a fabricated citation. It would also
 * be indistinguishable from a real one in a screenshot, which is how a mock-up
 * becomes a claim.
 *
 * So: the layout, drawn; the words, absent. A question turn, an answer turn
 * with two citation markers in it, and the source list underneath with its
 * deep-link affordance. Anyone can see what an answer will be. Nobody can
 * mistake this for one.
 *
 * Three details carry that:
 *
 *   1. **Dashed, not solid.** A dashed frame is the universal mark of a sketch.
 *   2. **Flat, not shimmering.** Deliberately not `.ui-skeleton`: a shimmer says
 *      *in flight* (`docs/17 §6`'s busy state) and would promise an answer is
 *      seconds away. The loading state uses the shimmer; this must not.
 *   3. **`aria-hidden`, with the promise in prose beside it.** A wireframe read
 *      aloud is noise. The caption and body say what the picture says, so a
 *      screen-reader user gets the commitment rather than a list of blanks.
 */

/** Bar widths, as percentages. Fixed, because a wireframe that reshuffles on
 *  re-render reads as content arriving and leaving again. */
const ANSWER_LINES: readonly (readonly number[])[] = [[62, 24], [88], [46, 30]];

const SOURCE_WIDTHS = [58, 41] as const;

export function AnswerShape() {
  const t = useT();
  const format = useFormatters();

  /* Even a decorative ordinal goes through `Intl` — locales with their own
   * digits render "١" rather than "1", and a hand-written numeral in a
   * component is the habit `docs/14 §6` exists to prevent forming. */
  const ordinals = SOURCE_WIDTHS.map((_, index) => format.count(index + 1));

  return (
    <section
      className="ask-panel ask-shape enc-enter-panel"
      aria-labelledby="ask-shape-caption"
    >
      <div className="ask-panel-inner">
        <b className="ask-shape-caption" id="ask-shape-caption">
          {t('ask.shape.caption')}
        </b>

        <div aria-hidden="true" className="ask-turns">
          <div className="ask-wire-turn">
            <span className="ask-wire-badge">
              <Icon name="user" size={11} />
            </span>
            <div className="ask-wire-lines">
              <span className="ask-wire-line">
                <span className="ask-wire-bar" style={{ inlineSize: '54%' }} />
              </span>
            </div>
          </div>

          <div className="ask-wire-turn">
            <span className="ask-wire-badge" data-tone="accent">
              <Icon name="spark" size={11} />
            </span>
            <div className="ask-wire-lines">
              {ANSWER_LINES.map((line, lineIndex) => (
                <span className="ask-wire-line" key={lineIndex}>
                  {line.map((width, barIndex) => (
                    <span
                      className="ask-wire-bar"
                      key={barIndex}
                      style={{ inlineSize: `${width}%` }}
                    />
                  ))}
                  {/* A citation marker closes the first and last line, which is
                   * where they land in a real answer: one per claim. */}
                  {lineIndex !== 1 && (
                    <span className="ask-wire-cite">{ordinals[lineIndex === 0 ? 0 : 1]}</span>
                  )}
                </span>
              ))}

              {/* The source list: ordinal, document, and the deep-link glyph
               * that opens it at the passage. `docs/09 §10`, drawn. */}
              <ol className="ask-wire-sources">
                {SOURCE_WIDTHS.map((width, index) => (
                  <li className="ask-wire-source" key={index}>
                    <span className="ask-wire-cite">{ordinals[index]}</span>
                    <Icon name="file" size={12} />
                    <span className="ask-wire-bar" style={{ inlineSize: `${width}%` }} />
                    {/* The trailing spacer, as the shared element rather than a
                     * fifth hand-written `margin-inline-start: auto`. */}
                    <Push />
                    <Icon name="ext" size={11} />
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>

        <p className="ask-panel-body">{t('ask.shape.body')}</p>
      </div>
    </section>
  );
}
