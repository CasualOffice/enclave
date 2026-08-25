import { useT } from '../../shared/i18n/index.tsx';
import { Button, Pill } from '../../shared/ui/primitives.tsx';

/* The composer: drawn in full, wired to nothing, and honest about which.
 *
 * The prototype's composer is a text field, two scope chips, a hint and a send
 * button. All four are here, because removing them would answer a different
 * question — *"is there an Ask composer?"* — than the one the screen is
 * answering, which is *"what will asking look like, and when?"*.
 *
 * Every control in it is `unbuilt`, and `unbuilt` has a precise meaning
 * (`docs/17 §6`, `plans/M5-MVP-GA.md` D33):
 *
 *   - **Not focusable.** `tabIndex={-1}` on the field and, via `ControlState`,
 *     on the send button. A keyboard user tabbing through this screen finds
 *     nothing, which is correct: there is nothing to find out and nothing to
 *     do. This is the single sharpest difference from a denial, which stays
 *     focusable precisely so a keyboard user can reach it and hear *why*.
 *   - **No remedy.** No *Request access*, no *Contact an admin*, no retry. A
 *     remedy implies an action that would obtain the thing, and none exists.
 *   - **Neutral.** Never `--danger`, never the denial's inset ring. The send
 *     button is the default variant rather than the accent one, because a
 *     dimmed primary button reads as a broken primary button.
 *
 * The field is `readOnly` rather than `disabled`. `disabled` removes it from
 * the accessibility tree's reach in ways that also drop its description, and
 * the description is the entire message: *"Arrives in a later release."*
 */

/* The id `<Button>` gives the note it renders for an `unbuilt` control:
 * `${label}-note` (`shared/ui/primitives.tsx`). Pointing the text field at the
 * same note keeps one sentence for the whole composer instead of repeating it
 * per control — repetition is how a marker becomes wallpaper.
 *
 * This is a coupling to a shared component's internals, so `ask-composer` in
 * `tests/unit` asserts the id is really in the DOM. If the primitive changes
 * its scheme, that test fails rather than the description silently pointing at
 * nothing. */
const SEND_NOTE_ID = 'ask.composer.send-note';

export function AskComposer() {
  const t = useT();

  return (
    <div className="ask-composer" data-state="unbuilt">
      <input
        className="ask-composer-input"
        type="text"
        readOnly
        tabIndex={-1}
        aria-disabled="true"
        aria-label={t('ask.composer.label')}
        placeholder={t('ask.composer.placeholder')}
        aria-describedby={SEND_NOTE_ID}
      />
      <div className="ask-composer-foot">
        {/* The scope chips describe the *default* breadth of an ask — every
         * library the user can open, any date — rather than naming a library
         * the way the prototype does. There is no scope picker yet, and a chip
         * reading "Contracts" would be asserting a filter that is not applied
         * to a query that is not made. */}
        <Pill label="ask.composer.scope.libraries" icon="folder" tone="outline" />
        <Pill label="ask.composer.scope.anyDate" tone="outline" />
        <span className="ask-composer-spacer" />
        {/* The prototype's hint here reads "Hybrid retrieval · sources always
         * shown". Both halves are wrong for this build: retrieval is lexical in
         * M5 (`plans/M5-MVP-GA.md` D37) and no retrieval happens at all on this
         * surface. The slot carries the release note instead, which is the true
         * thing there is to say about the send button beside it. */}
        {/* `<Button>` renders its release note as a sibling *after* itself.
         * `row-reverse` puts the note ahead of the control visually without
         * reordering the DOM, and it is a logical direction — it follows the
         * inline axis, so it mirrors in RTL rather than fighting it. Neither
         * element is focusable, so visual order and focus order cannot
         * disagree here (`docs/09 §6`). */}
        <span className="ask-send-slot">
          <Button
            label="ask.composer.send"
            icon="move"
            iconOnly
            size="sm"
            state={{ kind: 'unbuilt', note: 'ask.arrivesInM7' }}
          />
        </span>
      </div>
    </div>
  );
}
