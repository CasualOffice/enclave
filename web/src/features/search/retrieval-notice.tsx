import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Card } from '../../shared/ui/layout.tsx';
import { LaterChip } from '../../shared/ui/primitives.tsx';
import type { SearchDiagnostics } from './model.ts';

/* The degraded-search header.
 *
 * `docs/09 §10`: *"A degraded search (vector store unavailable) says so in the
 * results header rather than quietly returning less."* `plans/M5-MVP-GA.md` D37
 * records that it has never been designed, because until M5 it was never
 * reachable — `ENC-661`, no `EmbeddingProvider` is deployed, so dense retrieval
 * returns nothing and every search this milestone ships is lexical.
 *
 * ── What it has to be ────────────────────────────────────────────────────────
 *
 * **Honest.** A search box that silently returns fewer results than the product
 * promises is the "reads as working" failure the whole milestone exists to
 * prevent. The user must be able to see, without asking, that the thing they
 * were sold — find the document by what it means — is not what just happened.
 *
 * **Not an error.** `docs/09 §11` and `docs/17 §7` keep failures and
 * non-failures apart, and this is neither a failure nor a denial: the query
 * succeeded, the results are real, and they are correctly access-filtered. So
 * none of the error vocabulary is available to it — no `role="alert"`, no
 * `--danger`, no retry, no request ID, no warning triangle. `--warn` is out too,
 * because in this product amber is the DLP and restriction language ("No
 * download", "Preview only", "Watermarked") and borrowing it here would say
 * *something about your access is wrong*, which is a different and false story.
 *
 * ── How it reads as degraded rather than broken ──────────────────────────────
 *
 * Four decisions, in the order they matter:
 *
 * 1. **It says what still works before it says what does not.** "Every file you
 *    can open is still being searched" is the first sentence, and it is the true
 *    one: coverage is unchanged, only the *matching* is narrower. A notice that
 *    leads with the loss reads as an outage.
 * 2. **It names the consequence in the user's own terms, not the system's.**
 *    "A document that says *terminate for convenience* will not be found by
 *    searching *cancel the contract*." Nobody outside this repository knows what
 *    a vector store is; everybody knows what it means to have typed the wrong
 *    word. That sentence is also the only useful remedy available — *try the
 *    words the document would use* — and it is a remedy the user can act on,
 *    which a retry button is not.
 * 3. **Two variants, because there are two facts.** `diagnostics` carries `mode`
 *    and `degraded` separately and they are not the same situation:
 *
 *      · `lexical`, not degraded — this deployment has no dense retrieval. A
 *        product state. Future tense, about the product, and it carries the D33
 *        `Later` chip, which is the marker this codebase already uses for
 *        "not written yet". Nothing is wrong and nothing will change today.
 *      · `degraded` — the vector store is unreachable and the query fell back.
 *        Present tense, about the system, no `Later` chip, and it says the
 *        recovery is automatic. It must not carry `Later`: a transient incident
 *        marked as a roadmap item is a lie in the other direction.
 *
 *    Collapsing them into one line would tell half the users the wrong tense.
 * 4. **It sits with the results, not over them.** It is a caption on the result
 *    list, in the flow, immediately above row one — not a banner across the top
 *    of the screen and not a toast. A banner is chrome a user learns to skip; a
 *    toast is gone before the results are read. `role="status"` announces it
 *    politely once, which is what a screen-reader user needs for the same reason
 *    a sighted one needs it in the header.
 *
 * The surface itself is `--sunken` on a hairline, `--fg2` text, a 12 px neutral
 * icon: the same weight as a keyboard hint. Calm is not decoration here — it is
 * the difference between a user who adjusts their query and a user who files a
 * ticket.
 */

/** Which notice a diagnostics block calls for, or `null` for a healthy hybrid search. */
export type NoticeVariant = 'lexical' | 'degraded';

/**
 * Pure, and separate from the component, because two callers need the answer:
 * the notice renders it and the results header counts on it being absent for a
 * healthy search. `degraded` wins over `mode` — a fallback that landed on
 * lexical is an incident first and a mode second.
 */
export function noticeFor(diagnostics: SearchDiagnostics): NoticeVariant | null {
  if (diagnostics.degraded) return 'degraded';
  if (diagnostics.mode !== 'hybrid') return 'lexical';
  return null;
}

export function RetrievalNotice({ diagnostics }: { diagnostics: SearchDiagnostics }) {
  const t = useT();
  const variant = noticeFor(diagnostics);

  if (variant === null) return null;

  return (
    /* `Card` with the `sunken` tone, which is the recipe this file used to write
     * out by hand — a well the eye reads as behind the page, no semantic colour,
     * no border. The tone is the *only* thing it borrows: a sunken card is not a
     * warning, and nothing in the shared component paints one. */
    <Card tone="sunken" padded={false} className="esr-notice">
      <span className="esr-notice-icon">
        {/* `info` and `clock`, never `warn`. A triangle is the shape of an
         * alarm, and this is not one. `clock` on the degraded variant carries
         * the one fact that distinguishes it: this passes. */}
        <Icon name={variant === 'degraded' ? 'clock' : 'info'} size={12} />
      </span>
      {/* The live region is the copy, not the card, because `Card` renders no
       * attributes of its own — and the copy is all of the text anyway, so a
       * screen reader is announced the same sentences in the same order. */}
      <div className="esr-notice-copy" data-notice={variant} role="status">
        <p className="esr-notice-head">
          {t('search.retrieval.head')}
          {/* Only on the product-state variant. `docs/17 §6`: the `Later` chip is
           * future tense about the product, and an incident is neither. */}
          {variant === 'lexical' && <LaterChip note="later.chip" />}
        </p>
        <p className="esr-notice-body">{t('search.retrieval.stillSearched')}</p>
        <p className="esr-notice-body">
          {t(variant === 'degraded' ? 'search.retrieval.degraded' : 'search.retrieval.lexical')}
        </p>
      </div>
    </Card>
  );
}
