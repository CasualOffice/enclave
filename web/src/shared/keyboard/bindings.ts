import type { MessageKey } from '../i18n/catalog.ts';

/* `docs/09 §6`'s keyboard map, as data.
 *
 * ## Why it is a table and not a `switch`
 *
 * There are two consumers — the handlers that run a binding, and the `?` sheet
 * that teaches it — and `docs/09 §5` requires the second to agree with the
 * first ("Every command in the palette shows its keyboard shortcut, which is
 * how users learn them"). Two hand-maintained lists is how a product ends up
 * advertising a shortcut it no longer has. This is the list; the handlers
 * dispatch on `BindingId` and the sheet renders the same array, so a binding
 * that is added, retired or deferred moves in one place.
 *
 * ## Why some of it is `later`
 *
 * `docs/09 §6` is a specification of the finished product, not of M5. Six of
 * its rows act on a file, and the API registers **no endpoint for any of
 * them** — there is no rename, no move, no copy, no trash and no
 * classification-label route in `crates/api/src/lib.rs`, and while
 * `POST /files/{id}/shares` does exist there is no share dialog to open. A
 * binding that fires and silently does nothing is worse than one that is
 * absent: the user cannot tell "you pressed the wrong key" from "the product
 * ignored you". So those rows carry `state: 'later'`, appear in the sheet under
 * the **unbuilt** treatment with the specific blocker named, and are not
 * dispatched. That is `plans/M5-MVP-GA.md` D33's rule applied to a keyboard
 * surface, and it is the same treatment the Filter and Display buttons already
 * carry two metres away in the view bar.
 *
 * They are deliberately *not* the denial treatment (`ENC-673`). Nothing has
 * been refused; the policy chain has not been consulted, because there is no
 * route to consult it about.
 *
 * ## Where this table and `docs/09 §6` disagree
 *
 * Nowhere — that is the point, and `ENC-676` settled that this table overrules
 * the design reference rather than the other way round. Where §6 is *silent* or
 * *contradicts itself*, the gap is recorded here at the binding and in
 * `ENC-896`/`ENC-897`, and no binding was invented to paper over it.
 */

export type BindingId =
  | 'palette'
  | 'focusSearch'
  | 'moveSelection'
  | 'expandCollapse'
  | 'openPeek'
  | 'walk'
  | 'selectAll'
  | 'fileActions'
  | 'label'
  | 'trash'
  | 'details'
  | 'ask'
  | 'help'
  | 'escape';

/**
 * Where a binding is listened for.
 *
 * `global` is the document — it works from anywhere that is not a text field.
 * `list` only fires while focus is inside the file grid, because `↑`/`↓` inside
 * a combo box or a tab strip belong to that control and stealing them is how a
 * global handler breaks every widget underneath it.
 */
export type BindingScope = 'global' | 'list';

export interface Binding {
  readonly id: BindingId;
  /** The key caps, as a catalog key: `⌘` is not `Ctrl` and neither is universal. */
  readonly keys: MessageKey;
  /** What it does, in the user's words. */
  readonly action: MessageKey;
  readonly scope: BindingScope;
  /**
   * `built` dispatches. `later` renders in the sheet and does nothing else.
   * There is no third value: a binding is never *denied*, because a keyboard
   * shortcut is not a permission (`ENC-673`).
   */
  readonly state: 'built' | 'later';
  /** For a `later` binding, the specific thing it is waiting on. */
  readonly note?: MessageKey;
}

/**
 * The map, in `docs/09 §6`'s own order.
 *
 * The order is load-bearing: the `?` sheet renders this array top to bottom, so
 * a reader comparing the sheet against the document reads the same sequence and
 * can see at a glance that nothing was dropped.
 */
export const BINDINGS: readonly Binding[] = [
  {
    id: 'palette',
    keys: 'key.commandK',
    action: 'kbd.action.palette',
    scope: 'global',
    state: 'built',
  },
  {
    id: 'focusSearch',
    keys: 'key.slash',
    action: 'kbd.action.focusSearch',
    scope: 'global',
    state: 'built',
  },
  {
    id: 'moveSelection',
    keys: 'key.upDown',
    action: 'kbd.action.moveSelection',
    scope: 'list',
    state: 'built',
  },
  {
    id: 'expandCollapse',
    keys: 'key.leftRight',
    action: 'kbd.action.expandCollapse',
    scope: 'list',
    state: 'built',
  },
  {
    id: 'openPeek',
    keys: 'key.enterSpace',
    action: 'kbd.action.openPeek',
    scope: 'list',
    state: 'built',
  },
  { id: 'walk', keys: 'key.jk', action: 'kbd.action.walk', scope: 'list', state: 'built' },
  {
    id: 'selectAll',
    keys: 'key.commandA',
    action: 'kbd.action.selectAll',
    scope: 'list',
    state: 'built',
  },
  /* `R` `M` `C` `S` — one row in `docs/09 §6`, one row here, because they share
   * a blocker and splitting them into four identical `Later` lines would say
   * four different things are missing. */
  {
    id: 'fileActions',
    keys: 'key.rmcs',
    action: 'kbd.action.fileActions',
    scope: 'list',
    state: 'later',
    note: 'kbd.note.fileActions',
  },
  /* `L R`. **`docs/09 §6` contradicts itself here** and the contradiction is
   * recorded rather than resolved: the row above binds `R` to Rename, and this
   * row binds `R` again as half of the label chord. One of the two cannot fire.
   * `ENC-896` carries it to whoever owns `docs/09`; nothing here guesses which
   * reading was meant, because guessing and shipping it *is* the thing that
   * makes a specification stop being one. It is `later` regardless — no route
   * applies a classification label — so the collision has no runtime effect
   * today, which is exactly why it would go unnoticed until it did. */
  {
    id: 'label',
    keys: 'key.lr',
    action: 'kbd.action.label',
    scope: 'list',
    state: 'later',
    note: 'kbd.note.label',
  },
  {
    id: 'trash',
    keys: 'key.delete',
    action: 'kbd.action.trash',
    scope: 'list',
    state: 'later',
    note: 'kbd.note.trash',
  },
  {
    id: 'details',
    keys: 'key.iPin',
    action: 'kbd.action.details',
    scope: 'global',
    state: 'built',
  },
  /* `⌘J` — **"registered and disabled until M7"**, in §6's own words, and this
   * is what registered-and-disabled looks like. It is in the sheet so a user
   * who reads the map sees that Ask has a shortcut; it does not dispatch, and
   * it does not `preventDefault`, because swallowing a key to do nothing takes
   * it away from the browser as well as from the product. */
  {
    id: 'ask',
    keys: 'key.commandJ',
    action: 'kbd.action.ask',
    scope: 'global',
    state: 'later',
    note: 'kbd.note.ask',
  },
  { id: 'help', keys: 'key.question', action: 'kbd.action.help', scope: 'global', state: 'built' },
  { id: 'escape', keys: 'key.escape', action: 'kbd.action.escape', scope: 'global', state: 'built' },
];

/** The subset that dispatches. The sheet renders all of them; the handlers see these. */
export const BUILT: ReadonlySet<BindingId> = new Set(
  BINDINGS.filter((binding) => binding.state === 'built').map((binding) => binding.id),
);
