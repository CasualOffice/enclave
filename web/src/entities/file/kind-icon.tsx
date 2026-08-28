import { FileIcon } from '../../shared/ui/icons.tsx';
import type { FileKind } from './model.ts';
import './kind-icon.css';

/* The file-type glyph, tinted by MIME family. **One implementation.**
 *
 * There were three, byte-identical: `.egl-name-icon` in
 * `features/libraries/list/grouped-list.css`, and the same eleven lines again in
 * `features/home/home.css` and `features/search/search.css` — each hard-coding
 * the four hexes `#D0453A / #3B6FD4 / #2E8B57 / #D2591C`. A colour written out
 * three times is a colour that gets corrected twice.
 *
 * ## Why `entities/` and not `shared/ui/`
 *
 * `docs/17 §11`: `shared/ui` holds primitives, which are the things with **no**
 * domain knowledge. This component knows what a MIME family is — that a
 * presentation and a spreadsheet are different kinds of thing and are drawn
 * differently — so it belongs beside the model that defines `FileKind`.
 * `shared/ui/icons.tsx` still owns the *shape*; this owns the *reading*.
 *
 * ## Colour is reinforcement, never the carrier
 *
 * `docs/09 §15`. The row already states the file type twice in text — in the
 * dimmed extension after the name, and in the `Type` fact in the peek panel — so
 * a user who cannot separate the four tints loses nothing. That is also why the
 * glyph is `aria-hidden` (it is, in `shared/ui/icons.tsx`) rather than carrying
 * a label a screen reader would read out on every one of 100 000 rows.
 */
export function FileKindIcon({ kind }: { readonly kind: FileKind }) {
  /* `FileIcon` rather than the sprite's `#i-file`.
   *
   * `<Icon>` takes no `data-*`, so driving the tint from the sprite would need a
   * wrapper element — one extra node on every row of a list that is budgeted for
   * 100 000 of them (`docs/09 §2`). `FileIcon` already carries `data-kind`, so
   * the tint is an attribute on the glyph itself and the row stays one node
   * lighter. */
  return <FileIcon className="enc-kind-icon" kind={kind} />;
}
