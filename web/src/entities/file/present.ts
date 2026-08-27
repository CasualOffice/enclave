import type { FileRow, FileKind } from './model.ts';
import type { Item } from './api-model.ts';

/* Turning what the server said into what the list draws.
 *
 * Kept apart from both the Zod schema and the component: the schema states the
 * contract, the component states the geometry, and this states the reading. A
 * mapper inside the component would make the reading untestable without a DOM,
 * and a mapper inside the schema would make the contract depend on how one
 * screen happens to draw.
 *
 * **Nothing here invents a fact.** Where the API does not send something the
 * prototype draws — a classification, a modifier's name — the value is the
 * honest absence and the gap is recorded, not filled. `docs/17 §1`: the server
 * decides, the client renders the decision, and that applies to metadata as
 * much as to permissions.
 */

/**
 * Icon tint bucket, from the MIME type the server sent.
 *
 * Derived from `mimeType` rather than from the filename extension, because the
 * extension is user-supplied text and the MIME type is the server's own reading
 * of the bytes. A file called `invoice.pdf` that is really a spreadsheet gets
 * the spreadsheet's icon, which is the truthful one.
 */
export function kindOf(mimeType: string): FileKind {
  if (mimeType === 'application/pdf') return 'pdf';
  if (mimeType.includes('wordprocessingml') || mimeType === 'application/msword') return 'doc';
  if (mimeType.includes('spreadsheetml') || mimeType === 'application/vnd.ms-excel') return 'xls';
  if (mimeType.includes('presentationml') || mimeType === 'application/vnd.ms-powerpoint') {
    return 'ppt';
  }
  return 'other';
}

/**
 * Split a filename into stem and extension.
 *
 * The list renders the extension in a dimmer colour, which needs the two apart.
 * A leading dot is not an extension — `.gitignore` is a name — and a name with
 * no dot has an empty extension rather than a missing one.
 */
export function splitName(name: string): { readonly stem: string; readonly extension: string } {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { stem: name, extension: '' };
  return { stem: name.slice(0, dot), extension: name.slice(dot) };
}

/**
 * One listing row, as the list wants it.
 *
 * Two fields are deliberately empty, and both are gaps in the API rather than
 * omissions here:
 *
 * - **`classification`** is `unclassified`. `content.rs`'s `Item` carries no
 *   classification at all — `files.classification_id` exists in the schema and
 *   is not serialized. Guessing a level would be the worst possible guess to
 *   make in this product: the badge is how a user knows whether a document may
 *   leave the building, and a confident "Internal" on a document nobody
 *   labelled is a disclosure waiting to happen. `unclassified` is a real value
 *   in `entities/classification`, not a placeholder, and it says exactly what
 *   is true — nobody has labelled this.
 * - **`modifiedByInitials`** is empty. The listing sends `modifiedAt` but not
 *   `modified_by`'s display name, and an id is not initials. The row renders no
 *   avatar rather than two letters of a UUID.
 */
export function rowFromItem(item: Item): FileRow {
  const { stem, extension } = splitName(item.name);
  return {
    id: item.id,
    name: stem,
    extension,
    kind: item.type === 'FOLDER' ? 'other' : kindOf(item.mimeType),
    classification: 'unclassified',
    modifiedAt: Date.parse(item.modifiedAt),
    modifiedByInitials: '',
    modifiedByTone: 'a',
    sizeBytes: item.sizeBytes,
  };
}
