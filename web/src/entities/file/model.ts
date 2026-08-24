import type { ClassificationLevel } from '../classification/model.ts';

/** Icon tint buckets from the design reference (`.name .fi.pdf` and friends). */
export type FileKind = 'pdf' | 'doc' | 'xls' | 'ppt' | 'other';

/**
 * One row, as the client holds it.
 *
 * This is a view model, not the API shape: `docs/05-API.md` owns that, and the
 * Zod schema it is parsed from lands with the first real fetch (`docs/17 §3`),
 * at which point this type is inferred rather than declared.
 *
 * Deliberately flat and primitive-valued, because 100 000 of these exist at once
 * and every nested object is 100 000 allocations.
 */
export interface FileRow {
  readonly id: string;
  readonly name: string;
  /** Including the leading dot, or empty for an extensionless file. */
  readonly extension: string;
  readonly kind: FileKind;
  readonly classification: ClassificationLevel;
  /** Epoch milliseconds. Formatted through `Intl` at render, never stored formatted. */
  readonly modifiedAt: number;
  /** Initials only. The full name is not in the list payload. */
  readonly modifiedByInitials: string;
  readonly modifiedByTone: 'a' | 'b' | 'c' | 'd';
  readonly sizeBytes: number;
}
