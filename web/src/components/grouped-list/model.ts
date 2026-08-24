import type { MessageKey } from '../../i18n/catalog.ts';

/** The five levels plus the absence of one. `unclassified` is not a sixth level. */
export type ClassificationLevel =
  | 'public'
  | 'internal'
  | 'confidential'
  | 'highlyConfidential'
  | 'restricted'
  | 'unclassified';

/** Every level's catalog key, so no component ever maps a level to a literal. */
export const CLASSIFICATION_KEY: Record<ClassificationLevel, MessageKey> = {
  public: 'classification.public',
  internal: 'classification.internal',
  confidential: 'classification.confidential',
  highlyConfidential: 'classification.highlyConfidential',
  restricted: 'classification.restricted',
  unclassified: 'classification.unclassified',
};

/** Icon tint buckets from the design reference (`.name .fi.pdf` and friends). */
export type FileKind = 'pdf' | 'doc' | 'xls' | 'ppt' | 'other';

/**
 * One row, as the client holds it.
 *
 * This is a view model, not the API shape: `docs/05-API.md` owns that, and Zod
 * parsing at the boundary lands with the first real fetch. Deliberately flat and
 * primitive-valued, because 100 000 of these exist at once and every nested
 * object is 100 000 allocations.
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
