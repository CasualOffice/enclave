import type { MessageKey } from '../../shared/i18n/catalog.ts';

/* The sensitivity scale, and its one hard rule.
 *
 * The five colours are locked (`docs/09 §16a`) and colour is never the only
 * carrier — the badge carries its text as well (`docs/09 §15`) — which is why a
 * level maps to a catalog key here rather than to a string anywhere else. A
 * component that wants to name a level asks this map, and there is no other way
 * to get the word.
 *
 * It lives in `entities/` rather than in `shared/ui` because it knows what a
 * classification is (`docs/17 §11`).
 */

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
