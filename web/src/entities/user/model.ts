import { z } from 'zod';

/* The signed-in person, as `GET /api/v1/me` states them.
 *
 * `crates/api/src/me.rs` is the authority for this shape and it is smaller than
 * the shell would like: there is no `locale`, no `timeZone`, no workspace id
 * and no workspace name on the wire today. The specs in
 * `web/design-system/specs/` assume all four — the greeting bucket is supposed
 * to come from `me.timeZone`, and the subtitle names the workspace — so those
 * are recorded as gaps rather than invented here. A client that guesses a time
 * zone greets a travelling user with "Good evening" at breakfast and does it
 * confidently.
 *
 * `capabilities` carries exactly one field, `readSelf`. That is not a
 * placeholder to be widened client-side: it is the whole capability set this
 * endpoint decides, and the shell renders from it rather than from `isAdmin`
 * wherever the two could disagree.
 */

/**
 * `/me`'s capability object.
 *
 * Strict, so a field the server stops sending is a parse failure and therefore
 * an error state, rather than an `undefined` that reads as `false` and silently
 * hides a control the user is in fact allowed to use.
 */
export const ViewerCapabilities = z.object({
  readSelf: z.boolean(),
});

export const Viewer = z.object({
  id: z.string(),
  tenantId: z.string(),
  email: z.string(),
  displayName: z.string(),
  /**
   * Whether the account is an administrator.
   *
   * Used for **navigation only** — whether the Admin entry is worth showing.
   * It is never used to decide whether an administrative *action* is allowed:
   * every admin route runs the policy chain and answers `403` or
   * `STEP_UP_REQUIRED` on its own authority, and a client that pre-empted that
   * decision would be the second authority `docs/17 §1` exists to forbid.
   * Hiding the entry from a non-admin is a courtesy; showing it to one is not a
   * vulnerability, because the server still refuses.
   */
  isAdmin: z.boolean(),
  capabilities: ViewerCapabilities,
});

export type Viewer = z.infer<typeof Viewer>;

/**
 * The two graphemes shown in an avatar.
 *
 * `Intl.Segmenter` rather than `name.split(' ')`, because name order is not
 * universal (`docs/14 §6`): splitting on whitespace yields "NP" for one culture
 * and "PN" for another for the same person, and it produces nonsense for
 * scripts that do not use spaces at all. Segmenting by grapheme also keeps
 * combining marks and emoji intact, which slicing by code unit does not.
 *
 * Falls back to the first two code points where `Intl.Segmenter` is missing.
 */
export function initialsOf(displayName: string, locale: string): string {
  const trimmed = displayName.trim();
  if (trimmed.length === 0) return '';

  const words = trimmed.split(/\s+/u).filter((word) => word.length > 0);
  const sources = words.length > 1 ? [words[0], words[words.length - 1]] : [trimmed];

  const firstGrapheme = (input: string): string => {
    if (typeof Intl.Segmenter === 'function') {
      const segmenter = new Intl.Segmenter(locale, { granularity: 'grapheme' });
      for (const segment of segmenter.segment(input)) return segment.segment;
      return '';
    }
    return [...input][0] ?? '';
  };

  const initials =
    sources.length > 1
      ? `${firstGrapheme(sources[0] ?? '')}${firstGrapheme(sources[1] ?? '')}`
      : firstGrapheme(sources[0] ?? '');

  return initials.toLocaleUpperCase(locale);
}

/** The avatar quartet. Four tokens, chosen by a stable hash so a person keeps one colour. */
export type AvatarTone = 'a' | 'b' | 'c' | 'd';

const TONES: readonly AvatarTone[] = ['a', 'b', 'c', 'd'];

/**
 * Pick a tone from an identifier.
 *
 * Keyed on the id rather than the display name so a rename does not recolour
 * the person. The server never sends a colour: a colour in the payload is a
 * token the tenant cannot theme and nobody can test (`specs/home.md`).
 */
export function toneOf(id: string): AvatarTone {
  let hash = 0;
  for (let index = 0; index < id.length; index += 1) {
    hash = (hash * 31 + id.charCodeAt(index)) | 0;
  }
  return TONES[Math.abs(hash) % TONES.length] ?? 'a';
}
