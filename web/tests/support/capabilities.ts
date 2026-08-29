import type { FileCapabilities } from '../../src/entities/file/api-model.ts';

/**
 * A file's capabilities, as a fixture, typed by the schema they stand in for.
 *
 * There were three hand-written copies of this object — `tests/a11y/api-stub.ts`,
 * `tests/unit/capability-reasons.test.tsx` and
 * `tests/unit/library-capabilities.test.tsx` — and they all agreed with each
 * other and none of them agreed with the server. `ENC-807` added `move` and
 * `restore` to `crates/api/src/content.rs` and to nothing here, and 111
 * accessibility tests and 327 unit tests stayed green while the real listing
 * drew its failure state, because every one of them was checked against a copy
 * of the client's own belief (`ENC-929`).
 *
 * The return type is the annotation that matters. `FileCapabilities` is derived
 * from the Zod schema, so a field added there and not here is a **compile
 * error** in one file rather than a parse failure in production — which is the
 * only version of this that a person cannot forget. An inline object literal
 * inside a larger fixture gets no such check, which is exactly how three copies
 * drifted in silence.
 *
 * Defaults are deliberately not all `true`: markup that ignores `capabilities`
 * entirely would pass every assertion made against an all-permitted row, and
 * the refused treatment would never render for axe to measure.
 */
export function capabilitiesFixture(
  overrides: Partial<FileCapabilities> = {},
): FileCapabilities {
  return {
    metadataRead: true,
    preview: true,
    download: false,
    print: false,
    export: false,
    edit: true,
    share: true,
    shareExternal: false,
    delete: true,
    move: true,
    restore: false,
    sync: false,
    ...overrides,
  };
}
