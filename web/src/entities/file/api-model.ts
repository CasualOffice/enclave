import { z } from 'zod';
import { CapabilityReasons } from '../capability/denial.ts';

/* The wire shapes of `GET /libraries/{id}/items` and `GET /files/{id}`.
 *
 * `crates/api/src/content.rs` is the authority; `docs/05-API.md` is the contract
 * it implements. Types are **inferred** from these schemas and never declared
 * beside them (`docs/17 §3`) — two declarations of one shape drift, `z.infer`
 * cannot.
 *
 * Everything here is strict about `capabilities` and lenient about nothing.
 * `.optional()` appears only where the server genuinely omits a field
 * (`skip_serializing_if`), never as a way to make a parse failure go away.
 */

/**
 * The ten capability booleans, and why this object is `strictObject`.
 *
 * `CLAUDE.md` rule 6: preview, download, print, export and sync are five
 * different permissions that look like one, and `docs/17` exists because a
 * client that computes any of them has created a second authority. So the
 * client's only job is to read this object faithfully — which means a field the
 * server stopped sending must be a **parse failure**, not an `undefined`.
 *
 * The failure mode a loose schema produces is specific and bad: `undefined` is
 * falsy, so a dropped `download` renders as *download refused*. That is a
 * denial the policy chain never issued, shown with the same confidence as a
 * real one. The opposite default is worse still. Refusing to parse is the only
 * honest third option, and `docs/17 §3` says so.
 */
export const FileCapabilities = z.strictObject({
  metadataRead: z.boolean(),
  preview: z.boolean(),
  download: z.boolean(),
  print: z.boolean(),
  export: z.boolean(),
  edit: z.boolean(),
  share: z.boolean(),
  shareExternal: z.boolean(),
  delete: z.boolean(),
  sync: z.boolean(),
});

export type FileCapabilities = z.infer<typeof FileCapabilities>;

/** The capability names an obligation can name, so the two cannot drift apart. */
export type CapabilityName = keyof FileCapabilities;

/**
 * What must happen *as well as* the action being allowed.
 *
 * `CLAUDE.md` rule 8: obligations must be satisfied, not dropped. A watermark
 * that is required and not applied, or a justification that is required and not
 * collected, is a policy decision the client quietly discarded — which is why
 * these arrive alongside `capabilities` rather than being inferred from it.
 */
export const Obligations = z.object({
  watermark: z.boolean(),
  justificationRequired: z.array(z.string()),
  approvalRequired: z.array(z.string()),
});

export type Obligations = z.infer<typeof Obligations>;

/** `AVAILABLE | PROCESSING | QUARANTINED | FAILED`, verbatim from `files.status`. */
export const ItemStatus = z.enum(['AVAILABLE', 'PROCESSING', 'QUARANTINED', 'FAILED']);
export type ItemStatus = z.infer<typeof ItemStatus>;

export const NodeType = z.enum(['FILE', 'FOLDER']);
export type NodeType = z.infer<typeof NodeType>;

/** One row of a library or folder listing. */
export const Item = z.object({
  id: z.string(),
  type: NodeType,
  name: z.string(),
  mimeType: z.string(),
  sizeBytes: z.number(),
  /** Omitted at a library root, where there is no parent. */
  parentId: z.string().optional(),
  libraryId: z.string(),
  status: ItemStatus,
  revision: z.number(),
  capabilities: FileCapabilities,
  /**
   * Why each `false` above is `false` (`ENC-674`, `docs/05 §7`).
   *
   * Optional here and required on the server, and the asymmetry is deliberate.
   * The server always sends the object, so its absence means an older build —
   * and the honest rendering of that is the generic sentence, not a parse
   * failure that blanks the listing. `entities/capability/denial.ts` sets out
   * why this field takes the opposite answer from the booleans beside it.
   */
  capabilityReasons: CapabilityReasons.optional(),
  obligations: Obligations,
  createdAt: z.string(),
  modifiedAt: z.string(),
});

export type Item = z.infer<typeof Item>;

/**
 * The page envelope.
 *
 * `nextCursor` is omitted rather than nulled by `content.rs`, so both spellings
 * are accepted: a client that checked for the field's presence and one that
 * checked for a value must reach the same conclusion, and the server's two
 * modules do not agree on which they emit.
 */
export const PageInfo = z.object({
  nextCursor: z.string().nullish(),
  hasMore: z.boolean(),
  limit: z.number().optional(),
});

export const ItemPage = z.object({
  items: z.array(Item),
  page: PageInfo,
});

export type ItemPage = z.infer<typeof ItemPage>;

/** The version a read path would serve. */
/**
 * The version `GET /files/{id}` currently points at.
 *
 * `avStatus` and `isReadable` were added by `ENC-825` and are named here now
 * (`ENC-848`). Before them `status: "AVAILABLE"` was byte-identical for a file
 * that previews and one every delivery route answers `404` for, and the only
 * way to tell those apart was to press the button — so the peek panel had to
 * fetch `GET /files/{id}/versions` on every peek purely to reach `isReadable`.
 *
 * `docs/05 §7`: **`isReadable` is the field to branch on.** It is the server's
 * own readable predicate — the same one the delivery routes filter on, not a
 * restatement of it — so it cannot drift from them. `status` and `avStatus` are
 * for the *message*, never for the decision: they are what turns "not available"
 * into `Scanning`, `Published but unscanned` or `Quarantined` instead of an
 * unexplained spinner.
 */
export const CurrentVersion = z.object({
  id: z.string(),
  major: z.number(),
  minor: z.number(),
  status: z.enum(['PENDING', 'SCANNING', 'PROCESSING', 'AVAILABLE', 'QUARANTINED', 'FAILED']),
  avStatus: z.enum(['PENDING', 'CLEAN', 'INFECTED', 'SKIPPED', 'ERROR']),
  isReadable: z.boolean(),
});

export type CurrentVersion = z.infer<typeof CurrentVersion>;

/**
 * `GET /files/{id}` — what the peek panel reads.
 *
 * Note what is **not** here: no path, no breadcrumb, no owner, no classification
 * and no activity feed. The panel is written against this shape rather than
 * against the prototype's, and the difference is recorded as a gap rather than
 * filled in with a guess.
 */
export const FileDetail = z.object({
  id: z.string(),
  type: NodeType,
  name: z.string(),
  mimeType: z.string(),
  sizeBytes: z.number(),
  parentId: z.string().optional(),
  libraryId: z.string(),
  status: ItemStatus,
  currentVersion: CurrentVersion.optional(),
  revision: z.number(),
  aclRevision: z.number(),
  capabilities: FileCapabilities,
  obligations: Obligations,
  governance: z.object({
    onLegalHold: z.boolean(),
    isRecord: z.boolean(),
  }),
  createdAt: z.string(),
  modifiedAt: z.string(),
});

export type FileDetail = z.infer<typeof FileDetail>;

/** One entry of `GET /files/{id}/versions`. */
export const VersionEntry = z.object({
  id: z.string(),
  major: z.number(),
  minor: z.number(),
  status: z.enum(['PENDING', 'SCANNING', 'PROCESSING', 'AVAILABLE', 'QUARANTINED', 'FAILED']),
  avStatus: z.enum(['PENDING', 'CLEAN', 'INFECTED', 'SKIPPED', 'ERROR']),
  approvalState: z.enum(['DRAFT', 'PENDING', 'APPROVED', 'REJECTED']).optional(),
  sizeBytes: z.number(),
  mimeType: z.string(),
  checksumSha256: z.string(),
  /**
   * Whether this version may actually be served as bytes.
   *
   * `CLAUDE.md` rule 9: nothing is `AVAILABLE` before antivirus completes. The
   * server computes this from `status = 'AVAILABLE' AND av_status = 'CLEAN'`
   * and sends the answer — the client shows it and never recomputes it from the
   * two fields beside it, which is the same rule as `capabilities`.
   */
  isReadable: z.boolean(),
  createdBy: z.string(),
  createdAt: z.string(),
  comment: z.string().optional(),
});

export type VersionEntry = z.infer<typeof VersionEntry>;

export const VersionPage = z.object({
  items: z.array(VersionEntry),
  page: PageInfo,
});

export type VersionPage = z.infer<typeof VersionPage>;
