import { z } from 'zod';
import { CapabilityReasons } from '../capability/denial.ts';

/* The wire shapes of `GET /workspaces`, `GET /workspaces/{id}/libraries` and
 * `GET /libraries/{id}`.
 *
 * `crates/api/src/routes/workspaces.rs` and `routes/libraries.rs` are the
 * authority. Types are **inferred** from these schemas and never declared
 * beside them (`docs/17 §3`).
 *
 * These three routes are what makes a library picker possible at all. Until
 * `PR #71` a client had no way to discover which workspace or library a user
 * could see, so `features/libraries` took the id from the URL and drew the
 * unbuilt treatment when it was absent. That is no longer the honest state of
 * the world, and the picker below replaces it.
 */

/**
 * The six container capabilities, and why this is a `strictObject`.
 *
 * The same argument as `entities/file/api-model.ts`: a field the server stops
 * sending must be a **parse failure**, never an `undefined` that renders as
 * *refused*. `undefined` is falsy, so a dropped `create` would disable Upload
 * and New with the confidence of a real policy decision the chain never made.
 *
 * Note that these are *not* the file capabilities. A container is created in,
 * a file is downloaded from, and collapsing the two objects into one shape is
 * how `CLAUDE.md` rule 6 gets violated by a type rather than by a handler.
 */
export const ContainerCapabilities = z.strictObject({
  read: z.boolean(),
  create: z.boolean(),
  update: z.boolean(),
  delete: z.boolean(),
  manageMembers: z.boolean(),
  managePermissions: z.boolean(),
});

export type ContainerCapabilities = z.infer<typeof ContainerCapabilities>;

/** Shared by both container payloads; `CLAUDE.md` rule 8 — obligations are carried, not inferred. */
const Obligations = z.object({
  watermark: z.boolean(),
  justificationRequired: z.array(z.string()),
  approvalRequired: z.array(z.string()),
});

/** `GET /workspaces` — one row. `description` is `skip_serializing_if` on the server. */
export const Workspace = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  description: z.string().optional(),
  visibility: z.string(),
  revision: z.number(),
  capabilities: ContainerCapabilities,
  /** Why each `false` above is `false` (`ENC-674`). See `entities/capability/denial.ts`. */
  capabilityReasons: CapabilityReasons.optional(),
  obligations: Obligations,
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type Workspace = z.infer<typeof Workspace>;

/**
 * A library's settings.
 *
 * Read for two facts the picker genuinely uses — `externalSharing` and
 * `syncEnabled` are shown on the library's own header — and parsed in full
 * rather than picked apart, so a server that adds a setting does not silently
 * change what this means.
 */
export const LibrarySettings = z.object({
  versioningMode: z.string(),
  requireCheckout: z.boolean(),
  requireApproval: z.boolean(),
  externalSharing: z.string(),
  aiIndexingEnabled: z.boolean(),
  mcpVisible: z.boolean(),
  syncEnabled: z.boolean(),
});

/** `GET /workspaces/{id}/libraries` — one row — and `GET /libraries/{id}` whole. */
export const Library = z.object({
  id: z.string(),
  workspaceId: z.string(),
  name: z.string(),
  slug: z.string(),
  revision: z.number(),
  settings: LibrarySettings,
  capabilities: ContainerCapabilities,
  /** Why each `false` above is `false` (`ENC-674`). See `entities/capability/denial.ts`. */
  capabilityReasons: CapabilityReasons.optional(),
  obligations: Obligations,
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type Library = z.infer<typeof Library>;

const PageInfo = z.object({
  nextCursor: z.string().nullish(),
  hasMore: z.boolean(),
  limit: z.number().optional(),
});

export const WorkspacePage = z.object({ items: z.array(Workspace), page: PageInfo });
export type WorkspacePage = z.infer<typeof WorkspacePage>;

export const LibraryPage = z.object({ items: z.array(Library), page: PageInfo });
export type LibraryPage = z.infer<typeof LibraryPage>;
