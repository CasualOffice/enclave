-- `renditions` — the base-rendition cache of docs/04-DATA-MODEL.md §8.
--
-- DDL from docs/04-DATA-MODEL.md §8, with the additions that document's own rules require and its
-- §8 listing omits, each called out where it appears:
--
--   1. A composite foreign key onto `file_versions` (§3.3: "foreign keys within tenant-scoped
--      tables are composite and include tenant_id"). Without it a rendition row can name a version
--      in another tenant — both rows individually well-formed, so row-level security does not
--      catch it — and the read path would then serve one tenant's rendering under another
--      tenant's version id.
--   2. RLS enabled, forced, and a `tenant_isolation` policy (§3.2).
--   3. Grants for `enclave_app`. Migration 0003's catalog loop has already run and will not run
--      again, so a table created after it and not granted here is a table the application role
--      cannot see at all.
--   4. A `CHECK` on `profile`, mirrored by `enclave_preview::RenditionProfile`. §8 gives the column
--      as free text with examples; an open vocabulary here means a typo becomes a permanent cache
--      miss that regenerates on every request rather than an error anybody notices.
--
-- ON DELETE CASCADE is deliberate and is the mechanism behind docs/06 §5.1: "deleting or purging a
-- version purges its renditions in the same job". A rendition is derived content with no
-- independent right to exist — if its source version is gone, serving it would be serving content
-- the tenant believes they deleted. The objects the rows name are removed by the same purge job;
-- the cascade is what guarantees no row outlives its source and points at a key nobody will clean.
--
-- Forward-only: a new migration, never an edit to 0006.

CREATE TABLE IF NOT EXISTS renditions (
    tenant_id         UUID NOT NULL,
    version_id        UUID NOT NULL,
    -- Mirrored by `enclave_preview::RenditionProfile`; same members, same spellings.
    profile           TEXT NOT NULL CHECK (profile IN ('thumb', 'page-png-1x', 'page-png-2x',
                                                       'pdf-sanitized', 'html-sanitized')),
    object_key        TEXT NOT NULL,
    size_bytes        BIGINT NOT NULL CHECK (size_bytes >= 0),
    page_count        INT CHECK (page_count IS NULL OR page_count > 0),
    -- Which build of the pipeline produced this. Deliberately a column and not part of the primary
    -- key: docs/06 §5.1 keys the *cache* on (version_id, profile, generator_version), and if that
    -- triple were the key then every generator upgrade would silently strand the whole cache as
    -- unreachable rows. As a column, the read path compares it to the running generator and treats
    -- a mismatch as a miss, so an upgrade regenerates and replaces rather than accumulating.
    generator_version TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    last_access_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, version_id, profile),
    CONSTRAINT renditions_version_fkey
        FOREIGN KEY (tenant_id, version_id) REFERENCES file_versions (tenant_id, id)
        ON DELETE CASCADE
);

-- LRU eviction (docs/04-DATA-MODEL.md §12: "LRU eviction at the configured cache size") scans for
-- the coldest rows in a tenant. `NULLS FIRST` so a rendition that has never been read since it was
-- written sorts before one that has — an entry generated and never used again is the first thing
-- an eviction sweep should reclaim.
CREATE INDEX IF NOT EXISTS idx_renditions_lru
    ON renditions (tenant_id, last_access_at NULLS FIRST);

ALTER TABLE renditions ENABLE ROW LEVEL SECURITY;
ALTER TABLE renditions FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON renditions
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- UPDATE is granted for two writes and no others: `last_access_at` on the read path, and the
-- replacement of a row whose `generator_version` has gone stale. DELETE is granted for the eviction
-- sweep; a rendition carries no retention or legal-hold weight of its own, because destroying
-- derived content destroys no record — the version it came from is the record, and that one cannot
-- be deleted while held.
GRANT SELECT, INSERT, UPDATE, DELETE ON renditions TO enclave_app;
