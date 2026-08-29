-- 0030 — `idx_files_trash`: the index `docs/04-DATA-MODEL.md` has promised since `0004` and no
--   migration ever created. `ENC-938`; needed by `GET /api/v1/trash`.
--
-- # The drift
--
-- `docs/04-DATA-MODEL.md §7` carries this line, and has since the file surface was specified:
--
--     CREATE INDEX idx_files_trash ON files (tenant_id, purge_after) WHERE deleted_at IS NOT NULL;
--
-- It is in no migration. `SELECT indexname FROM pg_indexes WHERE tablename = 'files'` on a fully
-- migrated database returns seven indexes and this is not one of them. The document has described a
-- structure the schema does not have for the whole life of the project, and nothing noticed because
-- nothing queried the trash — `GET /libraries/{id}/items` filters `deleted_at IS NOT NULL` *out*,
-- which the existing indexes serve, and `find_including_trashed` looks up a single row by primary
-- key. `ENC-938` is the first reader of the trash as a set, and it found the promise unkept.
--
-- The `04-DATA-MODEL.md §7` cross-reference is corrected in the same change: the document keeps the
-- DDL, and this migration is what makes it true rather than aspirational.
--
-- # The column list is `(tenant_id, deleted_at DESC)`, not the documented `(tenant_id, purge_after)`
--
-- Deliberate, and the document is updated to match rather than the other way round.
--
-- `purge_after` is what a *reaper* keys on: "which rows are old enough to destroy" is a range scan
-- over that column, and there is no reaper yet. `deleted_at` is what a *reader* keys on: `GET /trash`
-- orders most-recently-deleted first, which is exactly this index read backwards, and it is the only
-- statement in the product that reads the trash today.
--
-- The two are not interchangeable and the difference is not cosmetic. `purge_after` is
-- `deleted_at + TRASH_RETENTION_DAYS` computed at write time, so today they sort identically and an
-- index on either would serve either query. That stops being true the moment retention becomes a
-- tenant setting — `ENC-913` records that every interval in this product is a `Default` nobody can
-- override — because two files deleted a minute apart under different policies then sort one way by
-- `deleted_at` and the other by `purge_after`. Indexing what the reader actually orders by means the
-- ordering survives that change; indexing the other means the day retention becomes configurable is
-- the day this listing silently starts sorting on a column nobody is looking at.
--
-- A reaper, when it exists, gets its own index on `purge_after` and its own argument.
--
-- # What this costs on a populated `files`, stated plainly
--
-- `CREATE INDEX` takes a `SHARE` lock: reads continue, **writes to `files` block for the duration of
-- the build**. `CONCURRENTLY` would avoid that and cannot be used here — sqlx runs each migration
-- inside one transaction and `CONCURRENTLY` cannot run in one. `ENC-517`, and `0012`, `0017`,
-- `0022`, `0023`, `0028` and `0029` all carry that account.
--
-- Where those migrations bounded the cost by argument — a new empty table, an all-`NULL` column —
-- **this one cannot**, and saying so is the point. `0022`'s own note calls `files` "the most
-- populated table in the schema". The index is partial and will be small, but PostgreSQL still scans
-- every row of `files` to build it, so the pause is proportional to the whole table and not to the
-- trash.
--
-- An operator with a large `files` should build it out of band before migrating, which makes this
-- statement a no-op:
--
--     CREATE INDEX CONCURRENTLY idx_files_trash
--         ON files (tenant_id, deleted_at DESC) WHERE deleted_at IS NOT NULL;
--
-- `IF NOT EXISTS` below is what makes that safe rather than a collision.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE INDEX IF NOT EXISTS idx_files_trash
    ON files (tenant_id, deleted_at DESC)
    WHERE deleted_at IS NOT NULL;

-- Asserted at apply time, in the shape `0025`, `0026` and `0029` use. A `CREATE INDEX` on the wrong
-- column list is an index the planner will not use, and a listing that silently sequential-scans
-- `files` is a page that gets slower with every deletion anybody ever makes.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'idx_files_trash'
    ) THEN
        RAISE EXCEPTION
            'idx_files_trash is missing; GET /api/v1/trash would sequential-scan files on every request';
    END IF;
END
$$;
