-- 0017 — a slug addresses exactly one live row in its container.
--
-- `ENC-544`. Closes the disagreement `migrations/0015_lists.sql` recorded rather than invented an
-- answer to: `workspaces` carries `uq_workspace_slug`, while `libraries` and `lists` carry nothing,
-- so two of the three URL-segment columns said a slug is a label and the third said it is an
-- address. `docs/04-DATA-MODEL.md §10.1` now decides — a slug is an address — and this file is what
-- makes the schema agree with it. The two indexes below are the two that were wrong.
--
-- # Why this is the direction the disagreement was resolved in
--
-- The argument is in §10.1 and is not repeated here. The one line worth carrying next to the DDL:
-- the alternative was dropping `uq_workspace_slug`, and a constraint is not symmetric with its
-- absence. Adding one can be done later at the cost of a repair; dropping one cannot be undone at
-- all once duplicates exist, because the rows that violate it are by then real content somebody
-- owns.
--
-- # Scope: per workspace, over live rows, on the stored value
--
--   * **Per workspace, not per tenant.** A library's path segment is only ever read beneath a
--     workspace's, so `(tenant_id, workspace_id, slug)` is the narrowest key that makes the path
--     unambiguous. Tenant-wide uniqueness would refuse `finance/reports` and `legal/reports`, which
--     are two different, entirely reachable paths.
--   * **`WHERE deleted_at IS NULL`, matching `uq_workspace_slug`.** Both tables soft-delete, and a
--     trashed row must not hold its name against a replacement. This is also why the index is
--     partial rather than a `UNIQUE` constraint: PostgreSQL has no partial unique *constraint*, only
--     a partial unique *index*, so the constraint form is not available even in principle.
--   * **On the stored value, with no `lower()`.** `enclave_db::normalize_slug` folds case and
--     whitespace in Rust on the way in, deliberately — PostgreSQL's `lower()` is collation
--     dependent and the collation belongs to the database, so a restore into a differently
--     configured cluster would quietly change what collides with what. `crates/db/src/normalize.rs`
--     carries the reasoning. `LibraryRepository::create` and `::update` already fold, which is why
--     this index can be built over existing library rows without a normalization pass first.
--
-- # If this migration fails on a populated deployment
--
-- It will fail with SQLSTATE `23505`, naming `uq_library_slug` or `uq_list_slug`, because that
-- deployment already holds two live rows in one workspace with the same slug. That is not a defect
-- in this file; it is the ambiguity this file exists to remove, surfacing at the only moment
-- anything has ever looked for it. **Do not edit this migration.** Migrations are forward-only and
-- checksummed (`ENC-155`, `ENC-172`); the repair is an operator action taken *before* re-running it,
-- and this file is re-runnable because every statement is `IF NOT EXISTS`.
--
-- Find the collisions:
--
--     SELECT tenant_id, workspace_id, slug, count(*) AS n, array_agg(id ORDER BY created_at)
--     FROM libraries WHERE deleted_at IS NULL
--     GROUP BY tenant_id, workspace_id, slug HAVING count(*) > 1;
--     -- and the same query against `lists`
--
-- Resolve each by **renaming** all but the oldest — `UPDATE libraries SET slug = slug || '-' ||
-- left(id::text, 8), updated_at = now() WHERE id = '…'` — and not by soft-deleting the extras.
-- Renaming is safe precisely because of the gap §10.1 admits: nothing in `docs/05-API.md` routes by
-- slug today, so no link anywhere points at the old value and no user-visible content moves.
-- Soft-deleting would remove a container and everything under it from every listing in order to fix
-- a naming clash, which is a data-loss remedy for a cosmetic problem. Then re-run.
--
-- The repair is not automated here. A migration that silently rewrote an operator's names would
-- change what their users see without anybody deciding to, and it would have to pick which of two
-- equally legitimate rows keeps the name.
--
-- # Why plain `CREATE INDEX`, never `CONCURRENTLY`
--
-- `ENC-517`, and `migrations/0012_lexical_search_indexes.sql` carries the full account. Two reasons,
-- either sufficient: sqlx runs each migration inside one transaction and `CONCURRENTLY` cannot run
-- in one; and `CONCURRENTLY` waits for every concurrent transaction holding an older snapshot, while
-- the test harness serialises setup behind a session-level advisory lock held across the whole
-- migration run — so test binaries deadlock against each other intermittently, with `40P01` naming
-- the RLS gate rather than this file.
--
-- The zero-downtime path is an operator step, exactly as 0012 documents it: build the same index
-- `CONCURRENTLY` by hand before deploying, under the same name, and `IF NOT EXISTS` makes this file
-- a no-op when it runs. The name is what makes that work, so it must match:
--
--     CREATE UNIQUE INDEX CONCURRENTLY uq_library_slug
--         ON libraries (tenant_id, workspace_id, slug) WHERE deleted_at IS NULL;
--     CREATE UNIQUE INDEX CONCURRENTLY uq_list_slug
--         ON lists (tenant_id, workspace_id, slug) WHERE deleted_at IS NULL;
--
-- A `CONCURRENTLY` build that hits a duplicate leaves the index `INVALID` rather than failing
-- outright; `DROP INDEX` it, repair as above, and build again.
--
-- # What this file does not touch
--
--   * `uq_workspace_slug` (0004) — already correct, and re-issuing it here would suggest otherwise.
--   * `tenants.slug` — a plain `UNIQUE` with **no** `deleted_at` predicate, and §10.1 states why
--     that asymmetry is deliberate rather than an oversight: a tenant slug is a routing key that
--     outlives the tenant, and handing a deleted tenant's slug to a new one makes an old link
--     resolve into somebody else's data.
--   * `pages.slug` — `pages` has no migration in this tree. §10.1 states the rule it must carry when
--     one lands, so that the index arrives with the table rather than as a repair.
--   * RLS, policies and grants on both tables — properties of the tables, established in 0004 and
--     0015. An index does not change any of them.

-- ---------------------------------------------------------------------------
-- libraries — docs/04 §7, rule in §10.1
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS uq_library_slug
    ON libraries (tenant_id, workspace_id, slug) WHERE deleted_at IS NULL;

COMMENT ON INDEX uq_library_slug IS
    'A library slug is a URL segment and addresses one live library per workspace (docs/04 §10.1, ENC-544). Partial: a trashed library does not hold its name.';

-- ---------------------------------------------------------------------------
-- lists — docs/04 §10, rule in §10.1
-- ---------------------------------------------------------------------------

-- `idx_lists_workspace` from 0015 is `(tenant_id, workspace_id) WHERE deleted_at IS NULL`, which is
-- a leading prefix of this index under the identical predicate — so this one serves the "the lists
-- in this workspace" listing too, and 0015's is now redundant. It is **not** dropped here, and that
-- is a choice rather than an omission: `ENC-544` is a correctness question about slugs, dropping an
-- index is an availability change to a read path, and the two do not belong in one migration where
-- a revert of either is a revert of both. Logged for its own row. (`libraries` had no such index at
-- all — 0004 creates none — so there is nothing to be redundant with there, and that table's
-- listing gains its first index as a side effect of this one.)
CREATE UNIQUE INDEX IF NOT EXISTS uq_list_slug
    ON lists (tenant_id, workspace_id, slug) WHERE deleted_at IS NULL;

COMMENT ON INDEX uq_list_slug IS
    'A list slug is a URL segment and addresses one live list per workspace (docs/04 §10.1, ENC-544). Partial: a trashed list does not hold its name.';
