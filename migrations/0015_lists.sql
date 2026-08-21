-- `lists` — docs/04-DATA-MODEL.md §10 — and the foreign key `library_views.list_id` has been
-- missing since 0010.
--
-- # What this closes
--
-- `migrations/0010_library_views.sql` declares `list_id` with no foreign key and says why: `lists`
-- had no migration, and a key cannot reference a table that does not exist. The consequence is the
-- one §3.3 exists to remove — a view naming *another tenant's* list is two individually well-formed
-- rows, and row-level security does not catch it, because RLS filters the rows a query returns and
-- has nothing to say about the value in a column. The `CHECK` insisting on exactly one container
-- kept such a row well-formed; it never made it right. Tracked as `ENC-502`.
--
-- 0010 is not edited to add the key. Migrations are checksummed and forward-only (`ENC-155`,
-- `ENC-172`), so a comment fix there would fail the gate on every database that has already applied
-- it; its note stays as the record of why the gap existed, and this is the migration it points to.
--
-- # What is created, and what deliberately is not
--
-- DDL from §10 as written — no column here that §10 does not list — with the additions this
-- document's own rules require and its listing omits:
--
--   1. `UNIQUE (tenant_id, id)`, which is what makes a composite key onto `lists` expressible at
--      all, and a composite key onto `workspaces` (§3.3). `libraries` carries exactly this pair,
--      for exactly this reason.
--   2. RLS enabled, forced, and a `tenant_isolation` policy (§3.2).
--   3. Grants for `enclave_app`.
--
-- `list_fields` and `list_items` are specified in §10 beside `lists` and are **not** created here.
-- The foreign key does not need them, no crate reads them, and a table nothing queries is one whose
-- isolation is asserted by a structural gate and by nothing else — which is how `content_types`
-- came to be created twice (`ENC-165`). They belong to the milestone that builds lists as a
-- feature, and it will find this file the way this file found 0010's note.
--
-- No unique constraint on `slug` either. §10 states none, and `libraries` — the sibling this table
-- is shaped after, with the same `workspace_id`/`slug`/`deleted_at` trio — has none. Making `lists`
-- stricter than `libraries` on the same column, with no document saying so, is a rule invented in a
-- migration; `workspaces` has `uq_workspace_slug`, so the difference between the two is a real
-- question, and it is one for §10 rather than for here.
--
-- # Why the index is plain `CREATE INDEX`
--
-- Not `CONCURRENTLY`, and `ENC-517` rather than preference is the reason. sqlx runs each migration
-- inside one transaction and `CONCURRENTLY` cannot run in one; worse, `CONCURRENTLY` waits for
-- every concurrent transaction holding an older snapshot while the test harness serialises setup
-- behind a session-level advisory lock held across the whole migration run, so binaries deadlock
-- against each other intermittently and the failure names the RLS gate rather than this file.
-- `migrations/0012_lexical_search_indexes.sql` carries the full account and the operator-side
-- zero-downtime path.
--
-- Forward-only: a new migration, never an edit to 0010.

CREATE TABLE IF NOT EXISTS lists (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    workspace_id UUID NOT NULL,
    name         TEXT NOT NULL,
    slug         TEXT NOT NULL,
    description  TEXT,
    inherit_permissions BOOLEAN NOT NULL DEFAULT TRUE,
    revision     BIGINT NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    deleted_at   TIMESTAMPTZ,

    -- The primary key is `id` alone, so `(tenant_id, id)` needs its own unique constraint before
    -- anything can reference it compositely. Without this the key added at the bottom of this file
    -- is not merely absent — it is unwritable.
    UNIQUE (tenant_id, id),
    CONSTRAINT lists_workspace_fkey
        FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id)
);

COMMENT ON COLUMN lists.inherit_permissions IS
    'FALSE stops ACL inheritance at this list; the break is materialised as copied entries with inherited_from set (docs/04 §9).';

-- The read path is "the lists in this workspace", and the soft-deleted ones are not part of the
-- answer to it. Partial rather than full, so a workspace that has been emptied and refilled does
-- not carry its history through every listing.
CREATE INDEX IF NOT EXISTS idx_lists_workspace
    ON lists (tenant_id, workspace_id) WHERE deleted_at IS NULL;

ALTER TABLE lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE lists FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON lists
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Full CRUD, on the same argument 0010 makes for `library_views`: what a caller may do to a list is
-- decided by the authorization stage against `acl_entries`, not by which verbs the application role
-- holds on the table. `DELETE` is granted because `deleted_at` is a soft delete and a hard one still
-- has to be possible for the paths that purge — trash expiry, tenant deletion — which run as this
-- role like everything else.
GRANT SELECT, INSERT, UPDATE, DELETE ON lists TO enclave_app;

-- ---------------------------------------------------------------------------
-- library_views.list_id — the key 0010 could not write
-- ---------------------------------------------------------------------------

-- `DROP … IF EXISTS` first so the file is re-runnable against a database that has it, matching how
-- 0014 adds its `CHECK`. Nothing in this tree has the constraint, so this is a no-op today; it
-- exists so that re-running is not a decision anyone has to make under pressure.
ALTER TABLE library_views
    DROP CONSTRAINT IF EXISTS library_views_list_fkey;

-- Composite, including `tenant_id` (§3.3): the point is not that `list_id` names *a* list but that
-- it names one belonging to the same tenant as the view.
--
-- The subtlety worth stating, because it is what makes this safe to add to a table whose column is
-- nullable in the ordinary case: a composite foreign key is `MATCH SIMPLE` by default, so a row with
-- `list_id IS NULL` satisfies it without any lookup at all. A library-owned view — every view that
-- exists today — is therefore unaffected, while a list-owned view is now checked against `lists`.
-- That is the same shape `library_views_library_fkey` already has for list-owned views, and it is
-- why the `CHECK` requiring exactly one container is the constraint that makes both meaningful.
--
-- `ON DELETE CASCADE` mirrors the library key: a view is an arrangement of a container's contents
-- and has no meaning once the container is gone.
ALTER TABLE library_views
    ADD CONSTRAINT library_views_list_fkey
        FOREIGN KEY (tenant_id, list_id) REFERENCES lists (tenant_id, id)
        ON DELETE CASCADE;

-- RLS, the `tenant_isolation` policy and the `enclave_app` grants on `library_views` are properties
-- of that table and were established in 0010. A constraint does not change any of them, and
-- re-issuing them here would suggest it does.
