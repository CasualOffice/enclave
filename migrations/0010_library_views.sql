-- `library_views` — docs/04-DATA-MODEL.md §10.
--
-- DDL from §10, with the additions this document's own rules require and its listing omits:
--
--   1. A composite foreign key onto `libraries` (§3.3). A view naming another tenant's library is
--      two individually well-formed rows, which row-level security does not catch. `list_id` gets
--      none, for the reason noted where it is declared.
--   2. RLS enabled, forced, and a `tenant_isolation` policy (§3.2).
--   3. Grants for `enclave_app`.
--   4. `CHECK`s mirrored by `enclave_libraries::views`'s vocabularies, which read *this file* to
--      verify they agree rather than restating the lists.
--   5. Three `CHECK`s that §10 states as prose or leaves implied: exactly one container, an owner
--      exactly when the scope is personal, and a personal view never being a library's default.
--      Each is an invariant a read below assumes, and an assumption a database does not enforce is
--      one that holds until the first bulk import.
--
-- Forward-only: a new migration, never an edit to 0009.

CREATE TABLE IF NOT EXISTS library_views (
    id                UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    -- Exactly one of these is set; the `CHECK` below enforces it. A view belongs to a library or to
    -- a list, and one belonging to both would have two sets of columns to be valid against.
    library_id        UUID,
    list_id           UUID,
    name              TEXT NOT NULL,
    view_type         TEXT NOT NULL CHECK (view_type IN ('LIST','COMPACT','DETAILS','GRID','CARDS','GALLERY','TILES','TREE','TIMELINE')),
    filter_definition JSONB NOT NULL,
    sort_definition   JSONB NOT NULL,
    group_definition  JSONB,
    visible_columns   JSONB NOT NULL,
    column_widths     JSONB,
    scope             TEXT NOT NULL CHECK (scope IN ('PERSONAL','LIBRARY','WORKSPACE','TENANT_TEMPLATE')),
    -- Set exactly when the scope is PERSONAL, and enforced rather than documented: a personal view
    -- with no owner is visible to everyone, and a shared view with one belongs to somebody who can
    -- be deactivated.
    owner_id          UUID,
    is_default        BOOLEAN NOT NULL DEFAULT FALSE,
    created_by        UUID NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,

    -- §10 gives this one as prose; it is the invariant every read below assumes.
    CONSTRAINT library_views_belongs_to_one_container
        CHECK ((library_id IS NOT NULL) <> (list_id IS NOT NULL)),
    CONSTRAINT library_views_owner_matches_scope
        CHECK ((scope = 'PERSONAL') = (owner_id IS NOT NULL)),
    -- A personal view is one person's arrangement of their own screen. Making it the *default* for
    -- a library would impose it on everybody, which is a different act with different permissions —
    -- so it is unrepresentable rather than merely refused in a handler.
    CONSTRAINT library_views_personal_is_never_default
        CHECK (NOT (is_default AND scope = 'PERSONAL')),

    CONSTRAINT library_views_library_fkey
        FOREIGN KEY (tenant_id, library_id) REFERENCES libraries (tenant_id, id)
        ON DELETE CASCADE
    -- `list_id` has **no** foreign key, and that is a gap rather than a decision: `lists` has no
    -- migration yet (`docs/04 §10` specifies it; nothing has needed it). A key cannot reference a
    -- table that does not exist, so the column is unconstrained until the milestone that creates
    -- `lists` adds one — which is why the `CHECK` above insists on exactly one container, keeping a
    -- row that names a list at least well-formed. Tracked as `ENC-502`.
);

-- One default per library, among the views that are not somebody's personal arrangement.
-- Partial, because `is_default` is false on almost every row and a full index would be mostly
-- entries nobody queries.
CREATE UNIQUE INDEX IF NOT EXISTS uq_view_default ON library_views (tenant_id, library_id)
    WHERE is_default AND scope <> 'PERSONAL';

-- The read path: every view a caller may see in one container, personal ones included.
CREATE INDEX IF NOT EXISTS idx_views_container
    ON library_views (tenant_id, library_id, scope);

-- Deactivating a user has to find their personal views to remove them, and a scan of every view in
-- a large tenant to answer "which are this person's" is the shape that makes offboarding slow.
CREATE INDEX IF NOT EXISTS idx_views_owner
    ON library_views (tenant_id, owner_id) WHERE owner_id IS NOT NULL;

ALTER TABLE library_views ENABLE ROW LEVEL SECURITY;
ALTER TABLE library_views FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON library_views
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- A view is an arrangement of a screen, not a permission: it decides which columns are shown and in
-- what order, and never which rows a caller may see. That is why full CRUD is granted here without
-- the argument the content tables needed — the authorization stage answers the row question
-- independently, and a view whose filter names a file the caller cannot read still shows them
-- nothing.
GRANT SELECT, INSERT, UPDATE, DELETE ON library_views TO enclave_app;
