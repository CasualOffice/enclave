-- `metadata_fields`, `metadata_values`, `taxonomy_terms` — docs/04-DATA-MODEL.md §10.
--
-- `content_types` is **not** here, though §10 lists it beside these: migration 0004 already created
-- it, with its RLS and its grants. The first draft of this file recreated it, and
-- `CREATE TABLE IF NOT EXISTS` silently did nothing while the `CREATE POLICY` after it failed —
-- which is the useful shape of that mistake, because a policy is exactly what a silently-skipped
-- duplicate table would have been missing. Read the migrations, not only the document describing
-- what should exist.
--
-- DDL from those sections, with the additions this document's own rules require and its listing
-- omits, each called out where it appears:
--
--   1. Composite foreign keys (§3.3) wherever the target is a tenant-scoped table.
--   2. RLS enabled, forced, and a `tenant_isolation` policy on all four (§3.2).
--   3. Grants for `enclave_app`.
--   4. `CHECK`s mirrored by `enclave_metadata`'s vocabularies, which read *this file* to verify
--      they agree rather than restating the lists.
--
-- Forward-only: a new migration, never an edit to 0008.

-- ---------------------------------------------------------------------------
-- metadata_fields
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS metadata_fields (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    scope         TEXT NOT NULL CHECK (scope IN ('TENANT','WORKSPACE','LIBRARY','CONTENT_TYPE')),
    scope_id      UUID,
    key           TEXT NOT NULL,
    label         TEXT NOT NULL,
    field_type    TEXT NOT NULL CHECK (field_type IN ('TEXT','NUMBER','BOOLEAN','DATE','DATETIME','USER','GROUP','CHOICE','MULTI_CHOICE','URL','EMAIL','TAXONOMY','REFERENCE','JSON')),
    required      BOOLEAN NOT NULL DEFAULT FALSE,
    indexed       BOOLEAN NOT NULL DEFAULT FALSE,
    config        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL,
    CONSTRAINT metadata_fields_scope_id_matches_scope
        CHECK ((scope = 'TENANT') = (scope_id IS NULL)),
    UNIQUE (tenant_id, scope, scope_id, key),
    UNIQUE (tenant_id, id)
);

-- `NULLS NOT DISTINCT` is not available on the unique constraint above for a TENANT-scoped row,
-- where `scope_id` is NULL and NULLs are distinct in a unique index — so two tenant-wide fields
-- could share a key. This partial index closes that: it is the same uniqueness, expressed where
-- the NULL lives.
CREATE UNIQUE INDEX IF NOT EXISTS uq_metadata_field_tenant_scope
    ON metadata_fields (tenant_id, key) WHERE scope = 'TENANT';

ALTER TABLE metadata_fields ENABLE ROW LEVEL SECURITY;
ALTER TABLE metadata_fields FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON metadata_fields
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON metadata_fields TO enclave_app;

-- ---------------------------------------------------------------------------
-- metadata_values
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS metadata_values (
    tenant_id     UUID NOT NULL,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('FILE','FOLDER','LIBRARY','LIST_ITEM','PAGE')),
    resource_id   UUID NOT NULL,
    field_id      UUID NOT NULL,
    value         JSONB NOT NULL,
    -- **Generated, not written.** docs/04 §10 calls this "a generated projection for
    -- filtering/sorting", and generating it in the database rather than in the application is the
    -- difference between a projection that cannot disagree with its source and one that does the
    -- moment anything writes `value` without going through the writer that maintains it. Filters
    -- and sorts read this column, so a drifted projection is a wrong answer to a query rather than
    -- a cosmetic defect.
    --
    -- Scalars only. `#>>'{}'` alone would render a container as its JSON text — `["a", "b"]` —
    -- and that is worse than nothing here: it sorts by punctuation, and a filter for the tag `a`
    -- would have to match a substring of a rendering rather than a value. An array or object has
    -- no single sortable projection, so the honest answer is NULL and the honest place to filter a
    -- multi-valued field is a containment query against `value` itself.
    --
    -- (The first draft did use bare `#>>'{}'` and claimed it yielded NULL for containers. It does
    -- not; the test below is what said so.)
    value_text    TEXT GENERATED ALWAYS AS (
        CASE WHEN jsonb_typeof(value) IN ('object', 'array') THEN NULL ELSE value #>> '{}' END
    ) STORED,
    updated_by    UUID NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, resource_type, resource_id, field_id),
    CONSTRAINT metadata_values_field_fkey
        FOREIGN KEY (tenant_id, field_id) REFERENCES metadata_fields (tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_metadata_field_value
    ON metadata_values (tenant_id, field_id, value_text);

ALTER TABLE metadata_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE metadata_values FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON metadata_values
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON metadata_values TO enclave_app;

-- ---------------------------------------------------------------------------
-- taxonomy_terms
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS taxonomy_terms (
    id         UUID PRIMARY KEY,
    tenant_id  UUID NOT NULL,
    set_name   TEXT NOT NULL,
    parent_id  UUID,
    label      TEXT NOT NULL,
    path       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, set_name, path),
    CONSTRAINT taxonomy_terms_parent_fkey
        FOREIGN KEY (tenant_id, parent_id) REFERENCES taxonomy_terms (tenant_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_taxonomy_set ON taxonomy_terms (tenant_id, set_name, path);

ALTER TABLE taxonomy_terms ENABLE ROW LEVEL SECURITY;
ALTER TABLE taxonomy_terms FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON taxonomy_terms
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON taxonomy_terms TO enclave_app;
