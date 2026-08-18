-- The `files` table, and the indexes ACL resolution walks.
--
-- Lands here rather than with ENC-130 (files and folders) because ACL resolution needs it *now*:
-- the inheritance walk in crates/authorization/src/repo.rs is a recursive CTE over `files`, so
-- without this table the resolver cannot answer a question about a file at all — not slowly, not
-- partially. Deferring it would mean shipping a resolver whose only real use case fails at runtime.
--
-- Only `files`. `file_versions`, `upload_sessions` and `file_locks` are docs/04 §8 too and arrive
-- with ENC-129 and ENC-131, when there is something to put in them. `current_version_id` is a bare
-- UUID with no foreign key in the documented schema, so it does not force their hand here.
--
-- DDL verbatim from docs/04-DATA-MODEL.md §8. Forward-only: a new migration, not an edit to 0004.

CREATE TABLE IF NOT EXISTS files (
    id                 UUID PRIMARY KEY,
    tenant_id          UUID NOT NULL,
    workspace_id       UUID NOT NULL,
    library_id         UUID NOT NULL,
    parent_id          UUID,                    -- NULL = library root
    node_type          TEXT NOT NULL CHECK (node_type IN ('FILE','FOLDER')),
    name               TEXT NOT NULL,
    normalized_name    TEXT NOT NULL,           -- casefolded + NFC, for uniqueness
    mime_type          TEXT NOT NULL,
    content_type_id    UUID,
    current_version_id UUID,
    size_bytes         BIGINT NOT NULL DEFAULT 0,
    classification_id  UUID,
    classification_source TEXT CHECK (classification_source IN ('MANUAL','INHERITED','DETECTED','WORKFLOW')),
    inherit_permissions BOOLEAN NOT NULL DEFAULT TRUE,
    revision           BIGINT NOT NULL DEFAULT 1,
    acl_revision       BIGINT NOT NULL DEFAULT 1,
    is_record          BOOLEAN NOT NULL DEFAULT FALSE,
    on_legal_hold      BOOLEAN NOT NULL DEFAULT FALSE,
    status             TEXT NOT NULL DEFAULT 'AVAILABLE'
                       CHECK (status IN ('AVAILABLE','PROCESSING','QUARANTINED','FAILED')),
    created_by         UUID NOT NULL,
    modified_by        UUID NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    modified_at        TIMESTAMPTZ NOT NULL,
    deleted_at         TIMESTAMPTZ,
    purge_after        TIMESTAMPTZ,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, library_id) REFERENCES libraries (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id)  REFERENCES files (tenant_id, id)
);

-- Name uniqueness within a folder, ignoring trashed items (docs/04 §8). A constraint rather than an
-- application check, so a concurrent create cannot slip a duplicate past a read-then-write.
CREATE UNIQUE INDEX IF NOT EXISTS uq_files_sibling_name
ON files (tenant_id, library_id, COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), normalized_name)
WHERE deleted_at IS NULL;

-- The walk in ACL resolution is parent-ward and tenant-scoped; this is the index it rides.
CREATE INDEX IF NOT EXISTS idx_files_parent    ON files (tenant_id, parent_id, normalized_name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_files_library   ON files (tenant_id, library_id, modified_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_files_workspace ON files (tenant_id, workspace_id);

-- Row-level security and grants, per 0002 and 0003. Stated explicitly rather than by re-running a
-- catalog loop, so that reading this file tells you what it did to this table.
ALTER TABLE files ENABLE ROW LEVEL SECURITY;
ALTER TABLE files FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON files
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON files TO enclave_app;
