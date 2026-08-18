-- `file_versions`, `upload_sessions` and `file_locks` — the three tables of docs/04-DATA-MODEL.md
-- §8 that migration 0005 deliberately left for the milestone that had something to put in them.
--
-- DDL verbatim from docs/04-DATA-MODEL.md §8, with three additions that the document's own rules
-- require and its §8 listing omits. Each is called out where it appears:
--
--   1. Composite foreign keys on `upload_sessions` and `file_locks` (§3.3: "foreign keys within
--      tenant-scoped tables are composite and include tenant_id"). §8 spells them out for
--      `files` and `file_versions` and not for these two; a single-column reference — or none at
--      all — lets a child row point at a parent in another tenant, which row-level security does
--      not catch because both rows are individually well-formed.
--   2. RLS enabled, forced, and a `tenant_isolation` policy on all three (§3.2).
--   3. Grants for `enclave_app` on all three. Migration 0003's catalog loop has already run and
--      will not run again, so a table created after it and not granted here is a table the
--      application role cannot see at all — which is how, before ENC-124, every isolation test in
--      the workspace passed with isolation switched off. Stated per table rather than looped, so
--      that reading this file tells you exactly what it did.
--
-- Forward-only: a new migration, never an edit to 0005.

-- ---------------------------------------------------------------------------
-- file_versions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS file_versions (
    id               UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    file_id          UUID NOT NULL,
    object_key       TEXT NOT NULL,
    storage_profile_id UUID NOT NULL,
    size_bytes       BIGINT NOT NULL,
    checksum_sha256  TEXT NOT NULL,
    mime_type        TEXT NOT NULL,
    major            INT NOT NULL,
    minor            INT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('PENDING','SCANNING','PROCESSING','AVAILABLE','QUARANTINED','FAILED')),
    av_status        TEXT NOT NULL DEFAULT 'PENDING' CHECK (av_status IN ('PENDING','CLEAN','INFECTED','SKIPPED','ERROR')),
    av_engine        TEXT,
    av_signature_version TEXT,
    av_scanned_at    TIMESTAMPTZ,
    approval_state   TEXT CHECK (approval_state IN ('DRAFT','PENDING','APPROVED','REJECTED')),
    encryption_mode  TEXT NOT NULL DEFAULT 'PROVIDER',
    encryption_key_ref TEXT,
    created_by       UUID NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    comment          TEXT,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
);

-- The version number is unique per file, and the database is the only place that can hold that
-- under concurrency: two commits racing to be `3.0` both read the same maximum and this index is
-- what rejects the loser. `crates/versions` maps the violation to a retryable conflict rather than
-- reading first and hoping.
CREATE UNIQUE INDEX IF NOT EXISTS uq_version_number ON file_versions (tenant_id, file_id, major, minor);

-- Deliberately *not* tenant-scoped, unlike every other index here. An object key names one blob in
-- one bucket, and two rows pointing at the same key is the one way a purge for tenant A can delete
-- tenant B's bytes. Global uniqueness is what makes that unrepresentable — which is also why
-- `restore` in `crates/versions` copies the object to a fresh key instead of re-pointing at the old
-- one.
CREATE UNIQUE INDEX IF NOT EXISTS uq_version_object ON file_versions (object_key);

-- Version history is always read newest-first for one file (docs/05-API.md §8), so the index
-- carries the sort order rather than leaving it to a sort node.
CREATE INDEX IF NOT EXISTS idx_versions_file ON file_versions (tenant_id, file_id, major DESC, minor DESC);

-- Immutability, as a database guarantee rather than an application convention
-- (plans/M1-CONTENT-CORE.md D12). docs/04 §8: rows are immutable once `AVAILABLE`, except for the
-- governance columns — `approval_state` and the AV rescan columns — which is why those are absent
-- from the list below and why `status` itself stays writable: an AV rescan that finds a new
-- signature must be able to move an `AVAILABLE` row to `QUARANTINED`.
--
-- What is frozen is the row's *content identity*: which bytes it names, how many there are, what
-- they hash to, and where the row sits in the file's history. A version whose checksum can be
-- rewritten after the fact is not evidence of anything, and every downstream guarantee — the AV
-- verdict, the retention record, the audit chain that references it — is a statement about bytes
-- that could since have been swapped.
--
-- BEFORE UPDATE rather than a CHECK constraint because a CHECK cannot see OLD, and AFTER would let
-- the write happen and then roll it back, which is the same outcome by a slower route.
CREATE OR REPLACE FUNCTION file_versions_reject_content_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    frozen_column TEXT;
BEGIN
    -- Before a version is AVAILABLE it is still being assembled by the upload state machine
    -- (docs/03-LLD.md §15), which legitimately rewrites size and checksum as parts land.
    IF OLD.status <> 'AVAILABLE' THEN
        RETURN NEW;
    END IF;

    frozen_column := CASE
        WHEN NEW.object_key      IS DISTINCT FROM OLD.object_key      THEN 'object_key'
        WHEN NEW.checksum_sha256 IS DISTINCT FROM OLD.checksum_sha256 THEN 'checksum_sha256'
        WHEN NEW.size_bytes      IS DISTINCT FROM OLD.size_bytes      THEN 'size_bytes'
        WHEN NEW.major           IS DISTINCT FROM OLD.major           THEN 'major'
        WHEN NEW.minor           IS DISTINCT FROM OLD.minor           THEN 'minor'
        ELSE NULL
    END;

    IF frozen_column IS NULL THEN
        RETURN NEW;
    END IF;

    -- The message names the row and the column and nothing else. `object_key` is derived from a
    -- file name and a file name is content (CLAUDE.md rule 10), so neither the old nor the new
    -- value appears here, in the log, or in the error the caller receives.
    --
    -- SQLSTATE 23514 with a named constraint and a COLUMN field, rather than a bare
    -- `raise_exception` with a formatted message: the driver then reports this as an integrity
    -- violation carrying `file_versions_immutable` and the offending column as *structured fields*.
    -- `crates/versions` reads those fields. Anything that had to parse the message string instead
    -- would be one wording change away from silently classifying this as an unknown failure.
    RAISE EXCEPTION
        'file version % is AVAILABLE; column % is immutable', OLD.id, frozen_column
        USING ERRCODE    = '23514',
              CONSTRAINT = 'file_versions_immutable',
              COLUMN     = frozen_column,
              HINT       = 'Commit a new version instead. Only approval_state and the av_* columns may change after a version becomes AVAILABLE.';
END;
$$;

CREATE OR REPLACE TRIGGER file_versions_immutable
    BEFORE UPDATE ON file_versions
    FOR EACH ROW
    EXECUTE FUNCTION file_versions_reject_content_mutation();

ALTER TABLE file_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_versions FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON file_versions
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- UPDATE is granted because the governance columns above are updated on the AV and approval paths;
-- the trigger, not the grant, is what keeps content identity frozen. DELETE is granted because
-- permanent deletion removes version rows together with the objects they name
-- (docs/03-LLD.md §18); what stops a row disappearing early is legal hold and retention, which are
-- row-level conditions rather than table-level privileges.
GRANT SELECT, INSERT, UPDATE, DELETE ON file_versions TO enclave_app;

-- ---------------------------------------------------------------------------
-- upload_sessions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS upload_sessions (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    library_id     UUID NOT NULL,
    parent_id      UUID,
    file_id        UUID,                       -- set when uploading a new version
    name           TEXT NOT NULL,
    declared_size  BIGINT,
    declared_mime  TEXT,
    staged_key     TEXT NOT NULL,
    multipart_id   TEXT,
    state          TEXT NOT NULL CHECK (state IN ('CREATED','UPLOADING','UPLOADED','SCANNING','PROCESSING','AVAILABLE','QUARANTINED','FAILED','ABORTED','EXPIRED')),
    bytes_received BIGINT NOT NULL DEFAULT 0,
    created_by     UUID NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    -- Addition (1) above. A session names where its bytes will land; all three references are to
    -- tenant-scoped tables, so all three carry `tenant_id` per §3.3. Without them a session in
    -- tenant A can be created against a library in tenant B, and the cross-tenant write only
    -- becomes visible when the version is committed against a file nobody in A can see.
    --
    -- `UNIQUE (tenant_id, id)` is the other half of the same rule: it is the target a future
    -- composite key can reference, and `file_versions` and `files` both carry it for that reason.
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, library_id) REFERENCES libraries (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id)  REFERENCES files (tenant_id, id),
    FOREIGN KEY (tenant_id, file_id)    REFERENCES files (tenant_id, id)
);

-- The reaper's index (docs/03-LLD.md §15: staged objects are collected after `upload.session_ttl`).
-- Partial, because sessions that reached `AVAILABLE` or `ABORTED` are terminal and are exactly the
-- rows the sweep must never walk — and they are the overwhelming majority.
CREATE INDEX IF NOT EXISTS idx_uploads_expiry ON upload_sessions (expires_at) WHERE state NOT IN ('AVAILABLE','ABORTED');

ALTER TABLE upload_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_sessions FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON upload_sessions
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- DELETE as well as UPDATE: the expiry sweep removes sessions once their staged objects are gone,
-- and a sweep that can only mark rows leaves a table that grows for the lifetime of the tenant.
GRANT SELECT, INSERT, UPDATE, DELETE ON upload_sessions TO enclave_app;

-- ---------------------------------------------------------------------------
-- file_locks
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS file_locks (
    tenant_id   UUID NOT NULL,
    file_id     UUID NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('CHECKOUT','EDITOR','SYSTEM')),
    holder_id   UUID NOT NULL,
    session_ref UUID,
    acquired_at TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ,
    -- One lock per file, and the primary key is what enforces it: two clients checking a document
    -- out at the same instant is precisely the race a lock exists to lose, and a read-then-insert
    -- would let both win.
    PRIMARY KEY (tenant_id, file_id),
    -- Addition (1) above.
    FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
);

ALTER TABLE file_locks ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_locks FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON file_locks
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- DELETE is the release path; without it a check-in cannot drop the lock and every checked-out
-- document stays locked until its `expires_at` passes.
GRANT SELECT, INSERT, UPDATE, DELETE ON file_locks TO enclave_app;
