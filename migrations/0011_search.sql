-- `retrieval_denylist` and `index_manifests` — docs/04-DATA-MODEL.md §13.
--
-- DDL from §13, with the additions this document's own rules require: composite foreign keys
-- (§3.3), RLS enabled and forced with a `tenant_isolation` policy (§3.2), grants for `enclave_app`,
-- and a `CHECK` on `status` mirrored by `enclave_search`'s vocabulary.
--
-- # Why the denylist exists at all
--
-- `docs/12-TESTING.md §4.3` S3 asks that a revoked file vanish from search results **immediately**,
-- before any index update. S4 asks that S3 still hold with the invalidation worker stopped.
--
-- Those two together forbid the design everybody reaches for first — enqueue a job, let a worker
-- remove the document from the index — because a stopped worker then means a revoked file stays
-- findable, *and the search still answers*. Not an outage: a wrong answer delivered confidently.
--
-- So revocation writes a row here in the same transaction that changes the ACL
-- (`plans/M3-DISCOVERY.md` D22), and every search consults it. The worker's job is to clean up
-- afterwards, and its absence must cost only index size, never correctness.
--
-- Forward-only: a new migration, never an edit to 0010.

CREATE TABLE IF NOT EXISTS retrieval_denylist (
    tenant_id  UUID NOT NULL,
    file_id    UUID NOT NULL,
    -- Why the file is suppressed. Free text rather than a closed vocabulary, deliberately: the
    -- denylist is written by whatever changed the ACL, and constraining the reason would mean this
    -- migration has to change every time a new revocation path appears — which is how a check ends
    -- up being dropped instead of extended.
    reason     TEXT NOT NULL,
    added_at   TIMESTAMPTZ NOT NULL,
    -- When the suppression may be lifted, once the index is known to have caught up. `NULL` means
    -- "not yet" and is the safe reading: a row with no expiry suppresses forever, which costs
    -- recall. The opposite default would cost correctness.
    clears_at  TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, file_id),
    CONSTRAINT retrieval_denylist_file_fkey
        FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
        ON DELETE CASCADE
);

-- The read path is "which of these candidates are suppressed", for a batch of file ids, and it runs
-- inside every search's latency budget. The primary key already serves it; this index exists for
-- the *sweep* — the worker asking which rows have become liftable — which would otherwise scan a
-- tenant's whole denylist on every pass.
CREATE INDEX IF NOT EXISTS idx_denylist_clears
    ON retrieval_denylist (tenant_id, clears_at) WHERE clears_at IS NOT NULL;

ALTER TABLE retrieval_denylist ENABLE ROW LEVEL SECURITY;
ALTER TABLE retrieval_denylist FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON retrieval_denylist
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- DELETE is granted because lifting a suppression is the worker's ordinary job. Note what that
-- means: the application role can remove a row that is suppressing a file. That is correct — the
-- suppression is an index-freshness mechanism, not an access control. What decides whether a caller
-- may see a file is the post-filter against `acl_entries`, which runs whether or not this table has
-- a row, and which no amount of denylist tampering can widen.
GRANT SELECT, INSERT, UPDATE, DELETE ON retrieval_denylist TO enclave_app;

-- ---------------------------------------------------------------------------
-- index_manifests — what the index believes about each file
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS index_manifests (
    tenant_id        UUID NOT NULL,
    file_id          UUID NOT NULL,
    version_id       UUID NOT NULL,
    index_version    INT NOT NULL,
    extractor_version TEXT NOT NULL,
    chunker_version  TEXT NOT NULL,
    embedding_model  TEXT NOT NULL,
    -- `files.acl_revision` as it stood when the index was last written. The reconciler compares the
    -- two: a file whose ACL has moved on since indexing has stale `acl_tokens` in the vector store,
    -- which is exactly the over-permissive candidate the post-filter exists to drop (S5).
    acl_epoch        BIGINT NOT NULL DEFAULT 0,
    status           TEXT NOT NULL CHECK (status IN ('PENDING','EXTRACTING','EMBEDDING','INDEXING','READY','FAILED','STALE','SKIPPED')),
    chunk_count      INT NOT NULL DEFAULT 0,
    -- Fixed vocabulary at the writer, never a provider's message: a failure reason is written by
    -- code that has just parsed a hostile document, and echoing what that produced into a column
    -- every operator reads is how a payload travels.
    failure_reason   TEXT,
    attempts         INT NOT NULL DEFAULT 0,
    indexed_at       TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, file_id),
    CONSTRAINT index_manifests_file_fkey
        FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT index_manifests_version_fkey
        FOREIGN KEY (tenant_id, version_id) REFERENCES file_versions (tenant_id, id)
        ON DELETE CASCADE
);

-- The worker's queue: what still needs doing, oldest first. Partial, because `READY` is the steady
-- state and a full index would be mostly rows the worker never looks at.
CREATE INDEX IF NOT EXISTS idx_manifests_pending
    ON index_manifests (tenant_id, updated_at)
    WHERE status <> 'READY';

ALTER TABLE index_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE index_manifests FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON index_manifests
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON index_manifests TO enclave_app;
