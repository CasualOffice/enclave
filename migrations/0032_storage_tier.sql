-- =================================================================================================
-- 0032 — where a version's bytes physically live, and how long it takes to get them back.
--
-- `ENC-946`. Archival — "deep storage" — is a product decision this schema has never carried:
-- `tier`, `storage class`, `Glacier` and `archive` appear nowhere in `docs/` before this migration,
-- so the reasoning is written here and lifted into `docs/04 §8` and `docs/08` rather than left in a
-- commit message.
--
-- ## Why this is not a `status` value
--
-- The obvious shape is `file_versions.status IN (…, 'ARCHIVED', 'RESTORING')`, and it is wrong.
-- `status` answers **"is this content processed and safe to serve"** — it is the column
-- `CLAUDE.md` rule 9 is about, the one that keeps `SCANNING` bytes off every read path. A tier
-- answers a different question: **"how long will fetching it take"**. They are orthogonal, and a
-- version that is clean, scanned, approved and cold is `AVAILABLE` *and* `ARCHIVED`.
--
-- Collapsing them costs three things. An archived version would become indistinguishable from a
-- quarantined one at every `status = 'AVAILABLE'` predicate in the tree, so archiving content would
-- silently make it look infected. Rule 9's column would start carrying a latency fact, so a future
-- reader could not tell which of its values were safety and which were speed. And restoring from
-- the archive would have to *write* `status`, which is the antivirus pipeline's column — a second
-- writer to the one place the product cannot afford two.
--
-- ## Four values, and why `ARCHIVING` and `RESTORING` are among them
--
-- A tier transition is not instant on any provider that has a cold tier. S3 Glacier Deep Archive
-- takes hours to restore; even the fast tiers take minutes. So the intermediate states are real
-- states the product must be able to name, not implementation noise:
--
--   HOT        the bytes are immediately readable. Every existing row, by default.
--   ARCHIVING  a transition has been requested and the provider has not confirmed it.
--   ARCHIVED   the bytes are cold. No read path may mint a URL for them.
--   RESTORING  a rehydration has been requested and the bytes are not back yet.
--
-- **The design assumes slow rehydration.** A design built for minutes breaks on Deep Archive; one
-- built for hours degrades to minutes without changing shape. So `RESTORING` is a state a caller
-- polls, never a request that blocks — and `restore_requested_at` is what a sweep and a support
-- engineer both read to answer *"is this stuck?"*.
--
-- ## `HOT` for every existing row, and why that is safe rather than convenient
--
-- The default backfills every version written before this migration as immediately readable, which
-- is exactly what they are: nothing has moved any bytes. The failure direction matters — a wrong
-- `HOT` makes the product try to read bytes that are there, and a wrong `ARCHIVED` makes it refuse
-- bytes it could have served. Backfilling to `ARCHIVED` would take every file in the deployment
-- offline.
-- =================================================================================================

ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS storage_tier TEXT NOT NULL DEFAULT 'HOT'
        CHECK (storage_tier IN ('HOT','ARCHIVING','ARCHIVED','RESTORING'));

-- When rehydration was asked for. NULL unless the row is `RESTORING`, or was and has landed.
--
-- Kept after the restore completes rather than cleared: *how long the last rehydration took* is the
-- only evidence a deployment has that its archive tier is behaving, and clearing it on success
-- destroys that evidence at exactly the moment it becomes useful.
ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS restore_requested_at TIMESTAMPTZ;

-- The two are tied: a row cannot claim to be restoring without a moment it started.
--
-- Stated as a constraint rather than trusted to the writer because the writer is a worker sweep,
-- and a sweep that sets the tier and fails before the timestamp leaves a row that is `RESTORING`
-- forever with nothing to measure the wait against — a state no operator can distinguish from a
-- provider that has stopped answering.
ALTER TABLE file_versions
    DROP CONSTRAINT IF EXISTS file_versions_restoring_has_a_start;
ALTER TABLE file_versions
    ADD CONSTRAINT file_versions_restoring_has_a_start
        CHECK (storage_tier <> 'RESTORING' OR restore_requested_at IS NOT NULL);

COMMENT ON COLUMN file_versions.storage_tier IS
    'How fast these bytes can be fetched, never whether they may be (ENC-946). Orthogonal to status, which is CLAUDE.md rule 9''s column: a version can be AVAILABLE and ARCHIVED at once — clean, scanned, permitted, and hours away.';

COMMENT ON COLUMN file_versions.restore_requested_at IS
    'When rehydration was requested. Not cleared on success: how long the last restore took is the only evidence a deployment has that its archive tier is behaving.';

-- The sweep's index, and the only one this adds.
--
-- Partial, on the two transient tiers alone. A sweep asks "what is mid-transition" and the answer is
-- a handful of rows in a table that holds every version of every file ever written, so an index over
-- all of them would be almost entirely `HOT` entries no query ever looks at. `tenant_id` leads it
-- because every read here is tenant-scoped (`docs/04 §1`) and a sweep runs per tenant.
--
-- Not `CONCURRENTLY`: sqlx runs each migration in a transaction and `CREATE INDEX CONCURRENTLY`
-- cannot run inside one. The `SHARE` lock this takes blocks writes to `file_versions` for the scan
-- — but the predicate means the *index* is near-empty, and on a fresh deployment the table is too.
-- An operator with a large `file_versions` should build it out of band first; `migrations/0030`
-- carries the same warning for the same reason, and unlike `0022` there is no argument that bounds
-- the table's size.
CREATE INDEX IF NOT EXISTS idx_file_versions_in_transition
    ON file_versions (tenant_id, storage_tier, restore_requested_at)
    WHERE storage_tier IN ('ARCHIVING','RESTORING');
