-- =================================================================================================
-- 0034 — what a person has starred.
--
-- `ENC-959`. *Favorites* has carried a `Later` chip in the navigation since the shell was written
-- and has never existed in this schema: `favorite`, `starred` and `bookmark` appear nowhere in
-- `docs/` or in `migrations/`. So this is a new product decision, recorded here and lifted into
-- `docs/04 §15`.
--
-- ## It is the user's own data, and that shapes every column
--
-- A favorite grants nothing, reveals nothing and decides nothing. It is a private note this person
-- made about a file they could already see, which is why the key is `(tenant_id, user_id, file_id)`
-- and why nothing else in the schema references it. Two people starring one file are two rows that
-- know nothing about each other, and neither can tell that the other exists.
--
-- ## `DELETE` is granted here, and withheld on every policy table
--
-- `retention_assignments`, `dlp_rules` and `print_tokens` all refuse it, for one reason: a statement
-- that removes the evidence a control existed is the statement those tables are for. **None of that
-- applies to a star.** There is no compliance value in the record that somebody once favourited a
-- document, and withholding `DELETE` would mean un-starring needed a `removed_at` column and a
-- filter on every read — carrying tombstones of a preference nobody audits. The verb every other
-- table withholds is the correct verb here, and saying so is the point of this paragraph: the
-- pattern is deliberate where it appears, not a house style to copy.
--
-- ## No `ON DELETE CASCADE`, and no trigger either
--
-- A favourite whose file has been trashed is filtered by the read's join on `files.deleted_at`,
-- exactly as `recent_files` is. Cascading on the *purge* would be correct and is unreachable —
-- `enclave_files::purge` is unimplemented (`ENC-946`) — so the composite foreign key is declared
-- without one and the row is left for whoever implements permanent deletion, alongside the
-- renditions, chunks and tombstones that purge already owes.
-- =================================================================================================

CREATE TABLE IF NOT EXISTS favorites (
    tenant_id  UUID NOT NULL REFERENCES tenants (id),

    -- Whose. A favourite is personal: it is never inherited, never shared, and never visible to
    -- anybody else, so this column is half the key rather than a filter applied afterwards.
    user_id    UUID NOT NULL,

    -- What. `files` holds both files and folders and a person may star either.
    file_id    UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- `tenant_id` leads (`CLAUDE.md` rule 4), and the three columns together are the natural key:
    -- starring a file twice is the same fact, not two of them. That is what makes the write
    -- idempotent without the handler needing a read first — see `ENC-959`'s endpoint.
    PRIMARY KEY (tenant_id, user_id, file_id),

    -- Composite, both of them. PostgreSQL runs referential integrity with row security deliberately
    -- not enforced (`docs/04 §3.3`), so a single-column `REFERENCES files (id)` would accept another
    -- tenant's file — and a favourite is a read the user's own screen performs, so a cross-tenant
    -- row would put another tenant's document on it.
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),
    FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
);

COMMENT ON TABLE favorites IS
    'What a person has starred (ENC-959). Private: a favorite grants nothing, reveals nothing and decides nothing, and two people starring one file are two rows that cannot see each other.';

-- The listing's index: one person's stars, most recent first.
--
-- The primary key already covers `(tenant_id, user_id, …)` and cannot serve this, because the
-- listing orders by `created_at` and the key's third column is `file_id`. A `LIMIT`ed read over the
-- key would sort the whole of a person's stars every time.
CREATE INDEX IF NOT EXISTS idx_favorites_recent
    ON favorites (tenant_id, user_id, created_at DESC);

ALTER TABLE favorites ENABLE ROW LEVEL SECURITY;
ALTER TABLE favorites FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON favorites
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Grants. Migration 0003's catalog loop has already run and will not run again, so a table created
-- after it and not granted here is one the application role cannot see at all.
--
-- `DELETE` is included, and the header says why it is right here and wrong on the policy tables.
GRANT SELECT, INSERT, DELETE ON favorites TO enclave_app;
