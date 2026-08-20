-- `chunk_text` — the extracted text of a version's chunks, held in PostgreSQL.
--
-- New DDL rather than a transcription: `docs/04-DATA-MODEL.md §15` defines `index_manifests` and
-- `retrieval_denylist` and has nowhere for the text itself, because the text was only ever going to
-- Milvus. `§15` is updated in the same change as this migration, so the document stays the single
-- place DDL is defined.
--
-- Written with the additions `docs/04 §3` requires of every tenant-scoped table: `tenant_id` first,
-- composite foreign keys that include it (§3.3), RLS enabled *and* forced with a `tenant_isolation`
-- policy (§3.2), and grants for `enclave_app` — migration 0003's catalog loop has already run and
-- will not run again, so a table created after it and not granted here is one the application role
-- cannot see at all.
--
-- Forward-only: a new migration, never an edit to 0012.
--
-- # Why this table exists
--
-- `ENC-514` shipped degraded search and `ENC-515` recorded what it could not do: with no extracted
-- text in PostgreSQL, the lexical path searched file names and scalar metadata only. A contract
-- whose body says *indemnity* was invisible unless that word was in its filename — and invisible in
-- exactly the circumstance degraded mode exists for, when the vector store is down and this is the
-- only retrieval there is.
--
-- Milvus already holds a copy of chunk text (`docs/07 §4`), and it is the wrong copy to reach for
-- here: the whole premise of the fallback is that the vector store cannot be reached.
--
-- # This is a derived store, and stays one
--
-- `docs/16-GLOSSARY.md` calls extracted text derived: rebuildable, never authoritative. Both foreign
-- keys therefore cascade. `docs/03-LLD.md §18` requires a purge to reach derived state, and a
-- content copy that outlived the file it was extracted from would be exactly the sort of orphan a
-- purge is supposed to eliminate — findable by search, attached to nothing, unnoticed until somebody
-- searches for the phrase that was meant to be gone.
--
-- Deleting every row here costs recall until the next reindex and costs nothing else. That is the
-- test of whether a store is derived, and this one passes it.
--
-- # What this table is not
--
-- It is not an authorization surface. A row here says *this text is in this file*, never *this
-- caller may read it*. Retrieval over it produces candidates, and every candidate goes through
-- `crates/search`'s post-filter against `acl_entries` before a caller sees it (`CLAUDE.md` rule 5).
-- Nothing in this table is consulted about permissions, which is why it carries no ACL column, no
-- classification rank and no barrier tokens: a column of that shape is one somebody eventually
-- trusts instead of resolving.
--
-- # Why the text is stored per chunk rather than per version
--
-- Chunk identity is deterministic — `chunk_id = uuid_v5(version_id, chunker_version || ordinal)`,
-- `docs/07 §2` — and that is what makes a retried indexing run an upsert rather than a duplication
-- (`ENC-513`). Storing one concatenated blob per version would throw that away and take the
-- citation boundary with it: an excerpt has to name a chunk for a result to deep-link to a place a
-- person can navigate to.
--
-- # Why the indexes here are NOT `CONCURRENTLY`
--
-- The same reason migration 0012 records at length, and it must not be reintroduced: `CONCURRENTLY`
-- waits for every concurrent transaction holding an older snapshot, while the test harness
-- serialises setup behind a session-level advisory lock held across the whole migration run
-- (`crates/testing/src/lib.rs`, `SETUP_LOCK`). One binary then blocks inside `CONCURRENTLY` waiting
-- for transactions belonging to binaries waiting for the lock it holds — `40P01`, every
-- database-backed test failing, and the failure naming the RLS gate rather than the migration
-- (`ENC-517`). It is intermittent, so it passes locally and fails in CI.
--
-- This table is empty when the migration runs, so a plain `CREATE INDEX` takes its `SHARE` lock on
-- nothing. For a deployment upgrading with rows already in it, build them by hand first:
--
--     CREATE INDEX CONCURRENTLY idx_chunk_text_fts ON chunk_text
--         USING GIN (to_tsvector('simple', regexp_replace(text, '[^[:alnum:]]+', ' ', 'g')));
--
-- `IF NOT EXISTS` then makes this migration a no-op, which is the reason it is written that way:
-- the zero-downtime path is available without a second migration, and taking it is an operator's
-- decision rather than a property of the schema.

CREATE TABLE IF NOT EXISTS chunk_text (
    tenant_id       UUID NOT NULL,
    -- Deterministic, from `enclave_indexing::chunk_id`. The primary key, so a re-run of the same
    -- version through the same chunker updates rows instead of adding a second copy of every one.
    chunk_id        UUID NOT NULL,
    file_id         UUID NOT NULL,
    -- Which version this text was extracted from. Not merely provenance: a file's chunks are
    -- replaced wholesale when a new version indexes, and this column is what makes "wholesale"
    -- checkable after the fact.
    version_id      UUID NOT NULL,
    -- Position within the version, from zero. Part of the chunk's identity upstream, kept here so a
    -- future excerpt can be ordered and cited rather than presented as a loose fragment.
    --
    -- `BIGINT` for a `u32`, which looks like slack and is not: `INT` would need a narrowing cast at
    -- the writer, and the only two things a narrowing cast can do on overflow are fail an indexing
    -- run or write a silently wrong ordinal. A wider column removes the decision.
    ordinal         BIGINT NOT NULL CHECK (ordinal >= 0),
    -- Which build of the splitter produced this row. A chunker change re-chunks the version and
    -- writes new ids (`docs/07 §5`); this column is what lets an operator see a version still
    -- carrying the old scheme without re-deriving the ids to find out.
    chunker_version TEXT NOT NULL,
    -- The chunk body. Bounded by `ChunkBudget::max_chars` at the writer and deliberately not by a
    -- CHECK here: the budget is configurable per deployment, and a constraint restating a
    -- configurable number is one that starts rejecting valid rows the day somebody tunes it.
    text            TEXT NOT NULL,
    -- The database's clock, not a caller's. Nothing compares this to a timestamp supplied from
    -- outside — `ENC-518` found that two clocks answering one question is how a worker running
    -- seconds fast changes what the database considers true.
    written_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, chunk_id),
    CONSTRAINT chunk_text_file_fkey
        FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT chunk_text_version_fkey
        FOREIGN KEY (tenant_id, version_id) REFERENCES file_versions (tenant_id, id)
        ON DELETE CASCADE
);

-- The lexical content search, and the reason the expression is spelled exactly like this.
--
-- It matches `crates/search/src/lexical.rs` **character for character**, `regexp_replace` included.
-- An expression index is used only when the query's expression is identical, so a difference of one
-- character does not produce a slower query — it produces a sequential scan over every chunk of
-- every file in the tenant while the index sits unused, which reads as "full-text search is slow"
-- rather than as a typo.
--
-- The `regexp_replace` is load-bearing for the same reason it is on `files.name`: PostgreSQL's
-- parser reads `clause-7.2(b)` as compound tokens, so a search for `clause` misses it. Folding
-- punctuation to spaces first is what makes the parts searchable, on both sides.
--
-- `'simple'`, not a language configuration: a stemmer must assume a language, and assuming wrongly
-- fails silently — an English stemmer over German text simply stops matching, with no error
-- anywhere. `docs/14-I18N-L10N.md` has tenants in many languages, and one guess for all of them is
-- worse than no stemming for any. Document *bodies* make this sharper than filenames did: a tenant's
-- files may be named in English while their contents are not.
CREATE INDEX IF NOT EXISTS idx_chunk_text_fts
    ON chunk_text
    USING GIN (to_tsvector('simple', regexp_replace(text, '[^[:alnum:]]+', ' ', 'g')));

-- Every write path names a file: the writer replaces one file's chunks in one statement, and the
-- `files` cascade above deletes by `(tenant_id, file_id)`. Without this, both scan the tenant's
-- whole chunk store, which is the largest table this schema has.
CREATE INDEX IF NOT EXISTS idx_chunk_text_file
    ON chunk_text (tenant_id, file_id);

-- The `file_versions` cascade deletes by `(tenant_id, version_id)` and cannot use the index above.
-- Version rows are removed by version-depth pruning and by purge, so this is not a rare path, and an
-- unindexed cascade turns a routine prune into a sequential scan per version removed.
CREATE INDEX IF NOT EXISTS idx_chunk_text_version
    ON chunk_text (tenant_id, version_id);

ALTER TABLE chunk_text ENABLE ROW LEVEL SECURITY;
ALTER TABLE chunk_text FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON chunk_text
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- UPDATE and DELETE are granted because replacing a file's text is the indexing worker's ordinary
-- job: a re-run upserts the chunks it produced and prunes the ones it did not. Note what that
-- means and what it does not — the application role can delete rows here, which costs recall until
-- the next reindex, and can insert rows here, which puts a file in front of a query it would not
-- otherwise have matched. Neither widens what any caller may *see*: that is decided by the
-- post-filter against `acl_entries`, which runs over every candidate this table produces.
GRANT SELECT, INSERT, UPDATE, DELETE ON chunk_text TO enclave_app;
