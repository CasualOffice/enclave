-- Full-text indexes for the degraded (lexical) search path.
--
-- # Why these are NOT `CONCURRENTLY`, despite CLAUDE.md's rule
--
-- `CLAUDE.md` says `CREATE INDEX CONCURRENTLY`; `migrations/0004_content_and_acl.sql` said an index
-- on a populated table "must be CONCURRENTLY, in a migration of its own". This migration was
-- written that way and had to be changed, so the reason is recorded here rather than left for
-- somebody to rediscover.
--
-- `CONCURRENTLY` waits for every concurrent transaction that could hold an older snapshot to
-- finish. The test harness serialises database setup behind a **session-level advisory lock**
-- (`crates/testing/src/lib.rs`, `SETUP_LOCK`) held across the whole migration run. So one test
-- binary holds the setup lock and blocks inside `CONCURRENTLY`, waiting for transactions belonging
-- to the other binaries — which are themselves waiting for the setup lock it is holding. PostgreSQL
-- reports `40P01 deadlock detected`, every database-backed test in the workspace fails, and the
-- failure names the RLS gate rather than this file.
--
-- It is intermittent, which is worse: it depends on how many test binaries start together, so it
-- passes locally, passes on a re-run, and fails in CI. It did exactly that — it was seen locally,
-- mistaken for an unrelated race, re-run, and went green.
--
-- So: plain `CREATE INDEX`, which takes a `SHARE` lock — blocking writes to the table for the
-- duration of the build, and allowing reads throughout.
--
-- **For a deployment with a large `files` table**, build these by hand before upgrading:
--
--     CREATE INDEX CONCURRENTLY idx_files_name_fts ON files
--         USING GIN (to_tsvector('simple', regexp_replace(name, '[^[:alnum:]]+', ' ', 'g')))
--         WHERE deleted_at IS NULL;
--
-- `IF NOT EXISTS` then makes this migration a no-op. That is the whole reason it is written that
-- way: the zero-downtime path is available without a second migration, and taking it is an
-- operator's decision rather than a property of the schema.
--
-- # Why the expressions are what they are
--
-- These match `crates/search/src/lexical.rs` **exactly**, including the `regexp_replace`. An
-- expression index is used only when the query's expression is identical, so a difference of one
-- character does not produce a slower query — it produces a sequential scan while the index sits
-- unused, which reads as the index not helping rather than as a typo.
--
-- The `regexp_replace` is load-bearing: PostgreSQL's text parser reads `budget-forecast.xlsx` as a
-- single indivisible `file` token, so a search for `budget` finds nothing. Folding punctuation to
-- spaces first is what makes a filename searchable by its parts.
--
-- `'simple'`, not a language configuration: a stemmer must assume a language, and assuming wrongly
-- fails silently — an English stemmer over German filenames simply stops matching, with no error
-- anywhere. `docs/14-I18N-L10N.md` has tenants in many languages, and one guess for all of them is
-- worse than no stemming for any.

CREATE INDEX IF NOT EXISTS idx_files_name_fts
    ON files
    USING GIN (to_tsvector('simple', regexp_replace(name, '[^[:alnum:]]+', ' ', 'g')))
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_metadata_value_text_fts
    ON metadata_values
    USING GIN (to_tsvector('simple', regexp_replace(coalesce(value_text, ''), '[^[:alnum:]]+', ' ', 'g')));
