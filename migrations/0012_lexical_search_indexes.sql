-- no-transaction
--
-- Full-text indexes for the degraded (lexical) search path.
--
-- # Why this migration is alone, and why the first line is what it is
--
-- `migrations/0004_content_and_acl.sql` wrote this one down in advance: *"an index on a populated
-- one of these tables must be CONCURRENTLY, in a migration of its own."* This is that migration.
--
-- `CREATE INDEX` takes an `ACCESS EXCLUSIVE` lock, which on a populated `files` table means every
-- read and write in the tenant blocks until the index is built — a maintenance window, for an
-- index whose entire purpose is to make an *outage* survivable. `CONCURRENTLY` cannot run inside a
-- transaction block, and sqlx wraps each migration in one, so the `-- no-transaction` marker on
-- line 1 tells it not to. That marker must stay first: sqlx matches it with `starts_with`.
--
-- The cost of running outside a transaction, stated rather than discovered: if a `CONCURRENTLY`
-- build fails part-way it leaves an **`INVALID`** index behind, which the planner ignores and which
-- must be dropped by hand before a retry. There is no partial rollback to lean on. That is the
-- trade for not locking a production table, and it is the right way round — a failed migration an
-- operator can see and fix beats a locked table nobody can use.
--
-- # Why the expressions are what they are
--
-- These match `crates/search/src/lexical.rs` **exactly**, including the `regexp_replace`. An
-- expression index is only used when the query's expression is identical, so a difference of one
-- character here does not produce a slower query — it produces a sequential scan while the index
-- sits unused, which looks like the index not helping rather than like a typo.
--
-- The `regexp_replace` is load-bearing rather than cosmetic: PostgreSQL's text parser reads
-- `budget-forecast.xlsx` as a single indivisible `file` token, so a search for `budget` finds
-- nothing. Folding punctuation to spaces first is what makes a filename searchable by its parts.
--
-- `'simple'` and not a language configuration, deliberately: a stemmer has to assume a language,
-- and assuming wrongly fails silently — an English stemmer on German filenames simply stops
-- matching, with no error anywhere. `docs/14-I18N-L10N.md` has tenants in many languages, and one
-- guess for all of them is worse than no stemming for any.--
-- # One statement per file, and why
--
-- PostgreSQL wraps *multiple* statements sent in one round trip in an implicit transaction block,
-- so two `CONCURRENTLY` builds in one migration fail with `25001` — the same error as running
-- inside an explicit transaction, from a file that carefully opted out of one. That is why this
-- index and the `metadata_values` one are separate migrations rather than two statements here.


CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_files_name_fts
    ON files
    USING GIN (to_tsvector('simple', regexp_replace(name, '[^[:alnum:]]+', ' ', 'g')))
    WHERE deleted_at IS NULL;
