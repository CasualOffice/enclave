-- no-transaction
--
-- The second half of the lexical-search indexes: `metadata_values.value_text`.
--
-- Separate from `0012` only because PostgreSQL wraps multiple statements sent in one round trip in
-- an implicit transaction block, so two `CONCURRENTLY` builds in one file fail with `25001` — the
-- same error as running inside an explicit transaction, raised from a file that had carefully
-- opted out of one. One `CONCURRENTLY` per migration is the rule that follows.
--
-- The expression matches `crates/search/src/lexical.rs` exactly; see `0012` for why that identity
-- matters and why the configuration is `'simple'`.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_metadata_value_text_fts
    ON metadata_values
    USING GIN (to_tsvector('simple', regexp_replace(coalesce(value_text, ''), '[^[:alnum:]]+', ' ', 'g')));
