-- `retrieval_denylist`: the two columns that let a row say whether the index has caught up.
-- docs/04-DATA-MODEL.md §15.
--
-- # What was wrong, and it was not a missing feature
--
-- `migrations/0011_search.sql` documents `clears_at` as "when the suppression may be lifted, once
-- the index is known to have caught up". Nothing in the schema could answer the second half, and
-- the four reasons are worth writing down because each of them is a proxy somebody would otherwise
-- reach for:
--
-- 1. **A denylist row carried no reference to an index write.** It recorded that a file was
--    suppressed and when, and nothing about the thing whose completion would make the suppression
--    pointless.
-- 2. **`index_manifests.acl_epoch` is the wrong fact.** It is `files.acl_revision` at the time of
--    the last index *write*, so it answers "have the ACL tokens in the store been rewritten" — not
--    "have this file's chunks been removed from the store". A revocation that suppresses a file and
--    a metadata rewrite that refreshes its tokens are different events; reading one as the other is
--    how a file stays in the index while the schema says it left.
-- 3. **A manifest join cannot tell "caught up" from "never indexed".** A suppressed file may have
--    no `index_manifests` row at all — it was never indexed, its library has AI indexing off, its
--    classification is `NO_INDEX`. `LEFT JOIN … WHERE m.file_id IS NULL` returns exactly the same
--    shape for "the index removed it" and "the index never had it", and only one of those is a fact
--    about a write having happened.
-- 4. **A NULL `clears_at` is the case where nobody has asserted anything.** Reading it as "not
--    caught up" is a guess in the safe direction, but it is still a guess, and it makes "unknown"
--    unrepresentable — which is the state that actually holds for every row in a deployment whose
--    index writer has never run.
--
-- # What these columns do and do not claim
--
-- `suppression_seq` is a per-row generation counter, bumped by every `suppress` (including the
-- re-suppression of an already-suppressed file). `indexed_seq` is the generation that the last
-- **confirmed** vector-store write covered, written by the code that performed that write, from the
-- value it read *before* it started. So:
--
--     indexed_seq IS NULL                    nobody has asserted anything — unknown, not "no"
--     indexed_seq <  suppression_seq         a write is confirmed; a later suppression is not
--     indexed_seq >= suppression_seq         a write covering this suppression is confirmed
--
-- Three states, and the first one is distinct from the other two. That is the whole point: the
-- honest answer to "has the index caught up" in this tree is *unknown*, because nothing writes
-- `indexed_seq` yet, and a signal that cannot say so is a signal that reads as "yes".
--
-- **It is a counter and not a timestamp on purpose.** `added_at` is supplied by the caller, from an
-- application clock; a confirmation written by a different process would be a second clock. Two
-- clocks compared against each other is exactly the latent bug `crates/search/src/denylist.rs`
-- records in `lift_expired` — a worker running seconds fast lifting a suppression the database
-- still considers in force. A counter read from the row and written back to it has no clock in it
-- at all.
--
-- **It is an assertion, not a verification.** `indexed_seq >= suppression_seq` says a writer
-- claimed to have removed this file's chunks. PostgreSQL cannot confirm that against Milvus, and
-- nothing here pretends otherwise. Which is fine, because nothing depends on it:
--
-- # Nothing lifts on this, and nothing on the search path reads it
--
-- The sweep (`crates/worker/src/invalidation.rs`) still lifts on `clears_at` alone, and
-- `denylist::suppressed` — the read every search makes — still consults `clears_at` alone. If
-- lifting were conditional on a confirmation, then S4 (`docs/12-TESTING.md §4.3`: a stopped
-- invalidation worker changes nothing a caller can observe) would start passing because a writer
-- ran, rather than because the denylist write sits inside the ACL transaction. That is the failure
-- `plans/M3-DISCOVERY.md` D22 and `crates/worker/src/epoch.rs` are both arranged against, and it is
-- asserted by tests over the SQL text in `crates/search/src/denylist.rs`.
--
-- There is deliberately no per-file "is this file's index current?" accessor either
-- (`ENC-518`, refusal 1): the reader offered here counts a tenant's rows by state and cannot answer
-- for one file, because a predicate shaped like that is the one a search eventually calls to skip
-- work.
--
-- # Locking
--
-- `ADD COLUMN … DEFAULT` does not rewrite the table on PostgreSQL 11+; the default is recorded in
-- the catalog and materialised on write. The `ACCESS EXCLUSIVE` lock is held for the catalog update
-- only. No index is created here, so `ENC-517`'s deadlock — `CREATE INDEX CONCURRENTLY` against the
-- test harness's session-level setup lock — has nothing to reintroduce. The catch-up reader
-- aggregates over the primary key's tenant prefix and needs no index of its own.
--
-- Forward-only: a new migration, never an edit to 0011.

ALTER TABLE retrieval_denylist
    -- Bumped by every suppression of this file. Starts at 1 so that "never suppressed" is not a
    -- value this column can hold: a row exists only because a suppression happened.
    ADD COLUMN IF NOT EXISTS suppression_seq BIGINT NOT NULL DEFAULT 1,
    -- The suppression generation a confirmed vector-store write covered. NULL means unknown.
    ADD COLUMN IF NOT EXISTS indexed_seq     BIGINT;

-- A confirmation can only ever name a generation the writer read from this row, so one that runs
-- ahead of `suppression_seq` is a bug in the writer — a confirmation fabricated rather than
-- observed. Refused here rather than stored, because the stored form of that bug reads as
-- "caught up" forever.
ALTER TABLE retrieval_denylist
    DROP CONSTRAINT IF EXISTS retrieval_denylist_indexed_seq_bounded;
ALTER TABLE retrieval_denylist
    ADD CONSTRAINT retrieval_denylist_indexed_seq_bounded
        CHECK (indexed_seq IS NULL OR indexed_seq <= suppression_seq);

-- RLS, the `tenant_isolation` policy and the `enclave_app` grants are properties of the table and
-- were established in 0011. Both are table-level, so they cover these columns; no re-grant is
-- needed and adding one would suggest otherwise.
