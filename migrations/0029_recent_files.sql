-- 0029 — `recent_files`: the read model behind `GET /api/v1/me/recent`, and the reason that
--   endpoint is not a query over `audit_events`.
--
-- `web/design-system/specs/home.md` names the requirement in its own backend list — *"Read model
-- for recents — must NOT be derived from audit_events, which is hash-chained and deliberately not
-- a user-facing feed"* — and `CLAUDE.md` rule 10 is why. Three separate things go wrong if the
-- home screen reads the audit trail, and only the first is obvious:
--
--   * **It is a security record, not a product surface.** `audit_events` holds denials as well as
--     allows, actor and target for principals a viewer may not know exist, and rows written by the
--     policy engine on paths the viewer was refused. A `SELECT … WHERE actor_id = me` over it
--     hands a user a list of the things they were told they could not see.
--   * **It is append-only and hash-chained** (`0001_foundations.sql`, `0002_rls_policies.sql`).
--     `enclave_app` holds `INSERT` and nothing else on it, deliberately, so there is no `UPDATE`
--     that could collapse forty opens of one document into the one row a "recent" list wants. The
--     feed would be a `DISTINCT ON` over an unbounded, partitioned, ever-growing table — the most
--     expensive query in the product, on the screen that loads first.
--   * **It would make the audit trail load-bearing for a feature**, which is the thing that makes
--     people relax its retention. A trail somebody's home screen depends on is a trail that gets
--     trimmed when the home screen gets slow.
--
-- # A *last seen* fact, not a log
--
-- One row per `(tenant, user, file)`, upserted. This is the whole shape decision and it is what
-- separates this table from the one it must not be:
--
--   * **A log** — one row per open — is what `audit_events` already is, and a second copy of it
--     would grow without bound for a surface that shows eight rows. Answering "the most recent
--     eight" from a log means `DISTINCT ON (file_id) … ORDER BY file_id, at DESC` and then a second
--     sort, over rows that outnumber the answer by whatever the retention window allows.
--   * **A last-seen fact** is bounded by the tenant's own content: at most one row per file a user
--     has actually opened, so the table cannot exceed users × files and shrinks with both. The
--     read is then a plain ordered range scan with no de-duplication step at all.
--
-- The cost is stated rather than hidden: **this table cannot answer "how often" or "when else".**
-- It holds one instant and overwrites it. That question is `audit_events`', it is answered there
-- with a chain nobody can rewrite, and the whole point of this file is that the two are different
-- tables with different guarantees rather than one table asked to be both.
--
-- # `ON CONFLICT … GREATEST(…)`, and why the upsert is not a plain assignment
--
-- The writing statement lives in `crates/db/src/recent.rs`; what this schema is *shaped for* is:
--
--     INSERT … VALUES ($1, $2, $3, now())
--     ON CONFLICT (tenant_id, user_id, file_id)
--     DO UPDATE SET last_accessed_at = GREATEST(recent_files.last_accessed_at, EXCLUDED.last_accessed_at)
--
-- `GREATEST` rather than `= EXCLUDED.last_accessed_at`, because `now()` is
-- `transaction_timestamp()` — fixed when a transaction *begins*, not when its statements run. Two
-- overlapping transactions therefore commit in the opposite order to the instants they carry, and a
-- plain assignment lets the one that began earlier and committed later write an **older** time over
-- a newer one. Recency then goes backwards for a user who did nothing but open two documents
-- quickly, which is a bug that only appears under load and looks like a caching problem when it
-- does. `GREATEST` makes the column monotonic by construction and costs one comparison.
--
-- And `now()` rather than an instant supplied by the caller: `crates/worker/src/invalidation.rs`'s
-- finding, restated once more. Ordering is only meaningful if every row in the column was stamped
-- by the same clock, and an API replica running a few seconds ahead would otherwise pin its own
-- writes to the top of every user's list for as long as the skew lasted.
--
-- # The index the read actually needs
--
-- The primary key is `(tenant_id, user_id, file_id)`, which serves the *write* — the conflict
-- target — and nothing else. The read is "this user's most recent N in this tenant", and a
-- b-tree ordered by `file_id` third cannot answer it without reading every row this user has and
-- sorting them. `idx_recent_files_by_recency` below is `(tenant_id, user_id, last_accessed_at DESC,
-- file_id DESC)`, which is the `ORDER BY` of the reading statement verbatim, so the query is an
-- index range scan that stops at the limit.
--
-- `file_id DESC` is in the index because it is in the `ORDER BY`, and it is in the `ORDER BY`
-- because two opens can share a microsecond: without a tiebreak the order of tied rows is whatever
-- the plan happens to produce, which makes the list flicker between two refreshes and makes a test
-- that asserts an order flaky rather than wrong.
--
-- # `tenant_id` first, and what it does not do on its own
--
-- `CLAUDE.md` rule 4 in full: `tenant_id` leads the primary key, RLS is enabled and forced, and
-- both foreign keys are composite. But note what tenancy cannot hold here, exactly as
-- `0028_print_tokens.sql` had to note it — **a recency list belongs to one user, and a colleague in
-- the same tenant is not that user.** Row-level security is blind to that; only the `user_id`
-- predicate in the reading statement refuses it. The suite in `crates/db/tests/recent.rs` therefore
-- proves the same-tenant case beside the cross-tenant one, because RLS would have refused the
-- second on its own.
--
-- # `enclave_app` gets `SELECT`, `INSERT` and `UPDATE`, and deliberately not `DELETE`
--
-- `0018`–`0023` mostly withheld `DELETE` and `0028` argued its way to it; the question is answered
-- the other way here, for a reason specific to this table rather than by default:
--
--   * **Nothing has to sweep it.** A print token accumulates one row per print for ever and needs a
--     reaper; a last-seen fact is idempotent in the row count, so the table has no growth curve of
--     its own to prune.
--   * **Both parents already reclaim.** `ON DELETE CASCADE` on the composite keys means a purged
--     file and a deprovisioned user take their rows with them, executed by the database rather than
--     by a job that could be switched off.
--   * **A "clear my recents" request does not exist.** `docs/05-API.md` registers `GET
--     /me/recent` and no counterpart, and `home.md` specifies no such control. Granting a verb
--     ahead of the endpoint that needs it means the verb is unreviewed on the day it is first used.
--     When that request is specified it gets its own migration and its own argument.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `0012`, `0017`, `0022`, `0023` and `0028` carry the full account. sqlx runs each
-- migration in one transaction and `CONCURRENTLY` cannot run inside one. The table is new and empty.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS recent_files (
    -- `tenant_id` first, and first in the primary key (docs/04 §1). Never taken from a request
    -- (`CLAUDE.md` rule 3) — it comes from the verified access token by way of `TenantScoped`.
    tenant_id        UUID NOT NULL REFERENCES tenants (id),

    -- Whose list this is. Composite key to `users`, so another tenant's user cannot be named:
    -- PostgreSQL runs referential-integrity checks with row security deliberately not enforced, so
    -- a single-column `REFERENCES users (id)` would accept one (docs/04 §3.3).
    --
    -- Only a `UserId`, and not the polymorphic `actor_type`/`actor_id` pair `print_tokens` carries.
    -- The surface is `GET /me/recent` on a screen a person is looking at; a service account and an
    -- MCP client have no home screen, and giving them rows here would mean a table storing what
    -- automation touched — which is `audit_events`' question, asked in the place this file exists to
    -- keep separate from it. A composite key to `users` is also stronger than a `CHECK` over an
    -- actor vocabulary could be.
    user_id          UUID NOT NULL,

    -- Which document. `ON DELETE CASCADE` because a recency row for a purged file is a row nothing
    -- can render: the reading statement joins `files` and would drop it anyway, so keeping it would
    -- only mean carrying rows that can never appear in an answer.
    file_id          UUID NOT NULL,

    -- The one fact this table holds. Monotonic by construction — see the header on `GREATEST` — and
    -- always PostgreSQL's clock, never a caller's.
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, user_id, file_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id) ON DELETE CASCADE
);

COMMENT ON TABLE recent_files IS
    'Per-user last-seen facts backing GET /api/v1/me/recent (web/design-system/specs/home.md). One row per (tenant, user, file), upserted. Explicitly NOT derived from audit_events, which is hash-chained and is not a user-facing feed (CLAUDE.md rule 10). It cannot answer how often or when else; that is audit_events'' question.';

COMMENT ON COLUMN recent_files.last_accessed_at IS
    'PostgreSQL now(), never a caller clock, and written with GREATEST(existing, incoming) so an earlier transaction committing later cannot move a user''s recency backwards.';

-- The reading statement's `ORDER BY`, verbatim. See the header: the primary key serves the conflict
-- target and cannot serve this, because it orders by `file_id` where the read orders by time.
CREATE INDEX IF NOT EXISTS idx_recent_files_by_recency
    ON recent_files (tenant_id, user_id, last_accessed_at DESC, file_id DESC);

-- -------------------------------------------------------------------------------------------------
-- Row-level security. `CLAUDE.md` rule 4, and `crates/db/tests/rls_coverage.rs` fails the build
-- without all three of enabled, forced and a policy.
--
-- `FORCE` is the half that matters, and it matters here in a particular way: every row is a
-- statement about what one named person opened and when. A `psql` session as the table's owner
-- without `FORCE` would be a cross-tenant reading history in one `SELECT` — not file content, but a
-- fact about content and about people, which is the pair `docs/06 §5` treats as one.
-- -------------------------------------------------------------------------------------------------

ALTER TABLE recent_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE recent_files FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON recent_files
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- -------------------------------------------------------------------------------------------------
-- Grants. Migration 0003's catalog loop has already run and will not run again, so a table created
-- after it and not granted here is one the application role cannot see at all — which is how, before
-- `ENC-124`, every isolation test in the workspace passed with isolation switched off.
--
-- `UPDATE` is the `DO UPDATE` arm of the upsert and nothing else. `DELETE` is withheld; the header
-- says why, and the assertion below is what keeps that a decision rather than a comment.
-- -------------------------------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON recent_files TO enclave_app;

-- Asserted at apply time in the shape `0002`, `0025` and `0026` use, because every statement above
-- is one a typo turns into a silent no-op: a misspelt role name in a `GRANT` succeeds, `ENABLE ROW
-- LEVEL SECURITY` on a table with no policy is a table that denies everything, and a `CREATE INDEX`
-- on the wrong column list is an index the planner will not use. The structural gates in
-- `crates/db/tests/` catch the first two on a fresh database; this catches all four on the
-- deployment being migrated, at the moment of migrating it, before anything writes a row.
DO $$
BEGIN
    IF NOT has_table_privilege('enclave_app', 'recent_files', 'SELECT')
       OR NOT has_table_privilege('enclave_app', 'recent_files', 'INSERT')
       OR NOT has_table_privilege('enclave_app', 'recent_files', 'UPDATE') THEN
        RAISE EXCEPTION
            'enclave_app is missing SELECT, INSERT or UPDATE on recent_files: GET /me/recent and every touch that feeds it will fail with permission denied';
    END IF;

    IF has_table_privilege('enclave_app', 'recent_files', 'DELETE') THEN
        RAISE EXCEPTION
            'enclave_app holds DELETE on recent_files; the cascades reclaim rows and no endpoint clears a recency list, so this verb is unreviewed';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'recent_files'
          AND c.relrowsecurity AND c.relforcerowsecurity
    ) THEN
        RAISE EXCEPTION
            'recent_files does not have row-level security both enabled and forced (CLAUDE.md rule 4)';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policy p
        WHERE p.polrelid = 'public.recent_files'::regclass AND p.polname = 'tenant_isolation'
    ) THEN
        RAISE EXCEPTION
            'recent_files has row-level security on with no tenant_isolation policy, which denies every row rather than isolating them';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'idx_recent_files_by_recency'
    ) THEN
        RAISE EXCEPTION
            'idx_recent_files_by_recency is missing; the recency read would sort every row a user has ever opened on the screen that loads first';
    END IF;
END
$$;
