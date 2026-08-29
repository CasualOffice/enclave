-- 0031 — `retention_policies` and `retention_assignments`: the two tables `docs/04-DATA-MODEL.md
--   §13` has defined since the document was written and **no migration has ever created**.
--
-- `docs/04 §2`'s inventory lists five compliance tables. Not one of them existed. `files` carries
-- `is_record`, `on_legal_hold` and `purge_after` — three columns whose §8 note says they are
-- *"denormalized flags maintained transactionally with `legal_hold_items` / `records`"* — against
-- tables that were never built, so every one of them has been a `DEFAULT FALSE` nothing writes and
-- nothing reads. The whole compliance model was document-only, which is the shape
-- `plans/M4-GOVERNANCE.md` keeps meeting: a specification everybody cites and nobody applied.
--
-- **This migration creates two of the five, deliberately.** `legal_holds`, `legal_hold_items` and
-- `records` are a separate item with a separate argument — a hold is a *matter*, with custodians, a
-- release ceremony and an audit obligation that has nothing to do with a duration — and five tables
-- created at once for a feature that reads two is three tables nobody reviewed. `records` in
-- particular cannot be written honestly until `crates/db/src/retention.rs` can answer *which policy
-- declared this a record*, which is exactly what this pair is for.
--
-- # What the read is, because the schema is shaped for it and not for the writer
--
-- One question: **which policy governs this file?** `retention_assignments` scopes at `TENANT`,
-- `WORKSPACE`, `LIBRARY`, `CONTENT_TYPE` and `FILE`, so a single file is routinely covered several
-- times over and something has to decide which of them wins. The precedence is argued in
-- `crates/db/src/retention.rs` and is *not* "most specific wins"; the short form of the argument is
-- that most-specific-wins makes a tenant-wide "keep everything for seven years" switchable off by
-- anybody who can create a library-scoped policy, which is a compliance control with an off switch.
-- **The strictest policy wins**, and specificity only breaks ties between equals.
--
-- The schema's job is to make that ranking answerable in one statement: every scope a file can be
-- covered at is a column of the file's own row (`workspace_id`, `library_id`, `content_type_id`,
-- `id`), so the five scopes are five equality probes against one index and no recursion at all —
-- unlike the ACL walk, retention has no per-folder scope and therefore no chain to climb.
--
-- # Four departures from `§13`'s DDL, and one thing it asks for that PostgreSQL cannot do
--
-- `docs/README.md §1` makes `04` authoritative and this file the thing that must yield. Where it is
-- the other way round it is said out loud, and `docs/04 §13` should be corrected to match rather
-- than the code bent back to it. `ENC-940`.
--
--   1. **`PRIMARY KEY (tenant_id, id)` rather than `id UUID PRIMARY KEY, tenant_id UUID NOT NULL`.**
--      Not a redesign — it is `§13`'s own DDL brought up to `§1`'s rule and `CLAUDE.md` rule 4,
--      which require `tenant_id` first in the column list *and* leading the key. It is what `0021`,
--      `0022` and `0024` already do; `§13` predates them. The composite key on the parent is also
--      what makes `retention_assignments`' composite foreign key possible at all.
--
--   2. **`retention_assignments`' primary key is a unique *index*, because the documented one is not
--      legal SQL.** `§13` writes
--
--          PRIMARY KEY (tenant_id, policy_id, scope_type,
--                       COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid))
--
--      and PostgreSQL does not accept an expression in a primary key. The intent is right and is
--      preserved exactly: `scope_id` is NULL for `TENANT` scope, NULLs are distinct in a unique
--      constraint, and so the one scope where a duplicate is most likely is the one the plain
--      constraint would not constrain. `uq_retention_assignments_scope` below is that key, written
--      as `uq_files_sibling_name` (`0005`) and `uq_workflow_definitions_version` (`0024`) write
--      theirs. The table therefore declares no `PRIMARY KEY`; the unique index is the key, and it
--      leads with `tenant_id`, which is what rule 4 is about.
--
--   3. **Four `CHECK` constraints `§13` does not have, each removing a state that is storable today
--      and meaningless.** `0021`'s test, restated: *a column the evaluator cannot read is a promise*
--      — and the mirror of it, a combination the evaluator cannot act on is a policy that silently
--      does nothing.
--
--        * `duration` is required for `KEEP_THEN_DELETE` and `DELETE_AFTER`, and must be positive.
--          Both actions *are* a duration; without one there is no instant to compute and the policy
--          governs nothing while appearing in every administrative listing as though it did. A zero
--          or negative duration is worse than nothing: it reads as retention and computes a deadline
--          in the past.
--        * `event_key` is present exactly when `basis = 'EVENT'`, in both directions. An `EVENT`
--          basis with no key waits for an event nobody can name; a key on any other basis is a
--          column nothing will ever read.
--        * `action = 'RECORD'` implies `is_record`. The two are `§13`'s own redundancy — one fact
--          in two columns — and the state that must not exist is the contradiction, `RECORD` with
--          `is_record = FALSE`. The implication is one-directional on purpose: a `KEEP` policy that
--          also declares its files records is coherent and stays expressible.
--        * `allow_user_delete` is refused for `LEGAL_HOLD` and `RECORD`. A legal hold a user may
--          delete under is not a legal hold, and it is the single most dangerous row this table can
--          hold, because it reads as a control in every listing while permitting the exact act the
--          control exists to prevent.
--
--   4. **No `DELETE` for `enclave_app` on either table, and no `deleted_at`.** `§13` implies neither.
--      The argument is below, on the grants; the short form is that a retention policy is the record
--      of what a tenant committed to preserving, and `expires_at` on the *assignment* is the
--      documented way to stop applying one without destroying the evidence that it ever applied.
--
-- # What this migration deliberately does **not** touch
--
--   * **`files.retention_policy_id` is not added.** `docs/04 §8`'s `files` DDL does not have that
--     column — checked rather than assumed — so adding it would be inventing schema in the one
--     document that forbids it, and it would be a *second* mechanism beside `retention_assignments`
--     for the same question. Two places to say which policy governs a file is two answers that can
--     disagree, on the deletion path, which is the worst place in the product for an ambiguity.
--
--   * **`libraries.retention_policy_id` and `content_types.retention_policy_id` are left as they
--     are** — both already exist (`0004_content_and_acl.sql`) and both are dangling untyped UUIDs
--     with no foreign key, because until this migration there was no table for them to reference.
--     They are *not* given composite keys here and they are *not* read by `retention.rs`. Adding a
--     key to a column no read path consults would bless a second mechanism by making it look
--     enforced. Whether those columns should be dropped in favour of `LIBRARY`- and
--     `CONTENT_TYPE`-scoped assignments, or the assignments dropped in favour of them, is a design
--     question with an owner and a tracker row; it is not a decision to take silently inside the
--     migration that first makes the conflict visible. See `ENC-940` and this file's report.
--
-- # `CREATE INDEX`, not `CONCURRENTLY`
--
-- `ENC-517`; `0012`, `0017`, `0022`, `0023`, `0028` and `0029` carry the full account. sqlx runs each
-- migration inside one transaction and `CONCURRENTLY` cannot run inside one. Both tables are new
-- and empty, so there is nothing to lock anybody out of.
--
-- Forward-only: a new migration, never an edit to an applied one.

-- =================================================================================================
-- retention_policies — what a tenant has committed to preserving, and for how long.
-- =================================================================================================

CREATE TABLE IF NOT EXISTS retention_policies (
    -- `tenant_id` first, and first in the primary key (docs/04 §1, CLAUDE.md rule 4). Never taken
    -- from a request (rule 3): it comes from the verified token by way of `TenantScoped`.
    tenant_id         UUID NOT NULL REFERENCES tenants (id),
    id                UUID NOT NULL,

    -- The administrator-facing name. Bounded like `workflow_definitions.name` (`0024`) — an
    -- unbounded TEXT in an admin listing is a rendering problem waiting for its first paste.
    name              TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),

    -- The vocabulary verbatim from docs/04 §13. Ranked — not ordered alphabetically, and not
    -- ordered by specificity — in `crates/db/src/retention.rs`'s `GOVERNING_SQL`, where
    -- LEGAL_HOLD > RECORD > KEEP > KEEP_THEN_DELETE > DELETE_AFTER by how much each preserves.
    action            TEXT NOT NULL CHECK (action IN
                          ('KEEP','KEEP_THEN_DELETE','DELETE_AFTER','RECORD','LEGAL_HOLD')),

    -- How long, as an INTERVAL and deliberately not as a count of seconds.
    --
    -- `timestamptz + interval '7 years'` is calendar arithmetic: it lands on the same day of the
    -- same month seven years later, across every leap day and every DST transition in between.
    -- `EXTRACT(EPOCH FROM interval '7 years')` is 220898664 seconds — a 365.25-day year — and adding
    -- *that* lands somewhere else entirely. A retention deadline that is a day or two out is a
    -- document destroyed a day before it was allowed to be, so the column stays an INTERVAL, the
    -- arithmetic stays in PostgreSQL, and `retention.rs` carries the value across the boundary
    -- without ever flattening it. See that module's note on `PgInterval`.
    duration          INTERVAL,

    -- Which instant `duration` is measured from. Vocabulary verbatim from §13.
    basis             TEXT NOT NULL CHECK (basis IN
                          ('CREATED','MODIFIED','LAST_ACCESSED','EVENT','DECLARED_RECORD')),

    -- The event `basis = 'EVENT'` waits for. Tied to the basis in both directions below.
    event_key         TEXT,

    -- Whether files governed by this policy are records — immutable, undeletable, and out of the
    -- ordinary lifecycle. Tied to `action = 'RECORD'` one-directionally below.
    is_record         BOOLEAN NOT NULL DEFAULT FALSE,

    -- Whether a user may still delete a governed file themselves. FALSE by default, which is the
    -- safe half: a policy written by a repair script that forgot the column retains rather than
    -- releases. Refused outright for LEGAL_HOLD and RECORD below.
    allow_user_delete BOOLEAN NOT NULL DEFAULT FALSE,

    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, id),

    -- Named table constraints rather than inline column checks, so the violation an administrator
    -- meets in a log line names itself instead of reading `retention_policies_check1`.

    -- KEEP_THEN_DELETE and DELETE_AFTER *are* a duration. Without one there is no deadline to
    -- compute, and the policy appears in every listing while governing nothing.
    CONSTRAINT retention_policies_duration_required
        CHECK (action NOT IN ('KEEP_THEN_DELETE','DELETE_AFTER') OR duration IS NOT NULL),

    -- A zero or negative retention period reads as retention and computes a deadline that has
    -- already passed, which is a delete-immediately rule wearing a compliance control's name.
    CONSTRAINT retention_policies_duration_positive
        CHECK (duration IS NULL OR duration > INTERVAL '0'),

    -- Both directions. An EVENT basis with no key waits for an event nobody can name; a key on any
    -- other basis is a column no evaluator reads.
    CONSTRAINT retention_policies_event_basis
        CHECK ((basis = 'EVENT') = (event_key IS NOT NULL)),

    -- One-directional: RECORD implies is_record, and a KEEP policy that also declares records stays
    -- expressible. What this forbids is the contradiction — RECORD with is_record FALSE — which is
    -- a row where the two columns holding one fact disagree.
    CONSTRAINT retention_policies_record_flag
        CHECK (action <> 'RECORD' OR is_record),

    -- The most dangerous row this table could hold: a control that reads as absolute in every
    -- listing and permits exactly the act it exists to prevent.
    CONSTRAINT retention_policies_hold_is_absolute
        CHECK (NOT allow_user_delete OR action NOT IN ('LEGAL_HOLD','RECORD'))
);

COMMENT ON TABLE retention_policies IS
    'What a tenant has committed to preserving and for how long (docs/04 §13, ENC-940). Specified since the document was written and created by no migration until 0031. Applied to content through retention_assignments; a policy with no assignment governs nothing.';

COMMENT ON COLUMN retention_policies.duration IS
    'An INTERVAL, never a count of seconds. timestamptz + interval ''7 years'' is calendar arithmetic; EXTRACT(EPOCH FROM …) assumes a 365.25-day year and lands on a different day. A deadline a day early is a document destroyed a day before it was permitted to be.';

COMMENT ON COLUMN retention_policies.allow_user_delete IS
    'Refused for LEGAL_HOLD and RECORD by retention_policies_hold_is_absolute: a hold a user may delete under is not a hold, and it would read as a control in every administrative listing.';

-- =================================================================================================
-- retention_assignments — where a policy applies. The table the governing read is driven from.
-- =================================================================================================

CREATE TABLE IF NOT EXISTS retention_assignments (
    tenant_id  UUID NOT NULL REFERENCES tenants (id),

    -- Which policy. Composite key, so another tenant's policy cannot be applied to this tenant's
    -- content: PostgreSQL runs referential-integrity checks with row security deliberately not
    -- enforced (docs/04 §3.3), so a single-column `REFERENCES retention_policies (id)` would accept
    -- one — and a cross-tenant retention assignment is a tenant governing another tenant's deletion
    -- path.
    policy_id  UUID NOT NULL,

    -- Where it applies. Five scopes, and each one is a column of the covered file's own row —
    -- which is what makes the governing read five equality probes rather than a recursive walk.
    scope_type TEXT NOT NULL CHECK (scope_type IN
                   ('TENANT','WORKSPACE','LIBRARY','CONTENT_TYPE','FILE')),

    -- The workspace, library, content type or file the scope names, and NULL exactly when the scope
    -- is the tenant.
    --
    -- **No foreign key, and the absence is stated rather than left to be discovered** (`ENC-502`'s
    -- lesson, and `content_types.scope_id` in `0004` before it): the referent depends on
    -- `scope_type`, so one key would have to point at four tables. `retention.rs` resolves it by
    -- comparing against the target file's own `workspace_id` / `library_id` / `content_type_id` /
    -- `id`, which is a comparison rather than a lookup — a `scope_id` naming something that does not
    -- exist matches no file and therefore governs nothing. It fails closed, which for a *retention*
    -- control means it fails towards not-preserving, so `crates/db/tests/retention.rs` proves the
    -- positive case for every scope rather than only the negatives.
    scope_id   UUID,

    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- When the assignment stops applying. NULL means indefinitely.
    --
    -- This, and not a `DELETE`, is how an assignment is withdrawn — see the grants. That is why the
    -- governing read filters on it and why `crates/db/tests/retention.rs` asserts an expired
    -- assignment is not found: with no `DELETE` granted, an unfiltered read would make withdrawal
    -- impossible rather than merely undocumented.
    expires_at TIMESTAMPTZ,

    CONSTRAINT retention_assignments_scope_target
        CHECK ((scope_type = 'TENANT') = (scope_id IS NULL)),

    -- An expiry before the application is an assignment edited to look as though it never applied.
    -- Ending one *now* is `expires_at = now()`, which is still after `applied_at`, so the ordinary
    -- withdrawal is unaffected.
    CONSTRAINT retention_assignments_expiry_after_application
        CHECK (expires_at IS NULL OR expires_at > applied_at),

    CONSTRAINT retention_assignments_policy_fkey
        FOREIGN KEY (tenant_id, policy_id) REFERENCES retention_policies (tenant_id, id)
);

-- `docs/04 §13`'s primary key, written as a unique index because a primary key may not contain an
-- expression. See departure 2 in the header. `COALESCE` because `scope_id` is NULL for every
-- `TENANT`-scoped row and NULLs are distinct in a unique constraint — so without it, the one scope
-- where a duplicate assignment is most likely is the one scope that would go unconstrained.
CREATE UNIQUE INDEX IF NOT EXISTS uq_retention_assignments_scope
    ON retention_assignments (
        tenant_id,
        policy_id,
        scope_type,
        COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- The governing read's index, and the only one it needs.
--
-- `GOVERNING_SQL` probes this five times per file — once per scope — with `scope_type` and
-- `scope_id` both equated, so each probe is a range scan of the handful of assignments at that
-- scope. Ordering the columns the other way round (`scope_id, scope_type`) would serve the same
-- probes and nothing else; this way round it also serves an administrator's "what applies at
-- library scope in this tenant", which is the only other question the table gets asked.
--
-- Deliberately **not** partial on `expires_at`: a predicate would have to name `now()`, which is not
-- immutable and which PostgreSQL refuses in an index predicate. Expiry is filtered in the query.
CREATE INDEX IF NOT EXISTS idx_retention_assignments_scope
    ON retention_assignments (tenant_id, scope_type, scope_id);

COMMENT ON TABLE retention_assignments IS
    'Where a retention policy applies (docs/04 §13, ENC-940). A file is routinely covered at several scopes at once; crates/db/src/retention.rs decides which wins, and the rule is strictest-first rather than most-specific-first — see that module. Withdrawn by setting expires_at, never by DELETE.';

COMMENT ON COLUMN retention_assignments.scope_id IS
    'The workspace, library, content type or file the scope names; NULL exactly for TENANT scope. Deliberately carries no foreign key: the referent depends on scope_type. It is resolved by comparison against the target file''s own columns, which fails closed — and for a retention control, failing closed means failing towards not preserving, so every scope has a positive test.';

COMMENT ON COLUMN retention_assignments.expires_at IS
    'When the assignment stops applying; NULL is indefinite. This is the withdrawal mechanism: enclave_app holds no DELETE, so an unfiltered read would make an assignment impossible to undo rather than merely permanent.';

-- =================================================================================================
-- Row-level security. `CLAUDE.md` rule 4; `crates/db/tests/rls_coverage.rs` fails the build without
-- all three of enabled, forced and a policy.
--
-- `FORCE` earns its place here in a particular way. A retention policy is the shape of a tenant's
-- legal obligations — how long they keep contracts, whether they declare records, which matters
-- they are preserving for — and `docs/06 §15` treats that as sensitive in itself, which is why a
-- retention refusal is the *last* stage in the chain and why it never explains itself to a caller
-- who failed an earlier one. A `psql` session as the table owner without `FORCE` would be every
-- tenant's compliance posture in one `SELECT`.
-- =================================================================================================

ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policies FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON retention_policies
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE retention_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_assignments FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON retention_assignments
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- =================================================================================================
-- Grants. Migration 0003's catalog loop has already run and will not run again, so a table created
-- after it and not granted here is one the application role cannot see at all — which is how, before
-- `ENC-124`, every isolation test in the workspace passed with isolation switched off.
--
-- **`SELECT`, `INSERT`, `UPDATE`; no `DELETE`.** `0028` argued its way to `DELETE` and `0029`
-- declined it for reasons specific to that table; here the answer is the strongest form of no in the
-- schema, for three reasons of this table's own:
--
--   * **A retention policy is the record of a commitment.** Deleting the row makes every past
--     decision taken under it unexplainable: an audit row saying *refused, policy 7f3a…* resolves to
--     nothing, and "we destroyed that document because a policy told us to" stops being a checkable
--     statement. That is the one property a retention system exists to have.
--   * **Withdrawal already has a mechanism, and it keeps the history.** `expires_at` on the
--     assignment stops the policy applying from an instant that is itself recorded. `DELETE` would
--     be a second way to do the same thing that leaves no trace it was ever done — and, being
--     easier, the one that gets used.
--   * **The deletion path must not be able to erase its own governor.** Everything that reaches
--     these tables is on the path that destroys content. A verb that lets that path remove the row
--     refusing it is the one verb worth withholding, and withholding it in the *schema* means it is
--     not reachable by a bug, a repair script, or an endpoint added later without this argument.
--
-- `UPDATE` is granted: an administrator renames a policy, and sets `expires_at` to withdraw an
-- assignment. That is a real weakening compared with append-only, and it is the deliberate line —
-- an `UPDATE` leaves the row and its identity in place for an audit row to resolve against, which
-- is the property the three reasons above are all about. Narrowing it further (column grants, or a
-- trigger refusing changes to `action` and `duration`) belongs with the admin endpoints that write
-- these tables, where there is something concrete to constrain.
-- =================================================================================================

GRANT SELECT, INSERT, UPDATE ON retention_policies    TO enclave_app;
GRANT SELECT, INSERT, UPDATE ON retention_assignments TO enclave_app;

-- Asserted at apply time in the shape `0002`, `0025`, `0026`, `0028` and `0029` use, because every
-- statement above is one a typo turns into a silent no-op: a misspelt role name in a `GRANT`
-- succeeds, `ENABLE ROW LEVEL SECURITY` on a table with no policy denies everything rather than
-- isolating anything, and a `CREATE INDEX` on the wrong column list is an index the planner will
-- not use. The structural gates in `crates/db/tests/` catch the first two on a fresh database; this
-- catches all of them on the deployment being migrated, at the moment of migrating it, before
-- anything writes a row.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['retention_policies', 'retention_assignments'] LOOP
        IF NOT has_table_privilege('enclave_app', t, 'SELECT')
           OR NOT has_table_privilege('enclave_app', t, 'INSERT')
           OR NOT has_table_privilege('enclave_app', t, 'UPDATE') THEN
            RAISE EXCEPTION
                'enclave_app is missing SELECT, INSERT or UPDATE on %: the retention stage would refuse every deletion with permission denied, which fails closed but for the wrong reason and with an unreadable message', t;
        END IF;

        IF has_table_privilege('enclave_app', t, 'DELETE') THEN
            RAISE EXCEPTION
                'enclave_app holds DELETE on %; withdrawal is expires_at on the assignment, and a deletion path that can remove the row governing it leaves an audit trail that resolves to nothing', t;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = t
              AND c.relrowsecurity AND c.relforcerowsecurity
        ) THEN
            RAISE EXCEPTION
                '% does not have row-level security both enabled and forced (CLAUDE.md rule 4)', t;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policy p
            WHERE p.polrelid = ('public.' || t)::regclass AND p.polname = 'tenant_isolation'
        ) THEN
            RAISE EXCEPTION
                '% has row-level security on with no tenant_isolation policy, which denies every row rather than isolating them', t;
        END IF;
    END LOOP;

    -- The composite key, asserted by shape rather than by name: a single-column
    -- `REFERENCES retention_policies (id)` would let one tenant's policy govern another tenant's
    -- content, and referential-integrity checks run with row security deliberately not enforced.
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_constraint con
        JOIN pg_catalog.pg_class src ON src.oid = con.conrelid
        WHERE con.contype = 'f'
          AND src.relname = 'retention_assignments'
          AND array_length(con.conkey, 1) = 2
          AND EXISTS (
              SELECT 1 FROM pg_catalog.pg_attribute a
              WHERE a.attrelid = con.conrelid AND a.attnum = ANY (con.conkey)
                AND a.attname = 'tenant_id')
    ) THEN
        RAISE EXCEPTION
            'retention_assignments has no two-column foreign key including tenant_id; one tenant''s retention policy could then be assigned to another tenant''s content (CLAUDE.md rule 4, docs/04 §3.3)';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'uq_retention_assignments_scope'
    ) THEN
        RAISE EXCEPTION
            'uq_retention_assignments_scope is missing; docs/04 §13''s primary key would be unenforced and one policy could be assigned to one scope twice over';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'idx_retention_assignments_scope'
    ) THEN
        RAISE EXCEPTION
            'idx_retention_assignments_scope is missing; the governing read runs on the deletion path of every file and would scan the tenant''s whole assignment set five times per file';
    END IF;
END
$$;
