-- 0018 — `storage_quotas`: the per-tenant stored-byte quota — docs/04-DATA-MODEL.md §16.1.
--
-- `ENC-584`, `plans/M4-GOVERNANCE.md` D31 and the answer to Q18: **storage bytes, per tenant**, one
-- number, reconciled nightly. The enforcement shape is the share-link download counter's
-- (`migrations/0008`): the limit is in the `WHERE` clause of the charging `UPDATE`, a zero-row
-- result is the refusal, and a `CHECK` is the backstop that turns a mistake in that statement into
-- a failed transaction rather than an exceeded quota.
--
-- # Why this is one table and not `docs/04 §16`'s `quotas` + `quota_usage` pair
--
-- §16 models a limit for any `(scope, kind)` and its usage as two tables. That split is right for
-- the kinds it was drawn for — the rate kinds are counted in Redis and flushed, and a rate kind has
-- one usage row *per period* against one limit row, which is precisely what a second table is for.
--
-- It is wrong for the one kind D31 governs, and for a reason PostgreSQL decides rather than taste:
-- **a `CHECK` constraint cannot reference another table.** With the limit in `quotas` and the
-- counter in `quota_usage` there is no `CHECK (used <= limit)` to write, and D31's backstop becomes
-- a trigger doing a lookup on every charge, or nothing. `STORAGE_BYTES` at `TENANT` scope is
-- exactly one row per tenant with no periods, so putting the limit and the counter in one row costs
-- nothing and buys the constraint the decision asks for.
--
-- §16.1 in the document records this and the boundary: the pair stays the model for the kinds that
-- are not enforced in-statement, and neither table is created here because nothing uses one yet.
--
-- # The four columns that are not obvious
--
--   * `used_bytes` — the counter. Moved **only** by relative expressions (`used_bytes + $n`,
--     `GREATEST(used_bytes - $n, 0)`, `GREATEST(used_bytes + $drift, 0)`). Nothing ever assigns it
--     an absolute figure, which is what makes the nightly reconciliation windowless; see below.
--   * `overshoot_bytes` — how far above `limit_bytes` this row has been *explicitly* allowed to
--     sit. Zero normally. A tenant can be genuinely over its limit — its plan was downgraded, or
--     reconciliation found real bytes the counter had missed — and a `CHECK (used <= limit)` with
--     no escape would make recording that truth impossible: the nightly job would fail on that
--     tenant every night, forever, leaving the figure it could not write as the one nobody sees.
--     So the constraint is `used_bytes <= limit_bytes + overshoot_bytes`, and the only statements
--     that raise `overshoot_bytes` are the ones that deliberately record an over-limit state
--     (reconciliation, and a limit change) — never the charging statement. A charge that escaped
--     its `WHERE` clause still aborts, which is the property D31 asks the backstop for.
--     **`overshoot_bytes` is not headroom.** The charging statement bounds itself by `limit_bytes`
--     alone, so a tenant carrying an overshoot is refused, not granted extra room.
--   * `enforcement` — `MONITOR` counts, `WARN` counts and notifies, `BLOCK` counts, notifies and
--     refuses. `plans/M4-GOVERNANCE.md §2`: a control that cannot be turned on gradually will be
--     turned on carelessly or not at all. The `CHECK` is therefore conditioned on `BLOCK`: a
--     `MONITOR` tenant may exceed its limit, because refusing is exactly what `MONITOR` promises
--     not to do. Turning enforcement on for a tenant already over the line has to acknowledge the
--     overshoot in the same statement, which is the point — it cannot be done silently.
--   * `soft_limit_notified_at` — set once, by the charging statement, at the first charge that
--     crosses `soft_limit_pct`; cleared by any statement that brings usage back under it. It lives
--     on the row rather than in the notifier so that "notify before you refuse" survives a restart
--     and cannot fire once per replica: the crossing is decided by the same row lock the charge
--     serialises on.
--
-- # Reconciliation, and the window the plan's risk table names
--
-- *"Two numbers for one fact. The nightly job must be able to correct without a window in which
-- writes are refused on a stale figure."*
--
-- The window appears the moment the job writes an **absolute** figure. Measure `SUM(size_bytes)`,
-- then assign it: every charge committed between the measurement and the assignment is erased, so
-- the tenant is under-counted; take the measurement while holding the row locked instead, and every
-- charge blocks for the duration of a full-table sum, which on a large tenant is the refusal window
-- in a different costume.
--
-- Neither happens here, because **the correction is relative**:
--
--   1. One statement, therefore one snapshot, reads the recorded counter and the measured sum
--      together. The charging statement updates this row inside the same transaction that writes
--      the `file_versions` row, so a snapshot sees both or neither — the pair is consistent by
--      construction rather than by timing.
--   2. `drift = measured - recorded` is computed in Rust from that pair.
--   3. A second, instantaneous statement applies `used_bytes = used_bytes + drift`.
--
-- Nothing is locked while the sum runs, and charges that commit between step 1 and step 3 keep
-- their effect: they are additive, the correction is additive, and drift is a property of the
-- *snapshot* it was measured in — a later legitimate charge does not make it stale. The worst case
-- is that drift arriving after the snapshot waits until tomorrow's run, which is what a nightly job
-- promises anyway. `crates/db/src/quota.rs` holds the same argument next to the statements.
--
-- # Why `enclave_app` gets no `DELETE`
--
-- A missing row means *unmetered*, not *refused* — a quota is a billing control, and defaulting an
-- unconfigured tenant to zero bytes would make provisioning order the difference between a working
-- deployment and a read-only one. That makes `DELETE FROM storage_quotas` the shortest statement
-- that disables enforcement for a tenant while leaving every gate in this repository green, so the
-- application role does not hold it. Removing a quota is an operator action.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `migrations/0012_lexical_search_indexes.sql` and `0017` carry the full account. sqlx
-- runs each migration in one transaction and `CONCURRENTLY` cannot run in one. There is in any case
-- no index here beyond the primary key: the table holds one row per tenant and every access is by
-- that key.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS storage_quotas (
    -- `tenant_id` first, and the primary key: Q18 is "one number per tenant", so the scope is not a
    -- column, it is the key. A future per-library quota is a different table with a different key
    -- rather than a nullable `scope_id` that every statement has to remember to constrain.
    tenant_id              UUID PRIMARY KEY REFERENCES tenants (id),

    -- What the tenant is sold. Never moved by a charge.
    limit_bytes            BIGINT NOT NULL CHECK (limit_bytes >= 0),

    -- What the tenant is using. Moved only by relative expressions; see the header.
    used_bytes             BIGINT NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),

    -- The acknowledged part of `used_bytes` that sits above `limit_bytes`. See the header.
    overshoot_bytes        BIGINT NOT NULL DEFAULT 0 CHECK (overshoot_bytes >= 0),

    -- The fraction of the limit at which administrators are told. docs/04 §16 gives 80.
    soft_limit_pct         INT NOT NULL DEFAULT 80
                           CHECK (soft_limit_pct > 0 AND soft_limit_pct <= 100),

    -- Rollout, not severity. `MONITOR` and `WARN` never refuse.
    enforcement            TEXT NOT NULL DEFAULT 'BLOCK'
                           CHECK (enforcement IN ('MONITOR','WARN','BLOCK')),

    -- When the soft limit was last announced, so it is announced once rather than once per write.
    soft_limit_notified_at TIMESTAMPTZ,

    -- The nightly job's stamp, and what it found. `last_drift_bytes` is signed on purpose: its sign
    -- says which way the write path is wrong, and a job that reported `abs()` would hide the more
    -- alarming direction. Non-zero drift is a defect in the write path (docs/04 §16), so it is a
    -- metric an operator watches rather than a number anybody bills from.
    reconciled_at          TIMESTAMPTZ,
    last_drift_bytes       BIGINT NOT NULL DEFAULT 0,

    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- D31's backstop. Conditioned on `BLOCK` because `MONITOR` and `WARN` promise not to refuse,
    -- and a constraint that aborted their charges would make them refuse in the least explicable
    -- way available. Under `BLOCK` it is unconditional, and the charging statement never touches
    -- `overshoot_bytes`, so a charge that lost its `WHERE` clause aborts.
    CONSTRAINT storage_quotas_within_budget
        CHECK (enforcement <> 'BLOCK' OR used_bytes <= limit_bytes + overshoot_bytes)
);

COMMENT ON TABLE storage_quotas IS
    'Per-tenant stored-byte quota (docs/04 §16.1, ENC-584). The limit and the counter share a row so that the CHECK backstop D31 requires can exist at all; a CHECK cannot reference another table.';

COMMENT ON COLUMN storage_quotas.used_bytes IS
    'Moved only by relative expressions. Reconciliation applies drift as `used_bytes + drift`, never an absolute assignment, which is what removes the window in which a nightly correction would either erase concurrent charges or lock them out.';

COMMENT ON COLUMN storage_quotas.overshoot_bytes IS
    'How far above limit_bytes this row has been explicitly allowed to sit. Raised only by reconciliation and by a limit change, never by a charge. Not headroom: the charging statement bounds itself by limit_bytes alone.';

-- Row-level security: enabled, forced, and a policy — docs/04 §3.2, CLAUDE.md rule 4. Forced
-- matters as much here as anywhere: this row decides whether a tenant may write, and a role that
-- could read every tenant's could also raise every tenant's.
ALTER TABLE storage_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage_quotas FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON storage_quotas
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migration 0003's catalog loop has already run and will not run again, so a table created after it
-- and not granted here is one the application role cannot see at all — which is how, before
-- ENC-124, every isolation test in the workspace passed with isolation switched off.
--
-- `SELECT, INSERT, UPDATE` and deliberately **no `DELETE`**: see the header.
GRANT SELECT, INSERT, UPDATE ON storage_quotas TO enclave_app;
