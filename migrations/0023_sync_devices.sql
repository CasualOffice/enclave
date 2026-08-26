-- 0023 — the sync device registry, the per-scope change feed, and the cursors into it.
--   docs/04-DATA-MODEL.md §15 and §15.1; docs/10-SYNC-AND-EDITING.md §§3–6 for the protocol;
--   docs/05-API.md §13 for the four endpoints. `ENC-732`.
--
-- `docs/04 §15` models two of these tables — `sync_devices` and `sync_cursors` — and this migration
-- creates them in the shape it gives, with the additions §15.1 now records. It also creates two
-- tables that document did not model, `sync_scope_sequences` and `sync_change_log`, because
-- `sync_cursors.cursor` is documented as *"a monotonic change sequence"* and nothing in the schema
-- produced one. A cursor into a feed that does not exist is a column, not a protocol.
--
-- # The hard part is the cursor, and it is a correctness problem rather than a naming one
--
-- A sync client asks *"what changed since X"* and must neither miss a change nor be handed one it
-- has already applied. Three candidates for X, and two of them are wrong in ways that only appear
-- under concurrency:
--
--   * **A timestamp** (`modified_at > $cursor`). Wrong, and wrong silently. Two transactions read
--     the clock in one order and commit in the other: A stamps 10:00:01 and commits at 10:00:04,
--     B stamps 10:00:02 and commits at 10:00:03. A client that polls at 10:00:03.5 sees B, stores
--     the cursor 10:00:02, and never sees A — which committed later but stamped earlier. The file
--     is simply missing from the device, for ever, with every row in the database correct.
--
--   * **A PostgreSQL `SEQUENCE`** (`nextval`). Wrong for the same reason one layer down, and this
--     is the tempting one because a sequence *looks* like it is handing out order. `nextval` is
--     deliberately non-transactional: it does not lock, it does not roll back, and it returns
--     before the caller commits. So A can take 5 and B take 6, and B can commit first. A reader
--     between the two commits sees 6, stores 6, and never sees 5. Sequences also leave permanent
--     holes on rollback, so a client cannot tell "5 was aborted" from "5 has not landed yet".
--
--   * **A transactional per-scope counter row** — what this migration uses. `sync_scope_sequences`
--     holds one row per scope, and a change is appended by `UPDATE … SET next_seq = next_seq + 1
--     RETURNING`. That statement takes a **row lock held until the transaction ends**, so the
--     second writer in the same scope blocks until the first commits or aborts. Allocation order is
--     therefore *commit* order, exactly, and the counter rolls back with its transaction so there
--     are no holes. The set of `seq` values visible to any reader is always a contiguous prefix,
--     which is what makes `WHERE seq > $cursor ORDER BY seq` both complete and duplicate-free.
--
-- What it costs is stated rather than discovered: appends to one scope **serialise**. A library
-- taking a thousand writes a second is a library whose writers queue behind one row lock. That is
-- the price of an ordering guarantee that does not need a reconciliation pass to be trusted, and
-- the scope is the library rather than the tenant precisely to keep the contention local. If a
-- deployment ever needs more, the answer is a finer scope (a folder subtree), not a looser cursor.
--
-- # Why a trigger writes the feed and not the application
--
-- Every crate that can change a file would otherwise have to remember to append — `crates/files`,
-- `crates/versions`, `crates/authorization` when it materialises a permission break, and whatever
-- lands next. One that forgets does not fail; it produces a device that is quietly missing a file,
-- which is the failure mode this whole protocol exists to avoid. The trigger is the same argument
-- row-level security makes about tenant predicates: completeness that does not depend on every
-- future author reading this comment.
--
-- The trigger fires on `INSERT OR UPDATE` of `files` and on nothing else. `files.acl_revision` is
-- bumped when a permission break is materialised, so a caller losing access produces a feed entry
-- and therefore a tombstone, which is `docs/10 §4`'s *"a file the user lost access to appears as a
-- TOMBSTONE with a reason, not as an omission"*. An ACL change that does **not** touch `files` —
-- an `acl_entries` row withdrawn on an inheriting file — produces no entry, and the client learns
-- at materialisation time instead, where `docs/10 §5` re-evaluates eligibility and returns
-- `SYNC_NOT_PERMITTED`. That gap is real, is `ENC-737`, and is written here rather than left for
-- someone to find.
--
-- # `enclave_app` gets `DELETE` on exactly one of these four tables
--
-- `0018`, `0019`, `0021` and `0022` each withheld it and each argued it on its own grounds. Here
-- the four tables answer differently, and the differences are the interesting part:
--
--   * **`sync_scope_sequences` — never.** Deleting a counter row restarts the scope at 1. Every
--     device holding a cursor of 500 then asks for `seq > 500` against a feed that is emitting
--     1, 2, 3, and receives nothing — for ever, silently, with no error and no re-enumeration,
--     because the client's cursor is not *too old*, it is too new. One statement turns every device
--     in a library into a device that has stopped syncing and does not know it.
--   * **`sync_devices` — never.** A wipe is recorded on the row (`wipe_requested_at`, `wiped_at`).
--     Deleting the row is a wipe that never happened and an offboarding nobody can evidence.
--     Revocation is an `UPDATE` of `state`.
--   * **`sync_cursors` — never.** Deleting a device's cursor silently re-enumerates its whole
--     selection on the next call, which for a large library is a re-download of everything. If a
--     re-enumeration is wanted it is asked for, by moving the cursor.
--   * **`sync_change_log` — yes.** It is the one table here that is a retention-bounded *derived*
--     feed rather than a record. `docs/10 §4` fixes a 30-day window and defines the consequence of
--     falling off it (`410 CURSOR_TOO_OLD`, scoped re-enumeration), so pruning is part of the
--     specified behaviour rather than a way to lose something.
--
-- # `ON DELETE CASCADE` from `files`, and what it means for a tombstone
--
-- `sync_change_log.file_id` is a composite key into `files` — `CLAUDE.md` rule 4, and without it
-- another tenant's file id could be appended to this tenant's feed, because PostgreSQL runs
-- referential-integrity checks with row security deliberately not enforced. It cascades rather than
-- restricting, because the alternative is a hard purge that fails on a feed row. The soft delete is
-- what a client actually sees: `files.deleted_at` is an `UPDATE`, so it appends a normal entry and
-- the delta renders it as a `DELETED` tombstone. A **purge** removes the entries with the file —
-- and a purge happens after `files.purge_after`, which is far outside the 30-day feed window, so a
-- device that had not seen the tombstone is already past `CURSOR_TOO_OLD` and re-enumerates.
-- Cascading also leaves holes in `seq`, which is harmless: the guarantee the counter buys is that
-- nothing ever appears *below* a cursor already served, not that the integers are dense.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `0012`, `0017` and `0022` carry the full account. sqlx runs each migration in one
-- transaction and `CONCURRENTLY` cannot run in one. Every table here is new and empty.
--
-- Forward-only: a new migration, never an edit to an applied one.

-- -------------------------------------------------------------------------------------------------
-- The device registry.
-- -------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sync_devices (
    -- `tenant_id` first, and first in the primary key (docs/04 §1).
    tenant_id   UUID NOT NULL REFERENCES tenants (id),
    device_id   UUID NOT NULL,

    -- One device belongs to one user (docs/10 §3). Composite, so another tenant's user cannot own
    -- this tenant's device — a single-column key would accept one.
    user_id     UUID NOT NULL,

    -- What the user sees in the device list, and what a wipe confirmation names.
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),

    -- Free text rather than a `CHECK`: `docs/10 §10` names Windows, macOS, Linux, iOS and Android
    -- today and the list is a client-build fact, not a policy vocabulary. Nothing in the schema or
    -- in policy branches on it.
    platform    TEXT NOT NULL CHECK (length(platform) BETWEEN 1 AND 100),

    -- `docs/10 §10`: the server can refuse an outdated client whose policy evaluation is known to
    -- be stale. Stored so that refusal has something to read.
    client_version TEXT NOT NULL CHECK (length(client_version) BETWEEN 1 AND 100),

    -- The library/folder selections this device replicates (docs/04 §15). JSONB because it is a
    -- user-defined selection document rather than anything queried in a hot path (docs/04 §1); the
    -- delta reads a scope named in the request, not this column.
    selected_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- MDM attestation's answer, feeding conditional access (docs/10 §3). Same vocabulary as
    -- `devices.posture` in 0001 and as `enclave_core::DevicePosture`, spelled identically so a
    -- value can move between them without translation.
    posture     TEXT NOT NULL DEFAULT 'UNKNOWN'
                CHECK (posture IN ('UNKNOWN','UNMANAGED','MANAGED','COMPLIANT')),

    -- The state machine docs/04 §15 gives. `WIPING` is the interval between a wipe being requested
    -- and the client acknowledging it; a device sitting in `WIPING` for a week is the honest
    -- rendering of a cooperative wipe that has not been cooperated with.
    state       TEXT NOT NULL DEFAULT 'ACTIVE'
                CHECK (state IN ('ACTIVE','PAUSED','REVOKED','WIPING','WIPED')),

    last_sync_at      TIMESTAMPTZ,

    -- Set when a wipe is requested, stamped when the client acknowledges. Both nullable and neither
    -- ever cleared: a wipe that was requested and then un-requested is not a thing a device can be
    -- told, so there is no state to return to.
    wipe_requested_at TIMESTAMPTZ,
    wiped_at          TIMESTAMPTZ,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Also the target of `sync_cursors`' composite key below: a two-column key cannot match a
    -- device belonging to another tenant, so no separate `UNIQUE (tenant_id, device_id)` is needed.
    PRIMARY KEY (tenant_id, device_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users (tenant_id, id),

    -- A wipe cannot be acknowledged before it is requested. Cheap, and it is the constraint that
    -- stops `wiped_at` being stamped by a handler that skipped the request step.
    CHECK (wiped_at IS NULL OR wipe_requested_at IS NOT NULL)
);

COMMENT ON TABLE sync_devices IS
    'The sync client registry (docs/04 §15, docs/10 §3, ENC-732). Distinct from `devices` in 0001, which is the auth-domain token-binding registry the `dev` claim names and which nothing writes yet; reconciling the two when device-bound tokens land is ENC-736.';

COMMENT ON COLUMN sync_devices.state IS
    'ACTIVE, PAUSED, REVOKED, WIPING, WIPED. WIPING is a wipe requested and not yet acknowledged — the visible form of the cooperative wipe docs/10 §3.1 describes, which cannot be completed without the device.';

COMMENT ON COLUMN sync_devices.wiped_at IS
    'Stamped when the client acknowledges deleting its cache and tokens. Never set by the server on its own behalf: a wipe the device has not confirmed has not happened, and recording it as though it had is the one thing a wipe record must not do.';

-- The device list, per user and tenant-wide (docs/05 §13). Ordered by `device_id`, which is UUIDv7
-- and therefore already registration order — the same argument `enclave_db::cursor` makes for
-- collapsing sort key and tie-break into one column.
CREATE INDEX IF NOT EXISTS idx_sync_devices_user
    ON sync_devices (tenant_id, user_id, device_id);

-- The reaper's index: devices that have been told to wipe and have not answered.
CREATE INDEX IF NOT EXISTS idx_sync_devices_wiping
    ON sync_devices (tenant_id, wipe_requested_at)
    WHERE wiped_at IS NULL AND wipe_requested_at IS NOT NULL;

-- -------------------------------------------------------------------------------------------------
-- The per-scope change sequence. One row per scope; the row lock is the ordering guarantee.
-- -------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sync_scope_sequences (
    tenant_id  UUID NOT NULL REFERENCES tenants (id),

    -- Only `LIBRARY` today. A closed vocabulary rather than free text because this value is half of
    -- a cursor's identity: a client resuming `library:X` against a feed that had silently started
    -- writing `folder:X` entries would read a different feed under the same cursor.
    scope_type TEXT NOT NULL CHECK (scope_type IN ('LIBRARY')),

    -- Polymorphic over `scope_type`, and therefore **not** a foreign key. PostgreSQL cannot express
    -- a key conditional on a sibling column, which is the same reason `acl_entries.resource_id`
    -- carries none (0004). The `CHECK` above is what bounds the polymorphism to one target today,
    -- and the trigger is the only writer, so the value always came from `files.library_id` — a
    -- column that *is* keyed. Recorded rather than left to be discovered, per `ENC-502`.
    scope_id   UUID NOT NULL,

    -- The last sequence handed out. Starts at 0 so the first entry is 1 and a cursor of 0 means
    -- "from the beginning" without needing a nullable column to say so.
    next_seq   BIGINT NOT NULL DEFAULT 0 CHECK (next_seq >= 0),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, scope_type, scope_id)
);

COMMENT ON TABLE sync_scope_sequences IS
    'One counter row per sync scope. The UPDATE that increments it takes a row lock held to commit, which is what makes allocation order equal commit order — see the header of migrations/0023_sync_devices.sql. enclave_app holds no DELETE: removing a row restarts the scope at 1 and every device holding a higher cursor stops receiving changes, silently and permanently.';

-- -------------------------------------------------------------------------------------------------
-- The change feed itself.
-- -------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sync_change_log (
    tenant_id  UUID NOT NULL REFERENCES tenants (id),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('LIBRARY')),
    scope_id   UUID NOT NULL,

    -- Allocated from `sync_scope_sequences`. Contiguous at allocation; see the header for why the
    -- cascade below may later leave holes and why holes are harmless.
    seq        BIGINT NOT NULL CHECK (seq > 0),

    file_id    UUID NOT NULL,

    -- What the entry says happened to the file *in the tree*. It is deliberately **not** what the
    -- delta puts on the wire: an `UPSERT` here can still be rendered as a `TOMBSTONE` to a
    -- particular caller once eligibility has been evaluated for them (docs/10 §4, §5). The feed
    -- records the change; the handler decides what each caller may be told about it.
    op         TEXT NOT NULL CHECK (op IN ('UPSERT','DELETE')),

    -- The version current at the moment of the change, or `NULL` for a folder or a file with no
    -- committed version. Not a key into `file_versions`: the row it names can be superseded, and a
    -- feed entry is a statement about the past that must not stop being readable when it is.
    version_id UUID,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, scope_type, scope_id, seq),
    -- Composite, and cascading — see the header. Without `tenant_id` in the key, another tenant's
    -- file id would be accepted into this tenant's feed, because referential-integrity checks run
    -- with row security not enforced.
    FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id) ON DELETE CASCADE
);

COMMENT ON TABLE sync_change_log IS
    'The ordered per-scope change feed a delta is served from (docs/10 §4). Append-only from the application''s side and pruned on a 30-day window; the only table in 0023 enclave_app may DELETE from, because falling off the window has a specified consequence — 410 CURSOR_TOO_OLD and a scoped re-enumeration — rather than being a silent loss.';

COMMENT ON COLUMN sync_change_log.op IS
    'The change to the tree, not the wire form. An UPSERT is rendered to a caller as a TOMBSTONE whenever eligibility fails for them (docs/10 §4), so what the client receives depends on the caller and what is stored does not.';

-- The delta's only read: one scope, everything above a cursor, in order. The primary key already
-- provides it — stated here so a later reader does not add a second index for the same access path.

-- The pruner's read: everything in one tenant older than the retention window, across scopes.
CREATE INDEX IF NOT EXISTS idx_sync_change_log_age
    ON sync_change_log (tenant_id, occurred_at);

-- -------------------------------------------------------------------------------------------------
-- Where each device has read to.
-- -------------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sync_cursors (
    tenant_id  UUID NOT NULL REFERENCES tenants (id),
    device_id  UUID NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('LIBRARY')),
    scope_id   UUID NOT NULL,

    -- The last `seq` this device has been served for this scope. `0` is a device that has never
    -- read the scope, which is the same starting position as a client that presents no cursor.
    cursor     BIGINT NOT NULL DEFAULT 0 CHECK (cursor >= 0),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, device_id, scope_type, scope_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES sync_devices (tenant_id, device_id)
);

COMMENT ON TABLE sync_cursors IS
    'Server-side record of where a device has read to (docs/04 §15). The authoritative cursor on any one call is the one the client presents; this row is what lets a device that lost its local state resume rather than re-enumerate, and what an operator reads to see a device falling behind.';

-- -------------------------------------------------------------------------------------------------
-- The appender. See the header for why this is a trigger.
-- -------------------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION sync_append_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    allocated BIGINT;
    change_op TEXT;
BEGIN
    -- A soft delete is a `DELETE` in the feed; everything else — creation, rename, move, a new
    -- current version, a permission break that bumped `acl_revision` — is an `UPSERT`. A move
    -- between libraries appends to the destination scope only, and the source scope's device sees
    -- it as an absence rather than a tombstone; that is `ENC-737` alongside the ACL case, and both
    -- are caught by the re-evaluation at materialisation time.
    IF NEW.deleted_at IS NOT NULL THEN
        change_op := 'DELETE';
    ELSE
        change_op := 'UPSERT';
    END IF;

    -- The allocation, and the whole ordering guarantee. `ON CONFLICT DO UPDATE` takes a row lock on
    -- the counter that is held until this transaction commits or aborts, so a concurrent writer in
    -- the same scope blocks here rather than taking the next number and racing us to commit.
    INSERT INTO sync_scope_sequences (tenant_id, scope_type, scope_id, next_seq, updated_at)
    VALUES (NEW.tenant_id, 'LIBRARY', NEW.library_id, 1, now())
    ON CONFLICT (tenant_id, scope_type, scope_id)
    DO UPDATE SET next_seq = sync_scope_sequences.next_seq + 1, updated_at = now()
    RETURNING next_seq INTO allocated;

    INSERT INTO sync_change_log
        (tenant_id, scope_type, scope_id, seq, file_id, op, version_id, occurred_at)
    VALUES
        (NEW.tenant_id, 'LIBRARY', NEW.library_id, allocated, NEW.id, change_op,
         NEW.current_version_id, now());

    RETURN NULL;  -- AFTER trigger; the return value is ignored.
END;
$$;

COMMENT ON FUNCTION sync_append_change() IS
    'Appends one entry to sync_change_log for every change to a file, allocating seq under the scope counter''s row lock so that allocation order is commit order (migrations/0023_sync_devices.sql, ENC-732).';

CREATE OR REPLACE TRIGGER sync_files_change_feed
    AFTER INSERT OR UPDATE ON files
    FOR EACH ROW
    EXECUTE FUNCTION sync_append_change();

-- -------------------------------------------------------------------------------------------------
-- Row-level security — docs/04 §3.2, CLAUDE.md rule 4.
--
-- `FORCE` matters on all four in the same specific way: `sync_devices` decides which machines hold
-- copies of a tenant's content, and a role that could write another tenant's row could enrol a
-- device into it. On the feed and the counter the consequence is quieter and worse — a writable
-- counter is a scope another tenant can silently stop replicating.
-- -------------------------------------------------------------------------------------------------

ALTER TABLE sync_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_devices FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sync_devices
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE sync_scope_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_scope_sequences FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sync_scope_sequences
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE sync_change_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_change_log FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sync_change_log
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE sync_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_cursors FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sync_cursors
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- -------------------------------------------------------------------------------------------------
-- Grants. Migration 0003's catalog loop has already run and will not run again, so a table created
-- after it and not granted here is one the application role cannot see at all — which is how, before
-- `ENC-124`, every isolation test in the workspace passed with isolation switched off.
--
-- The trigger runs as the invoker, so `enclave_app` needs `INSERT` on the feed and `INSERT, UPDATE`
-- on the counter for an ordinary file write to succeed at all.
-- -------------------------------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE         ON sync_devices         TO enclave_app;
GRANT SELECT, INSERT, UPDATE         ON sync_scope_sequences TO enclave_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sync_change_log      TO enclave_app;
GRANT SELECT, INSERT, UPDATE         ON sync_cursors         TO enclave_app;
