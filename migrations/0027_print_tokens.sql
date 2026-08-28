-- 0027 — `print_tokens`: the durable home of a print capability, and the single-use property held
--   by PostgreSQL instead of by one process's memory. `ENC-724`; modelled in
--   `docs/04-DATA-MODEL.md §15.2`, and the two endpoints that write and spend a row are
--   `docs/05-API.md §9`.
--
-- `ENC-720` shipped `POST /files/{id}/print-token`, which mints a 256-bit capability, returns it
-- once, and retains only its SHA-256. It kept the live grants in a `HashMap` behind a `Mutex` in
-- `crates/api/src/routes/delivery.rs`, and said so: *"this map is process-local. A grant minted on
-- one replica cannot be redeemed on another."* That failed in the safe direction — a presentation
-- to the wrong replica is **refused**, never honoured a second time — and it made print unusable
-- on any deployment with more than one API process, which is every real one.
--
-- # Why single use is a conditional `UPDATE` rather than a `DELETE`, a flag, or a unique index
--
-- The property is that **two concurrent redemptions of one token produce exactly one winner**, on
-- two machines that share nothing but this database. Four candidates, and three of them are wrong
-- in ways that only appear under concurrency:
--
--   * **A `SELECT` then an `UPDATE`.** The shape `plans/M2-ACCESS-DELIVERY.md` D18 forbids for
--     download budgets, for the same reason: two transactions both read `redeemed_at IS NULL`,
--     both decide they may proceed, and both write. Under `READ COMMITTED` neither blocks, because
--     the read took no lock. Two prints from one grant.
--
--   * **`DELETE … RETURNING`.** Correct on the race — a row can only be deleted once — but it
--     destroys the evidence in the same statement, so a replay arriving one second later is
--     indistinguishable from a replay arriving after the reaper has run, and nothing can be said
--     about how often grants are replayed. It also makes expiry and redemption the same event in
--     the table, which they are not.
--
--   * **A unique index on `(tenant_id, token_hash)` plus an insert-on-redeem into a second table.**
--     Two statements, two tables, and a failure mode where the second insert succeeds and the first
--     transaction rolls back. Nothing here needs a second table.
--
--   * **`UPDATE … WHERE redeemed_at IS NULL … RETURNING`** — what this migration is shaped for, and
--     the reason `redeemed_at` is nullable rather than a `redeemed BOOLEAN DEFAULT FALSE`. The
--     predicate names the column the statement writes. Under `READ COMMITTED` the second writer
--     finds the row already locked, waits for the first to commit, and then **re-evaluates its
--     `WHERE` against the updated row** — PostgreSQL's `EPQ` re-check — sees `redeemed_at` is no
--     longer `NULL`, and matches nothing. It returns zero rows, not an error, so the loser needs no
--     special handling: "no row came back" is already the answer for a token that never existed.
--     Under `REPEATABLE READ` or `SERIALIZABLE` the loser gets a serialization failure instead;
--     either way it does not win. The application connects at the default `READ COMMITTED`.
--
-- The `RETURNING` matters as much as the `WHERE`: the redeeming statement is the *only* place the
-- capability's contents are read, so there is no window between "this grant is valid" and "this
-- grant is spent" in which anything else could have observed it.
--
-- # Expiry is in the same predicate, and against the same clock
--
-- `expires_at > now()` sits beside `redeemed_at IS NULL` in the redeeming statement rather than in
-- a separate read, and `now()` is PostgreSQL's rather than the caller's. That is
-- `crates/worker/src/invalidation.rs`'s finding restated: a replica running a few seconds ahead of
-- the database would otherwise honour a grant the database considered dead, or refuse one it
-- considered live, and the window is small, silent and entirely avoidable. Every statement in this
-- system that judges a print token's life reads one clock.
--
-- # Rule 7 — four different failures, one answer
--
-- A token that was never issued, one whose lifetime has elapsed, one already redeemed and one
-- minted in another tenant all cause the same statement to return **zero rows**. There is no arm
-- that can tell them apart, so there is no arm that can leak which one happened: a presenter told
-- "expired" has been told the token was real. `docs/12-TESTING.md §4.2` A20 is the row that proves
-- it, and it proves it beside a real mint and a real first redemption, because "the second one was
-- refused" is otherwise satisfied by a route that refuses everything.
--
-- # `tenant_id` first, and what it does *not* do on its own
--
-- `CLAUDE.md` rule 4 in full: `tenant_id` leads the primary key, RLS is enabled and forced, and
-- both foreign keys are composite. But note what tenancy cannot hold here — **a grant is bound to
-- one actor, and a colleague in the same tenant is not that actor.** Row-level security is blind to
-- that; only the `actor_type`/`actor_id` predicate in the redeeming statement refuses it. This
-- repository has now had nine crates where a deleted `tenant_id` predicate failed to fail because
-- RLS was holding the property alone, so the test for this one uses a **same-tenant** thief
-- (`docs/12 §4.2` A21) rather than a `tenant-beta` one, which RLS would have refused anyway.
--
-- # No foreign key on the actor, and why that is not an omission
--
-- `actor_id` is polymorphic over `actor_type` — a user, a guest, a service account or an MCP client
-- — and PostgreSQL cannot express a key conditional on a sibling column. The same constraint
-- `acl_entries.resource_id` carries in `0004` and `sync_scope_sequences.scope_id` in `0023`. The
-- `CHECK` below bounds the polymorphism to the five kinds `enclave_core::ActorKind` has, spelled in
-- that enum's own wire strings so a value can move between the column, the `typ` access-token claim
-- and `audit_events.actor_type` without translation. It is deliberately *not* `refresh_tokens`'
-- uppercase three-value set, which is a narrower vocabulary that would refuse an MCP client's grant.
--
-- # `enclave_app` gets `DELETE`, which `0018`–`0023` mostly withheld
--
-- Each of those argued it on its own grounds, and the question is answered differently here for a
-- specific reason: **a print token is a live capability with a stated lifetime, not a record.** Who
-- printed what is in `audit_events`, written inside the policy chain, immutable and unreachable
-- from this role by `UPDATE` or `DELETE` at all. Deleting a `print_tokens` row after `expires_at`
-- destroys nothing anybody can ask a question of — the row is already refused by every statement
-- that reads it — and not deleting it leaves a table that grows for ever, one row per print, with
-- no upper bound. This is the same class as `sync_change_log` in `0023`: a bounded derived thing
-- whose pruning is part of its specification. `crates/worker`'s `print-token-reaper` pass is what
-- exercises the grant, and `crates/db/tests/grant_coverage.rs` proves the role actually has it
-- under `SET ROLE` — the check that `ENC-705` and `ENC-686` were both missing, because the dev
-- stack and the harness connect as the cluster superuser and a superuser has every grant.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `0012`, `0017`, `0022` and `0023` carry the full account. sqlx runs each migration in
-- one transaction and `CONCURRENTLY` cannot run inside one. The table is new and empty.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS print_tokens (
    -- `tenant_id` first, and first in the primary key (docs/04 §1). Never taken from a redeeming
    -- request (`CLAUDE.md` rule 3) — it comes from the verified access token, and is compared here.
    tenant_id    UUID NOT NULL REFERENCES tenants (id),

    -- Lowercase hex SHA-256 of the token, as `refresh_tokens.token_hash` and `share_links
    -- .token_hash` already spell it. The token itself is never stored: `plans/M2-ACCESS-DELIVERY.md`
    -- D19 — *a share link's token is never stored* — applied to the other capability in the delivery
    -- surface, for the same reason. What is not held cannot be read out of a backup, a core file or
    -- a `Debug` line. A 256-bit uniform value needs no key-stretching; there is no dictionary.
    token_hash   TEXT NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),

    -- One grant, one document. Composite, so another tenant's file id cannot be named by this
    -- tenant's grant: PostgreSQL runs referential-integrity checks with row security deliberately
    -- not enforced, so a single-column `REFERENCES files (id)` would accept one (docs/04 §3.3).
    file_id      UUID NOT NULL,

    -- Resolved at mint time from the readable-version query, so a grant cannot come to refer to
    -- content uploaded after it was issued, and cannot name a version antivirus has not cleared
    -- (`CLAUDE.md` rule 9).
    version_id   UUID NOT NULL,

    -- Who asked. A grant is not transferable, and this pair is in the redeeming statement's `WHERE`
    -- rather than checked after it, so a presentation by the wrong principal does not *consume* the
    -- grant on its way to being refused — a thief who could burn a colleague's token would have a
    -- denial of service for the price of a stolen value.
    actor_type   TEXT NOT NULL CHECK (actor_type IN ('user','guest','service','mcp','system')),
    actor_id     UUID,

    -- Which sign-in. `docs/06 §5.1` puts a session reference in the watermark itself, so a printed
    -- page is attributable to one sign-in and the grant that produced it should be too. It is the
    -- `sid` claim, which `crates/auth/src/refresh.rs` documents as *"the family, constant across
    -- every rotation in one login session"* — so requiring it to match costs a caller nothing when
    -- their access token rotates inside the 120-second window. `NULL` only for principals that have
    -- no session, which is why the redeeming statement compares it with `IS NOT DISTINCT FROM`.
    session_id   UUID,

    -- Whether whatever this grant is spent on must carry the viewer's mark.
    --
    -- Carried on the grant rather than re-derived at redemption, because the obligation belongs to
    -- the decision taken at mint time with that actor's context. A redemption that asked the
    -- question again could get a different answer from a policy edited in between — in the
    -- permissive direction. The redemption re-runs the chain anyway and takes the *union*: either
    -- side requiring a mark requires it.
    watermark    BOOLEAN NOT NULL,

    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The lifetime *is* the revocation window (`plans/M1-CONTENT-CORE.md` D14). 120 seconds, the
    -- same figure `docs/05 §9` fixes for a signed download URL. Enforced by the redeeming
    -- statement, not by a sweep: a grant is dead the instant this passes, whether or not anything
    -- has swept it.
    expires_at   TIMESTAMPTZ NOT NULL,

    -- `NULL` means unspent. This column is both what the redeeming statement writes and what its
    -- `WHERE` tests, which is the whole of the single-use mechanism — see the header.
    redeemed_at  TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, file_id)    REFERENCES files (tenant_id, id)         ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, version_id) REFERENCES file_versions (tenant_id, id) ON DELETE CASCADE,

    -- A grant cannot be spent before it was issued or after it died. Cheap, and it is the
    -- constraint that would catch a caller passing its own clock into the redeeming statement.
    CHECK (expires_at > issued_at),
    CHECK (redeemed_at IS NULL OR redeemed_at >= issued_at)
);

COMMENT ON TABLE print_tokens IS
    'Live print capabilities (docs/04 §15.2, docs/05 §9, ENC-724). Not an audit trail: who printed what is in audit_events, written inside the policy chain. Rows are reaped after expires_at by the worker''s print-token-reaper pass.';

COMMENT ON COLUMN print_tokens.token_hash IS
    'Lowercase hex SHA-256 of a 256-bit token. The token itself is returned once, at mint, and never stored — plans/M2-ACCESS-DELIVERY.md D19.';

COMMENT ON COLUMN print_tokens.redeemed_at IS
    'NULL until spent. Single use is UPDATE ... WHERE redeemed_at IS NULL RETURNING: the predicate names the column the statement writes, so under READ COMMITTED the second of two concurrent redemptions re-checks the updated row and matches nothing. Exactly one winner, across replicas.';

COMMENT ON COLUMN print_tokens.expires_at IS
    'Enforced in the redeeming statement against PostgreSQL now(), never a caller clock. An expired row is already refused before any sweep reaches it.';

-- The reaper's index, and the only query in the product that is not a primary-key lookup. Not
-- partial: a partial index would have to name a constant instant, and the predicate the reaper
-- writes is `expires_at <= now()`, which no index predicate can be built around. `(tenant_id,
-- expires_at)` is what a per-tenant range scan wants anyway, and it is the same shape `0023` gives
-- its own reaper.
CREATE INDEX IF NOT EXISTS idx_print_tokens_expiry
    ON print_tokens (tenant_id, expires_at);

-- -------------------------------------------------------------------------------------------------
-- Row-level security. `CLAUDE.md` rule 4, and `crates/db/tests/rls_coverage.rs` fails the build
-- without all three of enabled, forced and a policy.
--
-- `FORCE` is the half that matters, and it matters here in a specific way: the API and the worker
-- both connect through a role that owns nothing, but a future migration, a maintenance script or a
-- psql session as the table's owner would otherwise see every tenant's live capabilities in one
-- `SELECT` — including which files are being printed right now, which is a fact about content.
-- -------------------------------------------------------------------------------------------------

ALTER TABLE print_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE print_tokens FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON print_tokens
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- -------------------------------------------------------------------------------------------------
-- Grants. Migration 0003's catalog loop has already run and will not run again, so a table created
-- after it and not granted here is one the application role cannot see at all — which is how, before
-- `ENC-124`, every isolation test in the workspace passed with isolation switched off.
--
-- `DELETE` is argued in the header. `UPDATE` is the redemption itself.
-- -------------------------------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE, DELETE ON print_tokens TO enclave_app;
