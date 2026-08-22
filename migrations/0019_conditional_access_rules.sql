-- 0019 — `conditional_access_rules`: the stored form of a conditional-access rule.
--   docs/04-DATA-MODEL.md §12.1; docs/06-SECURITY-DLP-ACCESS.md §7 is authoritative for what a
--   rule *is*. `ENC-590`.
--
-- `ENC-583` built the evaluator and wired nothing to it: `main.rs` handed the policy engine
-- `UnconfiguredConditionalAccess`, so every rule in `crates/conditional_access` decided nothing in
-- a running deployment. Rules are **tenant data** — `docs/06 §7` has an administrator writing them
-- against their own tenant, and one `enclave.yaml` serves every tenant on a host — so they need a
-- table. Zone *definitions* stay in configuration, where `ENC-583` put them: a zone names the
-- deployment's networks, which is an operator's fact rather than a tenant's.
--
-- # Why this is `conditional_access_rules` and not docs/04 §12's `conditional_access_policies`
--
-- §12 models a policy with `priority`, `scope_type`/`scope_id`, `enabled` and an opaque
-- `definition JSONB`. Three of those describe an evaluator that was not built, and storing them
-- would be storing a promise:
--
--   * **`priority`** — the implemented resolution rule is *most restrictive effect wins*, ordered by
--     `Effect`'s declaration (`docs/06 §7.4`), precisely so that two deployments with the same rules
--     in a different order return the same reason code. A `priority` column would be a number the
--     evaluator ignores, and the first operator to tune it would conclude the product was broken.
--   * **`scope_type`/`scope_id`** — this stage runs *before* authorization so that its refusal
--     cannot depend on anything about the resource; a refusal that varied by library would be an
--     oracle for a resource the caller has not yet been permitted to know exists. Resource-shaped
--     conditions belong to the classification stage. There is nothing here to scope.
--   * **`definition JSONB`** carrying the effect — see the `effect` column below. The effect is the
--     part a `CHECK` has to be able to see.
--
-- So this is a second table for the same domain, exactly as `0018` is a second table beside §16's
-- `quotas`/`quota_usage` pair, and §12.1 records the boundary. `conditional_access_policies` is not
-- created here, because nothing uses one.
--
-- # `audience` is the Q19 control, and it is a column so the database can hold it
--
-- Q19: conditional access applies to every principal, with a **separate rule set** for service
-- accounts and MCP tokens — not one rule set with exemptions, because an exemption written once per
-- posture rule is the gap a compromised service token walks through. `ENC-583` made that a *type*
-- separation: `MachineCondition` has no `PostureBelow` and no `AuthStrengthBelow`, so a posture rule
-- against a service account is not skipped, it cannot be written.
--
-- Serialization is where a type separation is most easily lost, because JSONB will hold anything.
-- Two things keep it:
--
--   1. `audience` is a column with a `CHECK`, not a field inside `conditions`. It decides which Rust
--      type the document is decoded into, so a row is read as a machine rule or as a human rule and
--      never as "whichever the document looks like".
--   2. Decoding is strict. A `MACHINE` row whose `conditions` name `posture_below` fails to
--      deserialize — serde reports an unknown variant — and the load **errors** rather than
--      dropping the rule. See `crates/conditional_access/src/store.rs`; a rule that silently
--      vanished from the set would be the permissive failure, which is the one that matters.
--
-- The database cannot type-check the JSON document, so it is not asked to pretend it can. What it
-- can do is refuse a row whose *vocabulary* is wrong, which is `effect` and `mode` below.
--
-- # `effect` is a column with a `CHECK`, and `ALLOW` is not in it
--
-- `docs/06 §7` lists `allow` among the effects, and `ENC-583` deliberately did not implement it:
-- under most-restrictive-wins an `ALLOW` can never change an outcome, so offering it would let an
-- administrator write "allow the auditors from anywhere", see it accepted, and have it do nothing —
-- an exemption that appears to exist. `docs/06 §7.4` records that.
--
-- A vocabulary enforced only by a Rust enum is enforced only on the path that went through it. The
-- `CHECK` here means `INSERT … effect = 'ALLOW'` is refused by PostgreSQL, from psql, from a repair
-- script, from a future admin API that forgot. The absence is the security property; a constraint is
-- how an absence survives.
--
-- # Why `enclave_app` gets no `DELETE`, and what removing a rule means instead
--
-- `0018` withholds `DELETE` because `DELETE FROM storage_quotas` is the shortest statement that
-- disables enforcement for a tenant while leaving every gate in this repository green. The same
-- argument is stronger here, because this table holds refusals rather than a billing control:
-- `DELETE FROM conditional_access_rules` is one statement that lifts every network restriction a
-- tenant has, and leaves nothing behind to say it ever existed.
--
-- Removing a rule is nonetheless an ordinary administrative act, unlike removing a quota — so it is
-- an `UPDATE`: `deleted_at` is set, the row and its text stay, and the loader ignores it. An
-- administrator can see what the rule said, when it stopped applying, and reinstate it. An attacker
-- who reaches the application role can still switch a tenant's rules off — this is not a defence
-- against that — but they cannot do it without leaving the rows.
--
-- `deleted_at` is also the safe direction if the loader's filter is ever wrong: a withdrawn rule
-- that keeps applying denies too much, loudly. The failure mode of a `DELETE` we could not see is
-- the other one.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `migrations/0012_lexical_search_indexes.sql` and `0017` carry the full account. sqlx
-- runs each migration in one transaction and `CONCURRENTLY` cannot run in one. The table is new and
-- empty in every environment that applies this, so there is nothing to lock.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS conditional_access_rules (
    -- `tenant_id` first, and first in the primary key: rules are tenant data, and every access is
    -- "every live rule for this tenant".
    tenant_id   UUID NOT NULL REFERENCES tenants (id),
    id          UUID NOT NULL,

    -- Which rule set this rule belongs to — the Q19 separation, in the column that decides how the
    -- document below is decoded. Not derivable from `conditions`: `client_is` and `action_is` are
    -- legitimately in both vocabularies, so a document alone cannot say which set it belongs to,
    -- and guessing would be the coercion this column exists to prevent.
    audience    TEXT NOT NULL CHECK (audience IN ('HUMAN','MACHINE')),

    -- What an administrator calls it. Echoed in the operator log and the simulation report, never
    -- to the caller — `ReasonCode` is the whole of what crosses that boundary.
    name        TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),

    -- The conjunctive condition list, as a JSON array. Opaque to PostgreSQL by necessity — the
    -- vocabulary is a Rust enum — so the only structural claim made here is that it is an array.
    -- An empty array is legitimate and means "every request": "require a managed device, always".
    conditions  JSONB NOT NULL CHECK (jsonb_typeof(conditions) = 'array'),

    -- The effect, most restrictive first in `Effect`'s declaration order. **No `ALLOW`** — see the
    -- header. The strings are `Effect::as_sql`'s exactly; a second spelling would guarantee a
    -- mismatch that reads as "the rule stopped working".
    effect      TEXT NOT NULL CHECK (effect IN (
                    'BLOCK',
                    'REQUIRE_TRUSTED_NETWORK',
                    'REQUIRE_MANAGED_DEVICE',
                    'REQUIRE_MFA',
                    'PREVIEW_ONLY',
                    'NO_DOWNLOAD',
                    'NO_SYNC')),

    -- Rehearse or decide (`docs/06 §7`, `plans/M4-GOVERNANCE.md` D28). **The default is
    -- `SIMULATION`**, which is where this differs from docs/04 §12's model and it is deliberate:
    -- §2's sentence is that a control which cannot be turned on gradually will be turned on
    -- carelessly or not at all, so a rule written without saying which it is rehearses. Enforcing
    -- is the statement an administrator has to make.
    mode        TEXT NOT NULL DEFAULT 'SIMULATION' CHECK (mode IN ('SIMULATION','ENFORCE')),

    -- Who wrote it. `NOT NULL`: a rule that refuses people is a rule somebody is accountable for,
    -- and "the system" is not an answer to "who locked the finance team out on Friday".
    created_by  UUID NOT NULL,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Withdrawal, which is what this deployment has instead of `DELETE`. See the header.
    deleted_at  TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, id),

    -- `CLAUDE.md` rule 4 and docs/04 §3.3: a foreign key between two tenant-scoped tables carries
    -- `tenant_id`, because PostgreSQL runs referential-integrity checks with row security
    -- deliberately *not* enforced — a single-column `REFERENCES users (id)` would happily accept
    -- another tenant's user as the author of this tenant's rule. The `UNIQUE (tenant_id, id)` this
    -- names on `users` arrives in `0016_composite_auth_keys.sql`.
    CONSTRAINT conditional_access_rules_author_fkey
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);

-- One live rule per name, per tenant. The name is what an operator reads in a denial's log line and
-- in a simulation report; two live rules sharing one would make both ambiguous at exactly the moment
-- somebody is trying to work out which rule fired. Withdrawn rows are outside the index, so a name
-- can be reused after the rule it belonged to is withdrawn.
--
-- This is also the index the loader uses: it leads with `tenant_id` and covers `deleted_at IS NULL`,
-- which is the whole of the load predicate.
CREATE UNIQUE INDEX IF NOT EXISTS uq_conditional_access_rules_live_name
    ON conditional_access_rules (tenant_id, name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE conditional_access_rules IS
    'Stored conditional-access rules (docs/04 §12.1, docs/06 §7, ENC-590). One row per rule; `audience` decides which of the two Q19 rule sets the row belongs to and therefore which Rust type its conditions are decoded into.';

COMMENT ON COLUMN conditional_access_rules.audience IS
    'HUMAN or MACHINE — the Q19 rule-set separation. Not derivable from `conditions`, because several condition names are legitimately in both vocabularies; a row is read as the audience says and never as the document looks.';

COMMENT ON COLUMN conditional_access_rules.effect IS
    'Most restrictive matching effect wins, in this declaration order. There is deliberately no ALLOW: under that resolution rule an allow can never change an outcome, so accepting one would let an administrator write an exception that does nothing (docs/06 §7.4).';

COMMENT ON COLUMN conditional_access_rules.deleted_at IS
    'Withdrawal. enclave_app holds no DELETE on this table: one DELETE statement lifts every network restriction a tenant has and leaves nothing to say it existed. A withdrawn rule keeps its text and its history.';

-- Row-level security: enabled, forced, and a policy — docs/04 §3.2, CLAUDE.md rule 4. Forced is not
-- ceremony here: these rows decide who may reach a tenant's content, and a role that could read one
-- tenant's could write another's.
ALTER TABLE conditional_access_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE conditional_access_rules FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON conditional_access_rules
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migration 0003's catalog loop has already run and will not run again, so a table created after it
-- and not granted here is one the application role cannot see at all — which is how, before
-- ENC-124, every isolation test in the workspace passed with isolation switched off.
--
-- `SELECT, INSERT, UPDATE` and deliberately **no `DELETE`**: see the header.
GRANT SELECT, INSERT, UPDATE ON conditional_access_rules TO enclave_app;
