-- 0024 — workflows: definitions, instances and steps.
--   docs/15-WORKFLOWS-AND-SIGNING.md §2 (the model), §3 (step types), §4 (lifecycle) and §7 (the
--   data model) are authoritative for what a workflow *is*. docs/04-DATA-MODEL.md §17 carries the
--   reconciled shape. `ENC-739`.
--
-- `crates/workflows/src/lib.rs` was five lines and `docs/05-API.md §16` documented eight endpoints
-- with nothing behind them. These are the three tables those endpoints need.
--
-- # What is deliberately not here
--
-- The signing tables of `docs/15 §7` — `signature_requests`, `signature_participants`,
-- `signature_artifacts`, `signing_certificates` — belong to `migrations/0025`. `workflow_steps` is
-- their anchor (`signature_requests.workflow_step_id`), so `SIGNATURE` is in the `step_type`
-- vocabulary below even though nothing in `crates/workflows` can decide such a step: the signing
-- ceremony decides it, and a step type that cannot be *stored* is a workflow that cannot contain a
-- signature at all.
--
-- # The four departures from `docs/15 §7`, and the one argument behind all of them
--
-- `migrations/0021_dlp_rules.sql` states it: **storing a column the evaluator does not read is
-- storing a promise.** `docs/06 §10` lists thirteen DLP actions and `0021` stores twelve, because
-- the thirteenth fires and changes nothing. The same test applied here removes three columns and
-- narrows one vocabulary. Each is a row in `TRACKER.md`, not a silence.
--
--   1. **No `trigger JSONB` on `workflow_definitions`.** `docs/15 §5` gives five trigger kinds —
--      manual, event, metadata, schedule, API — and idempotency on
--      `(definition_id, resource_id, version_id)`. Exactly one of them is built: manual, through
--      `POST /api/v1/files/{id}/workflows`. Nothing evaluates a stored trigger document, so a
--      tenant that wrote *"start Contract Review when a version lands in `contracts`"* would see it
--      stored, see it listed, and watch nothing ever start. The idempotency the section actually
--      asks for is a `UNIQUE` constraint and it is below, where it applies to the manual path too.
--      `ENC-745`.
--
--   2. **No `resource_type` on `workflow_instances`.** §7 models it alongside `resource_id`, which
--      is a polymorphic reference — and a polymorphic reference cannot carry a foreign key, which
--      is `CLAUDE.md` rule 4's whole subject. The only resource an instance can be started on is a
--      file, so `resource_id` carries a composite key onto `files (tenant_id, id)` and **the key is
--      the discriminator**. It is strictly stronger than the column would have been: a `CHECK`
--      naming one legal value would still accept a `resource_id` that names no file, and a `CHECK`
--      naming several would accept ids the key then rejects with an internal error at `INSERT`
--      time. When a second resource type arrives it needs both a discriminator and a design for the
--      reference; adding the column alone would be the weaker half.
--
--   3. **No `assignee_type` on `workflow_steps`**, for reason 2 exactly. `docs/15 §2` gives a step
--      `assignees: users, groups, roles, or a dynamic resolver`; `assignee_id` keys onto
--      `users (tenant_id, id)`, so only a user can hold a step. Group assignment wants the
--      transitive closure that lives in `crates/authorization`, fanned out into one row per
--      resolved member at instantiation time — a change to the evaluator and to this table
--      together. `ENC-744`.
--
--   4. **`step_type` omits `AUTOMATION` and `CONDITION`.** `docs/15 §3` defines both, and this is
--      the `0021` `ALLOW` case rather than a scoping convenience: an `AUTOMATION` step calls
--      *allowlisted platform actions only*, there is no allowlist, and a `CONDITION` step branches
--      on facts nothing here reads. A step of either type would instantiate `ASSIGNED`, have no
--      assignee to decide it and no evaluator to skip it, and sit there — an instance stalled with
--      nobody able to unstick it and nothing to say why. PostgreSQL is what makes the absence hold
--      on the paths that never went through a Rust enum. Note which way it errs: a definition
--      naming an unbuilt step type is refused at the moment it is written, loudly, rather than at
--      the moment somebody needs the workflow to finish. `ENC-745`.
--
-- # Three columns `docs/15 §7` does not have, and why each is a security property
--
--   * **`workflow_instances.allow_self_approval`**, `delegation` and `on_new_version` are *pinned
--     copies* of the definition's policy. §7 puts `allow_self_approval` on the definition only,
--     which means editing a definition retroactively changes the separation of duties of every
--     instance already running under it — one `UPDATE` on a template turns a hundred in-flight
--     approvals self-approvable, with no row anywhere recording that the terms changed mid-flight.
--     §2's second core property is *determinism*: the same definition and the same event sequence
--     reach the same state. A policy the definition can move underneath a running instance breaks
--     that. So the instance carries what it was started under, and the definition row is a template
--     rather than a live authority.
--
--   * **`workflow_steps.decided_by`.** §7 has `delegated_to` and `decision_at` and no column saying
--     *who actually decided*. §4 requires that delegation be recorded and *never a silent
--     substitution* — which is unachievable without this column, because with only `delegated_to`
--     an approved step cannot distinguish "the assignee decided before delegating" from "the
--     delegate decided". That is exactly the fact an auditor is looking for. It is the
--     `acted_on_behalf_of` of §4, stored where the decision is.
--
-- # `delegation` has two values and neither of them is a chain
--
-- This is the privilege-escalation bound, and it is a vocabulary rather than a check. Delegation
-- transfers authority; an onward chain means the third holder's entitlement to it was never
-- examined by whoever originally held it. `FORBIDDEN` and `ONCE` are the whole vocabulary, so
-- *there is no value a definition, a repair script or a `psql` session could store that means
-- "delegate onward"*. The runtime half is the statement in `crates/workflows/src/repo.rs`:
-- `UPDATE … SET delegated_to = $x WHERE delegated_to IS NULL`, one statement, so a second
-- delegation racing the first loses in the database rather than in a read-then-write. `ENC-740`.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `migrations/0012_lexical_search_indexes.sql`, `0017` and `0021` carry the full account.
-- sqlx runs each migration in one transaction and `CONCURRENTLY` cannot run in one. All three
-- tables are new and empty in every environment that applies this, so there is nothing to lock.
--
-- Forward-only: a new migration, never an edit to an applied one.

-- ============================================================================================
-- workflow_definitions — the template.
-- ============================================================================================

CREATE TABLE IF NOT EXISTS workflow_definitions (
    -- `tenant_id` first, and first in the primary key: a definition is tenant data and every access
    -- is "this tenant's definition".
    tenant_id     UUID NOT NULL REFERENCES tenants (id),
    id            UUID NOT NULL,

    -- Where the definition may be started. Read, not decorative: `crates/workflows` refuses a start
    -- whose file is outside the scope, so a `LIBRARY`-scoped "Contract review" cannot be run
    -- against an HR file by anyone who knows its id. That is why this survived the `0021` test and
    -- `trigger` did not — one is evaluated, the other would not have been.
    scope_type    TEXT NOT NULL CHECK (scope_type IN ('TENANT','WORKSPACE','LIBRARY')),

    -- The workspace or library the scope names, and NULL exactly when the scope is the tenant.
    --
    -- **No foreign key, and the reason is stated rather than left as an absence** (`ENC-502`'s
    -- lesson): the referent depends on `scope_type`, so a single key would have to point at two
    -- tables. `crates/workflows` resolves it against the file's own `workspace_id`/`library_id` at
    -- start time, which is a comparison rather than a lookup — a `scope_id` naming a workspace that
    -- does not exist matches no file and therefore starts nothing. It fails closed.
    scope_id      UUID,

    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),

    -- Definitions are versioned (`docs/15 §2`), and an instance pins the version it started under.
    version       INT NOT NULL CHECK (version >= 1),

    -- Stages, their steps, assignees and quorums, as `enclave_workflows::definition` decodes it.
    -- Opaque to PostgreSQL by necessity — the vocabulary is a Rust enum — so the structural claims
    -- made here are that it is an object and that it carries a non-empty `stages` array. A
    -- definition with no stages instantiates nothing and would complete the instant it started,
    -- which is a workflow that quietly approves everything it is pointed at.
    definition    JSONB NOT NULL CHECK (
                      jsonb_typeof(definition) = 'object'
                      AND jsonb_typeof(definition -> 'stages') = 'array'
                      AND jsonb_array_length(definition -> 'stages') > 0),

    enabled       BOOLEAN NOT NULL DEFAULT TRUE,

    -- `docs/15 §4`: self-approval is rejected by default, and permitting it is a control weakness a
    -- tenant states out loud. The default is the safe one in the column as well as in the decoder,
    -- so a row written by a repair script inherits the refusal.
    allow_self_approval BOOLEAN NOT NULL DEFAULT FALSE,

    -- See the header. There is no third value.
    delegation    TEXT NOT NULL DEFAULT 'ONCE' CHECK (delegation IN ('FORBIDDEN','ONCE')),

    -- `docs/15 §2.1`: a new version invalidates in-flight approvals unless the definition says
    -- otherwise, *and it is audited loudly* when it does. Default `INVALIDATE`.
    on_new_version TEXT NOT NULL DEFAULT 'INVALIDATE'
                   CHECK (on_new_version IN ('INVALIDATE','CONTINUE')),

    -- Who wrote it. `NOT NULL`: a template that conscripts people into approving things is a
    -- template somebody is accountable for.
    created_by    UUID NOT NULL,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, id),

    -- The scope and its target agree in both directions. A table constraint so it names itself in
    -- the log line an administrator actually meets.
    CONSTRAINT workflow_definitions_scope_target
        CHECK ((scope_type = 'TENANT') = (scope_id IS NULL)),

    -- `CLAUDE.md` rule 4 and docs/04 §3.3: PostgreSQL runs referential-integrity checks with row
    -- security deliberately *not* enforced, so a single-column `REFERENCES users (id)` would accept
    -- another tenant's user as the author. The `UNIQUE (tenant_id, id)` this names on `users`
    -- arrives in `0016_composite_auth_keys.sql`.
    CONSTRAINT workflow_definitions_author_fkey
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);

-- `docs/15 §7`'s `UNIQUE (tenant_id, scope_type, scope_id, name, version)`, written as an index over
-- `COALESCE(scope_id, …)` rather than as a table constraint.
--
-- The constraint as written does not hold: `scope_id` is NULL for every `TENANT`-scoped definition,
-- NULLs are distinct in a unique constraint, and so the one scope where a name collision is most
-- likely is the one scope the constraint does not constrain. The same `COALESCE` trick
-- `uq_files_sibling_name` uses in `0005`, and for the same reason.
CREATE UNIQUE INDEX IF NOT EXISTS uq_workflow_definitions_version
    ON workflow_definitions (
        tenant_id,
        scope_type,
        COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid),
        name,
        version);

-- The lookup a start performs: this tenant's enabled definitions, by scope.
CREATE INDEX IF NOT EXISTS idx_workflow_definitions_scope
    ON workflow_definitions (tenant_id, scope_type, scope_id)
    WHERE enabled;

COMMENT ON TABLE workflow_definitions IS
    'Workflow templates (docs/04 §17.1, docs/15 §2 and §7, ENC-739). There is deliberately no trigger column: docs/15 §5 has five trigger kinds and none is evaluated, so a stored trigger document would be a promise the engine does not keep (ENC-745, migrations/0021''s argument).';

COMMENT ON COLUMN workflow_definitions.scope_id IS
    'The workspace or library the scope names, NULL exactly for TENANT scope. Deliberately carries no foreign key: the referent depends on scope_type, and crates/workflows resolves it by comparing against the target file''s own workspace_id/library_id, which fails closed when the scope names nothing.';

COMMENT ON COLUMN workflow_definitions.delegation IS
    'FORBIDDEN or ONCE, and there is no third value. An onward delegate chain is a privilege-escalation path — the third holder''s entitlement was never examined by whoever originally held the step — so it is unstorable rather than checked (ENC-740).';

ALTER TABLE workflow_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_definitions FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workflow_definitions
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migration 0003's catalog loop has already run and will not run again, so a table created after it
-- and not granted here is one the application role cannot see at all — which is how, before
-- ENC-124, every isolation test in the workspace passed with isolation switched off.
GRANT SELECT, INSERT, UPDATE ON workflow_definitions TO enclave_app;

-- ============================================================================================
-- workflow_instances — one running process, bound to one version.
-- ============================================================================================

CREATE TABLE IF NOT EXISTS workflow_instances (
    tenant_id     UUID NOT NULL REFERENCES tenants (id),
    id            UUID NOT NULL,

    definition_id UUID NOT NULL,

    -- The version of the definition this instance was started under, recorded so the audit trail
    -- can say what the terms were. The *behaviour* does not read it: the pinned policy columns
    -- below and the step rows carry everything the evaluator needs, which is what makes §2's
    -- determinism a property of the rows rather than of a template nobody froze.
    definition_version INT NOT NULL CHECK (definition_version >= 1),

    -- The file. See the header for why there is no `resource_type` beside it.
    resource_id   UUID NOT NULL,

    -- **`NOT NULL`, where `docs/15 §7` has it nullable.** §2.1 is the first of the model's core
    -- properties: *bound to a version, not a file — an approval approves what was actually
    -- reviewed*. An instance with no version is precisely the thing that property forbids, and a
    -- nullable column is an invitation to create one. It is also what makes the idempotency index
    -- below work at all: NULLs are distinct, so a nullable `version_id` would let the same
    -- definition start on the same file unboundedly often.
    version_id    UUID NOT NULL,

    state         TEXT NOT NULL
                  CHECK (state IN ('DRAFT','RUNNING','COMPLETED','REJECTED','CANCELLED','EXPIRED')),

    -- Which stage is open. Zero-based, matching the definition's `stages` array.
    current_stage INT NOT NULL DEFAULT 0 CHECK (current_stage >= 0),

    -- Who started it, and therefore — with a workspace owner — who may cancel it (`docs/15 §4`).
    started_by    UUID NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    due_at        TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,

    -- Why it ended, for the terminal states that have a reason. `docs/15 §4` requires one for
    -- cancellation specifically; the `CHECK` below is what makes "requires" true on every path.
    outcome_reason TEXT CHECK (outcome_reason IS NULL OR length(outcome_reason) BETWEEN 1 AND 2000),

    -- Pinned from the definition at start. See the header: a template must not be able to move the
    -- separation of duties of an instance already running under it.
    allow_self_approval BOOLEAN NOT NULL,
    delegation    TEXT NOT NULL CHECK (delegation IN ('FORBIDDEN','ONCE')),
    on_new_version TEXT NOT NULL CHECK (on_new_version IN ('INVALIDATE','CONTINUE')),

    revision      BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),

    PRIMARY KEY (tenant_id, id),

    -- A cancellation without a reason is the one this constraint exists for. `docs/15 §4`:
    -- *cancellation requires the initiator or a workspace owner, a reason, and is audited.* The
    -- handler refuses an empty reason with a `422` naming the field; this is what holds the same
    -- rule for a repair script, and it is why the rule survives somebody adding a second write path.
    CONSTRAINT workflow_instances_cancellation_reason
        CHECK (state <> 'CANCELLED' OR outcome_reason IS NOT NULL),

    -- A terminal state has an end time and a running one does not. Two states that disagree about
    -- whether the instance is over is the ambiguity every listing then has to guess at.
    CONSTRAINT workflow_instances_completion_time
        CHECK ((state IN ('COMPLETED','REJECTED','CANCELLED','EXPIRED')) = (completed_at IS NOT NULL)),

    CONSTRAINT workflow_instances_definition_fkey
        FOREIGN KEY (tenant_id, definition_id) REFERENCES workflow_definitions (tenant_id, id),
    CONSTRAINT workflow_instances_resource_fkey
        FOREIGN KEY (tenant_id, resource_id) REFERENCES files (tenant_id, id),
    CONSTRAINT workflow_instances_version_fkey
        FOREIGN KEY (tenant_id, version_id) REFERENCES file_versions (tenant_id, id),
    CONSTRAINT workflow_instances_starter_fkey
        FOREIGN KEY (tenant_id, started_by) REFERENCES users (tenant_id, id)
);

-- `docs/15 §5`: *trigger evaluation is idempotent on `(definition_id, resource_id, version_id)`, so
-- a redelivered event cannot start a duplicate instance.* Written as a constraint rather than as a
-- read-then-write, because two concurrent deliveries both read "no instance" and both insert. The
-- unique violation is the answer, and `crates/api` renders it as the `409` naming the instance that
-- already exists — which is also the right answer for the manual path, where the duplicate is a
-- double-clicked button rather than a redelivered event. `docs/15 §12` W4.
CREATE UNIQUE INDEX IF NOT EXISTS uq_workflow_instances_trigger
    ON workflow_instances (tenant_id, definition_id, resource_id, version_id);

-- `docs/15 §7`'s open-work index: what is running and what is late.
CREATE INDEX IF NOT EXISTS idx_workflow_instances_open
    ON workflow_instances (tenant_id, state, due_at)
    WHERE state = 'RUNNING';

-- The lookup `GET /api/v1/files/{id}` will want: what is in flight over this file.
CREATE INDEX IF NOT EXISTS idx_workflow_instances_resource
    ON workflow_instances (tenant_id, resource_id, started_at DESC);

COMMENT ON TABLE workflow_instances IS
    'One running workflow, bound to one immutable version (docs/04 §17.2, docs/15 §2 and §7, ENC-739). version_id is NOT NULL where docs/15 §7 has it nullable: §2.1''s first core property is that an approval approves what was actually reviewed, and a nullable column is how an instance bound to no version gets created.';

COMMENT ON COLUMN workflow_instances.allow_self_approval IS
    'Pinned from the definition at start, with delegation and on_new_version. A definition is a template, not a live authority: without the pin, one UPDATE on a template would make every in-flight approval under it self-approvable, with nothing recording that the terms changed mid-flight (docs/15 §2, determinism).';

COMMENT ON COLUMN workflow_instances.outcome_reason IS
    'Why the instance ended. Required for CANCELLED by workflow_instances_cancellation_reason, because docs/15 §4 makes the reason part of what cancellation *is* — and a constraint holds that for the repair script as well as for the handler.';

ALTER TABLE workflow_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_instances FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workflow_instances
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No `DELETE`, for `0018`/`0019`/`0021`'s reason applied to this table: an instance is the record of
-- who was asked to approve what and what they said, and `DELETE FROM workflow_instances` is the
-- shortest statement that removes the evidence of an approval that was refused. Cancellation is the
-- withdrawal, it keeps the row, and `docs/15 §4` requires it to carry a reason.
GRANT SELECT, INSERT, UPDATE ON workflow_instances TO enclave_app;

-- ============================================================================================
-- workflow_steps — one row per assignee per step, which is what makes a quorum countable.
-- ============================================================================================

CREATE TABLE IF NOT EXISTS workflow_steps (
    tenant_id     UUID NOT NULL REFERENCES tenants (id),
    id            UUID NOT NULL,

    instance_id   UUID NOT NULL,

    -- Where in the definition this row came from. `docs/15 §2`'s tree is
    -- `Stage[] -> Step[] -> assignees`, and a step with three assignees and a quorum of two is
    -- **three rows sharing `(stage, position)`** — which is what makes the quorum a `count(*)` over
    -- a key rather than a field somebody has to keep in step with reality.
    stage         INT NOT NULL CHECK (stage >= 0),
    position      INT NOT NULL CHECK (position >= 0),

    -- `docs/15 §3`, minus AUTOMATION and CONDITION. See the header.
    step_type     TEXT NOT NULL CHECK (step_type IN ('APPROVAL','REVIEW','SIGNATURE','TASK')),

    -- Who was asked. See the header for why there is no `assignee_type`.
    assignee_id   UUID NOT NULL,

    -- Who the assignee handed it to, at most once. `docs/15 §4`: delegation is explicit and
    -- recorded, never a silent substitution. NULL is the ordinary case.
    delegated_to  UUID,
    delegated_at  TIMESTAMPTZ,
    delegation_reason TEXT CHECK (
        delegation_reason IS NULL OR length(delegation_reason) BETWEEN 1 AND 2000),

    state         TEXT NOT NULL CHECK (state IN (
                      'PENDING','ASSIGNED','APPROVED','REJECTED','SIGNED','DECLINED','SKIPPED',
                      'EXPIRED')),

    -- **Who actually decided**, which `docs/15 §7` has no column for. See the header: with only
    -- `delegated_to`, an approved step cannot distinguish the assignee deciding before delegating
    -- from the delegate deciding, and that distinction is the whole content of §4's requirement
    -- that a delegation never be a silent substitution.
    decided_by    UUID,
    decision_at   TIMESTAMPTZ,
    comment       TEXT CHECK (comment IS NULL OR length(comment) BETWEEN 1 AND 4000),

    due_at        TIMESTAMPTZ,

    -- What this position was asked for, frozen at instantiation: the quorum, and the stage's name.
    -- Read by the evaluator, which never re-reads `workflow_definitions` — see
    -- `workflow_instances.definition_version`. That is what makes an in-flight instance immune to a
    -- template edit, and it is the same argument as the pinned policy columns one table up.
    config        JSONB NOT NULL DEFAULT '{}'::jsonb
                  CHECK (jsonb_typeof(config) = 'object'),

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, id),

    -- One row per assignee per position. Also the constraint that stops a definition naming the
    -- same person twice in one step and thereby letting them satisfy a two-of-three quorum alone.
    CONSTRAINT workflow_steps_one_row_per_assignee
        UNIQUE (tenant_id, instance_id, stage, position, assignee_id),

    -- A decided step names its decider and when; an undecided one names neither. Without this, a
    -- repair script can produce an `APPROVED` step with no decider — an approval nobody made.
    CONSTRAINT workflow_steps_decision_complete
        CHECK ((state IN ('APPROVED','REJECTED','SIGNED','DECLINED'))
               = (decided_by IS NOT NULL AND decision_at IS NOT NULL)),

    -- A delegation names its target, its time and its reason together, or none of them.
    CONSTRAINT workflow_steps_delegation_complete
        CHECK ((delegated_to IS NOT NULL)
               = (delegated_at IS NOT NULL AND delegation_reason IS NOT NULL)),

    -- Delegating to yourself is not a transfer. It would leave the trail saying authority moved
    -- when it did not, and it is the shape a `ONCE` budget gets spent on by accident.
    CONSTRAINT workflow_steps_delegate_is_not_assignee
        CHECK (delegated_to IS NULL OR delegated_to <> assignee_id),

    CONSTRAINT workflow_steps_instance_fkey
        FOREIGN KEY (tenant_id, instance_id) REFERENCES workflow_instances (tenant_id, id),
    CONSTRAINT workflow_steps_assignee_fkey
        FOREIGN KEY (tenant_id, assignee_id) REFERENCES users (tenant_id, id),
    CONSTRAINT workflow_steps_delegate_fkey
        FOREIGN KEY (tenant_id, delegated_to) REFERENCES users (tenant_id, id),
    CONSTRAINT workflow_steps_decider_fkey
        FOREIGN KEY (tenant_id, decided_by) REFERENCES users (tenant_id, id)
);

-- `docs/15 §7`'s inbox index, widened by one column.
--
-- The section indexes `(tenant_id, assignee_id, state) WHERE state = 'ASSIGNED'`, which finds the
-- steps a user was *originally* given and misses every step delegated **to** them — the delegate's
-- inbox would be empty, which is a delegation that transfers the obligation and not the work. Two
-- partial indexes rather than one over a `COALESCE(delegated_to, assignee_id)`, because the inbox
-- query is a `UNION` of two exact predicates and each is a single-column probe.
CREATE INDEX IF NOT EXISTS idx_workflow_steps_assignee
    ON workflow_steps (tenant_id, assignee_id, state)
    WHERE state = 'ASSIGNED';

CREATE INDEX IF NOT EXISTS idx_workflow_steps_delegate
    ON workflow_steps (tenant_id, delegated_to, state)
    WHERE state = 'ASSIGNED' AND delegated_to IS NOT NULL;

-- The evaluator's read: every step of one instance, in stage and position order.
CREATE INDEX IF NOT EXISTS idx_workflow_steps_instance
    ON workflow_steps (tenant_id, instance_id, stage, position);

COMMENT ON TABLE workflow_steps IS
    'One row per assignee per step position (docs/04 §17.3, docs/15 §2, §3 and §7, ENC-739). A quorum is therefore a count over (instance_id, stage, position) rather than a field somebody keeps in step with reality. step_type omits AUTOMATION and CONDITION: docs/15 §3 defines both, neither has an evaluator, and such a step would instantiate ASSIGNED and stall the instance with nobody able to decide it (ENC-745).';

COMMENT ON COLUMN workflow_steps.decided_by IS
    'Who actually decided — docs/15 §4''s acted_on_behalf_of, stored where the decision is. Not in docs/15 §7, and required by it: with only delegated_to, an APPROVED step cannot distinguish the assignee deciding before delegating from the delegate deciding.';

COMMENT ON COLUMN workflow_steps.delegated_to IS
    'Set at most once, by the statement in crates/workflows/src/repo.rs: UPDATE … WHERE delegated_to IS NULL. One statement, so a second delegation racing the first loses in the database. The instance''s delegation column has no value meaning "onward" (ENC-740).';

COMMENT ON COLUMN workflow_steps.config IS
    'The quorum and stage name this position was instantiated with, frozen. The evaluator reads this and never re-reads workflow_definitions, which is what makes an in-flight instance immune to a template edit (docs/15 §2, determinism).';

ALTER TABLE workflow_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE workflow_steps FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON workflow_steps
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No `DELETE`, for `workflow_instances`' reason. A step row is the record that a named person was
-- asked and what they said; `SKIPPED` is how a step stops mattering, and it leaves the row.
GRANT SELECT, INSERT, UPDATE ON workflow_steps TO enclave_app;
