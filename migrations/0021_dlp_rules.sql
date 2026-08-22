-- 0021 — `dlp_rules`: the stored form of a DLP rule.
--   docs/04-DATA-MODEL.md §12.3; docs/06-SECURITY-DLP-ACCESS.md §8, §9 and §10 are authoritative
--   for what a rule *is* and what its action means. `ENC-615`.
--
-- `ENC-582` built the modes and `ENC-594` wired the stage; both left the rules behind, because
-- `main.rs` had nowhere to read one from and handed the stage `RuleSet::empty()`. The consequence
-- was exact: `RuleSet::evaluate` returns `NotGoverned` for every action over an empty set, so a
-- tenant on `ENFORCE` was refused exactly as much as one on `DISABLED` — nothing. Rules are
-- **tenant data** (`docs/06 §8` has a security administrator writing detectors and thresholds
-- against their own tenant, and one `enclave.yaml` serves every tenant on a host), so they are rows.
--
-- The detector *set* stays compiled in, where `ENC-582` put it: `crates/dlp/src/builtin.rs` is the
-- vocabulary a rule names, and a tenant-editable detector is the regex Q16 forbids arriving through
-- a different door.
--
-- # Why this is `dlp_rules` and not docs/04 §12's `dlp_policies`
--
-- §12 models a policy with `enabled`, `mode`, `priority`, `scope_type`/`scope_id` and an opaque
-- `definition JSONB`. The same boundary `0019` drew for conditional access, and for the same reason
-- — storing a column the evaluator does not read is storing a promise:
--
--   * **`mode`** — and this one is not a convenience, it is the milestone's structural guarantee.
--     `plans/M4-GOVERNANCE.md` D28 requires `SIMULATION` to be indistinguishable from `ENFORCE`
--     except in its effect, and `crates/dlp` makes that true by *shape*: `RuleSet` holds no mode
--     field and `RuleSet::evaluate` takes no mode argument, so the code that reaches a conclusion
--     has not been told which mode is running and cannot branch on it. A per-rule `mode` column has
--     to be carried on the rule type to be read, which is precisely the field that would make the
--     divergence writable. So the mode is not stored here: it is the deployment's
--     `dlp.default_mode` (`enclave_config::DlpConfig`), read once at start-up. What that costs is
--     recorded rather than hidden — a tenant cannot roll `MONITOR` → `ENFORCE` at its own pace
--     while its neighbour stays behind — and it is `ENC-632`, to be closed by a tenant-level
--     setting that keeps the mode *outside* the rule.
--   * **`enabled`** — a second way to switch a rule off, beside withdrawal, is a second thing to
--     check when asking "why did this not fire". `deleted_at` below is the one answer.
--   * **`scope_type`/`scope_id`** — no rule type has a resource scope. `ActionScope` is a predicate
--     over the *action* (`Any`, `ExposesContent`, `ExternalSharing`, `Exactly`), deliberately, so a
--     rule written as "block export of anything carrying payment data" keeps working when a new
--     content-exposing action is added. A library-scoped rule is a real thing to want and it is not
--     a column that can be added alone: `DlpRule::governs` would have to take the resource. Not
--     stored, so nothing accepts a scope it would then ignore.
--   * **`definition JSONB`** carrying the action — see the `action` column. The action is the part
--     a `CHECK` has to be able to see.
--
-- `priority` is the one of the five that *is* read, and it earns its column: `RuleSet` is ordered
-- and `Verdict::blocking_code` returns the **first** refusal in rule order rather than a computed
-- "strongest", because ranking reason codes would need an ordering nothing else in the codebase
-- has. Order is therefore the administrator's expressed precedence, and a set loaded in whatever
-- order the query plan produced would make the reason code a caller sees non-deterministic. See the
-- column.
--
-- # `action` is a column with a `CHECK`, and `ALLOW` is not in it
--
-- `docs/06 §10` lists `ALLOW` among the thirteen actions — "a rule that fires and does nothing,
-- which exists so an exception can be written above a broader rule". The evaluator that exists does
-- not give it that meaning, and the gap is quiet: `DlpAction::Allow`'s demand is `Nothing`, and
-- `Verdict::blocking_code` scans **past** a `Nothing` to the next fired rule, so an `ALLOW` written
-- above a `BLOCK` does not suppress it. An administrator would write the exception, see it stored,
-- watch it fire, and still be refused.
--
-- That is exactly the failure `0019` refuses for conditional access, so the answer is the same: the
-- string is not in this vocabulary, and PostgreSQL is what makes the absence hold on paths that
-- never went through a Rust enum — psql, a repair script, a future admin API that forgot.
-- `ENC-631` is the row for giving exceptions a meaning; until it lands, an unstorable action is
-- better than one that silently does nothing. Note which way this errs: refusing to store an
-- exception can only *deny* more than the administrator wrote, and it denies loudly, at the moment
-- the rule is written.
--
-- # `reclassify_to` exists because `RECLASSIFY` carries a rank and the others carry nothing
--
-- `DlpAction::Reclassify { to }` is the one action with a payload. A rank hidden inside the
-- conditions document would be an argument the database cannot see, so it is a column, and the
-- `CHECK` ties it to the action in both directions: `RECLASSIFY` without a rank is an obligation
-- with no target, and a rank on any other action is a value nothing reads.
--
-- # Why `enclave_app` gets no `DELETE`
--
-- `0018` withholds it because one statement disables a billing control; `0019` because one
-- statement lifts every network restriction a tenant has. Both apply here — `DELETE FROM dlp_rules`
-- is the shortest statement that stops a tenant's content inspection refusing anything, and it
-- leaves nothing behind to say it ever did. This table has a third reason of its own, and it is the
-- one specific to DLP:
--
-- `docs/06 §9` makes simulation **mandatory** before enforcement for any policy whose effect is
-- `BLOCK` or `QUARANTINE`, and that gate is a query over simulation history that names a rule
-- (`ENC-593`). A record naming a rule that no longer exists cannot answer "has this ever been
-- simulated"; deleting the rule deletes the evidence that the gate is asked for. Withdrawal keeps
-- the row, so the history stays interpretable and a withdrawn rule can be read and reinstated.
--
-- An attacker who reaches the application role can still withdraw every rule a tenant has. This is
-- not a defence against that — it is that they cannot do it without leaving the rows.
--
-- `deleted_at` is also the safe direction if the loader's filter is ever wrong: a withdrawn rule
-- that keeps applying refuses too much, loudly, and somebody complains within the hour. A `DELETE`
-- nobody could see fails the other way.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `migrations/0012_lexical_search_indexes.sql` and `0017` carry the full account. sqlx
-- runs each migration in one transaction and `CONCURRENTLY` cannot run in one. The table is new and
-- empty in every environment that applies this, so there is nothing to lock.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS dlp_rules (
    -- `tenant_id` first, and first in the primary key: rules are tenant data, and every access is
    -- "every live rule for this tenant".
    tenant_id     UUID NOT NULL REFERENCES tenants (id),
    id            UUID NOT NULL,

    -- What an administrator calls it. Echoed in the observation and the operator log, never to the
    -- caller — `ReasonCode` is the whole of what crosses that boundary (`docs/06 §10`).
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),

    -- Rule order, ascending, ties broken by `name` in the loader.
    --
    -- What it decides, precisely: **which reason code a refused caller is shown** when two rules
    -- that both refuse fire on one request, and the order the fired rules appear in the record. It
    -- does *not* decide whether a rule fires — every governing rule whose conditions hold fires,
    -- and every obligation they demand is applied as a union. A rule cannot be shadowed by one
    -- above it, because there is no action that suppresses a later one (see `ALLOW`, above).
    priority      INT NOT NULL DEFAULT 100 CHECK (priority >= 0),

    -- Which actions the rule governs, as a JSON array of `ActionScope`. Opaque to PostgreSQL by
    -- necessity — the vocabulary is a Rust enum — so the structural claims made here are that it is
    -- an array and that it is **not empty**.
    --
    -- The emptiness check is not tidiness. `DlpRule::governs` reads an empty scope as governing
    -- *nothing* (the permissive reading of an empty list is how a mis-migrated row becomes a
    -- tenant-wide block), which is the right default and makes an empty scope a rule that silently
    -- protects nothing. Refusing the row is how an administrator finds out at the moment they write
    -- it rather than during the incident it failed to prevent.
    scope         JSONB NOT NULL CHECK (
                      jsonb_typeof(scope) = 'array' AND jsonb_array_length(scope) > 0),

    -- The conjunctive condition list, as a JSON array of `Condition`. An empty array is legitimate
    -- and means "whenever the action is governed": "block every external share of this library"
    -- needs no detector.
    --
    -- Every condition in that enum is a comparison against a count, a rank, a severity or a score
    -- (Q16). There is no variant a **pattern** could occupy, and decoding is strict and closed, so
    -- a document carrying one is refused by name rather than having the clause dropped. That is
    -- what stops storage becoming the door regex walks in through — `crates/dlp/src/store.rs`.
    conditions    JSONB NOT NULL CHECK (jsonb_typeof(conditions) = 'array'),

    -- What the rule demands when it fires. `docs/06 §10`'s vocabulary, minus `ALLOW` — see the
    -- header. The strings are `DlpAction::as_str`'s exactly; a second spelling would guarantee a
    -- mismatch whose symptom is "the rule stopped working".
    action        TEXT NOT NULL CHECK (action IN (
                      'AUDIT',
                      'WARN',
                      'REQUIRE_JUSTIFICATION',
                      'REQUIRE_APPROVAL',
                      'BLOCK',
                      'QUARANTINE',
                      'REMOVE_SHARE',
                      'READ_ONLY',
                      'NO_DOWNLOAD',
                      'WATERMARK',
                      'RECLASSIFY',
                      'NOTIFY_SECURITY')),

    -- The rank `RECLASSIFY` raises the resource to, and nothing otherwise. Tied to the action in
    -- both directions: a `RECLASSIFY` with no rank is an obligation with no target, and a rank on
    -- any other action is a value nothing reads.
    reclassify_to INT CHECK (reclassify_to IS NULL OR reclassify_to >= 0),

    -- Who wrote it. `NOT NULL`: a rule that refuses people is a rule somebody is accountable for.
    created_by    UUID NOT NULL,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Withdrawal, which is what this deployment has instead of `DELETE`. See the header.
    deleted_at    TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, id),

    -- The rank and the action agree, in both directions. Written as a table constraint so it can
    -- name itself: a violation an administrator meets in a log line reads
    -- `dlp_rules_reclassify_target` rather than `dlp_rules_check1`.
    CONSTRAINT dlp_rules_reclassify_target
        CHECK ((action = 'RECLASSIFY') = (reclassify_to IS NOT NULL)),

    -- `CLAUDE.md` rule 4 and docs/04 §3.3: a foreign key between two tenant-scoped tables carries
    -- `tenant_id`, because PostgreSQL runs referential-integrity checks with row security
    -- deliberately *not* enforced — a single-column `REFERENCES users (id)` would happily accept
    -- another tenant's user as the author of this tenant's rule. The `UNIQUE (tenant_id, id)` this
    -- names on `users` arrives in `0016_composite_auth_keys.sql`.
    CONSTRAINT dlp_rules_author_fkey
        FOREIGN KEY (tenant_id, created_by) REFERENCES users (tenant_id, id)
);

-- One live rule per name, per tenant. The name is what an operator reads in an observation and in a
-- simulation report; two live rules sharing one would make both ambiguous at exactly the moment
-- somebody is working out which rule refused a colleague's download. Withdrawn rows are outside the
-- index, so a name can be reused after the rule it belonged to is withdrawn.
--
-- It is also the tie-break in the loader's `ORDER BY priority, name`: unique among live rules means
-- the ordering is total, so two replicas evaluating the same rules cannot disagree about which
-- refusal a caller is shown.
CREATE UNIQUE INDEX IF NOT EXISTS uq_dlp_rules_live_name
    ON dlp_rules (tenant_id, name)
    WHERE deleted_at IS NULL;

-- The load path: every live rule for one tenant, in evaluation order. Leads with `tenant_id` and
-- carries the sort, so the order the reason code depends on comes out of the index rather than out
-- of a sort node whose stability nobody has promised.
CREATE INDEX IF NOT EXISTS idx_dlp_rules_live
    ON dlp_rules (tenant_id, priority, name)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE dlp_rules IS
    'Stored DLP rules (docs/04 §12.3, docs/06 §8-§10, ENC-615). One row per rule. There is deliberately no mode column: the mode lives outside the rule set so that RuleSet::evaluate can take no mode argument, which is what makes SIMULATION and ENFORCE structurally unable to diverge (M4 D28).';

COMMENT ON COLUMN dlp_rules.priority IS
    'Rule order, ascending, ties broken by name. Decides which reason code a refused caller sees when two refusing rules fire, and the order fired rules are recorded in. It does not decide whether a rule fires, and no action suppresses a later one.';

COMMENT ON COLUMN dlp_rules.action IS
    'docs/06 §10, minus ALLOW: DlpAction::Allow demands Nothing and Verdict::blocking_code scans past it to the next refusal, so an ALLOW written above a BLOCK would be an exception that fires and changes nothing (ENC-631).';

COMMENT ON COLUMN dlp_rules.conditions IS
    'Comparisons against counts, ranks, severities and scores only (Q16). No variant of Condition can hold a pattern, and decoding is strict, so a stored rule cannot smuggle a regex onto the synchronous path.';

COMMENT ON COLUMN dlp_rules.deleted_at IS
    'Withdrawal. enclave_app holds no DELETE on this table: one DELETE stops a tenant''s content inspection refusing anything and leaves nothing to say it did, and it would delete the rule that docs/06 §9''s mandatory-simulation gate has to query the history of.';

-- Row-level security: enabled, forced, and a policy — docs/04 §3.2, CLAUDE.md rule 4. Forced is not
-- ceremony: these rows decide what may leave a tenant, and a role that could read one tenant's
-- could write another's.
ALTER TABLE dlp_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE dlp_rules FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON dlp_rules
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migration 0003's catalog loop has already run and will not run again, so a table created after it
-- and not granted here is one the application role cannot see at all — which is how, before
-- ENC-124, every isolation test in the workspace passed with isolation switched off.
--
-- `SELECT, INSERT, UPDATE` and deliberately **no `DELETE`**: see the header.
GRANT SELECT, INSERT, UPDATE ON dlp_rules TO enclave_app;
