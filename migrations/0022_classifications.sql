-- 0022 — `classifications`: the tenant-defined labels a rank is resolved from.
--   docs/04-DATA-MODEL.md §12 and §12.4; docs/01-PRD.md §22 for the shipped label set;
--   docs/06-SECURITY-DLP-ACCESS.md §12.1 for what a rank decides. `ENC-574`, closing `ENC-614`.
--
-- Three things in this codebase take a `ClassificationRank` and none of them could ever be given
-- one, because the table it comes out of was created by no migration:
--
--   1. `FactsPolicy::is_forced_closed` compares the resource's *current* label against the tenant's
--      `dlp.restricted_at`. `ENC-591` moved that rank onto `FactsSnapshot` precisely so that D27's
--      mandatory `FAIL_CLOSED` fires on a `RESTRICTED` document **nobody has scanned** — and
--      `enclave_dlp::PgSecurityFacts` has passed `None` for it since the day it was written, so
--      under `FAIL_OPEN_AUDIT` an unscanned `RESTRICTED` document was permitted while its label sat
--      in the database. That is `ENC-614`.
--   2. `enclave_worker::indexing::FileClassification` refuses every document, so no deployment that
--      wires the vector stage embeds anything (`ENC-557`).
--   3. `security_facts.classification_rank` is an `INT` rather than a foreign key, recorded in
--      `docs/04 §12.2` as a deviation forced by this table's absence (`ENC-594`).
--
-- # Why the label is a row and the rank is an integer
--
-- `enclave_core::ClassificationRank`'s own documentation: *"labels are tenant-defined — one
-- tenant's `CONFIDENTIAL` is another's `INTERNAL_RESTRICTED` — while the ordering is the part
-- policy actually reasons about"*. So the vocabulary is rows (a tenant may ship five labels or
-- nine, and name them in its own language), and everything that compares compares `rank`.
-- `ClassificationRank::RESTRICTED = 50` stays what it says it is — a starting value, not a truth —
-- and `FactsPolicy::from_tenant_config` keeps taking `restricted_at` as a parameter. Nothing in
-- this migration assumes 10/20/30/40/50; the `CHECK` is `rank >= 0` and the ordering is whatever
-- the tenant wrote.
--
-- # `rank` is `UNIQUE` per tenant among live labels, and that is a control rather than tidiness
--
-- Two live labels at one rank are two names for one policy outcome. Every comparison in the
-- codebase is `>=` against a rank, so the pair is indistinguishable to policy while being
-- distinguishable to an administrator — which is the exact shape of "I moved the file to
-- `CONFIDENTIAL-EXTERNAL` and nothing changed". Refusing the second row is how they find out when
-- they write it.
--
-- # Why `enclave_app` gets no `DELETE`
--
-- `0018` withholds it because one statement disables a billing control, `0019` because one
-- statement lifts every network restriction a tenant has, `0021` because one statement stops
-- content inspection refusing anything. Each argued it on its own grounds; here is this table's,
-- and it is not either of those.
--
-- **Deleting a label declassifies content in bulk, silently, and the ranks it already produced stop
-- being interpretable.** The composite keys below are `ON DELETE RESTRICT` (the default) rather
-- than `CASCADE`, so a `DELETE` of a label in use is refused by PostgreSQL — the important half.
-- But a label that is *not* currently on any file can still be deleted, and there are two reasons
-- not to allow even that. `security_facts.classification_rank` and the `classification_rank` field
-- in the vector collection are **copies of `rank` taken at scan time**; they are not foreign keys
-- and no `RESTRICT` protects them, so after the row is gone a stored `40` names nothing and no one
-- can say what it meant. And a `DELETE` leaves nothing behind to say the label ever existed, which
-- is precisely what an operator reconstructing why a document was permitted needs.
--
-- Withdrawal — `deleted_at` — is what this deployment has instead. It stops the label being
-- *assigned* to anything new (`uq_classifications_live_key` and the loader's filter) and changes
-- nothing about what it means for content already carrying it. See the resolver note below, which
-- is the half of this that is easy to get backwards.
--
-- # A withdrawn label still resolves, deliberately
--
-- `enclave_db::classifications`' walk joins `classifications` **without** a `deleted_at IS NULL`
-- filter. That looks like an omission and is the point: if withdrawal stopped a label resolving,
-- withdrawing `RESTRICTED` would declassify every document carrying it in one statement — the same
-- bulk, silent declassification the missing `DELETE` grant exists to prevent, reached through the
-- door that *is* granted. Withdrawal governs assignment; it does not govern meaning.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `0012` and `0017` carry the full account. sqlx runs each migration in one transaction
-- and `CONCURRENTLY` cannot run in one. The table is new and empty in every environment that
-- applies this.
--
-- # The four `ALTER TABLE`s take `ACCESS EXCLUSIVE`, and the honest form is the simple one
--
-- `CLAUDE.md`'s SQL conventions say no long `ACCESS EXCLUSIVE` locks on populated tables, and
-- `files` is the most populated table in the schema. The usual answer is `ADD CONSTRAINT … NOT
-- VALID` followed by `VALIDATE CONSTRAINT`, which moves the scan under a `SHARE UPDATE EXCLUSIVE`
-- lock. It buys nothing here and claiming otherwise would be worse than not doing it: sqlx wraps
-- each migration in **one transaction**, so the `ACCESS EXCLUSIVE` the `ADD` takes is held until
-- commit whether the scan happens inside it or not. What actually bounds the cost is that the four
-- columns being keyed have never been written by anything — `files.classification_id`,
-- `libraries.default_classification_id`, `workspaces.default_classification_id` and
-- `content_types.default_classification_id` are `NULL` in every row of every environment that will
-- apply this, and a foreign-key validation scan over an all-`NULL` column matches nothing. If that
-- ever stops being true, this migration is the wrong shape and a two-release expand-then-contract
-- is the right one.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS classifications (
    -- `tenant_id` first, and first in the primary key: labels are tenant vocabulary, and every
    -- access is "this tenant's labels" or "this tenant's label with this id".
    tenant_id   UUID NOT NULL REFERENCES tenants (id),
    id          UUID NOT NULL,

    -- The stable identifier policy and imports name — `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, … — as
    -- docs/04 §12 models it. Deliberately **not** a `CHECK` over the five shipped names: the label
    -- set is tenant-defined, and a vocabulary constraint here would be the one place a tenant with
    -- six labels could not express its sixth.
    key         TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 100),

    -- What a person sees. Separate from `key` because the display form is localised and renamed and
    -- the identifier is neither.
    label       TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 200),

    -- The ordinal every comparison in the codebase is made against. Higher is more sensitive.
    --
    -- `>= 0` and no upper bound: the lower bound is what makes the `INT`→`i32`→`ClassificationRank`
    -- round trip carry a meaning (a negative rank would compare below every ceiling, which is the
    -- direction that leaks), and an upper bound would be this file inventing a ceiling for a scale
    -- it just said was the tenant's.
    rank        INT NOT NULL CHECK (rank >= 0),

    -- Presentation. Nothing policy reads.
    color       TEXT CHECK (color IS NULL OR length(color) BETWEEN 1 AND 32),

    -- The obligations docs/04 §12 attaches to a label. Stored because they are the label's
    -- definition rather than a rule about it; nothing evaluates them yet, and the row that gives
    -- them effect in the classification stage is `ENC-657`. They are booleans with a safe default
    -- rather than a nullable tri-state, so "not configured" is one value and not two.
    watermark_required     BOOLEAN NOT NULL DEFAULT FALSE,
    download_restricted    BOOLEAN NOT NULL DEFAULT FALSE,
    external_share_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    sync_blocked           BOOLEAN NOT NULL DEFAULT FALSE,

    -- Which embedding providers may see text at this label (docs/07 §3). The `CHECK` is a closed
    -- vocabulary here and not on `key` above, and the difference is which side of the boundary the
    -- value decides: `key` is a tenant's name for something, `embedding_policy` is an instruction to
    -- a router that sends text off-network. An unrecognised value read by that router is S8's
    -- failure — `NO_INDEX` misspelt as `NOINDEX` is a document that gets indexed.
    embedding_policy TEXT NOT NULL DEFAULT 'ANY'
                     CHECK (embedding_policy IN ('ANY','APPROVED_ONLY','LOCAL_ONLY','NO_INDEX')),

    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Withdrawal, which is what this deployment has instead of `DELETE`. See the header, and note
    -- that it does **not** stop the label resolving for content already carrying it.
    deleted_at  TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, id)
);

COMMENT ON CONSTRAINT classifications_pkey ON classifications IS
    'Also the target of every composite foreign key into this table (docs/04 §3.3): a two-column key cannot match a label belonging to another tenant.';

-- One live label per key, and one live label per rank, per tenant. Partial on `deleted_at` so a
-- withdrawn label frees both its name and its position — a tenant that renames `CONFIDENTIAL` to
-- `SENSITIVE` withdraws one row and writes another at the same rank.
CREATE UNIQUE INDEX IF NOT EXISTS uq_classifications_live_key
    ON classifications (tenant_id, key)
    WHERE deleted_at IS NULL;

-- See the header: two live labels at one rank are two names for one policy outcome, and policy
-- cannot tell them apart while an administrator can.
CREATE UNIQUE INDEX IF NOT EXISTS uq_classifications_live_rank
    ON classifications (tenant_id, rank)
    WHERE deleted_at IS NULL;

-- The admin list path: a tenant's live labels in ordinal order, which is the order they are shown
-- in and the order `restricted_at` is chosen from.
CREATE INDEX IF NOT EXISTS idx_classifications_live
    ON classifications (tenant_id, rank)
    WHERE deleted_at IS NULL;

COMMENT ON TABLE classifications IS
    'The tenant-defined label set (docs/04 §12, §12.4, ENC-574). Comparisons are against rank, never key: labels are tenant vocabulary and the ordering is the part policy reasons about. enclave_app holds no DELETE — deleting a label declassifies content in bulk and orphans every rank already copied into security_facts and the vector collection.';

COMMENT ON COLUMN classifications.rank IS
    'The ordinal policy compares. Higher is more sensitive. Tenant-defined: nothing in the schema assumes the shipped 10/20/30/40/50, and FactsPolicy takes restricted_at as configuration rather than as a constant.';

COMMENT ON COLUMN classifications.deleted_at IS
    'Withdrawal. It stops the label being assigned to anything new; it deliberately does not stop it resolving for content already carrying it, because a withdrawal that declassified in bulk would be the DELETE this table refuses to grant, through the door that is granted.';

COMMENT ON COLUMN classifications.embedding_policy IS
    'Which embedding providers may see text at this label (docs/07 §3). A closed vocabulary because an unrecognised value is read by a router that sends text off-network, where NO_INDEX misspelt is a document that gets indexed.';

-- -------------------------------------------------------------------------------------------------
-- The four references docs/04 already models, made composite — CLAUDE.md rule 4, docs/04 §3.3.
--
-- Every one of these columns has existed since 0004/0005 with no foreign key at all, because the
-- table they point at did not exist. A single-column `REFERENCES classifications (id)` would be
-- worse than none: PostgreSQL runs referential-integrity checks with row security deliberately
-- *not* enforced, so it would happily accept **another tenant's** label on this tenant's file —
-- and the resolver would then read that label's rank and hand it to a policy decision. The
-- two-column form cannot match a row whose `tenant_id` differs, because the tuple does not match.
--
-- `MATCH SIMPLE` (the default) is what makes the nullable case work: a row with a `NULL`
-- classification satisfies the constraint without a lookup, which is the ordinary state of every
-- file in the system.
-- -------------------------------------------------------------------------------------------------

ALTER TABLE files
    ADD CONSTRAINT files_classification_fkey
    FOREIGN KEY (tenant_id, classification_id) REFERENCES classifications (tenant_id, id);

ALTER TABLE libraries
    ADD CONSTRAINT libraries_default_classification_fkey
    FOREIGN KEY (tenant_id, default_classification_id) REFERENCES classifications (tenant_id, id);

ALTER TABLE workspaces
    ADD CONSTRAINT workspaces_default_classification_fkey
    FOREIGN KEY (tenant_id, default_classification_id) REFERENCES classifications (tenant_id, id);

ALTER TABLE content_types
    ADD CONSTRAINT content_types_default_classification_fkey
    FOREIGN KEY (tenant_id, default_classification_id) REFERENCES classifications (tenant_id, id);

COMMENT ON CONSTRAINT files_classification_fkey ON files IS
    'Composite so another tenant''s label cannot be attached to this tenant''s file: RI checks run with row security not enforced, so a single-column key would accept one (docs/04 §3.3).';

-- `idx_files_class` (docs/04 §8, created in 0005) already covers `(tenant_id, classification_id)`,
-- which is the index the resolver's join and this key's own lookups want. Nothing further is needed
-- on `files`.

-- Row-level security: enabled, forced, and a policy — docs/04 §3.2, CLAUDE.md rule 4. `FORCE` is
-- load-bearing here in a way worth naming: these rows are the definition of how sensitive a
-- tenant's content is, so a role that could read one tenant's label set could write another's — and
-- writing a rank is how a `RESTRICTED` document becomes a `PUBLIC` one without anything touching
-- the document.
ALTER TABLE classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE classifications FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON classifications
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migration 0003's catalog loop has already run and will not run again, so a table created after it
-- and not granted here is one the application role cannot see at all — which is how, before
-- ENC-124, every isolation test in the workspace passed with isolation switched off.
--
-- `SELECT, INSERT, UPDATE` and deliberately **no `DELETE`**: see the header. Withdrawal is an
-- `UPDATE`.
GRANT SELECT, INSERT, UPDATE ON classifications TO enclave_app;
