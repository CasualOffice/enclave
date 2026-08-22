-- 0020 — `security_facts`: what a completed asynchronous scan concluded about one version.
--   docs/04-DATA-MODEL.md §12 and §12.2; docs/06-SECURITY-DLP-ACCESS.md §12 is authoritative for
--   what the facts *mean*. `ENC-594`.
--
-- `ENC-581` gave the chain a `SecurityFacts` and `ENC-582` threaded a `FactsSnapshot` through it,
-- and neither could read one: there was no table, so `crates/api/src/main.rs` ran on
-- `enclave_core::stub::NoSecurityFacts`, which reports every resource as unscanned. That stub leans
-- in the safe direction — under the `FAIL_CLOSED` default an unscanned resource is refused, loudly
-- — but it refuses for the wrong reason, and a deployment cannot tell "no scanner has run" from
-- "the reader is missing".
--
-- # Counts, never content — and this table is where that has to be enforced rather than intended
--
-- `CLAUDE.md` rule 10 forbids DLP match values in anything that is logged or stored for a decision.
-- `enclave_core::SecurityFacts` honours it structurally: it has no field a matched value could
-- occupy, which is why deriving `Debug` and `Serialize` on it is safe rather than an oversight, and
-- why `crates/dlp`'s `Candidate` renders `<candidate withheld>`.
--
-- A table can lose that property in a way a Rust type cannot, because a `JSONB` column will hold
-- anything. So every column here is a count, a rank, a score, a version or a timestamp, and the one
-- column of §12 that is none of those is deliberately **not created** — see the deviation below.
--
-- # Three deviations from docs/04 §12, each recorded in §12.2 rather than left to be discovered
--
--   1. **No `detector_results JSONB`.** §12 models a per-detector breakdown as an opaque document.
--      Nothing reads one: a synchronous decision compares category counts, a severity, a risk score
--      and a rank (`enclave_dlp::policy::Condition` has no other shape of variant, by Q16). What an
--      opaque `results` document *is*, in practice, is the first place a future scanner writes the
--      string it matched — and once it does, every backup, replica and support export carries card
--      numbers. An absent column cannot be filled in by accident. When a per-detector breakdown is
--      genuinely needed it arrives as its own migration, with its own argument about what may go in
--      it, which is a conversation worth forcing.
--   2. **`classification_rank INT`, not `classification_id UUID`.** The decision compares *ranks*
--      (`ClassificationRank`), `classifications` does not exist as a table in this schema yet, and a
--      UUID pointing at nothing is a column no code can interpret and no foreign key can protect.
--      A rank is the value the comparison needs. When `classifications` lands, an id column can be
--      added beside this one and back-filled — expand-then-contract, in that migration.
--   3. **The counts carry `CHECK (… >= 0)`.** `DetectorCounts` holds `u32`; PostgreSQL's `INT` is
--      signed. Without the constraint a negative row would be read back as a `u32` near four
--      billion — a document that "carries two billion card numbers" and fires every threshold rule
--      in the tenant. The `CHECK` is what makes the conversion in `enclave_db::security_facts`
--      total rather than hopeful.
--
-- # Freshness is equality against the active detector set, and this column is why
--
-- `detector_set_version` is opaque `TEXT` — somebody else's build identifier. `docs/06 §12` says
-- facts are unusable when their version is "older than the active one", and `ENC-581` deliberately
-- implements that as **equality**, because any ordering we invented over that string would fail
-- one-directionally: a version that sorts unexpectedly high reads as *fresh*, and stale facts then
-- decide a request that believes it saw the current rules. So there is no ordering here, no
-- `CHECK` that pretends to parse it, and no index that would tempt a range scan over it. The only
-- comparison anything makes is `=`.
--
-- `scan_version` is the other version and answers a different question: the generation of the
-- *pipeline* (extraction, OCR) rather than of the rules. `idx_facts_stale` indexes it so a backfill
-- can find what a pipeline change invalidated. No decision reads it.
--
-- # Why `enclave_app` gets no `DELETE`, and what the cascade is for
--
-- `0018` and `0019` withhold `DELETE` because one statement disables a control while leaving every
-- gate in this repository green. The argument here is the same with the direction reversed, and it
-- is worth stating precisely: deleting a fact row does not make content *look* clean — the counts
-- do not become zero, the resource becomes **unscanned** — so under `FAIL_CLOSED` it denies and is
-- loud. Under `FAIL_OPEN_AUDIT` it permits with a high-visibility audit event. Neither is a silent
-- escalation, and that is what makes withholding `DELETE` an easy call rather than a hard one: the
-- statement has no legitimate use. A rescan **replaces** (`INSERT … ON CONFLICT DO UPDATE`), which
-- is why `UPDATE` is granted and `DELETE` is not.
--
-- What does remove a fact row is the content it describes going away: `ON DELETE CASCADE` on the
-- version key, exactly as `0007`'s renditions. Facts about a purged version would be facts about
-- nothing, and referential actions run with the constraint owner's privileges, so the purge job
-- keeps working without the application role ever holding `DELETE` on this table.
--
-- # Nothing writes these rows yet, and the absence is safe in both configured directions
--
-- `enclave_db::security_facts::record_facts` is the statement a scanner will call; no binary calls
-- it today (`ENC-613`). With no rows every version is unscanned, which is *true*, and what it means
-- is the tenant's `dlp.facts_unavailable` policy's to say: `FAIL_CLOSED` refuses the governed
-- action and explains that scanning is in progress, `FAIL_OPEN_AUDIT` permits and records. Both are
-- correct behaviour for a deployment whose scanner has not run, rather than an accident of a
-- missing writer — and `crates/dlp/tests/stored_facts.rs` asserts both.
--
-- # Plain `CREATE INDEX`, no `CONCURRENTLY`
--
-- `ENC-517`; `0012` and `0017` carry the full account. sqlx runs each migration in one transaction
-- and `CONCURRENTLY` cannot run inside one. The table is new and empty everywhere this applies.
--
-- Forward-only: a new migration, never an edit to an applied one.

CREATE TABLE IF NOT EXISTS security_facts (
    -- `tenant_id` first, and first in the primary key: facts are tenant data, and every read is
    -- "the facts for this tenant's version".
    tenant_id            UUID NOT NULL REFERENCES tenants (id),

    -- Both keys are carried, though `version_id` alone identifies the row. `file_id` is what the
    -- chain has when the action names a file rather than a version, and the alternative — joining
    -- `file_versions` on every request to learn it — is a second read on the synchronous path for a
    -- column that never changes.
    file_id              UUID NOT NULL,

    -- Facts are per **version**, never per file. A new version is unscanned content even though the
    -- file has been scanned many times before, and a row keyed by file would answer the question
    -- about the bytes somebody uploaded last week.
    version_id           UUID NOT NULL,

    -- The four categories of `enclave_core::DetectorCategory`, matching §12's four columns. Policy
    -- is written against categories rather than detectors so that adding a second card detector
    -- does not silently change what a rule about payment data means.
    pii_count            INT NOT NULL DEFAULT 0 CHECK (pii_count       >= 0),
    secret_count         INT NOT NULL DEFAULT 0 CHECK (secret_count    >= 0),
    financial_count      INT NOT NULL DEFAULT 0 CHECK (financial_count >= 0),
    health_count         INT NOT NULL DEFAULT 0 CHECK (health_count    >= 0),

    -- The most serious finding, in `enclave_core::Severity`'s spelling exactly. `NULL` means the
    -- scan attached no severity, which is the ordinary case for a clean document — and is not the
    -- same as `LOW`.
    max_severity         TEXT CHECK (max_severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),

    -- The composite risk signal, on §12's `0..=100` scale. The `CHECK` matches `RiskScore`, which
    -- clamps rather than rejecting: an out-of-range score is a scorer defect, and discarding exact
    -- counts to punish an inexact estimate would be the wrong trade.
    risk_score           INT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),

    -- The classification the **scan** resolved, if it resolved one. Deliberately not the label the
    -- resource carries: that is read from the resource in the same breath as these facts
    -- (`ResourceState`, `docs/06 §12.1`), because the mandatory `RESTRICTED` escalation must fire
    -- on a document *nobody has scanned* — asking the scan for the rank leaves the escalation dead
    -- in exactly the case it exists for (`ENC-591`).
    classification_rank  INT,

    -- The generation of the scanning pipeline. Indexed below so a backfill can find what a pipeline
    -- change invalidated; no decision reads it.
    scan_version         INT NOT NULL,

    -- Which detector set produced this row. Compared with `=` and nothing else — see the header.
    -- The length bound is a sanity bound on an opaque identifier, not a vocabulary: an empty string
    -- is refused because it is not a build identifier, and it would be a value that quietly matches
    -- a misconfigured deployment's idea of "the active set".
    detector_set_version TEXT NOT NULL CHECK (length(detector_set_version) BETWEEN 1 AND 200),

    scanned_at           TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (tenant_id, file_id, version_id),

    -- `CLAUDE.md` rule 4 and docs/04 §3.3: a foreign key between two tenant-scoped tables carries
    -- `tenant_id`, because PostgreSQL runs referential-integrity checks with row security
    -- deliberately *not* enforced — a single-column `REFERENCES file_versions (id)` would accept
    -- another tenant's version as the subject of these facts, and the facts of one tenant's
    -- document would then decide another tenant's request.
    CONSTRAINT security_facts_file_fkey
        FOREIGN KEY (tenant_id, file_id) REFERENCES files (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT security_facts_version_fkey
        FOREIGN KEY (tenant_id, version_id) REFERENCES file_versions (tenant_id, id)
        ON DELETE CASCADE
);

-- docs/04 §12's index, for the backfill a pipeline change requires: "which of this tenant's rows
-- were produced by a generation older than the one running now". `scan_version` is an `INT`, so an
-- ordering over it is meaningful — which is precisely what `detector_set_version` is not, and why
-- only one of the two is indexed.
CREATE INDEX IF NOT EXISTS idx_facts_stale ON security_facts (tenant_id, scan_version);

COMMENT ON TABLE security_facts IS
    'What a completed asynchronous scan concluded about one version (docs/04 §12, §12.2, docs/06 §12, ENC-594). Counts, ranks, scores and versions only: there is deliberately no column a matched value could occupy (CLAUDE.md rule 10).';

COMMENT ON COLUMN security_facts.detector_set_version IS
    'Which detector set produced this row. Compared for equality with the active set and never ordered: the column is an opaque build identifier, and an invented ordering fails one-directionally — a version sorting unexpectedly high reads as fresh, so stale facts decide a request that believes it saw the current rules (ENC-581).';

COMMENT ON COLUMN security_facts.classification_rank IS
    'The rank the scan resolved, if any. The rank the mandatory FAIL_CLOSED escalation compares against comes from the resource instead, read in the same breath as these facts — a label does not wait for a scanner (docs/06 §12.1, ENC-591).';

-- Row-level security: enabled, forced, and a policy — docs/04 §3.2, CLAUDE.md rule 4. Forced
-- matters here as much as anywhere in the schema: these rows are the evidence a DLP decision is
-- taken from, so a role that could read one tenant's could decide another tenant's requests.
ALTER TABLE security_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_facts FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON security_facts
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- Migration 0003's catalog loop has already run and will not run again, so a table created after it
-- and not granted here is one the application role cannot see at all — which is how, before
-- ENC-124, every isolation test in the workspace passed with isolation switched off.
--
-- `SELECT, INSERT, UPDATE` and deliberately **no `DELETE`**: see the header. A rescan replaces.
GRANT SELECT, INSERT, UPDATE ON security_facts TO enclave_app;
