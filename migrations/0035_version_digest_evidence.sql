-- =================================================================================================
-- 0035 — who confirmed a version's whole-object SHA-256, and when.
--
-- `ENC-829`. `ENC-820` made `file_versions.checksum_sha256` mean *"the object store computed this
-- digest over the bytes it holds and it matched"*. That is the right meaning and it cost the
-- product every upload above 16 MiB: above `multipart_threshold_bytes` the S3 backend sends a
-- multipart upload, and what S3 and MinIO compute for one is a **composite** checksum — base64 of
-- the SHA-256 of the concatenated part digests, with a `-N` suffix — which is not the whole-object
-- digest and cannot be compared with one. With nothing able to confirm the client's value, the only
-- honest answer available was to refuse the session, and that is what shipped.
--
-- AWS's `FULL_OBJECT` checksum type would close it on AWS. It does not close it here: probed on
-- 2026-09-09 against both `RELEASE.2025-04-22` (the pinned image) and `RELEASE.2025-09-07` (the
-- current one), MinIO answers `InvalidArgument: Invalid checksum provided.` So an AWS-only fix
-- leaves the default self-hosted deployment refusing every large upload.
--
-- ## The third thing that reads every byte
--
-- The antivirus pass already streams the whole of every version — it must, because a header-only
-- scan is exactly the shortcut `CLAUDE.md` rule 9 exists to prevent. Hashing while those bytes go
-- past costs one `Sha256::update` per chunk and no additional read, and it produces the one number
-- the object store could not: the SHA-256 of the whole object.
--
-- So the confirmation moves in time rather than disappearing. The client's digest is recorded at
-- commit exactly as before; what changes is *when* it becomes evidence, and this column is the
-- product being explicit about that difference instead of leaving a reader to assume.
--
-- ## Four states, and why `UNCONFIRMED` is not simply `NULL`
--
--   PROVIDER     the object store hashed the body it received and it matched — a single-shot
--                upload with `x-amz-checksum-sha256` signed into the URL (`ENC-820`).
--   ANTIVIRUS    the antivirus pass hashed every byte of the stored object and it matched.
--   UNCONFIRMED  the digest is the client's declaration and nothing has checked it yet.
--   MISMATCH     something hashed the stored bytes and got a different answer.
--
-- `MISMATCH` is why this is a state and not a nullable timestamp. *"Nobody has checked"* and
-- *"somebody checked and the bytes are not what was declared"* are opposite facts, and a schema in
-- which they are both `NULL` cannot tell an operator which one it is looking at. A version in
-- `MISMATCH` is quarantined by the pass that found it, for the same reason an infected one is: the
-- stored object is not the object the uploader vouched for, and nothing downstream — a retention
-- record, an audit entry, a signature — that quotes its digest is true of it.
--
-- ## `PROVIDER` for every existing row, and why that is a fact rather than a convenience
--
-- Every version row written before this migration passed through `VerifiedContent::verify`, which
-- **cannot be constructed** unless the store returned a whole-object digest that matched the
-- client's (`crates/uploads/src/content.rs`, `ENC-820`), and every multipart session was refused
-- outright. So `PROVIDER` is what the whole existing corpus is, not a value chosen to keep it
-- readable. There is no row this could be wrong about, because the state it would be wrong about
-- could not be created.
--
-- The `DEFAULT` is then dropped: new rows must say which state they are in. The commit statement in
-- `crates/versions/src/commit.rs` binds it explicitly and a unit test asserts that it does, so a
-- future `INSERT` that forgets the column fails loudly instead of quietly claiming that an object
-- store vouched for bytes it never saw.
--
-- ## The constraint is the part that cannot be routed around
--
-- `file_versions_available_digest_is_confirmed` is what makes this structural rather than a habit.
-- The antivirus pass will not publish a version whose digest is unconfirmed — that decision lives
-- in `Target::of`, in one function with one test — but a decision in one function is one refactor
-- away from being lost, and `AVAILABLE` is the value `CLAUDE.md` rule 9 is about. With the
-- constraint in place a build that regresses cannot leak: it fails the `UPDATE` with a `23514` an
-- operator can read, which is a loud failure rather than a served object nobody hashed.
--
-- `NOT VALID` then `VALIDATE`: the `ADD` is then O(1) under a brief `ACCESS EXCLUSIVE`, and the
-- table scan that proves the existing rows runs under `SHARE UPDATE EXCLUSIVE`, which does not
-- block writers. A plain `ADD CONSTRAINT` would hold `ACCESS EXCLUSIVE` for the whole scan of a
-- table that holds every version of every file ever written.
--
-- No new table, so no new RLS policy and no new grant: `file_versions` already has row-level
-- security enabled and forced, a `tenant_isolation` policy, and `UPDATE` granted to `enclave_app`
-- for exactly this class of governance column (`migrations/0006`). No index either — every query
-- that reads these columns already names a specific version, and the antivirus queue is selected by
-- `av_status`, which is unchanged.
-- =================================================================================================

ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS digest_state TEXT NOT NULL DEFAULT 'PROVIDER'
        CHECK (digest_state IN ('PROVIDER','ANTIVIRUS','UNCONFIRMED','MISMATCH'));

ALTER TABLE file_versions
    ALTER COLUMN digest_state DROP DEFAULT;

-- When the state last became one of the three settled ones. NULL exactly when `UNCONFIRMED`.
--
-- Left NULL for the existing corpus rather than set to this migration's clock: those digests were
-- confirmed when their uploads completed, and `now()` here would be a fabricated observation of an
-- event that happened months ago. The state is the load-bearing half; this is for the operator
-- asking how long a confirmation took to arrive.
ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS digest_verified_at TIMESTAMPTZ;

ALTER TABLE file_versions
    DROP CONSTRAINT IF EXISTS file_versions_available_digest_is_confirmed;
ALTER TABLE file_versions
    ADD CONSTRAINT file_versions_available_digest_is_confirmed
        CHECK (status <> 'AVAILABLE' OR digest_state IN ('PROVIDER','ANTIVIRUS'))
        NOT VALID;
ALTER TABLE file_versions
    VALIDATE CONSTRAINT file_versions_available_digest_is_confirmed;

COMMENT ON COLUMN file_versions.digest_state IS
    'Who confirmed checksum_sha256 against the stored bytes (ENC-829). PROVIDER: the object store, at upload. ANTIVIRUS: the worker pass, while streaming every byte. UNCONFIRMED: nobody yet — the client''s declaration, which no read path serves. MISMATCH: the bytes hash to something else, and the version is quarantined for it.';

COMMENT ON COLUMN file_versions.digest_verified_at IS
    'When digest_state last became settled. NULL exactly when UNCONFIRMED, and NULL for every row written before ENC-829, whose digests were confirmed at upload by a clock this migration does not have.';
