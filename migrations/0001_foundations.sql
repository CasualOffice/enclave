-- 0001_foundations.sql
--
-- Enclave migration 001 — tenancy, identity, credentials, auth tokens, devices,
-- audit, outbox, idempotency.
--
-- Authoritative source for every statement below: docs/04-DATA-MODEL.md
--   §4  Tenancy          §5  Identity        §6  Authentication tokens
--   §14 Audit            §17 Platform
-- DDL is taken verbatim from that document. Where a statement had to be changed to
-- be accepted by PostgreSQL at all, the change is marked `DEVIATION` with the reason;
-- docs/04 is authoritative and must be amended before this file is considered settled.
--
-- Ordering matters: roles → extensions → tables → partitions → ownership.
-- Row-level security, policies and role grants are in 0002_rls_policies.sql, which
-- must be applied in the same deployment (docs/04 §3.2, M0 plan D4).
--
-- Forward-only. There is no down-migration by design (docs/11-OPERATIONS.md §8): a
-- rollback of a schema change is a new numbered migration, so that what ran in
-- production is always reconstructible from the numbered sequence alone.
--
-- Re-runnable: every statement is guarded, so a partially-applied migration can be
-- re-applied without hand repair. That is a recovery property, not permission to edit
-- this file after it has shipped — edits change the checksum and are rejected.
--
-- Applying role: superuser, or a role with CREATEROLE + database CREATE. It creates
-- roles and installs extensions, which the ordinary migration role cannot do. Later
-- migrations run as `enclave_migrator`, which owns everything created here.

SET search_path TO public;

-- ---------------------------------------------------------------------------
-- 1. Roles
-- ---------------------------------------------------------------------------
-- Three roles, because tenant isolation is only as strong as the role the
-- application connects as (docs/04 §3.2, M0 plan D3):
--
--   enclave_app       the application. NOT the owner of any table, so RLS applies
--                     to it unconditionally, and NOBYPASSRLS so it cannot opt out.
--   enclave_migrator  owns every object. Migrations run as this role. It is still
--                     NOBYPASSRLS: `FORCE ROW LEVEL SECURITY` in 0002 makes the
--                     policies apply to the owner too, so an owner-side mistake is
--                     not a cross-tenant read.
--   enclave_platform  BYPASSRLS. Exactly three code paths use it — the outbox
--                     publisher, the migration runner and the scheduler's tenant
--                     enumerator (M0 plan ENC-104). Every other use is a defect.
--
-- No passwords are set here. Credentials are provisioned by the deployment from a
-- secret store; a literal password in a migration is a committed secret
-- (CLAUDE.md rule 11). Until one is set these roles cannot authenticate.
--
-- CREATE ROLE has no IF NOT EXISTS and roles are cluster-wide, not per-database.
--
-- A `IF NOT EXISTS (SELECT 1 FROM pg_roles ...)` guard is not enough: it is a
-- check-then-act race. Two databases in the same cluster migrating concurrently
-- both pass the check and both issue CREATE ROLE, and one gets
-- `duplicate key value violates unique constraint "pg_authid_rolname_index"`.
-- That is not hypothetical — it is what the ENC-112 harness hit the first time
-- two test databases were created at once, and it would equally hit two API
-- replicas starting together against different databases in one cluster.
--
-- Catching the failure is the race-safe form: it commits to the create and
-- tolerates losing the race, rather than trying to predict it.
--
-- BOTH conditions are needed. A name collision detected by PostgreSQL's own
-- check raises duplicate_object (42710), but losing a genuine race raises
-- unique_violation (23505) from pg_authid_rolname_index — which is precisely
-- the error the harness saw. Catching only duplicate_object handles the case
-- that was never the problem and misses the one that is.

DO $$
BEGIN
    BEGIN
        CREATE ROLE enclave_migrator WITH
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
        NULL;
    END;

    BEGIN
        CREATE ROLE enclave_app WITH
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
        NULL;
    END;

    BEGIN
        CREATE ROLE enclave_platform WITH
            LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;
    EXCEPTION WHEN duplicate_object OR unique_violation THEN
        NULL;
    END;
END
$$;

COMMENT ON ROLE enclave_app IS
    'Application role. Non-owner, NOBYPASSRLS: every query is subject to the tenant_isolation policy.';
COMMENT ON ROLE enclave_migrator IS
    'Owns all Enclave objects. Applies migrations. NOBYPASSRLS; FORCE RLS applies policies to it as well.';
COMMENT ON ROLE enclave_platform IS
    'BYPASSRLS. Permitted only for the outbox publisher, the migration runner and the tenant enumerator.';

-- ---------------------------------------------------------------------------
-- 2. Extensions
-- ---------------------------------------------------------------------------
-- pgcrypto  — digest()/gen_random_bytes() for token and share-link hashing.
-- pg_trgm   — trigram indexes for name and email substring lookup.
-- Both are trusted extensions on PostgreSQL 13+, so a non-superuser with CREATE on
-- the database can install them.
--
-- Note: primary keys are UUIDv7 generated by the application, never by the database
-- (docs/04 §1). pgcrypto is not here to generate ids.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- 3. Tenancy — docs/04 §4
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenants (
    id                UUID PRIMARY KEY,
    slug              TEXT NOT NULL UNIQUE,
    display_name      TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','READ_ONLY','DELETING')),
    residency_region  TEXT,
    storage_profile_id UUID,
    branding          JSONB NOT NULL DEFAULT '{}'::jsonb,
    settings          JSONB NOT NULL DEFAULT '{}'::jsonb,
    policy_generation BIGINT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    deleted_at        TIMESTAMPTZ
);

COMMENT ON COLUMN tenants.policy_generation IS
    'Bumped on any security-policy change; the cache-invalidation key for compiled policies (docs/03 §16).';

CREATE TABLE IF NOT EXISTS tenant_domains (
    tenant_id     UUID NOT NULL REFERENCES tenants (id),
    domain        TEXT NOT NULL,
    verified_at   TIMESTAMPTZ,
    verification_token TEXT NOT NULL,
    certificate_mode TEXT NOT NULL CHECK (certificate_mode IN ('AUTOMATIC','MANUAL')),
    is_primary    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (domain)
);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant ON tenant_domains (tenant_id);

-- ---------------------------------------------------------------------------
-- 4. Identity — docs/04 §5
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    email          TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    display_name   TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('ACTIVE','INVITED','SUSPENDED','DEPROVISIONED')),
    is_admin       BOOLEAN NOT NULL DEFAULT FALSE,
    token_epoch    INT NOT NULL DEFAULT 1,
    source         TEXT NOT NULL CHECK (source IN ('LOCAL','LDAP','SCIM','JIT')),
    external_id    TEXT,
    department     TEXT,
    locale         TEXT,
    last_login_at  TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    deleted_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON users (tenant_id, normalized_email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_external ON users (tenant_id, source, external_id);

COMMENT ON COLUMN users.token_epoch IS
    'Mass-revocation counter (docs/03 §5.4). Incrementing it invalidates every outstanding access token for this user.';

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id         UUID PRIMARY KEY REFERENCES users (id),
    tenant_id       UUID NOT NULL,
    password_hash   TEXT,                      -- Argon2id, includes params and salt
    algorithm       TEXT NOT NULL DEFAULT 'argon2id',
    changed_at      TIMESTAMPTZ,
    must_change     BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    breach_checked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS user_mfa_methods (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    user_id       UUID NOT NULL REFERENCES users (id),
    kind          TEXT NOT NULL CHECK (kind IN ('TOTP','WEBAUTHN','RECOVERY_CODE')),
    label         TEXT,
    secret_ref    TEXT,                        -- encrypted / secret-provider reference
    credential_id BYTEA,                       -- WebAuthn
    public_key    BYTEA,                       -- WebAuthn
    sign_count    BIGINT NOT NULL DEFAULT 0,
    aaguid        UUID,
    confirmed_at  TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mfa_user ON user_mfa_methods (tenant_id, user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS groups (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    name         TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    description  TEXT,
    source       TEXT NOT NULL CHECK (source IN ('LOCAL','LDAP','SCIM')),
    external_id  TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    deleted_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_name ON groups (tenant_id, normalized_name) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS group_members (
    tenant_id  UUID NOT NULL,
    group_id   UUID NOT NULL,
    member_id  UUID NOT NULL,
    member_type TEXT NOT NULL CHECK (member_type IN ('USER','GROUP','GUEST','SERVICE_ACCOUNT')),
    added_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, group_id, member_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_member ON group_members (tenant_id, member_id);

CREATE TABLE IF NOT EXISTS guests (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    email        TEXT NOT NULL,
    invited_by   UUID NOT NULL,
    accepted_at  TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    status       TEXT NOT NULL CHECK (status IN ('INVITED','ACTIVE','EXPIRED','REVOKED')),
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS service_accounts (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    name           TEXT NOT NULL,
    client_id      TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    scopes         JSONB NOT NULL,
    token_epoch    INT NOT NULL DEFAULT 1,
    ip_allowlist   JSONB,
    created_by     UUID NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    disabled_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mcp_clients (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    name                TEXT NOT NULL,
    client_id           TEXT NOT NULL UNIQUE,
    client_secret_hash  TEXT NOT NULL,
    scopes              JSONB NOT NULL,       -- SEARCH, READ_METADATA, READ_CONTENT, CREATE, UPDATE, SHARE, ADMIN
    classification_ceiling INT NOT NULL DEFAULT 20,
    workspace_allowlist JSONB,
    write_tools_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    rate_limit_profile  TEXT,
    token_epoch         INT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL,
    disabled_at         TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS identity_providers (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('LDAP','OIDC','SAML','SCIM')),
    name        TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    config      JSONB NOT NULL,               -- secret_ref values only, never plaintext
    jit_provisioning BOOLEAN NOT NULL DEFAULT FALSE,
    default_groups JSONB,
    last_sync_at TIMESTAMPTZ,
    last_sync_status TEXT,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

COMMENT ON COLUMN identity_providers.config IS
    'Secret references only (vault://, env://). A literal credential here is a security defect (CLAUDE.md rule 11).';

CREATE TABLE IF NOT EXISTS identity_links (
    tenant_id    UUID NOT NULL,
    provider_id  UUID NOT NULL,
    external_id  TEXT NOT NULL,
    user_id      UUID NOT NULL,
    linked_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, provider_id, external_id)
);

-- ---------------------------------------------------------------------------
-- 5. Authentication tokens — docs/04 §6
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    session_id     UUID NOT NULL,              -- family id, the `sid` claim
    actor_id       UUID NOT NULL,
    actor_type     TEXT NOT NULL CHECK (actor_type IN ('USER','GUEST','SERVICE_ACCOUNT')),
    token_hash     TEXT NOT NULL,              -- SHA-256 of the 256-bit random token
    device_id      UUID,
    client_type    TEXT NOT NULL,
    parent_id      UUID REFERENCES refresh_tokens (id),
    issued_at      TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  TEXT,
    ip             INET,
    user_agent     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_token_hash ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens (tenant_id, session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_actor_active ON refresh_tokens (tenant_id, actor_id)
    WHERE revoked_at IS NULL AND consumed_at IS NULL;

COMMENT ON COLUMN refresh_tokens.consumed_at IS
    'Set on rotation. Presenting an already-consumed token revokes the whole session_id family and raises SESSION_REPLAY (docs/03 §5.3).';

CREATE TABLE IF NOT EXISTS token_revocations (
    tenant_id   UUID NOT NULL,
    jti         UUID NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,          -- prune after this; equals the token's own exp
    reason      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, jti)
);

COMMENT ON TABLE token_revocations IS
    'Authoritative denylist. Redis mirrors it for the hot path, so a Redis flush cannot resurrect a revoked token.';

-- signing_keys is deployment-wide, not tenant-scoped: it carries no tenant_id and
-- therefore gets no RLS policy in 0002. Key material is never stored — only a
-- KeyProvider reference (M0 plan D5).
CREATE TABLE IF NOT EXISTS signing_keys (
    kid          TEXT PRIMARY KEY,
    algorithm    TEXT NOT NULL DEFAULT 'EdDSA',
    public_key   BYTEA NOT NULL,
    private_key_ref TEXT NOT NULL,             -- KeyProvider reference, never the key itself
    status       TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','RETIRING','RETIRED')),
    activates_at TIMESTAMPTZ NOT NULL,
    retires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    user_id       UUID NOT NULL,
    name          TEXT NOT NULL,
    platform      TEXT NOT NULL,
    client_type   TEXT NOT NULL CHECK (client_type IN ('WEB','DESKTOP','MOBILE')),
    posture       TEXT NOT NULL CHECK (posture IN ('UNKNOWN','UNMANAGED','MANAGED','COMPLIANT')),
    attestation   JSONB,
    trusted_at    TIMESTAMPTZ,
    last_seen_at  TIMESTAMPTZ,
    wipe_requested_at TIMESTAMPTZ,
    wiped_at      TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices (tenant_id, user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- 6. Audit — docs/04 §14
-- ---------------------------------------------------------------------------
-- Partitioned by month from day one: it is the fastest-growing table in every
-- deployment and retrofitting partitioning onto a populated audit table means an
-- outage (docs/04 §19).
--
-- DEVIATION 1 — `sequence BIGINT GENERATED ALWAYS AS IDENTITY` (docs/04 §14).
--   PostgreSQL rejects identity columns on partitioned tables before version 17
--   ("identity columns are not supported on partitioned tables"), and docs/04 §1
--   declares PostgreSQL 15+. Implemented as an explicit sequence with a DEFAULT,
--   which is accepted on 15+ and produces the same monotonic ordering the audit
--   hash chain needs. The lost property is GENERATED ALWAYS: a client with INSERT
--   could supply its own value. Mitigated in 0002 by granting the application only
--   USAGE on the sequence and never UPDATE on the table, so a forged sequence value
--   cannot be used to rewrite an existing row — it can only be detected by the
--   chain verifier. docs/04 §14 must be amended.
--
-- DEVIATION 2 — `id UUID PRIMARY KEY` (docs/04 §14).
--   PostgreSQL requires every unique constraint on a partitioned table to contain
--   all partition-key columns, so `PRIMARY KEY (id)` is rejected outright on a table
--   partitioned by `occurred_at`. Implemented as `PRIMARY KEY (id, occurred_at)`.
--   Consequence: uniqueness of `id` is enforced per partition, not globally. Ids are
--   application-generated UUIDv7 (docs/04 §1), so this is a collision-probability
--   argument rather than a constraint; every lookup by id must also carry
--   `occurred_at` to stay partition-pruned. docs/04 §14 must be amended.
--
-- No DEFAULT partition. An insert outside every range fails, which fails the
-- surrounding transaction and therefore the action being audited — audit loss is not
-- an acceptable outcome (CLAUDE.md rule 10), so failing closed is the correct
-- behaviour. Three months are pre-created here; the scheduler creates ahead of that
-- (docs/04 §14) and must apply the same RLS treatment 0002 applies to these.

CREATE SEQUENCE IF NOT EXISTS audit_events_sequence_seq AS BIGINT;

CREATE TABLE IF NOT EXISTS audit_events (
    id             UUID NOT NULL,
    tenant_id      UUID NOT NULL,
    sequence       BIGINT NOT NULL DEFAULT nextval('audit_events_sequence_seq'),
    occurred_at    TIMESTAMPTZ NOT NULL,
    actor_id       UUID,
    actor_type     TEXT NOT NULL,
    on_behalf_of   UUID,
    action         TEXT NOT NULL,
    resource_type  TEXT,
    resource_id    UUID,
    workspace_id   UUID,
    outcome        TEXT NOT NULL CHECK (outcome IN ('ALLOW','DENY','ERROR')),
    reason_code    TEXT,
    policy_refs    JSONB,
    request_id     UUID NOT NULL,
    session_id     UUID,
    client_type    TEXT,
    mcp_client_id  UUID,
    device_id      UUID,
    ip             INET,
    country        TEXT,
    user_agent     TEXT,
    detail         JSONB,
    previous_hash  BYTEA,
    event_hash     BYTEA,
    PRIMARY KEY (id, occurred_at)               -- DEVIATION 2, see above
) PARTITION BY RANGE (occurred_at);

ALTER SEQUENCE audit_events_sequence_seq OWNED BY audit_events.sequence;

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource    ON audit_events (tenant_id, resource_type, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor       ON audit_events (tenant_id, actor_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_request     ON audit_events (request_id);

COMMENT ON TABLE audit_events IS
    'Append-only. enclave_app holds INSERT and SELECT only; UPDATE and DELETE are revoked in 0002.';
COMMENT ON COLUMN audit_events.event_hash IS
    'SHA256(previous_hash || canonical_event) when tamper evidence is enabled, chained per tenant in sequence order (docs/04 §14).';

-- Three months of monthly partitions, starting with the current month in UTC.
-- Bounds are written as explicit UTC literals so a session TimeZone cannot shift a
-- partition boundary by a few hours at DDL time.
DO $$
DECLARE
    month_start  DATE := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    offset_month INT;
    range_start  DATE;
    range_end    DATE;
    part_name    TEXT;
BEGIN
    FOR offset_month IN 0..2 LOOP
        range_start := (month_start + (offset_month       || ' months')::interval)::date;
        range_end   := (month_start + ((offset_month + 1) || ' months')::interval)::date;
        part_name   := 'audit_events_' || to_char(range_start, 'YYYYMM');

        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = part_name AND n.nspname = 'public'
        ) THEN
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
                part_name,
                to_char(range_start, 'YYYY-MM-DD') || ' 00:00:00+00',
                to_char(range_end,   'YYYY-MM-DD') || ' 00:00:00+00'
            );
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- 7. Platform — docs/04 §17
-- ---------------------------------------------------------------------------

-- The transactional outbox (M0 plan D6). A state change and the event describing it
-- are written in one transaction; the publisher is a separate, at-least-once reader.
CREATE TABLE IF NOT EXISTS events_outbox (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    event_type    TEXT NOT NULL,
    schema_version INT NOT NULL DEFAULT 1,
    payload       JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    published_at  TIMESTAMPTZ,
    attempts      INT NOT NULL DEFAULT 0,
    last_error    TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_unpublished ON events_outbox (created_at) WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS idempotency_keys (
    tenant_id     UUID NOT NULL,
    key           TEXT NOT NULL,
    actor_id      UUID NOT NULL,
    endpoint      TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    response_status INT,
    response_body JSONB,
    state         TEXT NOT NULL CHECK (state IN ('IN_FLIGHT','COMPLETED')),
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, key, actor_id)
);

COMMENT ON COLUMN idempotency_keys.request_hash IS
    'Same key with a different request hash is a client bug and returns 409, never the cached response (docs/05 §8).';

-- ---------------------------------------------------------------------------
-- 8. Ownership
-- ---------------------------------------------------------------------------
-- Everything is owned by enclave_migrator so that later migrations, which run as
-- that role, can alter it — and so that enclave_app is provably not an owner, which
-- is what makes row-level security apply to it at all (docs/04 §3.2).
-- Re-assigning to the current owner is a no-op, so this block is re-runnable.

DO $$
DECLARE
    obj TEXT;
    owned CONSTANT TEXT[] := ARRAY[
        'tenants', 'tenant_domains',
        'users', 'user_credentials', 'user_mfa_methods', 'groups', 'group_members',
        'guests', 'service_accounts', 'mcp_clients', 'identity_providers', 'identity_links',
        'refresh_tokens', 'token_revocations', 'signing_keys', 'devices',
        'audit_events',
        'events_outbox', 'idempotency_keys'
    ];
BEGIN
    FOREACH obj IN ARRAY owned LOOP
        EXECUTE format('ALTER TABLE %I OWNER TO enclave_migrator', obj);
    END LOOP;

    -- Audit partitions, including any the scheduler has already created.
    FOR obj IN
        SELECT c.relname
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'public.audit_events'::regclass
    LOOP
        EXECUTE format('ALTER TABLE %I OWNER TO enclave_migrator', obj);
    END LOOP;

    EXECUTE 'ALTER SEQUENCE audit_events_sequence_seq OWNER TO enclave_migrator';
END
$$;
