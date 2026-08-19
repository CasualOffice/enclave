-- `share_links`, `share_link_grants`, `share_link_events` — docs/04-DATA-MODEL.md §11.
--
-- DDL from §11, with the additions that document's own rules require and its listing omits:
--
--   1. Composite foreign keys from the two child tables onto `share_links` (§3.3). A grant or an
--      event naming a link in another tenant is two individually well-formed rows, which is exactly
--      what row-level security does not catch.
--   2. RLS enabled, forced, and a `tenant_isolation` policy on all three (§3.2).
--   3. Grants for `enclave_app`. Migration 0003's catalog loop has already run and will not run
--      again, so a table created after it and not granted here is one the application role cannot
--      see at all.
--   4. A `CHECK` on `share_links.resource_type`, mirrored by `enclave_sharing::ShareResourceKind`.
--      §11 gives it as free text; an open vocabulary means a typo becomes a link that resolves to
--      nothing and reports no error.
--
-- `share_links.resource_id` has **no** foreign key, and that is deliberate rather than an omission.
-- The reference is polymorphic — a link may point at a file, a folder or a library — and PostgreSQL
-- cannot express a composite key whose target table varies by row. `acl_entries` has the same shape
-- for the same reason (migration 0004), so the resolution is the same one: the `CHECK` constrains
-- the discriminator, and the redemption path joins to the concrete table under RLS, which is what
-- actually makes a cross-tenant target unreachable.
--
-- Forward-only: a new migration, never an edit to 0007.

CREATE TABLE IF NOT EXISTS share_links (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    resource_type   TEXT NOT NULL CHECK (resource_type IN ('LIBRARY','FOLDER','FILE')),
    resource_id     UUID NOT NULL,
    -- SHA-256 of the token, lowercase hex. Never the token: `crates/sharing` mints 256 bits from
    -- the OS CSPRNG and hands the plaintext back exactly once, to the creator. A database backup,
    -- a replica or a support export therefore yields no working link.
    token_hash      TEXT NOT NULL,
    permission      TEXT NOT NULL CHECK (permission IN ('VIEW','PREVIEW_ONLY','EDIT')),
    allow_download  BOOLEAN NOT NULL DEFAULT TRUE,
    audience        TEXT NOT NULL CHECK (audience IN ('INTERNAL','SPECIFIC','EXTERNAL_AUTHENTICATED','DOMAIN_RESTRICTED','ANYONE')),
    password_hash   TEXT,                        -- Argon2id
    require_otp     BOOLEAN NOT NULL DEFAULT FALSE,
    require_mfa     BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ,
    max_downloads   BIGINT CHECK (max_downloads IS NULL OR max_downloads > 0),
    download_count  BIGINT NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    allowed_domains JSONB,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    -- The backstop, not the guard. §11: the counter is incremented inside the transaction that
    -- issues the URL, with the limit in the `WHERE` clause, and a zero-row result means exhausted.
    -- This constraint is what turns a mistake in that statement into a failed transaction instead
    -- of an over-issued download, which is the difference between a bug and an incident.
    CONSTRAINT share_links_within_budget
        CHECK (max_downloads IS NULL OR download_count <= max_downloads),
    UNIQUE (tenant_id, id)
);

-- Global, not tenant-scoped, and deliberately so. Redemption arrives with a token and nothing else
-- — there is no session and no tenant yet, because establishing the tenant is what redeeming the
-- token *does*. A per-tenant index would permit the same token hash in two tenants, and the lookup
-- that resolves it has no tenant to disambiguate with.
CREATE UNIQUE INDEX IF NOT EXISTS uq_share_token ON share_links (token_hash);

CREATE INDEX IF NOT EXISTS idx_share_resource
    ON share_links (tenant_id, resource_type, resource_id) WHERE revoked_at IS NULL;

ALTER TABLE share_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_links FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON share_links
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- UPDATE for the download counter and for revocation. DELETE because a link is ordinary data a
-- tenant may remove; the audit trail of what it did lives in `share_link_events` and in
-- `audit_events`, neither of which is deleted with it.
GRANT SELECT, INSERT, UPDATE, DELETE ON share_links TO enclave_app;

-- ---------------------------------------------------------------------------
-- share_link_grants — the named recipients of a SPECIFIC-audience link
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS share_link_grants (
    tenant_id      UUID NOT NULL,
    share_link_id  UUID NOT NULL,
    email          TEXT NOT NULL,
    guest_id       UUID,
    otp_hash       TEXT,
    otp_expires_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, share_link_id, email),
    CONSTRAINT share_link_grants_link_fkey
        FOREIGN KEY (tenant_id, share_link_id) REFERENCES share_links (tenant_id, id)
        ON DELETE CASCADE
);

ALTER TABLE share_link_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_link_grants FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON share_link_grants
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON share_link_grants TO enclave_app;

-- ---------------------------------------------------------------------------
-- share_link_events — what a link did, including what it refused
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS share_link_events (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    share_link_id UUID NOT NULL,
    event         TEXT NOT NULL CHECK (event IN ('VIEWED','DOWNLOADED','AUTH_FAILED','BLOCKED','EXPIRED')),
    ip            INET,
    country       TEXT,
    user_agent    TEXT,
    occurred_at   TIMESTAMPTZ NOT NULL,
    CONSTRAINT share_link_events_link_fkey
        FOREIGN KEY (tenant_id, share_link_id) REFERENCES share_links (tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_share_events_link
    ON share_link_events (tenant_id, share_link_id, occurred_at DESC);

ALTER TABLE share_link_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_link_events FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON share_link_events
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No UPDATE and no DELETE. `AUTH_FAILED` and `BLOCKED` rows are the evidence that somebody probed a
-- link, which makes this table the one place an attacker most wants to edit. Deletion happens only
-- through the cascade above, when the link itself goes.
GRANT SELECT, INSERT ON share_link_events TO enclave_app;
