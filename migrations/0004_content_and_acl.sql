-- 0004_content_and_acl.sql
--
-- Enclave migration 004 — the content containers and the access-control tables.
--
-- Authoritative source for every column below: docs/04-DATA-MODEL.md
--   §7  Workspaces and libraries   (workspaces, workspace_members, libraries, content_types)
--   §9  Access control             (role_definitions, acl_entries)
-- DDL is taken verbatim from that document. Anything that is not verbatim is marked
-- `ADDITION` or `DEVIATION` with the reason, and docs/04 is authoritative: each mark
-- is a request for an amendment there, not a licence to diverge further here.
--
-- Row-level security, policies, ownership and grants are in this same file rather than
-- in a follow-up migration (M0 plan D4, and the reason ENC-124 exists): a table that
-- reaches a deployment without its policy is readable across tenants for exactly as
-- long as it takes someone to notice, and a table that reaches a deployment without
-- its grants is never exercised by the application role at all — which is how PR #22's
-- cross-tenant read stayed invisible while the policies were correct the whole time.
--
-- Forward-only. 0001, 0002 and 0003 are applied and checksummed; this file adds, it
-- never amends (CLAUDE.md, SQL conventions; docs/11-OPERATIONS.md §8).
--
-- Re-runnable: every CREATE is guarded, because a partially-applied migration should be
-- repairable by re-running it rather than by hand.
--
-- Applying role: enclave_migrator, which owns everything created by 0001 and owns
-- everything created here. Only the owner may enable RLS or create policies.
--
-- Not `CREATE INDEX CONCURRENTLY`: sqlx runs each migration inside one transaction, and
-- CONCURRENTLY cannot run in a transaction block. Plain CREATE INDEX takes an ACCESS
-- EXCLUSIVE lock, which is free here and only here — these tables are created empty in
-- this same transaction, so there is nothing to block and nothing to build. Any later
-- index on a populated one of these tables must be CONCURRENTLY, in a migration of its
-- own, outside a transaction.

SET search_path TO public;

-- ---------------------------------------------------------------------------
-- 1. Workspaces and libraries — docs/04 §7
-- ---------------------------------------------------------------------------
-- Note on column order: docs/04 §1 says `tenant_id` is the first column of every
-- tenant-scoped table, while the DDL in §7 (and §5, and §8) puts `id` first. The DDL
-- is what is reproduced here, as 0001 did for `users`, so that the file matches the
-- document it claims to implement. The property that actually matters — `tenant_id`
-- leading every composite index and foreign key — is honoured throughout.

CREATE TABLE IF NOT EXISTS workspaces (
    id           UUID PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    name         TEXT NOT NULL,
    slug         TEXT NOT NULL,
    description  TEXT,
    visibility   TEXT NOT NULL CHECK (visibility IN ('PRIVATE','MEMBERS_ONLY','TENANT_VISIBLE','RESTRICTED')),
    default_classification_id UUID,
    storage_profile_id UUID,
    revision     BIGINT NOT NULL DEFAULT 1,
    created_by   UUID NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    deleted_at   TIMESTAMPTZ,
    UNIQUE (tenant_id, id)
);

COMMENT ON CONSTRAINT workspaces_tenant_id_id_key ON workspaces IS
    'Not redundant with the primary key: it is the target of every composite foreign key that includes tenant_id (docs/04 §3.3).';

-- Slug uniqueness ignores trashed workspaces, so a name can be reused after deletion.
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_slug ON workspaces (tenant_id, slug) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS workspace_members (
    tenant_id    UUID NOT NULL,
    workspace_id UUID NOT NULL,
    principal_id UUID NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('USER','GROUP','GUEST','SERVICE_ACCOUNT')),
    role_id      UUID NOT NULL,
    added_by     UUID NOT NULL,
    added_at     TIMESTAMPTZ NOT NULL,
    expires_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, workspace_id, principal_id),
    -- ADDITION 1 — docs/04 §7 declares no foreign key here; §3.3 states the rule that
    -- requires one, and gives this exact clause as its example. Without it a membership
    -- row may name a workspace belonging to another tenant, which is precisely the
    -- "structurally impossible rather than merely unlikely" property §3.3 exists for.
    -- Referential-integrity checks bypass even FORCE RLS, so this constraint holds
    -- independently of whether a session has set app.tenant_id.
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id)
);

-- `principal_id` is polymorphic across users, groups, guests and service accounts, and
-- `role_id` points at a table whose rows may be platform-wide (see §3 below), so neither
-- can carry a foreign key. Both are the application's responsibility; the composite key
-- above covers the one reference that can be enforced.

CREATE TABLE IF NOT EXISTS libraries (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    workspace_id        UUID NOT NULL,
    name                TEXT NOT NULL,
    slug                TEXT NOT NULL,
    inherit_permissions BOOLEAN NOT NULL DEFAULT TRUE,
    default_classification_id UUID,
    versioning_mode     TEXT NOT NULL CHECK (versioning_mode IN ('NONE','MAJOR','MAJOR_MINOR')),
    version_limit       INT,
    require_checkout    BOOLEAN NOT NULL DEFAULT FALSE,
    require_approval    BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_extensions  JSONB,
    blocked_extensions  JSONB,
    max_file_size_bytes BIGINT,
    external_sharing    TEXT NOT NULL CHECK (external_sharing IN ('DISABLED','EXISTING_GUESTS','NEW_GUESTS','ANYONE')),
    ai_indexing_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mcp_visible         BOOLEAN NOT NULL DEFAULT TRUE,
    sync_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    storage_profile_id  UUID,
    retention_policy_id UUID,
    revision            BIGINT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    deleted_at          TIMESTAMPTZ,
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces (tenant_id, id)
);

COMMENT ON COLUMN libraries.inherit_permissions IS
    'FALSE stops ACL inheritance at this library; the break is materialised as copied entries with inherited_from set (docs/04 §9).';

CREATE TABLE IF NOT EXISTS content_types (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    scope         TEXT NOT NULL CHECK (scope IN ('TENANT','WORKSPACE','LIBRARY')),
    scope_id      UUID,
    name          TEXT NOT NULL,
    parent_id     UUID,
    field_schema  JSONB NOT NULL,
    default_classification_id UUID,
    retention_policy_id UUID,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,
    -- ADDITION 2 — docs/04 §7 declares neither of these. `parent_id` is a self-reference
    -- of exactly the shape §8 gives `files.parent_id`, and §3.3 requires it to be
    -- composite; the UNIQUE is what makes the composite reference possible. It is implied
    -- by the primary key (id determines tenant_id) so it constrains nothing new.
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES content_types (tenant_id, id)
);

-- `scope_id` is polymorphic over tenant, workspace and library by `scope`, so it cannot
-- carry a foreign key either.

-- ---------------------------------------------------------------------------
-- 2. Access control — docs/04 §9
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS role_definitions (
    id           UUID PRIMARY KEY,
    tenant_id    UUID,                          -- NULL = built-in, platform-wide
    name         TEXT NOT NULL,
    description  TEXT,
    permissions  JSONB NOT NULL,                -- array of action strings
    is_builtin   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS acl_entries (
    id             UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    resource_type  TEXT NOT NULL CHECK (resource_type IN ('WORKSPACE','LIBRARY','FOLDER','FILE','PAGE','LIST','LIST_ITEM')),
    resource_id    UUID NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('USER','GROUP','GUEST','SERVICE_ACCOUNT','EVERYONE')),
    principal_id   UUID,                        -- NULL for EVERYONE
    action         TEXT NOT NULL,               -- FileAction variant
    effect         TEXT NOT NULL CHECK (effect IN ('ALLOW','DENY')),
    inherited_from UUID,
    granted_by     UUID NOT NULL,
    granted_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ
);

-- `resource_id` is polymorphic over seven resource types, so no foreign key is possible.
-- Cross-tenant resource references are prevented by RLS on write (WITH CHECK stamps the
-- row's tenant) and by resolution always starting from a tenant-scoped resource lookup.

COMMENT ON COLUMN acl_entries.effect IS
    'DENY at any level of the inheritance chain wins over every ALLOW (docs/04 §9 resolution rule 3).';
COMMENT ON COLUMN acl_entries.inherited_from IS
    'Set on entries copied down when inheritance is broken, so the break is explicit and auditable.';

-- One entry per (resource, principal, action). COALESCE folds the EVERYONE principal,
-- whose principal_id is NULL, into the uniqueness — NULLs are distinct in a unique index,
-- so without it EVERYONE could be granted the same action any number of times and the
-- duplicate rows would disagree the moment one of them was revoked.
CREATE UNIQUE INDEX IF NOT EXISTS uq_acl_entry
    ON acl_entries (tenant_id, resource_type, resource_id, principal_type,
                    COALESCE(principal_id, '00000000-0000-0000-0000-000000000000'::uuid), action);

-- The two resolution directions: "what applies to this resource" (the read path) and
-- "what does this principal hold" (revocation, and the search-index ACL invalidation
-- in docs/07 §6).
CREATE INDEX IF NOT EXISTS idx_acl_resource  ON acl_entries (tenant_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_acl_principal ON acl_entries (tenant_id, principal_type, principal_id);

-- `role_assignments` appears in the docs/04 §2 inventory under Access control but has no
-- DDL in §9 or anywhere else in the document. It is therefore NOT created here: docs/04
-- is the only place DDL is defined, and inventing a table shape to fill the gap would put
-- the authoritative definition in a migration. Reported for amendment; whichever migration
-- lands it must land its policy and grants in the same file.

-- ---------------------------------------------------------------------------
-- 3. Ownership
-- ---------------------------------------------------------------------------
-- Everything is owned by enclave_migrator, for the reason 0001 §8 gives: enclave_app must
-- provably own nothing, because non-ownership is what makes row-level security apply to it.
-- These tables are created by enclave_migrator in production and so already have the right
-- owner; the statement is written anyway so that a database migrated by a superuser (the
-- test harness path) ends up identical to one migrated normally.

DO $$
DECLARE
    obj TEXT;
    owned CONSTANT TEXT[] := ARRAY[
        'workspaces', 'workspace_members', 'libraries', 'content_types',
        'role_definitions', 'acl_entries'
    ];
BEGIN
    FOREACH obj IN ARRAY owned LOOP
        EXECUTE format('ALTER TABLE public.%I OWNER TO enclave_migrator', obj);
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- 4. Row-level security — docs/04 §3.2
-- ---------------------------------------------------------------------------
-- Applied explicitly, table by table, rather than by re-running 0002's catalog-driven
-- loop. Both produce the same result; the reason for this one is reviewability. A
-- reviewer of this file can see which control each new table receives without opening
-- another migration and reasoning about what a loop would have matched, and a table added
-- here that is deliberately treated differently would be visible as a difference rather
-- than as an absence. The loop's "cannot drift" property is not lost: it came from the
-- catalog predicate, and that predicate is re-asserted over the whole schema in §6 below
-- and again by the ENC-106 CI gate, either of which fails if a table listed here were
-- dropped from the list by a later edit.
--
-- USING and WITH CHECK both, always: USING alone stops a cross-tenant read while still
-- permitting a write stamped with another tenant's id.
--
-- FORCE matters as much as ENABLE: without it the owner is exempt, and connecting as the
-- owner silently disables the control. PR #22 is the same lesson from the other end — the
-- harness connected as a superuser, which is exempt from RLS no matter what FORCE says,
-- so the policies were never exercised. Configuration being right is not enforcement.
--
-- current_setting() is used in its strict form: a session that never set app.tenant_id
-- gets an ERROR, not an empty result. Fail closed and loudly.

DO $$
DECLARE
    tbl TEXT;
    scoped CONSTANT TEXT[] := ARRAY[
        'workspaces', 'workspace_members', 'libraries', 'content_types',
        'role_definitions', 'acl_entries'
    ];
BEGIN
    FOREACH tbl IN ARRAY scoped LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE public.%I FORCE  ROW LEVEL SECURITY', tbl);

        -- CREATE POLICY has no IF NOT EXISTS.
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_policy p
            WHERE p.polrelid = format('public.%I', tbl)::regclass
              AND p.polname  = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON public.%I'
                || ' USING      (tenant_id = current_setting(''app.tenant_id'')::uuid)'
                || ' WITH CHECK (tenant_id = current_setting(''app.tenant_id'')::uuid)',
                tbl
            );
        END IF;
    END LOOP;
END
$$;

-- role_definitions is in that list and is worth stating explicitly, because it is the one
-- table here where the policy has a consequence beyond isolation. docs/04 §9 makes its
-- tenant_id nullable — "NULL = built-in, platform-wide" — while §3.2 requires the policy
-- above on every table carrying a tenant_id column, and §1 says a tenant-scoped table's
-- tenant_id is non-null. Under `tenant_id = current_setting('app.tenant_id')::uuid` a NULL
-- tenant_id compares NULL, which is not TRUE, so built-in role rows are invisible to
-- enclave_app for SELECT and cannot be written by it at all.
--
-- Implemented as documented, both halves, because docs/04 is authoritative and reconciling
-- the two is a decision to take there rather than here. Two consequences to carry:
--   * seeding built-in roles requires enclave_platform (BYPASSRLS) or a policy amendment,
--     not the application role;
--   * any read of role_definitions from the application must therefore be tenant-scoped,
--     so built-in roles have to be materialised per tenant, expressed in code, or the
--     policy has to gain an `OR tenant_id IS NULL` arm — which would be a deliberate,
--     reviewed widening of a tenant-isolation policy, not something to slip in here.

-- ---------------------------------------------------------------------------
-- 5. Table privileges — the enclave_app grants (0003)
-- ---------------------------------------------------------------------------
-- RLS decides which rows; grants decide which verbs. A table with a correct policy and no
-- grant is not "secure by default" — it is untested, which is the state 0002 left every
-- table in and the reason PR #22's cross-tenant read survived to be found by a request
-- rather than by a test.
--
-- Full DML, matching 0003's treatment of ordinary tenant-scoped tables. DELETE is included
-- deliberately: a revoked ACL entry, a removed workspace member and a retired content type
-- are row removals, and workspaces and libraries carry deleted_at for the soft-delete path
-- with the hard purge behind it. audit_events remains the only table where DELETE is
-- withheld, and nothing here alters that.
--
-- Nothing is granted to PUBLIC, and nothing is granted to enclave_platform: no cross-tenant
-- code path reads content or ACLs today, so the grant lands with the code that needs it.

GRANT SELECT, INSERT, UPDATE, DELETE ON
    workspaces,
    workspace_members,
    libraries,
    content_types,
    role_definitions,
    acl_entries
TO enclave_app;

-- No sequences are created by this migration: every primary key here is an
-- application-generated UUIDv7 (docs/04 §1). Nothing to grant USAGE on.

-- ---------------------------------------------------------------------------
-- 6. Self-check
-- ---------------------------------------------------------------------------
-- The ENC-106 CI predicate, asserted at apply time over the whole schema rather than over
-- this migration's tables. The CI gate is the durable guard; this exists so that a mistake
-- fails the deployment that introduced it instead of the build afterwards, and so that
-- re-running the explicit lists in §4 and §5 cannot silently diverge from the rule they
-- implement.

DO $$
DECLARE
    offender TEXT;
BEGIN
    SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
    INTO offender
    FROM pg_catalog.pg_class     c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
    WHERE n.nspname  = 'public'
      AND c.relkind  IN ('r', 'p')
      AND a.attname  = 'tenant_id'
      AND a.attnum   > 0
      AND NOT a.attisdropped
      AND (
            NOT c.relrowsecurity
         OR NOT c.relforcerowsecurity
         OR NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_policy p
                WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation'
            )
      );

    IF offender IS NOT NULL THEN
        RAISE EXCEPTION
            'tenant-scoped table(s) without enabled+forced RLS and a tenant_isolation policy: %',
            offender;
    END IF;
END
$$;

-- And the grants, for this migration's tables specifically. The absence of a grant is what
-- made the isolation of every other table untested until PR #22; asserting it here means a
-- table can never again reach a deployment that the application role has no way to touch.

DO $$
DECLARE
    tbl TEXT;
    scoped CONSTANT TEXT[] := ARRAY[
        'workspaces', 'workspace_members', 'libraries', 'content_types',
        'role_definitions', 'acl_entries'
    ];
    verb TEXT;
BEGIN
    FOREACH tbl IN ARRAY scoped LOOP
        FOREACH verb IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
            IF NOT has_table_privilege('enclave_app', format('public.%I', tbl), verb) THEN
                RAISE EXCEPTION
                    'enclave_app lacks % on %; the table cannot be exercised by the application role',
                    verb, tbl;
            END IF;
        END LOOP;

        IF pg_catalog.pg_get_userbyid(
               (SELECT relowner FROM pg_catalog.pg_class WHERE oid = format('public.%I', tbl)::regclass)
           ) = 'enclave_app' THEN
            RAISE EXCEPTION
                'enclave_app owns %; an owner is exempt from row-level security unless FORCE applies', tbl;
        END IF;
    END LOOP;
END
$$;
