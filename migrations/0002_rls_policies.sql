-- 0002_rls_policies.sql
--
-- Enclave migration 002 — row-level security, the tenant_isolation policy, and the
-- role grants that make the audit log append-only.
--
-- Authoritative source: docs/04-DATA-MODEL.md §3.2 (RLS), §14 (audit is append-only).
-- Design decisions: M0 plan D3 (SET LOCAL app.tenant_id, non-owner app role) and D4
-- (a table and its policy land in the same migration, never later).
--
-- This is the second half of migration 001 and must be applied in the same
-- deployment. 0001 without 0002 leaves every table readable across tenants by
-- anything holding the application credentials.
--
-- Forward-only, and re-runnable: RLS enablement is idempotent by nature and every
-- CREATE POLICY is guarded, because CREATE POLICY has no IF NOT EXISTS.
--
-- Applying role: the object owner, i.e. enclave_migrator (or a superuser). Only the
-- owner may ALTER ... ENABLE ROW LEVEL SECURITY or create policies.

SET search_path TO public;

-- ---------------------------------------------------------------------------
-- 1. Schema access
-- ---------------------------------------------------------------------------
-- USAGE only. The application never creates objects; DDL belongs to migrations, and
-- a role that can CREATE in the schema can create a table without RLS on it.

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO enclave_app;
GRANT USAGE ON SCHEMA public TO enclave_platform;
GRANT USAGE, CREATE ON SCHEMA public TO enclave_migrator;

-- ---------------------------------------------------------------------------
-- 2. Row-level security — docs/04 §3.2
-- ---------------------------------------------------------------------------
-- The rule this implements, stated once so it is not restated per table:
--
--   Every table carrying a `tenant_id` column has RLS ENABLED and FORCED, and one
--   policy named `tenant_isolation`:
--
--       USING      (tenant_id = current_setting('app.tenant_id')::uuid)
--       WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid)
--
-- USING filters what is visible to SELECT/UPDATE/DELETE; WITH CHECK constrains what
-- INSERT/UPDATE may write. Both are required: USING alone stops a cross-tenant read
-- but still permits writing a row stamped with another tenant's id.
--
-- FORCE matters as much as ENABLE. Without it the table owner is exempt, and an
-- ordinary RLS mistake — connecting as the owner — silently disables the whole
-- control. With FORCE, enclave_migrator is subject to the policy too; only
-- enclave_platform (BYPASSRLS) is exempt, and that is deliberate and narrow.
--
-- The set of tables is derived from the catalog rather than hardcoded. The rule is
-- "a tenant_id column implies a policy", so reading the column list back is the only
-- form that cannot drift from the rule — a table added by a later migration and
-- listed nowhere here still cannot escape it, and the ENC-106 CI gate asserts the
-- same predicate from the outside.
--
-- Partitions are included: they carry tenant_id, they are BASE TABLEs in the
-- catalog, and a partition queried directly is not covered by its parent's policy.
-- Every audit_events partition the scheduler creates later must be given the same
-- treatment; that is part of the partition-creation job, not an optional extra.
--
-- current_setting() is used in its strict form, exactly as docs/04 §3.2 specifies:
-- if `app.tenant_id` was never set, the query ERRORS rather than returning an empty
-- result. That is the fail-closed direction — a loud failure in a code path that
-- forgot to open a TenantScoped transaction, instead of a silent empty result that
-- looks like "no rows matched" and gets papered over.

DO $$
DECLARE
    tbl RECORD;
BEGIN
    FOR tbl IN
        SELECT c.oid, c.relname
        FROM pg_catalog.pg_class      c
        JOIN pg_catalog.pg_namespace  n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute  a ON a.attrelid = c.oid
        WHERE n.nspname   = 'public'
          AND c.relkind   IN ('r', 'p')          -- ordinary and partitioned tables
          AND a.attname   = 'tenant_id'
          AND a.attnum    > 0
          AND NOT a.attisdropped
        ORDER BY c.relname
    LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl.relname);
        EXECUTE format('ALTER TABLE public.%I FORCE  ROW LEVEL SECURITY', tbl.relname);

        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policy p
            WHERE p.polrelid = tbl.oid AND p.polname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON public.%I'
                || ' USING      (tenant_id = current_setting(''app.tenant_id'')::uuid)'
                || ' WITH CHECK (tenant_id = current_setting(''app.tenant_id'')::uuid)',
                tbl.relname
            );
        END IF;
    END LOOP;
END
$$;

-- Two tables created by 0001 are deliberately absent from the loop above, because
-- neither has a tenant_id column. Recording why, so the omission is a decision and
-- not something that was missed:
--
--   tenants       — the tenant registry itself. Its tenant key is `id`, not
--                   `tenant_id`, so `tenant_isolation` as specified does not apply
--                   to it, and it is read during tenant resolution (custom domain or
--                   slug → tenant) before any tenant context exists. Cross-tenant
--                   exposure here is limited to tenant metadata and is held by the
--                   application layer. See the note in the ENC-105 report: whether
--                   `tenants` (and `tenant_domains`, which IS policied above and
--                   therefore is NOT readable during resolution) should be reachable
--                   by a bootstrap path needs a decision in docs/04.
--   signing_keys  — deployment-wide, not tenant-scoped. It holds public keys and
--                   KeyProvider references, never key material (M0 plan D5).

-- ---------------------------------------------------------------------------
-- 3. Table privileges
-- ---------------------------------------------------------------------------
-- RLS decides which rows; grants decide which verbs. Both are needed — RLS with
-- DELETE granted on audit_events would still let a tenant erase its own audit trail
-- within its own tenant scope, which is exactly the attack the append-only property
-- exists to stop.
--
-- Nothing is granted to PUBLIC anywhere in this file.

GRANT SELECT, INSERT, UPDATE, DELETE ON
    tenant_domains,
    users,
    user_credentials,
    user_mfa_methods,
    groups,
    group_members,
    guests,
    service_accounts,
    mcp_clients,
    identity_providers,
    identity_links,
    refresh_tokens,
    token_revocations,
    devices,
    events_outbox,
    idempotency_keys
TO enclave_app;

-- No DELETE: tenants are soft-deleted (`deleted_at`) and then purged by a platform
-- operation, never by an application request.
GRANT SELECT, INSERT, UPDATE ON tenants TO enclave_app;

-- No DELETE: a signing key is retired through `status`, never removed. Deleting a
-- key destroys the ability to verify tokens it signed and to explain them afterwards.
GRANT SELECT, INSERT, UPDATE ON signing_keys TO enclave_app;

-- ---------------------------------------------------------------------------
-- 4. audit_events is append-only — docs/04 §14
-- ---------------------------------------------------------------------------
-- "The application role holds INSERT and SELECT but not UPDATE/DELETE on
-- audit_events." This is the U2 assertion in docs/12 §4 and the reason the hash
-- chain is worth computing: without it, an attacker with application credentials
-- rewrites history and the chain still verifies.
--
-- The REVOKE is redundant against a clean database — nothing granted UPDATE or
-- DELETE — and is written anyway so that re-applying this migration over a database
-- where someone granted them by hand takes them back.

GRANT SELECT, INSERT ON audit_events TO enclave_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM enclave_app;

-- The same on every existing partition. Inserts arrive through the parent, whose
-- privileges are what PostgreSQL checks, but a direct partition reference must not
-- become a way around the rule.
DO $$
DECLARE
    part TEXT;
BEGIN
    FOR part IN
        SELECT c.relname
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class    c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'public.audit_events'::regclass
    LOOP
        EXECUTE format('GRANT SELECT, INSERT ON public.%I TO enclave_app', part);
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON public.%I FROM enclave_app', part);
    END LOOP;
END
$$;

-- `sequence` defaults to nextval(), so INSERT requires USAGE on the sequence.
-- SELECT is granted with it so the chain writer can read currval within its own
-- transaction; UPDATE is not, so the counter cannot be rewound.
GRANT USAGE, SELECT ON SEQUENCE audit_events_sequence_seq TO enclave_app;

-- ---------------------------------------------------------------------------
-- 5. enclave_platform — the BYPASSRLS role
-- ---------------------------------------------------------------------------
-- BYPASSRLS is a standing cross-tenant read. It is granted the narrowest set of
-- privileges that the three permitted code paths need and nothing else, so that a
-- fourth caller that reaches for this role fails on a missing grant rather than
-- quietly working (M0 plan ENC-104).
--
--   outbox publisher    — claims and marks published rows, and prunes them.
--   tenant enumerator   — lists tenants for the scheduler's per-tenant jobs.
--   migration runner    — runs as enclave_migrator, which owns everything; it needs
--                         no grant here.
--
-- Deliberately absent: any privilege on audit_events. Cross-tenant chain
-- verification (ENC-107) needs SELECT here; grant it in the migration that lands the
-- verifier, together with the code that uses it, rather than in advance.

GRANT SELECT, UPDATE, DELETE ON events_outbox TO enclave_platform;
GRANT SELECT ON tenants TO enclave_platform;

-- ---------------------------------------------------------------------------
-- 6. Self-check
-- ---------------------------------------------------------------------------
-- The same predicate the ENC-106 CI gate applies, asserted here at apply time. The
-- CI gate is the durable guard; this exists so that a migration which creates a
-- tenant-scoped table and forgets its policy fails during deployment rather than
-- passing deployment and failing CI afterwards.
--
-- It also catches the case the loop in §2 cannot: a table created by a later
-- migration inside the same transaction as this one.

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

-- And the append-only assertion, in the form docs/12 §4 states it (U2).
DO $$
BEGIN
    IF has_table_privilege('enclave_app', 'public.audit_events', 'UPDATE')
       OR has_table_privilege('enclave_app', 'public.audit_events', 'DELETE') THEN
        RAISE EXCEPTION
            'enclave_app holds UPDATE or DELETE on audit_events; the audit log is not append-only';
    END IF;

    IF NOT has_table_privilege('enclave_app', 'public.audit_events', 'INSERT')
       OR NOT has_table_privilege('enclave_app', 'public.audit_events', 'SELECT') THEN
        RAISE EXCEPTION
            'enclave_app cannot INSERT or SELECT audit_events; the policy engine cannot audit';
    END IF;
END
$$;
