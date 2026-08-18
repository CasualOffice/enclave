-- Grants the application role the privileges it needs, so that it can actually be used.
--
-- Migration 0002 created `enclave_app` as a non-owner role, enabled and FORCED row-level security
-- on every tenant-scoped table, and granted on `audit_events`. It never granted on the others.
--
-- That gap hid a larger one. With no grants, nothing could connect as `enclave_app` and do useful
-- work, so nothing did — the test harness and the dev stack both connect as the cluster superuser.
-- Superusers bypass row-level security entirely. Every test that believed it was demonstrating
-- tenant isolation was running with the isolation switched off, and a cross-tenant read returned
-- 200 the first time an end-to-end request actually tried one (ENC-124).
--
-- The policies in 0002 were correct throughout. Nothing had ever exercised them.
--
-- Forward-only, so this is a new migration rather than an edit to 0002 (CLAUDE.md, docs/12 §5).

-- Ordinary tenant-scoped tables: full DML. RLS decides which rows; these decide which verbs.
DO $$
DECLARE
    tbl RECORD;
BEGIN
    FOR tbl IN
        SELECT c.relname
        FROM pg_catalog.pg_class      c
        JOIN pg_catalog.pg_namespace  n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute  a ON a.attrelid = c.oid
        WHERE n.nspname   = 'public'
          AND c.relkind   IN ('r', 'p')
          AND a.attname   = 'tenant_id'
          AND a.attnum    > 0
          AND NOT a.attisdropped
          -- audit_events is append-only and was granted deliberately in 0002. Re-granting here
          -- would hand the application UPDATE and DELETE and quietly undo that.
          AND c.relname  <> 'audit_events'
          AND c.relname NOT LIKE 'audit_events_%'
        ORDER BY c.relname
    LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO enclave_app', tbl.relname
        );
    END LOOP;
END
$$;

-- Sequences behind identity columns.
DO $$
DECLARE
    seq RECORD;
BEGIN
    FOR seq IN
        SELECT c.relname
        FROM pg_catalog.pg_class     c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'S'
    LOOP
        EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE public.%I TO enclave_app', seq.relname);
    END LOOP;
END
$$;

GRANT USAGE ON SCHEMA public TO enclave_app;

-- The GUC the isolation policies read. Setting it is how a session declares its tenant; it is not
-- a privilege, but it must be settable by the role that uses it.
GRANT SET ON PARAMETER app.tenant_id TO enclave_app;
