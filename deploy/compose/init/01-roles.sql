-- Pre-provisions the three Enclave roles, before any migration runs.
--
-- Migration 0001 also creates them, guarded by
-- `IF NOT EXISTS (SELECT 1 FROM pg_roles ...)`. That guard is check-then-act, and roles are
-- cluster-wide rather than per-database: two databases in one cluster migrating concurrently both
-- pass the check, both issue CREATE ROLE, and one fails with `unique_violation` (23505) on
-- pg_authid_rolname_index. It reproduced ten times out of ten (ENC-116).
--
-- Creating the roles here — in docker-entrypoint-initdb.d, which PostgreSQL runs exactly once,
-- single-threaded, before the server accepts external connections — closes the window: by the time
-- any migration runs, the roles exist and 0001's guard is a no-op.
--
-- This is the shape production should take too. Migrations should not be creating cluster-wide
-- principals: they are a deployment concern, provisioned alongside the credentials that go with
-- them (see 0001's own comment, and docs/11-OPERATIONS.md §12).
--
-- It is a mitigation, not the fix. The racy guard is still in 0001 and would still fire for anyone
-- who migrates into a cluster where the roles were never provisioned. Removing it means amending a
-- merged migration, which is forward-only and gate-enforced — a control decision, tracked as
-- ENC-116 rather than taken quietly here.
--
-- No passwords. Credentials come from the deployment's secret store (CLAUDE.md rule 11); these
-- roles cannot authenticate until one is set. The dev stack connects as the superuser instead.

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
