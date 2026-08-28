-- ENC-705 — the two privileges `enclave_platform` needs on `refresh_tokens`.
--
-- `RefreshTokenStore::find_by_hash` and `revoke_returning` are the only statements in
-- `crates/db/src/auth_tokens.rs` that take `DbPool::platform_connection`, and they do so for a
-- stated reason: a refresh token arrives as an opaque string with no tenant beside it, so the
-- lookup cannot be tenant-scoped without accepting a tenant from the caller — one layer from a
-- request body, which is `CLAUDE.md` rule 3. The same argument holds for revocation, which must
-- reach every row in a family wherever it sits.
--
-- `0002_rls_policies.sql` grants `enclave_platform` only `SELECT, UPDATE, DELETE ON events_outbox`
-- and `SELECT ON tenants`. So in a deployment that genuinely separates the roles, both statements
-- fail with `permission denied` rather than returning no rows: **a user cannot refresh a session
-- and cannot log out.** Sign-in works, and staying signed in does not.
--
-- It has never been caught because the development stack and the test harness both connect as the
-- cluster superuser, which bypasses grants and row-level security alike. That is a property of
-- those environments, not of the code, and `crates/db/tests/grant_coverage.rs` now asserts these
-- two privileges by running the statements under `SET ROLE enclave_platform` rather than by
-- reading the catalogue — a grant that exists and a statement that works are different claims.
--
-- Deliberately not granted: `INSERT` or `DELETE`. `insert` and `rotate` are handed a
-- `RefreshRecord` that already carries its `tenant_id` and go through `DbPool::begin` like any
-- other write, so the platform role has no business creating or destroying these rows. Narrower is
-- the point: this role holds `BYPASSRLS`, so every privilege it gains is a privilege that sees
-- every tenant.

GRANT SELECT, UPDATE ON refresh_tokens TO enclave_platform;

-- The same shape as `0002`'s self-check: assert at apply time rather than trusting that the
-- statement above did what it reads like, since a typo'd role name is a no-op that succeeds.
DO $$
BEGIN
    IF NOT has_table_privilege('enclave_platform', 'refresh_tokens', 'SELECT') THEN
        RAISE EXCEPTION 'enclave_platform cannot SELECT refresh_tokens: session refresh will fail';
    END IF;
    IF NOT has_table_privilege('enclave_platform', 'refresh_tokens', 'UPDATE') THEN
        RAISE EXCEPTION 'enclave_platform cannot UPDATE refresh_tokens: logout will fail';
    END IF;
END
$$;
