-- ENC-686 — the privilege custom-domain routing needs.
--
-- `CLAUDE.md` rule 3 names exactly two sources of tenant identity: a verified token, and
-- custom-domain routing. The second has never worked. `enclave_db::resolve_routed_tenant` reads the
-- **slug** from the leftmost label and nothing else, because `tenant_domains` carries `tenant_id`,
-- so `0002_rls_policies.sql` gave it a row-level-security policy, and granted `enclave_platform`
-- nothing on it: the query fails with `permission denied` rather than returning no rows.
-- `enclave_app` cannot stand in either — `0003` derives its grants from the `tenant_id` predicate,
-- and the join's other side, `tenants`, has no such column.
--
-- So `enclave_identity::TenantRepository::find_by_verified_domain` exists, is correct, is
-- documented as taking a `PlatformConnection`, and had no caller that could succeed.
--
-- `SELECT` only. This role holds `BYPASSRLS`, so every privilege it gains is one that sees every
-- tenant; routing reads a mapping and writes nothing. Domain verification — the flow that sets
-- `verified_at` — is an administrative action under a tenant context and goes through `enclave_app`
-- like any other write.
--
-- The read is safe to make cross-tenant because of what it returns: a `TenantId` for a host that
-- TLS already terminated on. It cannot be steered by a request body (rule 3), and a forged `Host`
-- reaches the tenant that host names, where the caller's credentials do not work.

GRANT SELECT ON tenant_domains TO enclave_platform;

-- Asserted at apply time, in the shape `0002` uses: a typo'd role name is a no-op that succeeds.
DO $$
BEGIN
    IF NOT has_table_privilege('enclave_platform', 'tenant_domains', 'SELECT') THEN
        RAISE EXCEPTION 'enclave_platform cannot SELECT tenant_domains: custom-domain routing will fail';
    END IF;
    IF has_table_privilege('enclave_platform', 'tenant_domains', 'INSERT')
       OR has_table_privilege('enclave_platform', 'tenant_domains', 'UPDATE')
       OR has_table_privilege('enclave_platform', 'tenant_domains', 'DELETE') THEN
        RAISE EXCEPTION 'enclave_platform holds a write privilege on tenant_domains; routing reads a mapping and writes nothing';
    END IF;
END
$$;
