//! Host → tenant, for the requests that arrive before any tenant context exists.
//!
//! # Why this is here and not in the handler that needs it
//!
//! [`DbPool::platform_connection`](crate::DbPool::platform_connection) names three legitimate
//! callers and then says, in its own words, what a fourth almost always turns out to be:
//!
//! > If a handler appears to need this, the actual requirement is almost always "resolve a tenant
//! > from a host header", which is a separate, deliberately narrow lookup rather than general
//! > cross-tenant access.
//!
//! `ENC-685` is that handler: `POST /api/v1/auth/login` has no token to read a tenant out of, and
//! `CLAUDE.md` rule 3 leaves exactly one other source — the routed host. So the lookup is written
//! **here**, beside [`active_tenants`](crate::active_tenants), for the reason that function gives:
//! `grep -rn platform_connection crates/` stays a complete list of the places row-level security is
//! bypassed, and every cross-tenant `WHERE` clause in the workspace is reviewed on one screen.
//!
//! # Why the platform role at all, for a table with no policy
//!
//! `tenants` carries no `tenant_id` column, so migration `0002` gives it no row-level-security
//! policy — and migration `0003`, which derives its grants from the same predicate, therefore gives
//! `enclave_app` **no privilege on it whatsoever**. The application role cannot read `tenants` at
//! all. `0002` grants `SELECT ON tenants TO enclave_platform` and that is the only door.
//!
//! # It answers one question and cannot be asked a second
//!
//! [`resolve_routed_tenant`] returns a [`TenantId`] or nothing. Not a name, not a slug, not a
//! status, not a settings blob — the same narrowness [`active_tenants`](crate::active_tenants)
//! argues for, and for the same reason: a `tenant_by_host()` returning rows would be a
//! BYPASSRLS-backed reader of tenant metadata sitting in the crate every domain crate depends on,
//! and the first caller wanting a display name would find it perfectly reasonable to add one.
//!
//! # What it does not yet do: verified custom domains
//!
//! `docs/05-API.md §3` and `docs/13-IDENTITY-SSO-SCIM.md` model a tenant reachable at its own
//! domain, and `enclave_identity::TenantRepository::find_by_verified_domain` implements that
//! lookup against `tenant_domains`. It is not reachable from here: `tenant_domains` **does** carry
//! `tenant_id`, so it has a policy, and `0002` grants `enclave_platform` nothing on it — a query
//! would fail with `permission denied` rather than resolve. Closing that needs a migration, which
//! is `ENC-686`. Until then the routing key is the tenant **slug**, which `docs/04-DATA-MODEL.md
//! §7` already calls "a routing key: it appears in custom-domain resolution".

use enclave_core::id::TenantId;
use sqlx::Row as _;
use uuid::Uuid;

use crate::normalize::normalize_slug;
use crate::pool::DbPool;
use crate::DbError;

/// The tenant a request addressed to `host` executes inside, if there is one.
///
/// `host` is the routed authority — the `Host` header, or whatever the edge resolved it to. The
/// **leftmost DNS label** is read as the tenant slug: `tenant-alpha.enclave.example` resolves
/// `tenant-alpha`. A bare single-label host resolves nothing, because a deployment served at
/// `localhost` has not routed a tenant and guessing one would be inventing tenancy out of a default.
///
/// # This value becomes `app.tenant_id`, so read the two properties it rests on
///
/// 1. **The host is not a body field.** `CLAUDE.md` rule 3 forbids taking tenancy from anything the
///    caller puts in a request *payload*; the routed host is the other permitted source, and it is
///    the one TLS terminates on. A caller who forges `Host: tenant-beta.…` does not thereby reach
///    `tenant-alpha`'s data — they reach `tenant-beta`, where their credentials do not work. The
///    attack this closes is a login body naming its own tenant, which is unwritable now: the
///    parameter is a host and the caller of this function has no other one to pass.
/// 2. **Only a live tenant resolves.** `ACTIVE` and `READ_ONLY`; soft-deleted, `SUSPENDED` and
///    `DELETING` tenants resolve to `None`, so a suspended tenant's users cannot sign in and a
///    deleting tenant does not accept new sessions for data on its way out. That mirrors
///    [`active_tenants`](crate::active_tenants), which is the same lifecycle decision taken for
///    background work (`docs/11-OPERATIONS.md §12`).
///
/// # Errors
///
/// [`DbError::PlatformNotConfigured`] when the deployment has no platform DSN — which is a
/// deployment that cannot sign anyone in and should say so loudly rather than resolve every host to
/// nothing — and [`DbError::Query`] for a statement failure.
pub async fn resolve_routed_tenant(
    pool: &DbPool,
    host: &str,
) -> Result<Option<TenantId>, DbError> {
    let Some(slug) = routing_slug(host) else { return Ok(None) };

    let mut conn = pool.platform_connection().await?;
    let row = sqlx::query(SELECT_TENANT_BY_SLUG)
        .bind(&slug)
        .fetch_optional(&mut *conn)
        .await
        .map_err(DbError::Query)?;

    Ok(row.map(|row| TenantId::from_uuid(row.get::<Uuid, _>("id"))))
}

/// The slug a routed host names, or `None` when it names none.
///
/// Separate from the query so that the parsing — which is where the mistakes are — is testable
/// without a database. Everything it strips is something an intermediary or a browser can legally
/// add: a port, a trailing root dot, a case difference, surrounding whitespace.
fn routing_slug(host: &str) -> Option<String> {
    let host = host.trim();
    // An IPv6 authority is bracketed and contains colons; it addresses a host, never a tenant.
    if host.starts_with('[') {
        return None;
    }
    // `example.com:8443` — the port is not part of the name.
    let host = host.split(':').next().unwrap_or(host);
    // A fully-qualified name may carry the root label.
    let host = host.trim_end_matches('.');

    let label = host.split('.').next().unwrap_or_default();
    // One label is a bare host — `localhost`, a container name, a load-balancer address. It has
    // not routed a tenant, and reading it as a slug would make `http://localhost/` resolve to a
    // tenant called `localhost` the moment somebody created one.
    if label.is_empty() || !host.contains('.') {
        return None;
    }

    let slug = normalize_slug(label);
    if slug.is_empty() {
        return None;
    }
    Some(slug)
}

/// One tenant id by slug, restricted to the statuses that may serve a request.
///
/// `id` and nothing else — see the module documentation for why the column list is the whole
/// security surface of this function.
const SELECT_TENANT_BY_SLUG: &str = "SELECT id FROM tenants \
     WHERE slug = $1 AND deleted_at IS NULL AND status IN ('ACTIVE', 'READ_ONLY')";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_leftmost_label_is_the_slug() {
        assert_eq!(routing_slug("tenant-alpha.enclave.example").as_deref(), Some("tenant-alpha"));
        assert_eq!(routing_slug("TENANT-ALPHA.Enclave.Example").as_deref(), Some("tenant-alpha"));
        assert_eq!(routing_slug("tenant-alpha.enclave.example:8443").as_deref(), Some("tenant-alpha"));
        assert_eq!(routing_slug("tenant-alpha.enclave.example.").as_deref(), Some("tenant-alpha"));
        assert_eq!(routing_slug("  tenant-beta.enclave.example  ").as_deref(), Some("tenant-beta"));
    }

    /// The positive control for the case below: the same parser *does* produce a slug for a routed
    /// host, so "these resolve to nothing" is not passing against a function that returns `None`
    /// for everything (`docs/12-TESTING.md §1.2`).
    #[test]
    fn a_host_that_routes_no_tenant_resolves_nothing() {
        assert!(routing_slug("tenant-alpha.enclave.example").is_some(), "positive control");

        for host in ["localhost", "", "   ", "api", "[::1]", "[::1]:8443", ".", ":8443"] {
            assert_eq!(routing_slug(host), None, "{host:?} must not name a tenant");
        }
    }

    /// The statuses are in the SQL rather than filtered in Rust, so the assertion is on the SQL.
    #[test]
    fn only_a_live_tenant_can_be_routed_to() {
        assert!(SELECT_TENANT_BY_SLUG.contains("deleted_at IS NULL"));
        assert!(SELECT_TENANT_BY_SLUG.contains("status IN ('ACTIVE', 'READ_ONLY')"));
        // The narrowness this function's whole argument rests on: one column, and it is the id.
        assert!(SELECT_TENANT_BY_SLUG.starts_with("SELECT id FROM tenants"));
    }
}
