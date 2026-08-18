//! Reading the tenant registry.
//!
//! # The one place in this crate that is not tenant-scoped
//!
//! Every other repository here runs inside a `TenantScoped` transaction, where row-level security
//! has already narrowed the visible rows to one tenant. Tenant *resolution* cannot: it is what
//! produces the tenant id in the first place, and it runs before any context exists
//! (`docs/03-LLD.md §5`, `CLAUDE.md` rule 3 — the tenant comes from the verified token or from
//! custom-domain routing, never from the client).
//!
//! The shape of the functions does not change — they still take the `&mut PgConnection` a
//! transaction derefs to (`plans/M1-CONTENT-CORE.md` D10) — but the *connection* a caller supplies
//! differs by function, and getting that wrong is a silent failure rather than a loud one:
//!
//! | Function | Table read | Under RLS? | Connection to supply |
//! |---|---|---|---|
//! | [`TenantRepository::find_by_id`] | `tenants` | no policy (`migrations/0002` §2) | either |
//! | [`TenantRepository::find_by_slug`] | `tenants` | no policy | either |
//! | [`TenantRepository::find_by_verified_domain`] | `tenants` + `tenant_domains` | **`tenant_domains` is policied** | `PlatformConnection` |
//!
//! `tenant_domains` carries `tenant_id` and therefore received `tenant_isolation` in migration
//! 0002. Called on an application connection with no `app.tenant_id` set, the domain lookup returns
//! **no rows** — not an error, just an unresolvable domain. Migration 0002 records this as an open
//! question for `docs/04`; until it is answered, the routing layer must use
//! [`enclave_db::PlatformConnection`] for the domain path, and this table says so where the caller
//! will read it.

use enclave_core::TenantId;
use enclave_db::{normalize_slug, sql};
use sqlx::PgConnection;

use crate::error::Result;
use crate::model::Tenant;
use crate::normalize::normalize_domain;
use crate::row::tenant_from_row;

/// Reads the tenant registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct TenantRepository;

impl TenantRepository {
    /// Finds a tenant by id.
    ///
    /// Soft-deleted tenants are not returned. A tenant in `deleted_at` is being purged; resolving
    /// it would let requests continue to arrive for data that is on its way out, and the correct
    /// answer to those is that the tenant does not exist.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`crate::IdentityError::MalformedRow`] if `status` holds a value
    /// outside [`crate::model::TenantStatus`].
    pub async fn find_by_id(conn: &mut PgConnection, tenant: TenantId) -> Result<Option<Tenant>> {
        let row =
            sqlx::query(SELECT_TENANT_BY_ID).bind(sql(tenant)).fetch_optional(&mut *conn).await?;
        row.as_ref().map(tenant_from_row).transpose()
    }

    /// Finds a tenant by slug, folding case (see [`enclave_db::normalize_slug`]).
    ///
    /// # Errors
    ///
    /// As [`TenantRepository::find_by_id`].
    pub async fn find_by_slug(conn: &mut PgConnection, slug: &str) -> Result<Option<Tenant>> {
        let row = sqlx::query(SELECT_TENANT_BY_SLUG)
            .bind(normalize_slug(slug))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(tenant_from_row).transpose()
    }

    /// Finds the tenant that owns a **verified** custom domain.
    ///
    /// `verified_at IS NOT NULL` is the whole security property of this function. A `tenant_domains`
    /// row exists from the moment someone *claims* a domain; the verification token proves they
    /// control it. Resolving an unverified row would let any tenant claim `docs.competitor.example`
    /// and have requests for it routed into their own tenant — which, since this value becomes
    /// `app.tenant_id`, is a tenancy takeover rather than a cosmetic mistake.
    ///
    /// Supply a [`enclave_db::PlatformConnection`]: `tenant_domains` is under row-level security and
    /// there is no tenant context yet. See the [module documentation](self).
    ///
    /// # Errors
    ///
    /// As [`TenantRepository::find_by_id`].
    pub async fn find_by_verified_domain(
        conn: &mut PgConnection,
        domain: &str,
    ) -> Result<Option<Tenant>> {
        let row = sqlx::query(SELECT_TENANT_BY_DOMAIN)
            .bind(normalize_domain(domain))
            .fetch_optional(&mut *conn)
            .await?;
        row.as_ref().map(tenant_from_row).transpose()
    }
}

/// One tenant by id. `tenants` has no `tenant_id` column, so its key is `id` and there is no second
/// application predicate to add here.
const SELECT_TENANT_BY_ID: &str = "SELECT id, slug, display_name, status, residency_region, \
     policy_generation, created_at, updated_at \
     FROM tenants WHERE id = $1 AND deleted_at IS NULL";

/// One tenant by slug.
const SELECT_TENANT_BY_SLUG: &str = "SELECT id, slug, display_name, status, residency_region, \
     policy_generation, created_at, updated_at \
     FROM tenants WHERE slug = $1 AND deleted_at IS NULL";

/// One tenant by verified custom domain.
const SELECT_TENANT_BY_DOMAIN: &str = "SELECT t.id, t.slug, t.display_name, t.status, \
     t.residency_region, t.policy_generation, t.created_at, t.updated_at \
     FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id \
     WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND t.deleted_at IS NULL";

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::row::TENANT_COLUMNS;

    #[test]
    fn the_select_lists_match_the_decoders_column_constant() {
        assert!(SELECT_TENANT_BY_ID.contains(TENANT_COLUMNS), "{SELECT_TENANT_BY_ID}");
        assert!(SELECT_TENANT_BY_SLUG.contains(TENANT_COLUMNS), "{SELECT_TENANT_BY_SLUG}");
        // The joined form is aliased, so compare column by column instead.
        for column in TENANT_COLUMNS.split(',') {
            let qualified = format!("t.{}", column.trim());
            assert!(SELECT_TENANT_BY_DOMAIN.contains(&qualified), "missing {qualified}");
        }
    }

    /// The assertion that would have caught a domain lookup resolving an unverified claim. Cheap to
    /// state, and the consequence of losing it is that any tenant can claim any hostname.
    #[test]
    fn the_domain_lookup_requires_verification() {
        assert!(SELECT_TENANT_BY_DOMAIN.contains("d.verified_at IS NOT NULL"));
    }

    #[test]
    fn every_lookup_excludes_soft_deleted_tenants() {
        for query in [SELECT_TENANT_BY_ID, SELECT_TENANT_BY_SLUG, SELECT_TENANT_BY_DOMAIN] {
            assert!(query.contains("deleted_at IS NULL"), "{query}");
        }
    }
}
