//! `enclave-identity` — the principal store: tenants, users, groups and nested membership.
//!
//! Security and governance — a policy service in the canonical chain. See `docs/02-HLD.md §4` for
//! where this crate sits in the architecture.
//!
//! # What this crate is
//!
//! Repositories, and the types they return. Three of them:
//!
//! * [`TenantRepository`] — resolve a tenant by id, slug or **verified** custom domain. This is the
//!   trusted derivation of the value that becomes `app.tenant_id`; it never comes from a body
//!   field, a query parameter or a header (`CLAUDE.md` rule 3).
//! * [`UserRepository`] — look a user up, page through a tenant's directory, record a sign-in, and
//!   bump the mass-revocation counter of `docs/03-LLD.md §5.4`.
//! * [`GroupRepository`] — direct membership, and [`GroupRepository::transitive_groups`], which
//!   flattens nested groups to the configured depth with cycle detection.
//!
//! # What this crate is not
//!
//! **It makes no authorization decision.** [`GroupClosure`] is an *input* to the authorization
//! stage (`docs/04-DATA-MODEL.md §9`, `ENC-126`), not a permission answer. Nothing here reads an
//! ACL, and nothing here should: the policy chain is called from the handler, before a domain
//! service is reached (`plans/M1-CONTENT-CORE.md` D11), so a repository that started making
//! decisions would be a second, unlinted enforcement point.
//!
//! It also holds no credentials. Password hashes, MFA methods and refresh-token families are the
//! `auth` crate's, and a repository that returned a hash alongside a profile is one careless
//! `Debug` away from putting it in a log.
//!
//! # The shape every function takes
//!
//! ```text
//! let mut tx = pool.begin(ctx.tenant_id).await?;                       // TenantScoped
//! let user = UserRepository::find_by_id(&mut tx, ctx.tenant_id, id).await?;
//! tx.commit().await?;
//! ```
//!
//! `&mut PgConnection`, never a pool (`plans/M1-CONTENT-CORE.md` D10). The caller supplies a
//! `TenantScoped` transaction, so a repository physically cannot run without a tenant context — and
//! the `no-raw-pool` structural gate keeps it that way. A pooled connection has no `app.tenant_id`,
//! so under `FORCE ROW LEVEL SECURITY` a query on one either fails or silently returns nothing;
//! that "silently" is why the rule is structural rather than advisory.
//!
//! Every query also carries its own `tenant_id = $1` predicate. That is not belt-and-braces about
//! RLS working — it is the second of the two layers `docs/04-DATA-MODEL.md §3` specifies, and the
//! one that keeps a query correct if it is ever run somewhere the first layer is not in force.
//! `ENC-124` is the reason to take that seriously: the policies were right for months, and nothing
//! had ever run as the application role, so nothing had ever exercised them.
//!
//! # The one exception, stated where it will be read
//!
//! [`TenantRepository::find_by_verified_domain`] reads `tenant_domains`, which **is** under
//! row-level security, from a path that runs *before* any tenant context exists. It needs an
//! [`enclave_db::PlatformConnection`]. On an application connection it returns no rows — an
//! unresolvable domain rather than an error. See [`tenant_repo`] for the full table.

pub mod cursor;
pub mod error;
pub mod group_repo;
pub mod model;
pub mod normalize;
pub mod tenant_repo;
pub mod user_repo;

mod row;

pub use cursor::{Cursor, FilterFingerprint, PageSize};
pub use error::{IdentityError, Result};
pub use group_repo::{GroupClosure, GroupRepository, NestingLimit};
pub use model::{
    Group, GroupSource, MemberType, Tenant, TenantStatus, User, UserSource, UserStatus,
};
pub use normalize::{normalize_domain, normalize_email, normalize_group_name, normalize_slug};
pub use tenant_repo::TenantRepository;
pub use user_repo::{UserFilter, UserPage, UserRepository};
