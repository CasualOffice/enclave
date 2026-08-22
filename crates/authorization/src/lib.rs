//! `enclave-authorization` — ACL resolution: inheritance, group closure, deny-wins.
//!
//! The authorization stage of the policy chain (`docs/02-HLD.md §4`, `docs/03-LLD.md §12`). It
//! answers one question — *may this principal perform this action on this resource?* — by the four
//! rules of `docs/04-DATA-MODEL.md §9`, and nothing else. It applies no barrier, no classification
//! ceiling and no DLP rule; those are separate stages for the reason the chain has stages at all.
//!
//! ```text
//! 1. chain      resource → parents → library → workspace, stopping where inheritance is broken
//! 2. principals the caller, its transitive group closure, EVERYONE
//! 3. verdict    any matching DENY wins; otherwise any matching ALLOW grants; otherwise refuse
//! 4. expiry     entries past `expires_at` are not entries
//! ```
//!
//! # How it is laid out, and why
//!
//! * [`admin`] answers the one question the ACL model has no rows for — *may this principal
//!   administer this tenant* (`ENC-619`) — and composes with everything below it.
//! * [`resolve`] holds the rules as pure functions over rows. They are the definition.
//! * [`repo`] holds the SQL that fetches those rows in three round trips per batch, whatever the
//!   batch size. Its `WHERE` clauses duplicate rules 2 and 4 as a prefilter; [`resolve`] re-applies
//!   them, so a query that fetches too much is slow rather than wrong.
//! * [`service`] classifies references, refuses what has no ACL model, and implements
//!   [`enclave_core::AuthorizationService`].
//! * [`cache`] defines the key of rule 5. There is no cache behind it yet, deliberately — see the
//!   module documentation for the trap that key hides.
//!
//! # Deny-by-default in three places
//!
//! A resource that does not exist, one in another tenant, one whose kind has no ACL model, an actor
//! that no ACL entry can name, and a chain that could not be walked to its root all produce the same
//! refusal. The single most valuable property of this crate is that every path that is not an
//! explicit grant ends at a denial, and the tests are arranged around proving that rather than
//! around proving that grants work.
//!
//! # What is deliberately not here
//!
//! * **Roles.** `role_definitions` and `workspace_members` grant permissions too
//!   (`docs/04-DATA-MODEL.md §7`, `§9`). This resolver reads `acl_entries` only; RBAC composes with
//!   it and is a separate item.
//! * **Action implication.** An `ALLOW` on `file.download` does not imply `file.metadata_read`.
//!   Every implication is a policy decision, and inferring them here would silently widen every
//!   grant a tenant has already written. Resolving several actions in one pass
//!   ([`AclResolver::effective_actions_in_tx`]) is not an exception to this: it shares the two
//!   round trips that do not mention the action, and keeps each action's entries in a bucket of
//!   their own from the moment they leave PostgreSQL.
//! * **Caching.** Only the key. A cache whose invalidation is not designed is a stale-grant
//!   machine, and stale grants outlive the revocation that was supposed to end them.

pub mod admin;
pub mod cache;
pub mod error;
pub mod materialise;
pub mod repo;
pub mod resolve;
pub mod self_service;
pub mod service;

pub use admin::{AdminAuthorization, AdminGrants, AdminRoles, PgAdminRoles};
pub use cache::{cache_key, CACHE_KEY_PREFIX};
pub use error::{AuthzError, Result};
pub use materialise::{
    break_file_inheritance, break_library_inheritance, MAX_MATERIALISED_ENTRIES,
};
pub use resolve::{
    AclEntry, AclResourceType, ChainNode, Effect, Effective, EffectiveGrid, EffectiveIndex,
    InheritanceChain, Principal, PrincipalKind, PrincipalSet,
};
pub use self_service::SelfServiceAuthorization;
pub use service::{AclResolver, PgAclAuthorization, ResolverLimits};
