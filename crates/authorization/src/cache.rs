//! The cache key from `docs/04-DATA-MODEL.md §9` rule 5 — the key only, not a cache.
//!
//! # Why a key with no cache behind it
//!
//! The key is part of the *contract*, not of the implementation: the moment something writes an
//! entry under a key, invalidation depends on every writer and reader agreeing on the shape of it,
//! down to the separator. Defining it here, once, with the test that pins the literal format, means
//! the cache that lands later cannot quietly pick a different shape — and that `acl_revision`
//! cannot quietly be dropped from it, which is the mistake that turns a cache into a stale-grant
//! machine.
//!
//! # What the key identifies, and the trap in it
//!
//! `authz:{tenant}:{actor}:{resource}:{acl_revision}` — and note what is **not** in it: the action.
//! A key that omits the action cannot address one action's verdict, so anything stored under it
//! must be the caller's whole effective permission set for that resource. An implementation that
//! stored a single `Allow`/`Deny` here would answer `download` with the verdict computed for
//! `metadata_read` the first time both were asked in the same revision — a silent privilege
//! escalation with no failing test anywhere near it. If a per-action entry is ever wanted, the
//! action belongs *in the key*, and this function is where that change is made.
//!
//! `acl_revision` is the invalidation mechanism: `files.acl_revision`
//! (`docs/04-DATA-MODEL.md §8`) is bumped when permissions change, so a changed ACL yields a
//! different key rather than requiring anything to be deleted. Entries under the old revision are
//! unreachable and expire on their own.

use enclave_core::{Actor, ResourceRef, TenantId};

/// The prefix every key carries, so a cache can be swept by pattern without a registry of keys.
pub const CACHE_KEY_PREFIX: &str = "authz";

/// Builds the cache key for one caller's effective permissions on one resource.
///
/// The actor renders as `kind:id` — the kind is included because two principals of different kinds
/// could hold the same UUID, and a cache is exactly the place where "close enough" identity becomes
/// somebody else's permissions. [`Actor::System`] has no identifier and renders as `system:-`; it
/// is spelled explicitly rather than left empty so that a key can never collapse to one with a
/// missing segment.
///
/// See the [module documentation](self) for why the action is deliberately absent and what an
/// implementation must therefore store.
#[must_use]
pub fn cache_key(
    tenant: TenantId,
    actor: &Actor,
    resource: &ResourceRef,
    acl_revision: i64,
) -> String {
    // `ResourceRef`'s own `Display` is `kind:id`, which is already the form used in log lines and
    // error contexts. Reusing it keeps one spelling of a resource across the system rather than
    // inventing a second one that has to be kept in step.
    format!("{CACHE_KEY_PREFIX}:{tenant}:{}:{resource}:{acl_revision}", actor_segment(actor))
}

/// Renders the actor segment of the key.
fn actor_segment(actor: &Actor) -> String {
    match actor.subject_id() {
        Some(id) => format!("{}:{id}", actor.kind()),
        None => format!("{}:-", actor.kind()),
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{FileId, GuestId, UserId};
    use uuid::Uuid;

    use super::*;

    fn ids() -> (TenantId, UserId, FileId) {
        (
            TenantId::from_uuid(Uuid::from_u128(1)),
            UserId::from_uuid(Uuid::from_u128(2)),
            FileId::from_uuid(Uuid::from_u128(3)),
        )
    }

    #[test]
    fn the_key_matches_the_documented_shape() {
        // `docs/04-DATA-MODEL.md §9` rule 5, literal. A cache writer and a cache reader in
        // different crates agree only because this string is pinned here.
        let (tenant, user, file) = ids();
        let key = cache_key(tenant, &Actor::User(user), &ResourceRef::file(tenant, file), 7);
        assert_eq!(
            key,
            "authz:00000000-0000-0000-0000-000000000001:\
             user:00000000-0000-0000-0000-000000000002:\
             file:00000000-0000-0000-0000-000000000003:7"
        );
    }

    #[test]
    fn a_changed_acl_revision_changes_the_key() {
        // This is the whole invalidation strategy: permissions change, `files.acl_revision` is
        // bumped, and every cached decision for that resource becomes unreachable without anything
        // having to be found and deleted.
        let (tenant, user, file) = ids();
        let actor = Actor::User(user);
        let resource = ResourceRef::file(tenant, file);
        assert_ne!(
            cache_key(tenant, &actor, &resource, 1),
            cache_key(tenant, &actor, &resource, 2)
        );
    }

    #[test]
    fn two_principals_of_different_kinds_sharing_an_id_get_different_keys() {
        let (tenant, _, file) = ids();
        let id = Uuid::from_u128(42);
        let resource = ResourceRef::file(tenant, file);
        assert_ne!(
            cache_key(tenant, &Actor::User(UserId::from_uuid(id)), &resource, 1),
            cache_key(tenant, &Actor::Guest(GuestId::from_uuid(id)), &resource, 1)
        );
    }

    #[test]
    fn the_tenant_is_part_of_the_key() {
        // Two tenants can hold resources with different ids, but a key without the tenant would be
        // one collision away from serving a decision across the isolation boundary.
        let (alpha, user, file) = ids();
        let beta = TenantId::from_uuid(Uuid::from_u128(9));
        let actor = Actor::User(user);
        assert_ne!(
            cache_key(alpha, &actor, &ResourceRef::file(alpha, file), 1),
            cache_key(beta, &actor, &ResourceRef::file(beta, file), 1)
        );
    }

    #[test]
    fn different_resources_get_different_keys_even_at_the_same_revision() {
        let (tenant, user, file) = ids();
        let actor = Actor::User(user);
        let other = FileId::from_uuid(Uuid::from_u128(99));
        assert_ne!(
            cache_key(tenant, &actor, &ResourceRef::file(tenant, file), 1),
            cache_key(tenant, &actor, &ResourceRef::file(tenant, other), 1)
        );
        // Same identifier, different kind — a folder and a file share the `FileId` space
        // (`enclave_core::ResourceRef::folder`), so the kind is what separates them.
        assert_ne!(
            cache_key(tenant, &actor, &ResourceRef::file(tenant, file), 1),
            cache_key(tenant, &actor, &ResourceRef::folder(tenant, file), 1)
        );
    }

    #[test]
    fn the_system_actor_still_produces_a_well_formed_key() {
        let (tenant, _, file) = ids();
        let key = cache_key(tenant, &Actor::System, &ResourceRef::file(tenant, file), 1);
        assert!(key.contains(":system:-:"), "{key}");
        assert_eq!(key.matches(':').count(), 6, "a segment is missing from {key}");
    }
}
