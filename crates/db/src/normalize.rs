//! Canonical forms for values that rows are *looked up* by.
//!
//! # Why these are functions rather than a convention
//!
//! Lookup keys back unique indexes — `tenants.slug` has a plain `UNIQUE`, and
//! `uq_workspace_slug` is `UNIQUE (tenant_id, slug) WHERE deleted_at IS NULL`. A writer and a
//! reader that fold differently do not fail loudly: they produce a *second* row for the same
//! thing, and then a lookup that finds whichever one it happens to sort to. So the folding lives
//! in one place and both sides call it.
//!
//! # The folding happens in Rust, never in SQL
//!
//! No query calls `lower()`. PostgreSQL's `lower()` is collation-dependent and the collation is a
//! property of the database, so a restore into a differently-configured cluster would quietly
//! change what matches what. Folding in the application makes the stored value and the lookup
//! value come from the same code path on the same machine.
//!
//! # Why this one lives here
//!
//! [`normalize_slug`] was in `enclave-identity` next to the email and group-name folds, and
//! `enclave-workspaces` and `enclave-libraries` reached sideways into a peer domain crate for it —
//! the edge `plans/M0-FOUNDATIONS.md` D1 forbids. Slugs are a persistence concern (they exist to
//! satisfy a unique index), so the fold sits below every domain crate with the pagination
//! primitives (`ENC-137`). The folds that are genuinely about *identity* — email addresses, group
//! names and custom domains — stayed in `enclave_identity::normalize`, because nothing outside
//! identity looks a principal up.

/// Folds a slug for lookup.
///
/// `tenants.slug` has a plain `UNIQUE` constraint and no separate normalized column, so this is a
/// lookup-side fold only: it makes `/t/Acme` and `/t/acme` resolve to the same tenant without
/// claiming the stored value was written through here.
#[must_use]
pub fn normalize_slug(slug: &str) -> String {
    slug.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn slugs_fold_case_and_whitespace() {
        assert_eq!(normalize_slug(" Tenant-Alpha "), "tenant-alpha");
    }
}
