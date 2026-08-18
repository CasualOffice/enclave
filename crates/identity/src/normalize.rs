//! Canonical forms for the values that identity is *looked up* by.
//!
//! # Why these are functions rather than a convention
//!
//! `users.normalized_email` and `groups.normalized_name` back partial unique indexes
//! (`uq_users_email`, `uq_groups_name` in `migrations/0001_foundations.sql`). A writer and a reader
//! that fold differently do not fail loudly — they produce a *second* row for the same person, and
//! then a lookup that finds whichever one it happens to sort to. That is an account-takeover shape,
//! not a cosmetic bug, so the folding lives in one place and both sides call it.
//!
//! # The folding happens in Rust, never in SQL
//!
//! No query here calls `lower()`. PostgreSQL's `lower()` is collation-dependent and the collation
//! is a property of the database, so a restore into a differently-configured cluster would quietly
//! change what matches what. Folding in the application makes the stored value and the lookup value
//! come from the same code path on the same machine.

/// Folds an email address into the form stored in `users.normalized_email`.
///
/// Trim, then lowercase the whole address.
///
/// Lowercasing the local part is technically not what RFC 5321 says — `Bob@` and `bob@` are
/// distinct addresses to a strict reader. It is nonetheless what every mail system in practice
/// does, what the seeded fixtures do, and what users expect when they type their address with a
/// capital letter. The alternative, case-sensitive local parts, means `Bob@x` and `bob@x` are two
/// accounts, which is a far worse surprise than the one being accepted here.
///
/// This is normalization, not validation, and certainly not an identity check: it does not reject
/// malformed addresses and it does nothing about Unicode confusables. Validation belongs to the
/// provisioning path.
#[must_use]
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Folds a group name into the form stored in `groups.normalized_name`.
///
/// Trim, collapse internal whitespace runs to a single space, then lowercase. The whitespace
/// collapse matters here in a way it does not for email: group names are typed by administrators
/// and pasted from directories, and `"Finance  Leads"` and `"Finance Leads"` naming two different
/// groups is a permission model nobody can reason about.
#[must_use]
pub fn normalize_group_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (index, word) in name.split_whitespace().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(word);
    }
    out.to_lowercase()
}

/// Folds a tenant slug for lookup.
///
/// `tenants.slug` has a plain `UNIQUE` constraint and no separate normalized column, so this is a
/// lookup-side fold only: it makes `/t/Acme` and `/t/acme` resolve to the same tenant without
/// claiming the stored value was written through here.
#[must_use]
pub fn normalize_slug(slug: &str) -> String {
    slug.trim().to_lowercase()
}

/// Folds a hostname for a custom-domain lookup.
///
/// Trim, drop the trailing root dot a fully-qualified name may carry, drop any `:port` suffix, and
/// lowercase. DNS names are case-insensitive, and a `Host` header legitimately arrives with a port
/// and occasionally with the root dot; none of those may change which tenant is resolved — this is
/// the value that becomes `app.tenant_id`, so a fold that lets two spellings disagree is a tenancy
/// bug.
///
/// Internationalized names are **not** converted to punycode here. A browser sends the A-label
/// already, so a stored A-label matches; a U-label typed into a configuration file will not match
/// and should be rejected at provisioning time rather than silently converted at lookup time, where
/// the conversion would be invisible.
#[must_use]
pub fn normalize_domain(domain: &str) -> String {
    let trimmed = domain.trim();
    // IPv6 literals in a Host header are bracketed (`[::1]:8080`); splitting on the last colon
    // would mangle them, so only strip a port when the remainder has no colon left.
    let without_port = match trimmed.rsplit_once(':') {
        Some((head, port))
            if !head.contains(':')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            head
        }
        _ => trimmed,
    };
    without_port.trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn emails_fold_case_and_surrounding_whitespace() {
        assert_eq!(
            normalize_email("  Owner@Tenant-Alpha.Example \n"),
            "owner@tenant-alpha.example"
        );
        assert_eq!(normalize_email("owner@tenant-alpha.example"), "owner@tenant-alpha.example");
    }

    #[test]
    fn the_fold_agrees_with_what_the_fixtures_store() {
        // `enclave_testing` seeds `normalized_email` as `email.to_lowercase()`. If this function
        // ever diverges from that, every lookup against the seeded tenants silently returns None
        // and the integration tests fail in a way that looks like a query bug.
        let email = "owner@tenant-alpha.example";
        assert_eq!(normalize_email(email), email.to_lowercase());
    }

    #[test]
    fn group_names_collapse_whitespace_before_folding_case() {
        assert_eq!(normalize_group_name("  Finance   Leads "), "finance leads");
        assert_eq!(normalize_group_name("Finance Leads"), "finance leads");
        assert_eq!(normalize_group_name("finance-leads"), "finance-leads");
        assert_eq!(normalize_group_name(""), "");
    }

    #[test]
    fn domains_fold_case_ports_and_the_root_dot() {
        assert_eq!(normalize_domain("Docs.Acme.COM"), "docs.acme.com");
        assert_eq!(normalize_domain("docs.acme.com."), "docs.acme.com");
        assert_eq!(normalize_domain(" docs.acme.com:8443 "), "docs.acme.com");
        assert_eq!(normalize_domain("docs.acme.com:"), "docs.acme.com:");
    }

    #[test]
    fn an_ipv6_host_is_not_mangled_by_the_port_strip() {
        // `rsplit_once(':')` on `[::1]` would leave `[:`, which matches nothing and would send a
        // custom-domain lookup to the wrong answer rather than to no answer.
        assert_eq!(normalize_domain("[::1]"), "[::1]");
        assert_eq!(normalize_domain("[::1]:8443"), "[::1]:8443");
    }

    #[test]
    fn slugs_fold_case_and_whitespace() {
        assert_eq!(normalize_slug(" Tenant-Alpha "), "tenant-alpha");
    }
}
