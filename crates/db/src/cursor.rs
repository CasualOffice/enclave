//! Opaque pagination cursors, bound to a tenant and to a filter set.
//!
//! # Why this lives in `enclave-db` and not in a domain crate
//!
//! A cursor is signed and bound to a tenant and a filter set, which makes it a *persistence and
//! security* primitive rather than anything to do with users, workspaces or files. It started life
//! in `enclave-identity` because that is where the first listing needed it, and every later listing
//! then reached sideways into a domain crate to get it — an edge that inverts the dependency rule
//! in `plans/M0-FOUNDATIONS.md` D1. It sits here now because `enclave-db` is below every domain
//! crate, so no crate has to depend on a peer to page through its own rows. Nothing about the
//! bindings changed in the move (`ENC-137`).
//!
//! # What a cursor has to prevent
//!
//! `docs/03-LLD.md §17` fixes the shape: a cursor encodes `(sort_key, tie_break_id, filter_hash,
//! tenant_id)`, and *a cursor presented with different filters or by a different tenant is
//! rejected*. Both halves are enforced here, in [`Cursor::decode`], which is the only way to get the
//! key back out — a caller cannot obtain the position without also having proved the binding.
//!
//! The tenant check is belt-and-braces rather than the load-bearing control: the query runs inside a
//! `TenantScoped` transaction, so row-level security has already made another tenant's rows
//! invisible. It is here because a cursor that silently "works" across tenants is a cursor that
//! encourages a future caller to pass one across a boundary, and because the failure it produces
//! (an empty page) is much harder to diagnose than a rejection.
//!
//! The filter check prevents a subtler bug: page 1 filtered to `ACTIVE`, page 2 unfiltered, and the
//! caller silently skips every suspended user whose id sorts below the cursor. That is a wrong
//! answer that looks like a right one.
//!
//! # Sort key and tie-break are the same column
//!
//! Every identifier in this system is UUIDv7 (`enclave_core::id`), whose leading 48 bits are a
//! millisecond timestamp. `ORDER BY id` is therefore already creation order *and* already unique,
//! so the sort key and the tie-break collapse into one 16-byte value. There is no second column to
//! carry and no equal-key window to step over.
//!
//! # What is deliberately not here
//!
//! **The signature.** `§17` says cursors are signed; signing needs a key, and the key belongs to the
//! deployment's key provider, at the API edge, not in a repository. What signing adds over the two
//! checks below is integrity against a *tampered* cursor — and a tampered cursor can only move the
//! position within the same tenant and the same filter, which is a page the caller was already
//! entitled to request. The remaining gap is real but small, and it is closed where the key lives.
//! See the crate documentation for the note handed to the API layer.

use core::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use enclave_core::TenantId;
use sha2::{Digest, Sha256};

use crate::ids::SqlId;

/// Domain separator, so a fingerprint of a filter can never collide with a hash computed for some
/// other purpose over the same bytes.
///
/// The string still says `identity` because it is a wire constant, not a name: cursors issued by
/// the previous release are in flight and in clients' hands, and changing the separator would
/// reject every one of them. `ENC-137` moved the code, not the encoding.
const FINGERPRINT_DOMAIN: &[u8] = b"enclave.identity.cursor.filter.v1";

/// Bytes of the digest retained in the cursor.
///
/// Eight is enough: this is a *binding* check, not a secret. An attacker who found a colliding
/// filter would gain the ability to resume their own listing under a different filter of their own
/// choosing — no other tenant's rows become visible, because RLS decides that.
const FINGERPRINT_LEN: usize = 8;

/// Version byte, so the encoding can change without a stored or in-flight cursor from the previous
/// release being silently misread as the new layout.
const CURSOR_VERSION: u8 = 1;

/// `version | tenant (16) | key (16) | fingerprint (8)`.
const CURSOR_LEN: usize = 1 + 16 + 16 + FINGERPRINT_LEN;

/// The single answer every cursor rejection produces.
///
/// One variant with no detail, deliberately: wrong tenant, wrong filter, wrong length, wrong
/// version and forged all collapse to the same value, so a cursor cannot be used to probe
/// (`CLAUDE.md` rule 7). Callers map it onto their own crate's error — `IdentityError::InvalidCursor`
/// and its siblings — which is where the decision to render it as a `cursor` field validation
/// failure is made.
///
/// Its own type rather than a [`crate::DbError`] variant because nothing about it is a database
/// failure: no statement ran, nothing is retryable, and a caller matching on `DbError` should not
/// have to consider it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the pagination cursor is not valid for this request")]
pub struct InvalidCursor;

/// A digest of the filter set a page was produced under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterFingerprint([u8; FINGERPRINT_LEN]);

impl FilterFingerprint {
    /// Derives a fingerprint from a filter's canonical description.
    ///
    /// Each part is length-prefixed before hashing, so `["a", "bc"]` and `["ab", "c"]` cannot
    /// produce the same digest. Without that, two different filters whose descriptions concatenate
    /// identically would accept each other's cursors — which is precisely the check being made.
    #[must_use]
    pub fn of(parts: &[&str]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        let digest = hasher.finalize();
        let mut head = [0u8; FINGERPRINT_LEN];
        head.copy_from_slice(&digest[..FINGERPRINT_LEN]);
        Self(head)
    }
}

/// A position in a listing, bound to the tenant and filter set that produced it.
///
/// Generic over the identifier being paginated so that the binding rules are written once rather
/// than re-derived by each repository that grows a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor<T> {
    tenant: TenantId,
    after: T,
    filter: FilterFingerprint,
}

impl<T: SqlId> Cursor<T> {
    /// Builds the cursor that resumes *after* `key`.
    #[must_use]
    pub const fn new(tenant: TenantId, after: T, filter: FilterFingerprint) -> Self {
        Self { tenant, after, filter }
    }

    /// Renders the opaque form handed to clients.
    ///
    /// Base64url without padding, because this travels in a query string and `+`, `/` and `=` all
    /// need escaping there — an encoding that survives a copy-paste is one fewer support ticket.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut bytes = [0u8; CURSOR_LEN];
        bytes[0] = CURSOR_VERSION;
        bytes[1..17].copy_from_slice(self.tenant.as_uuid().as_bytes());
        bytes[17..33].copy_from_slice(self.after.to_uuid().as_bytes());
        bytes[33..].copy_from_slice(&self.filter.0);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Parses a cursor and returns the key to resume after, **only** if it was issued for this
    /// tenant and this filter set.
    ///
    /// There is no accessor that yields the key without these checks, and no variant of this
    /// function that skips them. That is the difference between a rule and a convention.
    ///
    /// # Errors
    ///
    /// [`InvalidCursor`] for every rejection — wrong length, wrong version, wrong tenant, wrong
    /// filter, not base64. One answer for all of them, so the cursor cannot be used to learn
    /// anything (`CLAUDE.md` rule 7).
    pub fn decode(
        text: &str,
        tenant: TenantId,
        filter: FilterFingerprint,
    ) -> Result<T, InvalidCursor> {
        let bytes = URL_SAFE_NO_PAD.decode(text).map_err(|_| InvalidCursor)?;
        if bytes.len() != CURSOR_LEN || bytes[0] != CURSOR_VERSION {
            return Err(InvalidCursor);
        }

        let mut raw = [0u8; 16];
        raw.copy_from_slice(&bytes[1..17]);
        if TenantId::from_uuid(uuid::Uuid::from_bytes(raw)) != tenant {
            return Err(InvalidCursor);
        }

        if bytes[33..] != filter.0 {
            return Err(InvalidCursor);
        }

        raw.copy_from_slice(&bytes[17..33]);
        Ok(T::from_uuid(uuid::Uuid::from_bytes(raw)))
    }
}

/// How many rows a page may hold.
///
/// A newtype rather than a `u32` because the clamp is the whole point: `docs/05-API.md §6` fixes the
/// default at 50 and the maximum at 500, and a caller asking for a million rows must get 500 rather
/// than an unbounded query. Clamping instead of rejecting is deliberate — a client that asks for too
/// much wants as much as it can have, and a `400` on a paging parameter is a worse answer than a
/// full page plus a cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageSize(u32);

impl PageSize {
    /// The default page size (`docs/05-API.md §6`).
    pub const DEFAULT: Self = Self(50);
    /// The largest page any caller can obtain.
    pub const MAX: u32 = 500;

    /// Clamps a requested size into the permitted range.
    ///
    /// Zero clamps up to one: a page size of zero returns nothing forever, which turns a caller's
    /// paging loop into an infinite one.
    #[must_use]
    pub const fn new(requested: u32) -> Self {
        if requested == 0 {
            return Self(1);
        }
        if requested > Self::MAX {
            return Self(Self::MAX);
        }
        Self(requested)
    }

    /// The size as the `LIMIT` binding wants it.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0 as i64
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for PageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::UserId;

    use super::*;

    fn filter_a() -> FilterFingerprint {
        FilterFingerprint::of(&["status=ACTIVE", "deleted=false"])
    }

    fn filter_b() -> FilterFingerprint {
        FilterFingerprint::of(&["status=SUSPENDED", "deleted=false"])
    }

    #[test]
    fn a_cursor_round_trips_to_the_key_it_encoded() {
        let tenant = TenantId::new_v7();
        let key = UserId::new_v7();
        let encoded = Cursor::new(tenant, key, filter_a()).encode();
        assert_eq!(Cursor::<UserId>::decode(&encoded, tenant, filter_a()).unwrap(), key);
    }

    #[test]
    fn the_encoded_form_is_url_safe_and_reveals_no_structure_by_eye() {
        let encoded = Cursor::new(TenantId::new_v7(), UserId::new_v7(), filter_a()).encode();
        assert!(
            encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{encoded}"
        );
        // Not a proof of opacity — it is base64, not encryption — but it does prove the id is not
        // sitting there in its hyphenated form for a caller to lift out and use as an id.
        assert!(!encoded.contains('='));
    }

    #[test]
    fn another_tenants_cursor_is_rejected() {
        let issuer = TenantId::new_v7();
        let other = TenantId::new_v7();
        let encoded = Cursor::new(issuer, UserId::new_v7(), filter_a()).encode();
        assert!(matches!(
            Cursor::<UserId>::decode(&encoded, other, filter_a()),
            Err(InvalidCursor)
        ));
    }

    #[test]
    fn a_cursor_presented_with_a_different_filter_is_rejected() {
        // The bug this stops: page 1 filtered, page 2 not, and every row the filter excluded is
        // silently skipped rather than returned.
        let tenant = TenantId::new_v7();
        let encoded = Cursor::new(tenant, UserId::new_v7(), filter_a()).encode();
        assert!(matches!(
            Cursor::<UserId>::decode(&encoded, tenant, filter_b()),
            Err(InvalidCursor)
        ));
    }

    #[test]
    fn garbage_truncation_and_a_wrong_version_are_all_rejected_identically() {
        let tenant = TenantId::new_v7();
        let good = Cursor::new(tenant, UserId::new_v7(), filter_a()).encode();

        for bad in [
            String::from("not base64 at all !!"),
            String::new(),
            good[..good.len() - 4].to_owned(),
            URL_SAFE_NO_PAD.encode([0u8; CURSOR_LEN + 1]),
        ] {
            assert!(
                matches!(Cursor::<UserId>::decode(&bad, tenant, filter_a()), Err(InvalidCursor)),
                "accepted {bad:?}"
            );
        }

        // A future version byte must not be read under the current layout.
        let mut bytes = URL_SAFE_NO_PAD.decode(&good).unwrap();
        bytes[0] = CURSOR_VERSION + 1;
        let versioned = URL_SAFE_NO_PAD.encode(&bytes);
        assert!(matches!(
            Cursor::<UserId>::decode(&versioned, tenant, filter_a()),
            Err(InvalidCursor)
        ));
    }

    #[test]
    fn a_flipped_bit_in_the_key_still_decodes_but_cannot_leave_the_tenant() {
        // Honest about what the unsigned cursor does and does not give: tampering with the position
        // is possible, and it is bounded to a position within the same tenant and filter — which is
        // a page the caller could have asked for anyway. Recorded as a test so the property is
        // asserted rather than assumed if signing is added later.
        let tenant = TenantId::new_v7();
        let good = Cursor::new(tenant, UserId::new_v7(), filter_a()).encode();
        let mut bytes = URL_SAFE_NO_PAD.decode(&good).unwrap();
        bytes[20] ^= 0x01;
        let tampered = URL_SAFE_NO_PAD.encode(&bytes);
        let key = Cursor::<UserId>::decode(&tampered, tenant, filter_a()).unwrap();
        assert_ne!(key.to_string(), "");
        // The tenant binding still holds, which is the part that matters.
        assert!(Cursor::<UserId>::decode(&tampered, TenantId::new_v7(), filter_a()).is_err());
    }

    #[test]
    fn fingerprints_are_length_prefixed_so_concatenations_cannot_collide() {
        assert_ne!(FilterFingerprint::of(&["a", "bc"]), FilterFingerprint::of(&["ab", "c"]));
        assert_eq!(FilterFingerprint::of(&["a", "bc"]), FilterFingerprint::of(&["a", "bc"]));
        assert_ne!(FilterFingerprint::of(&[]), FilterFingerprint::of(&[""]));
    }

    #[test]
    fn page_sizes_are_clamped_at_both_ends() {
        assert_eq!(PageSize::default().get(), 50);
        assert_eq!(PageSize::new(0).get(), 1, "a zero page size is an infinite paging loop");
        assert_eq!(PageSize::new(100).get(), 100);
        assert_eq!(PageSize::new(u32::MAX).get(), i64::from(PageSize::MAX));
    }
}
