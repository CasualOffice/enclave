//! What a delta is asked about, and the position within it.
//!
//! `docs/10-SYNC-AND-EDITING.md §4` puts both on the wire:
//! `GET /api/v1/sync/delta?scope=library:01937f…&cursor=8841203`.

use core::fmt;
use core::str::FromStr;

use enclave_core::{LibraryId, ResourceRef, TenantId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SyncError;

/// The kind of container a device replicates.
///
/// One variant, and it is a closed vocabulary rather than a `String` because the value is half of a
/// cursor's identity: a position of `8841203` means nothing without knowing which feed it counts.
/// A second variant is a schema change (`sync_scope_sequences.scope_type`'s `CHECK`) and a new
/// counter series, not a new spelling — which is exactly the kind of thing an open `String` lets
/// somebody introduce by typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// A document library, in whole. The only scope V1 replicates.
    Library,
}

impl ScopeKind {
    /// The stored form, exactly as `migrations/0023_sync_devices.sql` spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Library => "LIBRARY",
        }
    }

    /// The wire prefix, as `docs/10 §4` writes it: `library:01937f…`.
    #[must_use]
    pub const fn wire_prefix(self) -> &'static str {
        match self {
            Self::Library => "library",
        }
    }

    /// Every variant, so a test asserts the whole vocabulary rather than the ones it remembers.
    pub const ALL: [Self; 1] = [Self::Library];
}

impl fmt::Display for ScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One replicable container, tenant-qualified at the point of use.
///
/// Deliberately *not* carrying its tenant: the tenant comes from the verified token and is applied
/// by [`SyncScope::resource`], so a scope parsed out of a query string cannot bring one with it
/// (`CLAUDE.md` rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyncScope {
    kind: ScopeKind,
    id: Uuid,
}

impl SyncScope {
    /// A library scope.
    #[must_use]
    pub const fn library(id: LibraryId) -> Self {
        Self { kind: ScopeKind::Library, id: id.as_uuid() }
    }

    /// Which kind of container.
    #[must_use]
    pub const fn kind(self) -> ScopeKind {
        self.kind
    }

    /// The container's raw identifier, for binding into a statement.
    #[must_use]
    pub const fn id(self) -> Uuid {
        self.id
    }

    /// The resource the policy chain is asked about before the feed is read.
    ///
    /// The tenant arrives here, from the caller's verified context and from nowhere else.
    #[must_use]
    pub fn resource(self, tenant: TenantId) -> ResourceRef {
        match self.kind {
            ScopeKind::Library => ResourceRef::library(tenant, LibraryId::from_uuid(self.id)),
        }
    }
}

impl FromStr for SyncScope {
    type Err = SyncError;

    /// Parses `library:<uuid>`.
    ///
    /// One answer for every malformation — unknown prefix, missing colon, unparseable id — because
    /// the alternative is an endpoint that tells a caller which half of their guess was right.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (prefix, id) = raw.split_once(':').ok_or(SyncError::InvalidScope)?;
        let kind = ScopeKind::ALL
            .into_iter()
            .find(|candidate| candidate.wire_prefix() == prefix)
            .ok_or(SyncError::InvalidScope)?;
        let id = Uuid::parse_str(id).map_err(|_error| SyncError::InvalidScope)?;
        Ok(Self { kind, id })
    }
}

impl fmt::Display for SyncScope {
    /// The form `docs/10 §4` puts in the query string, so a scope round-trips.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.wire_prefix(), self.id)
    }
}

/// A position in one scope's change feed.
///
/// # Why this is an integer and not a signed, opaque blob
///
/// `enclave_db::Cursor` is the workspace's pagination cursor: it binds a position to a tenant and a
/// filter fingerprint so that page 2 of a differently-filtered listing cannot silently skip rows.
/// That is the right primitive for a *listing*, and the wrong one here, for a reason worth stating
/// rather than leaving as an inconsistency.
///
/// A delta cursor is **persisted by the client for weeks** and is stored on the server in
/// `sync_cursors` besides. It has to survive being written down, read back, and presented by a
/// client that has been offline across a release. `docs/10 §4` puts it on the wire as the integer
/// `"8841205"` for exactly that reason. And the property `Cursor` exists to protect is not at
/// stake: there is no filter set to disagree about — a delta is the whole scope, always — and the
/// tenant is applied from the token on every call, so a cursor from another tenant does not select
/// another tenant's rows, it selects nothing.
///
/// What it *cannot* do is move a caller to a position they were not entitled to, and that is not a
/// property of the encoding: every entry the feed returns is evaluated for eligibility for this
/// caller before it is rendered ([`crate::eligibility`]), so a fabricated cursor of `1` buys a
/// re-enumeration of what the caller may already sync and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeltaCursor(i64);

impl DeltaCursor {
    /// The position a client that has never synced this scope presents.
    pub const START: Self = Self(0);

    /// Builds a cursor from a sequence number.
    ///
    /// # Errors
    ///
    /// [`SyncError::InvalidCursor`] for a negative position. Nothing in the feed is at or below
    /// zero, so a negative cursor is a client that has invented one.
    pub const fn new(seq: i64) -> Result<Self, SyncError> {
        if seq < 0 {
            return Err(SyncError::InvalidCursor);
        }
        Ok(Self(seq))
    }

    /// The position, for binding into a statement.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl FromStr for DeltaCursor {
    type Err = SyncError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::new(raw.trim().parse::<i64>().map_err(|_error| SyncError::InvalidCursor)?)
    }
}

impl fmt::Display for DeltaCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_scope_round_trips_through_the_wire_form() {
        let library = LibraryId::new_v7();
        let scope = SyncScope::library(library);
        let rendered = scope.to_string();
        assert!(rendered.starts_with("library:"), "{rendered}");
        assert_eq!(rendered.parse::<SyncScope>().expect("re-parse"), scope);
    }

    #[test]
    fn every_malformed_scope_is_refused_the_same_way() {
        // An endpoint that distinguished "unknown prefix" from "bad uuid" would tell a caller which
        // half of their guess was right.
        for raw in [
            "",
            "library",
            "library:",
            "library:not-a-uuid",
            "folder:01937f00-0000-7000-8000-000000000000",
            ":01937f00-0000-7000-8000-000000000000",
        ] {
            assert!(
                matches!(raw.parse::<SyncScope>(), Err(SyncError::InvalidScope)),
                "`{raw}` was not refused"
            );
        }
    }

    #[test]
    fn a_scope_takes_its_tenant_from_the_caller_and_not_from_the_string() {
        // `CLAUDE.md` rule 3. The parsed scope has no tenant at all; the resource gains one only
        // when a verified context supplies it.
        let library = LibraryId::new_v7();
        let scope = format!("library:{}", library.as_uuid())
            .parse::<SyncScope>()
            .expect("a well-formed scope");
        let alpha = TenantId::new_v7();
        let beta = TenantId::new_v7();
        assert_eq!(scope.resource(alpha).tenant_id, alpha);
        assert_eq!(scope.resource(beta).tenant_id, beta);
        assert_eq!(scope.resource(alpha).id, library.as_uuid());
    }

    #[test]
    fn the_stored_and_wire_spellings_are_both_pinned() {
        // The stored form is a `CHECK` constraint's vocabulary and the wire form is a query-string
        // token; they are different strings and a test that read one from the other would prove
        // nothing.
        assert_eq!(ScopeKind::Library.as_str(), "LIBRARY");
        assert_eq!(ScopeKind::Library.wire_prefix(), "library");
        assert_eq!(ScopeKind::ALL.len(), 1);
    }

    #[test]
    fn a_cursor_is_a_non_negative_position_and_zero_is_the_beginning() {
        assert_eq!(DeltaCursor::START.get(), 0);
        assert_eq!("0".parse::<DeltaCursor>().expect("zero"), DeltaCursor::START);
        assert_eq!("8841205".parse::<DeltaCursor>().expect("a position").get(), 8_841_205);
        assert_eq!("8841205".parse::<DeltaCursor>().expect("a position").to_string(), "8841205");
        for raw in ["-1", "", "abc", "1.5", "9223372036854775808"] {
            assert!(
                matches!(raw.parse::<DeltaCursor>(), Err(SyncError::InvalidCursor)),
                "`{raw}` was accepted as a cursor"
            );
        }
    }
}
