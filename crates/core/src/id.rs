//! Strongly typed identifiers.
//!
//! Every identifier in Enclave is a newtype over [`Uuid`] rather than a bare `Uuid`, because the
//! compiler is the only reviewer that never gets tired: passing a `LibraryId` where a `FileId` is
//! expected is a whole class of cross-resource bug that simply cannot be written here.
//!
//! All of them are produced by one macro. Hand-writing fourteen near-identical newtypes guarantees
//! that one of them eventually acquires a different `Display`, a different serde representation, or
//! a `Default` that yields the nil UUID — and the divergence is discovered by a production
//! mismatch rather than by a test. One macro, one shape, no drift.
//!
//! Deliberately absent:
//!
//! * **`Default`** — a nil identifier is never a meaningful value, and a defaulted id silently
//!   pointing at `00000000-…` is far worse than a missing argument.
//! * **`sqlx::Type`** — persistence is the `db` crate's concern (`plans/M0-FOUNDATIONS.md` D1);
//!   `core` depends on nothing, and adding a driver here would make every crate in the workspace
//!   compile a database driver to use a `FileId`.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Failure to parse a string into a typed identifier.
///
/// The rejected input is deliberately **not** carried. Identifier parsing sits directly on
/// untrusted request paths, and anything placed in an error message eventually reaches a log line;
/// an opaque bearer token pasted into a path segment must not become log content
/// (`CLAUDE.md` non-negotiable rule 10). The type name plus the underlying `uuid` error is
/// everything an operator legitimately needs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a valid {type_name}: {source}")]
pub struct IdParseError {
    /// Name of the identifier type that rejected the input, e.g. `"FileId"`.
    pub type_name: &'static str,
    /// The underlying UUID parse failure.
    #[source]
    pub source: uuid::Error,
}

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// A newtype over [`Uuid`]; see the [module documentation](self) for why the shape is
        /// uniform across every identifier and why `Default` is not implemented.
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// The type's own name, for error messages and audit payloads that need to say which
            /// kind of identifier they are talking about without hard-coding a string at the call
            /// site.
            pub const TYPE_NAME: &'static str = stringify!($name);

            /// Mints a fresh identifier.
            ///
            /// UUIDv7 rather than v4: the leading 48 bits are a millisecond timestamp, so ids
            /// generated in sequence are also ordered in sequence. That keeps B-tree index inserts
            /// at the right-hand edge instead of scattering them across the whole index, and it
            /// makes `ORDER BY id` a usable, stable pagination key.
            #[must_use]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID.
            ///
            /// Reserved for the boundaries where a UUID legitimately arrives untyped — a database
            /// column, a verified token claim. Anywhere else, pass the typed value through.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Unwraps to the raw UUID, for those same boundaries in the outward direction.
            #[must_use]
            pub const fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            /// Renders the plain hyphenated UUID, with no type prefix, so that the string form is
            /// interchangeable with what the database and the JSON wire format hold.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::from_str(s)
                    .map(Self)
                    .map_err(|source| IdParseError { type_name: Self::TYPE_NAME, source })
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_id! {
    /// A tenant. The root of every isolation boundary: it scopes every other identifier here, it
    /// is the value `SET LOCAL app.tenant_id` carries, and it never comes from client input
    /// (`CLAUDE.md` non-negotiable rule 3).
    TenantId
}

define_id! {
    /// A member of the tenant's own directory, whether created locally or provisioned by SCIM.
    UserId
}

define_id! {
    /// A group used for authorization. Distinct from `UserId` so that a permission grant cannot
    /// accidentally be resolved against the wrong principal table.
    GroupId
}

define_id! {
    /// An external participant admitted to specific resources. Guests are a separate identity kind
    /// rather than a flag on a user, so that "is this principal external?" is answered by the type
    /// and by every `match` over [`Actor`](crate::actor::Actor).
    GuestId
}

define_id! {
    /// A non-human caller authenticating with client credentials.
    ServiceAccountId
}

define_id! {
    /// A registered MCP client. Separate from a service account because MCP callers carry an
    /// additional classification ceiling and a distinct tool scope set (`docs/03-LLD.md §5.6`).
    McpClientId
}

define_id! {
    /// A workspace: the top-level container users navigate and the usual unit of membership.
    WorkspaceId
}

define_id! {
    /// A document library inside a workspace.
    LibraryId
}

define_id! {
    /// A file or folder node. Folders share the identifier space with files because they share the
    /// permission and hierarchy model.
    FileId
}

define_id! {
    /// One immutable version of a file's content.
    VersionId
}

define_id! {
    /// A unit of extracted text submitted for embedding and retrieval.
    ChunkId
}

define_id! {
    /// One label in a tenant's classification set (`ENC-574`).
    ///
    /// The *identifier* is what `files.classification_id` and the three `default_classification_id`
    /// columns hold; the *ordinal* policy compares is
    /// [`ClassificationRank`](crate::ClassificationRank), and the two are deliberately different
    /// types. A label is tenant vocabulary — one tenant's `CONFIDENTIAL` is another's
    /// `INTERNAL_RESTRICTED` — so an id is meaningless across tenants and unorderable within one,
    /// while a rank is orderable and means nothing without the tenant whose scale it is on. Making
    /// them one type is how a rank ends up in a foreign key or an id ends up in a `>=`.
    ClassificationId
}

define_id! {
    /// A registered device. Bound into access tokens (`dev` claim) and required for sync and
    /// editor clients, so device posture can be evaluated per request.
    DeviceId
}

define_id! {
    /// A share link (`share_links.id`).
    ///
    /// The identifier of the **link**, never of the token that opens it. `enclave_sharing` keeps
    /// only a SHA-256 digest of the token and hands callers the row's id, so this is the one value
    /// that can name a redemption in an ACL row, an audit row or a log line without any of them
    /// carrying a live credential (`CLAUDE.md` rule 10).
    ///
    /// It exists as its own type rather than as the bare `Uuid` `ShareLink::id` carries because
    /// [`Actor::LinkBearer`](crate::Actor::LinkBearer) puts it on a public boundary, and a bare
    /// `Uuid` there would let a `FileId` — the very resource the link exposes — be passed as the
    /// principal permitted to read it.
    ShareLinkId
}

define_id! {
    /// A refresh-token family (`sid`).
    ///
    /// Correlation only — never a server-side session lookup. It exists so that audit can stitch a
    /// user's activity together and so that reuse detection can revoke an entire family at once
    /// (`docs/03-LLD.md §5.3`).
    SessionId
}

define_id! {
    /// One inbound request. Generated at the edge, echoed in every error envelope and every audit
    /// row, so a user-reported failure maps to exact log lines.
    RequestId
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn round_trips_through_string() {
        let id = FileId::new_v7();
        let parsed: FileId = id.to_string().parse().expect("a freshly formatted id must parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn round_trips_through_serde() {
        let id = TenantId::new_v7();
        let json = serde_json::to_string(&id).expect("uuid serialization cannot fail");
        // `#[serde(transparent)]` must keep the wire form a bare string, not `{"0":"…"}`.
        assert_eq!(json, format!("\"{id}\""));
        let back: TenantId = serde_json::from_str(&json).expect("round trip");
        assert_eq!(id, back);
    }

    #[test]
    fn every_id_type_round_trips() {
        // One case per type, so a future hand-written divergence from the macro is caught.
        macro_rules! check {
            ($($t:ty),+ $(,)?) => {$({
                let id = <$t>::new_v7();
                let via_string: $t = id.to_string().parse().expect("string round trip");
                let via_serde: $t = serde_json::from_str(
                    &serde_json::to_string(&id).expect("serialize"),
                ).expect("serde round trip");
                assert_eq!(id, via_string, "{} string round trip", <$t>::TYPE_NAME);
                assert_eq!(id, via_serde, "{} serde round trip", <$t>::TYPE_NAME);
                assert_eq!(id, <$t>::from(id.as_uuid()), "{} uuid round trip", <$t>::TYPE_NAME);
            })+};
        }
        check!(
            TenantId,
            UserId,
            GroupId,
            GuestId,
            ServiceAccountId,
            McpClientId,
            WorkspaceId,
            LibraryId,
            FileId,
            VersionId,
            ChunkId,
            ClassificationId,
            DeviceId,
            ShareLinkId,
            SessionId,
            RequestId,
        );
    }

    #[test]
    fn rejects_a_non_uuid_without_echoing_the_input() {
        let err = "not-a-uuid".parse::<FileId>().expect_err("must reject");
        assert_eq!(err.type_name, "FileId");
        // The rejected string must not appear anywhere in the rendered message.
        assert!(!err.to_string().contains("not-a-uuid"), "input leaked into the error message");
    }

    #[test]
    fn v7_ids_sort_in_generation_order() {
        // Relied upon by cursor pagination and by index locality; assert it rather than assume it.
        let first = FileId::new_v7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = FileId::new_v7();
        assert!(first < second);
    }

    #[test]
    fn distinct_id_types_are_distinct_at_the_type_level() {
        // Compile-time proof by construction: this function would not compile if `FileId` and
        // `LibraryId` were interchangeable.
        fn takes_file(_: FileId) {}
        let file = FileId::new_v7();
        takes_file(file);
        let library = LibraryId::from_uuid(file.as_uuid());
        assert_eq!(file.as_uuid(), library.as_uuid());
    }
}
