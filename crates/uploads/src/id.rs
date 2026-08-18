//! The upload session identifier.
//!
//! # Why it is defined here rather than in `enclave_core::id`
//!
//! It belongs there, next to the other fourteen. `core` is outside this task's boundary, so the
//! newtype is defined locally and shaped exactly like the ones the `define_id!` macro produces —
//! same constructors, same `Display`, same `FromStr` — so that moving it later is a deletion and a
//! re-export rather than a rewrite of every call site. See `integrator_actions`.
//!
//! What it is emphatically *not* is a bare `Uuid` on a public boundary (`CLAUDE.md`, Rust
//! conventions): a session id and a file id are both UUIDs and are never interchangeable, and the
//! `SqlId` implementation below is what lets it bind to a query without anyone reaching for
//! `Uuid` to get there.

use core::fmt;
use core::str::FromStr;

use enclave_core::{IdParseError, Uuid};
use enclave_db::SqlId;

/// The type name, defined once so the inherent constant and the [`SqlId`] one cannot disagree.
const TYPE_NAME: &str = "UploadSessionId";

/// One upload session — the `uploadId` of `docs/05-API.md §8`.
///
/// A newtype over [`Uuid`]. UUIDv7, so the primary key inserts at the right-hand edge of the index
/// and `ORDER BY id` is creation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UploadSessionId(Uuid);

impl UploadSessionId {
    /// The type's own name, for diagnostics that need to say which kind of id failed.
    pub const TYPE_NAME: &'static str = TYPE_NAME;

    /// Mints a fresh identifier.
    #[must_use]
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID — for a database column or a verified claim, and nowhere else.
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

impl fmt::Display for UploadSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for UploadSessionId {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s)
            .map(Self)
            .map_err(|source| IdParseError { type_name: Self::TYPE_NAME, source })
    }
}

impl SqlId for UploadSessionId {
    const TYPE_NAME: &'static str = TYPE_NAME;

    fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    fn to_uuid(self) -> Uuid {
        self.0
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_db::{sql, Sql};
    use sqlx::{Postgres, Type};

    use super::*;

    #[test]
    fn it_binds_as_a_postgres_uuid_like_every_other_identifier() {
        assert_eq!(
            <Sql<UploadSessionId> as Type<Postgres>>::type_info(),
            <Uuid as Type<Postgres>>::type_info()
        );
    }

    #[test]
    fn it_round_trips_through_its_string_and_sql_forms() {
        let id = UploadSessionId::new_v7();
        assert_eq!(id.to_string().parse::<UploadSessionId>().unwrap(), id);
        assert_eq!(sql(id).into_inner(), id);
        assert_eq!(UploadSessionId::from_uuid(id.as_uuid()), id);
    }

    #[test]
    fn a_string_that_is_not_a_uuid_names_the_type_it_failed_to_become() {
        let err = "not-a-uuid".parse::<UploadSessionId>().unwrap_err();
        assert!(err.to_string().contains("UploadSessionId"), "{err}");
    }
}
