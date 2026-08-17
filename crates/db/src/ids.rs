//! Driver glue for `enclave_core`'s typed identifiers.
//!
//! `core` deliberately carries no `sqlx` derives (`plans/M0-FOUNDATIONS.md` D1: `core` depends on
//! nothing, and a `FileId` must not oblige the frontend-facing crates to compile a database
//! driver). Persistence is this crate's concern, so the `Type`/`Encode`/`Decode` implementations
//! live here.
//!
//! They cannot be written directly on the identifier types: both the trait and the type would be
//! foreign, which the orphan rule forbids. The transport is therefore a local wrapper, [`Sql`],
//! plus a [`SqlId`] trait that says "this is a newtype over a UUID and here is how to get in and
//! out of it". One generic implementation then covers all fourteen identifiers at once — the same
//! reasoning that made `core` generate them from a single macro applies here: fourteen hand-written
//! implementations are fourteen chances for one of them to bind the wrong column type.
//!
//! ```text
//! // binding
//! sqlx::query("SELECT * FROM files WHERE id = $1").bind(sql(file_id))
//!
//! // reading
//! let file_id: FileId = row.try_get_id("id")?;
//! ```

use enclave_core::id::{
    ChunkId, DeviceId, FileId, GroupId, GuestId, LibraryId, McpClientId, RequestId,
    ServiceAccountId, SessionId, TenantId, UserId, VersionId, WorkspaceId,
};
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgHasArrayType, PgRow, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Row, Type};
use uuid::Uuid;

/// An identifier that is stored as a PostgreSQL `uuid`.
///
/// Implemented for every newtype in `enclave_core::id` and for nothing else. The bound is what
/// stops [`Sql`] from becoming a general-purpose escape hatch: wrapping an arbitrary type in it is
/// a compile error, so `Sql` cannot quietly grow into "the way we bypass the type system".
pub trait SqlId: Copy + Send + Sync + Sized + 'static {
    /// The identifier's own type name, propagated from `core` so diagnostics can say which kind of
    /// id failed to decode without the call site restating it.
    const TYPE_NAME: &'static str;

    /// Rebuilds the identifier from a column value.
    fn from_uuid(value: Uuid) -> Self;

    /// Unwraps to the value the driver sends.
    fn to_uuid(self) -> Uuid;
}

macro_rules! impl_sql_id {
    ($($id:ty),+ $(,)?) => {$(
        impl SqlId for $id {
            const TYPE_NAME: &'static str = <$id>::TYPE_NAME;

            fn from_uuid(value: Uuid) -> Self {
                <$id>::from_uuid(value)
            }

            fn to_uuid(self) -> Uuid {
                self.as_uuid()
            }
        }
    )+};
}

// Every identifier `core` defines. A new one that is not listed here simply cannot be bound to a
// query, which is a compile error at the call site rather than a runtime surprise.
impl_sql_id!(
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
    DeviceId,
    SessionId,
    RequestId,
);

/// A typed identifier on its way to or from PostgreSQL.
///
/// `#[repr(transparent)]` over the identifier, which is itself transparent over a `Uuid`, so this
/// costs nothing at runtime — it exists purely to give this crate a local type to hang the driver
/// traits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Sql<T>(pub T);

impl<T> Sql<T> {
    /// Wraps an identifier for binding.
    pub const fn new(id: T) -> Self {
        Self(id)
    }

    /// Unwraps back to the typed identifier.
    ///
    /// Call this at the boundary and pass the identifier itself onward: `Sql` is a transport, and
    /// letting it spread into domain signatures would put a persistence detail into types that have
    /// nothing to do with persistence.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Shorthand for [`Sql::new`], because it appears once per bound identifier in every query.
pub const fn sql<T: SqlId>(id: T) -> Sql<T> {
    Sql(id)
}

impl<T: SqlId> Type<Postgres> for Sql<T> {
    /// Reports `uuid`, delegating to the `Uuid` implementation rather than naming the OID here, so
    /// that a driver-side change to how UUIDs are described is picked up automatically.
    fn type_info() -> PgTypeInfo {
        <Uuid as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Uuid as Type<Postgres>>::compatible(ty)
    }
}

impl<T: SqlId> PgHasArrayType for Sql<T> {
    /// Present so that `&[Sql<FileId>]` binds as `uuid[]`, which is what the `= ANY($1)` form used
    /// throughout the repositories requires.
    fn array_type_info() -> PgTypeInfo {
        <Uuid as PgHasArrayType>::array_type_info()
    }
}

impl<'q, T: SqlId> Encode<'q, Postgres> for Sql<T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <Uuid as Encode<'q, Postgres>>::encode_by_ref(&self.0.to_uuid(), buf)
    }

    fn size_hint(&self) -> usize {
        core::mem::size_of::<Uuid>()
    }
}

impl<'r, T: SqlId> Decode<'r, Postgres> for Sql<T> {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        <Uuid as Decode<'r, Postgres>>::decode(value).map(|uuid| Self(T::from_uuid(uuid)))
    }
}

/// Reading typed identifiers straight out of a row.
///
/// Without this, every read site writes `row.try_get::<Sql<FileId>, _>("id")?.into_inner()`, and
/// the shortest way to avoid that noise is `row.try_get::<Uuid, _>("id")?` — which is exactly the
/// habit the newtypes exist to prevent. Making the typed form the shorter one is the point.
pub trait RowIdExt {
    /// Reads a non-null identifier column.
    fn try_get_id<T: SqlId>(&self, column: &str) -> Result<T, sqlx::Error>;

    /// Reads a nullable identifier column.
    fn try_get_opt_id<T: SqlId>(&self, column: &str) -> Result<Option<T>, sqlx::Error>;
}

impl RowIdExt for PgRow {
    fn try_get_id<T: SqlId>(&self, column: &str) -> Result<T, sqlx::Error> {
        self.try_get::<Sql<T>, _>(column).map(Sql::into_inner)
    }

    fn try_get_opt_id<T: SqlId>(&self, column: &str) -> Result<Option<T>, sqlx::Error> {
        self.try_get::<Option<Sql<T>>, _>(column).map(|value| value.map(Sql::into_inner))
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_identifier_binds_as_a_postgres_uuid() {
        // The failure this guards against is silent: a wrong `type_info` produces a runtime type
        // mismatch on the first query that binds that identifier, in whichever repository happens
        // to be written last.
        macro_rules! check {
            ($($t:ty),+ $(,)?) => {$(
                assert_eq!(
                    <Sql<$t> as Type<Postgres>>::type_info(),
                    <Uuid as Type<Postgres>>::type_info(),
                    "{} does not bind as uuid", <$t as SqlId>::TYPE_NAME,
                );
                assert_eq!(
                    <Sql<$t> as PgHasArrayType>::array_type_info(),
                    <Uuid as PgHasArrayType>::array_type_info(),
                    "{} does not bind as uuid[]", <$t as SqlId>::TYPE_NAME,
                );
            )+};
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
            DeviceId,
            SessionId,
            RequestId,
        );
    }

    #[test]
    fn the_wrapper_round_trips_without_changing_the_value() {
        let id = FileId::new_v7();
        assert_eq!(sql(id).into_inner(), id);
        assert_eq!(Sql::new(id).0.as_uuid(), id.as_uuid());
        // `SqlId` must not reinterpret the bytes on the way through.
        assert_eq!(FileId::from_uuid(id.to_uuid()), id);
    }

    #[test]
    fn the_type_name_survives_the_trip_through_the_trait() {
        assert_eq!(<FileId as SqlId>::TYPE_NAME, "FileId");
        assert_eq!(<TenantId as SqlId>::TYPE_NAME, "TenantId");
    }

    #[test]
    fn the_wrapper_is_a_zero_cost_transport() {
        assert_eq!(core::mem::size_of::<Sql<FileId>>(), core::mem::size_of::<Uuid>());
    }
}
