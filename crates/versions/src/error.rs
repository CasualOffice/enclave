//! The crate's error type and its one translation into [`enclave_core::Error`].
//!
//! Three things shape it, and they are the same three that shape `crates/files/src/error.rs`:
//!
//! 1. **No content ever appears in an error string.** An object key is derived from a file name and
//!    a file name is content (`CLAUDE.md` rule 10). A variant names a *column* and a fixed reason,
//!    never a value.
//! 2. **Absence and refusal are one answer.** A version in another tenant is removed by row-level
//!    security before this code sees it, so it is indistinguishable from one that never existed —
//!    and both are [`enclave_core::Error::NotFound`] (`CLAUDE.md` rule 7).
//! 3. **A refusal the caller can act on says so.** Losing the version-number race is a retry, not a
//!    bug; restoring from a quarantined version is a request that cannot be satisfied. Neither is
//!    an opaque 500.
//!
//! Every unclassified driver failure funnels through [`enclave_db::DbError`], so retryability and
//! the `RowNotFound` → `404` mapping are decided in exactly one place in the workspace.

use enclave_core::{Error as CoreError, FieldError, ValidationCode};
use enclave_db::{DbError, Refused};

/// Everything the version paths can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VersionsError {
    /// A statement, transaction or connection failed.
    #[error("versions database failure")]
    Database(#[from] DbError),

    /// A stored row could not be reconstructed.
    ///
    /// Almost always a `CHECK` constraint and a Rust enumeration that have drifted apart. Names the
    /// column and a fixed reason, never the value.
    #[error("file version column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// Which column could not be decoded.
        column: &'static str,
        /// What was wrong with it, as a fixed phrase.
        reason: &'static str,
    },

    /// No such version, or it belongs to another tenant.
    #[error("no such file version")]
    NotFound,

    /// The file does not exist, is in the trash, or belongs to another tenant.
    ///
    /// Distinct from [`VersionsError::NotFound`] internally — the two say different things to an
    /// operator reading a log — and identical on the wire, because a caller that could tell them
    /// apart could enumerate file ids.
    #[error("no such file")]
    FileNotFound,

    /// The tenant has no room for these bytes (`plans/M4-GOVERNANCE.md` D31).
    ///
    /// Raised by [`enclave_db::charge_storage`] returning zero rows, which is the refusal — not by
    /// reading the quota and comparing. Carries the [`Refused`] whole rather than an `i64`, so the
    /// rendering stays `enclave_db`'s: `403` `QUOTA_EXCEEDED` with the *limit* and not the usage,
    /// because usage is a number that has already moved by the time a client reads it.
    ///
    /// **Not a server error, and not retryable.** An identical retry fails identically until the
    /// tenant deletes something or its limit is raised — which is why deletes are never
    /// quota-blocked.
    #[error("the tenant's stored-byte quota is exhausted")]
    StorageQuotaExceeded(Refused),

    /// A version was described with a negative size.
    ///
    /// `file_versions.size_bytes` is a `BIGINT` with no `CHECK` (`migrations/0006`), so this is the
    /// refusal that keeps a negative size out of `SUM(size_bytes)` — the figure the nightly quota
    /// reconciliation treats as truth. A negative row there would hand the tenant credit for bytes
    /// it never stored.
    #[error("a version's size cannot be negative")]
    NegativeSize,

    /// A restore was asked for from a version that cannot be a source.
    ///
    /// A version that is still scanning has no settled bytes to copy, and a quarantined one has
    /// bytes nobody should be handed a fresh copy of. Restoring from either would be the system
    /// re-publishing content it has already refused to serve.
    #[error("the source version is not in a state that can be restored from")]
    SourceNotRestorable,

    /// Two commits raced for the same version number and this one lost.
    ///
    /// Detected by `uq_version_number` rejecting the write, never by reading first: a
    /// read-then-write leaves a window in which the other commit takes the number between the check
    /// and the insert.
    ///
    /// Carries the file revision this transaction observed *before* its own bump, which — since the
    /// losing transaction rolls back — is the revision the file still holds. That is what a caller
    /// needs in order to re-read and retry.
    #[error("another version was committed for this file at the same time")]
    VersionNumberTaken {
        /// The file's revision as it stood before the rolled-back attempt.
        current_revision: i64,
    },

    /// Another version already names this object key.
    ///
    /// `uq_version_object` is global rather than per tenant, so this is also the refusal a caller
    /// gets for trying to point a second row at another tenant's bytes — which is exactly why the
    /// index is not tenant-scoped.
    #[error("that object key already belongs to a version")]
    ObjectKeyInUse,

    /// The database refused to change a frozen column of an `AVAILABLE` version.
    ///
    /// Raised by the `file_versions_immutable` trigger
    /// (`migrations/0006_versions_and_uploads.sql`, `plans/M1-CONTENT-CORE.md` D12). Nothing in
    /// this crate writes those columns after commit, so seeing this means some other path tried —
    /// which is exactly the case the trigger exists to catch, and exactly the case a code review
    /// would have missed.
    #[error("an AVAILABLE version's `{column}` cannot be changed")]
    Immutable {
        /// Which frozen column was written. Taken from the trigger's message, which names the
        /// column and nothing else.
        column: String,
    },

    /// The event describing the commit could not be written.
    #[error("the version event could not be recorded")]
    Events(#[from] enclave_events::EventsError),

    /// The audit row for the commit could not be written.
    ///
    /// Fatal to the transaction on purpose: an unaudited state change is not an acceptable
    /// outcome (`CLAUDE.md` rule 10), so this propagates and the caller's transaction rolls back.
    #[error("the version audit row could not be recorded")]
    Audit(#[from] enclave_audit::AuditError),
}

impl VersionsError {
    /// Whether an identical retry has a realistic chance of succeeding.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Database(source) => source.is_retryable(),
            // The point of the variant: the loser of a numbering race succeeds on a second attempt.
            Self::VersionNumberTaken { .. } => true,
            Self::Events(source) => source.is_retryable(),
            _ => false,
        }
    }
}

impl From<sqlx::Error> for VersionsError {
    /// Routes every unclassified driver failure through [`DbError::Query`].
    ///
    /// Written by hand rather than as a second `#[from]` so the retryable/permanent classification
    /// is not re-derived here. Constraint violations do **not** arrive this way — [`crate::commit`]
    /// inspects the SQLSTATE and the constraint name first, and turns the ones this crate has a
    /// domain answer for into [`VersionsError::VersionNumberTaken`],
    /// [`VersionsError::FileNotFound`] and [`VersionsError::Immutable`].
    fn from(source: sqlx::Error) -> Self {
        Self::Database(DbError::Query(source))
    }
}

impl From<VersionsError> for CoreError {
    /// Maps a version failure onto the one error type the API layer renders.
    fn from(error: VersionsError) -> Self {
        match error {
            VersionsError::Database(source) => Self::from(source),
            VersionsError::NotFound | VersionsError::FileNotFound => Self::NotFound,
            // A 409 with the revision the file still holds: re-read, re-issue, succeed.
            VersionsError::VersionNumberTaken { current_revision } => {
                Self::Conflict { current_revision }
            }
            // `Inconsistent` rather than `NotFound`: the version named is real and the caller may
            // see it in the history; what is wrong is asking to restore *that one*.
            VersionsError::SourceNotRestorable => {
                Self::Validation(vec![FieldError::new("versionId", ValidationCode::Inconsistent)])
            }
            // The column is a documented schema name (`docs/04-DATA-MODEL.md §8`), not content, and
            // naming it is what makes the refusal actionable rather than mysterious.
            VersionsError::Immutable { column } => {
                Self::Validation(vec![FieldError::new(column, ValidationCode::Immutable)])
            }
            VersionsError::ObjectKeyInUse => {
                Self::Validation(vec![FieldError::new("objectKey", ValidationCode::NotUnique)])
            }
            // `enclave_db`'s own mapping, not a second opinion about the status. A quota is a
            // capacity refusal — `403` with the limit — and re-deriving it here is how two paths
            // end up rendering the same refusal two ways.
            VersionsError::StorageQuotaExceeded(refused) => refused.into(),
            VersionsError::NegativeSize => {
                Self::Validation(vec![FieldError::new("sizeBytes", ValidationCode::OutOfRange)])
            }
            // The reason stays in the source chain for the logs and never reaches the caller:
            // `Internal`'s `Display` is the bare phrase "internal error".
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

/// The crate's result alias.
pub type Result<T, E = VersionsError> = core::result::Result<T, E>;

/// The unique index that decides whether a version number is free
/// (`migrations/0006_versions_and_uploads.sql`).
const UQ_VERSION_NUMBER: &str = "uq_version_number";

/// The globally unique index over `object_key`.
const UQ_VERSION_OBJECT: &str = "uq_version_object";

/// The name the immutability trigger raises under.
const IMMUTABILITY_TRIGGER: &str = "file_versions_immutable";

/// Maps a driver failure from a write against `file_versions` onto this crate's vocabulary.
///
/// Public because `file_versions` is written by more than this crate — the antivirus path records a
/// verdict, the approval path records a decision — and every one of them can be refused by the same
/// three constraints. One mapping means one place where a new constraint has to be considered;
/// three private copies mean two of them will report a documented refusal as an opaque 500.
///
/// `observed_file_revision` is only ever used to build the `409` for a lost numbering race: pass
/// the `files.revision` the calling transaction observed, so a client that must re-read and retry
/// is told which revision to expect. Callers that do not insert versions cannot lose that race and
/// may pass anything.
///
/// Anything unrecognised is funnelled through [`enclave_db::DbError`] rather than guessed at, so
/// retryability stays decided in one place in the workspace.
#[must_use]
pub fn classify_write(error: sqlx::Error, observed_file_revision: i64) -> VersionsError {
    let Some(db) = error.as_database_error() else {
        return VersionsError::from(error);
    };
    let facts = ConstraintFacts {
        constraint: db.constraint(),
        // `column()` is Postgres-specific: the generic `DatabaseError` trait has no accessor for
        // it, and it is the field the immutability trigger uses to say *which* column was frozen
        // without anyone having to parse its message.
        column: db
            .downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .column()
            .filter(|column| !column.is_empty()),
        kind: db.kind(),
    };
    match classify_facts(&facts, observed_file_revision) {
        Some(mapped) => mapped,
        None => VersionsError::from(error),
    }
}

/// The parts of a database error this crate makes a decision from.
///
/// Split out so the decision is a pure function over three values and can be tested without a
/// database — constructing a `PgDatabaseError` by hand is not something the driver supports, and a
/// mapping nobody can test is a mapping that quietly rots.
struct ConstraintFacts<'a> {
    constraint: Option<&'a str>,
    column: Option<&'a str>,
    kind: sqlx::error::ErrorKind,
}

/// Decides what a constraint violation means, or `None` for "not one this crate has an answer for".
fn classify_facts(
    facts: &ConstraintFacts<'_>,
    observed_file_revision: i64,
) -> Option<VersionsError> {
    use sqlx::error::ErrorKind;

    match facts.constraint {
        Some(UQ_VERSION_NUMBER) => {
            return Some(VersionsError::VersionNumberTaken {
                current_revision: observed_file_revision,
            })
        }
        Some(UQ_VERSION_OBJECT) => return Some(VersionsError::ObjectKeyInUse),
        Some(IMMUTABILITY_TRIGGER) => {
            return Some(VersionsError::Immutable {
                // The trigger always sets the column; the fallback exists so that a future
                // migration which forgets to still produces the right *class* of error.
                column: facts.column.unwrap_or("object_key").to_owned(),
            });
        }
        _ => {}
    }

    // The only foreign key on `file_versions` is `(tenant_id, file_id) -> files`, so a violation
    // means the file is not there — which, for a caller, is indistinguishable from never having
    // existed and must stay that way (`CLAUDE.md` rule 7).
    if facts.kind == ErrorKind::ForeignKeyViolation {
        return Some(VersionsError::FileNotFound);
    }
    None
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_missing_version_and_a_missing_file_are_both_404_and_never_403() {
        for error in [VersionsError::NotFound, VersionsError::FileNotFound] {
            let core: CoreError = error.into();
            assert!(matches!(core, CoreError::NotFound));
            assert_eq!(core.status_code(), 404);
        }
        // And so is a row row-level security filtered away.
        let core: CoreError = VersionsError::from(sqlx::Error::RowNotFound).into();
        assert!(matches!(core, CoreError::NotFound));
    }

    #[test]
    fn a_lost_numbering_race_is_a_retryable_conflict_carrying_the_live_revision() {
        let error = VersionsError::VersionNumberTaken { current_revision: 7 };
        assert!(error.is_retryable(), "the whole point of the variant is that a retry works");
        match CoreError::from(error) {
            CoreError::Conflict { current_revision } => assert_eq!(current_revision, 7),
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn the_trigger_refusal_names_the_column_and_reports_it_as_immutable() {
        let error = VersionsError::Immutable { column: "checksum_sha256".to_owned() };
        assert!(!error.is_retryable(), "retrying an immutable write fails identically");
        match CoreError::from(error) {
            CoreError::Validation(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].field, "checksum_sha256");
                assert_eq!(fields[0].code, ValidationCode::Immutable);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn restoring_from_a_quarantined_version_points_at_the_field_that_was_wrong() {
        match CoreError::from(VersionsError::SourceNotRestorable) {
            CoreError::Validation(fields) => {
                assert_eq!(fields[0].field, "versionId");
                assert_eq!(fields[0].code, ValidationCode::Inconsistent);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn nothing_internal_renders_its_detail_to_the_caller() {
        for error in [
            VersionsError::MalformedRow { column: "status", reason: "not a known status" },
            VersionsError::Audit(enclave_audit::AuditError::MalformedRow {
                column: "outcome",
                reason: "not one of ALLOW, DENY, ERROR",
            }),
        ] {
            let core: CoreError = error.into();
            assert_eq!(core.to_string(), "internal error");
        }
    }

    #[test]
    fn no_error_message_can_carry_an_object_key_or_a_file_name() {
        // The property, asserted rather than reviewed. Every variant that is *about* a value takes
        // a column name or nothing at all; a variant added with a `String` value field would have
        // to be added here, which is the point at which someone notices.
        let messages = [
            VersionsError::NotFound.to_string(),
            VersionsError::FileNotFound.to_string(),
            VersionsError::SourceNotRestorable.to_string(),
            VersionsError::VersionNumberTaken { current_revision: 1 }.to_string(),
            VersionsError::Immutable { column: "object_key".to_owned() }.to_string(),
        ];
        for message in messages {
            assert!(!message.contains('/'), "{message} looks like it carries a key");
        }
    }

    /// Quota exhaustion is a capacity refusal, not a server error and not a retry.
    #[test]
    fn an_exhausted_quota_is_a_403_carrying_the_limit_rather_than_a_500() {
        use enclave_db::{Enforcement, StorageQuota};

        let refused = Refused {
            quota: StorageQuota {
                limit_bytes: 4_096,
                used_bytes: 4_096,
                overshoot_bytes: 0,
                soft_limit_pct: 80,
                enforcement: Enforcement::Block,
            },
            requested_bytes: 1,
        };
        let error = VersionsError::StorageQuotaExceeded(refused);
        assert!(!error.is_retryable(), "an identical retry fails identically until room is freed");

        let core = CoreError::from(error);
        assert_eq!(core.status_code(), 403, "waiting does not fix a capacity quota");
        match core {
            CoreError::QuotaExceeded { quota, limit } => {
                assert_eq!(quota, enclave_core::QuotaKind::StorageBytes);
                // The limit, never the usage: usage has already moved by the time a client reads
                // it, and an error quoting it invites a retry against a stale figure.
                assert_eq!(limit, 4_096);
            }
            other => panic!("expected a quota refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_negative_size_is_a_field_error_and_not_a_free_charge() {
        match CoreError::from(VersionsError::NegativeSize) {
            CoreError::Validation(fields) => {
                assert_eq!(fields[0].field, "sizeBytes");
                assert_eq!(fields[0].code, ValidationCode::OutOfRange);
            }
            other => panic!("expected a validation failure, got {other:?}"),
        }
    }

    #[test]
    fn a_pool_timeout_is_retryable_and_a_bad_restore_is_not() {
        assert!(VersionsError::from(sqlx::Error::PoolTimedOut).is_retryable());
        assert!(!VersionsError::SourceNotRestorable.is_retryable());
    }
}
