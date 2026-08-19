//! Validation outcomes and the errors this crate can produce.
//!
//! # Why a violation is not an error
//!
//! [`FieldViolation`] is data, returned in a [`ValidationOutcome`]. It says a *caller* sent
//! something the field does not accept. [`MetadataError`] means the crate could not reach an
//! answer — the database was unreachable, a stored row was unreadable.
//!
//! Keeping them apart matters more here than in most places, because validation runs over every
//! field of every write and a design that returns `Err` for a rejected value makes the ordinary
//! case indistinguishable from an outage in the logs. It also makes reporting *all* the problems
//! with a submission awkward, and reporting one at a time is how a form with four bad fields takes
//! four round trips to fix.

use enclave_core::{Dependency, Error as CoreError, FieldError, ValidationCode};

/// The result type used throughout this crate.
pub type Result<T, E = MetadataError> = core::result::Result<T, E>;

/// Why one value was not accepted.
///
/// Carries bounds but never the offending value. A rejected value is attacker-controlled by
/// definition, and echoing it into a log or an error body is how an injection payload travels — the
/// same rule `enclave_authorization::AuthzError::MalformedRow` follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldViolation {
    /// The field is required and no value was supplied.
    ///
    /// Also raised for an explicit `null`: `{"field": null}` is absence written out, and treating
    /// it as presence would let a required field be satisfied by not filling it in.
    Required,
    /// The value is not of the type the field holds.
    WrongType {
        /// What was expected, in fixed vocabulary.
        expected: &'static str,
    },
    /// The value is the right type and the wrong shape — a date that is not a date.
    WrongFormat {
        /// What was expected, in fixed vocabulary.
        expected: &'static str,
    },
    /// Longer than the field permits. Counted in characters, not bytes.
    TooLong {
        /// The configured maximum.
        max: usize,
        /// What arrived.
        actual: usize,
    },
    /// Shorter than the field permits.
    TooShort {
        /// The configured minimum.
        min: usize,
        /// What arrived.
        actual: usize,
    },
    /// Outside the configured bounds, or not a finite number.
    OutOfRange,
    /// Not one of the field's choices — including the case where the field defines none.
    NotAChoice,
    /// More selections than the field permits.
    TooManySelections {
        /// The configured maximum.
        max: usize,
        /// What arrived.
        actual: usize,
    },
    /// The same choice was selected twice.
    ///
    /// Refused rather than deduplicated: nothing in this crate rewrites a caller's value, because
    /// a stored value that differs from what was sent is a record that quietly disagrees with the
    /// system that sent it.
    DuplicateSelection,
    /// A `JSON` value nests deeper than permitted.
    TooDeep {
        /// The configured maximum depth.
        max: usize,
    },
    /// A `JSON` value serializes larger than permitted.
    TooLarge {
        /// The configured maximum, in bytes.
        max: usize,
    },
    /// The value contains a character that cannot be stored — a `NUL`, in practice.
    IllegalCharacter,
    /// The value names something that does not exist in this tenant.
    ///
    /// Raised by [`crate::repo`] rather than by [`crate::validate`], which cannot resolve a
    /// reference without a database. A reference to another tenant's resource produces this and
    /// not a distinct error: distinguishing them would confirm the resource exists
    /// (`CLAUDE.md` rule 7).
    UnresolvedReference,
}

impl FieldViolation {
    /// The closed code the API edge renders.
    #[must_use]
    pub const fn code(self) -> ValidationCode {
        match self {
            Self::Required => ValidationCode::Required,
            Self::WrongType { .. } | Self::WrongFormat { .. } | Self::IllegalCharacter => {
                ValidationCode::InvalidFormat
            }
            Self::TooLong { .. } | Self::TooManySelections { .. } | Self::TooLarge { .. } => {
                ValidationCode::TooLong
            }
            Self::TooShort { .. } => ValidationCode::TooShort,
            Self::OutOfRange | Self::TooDeep { .. } => ValidationCode::OutOfRange,
            Self::NotAChoice | Self::UnresolvedReference => ValidationCode::Unsupported,
            Self::DuplicateSelection => ValidationCode::NotUnique,
        }
    }
}

/// What validating one value produced.
///
/// Holds every violation rather than the first, so a submission with four bad fields is reported
/// once rather than four times.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "an unchecked ValidationOutcome is a value stored without being validated, which is \
              the entire failure this type exists to prevent"]
pub struct ValidationOutcome {
    violations: Vec<FieldViolation>,
}

impl ValidationOutcome {
    /// Builds an outcome.
    pub fn new(violations: Vec<FieldViolation>) -> Self {
        Self { violations }
    }

    /// Whether the value may be stored.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }

    /// Everything wrong with it.
    #[must_use]
    pub fn violations(&self) -> &[FieldViolation] {
        &self.violations
    }

    /// Renders the violations against a field key, for the API's `Validation` error.
    #[must_use]
    pub fn field_errors(&self, key: &str) -> Vec<FieldError> {
        self.violations.iter().map(|v| FieldError::new(key, v.code())).collect()
    }
}

/// Something went wrong reading or writing metadata.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataError {
    /// A statement failed.
    #[error("metadata query failed")]
    Storage(#[from] sqlx::Error),

    /// A tenant-scoped transaction could not be opened.
    #[error("metadata database failure")]
    Database(#[from] enclave_db::DbError),

    /// A stored row could not be interpreted.
    #[error("metadata column `{column}` is not readable: {reason}")]
    MalformedRow {
        /// The column that failed to parse.
        column: &'static str,
        /// Why, in fixed vocabulary rather than the offending value.
        reason: &'static str,
    },

    /// One or more values were rejected.
    ///
    /// Carries the field key alongside each violation so a caller can attach the message to the
    /// input the user actually typed into.
    #[error("{} metadata value(s) rejected", .0.len())]
    Invalid(Vec<FieldError>),
}

impl From<MetadataError> for CoreError {
    fn from(value: MetadataError) -> Self {
        match value {
            MetadataError::Storage(ref error) => {
                let retryable = matches!(
                    error,
                    sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_)
                );
                Self::Upstream { dependency: Dependency::Postgres, retryable }
            }
            MetadataError::Database(error) => error.into(),
            MetadataError::Invalid(fields) => Self::Validation(fields),
            other => Self::Internal(anyhow::Error::new(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn a_rejected_value_is_a_validation_failure_and_not_an_outage() {
        let error: CoreError =
            MetadataError::Invalid(vec![FieldError::new("owner", ValidationCode::Required)]).into();
        assert_eq!(error.code(), "VALIDATION_FAILED");
    }

    #[test]
    fn a_database_outage_is_not_a_rejected_value() {
        // If these collapsed, an incident would read as "every metadata write was invalid" and the
        // support queue would fill with people told their input was wrong.
        let error: CoreError = MetadataError::Storage(sqlx::Error::PoolClosed).into();
        assert!(!matches!(error, CoreError::Validation(_)), "{error:?}");
    }

    #[test]
    fn no_violation_carries_the_value_that_caused_it() {
        // Asserted structurally: `FieldViolation` is `Copy`, so it cannot hold a `String`, so it
        // cannot carry a rejected value into a log. This test fails to compile the day someone adds
        // a variant with an owned payload — which is the moment to think about it.
        fn assert_copy<T: Copy>() {}
        assert_copy::<FieldViolation>();
    }
}
