//! Typed identifiers for the three workflow tables.
//!
//! `CLAUDE.md`'s Rust conventions: newtype every id, no bare `Uuid` on a public boundary. Three
//! distinct types rather than one shared `WorkflowId`, for the reason `enclave_db::DlpRuleId`
//! records: a shared type would let an instance identifier be passed where a step identifier is
//! meant — a mistake that compiles, and then decides the wrong row or, worse, none.
//!
//! They live here rather than in `enclave_core::id` because `crates/core` depends on nothing and
//! its id set is generated from one macro; and they implement [`enclave_db::SqlId`] here rather
//! than in `enclave-db` because this crate owns the tables, which is what `enclave-db`'s own header
//! asks for — *table-shaped access belongs in the domain crate that owns the table*.

use enclave_db::SqlId;
use uuid::Uuid;

/// Generates one identifier newtype with the same surface as `enclave_core::id`'s.
///
/// A macro for the reason `core`'s is one: written out by hand, five identifiers are five chances
/// for one of them to bind the wrong column type or to forget `Display`, and the one that is wrong
/// is the one whose failure looks like a missing row.
macro_rules! workflow_id {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Uuid);

        impl $name {
            /// The type's own name, for diagnostics that must say which kind of id failed.
            pub const TYPE_NAME: &'static str = $label;

            /// A new, time-ordered identifier.
            ///
            /// v7 rather than v4 so that rows written in sequence are stored in sequence, which is
            /// what keeps the `(tenant_id, instance_id, stage, position)` index from fragmenting.
            #[must_use]
            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl core::str::FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse::<Uuid>().map(Self)
            }
        }

        impl SqlId for $name {
            const TYPE_NAME: &'static str = $label;

            fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            fn to_uuid(self) -> Uuid {
                self.0
            }
        }
    };
}

workflow_id!(
    /// A workflow template's identifier.
    WorkflowDefinitionId,
    "WorkflowDefinitionId"
);

workflow_id!(
    /// One running workflow's identifier.
    WorkflowInstanceId,
    "WorkflowInstanceId"
);

workflow_id!(
    /// One step row's identifier — one assignee of one step of one stage.
    WorkflowStepId,
    "WorkflowStepId"
);

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_three_identifiers_are_not_interchangeable() {
        // The whole reason there are three. This is a compile-time property, so the assertion a
        // test can make is the weaker one — that the round trip is faithful — and the strong one is
        // held by the type checker: `WorkflowStepId` has no `From<WorkflowInstanceId>`.
        let raw = Uuid::now_v7();
        assert_eq!(WorkflowStepId::from_uuid(raw).as_uuid(), raw);
        assert_eq!(WorkflowInstanceId::from_uuid(raw).as_uuid(), raw);
        assert_eq!(WorkflowDefinitionId::from_uuid(raw).as_uuid(), raw);
    }

    #[test]
    fn identifiers_parse_back_from_their_display_form() {
        let id = WorkflowStepId::new_v7();
        let parsed: WorkflowStepId = id.to_string().parse().expect("round trip");
        assert_eq!(parsed, id);
        assert!("not-a-uuid".parse::<WorkflowStepId>().is_err());
    }
}
