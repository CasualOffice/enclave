//! Field definitions and the closed vocabularies their columns hold.
//!
//! Every enumeration mirrors a `CHECK` constraint in `migrations/0009_metadata.sql`
//! (`docs/04-DATA-MODEL.md §7`) — same members, same spellings, verified by reading the migration.

use core::fmt;

use chrono::{DateTime, Utc};
use enclave_core::{TenantId, UnknownVariant, Uuid};

macro_rules! db_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }

        impl $name {
            /// The stored form, exactly as the `CHECK` constraint spells it.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                match self { $( Self::$variant => $wire ),+ }
            }

            /// Every variant, so a test can assert the Rust set against the constraint's set.
            #[must_use]
            pub const fn all() -> &'static [Self] {
                &[ $( Self::$variant ),+ ]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = UnknownVariant;

            fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
                match s {
                    $( $wire => Ok(Self::$variant), )+
                    other => Err(UnknownVariant::new(stringify!($name), other)),
                }
            }
        }
    };
}

db_enum! {
    /// Where a field definition applies (`metadata_fields.scope`).
    pub enum FieldScope {
        /// Everywhere in the tenant.
        Tenant => "TENANT",
        /// One workspace.
        Workspace => "WORKSPACE",
        /// One library.
        Library => "LIBRARY",
        /// Everything of one content type.
        ContentType => "CONTENT_TYPE",
    }
}

db_enum! {
    /// What a field holds (`metadata_fields.field_type`).
    ///
    /// The type is what [`crate::validate`] dispatches on, and it is closed for that reason: an
    /// unknown type would have no validator, and a value with no validator is a value that gets
    /// stored unchecked.
    pub enum FieldType {
        /// Free text, bounded by `config.max_length`.
        Text => "TEXT",
        /// A JSON number, bounded by `config.min` and `config.max`.
        Number => "NUMBER",
        /// `true` or `false`, and nothing that merely looks like one.
        Boolean => "BOOLEAN",
        /// A calendar date, `YYYY-MM-DD`.
        Date => "DATE",
        /// An instant, RFC 3339.
        DateTime => "DATETIME",
        /// A user in this tenant.
        User => "USER",
        /// A group in this tenant.
        Group => "GROUP",
        /// One of `config.choices`.
        Choice => "CHOICE",
        /// A subset of `config.choices`.
        MultiChoice => "MULTI_CHOICE",
        /// An absolute URL with a permitted scheme.
        Url => "URL",
        /// An email address.
        Email => "EMAIL",
        /// A term from a taxonomy set.
        Taxonomy => "TAXONOMY",
        /// Another resource in this tenant.
        Reference => "REFERENCE",
        /// Arbitrary JSON, bounded by size and depth.
        Json => "JSON",
    }
}

db_enum! {
    /// What a value is attached to (`metadata_values.resource_type`).
    pub enum ValueResourceKind {
        /// A file.
        File => "FILE",
        /// A folder.
        Folder => "FOLDER",
        /// A library.
        Library => "LIBRARY",
        /// One row of a structured list.
        ListItem => "LIST_ITEM",
        /// A published page.
        Page => "PAGE",
    }
}

/// A field definition.
#[derive(Debug, Clone, PartialEq)]
pub struct MetadataField {
    /// The field's identifier.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: TenantId,
    /// Where it applies.
    pub scope: FieldScope,
    /// Which workspace, library or content type — `None` for a tenant-wide field.
    pub scope_id: Option<Uuid>,
    /// The stable key callers use. Not the label: a label is translated and edited.
    pub key: String,
    /// What a person sees. Already localized by whoever wrote it.
    pub label: String,
    /// What it holds.
    pub field_type: FieldType,
    /// Whether a value must be present.
    pub required: bool,
    /// Whether the search index carries it.
    pub indexed: bool,
    /// Type-specific rules. See [`crate::validate`].
    pub config: FieldConfig,
    /// When the field was defined.
    pub created_at: DateTime<Utc>,
}

/// The rules a value must satisfy, beyond its type.
///
/// One structure for every field type rather than an enum per type, because the column is a single
/// `JSONB` and a shape that varies by type is a shape that cannot be validated on the way in. Every
/// field is optional; a validator ignores the ones its type has no use for.
/// Not `Eq`: `min` and `max` are `f64`, and float equality is not an equivalence relation. Deriving
/// it would require pretending `NaN == NaN`, and a config comparison that lies is worse than one
/// that is merely partial.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FieldConfig {
    /// Maximum length, for `TEXT`.
    pub max_length: Option<usize>,
    /// Minimum length, for `TEXT`.
    pub min_length: Option<usize>,
    /// A regular expression the value must match, for `TEXT`.
    ///
    /// Stored as written and compiled by the caller — this crate does not take a regex engine, and
    /// `docs/12-TESTING.md` would want a catastrophic-backtracking test before it did.
    pub pattern: Option<String>,
    /// Inclusive lower bound, for `NUMBER`.
    pub min: Option<f64>,
    /// Inclusive upper bound, for `NUMBER`.
    pub max: Option<f64>,
    /// Permitted values, for `CHOICE` and `MULTI_CHOICE`.
    pub choices: Option<Vec<String>>,
    /// Maximum selections, for `MULTI_CHOICE`.
    pub max_selections: Option<usize>,
    /// Which taxonomy set a `TAXONOMY` value must come from.
    pub taxonomy_set: Option<String>,
    /// Which resource kinds a `REFERENCE` may point at.
    pub reference_kinds: Option<Vec<String>>,
    /// Maximum serialized size in bytes, for `JSON`.
    pub max_bytes: Option<usize>,
    /// Maximum nesting depth, for `JSON`.
    pub max_depth: Option<usize>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use core::str::FromStr as _;

    use super::*;

    #[test]
    fn every_vocabulary_matches_its_check_constraint() {
        let migration = include_str!("../../../migrations/0009_metadata.sql");

        let cases: [(&str, Vec<&'static str>); 3] = [
            (
                "field_type    TEXT NOT NULL CHECK (field_type IN (",
                FieldType::all().iter().map(|v| v.as_str()).collect(),
            ),
            (
                "scope         TEXT NOT NULL CHECK (scope IN ('TENANT','WORKSPACE','LIBRARY','CONTENT_TYPE')",
                FieldScope::all().iter().map(|v| v.as_str()).collect(),
            ),
            (
                "resource_type TEXT NOT NULL CHECK (resource_type IN (",
                ValueResourceKind::all().iter().map(|v| v.as_str()).collect(),
            ),
        ];

        for (needle, variants) in cases {
            let clause = migration
                .split_once(needle)
                .unwrap_or_else(|| panic!("constraint not found: {needle}"))
                .1;
            let clause = if needle.ends_with("')") {
                needle
            } else {
                clause.split_once(')').expect("closing paren").0
            };
            for variant in &variants {
                assert!(
                    clause.contains(&format!("'{variant}'")),
                    "`{variant}` is missing from the constraint"
                );
            }
        }
    }

    #[test]
    fn every_vocabulary_round_trips() {
        for value in FieldType::all() {
            assert_eq!(FieldType::from_str(value.as_str()), Ok(*value));
        }
        assert!(FieldType::from_str("RICH_TEXT").is_err());
    }

    #[test]
    fn an_unknown_config_key_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` is load-bearing. A typo in an administrator's field definition —
        // `maxLength` for `max_length` — would otherwise deserialize to a config with no bound at
        // all, which silently turns a constrained field into an unconstrained one.
        let typo = serde_json::json!({ "maxLength": 10 });
        assert!(serde_json::from_value::<FieldConfig>(typo).is_err());

        let correct = serde_json::json!({ "max_length": 10 });
        let config: FieldConfig = serde_json::from_value(correct).expect("valid");
        assert_eq!(config.max_length, Some(10));
    }
}
