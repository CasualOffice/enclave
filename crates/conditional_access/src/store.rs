//! The stored form of a rule, and the one place a stored rule becomes a typed one.
//!
//! `ENC-590`. `crates/db/src/conditional_access.rs` holds the statements and no opinion about what
//! a rule means; this module holds the meaning and no statement. The seam between them is
//! [`enclave_db::RuleRow`], which is strings.
//!
//! # The property this module exists to keep
//!
//! Q19's answer is a **type** separation ([`crate::rules`]): `MachineCondition` has no
//! `PostureBelow` and no `AuthStrengthBelow`, so a device-posture rule against a service account is
//! not a rule that gets skipped — it is a rule that cannot be written. `ENC-583` got that from the
//! compiler for free, because the only way to build a rule was to name its type.
//!
//! Storage is where that guarantee is most easily lost, and losing it would be silent. JSONB holds
//! any document; a decoder that tried each shape in turn, or that used an untagged enum, or that
//! skipped clauses it did not recognise, would turn the compiler's refusal into a shrug. So:
//!
//! 1. **The audience is a column, not a field in the document.** `audience` decides which Rust type
//!    the conditions are decoded into. It is not inferred from the document, and it cannot be:
//!    `client_is` and `action_is` are legitimately in both vocabularies, so the document alone
//!    genuinely does not say which set it belongs to.
//! 2. **Decoding is strict and closed.** Both condition enums are externally tagged with
//!    `deny_unknown_fields`, so `{"posture_below": "MANAGED"}` in a `MACHINE` row produces
//!    `unknown variant \`posture_below\`` — named, and refused.
//! 3. **A rule that cannot be decoded is an error, never an omission.** [`decode_rules`] returns
//!    `Err` for the whole set rather than dropping the offending rule. Dropping it is the
//!    permissive failure: the deployment would carry on with one refusal fewer than the
//!    administrator wrote, and nothing would say so. `crates/conditional_access/src/tenant.rs`
//!    carries that error to the caller, so the request fails rather than being decided against an
//!    incomplete policy.
//!
//! # Why `Effect` has no `ALLOW` here either
//!
//! `docs/06 §7.4`: under most-restrictive-wins an allow can never change an outcome, so accepting
//! one would let an administrator write an exception, see it stored, and have it do nothing.
//! [`Effect::from_sql`] refuses the string, and `migrations/0019`'s `CHECK` refuses the row — the
//! second is what makes the absence hold on paths that never went through this enum.

use enclave_db::{RuleId, RuleRow};
use serde::Serialize;

use crate::policy::Audience;
use crate::rules::{Effect, HumanCondition, HumanRule, MachineCondition, MachineRule, RuleMode};

/// Why a stored rule could not be turned into a rule.
///
/// Every variant names the rule, because an operator staring at a failed start-up needs to know
/// *which* row to fix and the id alone does not tell them. None of this text reaches a caller:
/// [`enclave_core::Error::Internal`]'s `Display` is the bare phrase "internal error", and the chain
/// below is available only to a log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuleError {
    /// The `audience` column held something that is neither rule set.
    #[error(
        "conditional-access rule `{name}` names an audience that is not a rule set: `{audience}`"
    )]
    UnknownAudience {
        /// The rule's administrator-facing name.
        name: String,
        /// What the column held.
        audience: String,
    },

    /// The `effect` column held an effect this stage does not apply — `ALLOW` among them.
    #[error(
        "conditional-access rule `{name}` names an effect this stage cannot apply: `{effect}`"
    )]
    UnknownEffect {
        /// The rule's administrator-facing name.
        name: String,
        /// What the column held.
        effect: String,
    },

    /// The `mode` column held something that is neither enforcing nor rehearsing.
    #[error("conditional-access rule `{name}` names a mode that is neither ENFORCE nor SIMULATION: `{mode}`")]
    UnknownMode {
        /// The rule's administrator-facing name.
        name: String,
        /// What the column held.
        mode: String,
    },

    /// The conditions are not this audience's conditions.
    ///
    /// The Q19 refusal, and the one worth reading closely when it appears: a `MACHINE` rule whose
    /// document names `posture_below` lands here, because [`MachineCondition`] has no such variant.
    /// The rule is refused rather than trimmed to the clauses that did decode — a rule missing a
    /// condition matches *more* requests than the administrator wrote, and this stage's rules deny.
    #[error("conditional-access rule `{name}` is stored as a {audience:?} rule, and its conditions are not {audience:?} conditions")]
    Conditions {
        /// The rule's administrator-facing name.
        name: String,
        /// The rule set the row claims to belong to.
        audience: Audience,
        /// serde's account, which names the offending clause.
        #[source]
        source: serde_json::Error,
    },

    /// A rule could not be serialized on its way to the table.
    #[error("conditional-access rule `{name}` could not be serialized")]
    Encode {
        /// The rule's administrator-facing name.
        name: String,
        /// serde's account.
        #[source]
        source: serde_json::Error,
    },
}

impl From<RuleError> for enclave_core::Error {
    /// A stored rule that cannot be decoded is an internal fault, not a client error.
    ///
    /// The caller asked for nothing wrong; the deployment's own configuration is unreadable. It is
    /// deliberately not a denial either: a `403` would tell the caller a policy refused them when
    /// no policy was evaluated, and the audit row would record a decision nobody made.
    fn from(error: RuleError) -> Self {
        Self::Internal(anyhow::Error::new(error))
    }
}

impl Audience {
    /// The value as `conditional_access_rules.audience` spells it.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Human => "HUMAN",
            Self::Machine => "MACHINE",
        }
    }

    /// Reads the column.
    ///
    /// # Errors
    ///
    /// Any value the migration's `CHECK` would have refused. Reaching this means the constraint and
    /// this function have diverged, which is a defect rather than a rule to skip.
    pub fn from_sql(value: &str, rule_name: &str) -> Result<Self, RuleError> {
        match value {
            "HUMAN" => Ok(Self::Human),
            "MACHINE" => Ok(Self::Machine),
            other => Err(RuleError::UnknownAudience {
                name: rule_name.to_owned(),
                audience: other.to_owned(),
            }),
        }
    }
}

impl Effect {
    /// The value as `conditional_access_rules.effect` spells it.
    ///
    /// The strings match the migration's `CHECK` exactly; a second spelling would guarantee a
    /// mismatch, and the symptom would be "the rule stopped working" rather than an error.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Block => "BLOCK",
            Self::RequireTrustedNetwork => "REQUIRE_TRUSTED_NETWORK",
            Self::RequireManagedDevice => "REQUIRE_MANAGED_DEVICE",
            Self::RequireMfa => "REQUIRE_MFA",
            Self::PreviewOnly => "PREVIEW_ONLY",
            Self::NoDownload => "NO_DOWNLOAD",
            Self::NoSync => "NO_SYNC",
        }
    }

    /// Reads the column.
    ///
    /// # Errors
    ///
    /// Anything that is not one of the seven effects — including `ALLOW`, which is refused here and
    /// again by the migration's `CHECK`. See the module header for why there is no allow.
    pub fn from_sql(value: &str, rule_name: &str) -> Result<Self, RuleError> {
        match value {
            "BLOCK" => Ok(Self::Block),
            "REQUIRE_TRUSTED_NETWORK" => Ok(Self::RequireTrustedNetwork),
            "REQUIRE_MANAGED_DEVICE" => Ok(Self::RequireManagedDevice),
            "REQUIRE_MFA" => Ok(Self::RequireMfa),
            "PREVIEW_ONLY" => Ok(Self::PreviewOnly),
            "NO_DOWNLOAD" => Ok(Self::NoDownload),
            "NO_SYNC" => Ok(Self::NoSync),
            other => Err(RuleError::UnknownEffect {
                name: rule_name.to_owned(),
                effect: other.to_owned(),
            }),
        }
    }
}

impl RuleMode {
    /// The value as `conditional_access_rules.mode` spells it.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::Enforce => "ENFORCE",
            Self::Simulation => "SIMULATION",
        }
    }

    /// Reads the column.
    ///
    /// # Errors
    ///
    /// Anything that is neither `ENFORCE` nor `SIMULATION`. Note the direction this refuses in: an
    /// unrecognised mode is *not* quietly treated as `SIMULATION`, because an administrator whose
    /// enforcing rule was demoted by a typo would have a control that reports itself as on.
    pub fn from_sql(value: &str, rule_name: &str) -> Result<Self, RuleError> {
        match value {
            "ENFORCE" => Ok(Self::Enforce),
            "SIMULATION" => Ok(Self::Simulation),
            other => {
                Err(RuleError::UnknownMode { name: rule_name.to_owned(), mode: other.to_owned() })
            }
        }
    }
}

/// One decoded rule, in whichever rule set it belongs to.
///
/// The enum exists so that a decoded row cannot be handled without saying which set it is in — the
/// same reason the two rule types are separate in the first place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// A rule about people.
    Human(HumanRule),
    /// A rule about service accounts, MCP clients and `system`.
    Machine(MachineRule),
}

impl Rule {
    /// The audience this rule belongs to.
    #[must_use]
    pub const fn audience(&self) -> Audience {
        match self {
            Self::Human(_) => Audience::Human,
            Self::Machine(_) => Audience::Machine,
        }
    }

    /// The rule's name, as an administrator wrote it.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Human(rule) => &rule.name,
            Self::Machine(rule) => &rule.name,
        }
    }
}

/// Turns one stored row into a rule.
///
/// # Errors
///
/// [`RuleError`], for any of: an audience that is not a rule set, an effect this stage cannot
/// apply, an unrecognised mode, or conditions that are not this audience's conditions. Nothing here
/// falls back to a default, and nothing skips a clause it does not recognise.
pub fn decode_rule(row: &RuleRow) -> Result<Rule, RuleError> {
    let audience = Audience::from_sql(&row.audience, &row.name)?;
    let effect = Effect::from_sql(&row.effect, &row.name)?;
    let mode = RuleMode::from_sql(&row.mode, &row.name)?;
    let name = row.name.clone();

    // The one line the whole module is about: the *column* selects the type, and the document is
    // then required to be that type. There is no second attempt at the other shape.
    match audience {
        Audience::Human => {
            let when: Vec<HumanCondition> = conditions(&row.conditions, &name, audience)?;
            Ok(Rule::Human(HumanRule { name, when, effect, mode }))
        }
        Audience::Machine => {
            let when: Vec<MachineCondition> = conditions(&row.conditions, &name, audience)?;
            Ok(Rule::Machine(MachineRule { name, when, effect, mode }))
        }
    }
}

/// Decodes a condition list, attributing any failure to the rule it came from.
fn conditions<T: serde::de::DeserializeOwned>(
    document: &str,
    name: &str,
    audience: Audience,
) -> Result<Vec<T>, RuleError> {
    serde_json::from_str(document).map_err(|source| RuleError::Conditions {
        name: name.to_owned(),
        audience,
        source,
    })
}

/// Turns a tenant's stored rows into rules.
///
/// # Errors
///
/// The first row that cannot be decoded, and **the whole set fails with it**. A partial rule set is
/// the permissive failure: it is a policy the administrator did not write, applied silently, with
/// exactly the clauses that could be parsed. Better to refuse and say which row.
pub fn decode_rules(rows: &[RuleRow]) -> Result<Vec<Rule>, RuleError> {
    rows.iter().map(decode_rule).collect()
}

/// Renders a rule about people into a row this deployment can store.
///
/// # Errors
///
/// Serialization failure, which in practice means a condition holding a value serde cannot
/// represent — no such condition exists today, and the error is kept rather than unwrapped because
/// "no such condition exists today" is a statement about today.
pub fn encode_human(id: RuleId, rule: &HumanRule) -> Result<RuleRow, RuleError> {
    Ok(RuleRow {
        id,
        audience: Audience::Human.as_sql().to_owned(),
        name: rule.name.clone(),
        conditions: document(&rule.when, &rule.name)?,
        effect: rule.effect.as_sql().to_owned(),
        mode: rule.mode.as_sql().to_owned(),
    })
}

/// Renders a rule about machines into a row this deployment can store.
///
/// # Errors
///
/// As [`encode_human`].
pub fn encode_machine(id: RuleId, rule: &MachineRule) -> Result<RuleRow, RuleError> {
    Ok(RuleRow {
        id,
        audience: Audience::Machine.as_sql().to_owned(),
        name: rule.name.clone(),
        conditions: document(&rule.when, &rule.name)?,
        effect: rule.effect.as_sql().to_owned(),
        mode: rule.mode.as_sql().to_owned(),
    })
}

/// Renders a rule of either kind.
///
/// # Errors
///
/// As [`encode_human`].
pub fn encode_rule(id: RuleId, rule: &Rule) -> Result<RuleRow, RuleError> {
    match rule {
        Rule::Human(rule) => encode_human(id, rule),
        Rule::Machine(rule) => encode_machine(id, rule),
    }
}

fn document<T: Serialize>(conditions: &[T], name: &str) -> Result<String, RuleError> {
    serde_json::to_string(conditions)
        .map_err(|source| RuleError::Encode { name: name.to_owned(), source })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// The migration with its commentary removed, which is the only form worth scanning.
    ///
    /// The first version of `allow_is_not_a_storable_effect` scanned the whole file and **failed on
    /// its first run against itself**: the header explains that `INSERT … effect = 'ALLOW'` is
    /// refused, so the needle was in the prose. `docs/12-TESTING.md §1.2` records two earlier tests
    /// in this repository that did exactly this; this is the third, and it is left written down
    /// rather than quietly fixed. A claim about what the *schema* accepts has to be made against
    /// the schema.
    fn ddl() -> String {
        const MIGRATION: &str =
            include_str!("../../../migrations/0019_conditional_access_rules.sql");
        MIGRATION
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every vocabulary in this module is also a `CHECK` constraint in `migrations/0019`. The two
    /// are separate declarations of one list, so they are asserted against each other here — a
    /// rename on either side that reached only one of them would otherwise surface as "the rule
    /// stopped applying", which is the quietest possible failure for a refusal.
    #[test]
    fn every_sql_spelling_round_trips_and_matches_the_migrations_check() {
        let migration = ddl();

        for effect in [
            Effect::Block,
            Effect::RequireTrustedNetwork,
            Effect::RequireManagedDevice,
            Effect::RequireMfa,
            Effect::PreviewOnly,
            Effect::NoDownload,
            Effect::NoSync,
        ] {
            let spelling = effect.as_sql();
            assert_eq!(Effect::from_sql(spelling, "t").expect("round trip"), effect);
            assert!(
                migration.contains(&format!("'{spelling}'")),
                "{spelling} is not in the migration's CHECK vocabulary"
            );
        }

        for mode in [RuleMode::Enforce, RuleMode::Simulation] {
            assert_eq!(RuleMode::from_sql(mode.as_sql(), "t").expect("round trip"), mode);
            assert!(migration.contains(&format!("'{}'", mode.as_sql())));
        }

        for audience in [Audience::Human, Audience::Machine] {
            assert_eq!(Audience::from_sql(audience.as_sql(), "t").expect("round trip"), audience);
            assert!(migration.contains(&format!("'{}'", audience.as_sql())));
        }
    }

    /// `docs/06 §7.4`: there is no allow. The absence is asserted in both directions — this decoder
    /// refuses the string, and the migration does not offer it — because an absence asserted on one
    /// side only is an absence somebody can add on the other.
    #[test]
    fn allow_is_not_a_storable_effect() {
        let migration = ddl();
        let needle = format!("'{}'", "ALLOW");

        assert!(
            Effect::from_sql("ALLOW", "auditors from anywhere").is_err(),
            "an ALLOW effect would be an exception that appears to exist and does nothing"
        );
        assert!(
            !migration.contains(&needle),
            "the migration's CHECK must not accept an ALLOW effect"
        );
        // The positive control for the source scan: the needle is one this test can find, and the
        // vocabulary it belongs to *is* in the file. Without this, the assertion above passes
        // against a migration file that failed to load, or a needle that could never match.
        assert!(migration.contains(&format!("'{}'", Effect::Block.as_sql())));
        assert!(format!("effect IN ({needle})").contains(&needle));
    }
}
