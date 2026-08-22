//! The stored form of a DLP rule, and the one place a stored rule becomes a typed one.
//!
//! `ENC-615`. `crates/db/src/dlp.rs` holds the statements and no opinion about what a rule means;
//! this module holds the meaning and no statement. The seam between them is [`enclave_db::
//! DlpRuleRow`], which is strings, numbers and JSON text.
//!
//! # The two properties this module exists to keep
//!
//! **Q16 — structured detectors, no regex on the synchronous path.** `crates/dlp` gets that from
//! the compiler: [`crate::detector::StructuredDetector`]'s `validate(&Candidate) -> Verdict` has
//! nowhere to put a pattern, and [`Condition`] is a comparison against a count, a rank, a severity
//! or a score. Storage is where a type guarantee is most easily lost, because JSONB holds any
//! document. So decoding is **strict and closed**: both enums are externally tagged with
//! `deny_unknown_fields`, and `{"pattern": "\\d{16}"}` produces *unknown variant `pattern`* rather
//! than a clause somebody's decoder skipped.
//!
//! **D28 — `SIMULATION` and `ENFORCE` cannot diverge.** [`crate::policy::RuleSet`] holds no mode
//! and `evaluate` takes none, so the code that reaches a conclusion has not been told which mode is
//! running. Nothing here changes that: [`DlpRuleRow`] has no `mode` field, `dlp_rules` has no
//! `mode` column, and a rule decoded from a row is the same `DlpRule` a test constructs by hand.
//! The mode arrives from configuration, once, in `crates/api/src/main.rs`.
//!
//! # A rule that cannot be decoded is an error, never an omission
//!
//! [`decode_rules`] returns `Err` for the whole set rather than dropping the offending rule, and
//! [`crate::tenant::TenantDlp`] carries that error to the caller so the request fails. Both
//! alternatives are worse in the same direction: a dropped rule is a refusal the administrator
//! wrote and the deployment is not applying, and an empty rule set is a DLP stage that inspects
//! nothing at all. `ENC-615` exists because the second state shipped.
//!
//! # There is no `ALLOW`
//!
//! `docs/06 §10` lists it, and [`DlpAction::Allow`] exists as a variant, but it cannot be stored.
//! `Allow`'s demand is [`crate::policy::Demand::Nothing`] and `Verdict::blocking_code` scans past a
//! `Nothing` to the next fired rule, so an `ALLOW` written above a `BLOCK` fires and changes
//! nothing — an exception that appears to exist. [`DlpAction::from_sql`] refuses the string and
//! `migrations/0021`'s `CHECK` refuses the row; the second is what makes the absence hold on paths
//! that never went through this enum. `ENC-631` is the row for giving an exception a meaning.

use enclave_core::ClassificationRank;
use enclave_db::{DlpRuleId, DlpRuleRow};
use serde::Serialize;

use crate::policy::{ActionScope, Condition, DlpAction, DlpRule, RuleId, RuleSet};

/// Why a stored rule could not be turned into a rule.
///
/// Every variant names the rule, because an operator staring at a failed request needs to know
/// *which* row to fix and the id alone does not tell them. None of this text reaches a caller:
/// [`enclave_core::Error::Internal`]'s `Display` is the bare phrase "internal error", and the chain
/// below is available only to a log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DlpRuleError {
    /// The `action` column held something this stage cannot demand — `ALLOW` among them.
    #[error("DLP rule `{name}` names an action this stage cannot demand: `{action}`")]
    UnknownAction {
        /// The rule's administrator-facing name.
        name: String,
        /// What the column held.
        action: String,
    },

    /// `RECLASSIFY` with no rank, or a rank on an action that has no target.
    ///
    /// The migration's `dlp_rules_reclassify_target` constraint refuses both, so reaching this
    /// means the constraint and this function have diverged — a defect, not a rule to repair by
    /// guessing a rank.
    #[error("DLP rule `{name}` is a {action} whose reclassification target is {problem}")]
    ReclassifyTarget {
        /// The rule's administrator-facing name.
        name: String,
        /// The action as stored.
        action: String,
        /// Which half of the pairing is wrong.
        problem: &'static str,
    },

    /// The scope document is not a list of [`ActionScope`].
    ///
    /// Refused rather than trimmed to the scopes that decoded. A rule that lost a scope governs
    /// fewer actions than the administrator wrote, and it stops governing them silently.
    #[error("DLP rule `{name}` has a scope this stage cannot read")]
    Scope {
        /// The rule's administrator-facing name.
        name: String,
        /// serde's account, which names the offending clause.
        #[source]
        source: serde_json::Error,
    },

    /// The conditions document is not a list of [`Condition`].
    ///
    /// **The Q16 refusal**, and the one worth reading closely when it appears: a stored rule whose
    /// conditions name `pattern`, `regex` or any other expression lands here, because [`Condition`]
    /// has no such variant and its `Deserialize` is closed. The rule is refused rather than trimmed
    /// — a rule missing a condition matches *more* requests than the administrator wrote.
    #[error("DLP rule `{name}` has conditions this stage cannot evaluate")]
    Conditions {
        /// The rule's administrator-facing name.
        name: String,
        /// serde's account, which names the offending clause.
        #[source]
        source: serde_json::Error,
    },

    /// A rule could not be serialized on its way to the table.
    #[error("DLP rule `{name}` could not be serialized")]
    Encode {
        /// The rule's administrator-facing name.
        name: String,
        /// serde's account.
        #[source]
        source: serde_json::Error,
    },
}

impl From<DlpRuleError> for enclave_core::Error {
    /// A stored rule that cannot be decoded is an internal fault, not a client error.
    ///
    /// The caller asked for nothing wrong; the deployment's own configuration is unreadable. It is
    /// deliberately not a denial either: a `403` would tell the caller a policy refused them when
    /// no policy was evaluated, and the audit row would record a decision nobody made. What it must
    /// not become is an *allow*, which is what an empty rule set would have made it.
    fn from(error: DlpRuleError) -> Self {
        Self::Internal(anyhow::Error::new(error))
    }
}

impl DlpAction {
    /// The value as `dlp_rules.action` spells it, for the twelve storable actions.
    ///
    /// `ALLOW` returns `None`: it is the one action of `docs/06 §10` that this deployment cannot
    /// store, because it would do nothing (see the module header). Returning an `Option` rather
    /// than a string nobody may write is what makes that unrepresentable at the call site instead
    /// of caught by the database — and the database catches it too.
    #[must_use]
    pub const fn as_sql(&self) -> Option<&'static str> {
        match self {
            Self::Allow => None,
            other => Some(other.as_str()),
        }
    }

    /// The reclassification target, for the one action that has one.
    #[must_use]
    pub const fn reclassify_to(&self) -> Option<ClassificationRank> {
        match self {
            Self::Reclassify { to } => Some(*to),
            _ => None,
        }
    }

    /// Reads the `action` column and its `reclassify_to` companion.
    ///
    /// # Errors
    ///
    /// Any value the migration's `CHECK` would have refused: an action outside the vocabulary
    /// (`ALLOW` among them), a `RECLASSIFY` with no rank, or a rank on an action that has no
    /// target. Reaching any of these means the constraint and this function have diverged, which is
    /// a defect rather than a rule to skip.
    pub fn from_sql(
        value: &str,
        reclassify_to: Option<i32>,
        rule_name: &str,
    ) -> Result<Self, DlpRuleError> {
        let action = match value {
            "AUDIT" => Self::Audit,
            "WARN" => Self::Warn,
            "REQUIRE_JUSTIFICATION" => Self::RequireJustification,
            "REQUIRE_APPROVAL" => Self::RequireApproval,
            "BLOCK" => Self::Block,
            "QUARANTINE" => Self::Quarantine,
            "REMOVE_SHARE" => Self::RemoveShare,
            "READ_ONLY" => Self::ReadOnly,
            "NO_DOWNLOAD" => Self::NoDownload,
            "WATERMARK" => Self::Watermark,
            "NOTIFY_SECURITY" => Self::NotifySecurity,
            "RECLASSIFY" => match reclassify_to {
                Some(rank) => Self::Reclassify { to: ClassificationRank(rank) },
                None => {
                    return Err(DlpRuleError::ReclassifyTarget {
                        name: rule_name.to_owned(),
                        action: value.to_owned(),
                        problem: "absent, so the obligation has no target",
                    })
                }
            },
            other => {
                return Err(DlpRuleError::UnknownAction {
                    name: rule_name.to_owned(),
                    action: other.to_owned(),
                })
            }
        };

        // The other direction. A rank stored beside `BLOCK` is a value nothing reads, and reading
        // the row as an ordinary `BLOCK` would silently discard whatever an administrator meant by
        // it. The migration refuses the row; this refuses the interpretation.
        if reclassify_to.is_some() && action.reclassify_to().is_none() {
            return Err(DlpRuleError::ReclassifyTarget {
                name: rule_name.to_owned(),
                action: value.to_owned(),
                problem: "set, and this action has no target to raise",
            });
        }

        Ok(action)
    }
}

/// Turns one stored row into a rule.
///
/// # Errors
///
/// [`DlpRuleError`], for any of: an action this stage cannot demand, a broken `RECLASSIFY` pairing,
/// a scope this stage cannot read, or conditions it cannot evaluate. Nothing here falls back to a
/// default, and nothing skips a clause it does not recognise.
pub fn decode_rule(row: &DlpRuleRow) -> Result<DlpRule, DlpRuleError> {
    let action = DlpAction::from_sql(&row.action, row.reclassify_to, &row.name)?;

    let scope: Vec<ActionScope> = serde_json::from_str(&row.scope)
        .map_err(|source| DlpRuleError::Scope { name: row.name.clone(), source })?;
    let conditions: Vec<Condition> = serde_json::from_str(&row.conditions)
        .map_err(|source| DlpRuleError::Conditions { name: row.name.clone(), source })?;

    Ok(DlpRule::new(RuleId::new(row.name.clone()), scope, conditions, action))
}

/// Turns a tenant's stored rows into the rule set that decides its requests.
///
/// The rows arrive in the order `enclave_db::load_dlp_rules` produced — `priority`, then `name` —
/// and that order is preserved, because it is what `Verdict::blocking_code` reads when two refusing
/// rules fire.
///
/// # Errors
///
/// The first row that cannot be decoded, and **the whole set fails with it**. A partial rule set is
/// a policy the administrator did not write, applied silently, with exactly the clauses that could
/// be parsed. Better to refuse and say which row.
pub fn decode_rules(rows: &[DlpRuleRow]) -> Result<RuleSet, DlpRuleError> {
    rows.iter().map(decode_rule).collect::<Result<Vec<_>, _>>().map(RuleSet::new)
}

/// Renders a rule into a row this deployment can store.
///
/// `id` and `priority` are the row's rather than the rule's: neither is anything the evaluator
/// reads off a [`DlpRule`] — the identity it evaluates with is the administrator's *name*, and
/// order is the position in the set — so carrying them on the rule type would be carrying two
/// fields that mean something only in a table.
///
/// # Errors
///
/// [`DlpRuleError::UnknownAction`] for `ALLOW`, which cannot be stored (see the module header), and
/// [`DlpRuleError::Encode`] for a serialization failure.
pub fn encode_rule(
    id: DlpRuleId,
    priority: i32,
    rule: &DlpRule,
) -> Result<DlpRuleRow, DlpRuleError> {
    let name = rule.id().as_str().to_owned();
    let action = rule.action();

    let stored = action.as_sql().ok_or_else(|| DlpRuleError::UnknownAction {
        name: name.clone(),
        action: action.as_str().to_owned(),
    })?;

    Ok(DlpRuleRow {
        id,
        name: name.clone(),
        priority,
        scope: document(rule.scope(), &name)?,
        conditions: document(rule.conditions(), &name)?,
        action: stored.to_owned(),
        reclassify_to: action.reclassify_to().map(|rank| rank.0),
    })
}

fn document<T: Serialize>(values: &[T], name: &str) -> Result<String, DlpRuleError> {
    serde_json::to_string(values)
        .map_err(|source| DlpRuleError::Encode { name: name.to_owned(), source })
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{DetectorCategory, FileAction, Severity};

    use super::*;

    /// The migration with its commentary removed, which is the only form worth scanning.
    ///
    /// `docs/12-TESTING.md §1.2` records three tests in this repository whose source-scanning
    /// assertion passed against its own prose. The header of `0021` discusses `ALLOW` at length, so
    /// a claim about what the *schema* accepts has to be made against the schema.
    fn ddl() -> String {
        const MIGRATION: &str = include_str!("../../../migrations/0021_dlp_rules.sql");
        MIGRATION
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn row(conditions: &str) -> DlpRuleRow {
        DlpRuleRow {
            id: DlpRuleId::new_v7(),
            name: "block external sharing of payment data".to_owned(),
            priority: 100,
            scope: r#"["external_sharing"]"#.to_owned(),
            conditions: conditions.to_owned(),
            action: "BLOCK".to_owned(),
            reclassify_to: None,
        }
    }

    /// The vocabulary in this module is also a `CHECK` constraint in `migrations/0021`. The two are
    /// separate declarations of one list, so they are asserted against each other — a rename on
    /// either side that reached only one of them would surface as "the rule stopped applying",
    /// which is the quietest possible failure for a refusal.
    #[test]
    fn every_storable_action_round_trips_and_matches_the_migrations_check() {
        let migration = ddl();

        for action in [
            DlpAction::Audit,
            DlpAction::Warn,
            DlpAction::RequireJustification,
            DlpAction::RequireApproval,
            DlpAction::Block,
            DlpAction::Quarantine,
            DlpAction::RemoveShare,
            DlpAction::ReadOnly,
            DlpAction::NoDownload,
            DlpAction::Watermark,
            DlpAction::NotifySecurity,
            DlpAction::Reclassify { to: ClassificationRank::RESTRICTED },
        ] {
            let spelling = action.as_sql().expect("every action here is storable");
            let rank = action.reclassify_to().map(|value| value.0);
            assert_eq!(DlpAction::from_sql(spelling, rank, "t").expect("round trip"), action);
            assert!(
                migration.contains(&format!("'{spelling}'")),
                "{spelling} is not in the migration's CHECK vocabulary"
            );
        }
    }

    /// `ALLOW` cannot be stored, and the absence is asserted in both directions — this decoder
    /// refuses the string, the encoder refuses the rule, and the migration does not offer it.
    ///
    /// An absence asserted on one side only is an absence somebody can add on the other.
    #[test]
    fn allow_is_not_a_storable_action() {
        let migration = ddl();
        let needle = format!("'{}'", "ALLOW");

        assert!(
            DlpAction::from_sql("ALLOW", None, "an exception above the block").is_err(),
            "an ALLOW action would be an exception that fires and changes nothing"
        );
        assert!(DlpAction::Allow.as_sql().is_none(), "ALLOW has no stored spelling");
        assert!(
            encode_rule(
                DlpRuleId::new_v7(),
                100,
                &DlpRule::new(
                    RuleId::new("an exception"),
                    vec![ActionScope::Any],
                    Vec::new(),
                    DlpAction::Allow,
                ),
            )
            .is_err(),
            "the encoder must refuse a rule it cannot store rather than storing a different one"
        );
        assert!(
            !migration.contains(&needle),
            "the migration's CHECK must not accept an ALLOW action"
        );
        // The positive control for the source scan: the vocabulary it belongs to *is* in the file,
        // and the needle is one this test can find. Without these the assertion above passes
        // against a migration that failed to load, or a needle that could never match.
        assert!(migration.contains(&format!("'{}'", DlpAction::Block.as_str())));
        assert!(format!("action IN ({needle})").contains(&needle));
    }

    /// **Q16, at the storage boundary.** A stored rule may not smuggle a pattern onto the
    /// synchronous path, and the refusal is by name.
    #[test]
    fn a_stored_condition_cannot_carry_a_pattern() {
        for smuggled in [
            r#"[{"pattern":"\\d{16}"}]"#,
            r#"[{"regex":"[A-Z]{2}\\d{2}"}]"#,
            r#"[{"category_at_least":{"category":"FINANCIAL","count":1,"pattern":"x"}}]"#,
        ] {
            let error = decode_rule(&row(smuggled)).expect_err("a pattern is not a condition");
            let rendered = format!("{error:?}");
            assert!(
                matches!(error, DlpRuleError::Conditions { .. }),
                "a pattern must be refused as a condition this stage cannot evaluate: {rendered}"
            );
            assert!(
                rendered.contains("unknown variant") || rendered.contains("unknown field"),
                "serde must name what it refused, so an operator can fix the row: {rendered}"
            );
        }

        // The control: the same row with a condition this stage *does* have decodes, so the three
        // refusals above are about the pattern rather than about the row, the decoder or the test's
        // JSON being malformed in some other way.
        let rule =
            decode_rule(&row(r#"[{"category_at_least":{"category":"FINANCIAL","count":1}}]"#))
                .expect("a count comparison is a condition");
        assert_eq!(
            rule.conditions(),
            [Condition::CategoryAtLeast { category: DetectorCategory::Financial, count: 1 }]
        );
    }

    /// A rule is refused whole, never trimmed to the clauses that parsed.
    ///
    /// The distinction is the whole of `ENC-590`'s argument reapplied: a rule that lost its
    /// condition fires on every governed action, and a rule that lost its scope governs nothing.
    /// Both are policies nobody wrote.
    #[test]
    fn one_undecodable_rule_fails_the_whole_set() {
        let good = row(r#"["any_finding"]"#);
        let bad = DlpRuleRow { conditions: r#"[{"pattern":"x"}]"#.to_owned(), ..row("[]") };

        // The control first: the good row on its own is a set of one.
        let set = decode_rules(std::slice::from_ref(&good)).expect("a decodable rule set");
        assert_eq!(set.len(), 1);

        let error = decode_rules(&[good, bad]).expect_err("the set must fail with the row");
        assert!(
            error.to_string().contains("block external sharing of payment data"),
            "the error must name the rule an operator has to fix: {error}"
        );
    }

    /// A scope naming something this stage cannot evaluate is refused too, for the mirror reason.
    #[test]
    fn a_scope_this_stage_cannot_read_is_refused_rather_than_dropped() {
        let broken = DlpRuleRow { scope: r#"["everything_ever"]"#.to_owned(), ..row("[]") };
        assert!(matches!(decode_rule(&broken), Err(DlpRuleError::Scope { .. })));

        // The control: a scope it can read decodes, so the refusal is the name and not the shape.
        let fine = DlpRuleRow {
            scope: r#"[{"exactly":{"resource":"file","action":"download"}}]"#.to_owned(),
            ..row("[]")
        };
        assert_eq!(
            decode_rule(&fine).expect("a known scope").scope(),
            [ActionScope::Exactly(enclave_core::Action::File(FileAction::Download))]
        );
    }

    /// `RECLASSIFY` and its rank travel together, in both directions.
    #[test]
    fn a_reclassification_without_a_rank_is_refused_and_so_is_a_rank_without_one() {
        assert!(matches!(
            DlpAction::from_sql("RECLASSIFY", None, "raise it"),
            Err(DlpRuleError::ReclassifyTarget { .. })
        ));
        assert!(matches!(
            DlpAction::from_sql("BLOCK", Some(30), "refuse it"),
            Err(DlpRuleError::ReclassifyTarget { .. })
        ));
        // The control: the pairing that is right is accepted, and keeps the rank.
        assert_eq!(
            DlpAction::from_sql("RECLASSIFY", Some(30), "raise it").expect("a paired rank"),
            DlpAction::Reclassify { to: ClassificationRank(30) }
        );
    }

    /// Encoding and decoding are each other's inverse, over a rule using every part of the shape.
    ///
    /// Without this, the two directions could drift into a state where a rule an admin surface
    /// stored is not the rule the evaluator later reads — which would be invisible until a rule
    /// stopped firing.
    #[test]
    fn a_rule_survives_the_round_trip_through_a_row() {
        let rule = DlpRule::new(
            RuleId::new("no external sharing of high-severity findings"),
            vec![ActionScope::ExternalSharing, ActionScope::ExposesContent],
            vec![
                Condition::SeverityAtLeast(Severity::High),
                Condition::CategoryAtLeast { category: DetectorCategory::Secret, count: 2 },
            ],
            DlpAction::Block,
        );

        let row = encode_rule(DlpRuleId::new_v7(), 10, &rule).expect("encodes");
        assert_eq!(decode_rule(&row).expect("decodes"), rule);
    }

    /// The stored form must not contain a mode, because a mode on the rule is the field D28's
    /// guarantee would be lost through.
    ///
    /// Asserted against the migration rather than against the Rust type, because the type having no
    /// field is already a compile-time fact — what a test can add is that the *table* has no column
    /// a future decoder could start reading.
    #[test]
    fn the_stored_form_has_no_mode() {
        let columns = column_names();

        // The control first, and it is not decoration: `column_names` parses a file, and an
        // assertion that a list does not contain something is satisfied by an empty list.
        assert!(
            columns.iter().any(|column| column == "conditions"),
            "the column list was not parsed at all: {columns:?}"
        );
        assert!(columns.iter().any(|column| column == "action"), "{columns:?}");

        assert!(
            !columns.iter().any(|column| column == "mode"),
            "a mode column would have to be carried on the rule type to be read, and \
             RuleSet::evaluate taking no mode is what makes SIMULATION and ENFORCE identical: \
             {columns:?}"
        );
        // The other two §12 columns nothing reads. `enabled` would be a second way to switch a rule
        // off beside withdrawal; `scope_type` would be a resource scope no rule type has.
        assert!(!columns.iter().any(|column| column == "enabled"), "{columns:?}");
        assert!(!columns.iter().any(|column| column == "scope_type"), "{columns:?}");
    }

    /// The first token of each line of `dlp_rules`' column list.
    ///
    /// Parsed rather than searched for, because the words `mode` and `enabled` appear in this
    /// migration's prose and in a `COMMENT ON` string — a substring search would report a column
    /// that is not there, and the first version of `the_stored_form_has_no_mode` did exactly that.
    fn column_names() -> Vec<String> {
        let migration = ddl();
        let (_, body) = migration
            .split_once("CREATE TABLE IF NOT EXISTS dlp_rules (")
            .expect("the migration creates the table");
        let (columns, _) = body.split_once("\n);").expect("the column list is closed");

        columns
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|token| token.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
            .map(str::to_owned)
            .collect()
    }
}
