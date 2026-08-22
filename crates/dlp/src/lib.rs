//! `enclave-dlp` — Detectors, policies, decisions, security facts
//!
//! Security and governance — a policy service in the canonical chain.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.
//!
//! # What is here so far
//!
//! | Module | Contents |
//! |---|---|
//! | [`detector`] | The shape of a detector: [`Candidate`], [`Verdict`], [`StructuredDetector`], and the linear scan |
//! | [`checksum`] | Luhn and ISO 7064 MOD 97-10, written out rather than depended on |
//! | [`builtin`] | The detectors a deployment gets without configuring anything |
//! | [`policy`] | Rules, and the **mode-independent** verdict evaluating them produces |
//! | [`mode`] | The five modes of `docs/06 §9`, and the one function that maps a verdict to an effect |
//! | [`observation`] | What an evaluation leaves behind, and the port it leaves it through |
//! | [`service`] | [`ModedDlp`] — the `DlpService` the chain holds |
//!
//! The facts a scan produces — [`enclave_core::SecurityFacts`] and the
//! [`enclave_core::FactsSnapshot`] the chain threads them through — live in `core`, because they
//! are vocabulary several stages read rather than anything this crate owns.
//!
//! # The two rules this crate is arranged around
//!
//! 1. **No regex on the synchronous path** (`plans/M4-GOVERNANCE.md` Q16). Detectors are validated
//!    by structure and checksum, and [`detector`] has nowhere to put a pattern.
//! 2. **Counts leave, content does not** (`CLAUDE.md` rule 10). A [`Candidate`] borrows the
//!    document and redacts itself in `Debug`; a [`ScanReport`] carries numbers.
//! 3. **Nothing that computes a verdict can see the mode** (`plans/M4-GOVERNANCE.md` D28).
//!    [`policy::RuleSet`] holds no mode and [`policy::RuleSet::evaluate`] takes none, so
//!    `SIMULATION` and `ENFORCE` cannot reach different conclusions — the code that reaches one
//!    has not been told which is running. [`mode`] carries the rest of that argument.

pub mod builtin;
pub mod checksum;
pub mod detector;
pub mod mode;
pub mod observation;
pub mod policy;
pub mod service;

pub use builtin::{builtin_set, Iban, PaymentCardNumber, BUILTIN_SET_VERSION};
pub use checksum::{luhn_valid, mod97};
pub use detector::{
    Candidate, CandidateClass, Confidence, DetectorFinding, DetectorId, DetectorSet, ScanReport,
    StructuredDetector, Verdict, MAX_CANDIDATE_LEN,
};
pub use mode::{DlpMode, Effect};
pub use observation::{Observation, ObservationSink, TracingObservations};
pub use policy::{
    ActionScope, Basis, Condition, Demand, DlpAction, DlpRule, RuleId, RuleSet,
    Verdict as PolicyVerdict,
};
pub use service::ModedDlp;

use async_trait::async_trait;
use enclave_core::{
    Action, DlpService, FactsSnapshot, RequestContext, ResourceRef, Result, StageDecision,
};

/// DLP in its `DISABLED` mode.
///
/// Unlike the other unconfigured stages, this one models a state the specification names explicitly:
/// `DISABLED` is one of the five modes in `docs/06-SECURITY-DLP-ACCESS.md §9`, alongside `MONITOR`,
/// `SIMULATION`, `WARN` and `ENFORCE`. A tenant may legitimately run with DLP off.
///
/// So this is not a placeholder for missing code — it is the correct behaviour of a real mode, and
/// it will remain reachable after `ENC-133` lands the detector engine. What changes then is that
/// the mode becomes a configuration choice rather than the only option.
///
/// It deliberately does **not** consult `SecurityFacts`, and now that the other four modes exist
/// that is worth restating rather than removing: with DLP disabled there is no policy whose
/// conditions could reference them, so a missing-facts decision (`docs/06 §12`) cannot arise. It
/// receives the snapshot because every implementation of the trait does — not consulting one you
/// were handed is a visible choice, whereas not having one to consult is an absence nobody reviews.
///
/// Equivalent to [`ModedDlp`] in [`DlpMode::Disabled`], and asserted to be in `tests/modes.rs`.
/// It is kept because a deployment that wants DLP off should not have to name a rule set and a sink
/// in order to say so.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledDlp;

#[async_trait]
impl DlpService for DisabledDlp {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
        _facts: &FactsSnapshot,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use enclave_core::{
        ClassificationRank, DetectorCategory, DetectorSetVersion, Exposure, FactsOutcome,
        FactsPolicy, FactsSnapshot, FileAction, FileId, ResourceState, ScanVersion, SecurityFacts,
        Utc, VersionId,
    };

    use super::*;

    /// The join this milestone step exists to define: a scan produces counts, the counts become
    /// facts, and the facts are what a stage decides against.
    ///
    /// The interesting property is what does **not** cross that boundary. `CLAUDE.md` rule 10
    /// forbids DLP match values in audit, and a `SecurityFacts` is the value an audit row is built
    /// from — so the match value must be absent from it, and absent from its `Debug`.
    #[test]
    fn a_scan_becomes_facts_that_carry_counts_and_no_content() {
        let pan = "4111111111111111";
        let iban = "GB82WEST12345698765432";
        let document =
            format!("Please charge {pan} and remit the balance to {iban} before Friday.");

        let set = builtin_set();
        let counts = set.scan(&document).counts();

        // The positive control comes first, deliberately: every assertion below is about an
        // absence, and an absence holds for free against a scanner that found nothing at all.
        assert_eq!(
            counts.get(DetectorCategory::Financial),
            2,
            "the scan must have found both identifiers, or the redaction proves nothing"
        );

        let facts = SecurityFacts::scanned(
            FileId::new_v7(),
            VersionId::new_v7(),
            counts,
            set.version().clone(),
            ScanVersion::new(1),
            Utc::now(),
        );

        let rendered = format!("{facts:?}");
        assert!(!rendered.contains(pan), "a card number reached a format string: {rendered}");
        assert!(!rendered.contains(iban), "an IBAN reached a format string: {rendered}");
        assert!(!rendered.contains("4111"), "a prefix of the card number did: {rendered}");
        assert!(!rendered.contains("WEST"), "part of the IBAN did: {rendered}");

        // And the second control: the needles are findable in a rendering that does not redact, so
        // the four misses above are the type carrying no content rather than the search being
        // wrong. `docs/12 §1.2`.
        assert!(document.contains(pan));
        assert!(document.contains(iban));
        assert!(document.contains("4111"));
        assert!(document.contains("WEST"));

        // The count did survive, which is the whole point of carrying facts at all.
        assert!(rendered.contains("financial: 2"), "the count did not survive: {rendered}");
    }

    /// The set's version is what a fact row is stamped with, and equality with the active set is
    /// what makes the row usable (`enclave_core::DetectorSetVersion`).
    #[test]
    fn facts_stamped_by_the_builtin_set_are_usable_against_that_same_set() {
        let set = builtin_set();
        let facts = SecurityFacts::scanned(
            FileId::new_v7(),
            VersionId::new_v7(),
            set.scan("nothing sensitive here").counts(),
            set.version().clone(),
            ScanVersion::new(1),
            Utc::now(),
        );

        let snapshot = FactsSnapshot::gathered(
            facts,
            set.version(),
            FactsPolicy::fail_closed(),
            ResourceState::new(Exposure::Internal, None),
        );
        assert!(matches!(
            snapshot.require(Action::File(FileAction::ContentRead)),
            FactsOutcome::Facts(_)
        ));

        // The control: a deployment running a *different* set cannot use them, so the assertion
        // above is the versions matching rather than `require` handing over whatever it holds.
        let facts = SecurityFacts::scanned(
            FileId::new_v7(),
            VersionId::new_v7(),
            set.scan("nothing sensitive here").counts(),
            DetectorSetVersion::new("builtin/2"),
            ScanVersion::new(1),
            Utc::now(),
        );
        let snapshot = FactsSnapshot::gathered(
            facts,
            set.version(),
            FactsPolicy::fail_closed(),
            ResourceState::new(Exposure::Internal, Some(ClassificationRank::new(20))),
        );
        assert!(matches!(
            snapshot.require(Action::File(FileAction::ContentRead)),
            FactsOutcome::Denied { .. }
        ));
    }
}
