//! The result of running the policy chain (`docs/03-LLD.md §12`).
//!
//! # Why everything here is `#[must_use]`
//!
//! Design decision D2 (`plans/M0-FOUNDATIONS.md`) and non-negotiable rule 8: **a dropped policy
//! decision must be a compile-time problem.**
//!
//! An allow is rarely unconditional. It usually arrives with obligations — watermark the
//! rendition, record a justification, treat the file as read-only — that the *caller* has to
//! satisfy, because only the caller knows how to render a watermark or where to put a
//! justification prompt. The engine decides; the caller complies.
//!
//! Which means the dangerous failure mode is not a wrong decision. It is a correct decision that
//! nobody looked at: `engine.enforce(...).await?;` compiles, runs the whole chain, audits
//! correctly, and then throws the obligations away. The file is served unwatermarked and every
//! test still passes. The only reliable defence is to make the value impossible to ignore
//! silently, which is what `#[must_use]` on both [`PolicyDecision`] and [`Obligations`] does — the
//! workspace additionally sets `clippy::let_underscore_must_use` to `deny`, so the usual escape
//! hatch of `let _ = …` is closed too.
//!
//! # Why there is no `Deny` variant
//!
//! A denial is `Err(Error::PolicyDenied { … })`, never a `PolicyDecision::Deny`. If denial were a
//! variant, then `let decision = enforce(…)?;` would yield a value that *looks* like success, and
//! forgetting to match on it would allow the operation. As an `Err`, the `?` operator handles it
//! correctly by default and the failure mode of forgetting is a compile error rather than a
//! bypass. So a `PolicyDecision` in hand always means "allowed"; the only open question it carries
//! is what still has to be done about it.

use serde::{Deserialize, Serialize};

/// A classification's ordinal, matching `classifications.rank` in `docs/04-DATA-MODEL.md §9`.
///
/// A rank rather than a label because labels are tenant-defined — one tenant's `CONFIDENTIAL` is
/// another's `INTERNAL_RESTRICTED` — while the *ordering* is the part policy actually reasons
/// about ("at or above this level, block export"). Higher is more sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClassificationRank(pub i32);

impl ClassificationRank {
    /// Wraps a raw rank.
    #[must_use]
    pub const fn new(rank: i32) -> Self {
        Self(rank)
    }

    /// The underlying ordinal.
    #[must_use]
    pub const fn get(&self) -> i32 {
        self.0
    }
}

/// A single condition attached to an allow, which the caller must satisfy or apply before the
/// operation completes (`docs/03-LLD.md §10`, `§12`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Obligation {
    /// Stamp the rendition with an identifying watermark before showing it. Applies to previews,
    /// prints and exports; ignoring it turns a traceable disclosure into an untraceable one.
    Watermark,
    /// The caller must supply a business justification, which is recorded in audit and in the
    /// incident. Unsatisfied, the operation must fail rather than proceed unexplained.
    RequireJustification,
    /// The operation must be routed for approval instead of executed now.
    RequireApproval,
    /// Permit the read but suppress every mutation path in the response — no edit affordance, no
    /// write capability in the returned `capabilities` object.
    ReadOnly,
    /// Serve a rendition but never the original bytes, and never an object-storage URL for them.
    NoDownload,
    /// Do not replicate to a device, whatever the client asked for.
    NoSync,
    /// Apply a new classification to the resource as a side effect — DLP found something more
    /// sensitive than the current label claims.
    Reclassify {
        /// The rank to raise the resource to.
        to: ClassificationRank,
    },
}

impl Obligation {
    /// Whether satisfying this obligation requires action *before* the operation proceeds, as
    /// opposed to constraining how its result is served.
    ///
    /// The distinction is operational: a blocking obligation that the caller cannot satisfy must
    /// turn into a denial, while a constraining one shapes the response. Stated once here so two
    /// callers cannot classify the same obligation differently.
    #[must_use]
    pub const fn blocks_until_satisfied(&self) -> bool {
        matches!(self, Self::RequireJustification | Self::RequireApproval)
    }
}

/// The obligations accumulated across the stages of one policy evaluation.
///
/// Stages *add* to this; nothing ever removes from it. A later stage cannot relax an earlier
/// stage's requirement, which is what makes the accumulated set safe to reason about: conditional
/// access saying "watermark" cannot be undone by DLP saying nothing.
///
/// Order of insertion is not preserved and does not matter — obligations are a set of
/// requirements, all of which apply.
#[must_use = "obligations are requirements the caller must satisfy; dropping them silently skips a control"]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Obligations(Vec<Obligation>);

impl Obligations {
    /// No obligations: an unconditional allow.
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Adds one obligation, returning whether it was new.
    ///
    /// Duplicates are dropped so that three stages independently demanding a watermark do not
    /// produce three watermarks.
    pub fn insert(&mut self, obligation: Obligation) -> bool {
        if self.0.contains(&obligation) {
            return false;
        }
        self.0.push(obligation);
        true
    }

    /// Folds another stage's obligations into this set.
    ///
    /// The union, never the intersection and never a replacement: a stage that produced no
    /// obligations is saying "I require nothing further", not "nothing is required".
    ///
    /// Note that [`Obligation::Reclassify`] entries with different targets are *both* retained —
    /// deciding which classification wins is classification policy, and silently discarding one
    /// here would hide a genuine disagreement between stages from the code equipped to resolve it.
    pub fn merge(&mut self, other: Self) {
        for obligation in other.0 {
            self.insert(obligation);
        }
    }

    /// Whether this exact obligation is present.
    #[must_use]
    pub fn contains(&self, obligation: &Obligation) -> bool {
        self.0.contains(obligation)
    }

    /// Whether any obligation must be satisfied before the operation may proceed.
    ///
    /// The question a caller asks to decide between "shape the response" and "stop and ask the
    /// user something".
    #[must_use]
    pub fn has_blocking(&self) -> bool {
        self.0.iter().any(Obligation::blocks_until_satisfied)
    }

    /// The classification this evaluation demands the resource be raised to, if any.
    ///
    /// Returns the highest rank when several stages disagree: reclassification only ever raises
    /// sensitivity, so taking the maximum is the conservative resolution.
    #[must_use]
    pub fn reclassify_to(&self) -> Option<ClassificationRank> {
        self.0
            .iter()
            .filter_map(|o| match o {
                Obligation::Reclassify { to } => Some(*to),
                _ => None,
            })
            .max()
    }

    /// Iterates the accumulated obligations.
    pub fn iter(&self) -> impl Iterator<Item = &Obligation> + '_ {
        self.0.iter()
    }

    /// How many distinct obligations were accumulated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the allow is unconditional.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<Obligation> for Obligations {
    fn from_iter<I: IntoIterator<Item = Obligation>>(iter: I) -> Self {
        let mut set = Self::none();
        for obligation in iter {
            set.insert(obligation);
        }
        set
    }
}

impl<'a> IntoIterator for &'a Obligations {
    type Item = &'a Obligation;
    type IntoIter = core::slice::Iter<'a, Obligation>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Proof that the policy chain ran and allowed the operation, together with what remains to be
/// done about it.
///
/// Holding one of these is the only legitimate basis for performing a protected operation. It is
/// returned by `PolicyEngine::enforce` and by nothing else; see the [module documentation](self)
/// for why it is `#[must_use]` and why there is no `Deny` variant.
#[must_use = "a policy decision carries obligations that must be satisfied; dropping it performs the operation without them"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    obligations: Obligations,
}

impl PolicyDecision {
    /// Records an allow carrying the obligations accumulated by the chain.
    ///
    /// Constructing one asserts that every stage ran and none denied. Only the policy engine is in
    /// a position to make that assertion honestly — the constructor is public because the engine
    /// lives in another crate, not because anything else should call it.
    pub fn allow(obligations: Obligations) -> Self {
        Self { obligations }
    }

    /// Records an allow with nothing further required.
    pub fn allow_unconditional() -> Self {
        Self { obligations: Obligations::none() }
    }

    /// The obligations attached to this decision.
    pub const fn obligations(&self) -> &Obligations {
        &self.obligations
    }

    /// Consumes the decision, yielding its obligations.
    ///
    /// The intended way to discharge one: taking the obligations by value is the caller saying "I
    /// have this, and I am now responsible for it". The returned set is itself `#[must_use]`, so
    /// the responsibility cannot be dropped on the floor one line later either.
    pub fn into_obligations(self) -> Obligations {
        self.obligations
    }

    /// Whether the allow came with no strings attached.
    #[must_use]
    pub fn is_unconditional(&self) -> bool {
        self.obligations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    // --- Compile-fail expectations -------------------------------------------------------------
    //
    // The following must NOT compile, and `trybuild` cases asserting so are ENC-103's remaining
    // acceptance item (see the crate notes). They cannot be expressed as ordinary unit tests,
    // because a test that fails to compile fails the build rather than passing:
    //
    //     engine.enforce(&ctx, action, &resource).await?;            // unused `PolicyDecision`
    //     let _ = engine.enforce(&ctx, action, &resource).await?;    // let_underscore_must_use
    //     decision.into_obligations();                               // unused `Obligations`
    //
    // The first and third are `unused_must_use`; the second is denied at the workspace level by
    // `clippy::let_underscore_must_use`. `trybuild` is deliberately not wired up yet: it needs a
    // `PolicyEngine` to call, and that lands with ENC-109. The `#[must_use]` attributes those
    // cases will assert on are in place now, which is what matters for anything built in the
    // meantime.
    //
    // What *can* be asserted here is that the attributes exist and that the accumulation
    // behaviour they protect is correct.

    #[test]
    fn merging_accumulates_across_stages() {
        let mut accumulated = Obligations::default();
        accumulated.merge([Obligation::Watermark].into_iter().collect());
        accumulated.merge([Obligation::NoDownload, Obligation::NoSync].into_iter().collect());

        assert_eq!(accumulated.len(), 3);
        assert!(accumulated.contains(&Obligation::Watermark));
        assert!(accumulated.contains(&Obligation::NoDownload));
        assert!(accumulated.contains(&Obligation::NoSync));
    }

    #[test]
    fn merging_is_a_union_and_deduplicates() {
        let mut accumulated: Obligations =
            [Obligation::Watermark, Obligation::ReadOnly].into_iter().collect();
        accumulated.merge([Obligation::Watermark].into_iter().collect());
        assert_eq!(accumulated.len(), 2);
    }

    #[test]
    fn merging_an_empty_set_never_relaxes_an_earlier_stage() {
        // A later stage having nothing to say must not clear what an earlier stage required.
        let mut accumulated: Obligations = [Obligation::Watermark].into_iter().collect();
        accumulated.merge(Obligations::none());
        assert!(accumulated.contains(&Obligation::Watermark));
        assert_eq!(accumulated.len(), 1);
    }

    #[test]
    fn insert_reports_whether_the_obligation_was_new() {
        let mut obligations = Obligations::none();
        assert!(obligations.insert(Obligation::RequireApproval));
        assert!(!obligations.insert(Obligation::RequireApproval));
    }

    #[test]
    fn blocking_obligations_are_distinguished_from_shaping_ones() {
        assert!(Obligation::RequireJustification.blocks_until_satisfied());
        assert!(Obligation::RequireApproval.blocks_until_satisfied());
        assert!(!Obligation::Watermark.blocks_until_satisfied());
        assert!(!Obligation::NoDownload.blocks_until_satisfied());

        let shaping: Obligations =
            [Obligation::Watermark, Obligation::NoSync].into_iter().collect();
        assert!(!shaping.has_blocking());
        let blocking: Obligations =
            [Obligation::Watermark, Obligation::RequireApproval].into_iter().collect();
        assert!(blocking.has_blocking());
    }

    #[test]
    fn conflicting_reclassifications_resolve_upwards() {
        let obligations: Obligations = [
            Obligation::Reclassify { to: ClassificationRank::new(30) },
            Obligation::Reclassify { to: ClassificationRank::new(50) },
        ]
        .into_iter()
        .collect();
        // Both are retained; resolution takes the more sensitive one.
        assert_eq!(obligations.len(), 2);
        assert_eq!(obligations.reclassify_to(), Some(ClassificationRank::new(50)));
    }

    #[test]
    fn no_reclassification_means_none() {
        let obligations: Obligations = [Obligation::Watermark].into_iter().collect();
        assert_eq!(obligations.reclassify_to(), None);
    }

    #[test]
    fn a_decision_carries_its_obligations_through_to_the_caller() {
        let mut obligations = Obligations::none();
        obligations.insert(Obligation::Watermark);
        let decision = PolicyDecision::allow(obligations);

        assert!(!decision.is_unconditional());
        assert!(decision.obligations().contains(&Obligation::Watermark));

        let discharged = decision.into_obligations();
        assert_eq!(discharged.len(), 1);
    }

    #[test]
    fn an_unconditional_allow_is_empty() {
        let decision = PolicyDecision::allow_unconditional();
        assert!(decision.is_unconditional());
        assert!(decision.obligations().is_empty());
        assert!(!decision.obligations().has_blocking());
    }

    #[test]
    fn obligations_round_trip_through_serde() {
        // Audit rows and job payloads carry these, so the wire form is part of the contract.
        let obligations: Obligations =
            [Obligation::Watermark, Obligation::Reclassify { to: ClassificationRank::new(40) }]
                .into_iter()
                .collect();
        let json = serde_json::to_string(&obligations).expect("serialize");
        assert_eq!(json, r#"[{"type":"WATERMARK"},{"type":"RECLASSIFY","to":40}]"#);
        let back: Obligations = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(obligations, back);
    }

    #[test]
    fn decisions_round_trip_through_serde() {
        let decision = PolicyDecision::allow([Obligation::NoDownload].into_iter().collect());
        let json = serde_json::to_string(&decision).expect("serialize");
        let back: PolicyDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decision, back);
    }
}
