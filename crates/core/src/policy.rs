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
//!
//! # Why `SecurityFacts` lives here too
//!
//! This module is the vocabulary one policy evaluation speaks. [`PolicyDecision`] is what comes
//! out of it; [`SecurityFacts`] — the precomputed detector counts a synchronous decision consumes
//! (`docs/06-SECURITY-DLP-ACCESS.md §12`) — is what goes in. Keeping the two together is what
//! makes the second half of the guarantee legible: a decision is only as good as the facts it was
//! taken against, and [`FactsSnapshot`] exists so that every stage of one request is taken against
//! the *same* facts (`plans/M4-GOVERNANCE.md` D26).
//!
//! The `#[must_use]` discipline extends to them. [`FactsOutcome`] and [`UnscannedAllow`] carry
//! obligations of their own — a denial to return, or an audit event that is the entire difference
//! between the two `facts_unavailable` modes — and dropping either is the same class of defect as
//! dropping an obligation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::action::Action;
use crate::error::{Error, ReasonCode, Remediation};
use crate::id::{FileId, VersionId};

/// A classification's ordinal, matching `classifications.rank` in `docs/04-DATA-MODEL.md §9`.
///
/// A rank rather than a label because labels are tenant-defined — one tenant's `CONFIDENTIAL` is
/// another's `INTERNAL_RESTRICTED` — while the *ordering* is the part policy actually reasons
/// about ("at or above this level, block export"). Higher is more sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClassificationRank(pub i32);

impl ClassificationRank {
    /// The rank `RESTRICTED` carries in the shipped label set — `PUBLIC` 10, `INTERNAL` 20,
    /// `CONFIDENTIAL` 30, `HIGHLY_CONFIDENTIAL` 40, `RESTRICTED` 50 (`docs/01-PRD.md §17`).
    ///
    /// A *default*, not a truth: ranks are tenant-defined, so anything that needs to know where
    /// `RESTRICTED` sits for a particular tenant takes it as a parameter (see
    /// [`FactsPolicy::from_tenant_config`]) and uses this only as the starting value.
    pub const RESTRICTED: Self = Self(50);

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

    /// The denial a path that *cannot* satisfy this obligation must return.
    ///
    /// D29 (`plans/M4-GOVERNANCE.md`): an obligation is satisfied or the operation fails, and there
    /// is no third outcome. Every path therefore needs an answer to "what if I cannot do this", and
    /// the answer must not be invented per call site — two handlers refusing the same
    /// unsatisfiable obligation with two different codes is a client that cannot offer a coherent
    /// next step.
    ///
    /// The codes are chosen so the caller learns what to *do*, not what we could not do:
    /// `DLP_JUSTIFICATION_REQUIRED` and `DLP_APPROVAL_REQUIRED` name the missing input, and
    /// `PREVIEW_ONLY` says the file is reachable by another route. `ACCESS_DENIED` is the residue
    /// for obligations that shape a *response* — meeting one of those on a path with no response to
    /// shape means the stage and the surface disagree about what is happening, which is not
    /// something to advise a caller about.
    #[must_use]
    pub const fn unsatisfied_code(&self) -> ReasonCode {
        match self {
            Self::RequireJustification => ReasonCode::DlpJustificationRequired,
            Self::RequireApproval => ReasonCode::DlpApprovalRequired,
            Self::Watermark | Self::NoDownload => ReasonCode::PreviewOnly,
            Self::ReadOnly | Self::NoSync | Self::Reclassify { .. } => ReasonCode::AccessDenied,
        }
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

    /// Refuses when this path was handed an obligation it has no way to satisfy.
    ///
    /// For the call sites — a listing, a self-read — where *no* obligation is satisfiable, so the
    /// exhaustive `match` a delivery path writes would have one arm and it would be a refusal.
    ///
    /// # Why this exists rather than a `debug_assert!`
    ///
    /// Three handlers asserted `obligations.is_empty()` with `debug_assert!`, which is compiled out
    /// of a release build: the release binary dropped the obligation and served the response. That
    /// is precisely D29's third outcome, and precisely the defect `ENC-544` found in the audit
    /// crate's field-count guard — a guard that only ran where nobody was looking. A check that
    /// protects a control has to be a check in the build that ships.
    ///
    /// # Errors
    ///
    /// [`Error::PolicyDenied`] carrying [`Obligation::unsatisfied_code`] for the first outstanding
    /// obligation.
    pub fn require_none(&self) -> Result<(), Error> {
        match self.0.first() {
            None => Ok(()),
            Some(obligation) => Err(Error::denied(obligation.unsatisfied_code())),
        }
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

// =================================================================================================
// Security facts — the inputs half of the chain's vocabulary.
//
// `docs/06-SECURITY-DLP-ACCESS.md §12`, and design decisions D26/D27 of `plans/M4-GOVERNANCE.md`.
// =================================================================================================

wire_enum! {
    /// The bucket a detector's findings are counted under.
    ///
    /// Four, matching the four count columns of `security_facts` in `docs/04-DATA-MODEL.md §12`.
    /// Policy is written against categories rather than against individual detectors, because a
    /// rule saying "block export of anything carrying payment data" has to keep working when a
    /// second card detector is added beside the first.
    pub enum DetectorCategory {
        /// Personal data: national identifiers, passport numbers, contact details.
        Pii => "PII",
        /// Credentials and key material: API keys, tokens, private keys, source-code secrets.
        Secret => "SECRET",
        /// Payment and banking instruments: card numbers, IBANs, account numbers.
        Financial => "FINANCIAL",
        /// Health identifiers and records.
        Health => "HEALTH",
    }
}

wire_enum! {
    /// How serious the most serious finding in a scan was (`security_facts.max_severity`).
    ///
    /// Ordered, and the ordering is the point: the column exists so a policy can say "at or above
    /// `HIGH`" without enumerating detectors.
    pub enum Severity {
        /// Worth recording, not worth acting on alone.
        Low => "LOW",
        /// Acts in combination with other signals.
        Medium => "MEDIUM",
        /// Acts alone.
        High => "HIGH",
        /// Acts alone and raises an incident.
        Critical => "CRITICAL",
    }
}

/// How many instances a scan found, per [`DetectorCategory`].
///
/// **Counts, never content.** A count is what a synchronous decision needs — does this version
/// carry payment data at all, and how much — and the matched bytes are not carried forward past
/// the scanner that produced them (`CLAUDE.md` rule 10). There is deliberately no field here that
/// a match value could occupy, which is what makes deriving [`Debug`] and [`Serialize`] on this
/// type and on [`SecurityFacts`] a safe default rather than an oversight.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorCounts {
    #[serde(rename = "pii_count")]
    pii: u32,
    #[serde(rename = "secret_count")]
    secret: u32,
    #[serde(rename = "financial_count")]
    financial: u32,
    #[serde(rename = "health_count")]
    health: u32,
}

impl DetectorCounts {
    /// A clean document.
    #[must_use]
    pub const fn none() -> Self {
        Self { pii: 0, secret: 0, financial: 0, health: 0 }
    }

    /// Adds findings to a category.
    ///
    /// Saturating rather than wrapping: a document engineered to overflow a `u32` of card numbers
    /// must not wrap round to "clean". Saturation loses precision at the point where precision has
    /// stopped mattering — every threshold worth writing was crossed four billion findings ago.
    pub const fn add(&mut self, category: DetectorCategory, count: u32) {
        let slot = match category {
            DetectorCategory::Pii => &mut self.pii,
            DetectorCategory::Secret => &mut self.secret,
            DetectorCategory::Financial => &mut self.financial,
            DetectorCategory::Health => &mut self.health,
        };
        *slot = slot.saturating_add(count);
    }

    /// The count in one category.
    #[must_use]
    pub const fn get(&self, category: DetectorCategory) -> u32 {
        match category {
            DetectorCategory::Pii => self.pii,
            DetectorCategory::Secret => self.secret,
            DetectorCategory::Financial => self.financial,
            DetectorCategory::Health => self.health,
        }
    }

    /// Every finding, across every category.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.pii
            .saturating_add(self.secret)
            .saturating_add(self.financial)
            .saturating_add(self.health)
    }

    /// Whether the scan found nothing at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// The generation of the scanning *pipeline* that produced a fact row (`scan_version`).
///
/// Distinct from [`DetectorSetVersion`], and the distinction is operational: the pipeline moves
/// when extraction changes (a new rasteriser, OCR arriving), the detector set moves when the rules
/// change. `idx_facts_stale` indexes this one so a backfill can find what a pipeline change
/// invalidated. It is carried here for that, not because a decision reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScanVersion(i32);

impl ScanVersion {
    /// Wraps a raw generation number.
    #[must_use]
    pub const fn new(version: i32) -> Self {
        Self(version)
    }

    /// The underlying number.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// Which detector set produced a fact row (`security_facts.detector_set_version`).
///
/// # Why freshness is equality and not an ordering
///
/// `docs/06 §12` says facts are unusable when their version is "older than the active one", and
/// this type deliberately offers no way to ask that question. The column is `TEXT` — an opaque
/// build identifier — and any ordering imposed on it, lexical or numeric-after-parsing or semver,
/// would be an ordering *we* invented over a string somebody else formats. The failure mode is
/// silent and one-directional: a version that sorts unexpectedly high reads as fresh, and stale
/// facts are then used for a decision that believes it saw the current rules.
///
/// So the rule is equality with the active set, and everything else — older, newer, unrecognised,
/// empty — is [`FactsStaleness::StaleDetectorSet`]. A version we do not recognise is not evidence
/// that the active detectors ran.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DetectorSetVersion(String);

impl DetectorSetVersion {
    /// Names a detector set.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    /// The identifier as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DetectorSetVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The composite risk signal `docs/06 §12` asks for, on the `0..=100` scale of
/// `security_facts.risk_score`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct RiskScore(u8);

impl RiskScore {
    /// No elevated risk.
    pub const ZERO: Self = Self(0);

    /// Clamps to `0..=100` rather than rejecting.
    ///
    /// A risk score is a heuristic aggregate, so an out-of-range value is a scorer defect and not
    /// a caller error — and refusing the whole fact row over it would discard the counts, which
    /// are exact, in order to punish an estimate that is not.
    #[must_use]
    pub const fn new(score: u8) -> Self {
        Self(if score > 100 { 100 } else { score })
    }

    /// The score, `0..=100`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// What a completed asynchronous scan concluded about one version of one file.
///
/// The row of `security_facts` (`docs/04-DATA-MODEL.md §12`) as a value. Every field is a count, a
/// rank, a version or a timestamp — see [`DetectorCounts`] for why that is a property worth
/// stating rather than an accident of what the table happened to need.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFacts {
    file_id: FileId,
    version_id: VersionId,
    counts: DetectorCounts,
    classification: Option<ClassificationRank>,
    max_severity: Option<Severity>,
    risk_score: RiskScore,
    scan_version: ScanVersion,
    detector_set: DetectorSetVersion,
    scanned_at: DateTime<Utc>,
}

impl SecurityFacts {
    /// Records the outcome of a completed scan.
    ///
    /// The optional signals — classification, severity, risk score — attach with the `with_*`
    /// methods, because a scan that produced counts and nothing else is the ordinary case and
    /// should not have to name three `None`s to say so.
    #[must_use]
    pub fn scanned(
        file_id: FileId,
        version_id: VersionId,
        counts: DetectorCounts,
        detector_set: DetectorSetVersion,
        scan_version: ScanVersion,
        scanned_at: DateTime<Utc>,
    ) -> Self {
        Self {
            file_id,
            version_id,
            counts,
            classification: None,
            max_severity: None,
            risk_score: RiskScore::ZERO,
            scan_version,
            detector_set,
            scanned_at,
        }
    }

    /// Attaches the classification the scan resolved.
    #[must_use]
    pub fn with_classification(mut self, rank: ClassificationRank) -> Self {
        self.classification = Some(rank);
        self
    }

    /// Attaches the severity of the most serious finding.
    #[must_use]
    pub fn with_max_severity(mut self, severity: Severity) -> Self {
        self.max_severity = Some(severity);
        self
    }

    /// Attaches the composite risk score.
    #[must_use]
    pub fn with_risk_score(mut self, score: RiskScore) -> Self {
        self.risk_score = score;
        self
    }

    /// The file these facts describe.
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    /// The immutable version these facts describe.
    ///
    /// Facts are per version and never per file: a new version is unscanned content even though
    /// the file has been scanned many times before.
    #[must_use]
    pub const fn version_id(&self) -> VersionId {
        self.version_id
    }

    /// What the detectors found, per category.
    #[must_use]
    pub const fn counts(&self) -> &DetectorCounts {
        &self.counts
    }

    /// The classification the scan resolved, if it resolved one.
    #[must_use]
    pub const fn classification(&self) -> Option<ClassificationRank> {
        self.classification
    }

    /// The severity of the most serious finding.
    #[must_use]
    pub const fn max_severity(&self) -> Option<Severity> {
        self.max_severity
    }

    /// The composite risk signal.
    #[must_use]
    pub const fn risk_score(&self) -> RiskScore {
        self.risk_score
    }

    /// The pipeline generation that produced these facts.
    #[must_use]
    pub const fn scan_version(&self) -> ScanVersion {
        self.scan_version
    }

    /// The detector set that produced these facts.
    #[must_use]
    pub const fn detector_set(&self) -> &DetectorSetVersion {
        &self.detector_set
    }

    /// When the scan completed.
    #[must_use]
    pub const fn scanned_at(&self) -> DateTime<Utc> {
        self.scanned_at
    }
}

/// Why the chain may not be able to decide from facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactsStaleness {
    /// Facts exist and were produced by the active detector set.
    Fresh,
    /// Facts exist and were produced by some *other* detector set. See [`DetectorSetVersion`] for
    /// why that is not narrowed to "an older one".
    StaleDetectorSet,
    /// No facts at all: the version is unscanned, or its scan has not finished.
    Missing,
}

impl FactsStaleness {
    /// Whether a decision may be taken from these facts.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// The tenant's configured answer to "what happens when there are no usable facts"
/// (`docs/06 §12`).
///
/// # Why this type cannot be deserialized
///
/// D27: this is tenant policy, never a per-request choice, because *"a per-request override is the
/// shape that gets added for 'just this bulk import' and stays."*
///
/// Every piece of caller-supplied data in this codebase becomes a typed value through `serde` — a
/// JSON body, a query string, a header extractor. This enum implements [`Serialize`], so an audit
/// row can record which mode was in force, and implements neither `Deserialize` nor `FromStr`.
/// There is therefore no route from bytes on the wire to a value of this type: a request cannot
/// carry one even as a field somebody meant to ignore, because the field would not parse. That is
/// the difference between "we do not read an override" and "an override is unrepresentable".
///
/// The only way in is [`FactsPolicy::from_tenant_config`], called where tenant configuration is
/// loaded. The only consumer, [`FactsSnapshot::require`], takes no argument through which a mode
/// could travel — its inputs are the action and the resource's rank, both facts about what is
/// being attempted rather than choices about how to treat it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FactsUnavailable {
    /// Deny the sensitive action and explain that scanning is in progress.
    ///
    /// The default, here as everywhere in this codebase: a control that could not evaluate has not
    /// allowed.
    #[default]
    FailClosed,
    /// Allow, record a high-visibility audit event, and enqueue a priority rescan.
    FailOpenAudit,
}

impl FactsUnavailable {
    /// The stable form, for audit rows and configuration diffs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "FAIL_CLOSED",
            Self::FailOpenAudit => "FAIL_OPEN_AUDIT",
        }
    }
}

impl std::fmt::Display for FactsUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for FactsUnavailable {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Whether the resource an action targets is *already* reachable from outside the tenant.
///
/// # Why this exists (`ENC-588`)
///
/// D27 makes `FAIL_CLOSED` mandatory for external sharing at any classification, and
/// [`Action::is_external_share`] can only recognise the two actions that *create* external
/// exposure. `ShareAction::Update` — change expiry, permission or password on an existing share —
/// is not among them and cannot be: whether that share is external is a property of the
/// **resource**. So under `FAIL_OPEN_AUDIT`, removing the password from an existing external link
/// over unscanned content was permitted, while creating that same link would have been denied.
///
/// The narrow reading — the content was already exposed, so nothing new is — does not hold.
/// Broadening a permission or dropping a password increases the exposure of a document nobody has
/// scanned.
///
/// # Why it lives on the snapshot rather than on `require`
///
/// [`FactsSnapshot`] is the value gathered once, at the single point facts enter the request
/// (D26). Putting the resource's exposure there means two stages cannot answer the question
/// differently, and no caller can omit it — whereas a `require` parameter defaulting to
/// [`Exposure::Internal`] would be silently permissive exactly when it was forgotten.
///
/// Serializable for the audit row, and deliberately **not** deserializable, for the same reason
/// [`FactsUnavailable`] is not: there must be no route from bytes on the wire to a value that
/// relaxes an escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exposure {
    /// Reachable only inside the tenant.
    Internal,
    /// Already reachable from outside it — the resource is an external share, or one exists over
    /// it.
    External,
}

impl Exposure {
    /// The stable form, for audit rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::External => "EXTERNAL",
        }
    }

    /// Whether the resource already reaches outside the tenant.
    #[must_use]
    pub const fn is_external(self) -> bool {
        matches!(self, Self::External)
    }
}

impl std::fmt::Display for Exposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Exposure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// What the chain knows about the **resource** rather than about its content.
///
/// [`SecurityFacts`] is what a *scan* concluded, and a scan may not have run. This is what is true
/// of the resource whether or not one has: the label it carries and how far it already reaches.
/// Both are read in the same breath as the facts, so they are as of the same instant (D26).
///
/// # Why the classification is here and not a parameter of [`FactsSnapshot::require`]
///
/// `ENC-591`. D27 makes `FAIL_CLOSED` mandatory *for `RESTRICTED`*, and the rank the escalation
/// compares against was originally supplied by the caller. The only caller is the DLP stage, which
/// has no label of its own to offer — so where a scan had not completed it had nothing to pass,
/// and the rank arrived as `None`. That left the escalation dead in exactly the case it exists
/// for: an unscanned `RESTRICTED` document under `FAIL_OPEN_AUDIT` was permitted, because the
/// evidence that it was `RESTRICTED` was expected to come from the scan that had not happened.
///
/// A resource's label does not depend on a scan. Reading it beside the facts, and taking it from
/// the snapshot rather than from an argument, is what makes the escalation fire on a document
/// nobody has looked at yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceState {
    exposure: Exposure,
    classification: Option<ClassificationRank>,
}

impl ResourceState {
    /// Records what was read about the resource.
    ///
    /// `classification` is the label the resource carries *now*, from the classification tables —
    /// not the one a scan resolved. `None` means the resource genuinely has no label, which is
    /// itself a fact and not a missing read.
    #[must_use]
    pub const fn new(exposure: Exposure, classification: Option<ClassificationRank>) -> Self {
        Self { exposure, classification }
    }

    /// How far the resource already reaches.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }

    /// The label the resource carries.
    #[must_use]
    pub const fn classification(&self) -> Option<ClassificationRank> {
        self.classification
    }
}

/// Tenant policy for evaluating without usable facts.
///
/// Two fields, both from tenant configuration, and no setters. See [`FactsUnavailable`] for why
/// there is no third field a request could fill in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactsPolicy {
    on_unavailable: FactsUnavailable,
    restricted_at: ClassificationRank,
}

impl FactsPolicy {
    /// The only constructor, named for the only legitimate source of both values.
    ///
    /// `restricted_at` is the rank at which this tenant's labels become `RESTRICTED`. It is a
    /// parameter rather than the constant 50 because ranks are tenant-defined
    /// ([`ClassificationRank`]) — and it is not a way round D27, because raising it is a
    /// configuration change that shows up in a diff, not a field on a request.
    #[must_use]
    pub const fn from_tenant_config(
        on_unavailable: FactsUnavailable,
        restricted_at: ClassificationRank,
    ) -> Self {
        Self { on_unavailable, restricted_at }
    }

    /// The safe default: deny without facts, with the shipped label set's `RESTRICTED` rank.
    ///
    /// What a deployment has before its DLP configuration is loaded, and what a test that does not
    /// care about the mode should use.
    #[must_use]
    pub const fn fail_closed() -> Self {
        Self::from_tenant_config(FactsUnavailable::FailClosed, ClassificationRank::RESTRICTED)
    }

    /// The configured mode, for the audit row that records which policy was in force.
    #[must_use]
    pub const fn on_unavailable(&self) -> FactsUnavailable {
        self.on_unavailable
    }

    /// Whether this attempt fails closed whatever the configured mode says.
    ///
    /// D27's second sentence in code: `FAIL_CLOSED` is mandatory for `RESTRICTED` and for external
    /// sharing at *any* classification. Both are cases where allowing an unscanned action puts
    /// content somewhere it cannot be recalled from — outside the tenant, or in front of the
    /// caller the label exists to keep it away from.
    ///
    /// "External sharing" is two questions, not one, and `ENC-588` is the second of them.
    /// [`Action::is_external_share`] recognises the actions that *create* exposure;
    /// [`Action::alters_existing_share`] paired with [`Exposure::External`] recognises the ones
    /// that *broaden* it. Neither implies the other, and the second needs the resource — which is
    /// why the exposure travels on the snapshot.
    #[must_use]
    pub fn is_forced_closed(
        &self,
        action: Action,
        rank: Option<ClassificationRank>,
        exposure: Exposure,
    ) -> bool {
        action.is_external_share()
            || (exposure.is_external() && action.alters_existing_share())
            || rank.is_some_and(|r| r >= self.restricted_at)
    }
}

/// The evidence a `FAIL_OPEN_AUDIT` allow must leave behind (`docs/06 §12`).
///
/// `#[must_use]` for the reason the rest of this module is: fail-open without the audit event is
/// an ordinary allow that nobody can find afterwards, and the trail is the *entire* difference
/// between the two modes. Dropping this value deletes that difference.
#[must_use = "FAIL_OPEN_AUDIT permitted an action against unscanned content; without the \
              high-visibility audit event and the priority rescan it is an ordinary allow that \
              leaves no trace"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnscannedAllow {
    action: Action,
    staleness: FactsStaleness,
}

impl UnscannedAllow {
    /// What was permitted without facts.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// Whether facts were absent or merely produced by another detector set.
    ///
    /// The difference between "the scan has not run" and "the rules have moved", which is what
    /// lets the rescan queue prioritise sensibly instead of treating both as urgent.
    #[must_use]
    pub const fn staleness(&self) -> FactsStaleness {
        self.staleness
    }
}

/// What a stage may do about one attempt, given the facts it has.
///
/// Three arms and no fourth: there is no "carry on and hope". The `match` is exhaustive at every
/// call site, so a stage that gains a new way to be uncertain cannot silently take the allow path.
#[must_use = "a facts outcome decides whether the stage proceeds, denies, or proceeds and must audit"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactsOutcome<'a> {
    /// Facts are current. Decide with them.
    Facts(&'a SecurityFacts),
    /// No usable facts, and this attempt fails closed.
    Denied {
        /// The stable code the caller may be told.
        code: ReasonCode,
        /// What they can do about it.
        remediation: Remediation,
    },
    /// No usable facts, and the tenant's policy permits proceeding. Discharge the obligation.
    Unscanned(UnscannedAllow),
}

impl FactsOutcome<'_> {
    /// The denial, when this outcome is one.
    ///
    /// A convenience for a stage that translates straight into the chain's error type. The
    /// exhaustive `match` stays available and is what a stage with something to record wants.
    #[must_use]
    pub fn into_denial(self) -> Option<Error> {
        match self {
            Self::Denied { code, remediation } => Some(Error::denied_with(code, remediation)),
            Self::Facts(_) | Self::Unscanned(_) => None,
        }
    }
}

/// Everything the chain knows about one resource's content, gathered once and passed down (D26).
///
/// # Why every stage receives the same value
///
/// The obvious reason is cost: facts are a read per resource and the chain has seven stages. The
/// reason that matters is that a stage re-fetching can observe *different* facts from the stage
/// before it — a scan completing mid-chain flips availability between DLP and retention, and the
/// request is then decided against two views of the same document. That is not a race that
/// occasionally produces a wrong answer; it is a race that produces a decision nobody can
/// reconstruct from the audit row, because the row records one of the two.
///
/// **The consequence is accepted rather than mitigated: facts are as of the start of the request.**
/// A scan finishing during a request does not affect that request.
///
/// # Why staleness is settled at construction
///
/// [`Self::gathered`] takes the *active* detector set and answers the freshness question once, at
/// the single point where facts enter the request. There is no accessor that hands out unusable
/// facts, so a stage cannot read counts the active rules never produced: the only route to a
/// [`SecurityFacts`] is [`Self::require`], and it settles availability on the way past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactsSnapshot {
    facts: Option<SecurityFacts>,
    staleness: FactsStaleness,
    policy: FactsPolicy,
    resource: ResourceState,
}

impl FactsSnapshot {
    /// Records facts read at the start of a request, against the detector set active now.
    ///
    /// [`ResourceState`] is read in the same breath and for the same reason: its two fields are
    /// what the mandatory escalations compare against, and gathering them anywhere else would
    /// reintroduce the second read D26 exists to forbid.
    #[must_use]
    pub fn gathered(
        facts: SecurityFacts,
        active_set: &DetectorSetVersion,
        policy: FactsPolicy,
        resource: ResourceState,
    ) -> Self {
        let staleness = if facts.detector_set() == active_set {
            FactsStaleness::Fresh
        } else {
            FactsStaleness::StaleDetectorSet
        };
        Self { facts: Some(facts), staleness, policy, resource }
    }

    /// Records that the resource has no facts — unscanned, or a scan still running.
    #[must_use]
    pub const fn missing(policy: FactsPolicy, resource: ResourceState) -> Self {
        Self { facts: None, staleness: FactsStaleness::Missing, policy, resource }
    }

    /// Why the facts are or are not usable, for the audit row.
    #[must_use]
    pub const fn staleness(&self) -> FactsStaleness {
        self.staleness
    }

    /// The tenant policy this snapshot was gathered under.
    #[must_use]
    pub const fn policy(&self) -> FactsPolicy {
        self.policy
    }

    /// What was read about the resource itself — its label and its reach.
    #[must_use]
    pub const fn resource(&self) -> ResourceState {
        self.resource
    }

    /// Whether the resource already reaches outside the tenant.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.resource.exposure()
    }

    /// The rank the resource carries, if anything above or on it is labelled.
    ///
    /// Exposed beside [`Self::exposure`] for the same reason: both are properties of the
    /// *resource* that travelled here with the facts, and a test that cannot read them can only
    /// assert the comparison a hand-built `ResourceState` makes rather than that the real value
    /// arrived. `ENC-655` is what that distinction cost — the escalation was unit-tested and dead
    /// in the binary at the same time, because the provider passed `None` and nothing could see it.
    #[must_use]
    pub const fn classification(&self) -> Option<ClassificationRank> {
        self.resource.classification()
    }

    /// The facts, or what the tenant's policy says to do without them.
    ///
    /// `action` is a property of the attempt, not a choice about how to treat it: there is no
    /// parameter here through which a caller could ask for a different failure mode. See
    /// [`FactsUnavailable`]. The other two inputs the escalations need — the resource's label and
    /// whether it is already externally exposed — are not parameters either; they were settled
    /// when the snapshot was gathered, so a stage cannot supply a rank of its own and a stage that
    /// forgets one cannot exist.
    pub fn require(&self, action: Action) -> FactsOutcome<'_> {
        if let Some(facts) = self.facts.as_ref().filter(|_| self.staleness.is_usable()) {
            return FactsOutcome::Facts(facts);
        }

        let fail_closed = self.policy.is_forced_closed(
            action,
            self.resource.classification(),
            self.resource.exposure(),
        ) || self.policy.on_unavailable() == FactsUnavailable::FailClosed;

        if fail_closed {
            // `DLP_BLOCKED` with `RETRY_LATER` rather than its default `REQUEST_EXCEPTION`: the
            // condition is transient, and the honest advice is to wait for the scan rather than to
            // ask a security administrator to except a file from being scanned. A dedicated
            // `SCAN_IN_PROGRESS` code would say it better and is `ENC-587`.
            FactsOutcome::Denied {
                code: ReasonCode::DlpBlocked,
                remediation: Remediation::RetryLater,
            }
        } else {
            FactsOutcome::Unscanned(UnscannedAllow { action, staleness: self.staleness })
        }
    }
}

/// Where on a resource's chain the label that decided its rank was found.
///
/// Carried rather than discarded because "why is this document `RESTRICTED`" has four different
/// answers and only one of them is fixable by relabelling the document. An administrator told that
/// the rank came from the workspace goes to the workspace; one told only the number goes looking.
///
/// Serializable for the audit row, and — like [`Exposure`] and [`FactsUnavailable`] — deliberately
/// **not** deserializable. Nothing about where a label came from may arrive from a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelSource {
    /// The resource carries the label itself.
    Resource,
    /// A folder above it does.
    Ancestor,
    /// The library's default.
    Library,
    /// The workspace's default.
    Workspace,
}

impl LabelSource {
    /// The stable form, for audit rows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "RESOURCE",
            Self::Ancestor => "ANCESTOR",
            Self::Library => "LIBRARY",
            Self::Workspace => "WORKSPACE",
        }
    }
}

impl std::fmt::Display for LabelSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for LabelSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A resource's **effective** classification: the rank a label actually put on it, and where.
///
/// "Effective" is the whole of `ENC-574`. A file's own `classification_id` is not the answer,
/// because a document in a `RESTRICTED` folder is restricted whether or not anyone stamped the
/// document — so the rank is resolved over the chain (`enclave_db::classifications`) and this is
/// what that resolution produced.
///
/// There is no constructor taking a bare rank without a source. That is deliberate: a rank with no
/// provenance is the shape a constant would arrive in, and a constant is the failure
/// `enclave_worker::indexing::UnclassifiedFiles` refuses in both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EffectiveClassification {
    rank: ClassificationRank,
    source: LabelSource,
}

impl EffectiveClassification {
    /// Records a label found on the chain.
    #[must_use]
    pub const fn found(rank: ClassificationRank, source: LabelSource) -> Self {
        Self { rank, source }
    }

    /// The rank policy compares.
    #[must_use]
    pub const fn rank(&self) -> ClassificationRank {
        self.rank
    }

    /// Where the label was found.
    #[must_use]
    pub const fn source(&self) -> LabelSource {
        self.source
    }
}

/// The tenant's configured answer to "what happens when nothing on a resource's chain carries a
/// label" (`ENC-574`).
///
/// # Why this is a policy and not a default
///
/// The row this closes was open because both plausible defaults are wrong in opposite, undetectable
/// directions. Defaulting an unlabelled file to the lowest rank sends every document to whichever
/// embedding provider the ceiling admits, with the ceiling comparison working perfectly — S8
/// defeated through its input. Defaulting it to the highest writes a rank no caller's ceiling
/// admits, so the document is visible in the tree and absent from every search. Neither is visible
/// from outside.
///
/// So there is no default rank here. There is [`Self::FailClosed`], which refuses and says why, and
/// there is [`Self::Assume`], in which **the tenant names the rank** an unlabelled resource is
/// treated as carrying — and every allow taken under it carries an audit obligation, so the choice
/// leaves a trail rather than becoming invisible.
///
/// # Why this type cannot be deserialized
///
/// D27, exactly as [`FactsUnavailable`] states it: this is tenant policy, never a per-request
/// choice, because *"a per-request override is the shape that gets added for 'just this bulk
/// import' and stays."* It implements [`Serialize`] so an audit row can record which mode was in
/// force, and implements neither `Deserialize` nor `FromStr`. There is therefore no route from
/// bytes on the wire to a value of this type — a request cannot carry one even as a field somebody
/// meant to ignore, because the field would not parse.
///
/// Note what the [`Self::Assume`] payload would be if that were not true: a rank, supplied by the
/// caller, applied to content the caller is about to act on. It is the single most valuable field
/// an attacker could add to a request body, which is why the enum that carries it is the one that
/// must not be constructible from input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Unlabelled {
    /// Refuse, and tell the caller the resource has no classification.
    ///
    /// The default, here as everywhere in this codebase: a control that could not evaluate has not
    /// allowed. It is also what every deployment has today —
    /// `enclave_worker::indexing::UnclassifiedFiles` refuses every document — so this is the
    /// behaviour being *preserved* rather than a new refusal being introduced.
    #[default]
    FailClosed,
    /// Proceed as though the resource carried this rank, and audit the fact that it did not.
    ///
    /// The rank is the tenant's, from configuration. A tenant whose content is overwhelmingly
    /// internal sets it to their `INTERNAL` rank and gets a working product; a tenant that sets it
    /// to their `RESTRICTED` rank gets local-only embedding for everything unlabelled. Both are
    /// legitimate and neither is a guess this codebase made.
    Assume(ClassificationRank),
}

impl std::fmt::Display for Unlabelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailClosed => f.write_str("FAIL_CLOSED"),
            Self::Assume(rank) => write!(f, "ASSUME_RANK({})", rank.get()),
        }
    }
}

impl Serialize for Unlabelled {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Tenant policy for acting on a resource no label could be resolved for.
///
/// One field, from tenant configuration, and no setters — the shape [`FactsPolicy`] uses, and for
/// the same reason. See [`Unlabelled`] for why there is no field a request could fill in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassificationPolicy {
    on_unlabelled: Unlabelled,
}

impl ClassificationPolicy {
    /// The only constructor, named for the only legitimate source of the value.
    #[must_use]
    pub const fn from_tenant_config(on_unlabelled: Unlabelled) -> Self {
        Self { on_unlabelled }
    }

    /// The safe default: refuse without a label.
    ///
    /// What a deployment has before its classification configuration is loaded, and what a test
    /// that does not care about the mode should use.
    #[must_use]
    pub const fn fail_closed() -> Self {
        Self::from_tenant_config(Unlabelled::FailClosed)
    }

    /// The configured mode, for the audit row that records which policy was in force.
    #[must_use]
    pub const fn on_unlabelled(&self) -> Unlabelled {
        self.on_unlabelled
    }

    /// Whether an unlabelled resource refuses this attempt whatever the configured mode says.
    ///
    /// D27's shape applied to labels, and deliberately **narrower** than
    /// [`FactsPolicy::is_forced_closed`]. Only [`Action::is_external_share`] is here: putting
    /// content outside the tenant is the one attempt whose consequence cannot be recalled, so
    /// doing it to a document nobody has classified is refused even by a tenant that configured
    /// [`Unlabelled::Assume`].
    ///
    /// What is deliberately *not* here is [`Action::exposes_content`]. Forcing every read of every
    /// unlabelled document closed is the "the product refuses everything, so the label gets
    /// disabled wholesale" failure this row was open about — a control nobody can leave switched on
    /// is a control nobody has.
    ///
    /// [`Action::alters_existing_share`] is absent for a different reason: it is only half a
    /// question, and its other half is the resource's [`Exposure`], which this type is not given.
    /// `FactsPolicy` pairs the two because the snapshot carries the exposure; nothing here does,
    /// and inventing an answer for the missing half is how a control starts firing on the wrong
    /// requests. It is `ENC-658`.
    #[must_use]
    pub fn is_forced_closed(&self, action: Action) -> bool {
        action.is_external_share()
    }
}

/// The evidence an allow taken on an *assumed* rank must leave behind.
///
/// `#[must_use]` for the reason [`UnscannedAllow`] is: an assumption without the audit event is an
/// ordinary allow that nobody can find afterwards, and the trail is the entire difference between
/// [`Unlabelled::Assume`] and having picked a default in the source. Dropping this value deletes
/// that difference.
#[must_use = "this rank was assumed, not read: without the audit event, an unlabelled resource was \
              treated as classified and nothing records that it was not"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssumedClassification {
    rank: ClassificationRank,
}

impl AssumedClassification {
    /// The rank the tenant's policy named.
    ///
    /// Note the return type: a bare [`ClassificationRank`] and never an
    /// [`EffectiveClassification`], because an assumed rank has no [`LabelSource`] and inventing
    /// one would make an assumption indistinguishable from a reading in the audit trail.
    #[must_use]
    pub const fn rank(&self) -> ClassificationRank {
        self.rank
    }
}

/// What a caller may do about one attempt, given the label the chain could resolve.
///
/// Three arms and no fourth, exactly as [`FactsOutcome`] has: there is no "carry on with a
/// reasonable number". The `match` is exhaustive at every call site, so a caller that gains a new
/// way to be unlabelled cannot silently take the allow path with a constant.
#[must_use = "a classification outcome decides whether the caller proceeds on a resolved rank, \
              refuses, or proceeds on an assumed rank and must audit"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationOutcome {
    /// A label was found on the resource or above it. Act on this rank.
    Labelled(EffectiveClassification),
    /// Nothing on the chain carries a label, and this attempt fails closed.
    Denied {
        /// The stable code the caller may be told.
        code: ReasonCode,
        /// What they can do about it.
        remediation: Remediation,
    },
    /// Nothing carries a label, and the tenant's policy names a rank to proceed on. Discharge the
    /// obligation.
    Assumed(AssumedClassification),
}

impl ClassificationOutcome {
    /// The denial, when this outcome is one.
    ///
    /// A convenience for a caller that translates straight into the chain's error type. The
    /// exhaustive `match` stays available and is what a caller with something to record wants.
    #[must_use]
    pub fn into_denial(self) -> Option<Error> {
        match self {
            Self::Denied { code, remediation } => Some(Error::denied_with(code, remediation)),
            Self::Labelled(_) | Self::Assumed(_) => None,
        }
    }
}

/// What the resolver read about a resource's classification, and the policy that says what an
/// absence means.
///
/// # Why the absence is a state and not a number
///
/// `ENC-574` sat open because *"both plausible defaults are wrong in opposite, undetectable
/// directions"*. The way out is the one M4 already took for `facts_unavailable`: stop choosing.
/// [`Self::unlabelled`] is a constructor, so "nothing on this chain carries a label" is a value the
/// type system carries from the query that discovered it to the caller that has to act on it, and
/// [`ClassificationOutcome`] is `#[must_use]` with no arm a caller can mistake for a rank.
///
/// # The two doors, and why there are two rather than one
///
/// [`Self::require`] is for a request: an [`Action`] is being attempted, so the mandatory
/// escalation in [`ClassificationPolicy::is_forced_closed`] applies. [`Self::require_for_indexing`]
/// is for the asynchronous pipeline, which is not a request and has no `Action` to escalate on —
/// nobody is attempting anything, a document is being embedded. Passing a borrowed `Action` there
/// to satisfy one signature would make the audit trail claim a user did something they did not.
///
/// Both delegate to one body, so the two doors cannot answer differently about the configured mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassificationResolution {
    effective: Option<EffectiveClassification>,
    policy: ClassificationPolicy,
}

impl ClassificationResolution {
    /// Records a label resolved from the resource's chain.
    #[must_use]
    pub const fn resolved(
        policy: ClassificationPolicy,
        effective: EffectiveClassification,
    ) -> Self {
        Self { effective: Some(effective), policy }
    }

    /// Records that nothing on the resource's chain carries a label.
    ///
    /// Not an error and not a rank. What it *means* is [`Self::policy`]'s to decide.
    #[must_use]
    pub const fn unlabelled(policy: ClassificationPolicy) -> Self {
        Self { effective: None, policy }
    }

    /// The label that was read, if one was.
    #[must_use]
    pub const fn effective(&self) -> Option<EffectiveClassification> {
        self.effective
    }

    /// The rank that was **read**, for [`ResourceState`] and the escalations that compare against
    /// it.
    ///
    /// Deliberately the read rank and never the assumed one. `ResourceState::new`'s contract is
    /// that `None` means the resource genuinely has no label; handing it an assumed rank would make
    /// `FactsPolicy::is_forced_closed` fire on a document whose `RESTRICTED`-ness this codebase
    /// inferred rather than read, which is the same untraceable substitution the whole of
    /// [`Unlabelled`] exists to prevent.
    #[must_use]
    pub fn rank(&self) -> Option<ClassificationRank> {
        self.effective.map(|effective| effective.rank())
    }

    /// The tenant policy this resolution was taken under.
    #[must_use]
    pub const fn policy(&self) -> ClassificationPolicy {
        self.policy
    }

    /// The label, or what the tenant's policy says to do without one, for an attempted action.
    pub fn require(&self, action: Action) -> ClassificationOutcome {
        self.decide(self.policy.is_forced_closed(action))
    }

    /// The label, or what the tenant's policy says to do without one, for the indexing pipeline.
    ///
    /// No mandatory escalation, and that is the argued half. Embedding an unlabelled document is
    /// not the unrecallable act external sharing is: the rank the tenant assumed is written into
    /// the collection *and* routes the provider, so a tenant that assumes a high rank gets
    /// local-only embedding rather than a leak. The escalation that matters on this path is the
    /// ceiling comparison `crates/embeddings` already enforces, and it works on an assumed rank
    /// exactly as it works on a read one.
    pub fn require_for_indexing(&self) -> ClassificationOutcome {
        self.decide(false)
    }

    /// The one body both doors use.
    fn decide(&self, forced: bool) -> ClassificationOutcome {
        if let Some(effective) = self.effective {
            return ClassificationOutcome::Labelled(effective);
        }

        match self.policy.on_unlabelled() {
            Unlabelled::Assume(rank) if !forced => {
                ClassificationOutcome::Assumed(AssumedClassification { rank })
            }
            // `CLASSIFICATION_CEILING` with `CONTACT_ADMINISTRATOR` rather than its default
            // `REQUEST_ACCESS`: the caller's access is not the problem and asking the owner for
            // more of it will not help. The resource has no label, and only an administrator can
            // give it one.
            Unlabelled::FailClosed | Unlabelled::Assume(_) => ClassificationOutcome::Denied {
                code: ReasonCode::ClassificationCeiling,
                remediation: Remediation::ContactAdministrator,
            },
        }
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

    // --- Security facts ------------------------------------------------------------------------
    //
    // A further compile-fail expectation, in the same shape as the ones above and blocked on the
    // same missing `trybuild` wiring. `FactsUnavailable` implements `Serialize` and not
    // `Deserialize`, which is what makes a per-request override unrepresentable rather than merely
    // undocumented (D27) — every route from the wire into a typed value in this codebase runs
    // through `serde`:
    //
    //     serde_json::from_str::<FactsUnavailable>("\"FAIL_OPEN_AUDIT\"")  // no `Deserialize`
    //     "FAIL_OPEN_AUDIT".parse::<FactsUnavailable>()                    // no `FromStr`
    //
    // Neither compiles today. The tests below cover what a runtime test *can* cover: that the
    // escalations hold for both configured modes, and that the mode is nonetheless load-bearing
    // where it is allowed to be.

    use crate::action::{FileAction, ShareAction};
    use crate::id::{FileId, VersionId};
    use chrono::TimeZone as _;

    const ACTIVE_SET: &str = "builtin/1";

    fn facts(set: &str) -> SecurityFacts {
        let mut counts = DetectorCounts::none();
        counts.add(DetectorCategory::Financial, 3);
        SecurityFacts::scanned(
            FileId::new_v7(),
            VersionId::new_v7(),
            counts,
            DetectorSetVersion::new(set),
            ScanVersion::new(4),
            Utc.timestamp_opt(1_800_000_000, 0).single().expect("a valid instant"),
        )
    }

    fn policy(mode: FactsUnavailable) -> FactsPolicy {
        FactsPolicy::from_tenant_config(mode, ClassificationRank::RESTRICTED)
    }

    const READ: Action = Action::File(FileAction::ContentRead);
    const EXTERNAL: Action = Action::File(FileAction::ShareExternal);

    /// An unclassified resource that reaches nowhere — the neutral case, so a test that is about
    /// something else does not accidentally assert the escalations as well.
    fn plain() -> ResourceState {
        ResourceState::new(Exposure::Internal, None)
    }

    /// An internal resource carrying a label.
    fn labelled(rank: ClassificationRank) -> ResourceState {
        ResourceState::new(Exposure::Internal, Some(rank))
    }

    #[test]
    fn facts_from_the_active_detector_set_are_the_ones_a_stage_gets() {
        let snapshot = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            policy(FactsUnavailable::FailClosed),
            plain(),
        );

        assert_eq!(snapshot.staleness(), FactsStaleness::Fresh);
        match snapshot.require(READ) {
            FactsOutcome::Facts(facts) => {
                assert_eq!(facts.counts().get(DetectorCategory::Financial), 3);
            }
            other => panic!("fresh facts must be handed over, got {other:?}"),
        }
    }

    #[test]
    fn facts_from_another_detector_set_are_unusable_however_the_versions_sort() {
        // Both directions, because the rule is equality and not an ordering: a set version that
        // sorts *above* the active one is no more evidence that the active rules ran than one that
        // sorts below it. A comparison written as `<` would let the second of these through.
        for other in ["builtin/0", "builtin/2", "", "custom/acme"] {
            let snapshot = FactsSnapshot::gathered(
                facts(other),
                &DetectorSetVersion::new(ACTIVE_SET),
                policy(FactsUnavailable::FailClosed),
                plain(),
            );
            assert_eq!(
                snapshot.staleness(),
                FactsStaleness::StaleDetectorSet,
                "{other:?} is not the active set and its facts are not usable"
            );
            assert!(
                matches!(snapshot.require(READ), FactsOutcome::Denied { .. }),
                "stale facts reached a decision for set {other:?}"
            );
        }

        // The control: the active version itself is usable, so the four refusals above are the
        // comparison working rather than `gathered` refusing everything.
        let snapshot = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            policy(FactsUnavailable::FailClosed),
            plain(),
        );
        assert!(matches!(snapshot.require(READ), FactsOutcome::Facts(_)));
    }

    /// D27, and the half of it that is not the tenant's to choose.
    ///
    /// `FAIL_CLOSED` is mandatory for `RESTRICTED` and for external sharing at *any*
    /// classification. The table is walked for **both** configured modes, because a rule that
    /// holds only under the mode that would have denied anyway is not a rule.
    #[test]
    fn restricted_content_and_external_sharing_fail_closed_in_either_mode() {
        let internal = ClassificationRank::new(20);

        for mode in [FactsUnavailable::FailClosed, FactsUnavailable::FailOpenAudit] {
            let restricted_doc =
                FactsSnapshot::missing(policy(mode), labelled(ClassificationRank::RESTRICTED));
            assert!(
                matches!(restricted_doc.require(READ), FactsOutcome::Denied { .. }),
                "RESTRICTED content was served without facts under {mode}"
            );

            let internal_doc = FactsSnapshot::missing(policy(mode), labelled(internal));
            assert!(
                matches!(internal_doc.require(EXTERNAL), FactsOutcome::Denied { .. }),
                "an INTERNAL file was shared externally without facts under {mode}"
            );

            let unlabelled = FactsSnapshot::missing(policy(mode), plain());
            assert!(
                matches!(unlabelled.require(EXTERNAL), FactsOutcome::Denied { .. }),
                "an unclassified file was shared externally without facts under {mode}"
            );
            assert!(
                matches!(
                    unlabelled.require(Action::Share(ShareAction::CreateExternal)),
                    FactsOutcome::Denied { .. }
                ),
                "an external share link was created without facts under {mode}"
            );
        }

        // The positive control, and the assertion that makes the four above mean something.
        // `docs/12 §1.2`: an assertion about a denial passes for free against a policy that denies
        // everything, and this whole test would then be proving nothing about the escalations.
        // `FAIL_OPEN_AUDIT` must genuinely fail open for an internal read.
        let snapshot =
            FactsSnapshot::missing(policy(FactsUnavailable::FailOpenAudit), labelled(internal));
        match snapshot.require(READ) {
            FactsOutcome::Unscanned(allow) => {
                assert_eq!(allow.action(), READ);
                assert_eq!(allow.staleness(), FactsStaleness::Missing);
            }
            other => panic!(
                "FAIL_OPEN_AUDIT denied an internal read, so the escalations above \
                             prove nothing: {other:?}"
            ),
        }
    }

    /// `ENC-588` — the escalation must reach a share that is *already* external.
    ///
    /// Creating an external link over unscanned content was always denied, because
    /// `Action::is_external_share` recognises the actions that create exposure. **Updating** one —
    /// dropping its password, widening its permission, pushing its expiry out — was not, because
    /// whether the share is external is a fact about the resource and `require` was never given
    /// one. Under `FAIL_OPEN_AUDIT` that made the weaker operation the permitted one.
    ///
    /// The two controls are what make this more than "everything is denied": the *same* update
    /// against an internal share still fails open, and revoking the external share still fails
    /// open — a tenant that cannot revoke a link over unscanned content is left holding the link.
    #[test]
    fn updating_a_share_that_is_already_external_fails_closed() {
        const UPDATE: Action = Action::Share(ShareAction::Update);
        const REVOKE: Action = Action::Share(ShareAction::Revoke);
        let internal = ClassificationRank::new(20);
        let open = policy(FactsUnavailable::FailOpenAudit);

        let external =
            FactsSnapshot::missing(open, ResourceState::new(Exposure::External, Some(internal)));
        assert!(
            matches!(external.require(UPDATE), FactsOutcome::Denied { .. }),
            "the password was dropped from an external link over content nobody has scanned"
        );
        let unlabelled_external =
            FactsSnapshot::missing(open, ResourceState::new(Exposure::External, None));
        assert!(
            matches!(unlabelled_external.require(UPDATE), FactsOutcome::Denied { .. }),
            "an unclassified file's external link was widened without facts"
        );

        // Control 1: the same action on an internal share is governed by the configured mode, so
        // the denial above is the *exposure* and not the action.
        let internal_share = FactsSnapshot::missing(open, labelled(internal));
        assert!(
            matches!(internal_share.require(UPDATE), FactsOutcome::Unscanned(_)),
            "an internal share update was denied, so the escalation above proves nothing"
        );

        // Control 2: revocation reduces exposure and must stay available, or a tenant cannot undo
        // the link it is being refused permission to change.
        assert!(
            matches!(external.require(REVOKE), FactsOutcome::Unscanned(_)),
            "revoking an external link over unscanned content was refused, which strands the link"
        );

        // Control 3: the mandatory half still holds — `FAIL_CLOSED` denies the internal update
        // too, so control 1 is the mode rather than the predicate.
        let closed =
            FactsSnapshot::missing(policy(FactsUnavailable::FailClosed), labelled(internal));
        assert!(matches!(closed.require(UPDATE), FactsOutcome::Denied { .. }));
    }

    /// `ENC-591` — the `RESTRICTED` escalation must fire on a document *no scan has run over*.
    ///
    /// That is the only case it exists for. The rank used to be an argument, the DLP stage was the
    /// only caller, and it had nothing to pass when the scan had not completed — so the escalation
    /// was asked about `None` precisely when it mattered. A label is a property of the resource
    /// and does not wait for a scanner.
    ///
    /// The control is the rank one below the boundary: it fails *open*, so the two denials are the
    /// comparison working rather than a snapshot that refuses everything unscanned.
    #[test]
    fn an_unscanned_restricted_document_fails_closed_without_the_scan_that_would_prove_it() {
        let open = policy(FactsUnavailable::FailOpenAudit);

        let restricted = FactsSnapshot::missing(open, labelled(ClassificationRank::RESTRICTED));
        assert!(
            matches!(restricted.require(READ), FactsOutcome::Denied { .. }),
            "an unscanned RESTRICTED document was read under FAIL_OPEN_AUDIT"
        );
        assert_eq!(restricted.resource().classification(), Some(ClassificationRank::RESTRICTED));

        let above = FactsSnapshot::missing(open, labelled(ClassificationRank::new(60)));
        assert!(matches!(above.require(READ), FactsOutcome::Denied { .. }));

        let below = FactsSnapshot::missing(open, labelled(ClassificationRank::new(49)));
        assert!(
            matches!(below.require(READ), FactsOutcome::Unscanned(_)),
            "a document below the boundary was denied, so the boundary is a blanket"
        );
    }

    /// The resource's state is settled where the facts are, so no stage can supply its own answer.
    #[test]
    fn resource_state_travels_with_the_snapshot_and_is_reported_for_audit() {
        let snapshot = FactsSnapshot::missing(
            policy(FactsUnavailable::FailOpenAudit),
            ResourceState::new(Exposure::External, Some(ClassificationRank::new(30))),
        );
        assert_eq!(snapshot.exposure(), Exposure::External);
        assert_eq!(snapshot.resource().classification(), Some(ClassificationRank::new(30)));
        assert_eq!(serde_json::to_string(&Exposure::External).expect("serialize"), "\"EXTERNAL\"");
        assert_eq!(serde_json::to_string(&Exposure::Internal).expect("serialize"), "\"INTERNAL\"");

        let gathered = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            FactsPolicy::fail_closed(),
            ResourceState::new(Exposure::External, None),
        );
        assert_eq!(gathered.exposure(), Exposure::External);
    }

    /// D29 — a path with no way to satisfy an obligation refuses, in *release* as well as debug.
    ///
    /// The positive control is the empty set: `require_none` must not simply refuse everything, or
    /// the three call sites it replaced would refuse every listing and every self-read.
    #[test]
    fn an_obligation_reaching_a_path_that_cannot_satisfy_it_is_a_denial() {
        assert!(Obligations::none().require_none().is_ok(), "an unconditional allow must proceed");

        for (obligation, expected) in [
            (Obligation::RequireJustification, ReasonCode::DlpJustificationRequired),
            (Obligation::RequireApproval, ReasonCode::DlpApprovalRequired),
            (Obligation::Watermark, ReasonCode::PreviewOnly),
            (Obligation::NoDownload, ReasonCode::PreviewOnly),
            (Obligation::ReadOnly, ReasonCode::AccessDenied),
            (Obligation::NoSync, ReasonCode::AccessDenied),
            (Obligation::Reclassify { to: ClassificationRank::new(40) }, ReasonCode::AccessDenied),
        ] {
            let set: Obligations = [obligation].into_iter().collect();
            let error = set.require_none().expect_err("an outstanding obligation must refuse");
            match error {
                Error::PolicyDenied { code, .. } => assert_eq!(
                    code, expected,
                    "{obligation:?} refused with the wrong code, so a client cannot offer the \
                     right next step"
                ),
                other => panic!("{obligation:?} produced {other:?} rather than a denial"),
            }
            assert_eq!(obligation.unsatisfied_code(), expected);
        }
    }

    #[test]
    fn the_configured_mode_decides_everything_the_escalations_do_not() {
        let internal = labelled(ClassificationRank::new(20));

        let closed = FactsSnapshot::missing(policy(FactsUnavailable::FailClosed), internal);
        assert!(matches!(closed.require(READ), FactsOutcome::Denied { .. }));

        let open = FactsSnapshot::missing(policy(FactsUnavailable::FailOpenAudit), internal);
        assert!(matches!(open.require(READ), FactsOutcome::Unscanned(_)));
    }

    #[test]
    fn a_rank_at_or_above_the_tenants_restricted_level_fails_closed() {
        // Ranks are tenant-defined, so the boundary is configured rather than the constant 50.
        let tenant = FactsPolicy::from_tenant_config(
            FactsUnavailable::FailOpenAudit,
            ClassificationRank::new(30),
        );
        let at = FactsSnapshot::missing(tenant, labelled(ClassificationRank::new(30)));
        assert!(matches!(at.require(READ), FactsOutcome::Denied { .. }));

        let above = FactsSnapshot::missing(tenant, labelled(ClassificationRank::new(40)));
        assert!(matches!(above.require(READ), FactsOutcome::Denied { .. }));

        // Below the line, the configured mode applies — the boundary is a boundary and not a
        // blanket.
        let below = FactsSnapshot::missing(tenant, labelled(ClassificationRank::new(29)));
        assert!(matches!(below.require(READ), FactsOutcome::Unscanned(_)));
    }

    #[test]
    fn a_fail_closed_denial_says_retry_rather_than_ask_for_an_exception() {
        let snapshot = FactsSnapshot::missing(FactsPolicy::fail_closed(), plain());
        let denial = snapshot.require(READ).into_denial().expect("fail-closed denies");

        match denial {
            Error::PolicyDenied { code, remediation } => {
                assert_eq!(code, ReasonCode::DlpBlocked);
                assert_eq!(
                    remediation,
                    Remediation::RetryLater,
                    "a scan in progress is transient; telling the caller to request an exception \
                     asks them to have a file excused from being scanned"
                );
            }
            other => panic!("a fail-closed outcome must be a policy denial, got {other:?}"),
        }

        // The control: the other two outcomes are not denials, so `into_denial` is reading the
        // variant rather than answering `Some` to everything.
        let open = FactsSnapshot::missing(policy(FactsUnavailable::FailOpenAudit), plain());
        assert!(open.require(READ).into_denial().is_none());
        let fresh = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            FactsPolicy::fail_closed(),
            plain(),
        );
        assert!(fresh.require(READ).into_denial().is_none());
    }

    #[test]
    fn the_default_facts_policy_denies() {
        assert_eq!(FactsUnavailable::default(), FactsUnavailable::FailClosed);
        let default = FactsPolicy::fail_closed();
        assert_eq!(default.on_unavailable(), FactsUnavailable::FailClosed);
        assert!(default.is_forced_closed(
            READ,
            Some(ClassificationRank::RESTRICTED),
            Exposure::Internal
        ));
        assert!(!default.is_forced_closed(
            READ,
            Some(ClassificationRank::new(20)),
            Exposure::Internal
        ));
    }

    #[test]
    fn detector_counts_saturate_rather_than_wrap() {
        let mut counts = DetectorCounts::none();
        counts.add(DetectorCategory::Pii, u32::MAX);
        counts.add(DetectorCategory::Pii, 10);
        assert_eq!(counts.get(DetectorCategory::Pii), u32::MAX, "a wrap would read as clean");
        counts.add(DetectorCategory::Secret, 5);
        assert_eq!(counts.total(), u32::MAX);
        assert!(!counts.is_empty());
    }

    #[test]
    fn counts_are_kept_per_category_and_not_pooled() {
        // A transposition between categories is the one interesting bug in a four-slot counter,
        // and it is invisible against a fixture where the numbers happen to be equal.
        let mut counts = DetectorCounts::none();
        counts.add(DetectorCategory::Pii, 1);
        counts.add(DetectorCategory::Secret, 2);
        counts.add(DetectorCategory::Financial, 3);
        counts.add(DetectorCategory::Health, 4);

        assert_eq!(counts.get(DetectorCategory::Pii), 1);
        assert_eq!(counts.get(DetectorCategory::Secret), 2);
        assert_eq!(counts.get(DetectorCategory::Financial), 3);
        assert_eq!(counts.get(DetectorCategory::Health), 4);
        assert_eq!(counts.total(), 10);
    }

    #[test]
    fn a_risk_score_is_clamped_rather_than_refused() {
        assert_eq!(RiskScore::new(255).get(), 100);
        assert_eq!(RiskScore::new(100).get(), 100);
        assert_eq!(RiskScore::new(37).get(), 37);
        assert_eq!(RiskScore::ZERO.get(), 0);
    }

    #[test]
    fn facts_round_trip_through_serde_under_the_column_names() {
        // `security_facts` is read back into this type, so the field names are part of the
        // contract with `docs/04 §12` rather than an internal detail.
        let facts = facts(ACTIVE_SET)
            .with_classification(ClassificationRank::new(30))
            .with_max_severity(Severity::High)
            .with_risk_score(RiskScore::new(80));

        let json = serde_json::to_string(&facts).expect("serialize");
        assert!(json.contains("\"financial_count\":3"), "column name drifted: {json}");
        assert!(json.contains("\"pii_count\":0"));

        let back: SecurityFacts = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(facts, back);
    }

    #[test]
    fn the_facts_unavailable_mode_serializes_to_the_documented_spelling() {
        // It is written into audit rows so an operator can see which policy was in force. The
        // strings are `docs/06 §12`'s.
        assert_eq!(
            serde_json::to_string(&FactsUnavailable::FailClosed).expect("serialize"),
            "\"FAIL_CLOSED\""
        );
        assert_eq!(
            serde_json::to_string(&FactsUnavailable::FailOpenAudit).expect("serialize"),
            "\"FAIL_OPEN_AUDIT\""
        );
    }

    #[test]
    fn external_sharing_is_recognised_on_both_of_the_actions_that_do_it() {
        // The escalation in `is_forced_closed` is only as good as this predicate. A variant
        // forgotten here is a sharing path that silently stops failing closed.
        assert!(Action::File(FileAction::ShareExternal).is_external_share());
        assert!(Action::Share(ShareAction::CreateExternal).is_external_share());
        assert!(!Action::File(FileAction::Share).is_external_share());
        assert!(!Action::Share(ShareAction::Create).is_external_share());
        assert!(!Action::File(FileAction::Download).is_external_share());
    }

    // --- Classification: unresolved is a state, and what it means is tenant policy --------------
    //
    // `Unlabelled` implements `Serialize` and neither `Deserialize` nor `FromStr`, for the reason
    // `FactsUnavailable` does. The compile-fail cases share that type's missing `trybuild` wiring
    // and would read:
    //
    //     serde_json::from_str::<Unlabelled>("\"FAIL_CLOSED\"")   // no `Deserialize`
    //     "FAIL_CLOSED".parse::<Unlabelled>()                     // no `FromStr`
    //
    // The second is the one worth naming: `Unlabelled::Assume` carries a **rank**, applied to
    // content the caller is about to act on, so it is the single most valuable field an attacker
    // could add to a request body.

    fn unlabelled(on_unlabelled: Unlabelled) -> ClassificationResolution {
        ClassificationResolution::unlabelled(ClassificationPolicy::from_tenant_config(
            on_unlabelled,
        ))
    }

    #[test]
    fn an_unlabelled_resource_refuses_rather_than_defaulting() {
        let outcome =
            unlabelled(Unlabelled::FailClosed).require(Action::File(FileAction::Download));

        match outcome {
            ClassificationOutcome::Denied { code, remediation } => {
                assert_eq!(code, ReasonCode::ClassificationCeiling);
                // Not `REQUEST_ACCESS`, which is the code's default: the caller's access is not the
                // problem and asking the owner for more of it will not help.
                assert_eq!(remediation, Remediation::ContactAdministrator);
            }
            other => panic!("FAIL_CLOSED must refuse an unlabelled resource, not {other:?}"),
        }
    }

    #[test]
    fn a_tenant_that_named_a_rank_gets_that_rank_and_an_obligation() {
        let rank = ClassificationRank::new(20);
        let outcome =
            unlabelled(Unlabelled::Assume(rank)).require(Action::File(FileAction::Preview));

        match outcome {
            ClassificationOutcome::Assumed(allow) => assert_eq!(allow.rank(), rank),
            other => panic!("a configured Assume must be honoured, not {other:?}"),
        }
    }

    /// D27's shape applied to labels: external sharing is refused whatever the tenant configured.
    ///
    /// The pairing is the point. The *same* policy permits a preview of the *same* unlabelled
    /// resource, so the refusal is the escalation rather than the policy refusing everything —
    /// which is the failure mode that gets a control switched off wholesale.
    #[test]
    fn an_external_share_of_an_unlabelled_resource_fails_closed_whatever_the_tenant_configured() {
        let resolution = unlabelled(Unlabelled::Assume(ClassificationRank::new(20)));

        assert!(
            matches!(
                resolution.require(Action::File(FileAction::Preview)),
                ClassificationOutcome::Assumed(_)
            ),
            "the control: the configured rank is honoured for an ordinary read"
        );

        for action in
            [Action::File(FileAction::ShareExternal), Action::Share(ShareAction::CreateExternal)]
        {
            assert!(
                resolution.require(action).into_denial().is_some(),
                "putting an unclassified document outside the tenant is the one attempt whose \
                 consequence cannot be recalled, so it is refused even under Assume: {action:?}"
            );
        }
    }

    /// Indexing has no `Action`, and therefore no mandatory escalation — argued, not overlooked.
    ///
    /// Embedding an unlabelled document is not the unrecallable act external sharing is: the
    /// assumed rank both routes the provider and is written into the collection, so a tenant that
    /// assumes a high rank gets local-only embedding rather than a leak.
    #[test]
    fn the_indexing_door_honours_assume_and_the_fail_closed_default_still_refuses() {
        let rank = ClassificationRank::new(40);
        match unlabelled(Unlabelled::Assume(rank)).require_for_indexing() {
            ClassificationOutcome::Assumed(allow) => assert_eq!(allow.rank(), rank),
            other => panic!("indexing must honour a configured rank, not {other:?}"),
        }

        assert!(
            unlabelled(Unlabelled::FailClosed).require_for_indexing().into_denial().is_some(),
            "the default is what every deployment has today — `UnclassifiedFiles` refuses — and \
             that behaviour is preserved rather than replaced"
        );
    }

    #[test]
    fn an_assumed_rank_is_never_reported_as_a_read_rank() {
        let resolution = unlabelled(Unlabelled::Assume(ClassificationRank::RESTRICTED));

        assert_eq!(
            resolution.rank(),
            None,
            "`ResourceState`'s contract is that None means the resource genuinely has no label. An \
             assumption laundered through it would make FactsPolicy::is_forced_closed fire on a \
             rank this codebase inferred rather than read"
        );
    }

    #[test]
    fn a_resolved_label_is_returned_whatever_the_unlabelled_policy_says() {
        let effective =
            EffectiveClassification::found(ClassificationRank::new(30), LabelSource::Ancestor);

        for mode in [Unlabelled::FailClosed, Unlabelled::Assume(ClassificationRank::new(10))] {
            let resolution = ClassificationResolution::resolved(
                ClassificationPolicy::from_tenant_config(mode),
                effective,
            );

            assert_eq!(resolution.rank(), Some(ClassificationRank::new(30)));
            assert_eq!(
                resolution.require(Action::File(FileAction::ShareExternal)),
                ClassificationOutcome::Labelled(effective),
                "the unlabelled policy decides nothing about a resource that has a label — not \
                 even for a forced-closed action"
            );
        }
    }

    #[test]
    fn the_unlabelled_mode_serializes_to_a_form_an_audit_row_can_carry() {
        assert_eq!(
            serde_json::to_string(&Unlabelled::FailClosed).expect("serialize"),
            "\"FAIL_CLOSED\""
        );
        // The rank is in the string because it is the whole of what the mode means: two tenants on
        // `Assume` with different ranks are running different policies, and an audit row that
        // recorded only `ASSUME_RANK` could not tell them apart.
        assert_eq!(
            serde_json::to_string(&Unlabelled::Assume(ClassificationRank::new(20)))
                .expect("serialize"),
            "\"ASSUME_RANK(20)\""
        );
    }

    #[test]
    fn a_label_source_serializes_to_the_place_an_administrator_would_go() {
        for (source, expected) in [
            (LabelSource::Resource, "\"RESOURCE\""),
            (LabelSource::Ancestor, "\"ANCESTOR\""),
            (LabelSource::Library, "\"LIBRARY\""),
            (LabelSource::Workspace, "\"WORKSPACE\""),
        ] {
            assert_eq!(serde_json::to_string(&source).expect("serialize"), expected);
        }
    }
}
