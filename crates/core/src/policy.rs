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
    #[must_use]
    pub fn is_forced_closed(&self, action: Action, rank: Option<ClassificationRank>) -> bool {
        action.is_external_share() || rank.is_some_and(|r| r >= self.restricted_at)
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
}

impl FactsSnapshot {
    /// Records facts read at the start of a request, against the detector set active now.
    #[must_use]
    pub fn gathered(
        facts: SecurityFacts,
        active_set: &DetectorSetVersion,
        policy: FactsPolicy,
    ) -> Self {
        let staleness = if facts.detector_set() == active_set {
            FactsStaleness::Fresh
        } else {
            FactsStaleness::StaleDetectorSet
        };
        Self { facts: Some(facts), staleness, policy }
    }

    /// Records that the resource has no facts — unscanned, or a scan still running.
    #[must_use]
    pub const fn missing(policy: FactsPolicy) -> Self {
        Self { facts: None, staleness: FactsStaleness::Missing, policy }
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

    /// The facts, or what the tenant's policy says to do without them.
    ///
    /// `action` and `rank` are properties of the attempt, not choices about how to treat it: there
    /// is no parameter here through which a caller could ask for a different failure mode. See
    /// [`FactsUnavailable`].
    pub fn require(&self, action: Action, rank: Option<ClassificationRank>) -> FactsOutcome<'_> {
        if let Some(facts) = self.facts.as_ref().filter(|_| self.staleness.is_usable()) {
            return FactsOutcome::Facts(facts);
        }

        let fail_closed = self.policy.is_forced_closed(action, rank)
            || self.policy.on_unavailable() == FactsUnavailable::FailClosed;

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

    #[test]
    fn facts_from_the_active_detector_set_are_the_ones_a_stage_gets() {
        let snapshot = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            policy(FactsUnavailable::FailClosed),
        );

        assert_eq!(snapshot.staleness(), FactsStaleness::Fresh);
        match snapshot.require(READ, None) {
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
            );
            assert_eq!(
                snapshot.staleness(),
                FactsStaleness::StaleDetectorSet,
                "{other:?} is not the active set and its facts are not usable"
            );
            assert!(
                matches!(snapshot.require(READ, None), FactsOutcome::Denied { .. }),
                "stale facts reached a decision for set {other:?}"
            );
        }

        // The control: the active version itself is usable, so the four refusals above are the
        // comparison working rather than `gathered` refusing everything.
        let snapshot = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            policy(FactsUnavailable::FailClosed),
        );
        assert!(matches!(snapshot.require(READ, None), FactsOutcome::Facts(_)));
    }

    /// D27, and the half of it that is not the tenant's to choose.
    ///
    /// `FAIL_CLOSED` is mandatory for `RESTRICTED` and for external sharing at *any*
    /// classification. The table is walked for **both** configured modes, because a rule that
    /// holds only under the mode that would have denied anyway is not a rule.
    #[test]
    fn restricted_content_and_external_sharing_fail_closed_in_either_mode() {
        let restricted = Some(ClassificationRank::RESTRICTED);
        let internal = Some(ClassificationRank::new(20));

        for mode in [FactsUnavailable::FailClosed, FactsUnavailable::FailOpenAudit] {
            let snapshot = FactsSnapshot::missing(policy(mode));

            assert!(
                matches!(snapshot.require(READ, restricted), FactsOutcome::Denied { .. }),
                "RESTRICTED content was served without facts under {mode}"
            );
            assert!(
                matches!(snapshot.require(EXTERNAL, internal), FactsOutcome::Denied { .. }),
                "an INTERNAL file was shared externally without facts under {mode}"
            );
            assert!(
                matches!(snapshot.require(EXTERNAL, None), FactsOutcome::Denied { .. }),
                "an unclassified file was shared externally without facts under {mode}"
            );
            assert!(
                matches!(
                    snapshot.require(Action::Share(ShareAction::CreateExternal), None),
                    FactsOutcome::Denied { .. }
                ),
                "an external share link was created without facts under {mode}"
            );
        }

        // The positive control, and the assertion that makes the four above mean something.
        // `docs/12 §1.2`: an assertion about a denial passes for free against a policy that denies
        // everything, and this whole test would then be proving nothing about the escalations.
        // `FAIL_OPEN_AUDIT` must genuinely fail open for an internal read.
        let snapshot = FactsSnapshot::missing(policy(FactsUnavailable::FailOpenAudit));
        match snapshot.require(READ, internal) {
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

    #[test]
    fn the_configured_mode_decides_everything_the_escalations_do_not() {
        let internal = Some(ClassificationRank::new(20));

        let closed = FactsSnapshot::missing(policy(FactsUnavailable::FailClosed));
        assert!(matches!(closed.require(READ, internal), FactsOutcome::Denied { .. }));

        let open = FactsSnapshot::missing(policy(FactsUnavailable::FailOpenAudit));
        assert!(matches!(open.require(READ, internal), FactsOutcome::Unscanned(_)));
    }

    #[test]
    fn a_rank_at_or_above_the_tenants_restricted_level_fails_closed() {
        // Ranks are tenant-defined, so the boundary is configured rather than the constant 50.
        let tenant = FactsPolicy::from_tenant_config(
            FactsUnavailable::FailOpenAudit,
            ClassificationRank::new(30),
        );
        let snapshot = FactsSnapshot::missing(tenant);

        assert!(matches!(
            snapshot.require(READ, Some(ClassificationRank::new(30))),
            FactsOutcome::Denied { .. }
        ));
        assert!(matches!(
            snapshot.require(READ, Some(ClassificationRank::new(40))),
            FactsOutcome::Denied { .. }
        ));
        // Below the line, the configured mode applies — the boundary is a boundary and not a
        // blanket.
        assert!(matches!(
            snapshot.require(READ, Some(ClassificationRank::new(29))),
            FactsOutcome::Unscanned(_)
        ));
    }

    #[test]
    fn a_fail_closed_denial_says_retry_rather_than_ask_for_an_exception() {
        let snapshot = FactsSnapshot::missing(FactsPolicy::fail_closed());
        let denial = snapshot.require(READ, None).into_denial().expect("fail-closed denies");

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
        let open = FactsSnapshot::missing(policy(FactsUnavailable::FailOpenAudit));
        assert!(open.require(READ, None).into_denial().is_none());
        let fresh = FactsSnapshot::gathered(
            facts(ACTIVE_SET),
            &DetectorSetVersion::new(ACTIVE_SET),
            FactsPolicy::fail_closed(),
        );
        assert!(fresh.require(READ, None).into_denial().is_none());
    }

    #[test]
    fn the_default_facts_policy_denies() {
        assert_eq!(FactsUnavailable::default(), FactsUnavailable::FailClosed);
        let default = FactsPolicy::fail_closed();
        assert_eq!(default.on_unavailable(), FactsUnavailable::FailClosed);
        assert!(default.is_forced_closed(READ, Some(ClassificationRank::RESTRICTED)));
        assert!(!default.is_forced_closed(READ, Some(ClassificationRank::new(20))));
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
}
