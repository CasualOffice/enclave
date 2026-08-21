//! The shape of a detector, and the linear scan that drives them.
//!
//! # Q16, and why there is nowhere to put a pattern
//!
//! `plans/M4-GOVERNANCE.md` Q16 is answered and binding: **structured detectors only, no regex on
//! the synchronous path.** A regex engine reading attacker-supplied content inside a request is a
//! denial-of-service surface with a long CVE history, and its failure mode is the bad one — one
//! crafted document stalls every write and arrives as *load* rather than as a refusal, which is far
//! harder to attribute during an incident than a control that says no.
//!
//! That decision is expressed here as an absence. A [`StructuredDetector`] receives a
//! [`Candidate`] and returns a [`Verdict`]; it declares a [`CandidateClass`], which is a closed
//! enumeration of character classes rather than an expression. There is no field, parameter or
//! associated type in this module that a pattern could occupy, and nothing anywhere assumes
//! capture groups. A tenant asking for a custom pattern — which is the first thing enterprise
//! buyers ask for — cannot be served by adding one here; the answer is a linear-time engine on the
//! *asynchronous* path, and keeping this API pattern-free is what forces that conversation to
//! happen rather than be quietly avoided.
//!
//! # The cost bound
//!
//! [`DetectorSet::scan`] is one pass per candidate class over the text, and there are two classes.
//! Work per candidate is bounded by [`MAX_CANDIDATE_LEN`], and a run longer than that is discarded
//! rather than examined — no structured identifier this crate knows is longer, and a megabyte-long
//! run of digits must not become a megabyte of per-detector work. There is no backtracking and
//! nothing quadratic: the runtime is a function of the document's length and nothing else, which
//! is the property `docs/06 §5`'s per-request budget needs and the property a regex cannot offer.
//!
//! # What leaves this module
//!
//! Counts. [`ScanReport`] carries how many instances each detector accepted, and no bytes at all.
//! The matched text exists only as a [`Candidate`] borrowed from the caller's buffer during the
//! scan, and [`Candidate`]'s [`std::fmt::Debug`] renders `<candidate withheld>` so it cannot reach
//! a log line by way of a format string (`CLAUDE.md` rule 10, following the precedent set by
//! `enclave_search::excerpt::Excerpt`).

use std::fmt;

use enclave_core::{DetectorCategory, DetectorCounts, DetectorSetVersion};

/// The longest candidate any structured detector here can accept.
///
/// The IBAN maximum is 34 characters and a payment card's is 19, so 64 is generous. It exists as a
/// *bound* rather than as a fit: a run of separator-joined digits can be as long as the document,
/// and offering that run to every detector is how a linear scan acquires a large constant. A run
/// that normalises longer than this is dropped without being validated.
pub const MAX_CANDIDATE_LEN: usize = 64;

/// A detector's stable machine name.
///
/// `&'static str` rather than `String`: detector identities are compiled in, they appear in
/// `security_facts.detector_results` and in policy rules that name a detector, and a detector whose
/// name could be built at run time is a detector a request could name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorId(&'static str);

impl DetectorId {
    /// Names a detector. `const` so an implementation can hold its id as an associated constant.
    #[must_use]
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// The name as written. Stable: it is persisted and rules match on it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DetectorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

/// How much a single acceptance is worth on its own (`docs/06 §8`).
///
/// Declared by the detector rather than computed per match, because a checksum either holds or it
/// does not — there is no per-instance gradation to compute. What varies is how much a *held*
/// checksum tells you, and that is a property of the identifier's structure: sixteen Luhn-valid
/// digits are strong evidence, whereas a nine-digit national identifier with a weak check digit is
/// evidence only in company.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Meaningful only alongside other signals — proximity, several instances, a matching label.
    Low,
    /// Meaningful in numbers.
    Medium,
    /// Meaningful alone. Where a strong checksum over a long identifier lands.
    High,
}

/// The character class a detector's candidates are cut from.
///
/// A closed set, and closed deliberately: this is the whole of what a detector may say about the
/// *shape* of what it wants, and it is the reason nothing here can express a pattern. Adding a
/// variant is a deliberate act with a review attached, not a configuration value.
///
/// # Both forms of a run are offered
///
/// An identifier appears in a document two ways — as one token (`GB82WEST12345698765432`,
/// `4111111111111111`) or printed in groups (`GB82 WEST 1234 5698 7654 32`,
/// `4111-1111-1111-1111`) — and a scanner that handles only one of them has a hole in exactly the
/// half of the corpus it was not tested against.
///
/// So a run is offered **joined** (separators removed), and, when it contained a separator, each
/// of its tokens is offered as well. The two are never the same string, so nothing is offered
/// twice: with no separator there is only the joined form, and with one the joined form is
/// strictly longer than every token.
///
/// The first draft absorbed separators and offered only the joined form. It found
/// `4111 1111 1111 1111` and *missed* `Remit to GB82WEST12345698765432 by Friday`, because a space
/// continues the run and the sentence normalised past the IBAN length — the common case failing
/// while the clever one worked. Both tests are below.
///
/// The residual is a double count, not a miss: a run whose joined form *and* one of whose tokens
/// are both independently valid is counted twice. It needs two valid checksums nested inside one
/// unbroken run, and it errs upward — a count that is too high denies more, which is the safe
/// direction for a control whose failure mode is being switched off for crying wolf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateClass {
    /// Runs of ASCII digits grouped by spaces and hyphens.
    DigitGroups,
    /// Runs of ASCII alphanumerics grouped by spaces.
    AlphanumericGroups,
}

impl CandidateClass {
    /// Every class, so the scanner can loop rather than enumerate.
    pub const ALL: [Self; 2] = [Self::DigitGroups, Self::AlphanumericGroups];

    /// Whether this character continues a run of this class.
    #[must_use]
    fn continues_run(self, character: char) -> bool {
        match self {
            Self::DigitGroups => character.is_ascii_digit() || matches!(character, ' ' | '-'),
            Self::AlphanumericGroups => character.is_ascii_alphanumeric() || character == ' ',
        }
    }

    /// Whether this character is decoration inside a run rather than part of the identifier.
    #[must_use]
    fn is_separator(self, character: char) -> bool {
        match self {
            Self::DigitGroups => matches!(character, ' ' | '-'),
            Self::AlphanumericGroups => character == ' ',
        }
    }
}

/// A run of characters offered to a detector.
///
/// This *is* document content, which is the only interesting thing about the type. It borrows from
/// the caller's buffer, so it cannot outlive the scan, and its [`std::fmt::Debug`] renders
/// `<candidate withheld>` — the same wording `enclave_search::excerpt::Excerpt` uses, so a
/// redacted value reads identically wherever it is met. `CLAUDE.md` rule 10 forbids DLP match
/// values in audit; a `#[derive(Debug)]` on some future type that holds one, or a
/// `tracing::debug!(?candidate)` added while chasing a false positive, are exactly how that rule
/// gets broken by accident, and the hand-written impl is what makes both harmless.
///
/// Reaching the text at all goes through [`Candidate::normalised`] or [`Candidate::raw`], which
/// are named so that a call to either is visible in review.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Candidate<'a> {
    raw: &'a str,
    normalised: &'a str,
}

impl<'a> Candidate<'a> {
    /// The run with its separators removed — what a checksum is computed over.
    #[must_use]
    pub const fn normalised(&self) -> &'a str {
        self.normalised
    }

    /// The run exactly as it appears in the document, separators included.
    ///
    /// For a detector whose structure includes its punctuation. Most want
    /// [`Candidate::normalised`].
    #[must_use]
    pub const fn raw(&self) -> &'a str {
        self.raw
    }
}

/// `CLAUDE.md` rule 10, on the type that *is* the match value.
///
/// Neither the raw run nor the normalised one is printed. The length is withheld too, for the
/// reason `enclave_search::excerpt` withholds its offsets: in a line whose body has been redacted,
/// the shape of the redacted thing gives back part of what the redaction removed — a sixteen-digit
/// candidate in a DLP log is a card number whether or not the digits are shown.
impl fmt::Debug for Candidate<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<candidate withheld>")
    }
}

/// What a detector concluded about one candidate.
///
/// Two arms, and there is no third carrying the matched text: a detector's output is a decision,
/// and the bytes stop here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// This candidate is an instance of what the detector detects.
    Match,
    /// It is not.
    NoMatch,
}

/// A detector validated by structure and checksum (Q16).
///
/// Implementations are pure and total: given the same candidate they return the same verdict, they
/// allocate nothing, and they cannot fail — a candidate that is not an instance is
/// [`Verdict::NoMatch`], never an error. That is what lets [`DetectorSet::scan`] have a cost bound
/// rather than a cost estimate.
pub trait StructuredDetector: Send + Sync + fmt::Debug {
    /// The stable name, persisted with the facts and named by rules.
    fn id(&self) -> DetectorId;

    /// Which of the four `security_facts` count columns instances land in.
    fn category(&self) -> DetectorCategory;

    /// What kind of run this detector wants to be shown.
    fn candidate_class(&self) -> CandidateClass;

    /// Whether this candidate is an instance. Structure and checksum only.
    fn validate(&self, candidate: &Candidate<'_>) -> Verdict;

    /// How much one acceptance is worth alone. Defaults to [`Confidence::High`], which is where a
    /// strong checksum over a long identifier belongs; a weaker detector overrides it downward.
    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    /// How many acceptances a document needs before this detector is considered to have fired
    /// (`docs/06 §8`).
    ///
    /// One by default. A detector raises it when a single instance is not evidence — one
    /// Luhn-valid number in a hundred pages of order references is noise, ninety of them is a
    /// cardholder database.
    fn min_matches(&self) -> u32 {
        1
    }
}

/// What one detector found in one document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectorFinding {
    id: DetectorId,
    category: DetectorCategory,
    confidence: Confidence,
    count: u32,
    min_matches: u32,
}

impl DetectorFinding {
    /// Which detector.
    #[must_use]
    pub const fn id(&self) -> DetectorId {
        self.id
    }

    /// Which count column instances belong to.
    #[must_use]
    pub const fn category(&self) -> DetectorCategory {
        self.category
    }

    /// How much one instance is worth alone.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// How many instances were accepted. Present even when the detector did not fire, because "two
    /// instances against a minimum of five" is the number that tells an administrator their
    /// threshold is in the wrong place.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Whether the count reached the detector's minimum.
    #[must_use]
    pub const fn is_triggered(&self) -> bool {
        self.count >= self.min_matches && self.count > 0
    }
}

/// What a scan concluded, per detector.
///
/// Counts only. See the [module documentation](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    findings: Vec<DetectorFinding>,
}

impl ScanReport {
    /// Every detector in the set, including the ones that found nothing.
    ///
    /// A detector that found nothing is a fact: it says the set was asked and declined, which is
    /// what distinguishes "no card numbers" from "no card detector was configured".
    #[must_use]
    pub fn findings(&self) -> &[DetectorFinding] {
        &self.findings
    }

    /// The detectors that reached their minimum match count.
    pub fn triggered(&self) -> impl Iterator<Item = &DetectorFinding> + '_ {
        self.findings.iter().filter(|finding| finding.is_triggered())
    }

    /// The per-category counts that go into [`enclave_core::SecurityFacts`].
    ///
    /// Only triggered detectors contribute. A detector that declared a minimum of five and
    /// accepted two has *not* found what it detects, and letting those two through into
    /// `pii_count` would put the minimum-match threshold in the report and out of the number every
    /// policy actually reads.
    #[must_use]
    pub fn counts(&self) -> DetectorCounts {
        let mut counts = DetectorCounts::none();
        for finding in self.triggered() {
            counts.add(finding.category, finding.count);
        }
        counts
    }
}

/// The detectors a deployment runs, and the version that names them.
///
/// The version is the string written to `security_facts.detector_set_version` and compared for
/// equality when facts are read back (`enclave_core::DetectorSetVersion`). It is carried by the set
/// rather than by the caller so that the thing that produced a fact row and the thing that stamps
/// it cannot disagree.
#[derive(Debug)]
pub struct DetectorSet {
    version: DetectorSetVersion,
    detectors: Vec<Box<dyn StructuredDetector>>,
}

impl DetectorSet {
    /// Assembles a set under a version.
    #[must_use]
    pub fn new(version: DetectorSetVersion, detectors: Vec<Box<dyn StructuredDetector>>) -> Self {
        Self { version, detectors }
    }

    /// The version stamped onto facts this set produces.
    #[must_use]
    pub const fn version(&self) -> &DetectorSetVersion {
        &self.version
    }

    /// The detectors in the set, in order.
    pub fn ids(&self) -> impl Iterator<Item = DetectorId> + '_ {
        self.detectors.iter().map(|detector| detector.id())
    }

    /// Runs every detector over `text` in one pass per candidate class.
    ///
    /// See the [module documentation](self) for the cost bound this keeps and why it matters.
    #[must_use]
    pub fn scan(&self, text: &str) -> ScanReport {
        let mut counts = vec![0_u32; self.detectors.len()];

        for class in CandidateClass::ALL {
            let members: Vec<usize> = self
                .detectors
                .iter()
                .enumerate()
                .filter(|(_, detector)| detector.candidate_class() == class)
                .map(|(index, _)| index)
                .collect();

            if members.is_empty() {
                continue;
            }

            for_each_candidate(text, class, |candidate| {
                for &index in &members {
                    if self.detectors[index].validate(&candidate) == Verdict::Match {
                        counts[index] = counts[index].saturating_add(1);
                    }
                }
            });
        }

        ScanReport {
            findings: self
                .detectors
                .iter()
                .zip(counts)
                .map(|(detector, count)| DetectorFinding {
                    id: detector.id(),
                    category: detector.category(),
                    confidence: detector.confidence(),
                    count,
                    min_matches: detector.min_matches(),
                })
                .collect(),
        }
    }
}

/// Cuts `text` into maximal runs of `class` and offers each to `visit`.
///
/// One pass, one reused normalisation buffer, and a hard length cut. Separate from
/// [`DetectorSet::scan`] so that the tokenisation — the only part with an index in it — can be
/// tested on its own.
fn for_each_candidate(text: &str, class: CandidateClass, mut visit: impl FnMut(Candidate<'_>)) {
    let mut buffer = String::with_capacity(MAX_CANDIDATE_LEN);
    let mut start: Option<usize> = None;

    for (offset, character) in text.char_indices() {
        if class.continues_run(character) {
            if start.is_none() {
                start = Some(offset);
            }
        } else if let Some(begin) = start.take() {
            offer(&text[begin..offset], class, &mut buffer, &mut visit);
        }
    }

    if let Some(begin) = start {
        offer(&text[begin..], class, &mut buffer, &mut visit);
    }
}

/// Offers one run in both of the forms an identifier is printed in.
///
/// The joined form first, then — only if the run actually carried a separator — its tokens. See
/// [`CandidateClass`] for why both, and why that cannot offer the same string twice.
fn offer(
    run: &str,
    class: CandidateClass,
    buffer: &mut String,
    visit: &mut impl FnMut(Candidate<'_>),
) {
    let run = run.trim_matches(|character| class.is_separator(character));
    if run.is_empty() {
        return;
    }

    if join_into(run, class, buffer) {
        visit(Candidate { raw: run, normalised: buffer });
    }

    if !run.chars().any(|character| class.is_separator(character)) {
        return;
    }

    for token in run.split(|character| class.is_separator(character)) {
        // A token carries no separators, so it is already its own normalised form.
        if !token.is_empty() && token.len() <= MAX_CANDIDATE_LEN {
            visit(Candidate { raw: token, normalised: token });
        }
    }
}

/// Writes `run` into `buffer` with its separators removed.
///
/// Returns `false` when the result would exceed [`MAX_CANDIDATE_LEN`] — longer than anything this
/// crate detects. The run is dropped rather than truncated: a truncated run is a *different*
/// string, and validating it would answer a question about content that is not in the document.
fn join_into(run: &str, class: CandidateClass, buffer: &mut String) -> bool {
    buffer.clear();
    for character in run.chars() {
        if class.is_separator(character) {
            continue;
        }
        if buffer.len() == MAX_CANDIDATE_LEN {
            return false;
        }
        buffer.push(character);
    }
    true
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Collects the normalised candidates a class cuts out of a string.
    ///
    /// Only a test may do this — it copies content out of a [`Candidate`], which is precisely what
    /// production code must not do.
    fn candidates(text: &str, class: CandidateClass) -> Vec<String> {
        let mut seen = Vec::new();
        for_each_candidate(text, class, |candidate| seen.push(candidate.normalised().to_owned()));
        seen
    }

    #[test]
    fn a_grouped_run_is_offered_joined_as_well_as_in_pieces() {
        assert_eq!(
            candidates("card 4111 1111 1111 1111 on file", CandidateClass::DigitGroups),
            vec!["4111111111111111", "4111", "1111", "1111", "1111"],
            "the joined form is what a grouped card number is; the tokens come with it"
        );
        assert_eq!(
            candidates("4111-1111-1111-1111", CandidateClass::DigitGroups),
            vec!["4111111111111111", "4111", "1111", "1111", "1111"]
        );
    }

    #[test]
    fn an_unseparated_run_is_offered_exactly_once() {
        // Otherwise the joined form and the single token are the same string, and every count is
        // double what the document contains.
        assert_eq!(
            candidates("4111111111111111", CandidateClass::DigitGroups),
            vec!["4111111111111111"]
        );
        assert_eq!(
            candidates("GB82WEST12345698765432", CandidateClass::AlphanumericGroups),
            vec!["GB82WEST12345698765432"]
        );
    }

    #[test]
    fn a_token_survives_a_run_whose_joined_form_is_too_long() {
        // The case the first draft of this module got wrong. A space continues an alphanumeric
        // run, so an identifier inside a sentence joins to the whole sentence — past every
        // detector's length, and past this module's bound once the sentence is long enough. The
        // tokens are what is left, and offering only the joined form meant an IBAN in prose was
        // never found.
        let sentence = "Remit to GB82WEST12345698765432 by Friday";
        let offered = candidates(sentence, CandidateClass::AlphanumericGroups);
        assert!(
            offered.contains(&"GB82WEST12345698765432".to_owned()),
            "the identifier was lost with its sentence: {offered:?}"
        );

        // And with the sentence long enough to pass the bound, so the joined form is not merely
        // useless but absent — the token is then the only thing that could carry the match.
        let padded = format!("{sentence} {}", "and thanks for your patience with all of this");
        let offered = candidates(&padded, CandidateClass::AlphanumericGroups);
        assert!(
            !offered.iter().any(|candidate| candidate.starts_with("Remitto")),
            "the joined form is past the bound and must have been dropped: {offered:?}"
        );
        assert!(
            offered.contains(&"GB82WEST12345698765432".to_owned()),
            "the identifier was lost with its sentence: {offered:?}"
        );
    }

    #[test]
    fn a_run_is_trimmed_of_leading_and_trailing_separators() {
        // The hyphen in "invoice-4111..." starts the run under `continues_run`; if it survived
        // normalisation nothing would change, but a run that is *only* separators must not become
        // an empty candidate that every detector then has to defend against.
        assert_eq!(candidates("a - b", CandidateClass::DigitGroups), Vec::<String>::new());
        assert_eq!(candidates("   ", CandidateClass::AlphanumericGroups), Vec::<String>::new());
        // The control: a run with content in it does survive, so the two emptinesses above are not
        // the tokeniser declining to emit anything at all.
        assert_eq!(candidates("a - 7 b", CandidateClass::DigitGroups), vec!["7"]);
    }

    #[test]
    fn a_run_longer_than_the_bound_is_dropped_rather_than_truncated() {
        let long = "9".repeat(MAX_CANDIDATE_LEN + 1);
        assert!(
            candidates(&long, CandidateClass::DigitGroups).is_empty(),
            "an over-long run must not be offered at all"
        );
        // The control: one character shorter is offered whole. Without it, "is_empty" above would
        // pass against a tokeniser that emits nothing ever.
        let at_bound = "9".repeat(MAX_CANDIDATE_LEN);
        assert_eq!(candidates(&at_bound, CandidateClass::DigitGroups), vec![at_bound.clone()]);
    }

    #[test]
    fn a_run_at_the_end_of_the_text_is_not_lost() {
        // The classic off-by-one in a tokeniser written as a loop: the final run has no
        // terminating character to close it.
        assert_eq!(candidates("balance 4111", CandidateClass::DigitGroups), vec!["4111"]);
    }

    #[test]
    fn runs_are_cut_on_a_character_boundary_not_a_byte_boundary() {
        // Slicing by byte index into a multi-byte character panics. The document is user content,
        // so this is reachable from an upload rather than from a fixture.
        assert_eq!(candidates("Größe 4111 mm", CandidateClass::DigitGroups), vec!["4111"]);
        assert_eq!(candidates("→4111←", CandidateClass::DigitGroups), vec!["4111"]);
    }

    /// `CLAUDE.md` rule 10, at the type that holds the match value.
    ///
    /// Following `enclave_search::excerpt`'s precedent, down to the wording, so a redacted value
    /// reads the same wherever it is met.
    #[test]
    fn a_candidates_debug_carries_neither_the_match_nor_its_length() {
        let pan = "4111111111111111";
        let length = pan.len().to_string();

        let mut redacted = String::new();
        let mut option_form = String::new();
        for_each_candidate(pan, CandidateClass::DigitGroups, |candidate| {
            redacted = format!("{candidate:?}");
            option_form = format!("{:?}", Some(candidate));
        });

        assert_eq!(redacted, "<candidate withheld>");
        assert!(!redacted.contains(pan), "the match value reached a format string: {redacted}");
        assert!(!redacted.contains("4111"), "a prefix of it did: {redacted}");
        assert!(!redacted.contains(&length), "its length did: {redacted}");

        // The positive controls. `docs/12 §1.2`: an assertion about an absence passes for free —
        // all three above hold against a `Debug` that prints nothing, against a tokeniser that
        // offered no candidate, and against needles that could never have been found anyway.
        //
        // First: the needles are findable in a rendering that does not redact, so a miss above is
        // the redaction working rather than the search being wrong.
        let unredacted = format!("Candidate({pan}, {length} chars)");
        assert!(unredacted.contains(pan));
        assert!(unredacted.contains("4111"));
        assert!(unredacted.contains(&length));

        // Second: a candidate *was* produced, and the `Option` form still distinguishes present
        // from absent — a `Debug` that wrote nothing at all would fail this.
        assert_eq!(option_form, "Some(<candidate withheld>)");
        assert_eq!(format!("{:?}", Option::<Candidate<'_>>::None), "None");
    }
}
