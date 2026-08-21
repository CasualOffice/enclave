//! The detectors a deployment gets without configuring anything.
//!
//! Two, both financial, both validated by a published check algorithm. They are here to prove the
//! [shape](crate::detector) rather than to be a complete detector library: `docs/06 §8` lists a
//! dozen more, and each is its own piece of work with its own check algorithm and its own
//! false-positive argument. What they demonstrate is that the shape carries a real detector — a
//! candidate class, a structural test, a checksum, a category, and no pattern anywhere.
//!
//! # What is deliberately not here yet
//!
//! **API-key shapes**, which `plans/M4-GOVERNANCE.md` Q16 names alongside these two. They are the
//! one family in that list with no checksum: an API key is recognised by its issuer's prefix and
//! its length, which is a *pattern* however it is spelled, and building one inside a module whose
//! whole argument is "there is nowhere to put a pattern" needs its own decision rather than a
//! quiet precedent. There is a practical reason to be careful too: a realistic test vector for one
//! is a string the repository's own secrets gate refuses, and a detector whose tests cannot be
//! written honestly is a detector that gets tested dishonestly.
//!
//! **National identifiers**, because each is a different check over a different structure and
//! several (India's Aadhaar, for instance) are legally sensitive to hold test vectors for.

use enclave_core::{DetectorCategory, DetectorSetVersion};

use crate::checksum::{luhn_valid, mod97};
use crate::detector::{
    Candidate, CandidateClass, DetectorId, DetectorSet, StructuredDetector, Verdict,
};

/// The version stamped on facts the built-in set produces.
///
/// Bumping it invalidates every fact row: `enclave_core::DetectorSetVersion` compares for equality,
/// so facts produced by the previous set stop being usable the moment this string moves, and the
/// tenant's `facts_unavailable` policy takes over until a rescan catches up. That is the intended
/// behaviour and the reason the string is a constant here rather than a value assembled at start-up
/// — a set version that could drift from the set is a cache serving answers the current rules never
/// gave.
pub const BUILTIN_SET_VERSION: &str = "builtin/1";

/// The built-in detectors, under [`BUILTIN_SET_VERSION`].
#[must_use]
pub fn builtin_set() -> DetectorSet {
    DetectorSet::new(
        DetectorSetVersion::new(BUILTIN_SET_VERSION),
        vec![Box::new(PaymentCardNumber), Box::new(Iban)],
    )
}

/// A payment card number: 12 to 19 digits with a valid Luhn check digit.
///
/// The length range is the primary account number's, from ISO/IEC 7812-1 — not a list of issuer
/// prefixes. Prefix tables are a pattern by another name, they go stale as issuer identification
/// numbers are allocated, and the failure when they do is silent under-detection: a real card
/// number from a new range stops being found, and nothing says so.
#[derive(Debug, Clone, Copy, Default)]
pub struct PaymentCardNumber;

impl PaymentCardNumber {
    /// The detector's stable name.
    pub const ID: DetectorId = DetectorId::new("payment_card_number");

    /// ISO/IEC 7812-1 primary account number lengths.
    const LENGTHS: std::ops::RangeInclusive<usize> = 12..=19;
}

impl StructuredDetector for PaymentCardNumber {
    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::Financial
    }

    fn candidate_class(&self) -> CandidateClass {
        CandidateClass::DigitGroups
    }

    fn validate(&self, candidate: &Candidate<'_>) -> Verdict {
        let digits = candidate.normalised();
        if !Self::LENGTHS.contains(&digits.len()) {
            return Verdict::NoMatch;
        }
        if luhn_valid(digits) {
            Verdict::Match
        } else {
            Verdict::NoMatch
        }
    }
}

/// An IBAN: ISO 13616 structure with a valid ISO 7064 MOD 97-10 check.
///
/// Structure checked here, checksum in [`crate::checksum::mod97`]: 15 to 34 alphanumerics, the
/// first two a country code, the next two the check digits.
///
/// # The per-country length table is deliberately absent
///
/// ISO 13616 fixes a length per country — 22 for `GB`, 27 for `FR` — and checking it would remove
/// the small number of false positives that satisfy mod-97 at the wrong length. It is not here
/// because the table is ninety-odd rows that change when a country joins the scheme, and a stale
/// row fails in the direction that matters: a *valid* IBAN from a country whose entry is missing or
/// out of date is silently not detected. The checksum already rejects roughly ninety-six of every
/// hundred arbitrary strings of the right shape, and a false positive costs an administrator a
/// second look while a false negative costs the control.
#[derive(Debug, Clone, Copy, Default)]
pub struct Iban;

impl Iban {
    /// The detector's stable name.
    pub const ID: DetectorId = DetectorId::new("iban");

    /// ISO 13616 IBAN lengths, across every country in the scheme.
    const LENGTHS: std::ops::RangeInclusive<usize> = 15..=34;
}

impl StructuredDetector for Iban {
    fn id(&self) -> DetectorId {
        Self::ID
    }

    fn category(&self) -> DetectorCategory {
        DetectorCategory::Financial
    }

    fn candidate_class(&self) -> CandidateClass {
        CandidateClass::AlphanumericGroups
    }

    fn validate(&self, candidate: &Candidate<'_>) -> Verdict {
        let text = candidate.normalised();
        if !Self::LENGTHS.contains(&text.len()) {
            return Verdict::NoMatch;
        }

        // `normalised()` is ASCII alphanumeric by construction (`CandidateClass`), so a byte index
        // is a character index here and `split_at` cannot fall inside a character.
        let bytes = text.as_bytes();
        let structural = bytes[0].is_ascii_alphabetic()
            && bytes[1].is_ascii_alphabetic()
            && bytes[2].is_ascii_digit()
            && bytes[3].is_ascii_digit();
        if !structural {
            return Verdict::NoMatch;
        }

        // ISO 13616: move the country code and check digits to the end, then reduce modulo 97.
        // Chained slices rather than an allocated copy — see `checksum::mod97`.
        let (head, rest) = bytes.split_at(4);
        let remainder = mod97(rest.iter().copied().chain(head.iter().copied()));

        if remainder == Some(1) {
            Verdict::Match
        } else {
            Verdict::NoMatch
        }
    }
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;
    use enclave_core::DetectorCounts;

    /// The set's membership is pinned to [`BUILTIN_SET_VERSION`].
    ///
    /// The same guard `ENC-168` put on the rendition cache's generator string, for the same
    /// reason. `enclave_core::DetectorSetVersion` compares for equality and a fact row carries the
    /// version that produced it — so adding a detector without moving the version leaves every
    /// stored fact row claiming to have been produced by a set that no longer exists, and it
    /// claims it *successfully*: the counts read as current while a whole detector's findings are
    /// missing from them. Nothing else in the system can notice.
    ///
    /// If this fails because you added a detector, that is the test working. Bump the version.
    #[test]
    fn the_builtin_sets_membership_is_pinned_to_its_version() {
        let set = builtin_set();
        let ids: Vec<&str> = set.ids().map(DetectorId::as_str).collect();

        assert_eq!(
            ids,
            vec!["payment_card_number", "iban"],
            "the built-in set has changed but {BUILTIN_SET_VERSION} has not; stored facts would \
             read as current while missing a detector's findings"
        );
        assert_eq!(set.version().as_str(), BUILTIN_SET_VERSION);
    }

    #[test]
    fn a_card_number_in_prose_is_found_however_it_is_printed() {
        let set = builtin_set();
        for document in [
            "Please charge 4111111111111111 for the balance.",
            "Please charge 4111 1111 1111 1111 for the balance.",
            "Please charge 4111-1111-1111-1111 for the balance.",
            "card=378282246310005;expiry=12/29",
        ] {
            let counts = set.scan(document).counts();
            assert_eq!(
                counts.get(DetectorCategory::Financial),
                1,
                "a card number was not found in: {document}"
            );
        }
    }

    #[test]
    fn a_digit_run_that_is_not_a_card_number_is_not_counted() {
        let set = builtin_set();
        for document in [
            "Order reference 4111111111111112 shipped.", // right length, wrong check digit
            "Invoice 20260822 dated today.",             // too short
            "Serial 11111111111111111111111.",           // too long
            "Meeting at 14:30 in room 4111.",
        ] {
            assert!(
                set.scan(document).counts().is_empty(),
                "a false positive was counted in: {document}"
            );
        }

        // The control: the identical sentence carrying a *valid* number is counted, so the four
        // emptinesses above are the checksum working rather than the scan never firing.
        let counts = set.scan("Order reference 4111111111111111 shipped.").counts();
        assert_eq!(counts.get(DetectorCategory::Financial), 1);
    }

    #[test]
    fn an_iban_is_found_in_the_forms_a_document_uses() {
        let set = builtin_set();
        for document in [
            "Remit to GB82WEST12345698765432 by Friday.",
            "IBAN: GB82 WEST 1234 5698 7654 32\nBIC: WESTGB2L",
            "iban=FR1420041010050500013M02606",
        ] {
            let counts = set.scan(document).counts();
            assert_eq!(
                counts.get(DetectorCategory::Financial),
                1,
                "an IBAN was not found in: {document:?}"
            );
        }
    }

    #[test]
    fn an_alphanumeric_run_that_is_not_an_iban_is_not_counted() {
        let set = builtin_set();
        for document in [
            "Remit to GB82WEST12345698765433 by Friday.", // wrong check digits
            "Reference WEST12345698765432 attached.",     // no country code
            "Token GB82WEST123 is short.",
        ] {
            assert!(
                set.scan(document).counts().is_empty(),
                "a false positive was counted in: {document}"
            );
        }

        // The control, as above.
        let counts = set.scan("Remit to GB82WEST12345698765432 by Friday.").counts();
        assert_eq!(counts.get(DetectorCategory::Financial), 1);
    }

    #[test]
    fn every_instance_is_counted_not_merely_the_first() {
        // A count is what a policy threshold reads ("more than fifty card numbers"), so a scanner
        // that stops at the first match satisfies every is-it-there test and answers every
        // how-many question wrongly.
        let set = builtin_set();
        let document = "4111111111111111, 5500005555555559, 378282246310005 and \
                        GB82WEST12345698765432";
        let counts = set.scan(document).counts();
        assert_eq!(counts.get(DetectorCategory::Financial), 4);
        assert_eq!(counts.total(), 4);
    }

    #[test]
    fn a_clean_document_produces_no_counts_and_still_produces_findings() {
        let set = builtin_set();
        let report = set.scan("The quarterly review is on Tuesday at 14:30 in room 4111.");

        assert_eq!(report.counts(), DetectorCounts::none());
        assert_eq!(report.triggered().count(), 0);
        // But both detectors are reported as having looked. "No card numbers" and "no card
        // detector configured" are different facts and must not render identically.
        assert_eq!(report.findings().len(), 2);
        assert!(report.findings().iter().all(|finding| finding.count() == 0));
    }
}
