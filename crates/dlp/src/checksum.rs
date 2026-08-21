//! The published check algorithms the structured detectors are built on.
//!
//! Both are a few lines and are written here rather than taken from a crate. That is not
//! not-invented-here: `plans/M4-GOVERNANCE.md` Q16 puts these on the *synchronous* path, where
//! every dependency is code running against attacker-supplied content inside a request, and the
//! whole point of the structured-detector answer is that this path contains nothing that can be
//! made to do unbounded work. Twenty lines that visibly cannot are worth more than a crate that
//! probably does not.
//!
//! Neither function allocates, and both are a single pass over their input.

/// The Luhn check, ISO/IEC 7812-1 Annex B — the check digit every payment card number carries.
///
/// Doubles every second digit from the right, casts out nines, and requires the total to be a
/// multiple of ten.
///
/// Returns `false` for anything that is not at least two ASCII digits: a one-digit string passes
/// the arithmetic trivially (`0`) and is not a check of anything, and a non-digit means the caller
/// handed over something that was never a candidate.
///
/// # Why this is worth a checksum at all
///
/// Luhn catches every single-digit error and almost every transposition, so it rejects roughly
/// nine of every ten arbitrary digit strings of card length. That is the difference between a
/// detector that fires on invoice numbers, order references and timestamps and one that does not —
/// and a DLP control that cries wolf is a DLP control an administrator turns off, which is the
/// failure `plans/M4-GOVERNANCE.md §2` is arranged against.
#[must_use]
pub fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0_u32;
    let mut seen = 0_usize;

    for (index, byte) in digits.bytes().rev().enumerate() {
        if !byte.is_ascii_digit() {
            return false;
        }
        let mut value = u32::from(byte - b'0');
        if index % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        seen += 1;
    }

    seen >= 2 && sum.is_multiple_of(10)
}

/// ISO 7064 MOD 97-10, the check ISO 13616 specifies for an IBAN.
///
/// Takes the characters already rearranged (the first four moved to the end), maps `A`–`Z` to
/// 10–35, and reduces the resulting decimal string modulo 97. A valid IBAN leaves a remainder of
/// one.
///
/// Returns [`None`] when a character is neither an ASCII letter nor an ASCII digit — the caller
/// has offered something that is not an alphanumeric identifier and no remainder is meaningful.
///
/// # Why an iterator rather than a `&str`
///
/// The rearrangement is `s[4..]` followed by `s[..4]`, and taking an iterator lets the caller
/// express that as a `chain` of two slices instead of allocating a rearranged copy — of content —
/// per candidate. On a path that runs over every digit run in every uploaded document, an
/// allocation per candidate is the difference between a linear scan and a linear scan with a
/// heap in it.
///
/// The running remainder never exceeds `96 * 100 + 35`, so the two-digit case cannot overflow.
#[must_use]
pub fn mod97(characters: impl Iterator<Item = u8>) -> Option<u32> {
    let mut remainder = 0_u32;

    for byte in characters {
        let value = if byte.is_ascii_digit() {
            u32::from(byte - b'0')
        } else if byte.is_ascii_alphabetic() {
            u32::from(byte.to_ascii_uppercase() - b'A') + 10
        } else {
            return None;
        };

        remainder = if value < 10 { remainder * 10 + value } else { remainder * 100 + value };
        remainder %= 97;
    }

    Some(remainder)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Published vectors, which `docs/12 §1.1` permits here: the implementation being measured is
    /// **ours**, not a vendor's. The exemption in §1.1 covers somebody else's correctness; a check
    /// algorithm we wrote out of a specification is exactly the thing that has to be pinned.
    ///
    /// The card numbers below are the industry's published test PANs — they are issued to nobody
    /// and authorise nothing, which is why they can be written down.
    #[test]
    fn luhn_accepts_published_valid_card_numbers() {
        for pan in [
            "4111111111111111", // Visa test PAN
            "4012888888881881", // Visa test PAN
            "5500005555555559", // Mastercard test PAN
            "378282246310005",  // American Express test PAN, 15 digits
            "6011111111111117", // Discover test PAN
            "3530111333300000", // JCB test PAN
            "79927398713",      // The worked example in ISO/IEC 7812-1 Annex B
        ] {
            assert!(luhn_valid(pan), "a published valid check digit was rejected: {pan}");
        }
    }

    #[test]
    fn luhn_rejects_a_wrong_check_digit() {
        // Each is a published PAN with its final digit moved on by one — the single-digit error
        // Luhn exists to catch.
        for pan in ["4111111111111112", "5500005555555558", "378282246310006", "79927398710"] {
            assert!(!luhn_valid(pan), "a broken check digit was accepted: {pan}");
        }
    }

    #[test]
    fn luhn_rejects_a_transposition() {
        // The other error class the check is specified to catch: two adjacent digits swapped.
        assert!(luhn_valid("79927398713"));
        assert!(!luhn_valid("79927389713"), "a transposition was accepted");
    }

    #[test]
    fn luhn_refuses_input_that_is_not_at_least_two_digits() {
        assert!(!luhn_valid(""), "the empty string is not a checked number");
        assert!(!luhn_valid("0"), "a single zero passes the arithmetic and checks nothing");
        assert!(!luhn_valid("4111-1111"), "a separator means the caller did not normalise");
        assert!(!luhn_valid("4111 1111"), "nor does a space");
        assert!(!luhn_valid("41a1"), "nor a letter");
        // The control: the same length of genuinely valid digits is accepted, so the four
        // refusals above are not free.
        assert!(luhn_valid("00"), "two digits summing to a multiple of ten is a valid check");
    }

    /// The example IBANs published in ISO 13616 and by the national registrars.
    #[test]
    fn mod97_accepts_published_valid_ibans() {
        for iban in [
            "GB82WEST12345698765432",          // The ISO 13616 worked example
            "DE89370400440532013000",          // Germany
            "FR1420041010050500013M02606",     // France, with a letter in the BBAN
            "GB33BUKB20201555555555",          // United Kingdom
            "NL91ABNA0417164300",              // Netherlands, 18 characters
            "MT84MALT011000012345MTLCAST001S", // Malta, 31 characters
        ] {
            assert_eq!(
                rearranged_mod97(iban),
                Some(1),
                "a published valid IBAN did not reduce to 1: {iban}"
            );
        }
    }

    #[test]
    fn mod97_rejects_a_broken_check_digit() {
        for iban in ["GB82WEST12345698765433", "DE89370400440532013001", "NL91ABNA0417164301"] {
            assert_ne!(rearranged_mod97(iban), Some(1), "a broken IBAN reduced to 1: {iban}");
        }
    }

    #[test]
    fn mod97_rejects_a_non_alphanumeric_character() {
        assert_eq!(rearranged_mod97("GB82 WEST12345698765432"), None, "a space is not a value");
        assert_eq!(rearranged_mod97("GB82-WEST12345698765432"), None, "nor is a hyphen");
        // The control: the same string without the separator does reduce, so `None` above is a
        // verdict on the separator rather than on the digits around it.
        assert_eq!(rearranged_mod97("GB82WEST12345698765432"), Some(1));
    }

    #[test]
    fn mod97_folds_case_because_a_document_is_not_a_registrar() {
        assert_eq!(rearranged_mod97("gb82west12345698765432"), Some(1));
    }

    /// The rearrangement ISO 13616 specifies, done the way the detector does it — as two chained
    /// slices rather than an allocated copy.
    fn rearranged_mod97(iban: &str) -> Option<u32> {
        if iban.len() < 4 {
            return None;
        }
        let (head, rest) = iban.as_bytes().split_at(4);
        mod97(rest.iter().copied().chain(head.iter().copied()))
    }
}
