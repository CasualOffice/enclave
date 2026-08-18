//! The EICAR anti-malware test file, assembled at runtime.
//!
//! EICAR is the 68-byte ASCII string every antivirus product agrees to report as a detection, and
//! it is malware in no sense — it is a printable COM stub that prints a message. It is what
//! `docs/12-TESTING.md §4.8` G1 is written against, and the only way to prove the ingest path
//! quarantines a detection without keeping an actual sample in the repository.
//!
//! # Why it is built from fragments rather than written out
//!
//! Because a tracked file containing the contiguous string is a file that a contributor's own
//! endpoint protection deletes on checkout, and that CI's runner image may quarantine mid-clone.
//! That failure arrives as "the repository is corrupt" rather than as anything pointing here.
//!
//! This is the same manoeuvre `CLAUDE.md` rule 11 requires for PEM banners in fixtures, and for
//! the same underlying reason: a scanner matches a literal, so do not commit the literal. The
//! value is identical at runtime, so nothing about the test is weakened — [`is_eicar`] checks
//! that.

/// The EICAR standard antivirus test string, as bytes.
///
/// Exactly the 68 bytes the specification defines, with no trailing newline. Some engines accept
/// up to 128 bytes of trailing whitespace; nothing here relies on that.
#[must_use]
pub fn eicar_test_file() -> Vec<u8> {
    // Split so that no fragment is long enough for a scanner's signature to match, and so that
    // concatenating them is visibly the whole string rather than something clever.
    const HEAD: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    const BODY: &str = "EICAR-STANDARD-ANTIVIRUS-";
    const TAIL: &str = "TEST-FILE!$H+H*";

    let mut out = Vec::with_capacity(HEAD.len() + BODY.len() + TAIL.len());
    out.extend_from_slice(HEAD.as_bytes());
    out.extend_from_slice(BODY.as_bytes());
    out.extend_from_slice(TAIL.as_bytes());
    out
}

/// Whether `bytes` is exactly the EICAR test file.
///
/// Exists so a fake engine in a test can detect it the way a real one would, without that test
/// having to carry the literal either.
#[must_use]
pub fn is_eicar(bytes: &[u8]) -> bool {
    bytes == eicar_test_file().as_slice()
}

/// The signature name ClamAV reports for [`eicar_test_file`].
///
/// Other engines use other names; nothing in this crate depends on the string beyond the
/// clamd-facing tests, which is the point of [`crate::ScanVerdict::Infected`] carrying whatever
/// the engine said rather than a normalized enum.
pub const CLAMAV_SIGNATURE: &str = "Win.Test.EICAR_HDB-1";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn the_assembled_file_is_the_specified_68_bytes() {
        assert_eq!(eicar_test_file().len(), 68);
    }

    #[test]
    fn it_is_printable_ascii_which_is_the_whole_reason_it_is_safe_to_ship() {
        assert!(eicar_test_file().iter().all(|byte| byte.is_ascii_graphic()));
    }

    #[test]
    fn assembly_is_deterministic_and_recognized_by_its_own_check() {
        assert_eq!(eicar_test_file(), eicar_test_file());
        assert!(is_eicar(&eicar_test_file()));
        assert!(!is_eicar(b"harmless"));
        assert!(!is_eicar(&eicar_test_file()[..67]), "a truncated EICAR is not EICAR");
    }
}
