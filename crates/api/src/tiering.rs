//! What a read path says when the bytes are real, permitted, and hours away (`ENC-946`).
//!
//! # Why this is not a `404` and not a `403`
//!
//! Every other miss on a content read is [`Error::NotFound`], deliberately and uniformly: rule 7
//! says a `403` confirms existence, and rule 9 says unscanned content is indistinguishable from
//! absent. An archived version is neither case. The caller **may** read it, the file **does**
//! exist, and telling them it does not would send them to look for something they already have —
//! and would hide the one action that actually helps, which is asking for it back.
//!
//! So the answer is `409 CONFLICT` with a remediation. That leaks nothing rule 7 protects: the
//! caller has already passed the chain for this exact file on this exact action, so existence was
//! established before this code runs. It is the same reasoning `IF_MATCH_REQUIRED` is answered
//! under — a precondition on a resource the caller is already entitled to.
//!
//! # Why the check is before the mint and not after the failure
//!
//! `download` hands back a **pre-signed URL**. Once that URL exists, the fetch happens between the
//! caller and the object store, and a Glacier object answers it with `InvalidObjectState` as XML,
//! from a hostname that is not ours, in a shape no client of this API is written to parse. The
//! product never sees it and cannot explain it.
//!
//! That is what makes the tier a *column* rather than a probe. Asking the store would be a network
//! call on the critical path of every download, and it would still be a race — the object can begin
//! transitioning between the probe and the fetch. `StorageTier::Archiving` exists to close that
//! window from the other side: a read is refused from the moment a transition is *requested*, not
//! from the moment it is confirmed.

use axum::http::StatusCode;

use crate::error::Envelope;

/// The envelope a caller gets for content that is not immediately retrievable.
///
/// One function rather than one per read path, for the reason `admin::require_step_up` is one: a
/// refusal with three implementations is a refusal with three chances to be weakened one at a time,
/// and `docs/14 §5` makes the client authoritative for wording anyway — what travels is the code
/// and the remediation, and both must be identical whichever path refused.
///
/// `tier` names the state so a client can distinguish *"ask for it"* from *"it is already coming"*.
/// It is the stored spelling and not a sentence: `docs/05 §5` details are machine-readable.
pub(crate) fn archived(tier: &str) -> Envelope {
    Envelope::new(
        StatusCode::CONFLICT,
        "CONTENT_ARCHIVED",
        "This version is in long-term storage and is not immediately available.",
        "Request it back, then try again once it has been restored.",
    )
    .with_details(vec![serde_json::json!({ "storageTier": tier })])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// The refusal is a `409`, and stays one.
    ///
    /// Asserted rather than assumed because the two neighbouring answers are both wrong in ways
    /// that are individually reasonable: `404` is what every other miss on this path returns, and
    /// `403` is what a policy refusal returns. This is neither, and a future edit that "made it
    /// consistent" with either would break a client that branches on the code.
    #[test]
    fn archived_content_is_a_conflict_rather_than_a_denial_or_a_miss() {
        let envelope = archived("ARCHIVED");
        let rendered = envelope.into_response(enclave_core::RequestId::new_v7());
        assert_eq!(
            rendered.status(),
            StatusCode::CONFLICT,
            "archived content must not be reported as missing or as denied: the caller is \
             permitted, the file exists, and the only useful answer names the way back"
        );
    }
}
