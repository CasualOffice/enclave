//! `enclave-audit` — the audit event model, its canonical serialization, the tamper-evidence hash
//! chain, and the sinks that persist and forward events.
//!
//! Foundation crate: depended on by everything above it, depends on nothing above
//! (`docs/02-HLD.md §4`).
//!
//! # The four things this crate is responsible for
//!
//! 1. **[`AuditEvent`]** — one row of `audit_events` (`docs/04-DATA-MODEL.md §14`), built from a
//!    [`RequestContext`](enclave_core::RequestContext) so that the row cannot disagree with the
//!    request it describes.
//! 2. **[`canonical`]** — a frozen, versioned byte encoding. Read that module before changing
//!    anything about the event's fields: the encoding is what every stored hash was computed
//!    over, and it cannot be changed, only versioned.
//! 3. **[`chain`]** — `event_hash = SHA256(previous_hash || canonical_event)` per tenant, and a
//!    verifier that reports the *first* divergent sequence number, because that number is the
//!    investigation.
//! 4. **[`sink`] and [`siem`]** — where events go. The database write is synchronous and inside
//!    the policy engine; SIEM forwarding is asynchronous and must never block a user operation.
//!
//! # Two invariants this crate enforces structurally
//!
//! **Audit never contains credentials** (`CLAUDE.md` rule 10, test `U4`). The `detail` column
//! accepts only a [`Detail`], and every constructor of one either rejects credential-shaped field
//! names or masks their values — see [`redact`]. This is deliberately a type-level restriction
//! rather than a review convention.
//!
//! **Denials are audited exactly like allows.** [`AuditSink::record_deny`] and
//! [`AuditSink::record_allow`] both funnel into [`AuditSink::record`]. One path cannot be extended
//! without the other, which is what stops "we log successes" from becoming true by accident.
//!
//! # What this crate deliberately does not do
//!
//! It does not decide *whether* to audit — the policy engine does (`docs/03-LLD.md §12`) — and it
//! does not retry, buffer or batch on the write path. An audit write that fails must fail the
//! operation it describes, and a crate that quietly retried would blur that.

pub mod canonical;
pub mod chain;
pub mod error;
pub mod event;
pub mod redact;
pub mod siem;
pub mod sink;

#[cfg(test)]
mod test_support;

pub use canonical::{canonical_bytes, CANONICAL_FIELD_COUNT, CANONICAL_VERSION};
pub use chain::{compute_hash, seal, verify_chain, Divergence, EventHash, VerifyResult};
pub use error::{AuditError, HashLengthError, Result};
pub use event::{
    actor_from_parts, parse_action, AuditEvent, AuditEventBuilder, Outcome, PolicyRef,
    MAX_USER_AGENT_BYTES, UNASSIGNED_SEQUENCE,
};
pub use redact::{
    is_forbidden_field, Detail, RedactionError, FORBIDDEN_FIELD_MARKERS, REDACTED_PLACEHOLDER,
};
pub use siem::{NullSiemSink, SiemSink};
pub use sink::{
    chain_lock_key, read_page, record_in_tx, verify_tenant, AuditFilter, AuditRecord, AuditSink,
    ChainMode, MemoryAuditSink, PgAuditSink, Recorded,
};
