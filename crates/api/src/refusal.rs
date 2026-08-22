//! The refusal a handler takes *after* the chain has allowed, and the audit row it leaves.
//!
//! `CLAUDE.md` rule 8, rule 10; `plans/M4-GOVERNANCE.md` D29; `docs/12-TESTING.md §4.10` U7.
//!
//! # The defect this module exists to close
//!
//! `ENC-606`. The policy chain allows a download and attaches [`Obligation::NoDownload`]. The
//! handler cannot discharge it — a signed URL to the original bytes is the one thing that
//! obligation forbids — so it refuses, which is rule 8 honoured exactly. But the chain had already
//! written its row, and that row says `outcome = ALLOW`. The caller received `403 PREVIEW_ONLY`
//! and the audit table recorded a success. An auditor running `WHERE outcome = 'DENY'` did not see
//! the refusal at all, and the row was structurally identical to the one written for a preview that
//! *succeeded* with its watermark obligation discharged. Both were executed against a live database
//! and are transcribed in `plans/M4-PROVENANCE-WALKTHROUGH.md §2`.
//!
//! # Why a second row rather than an amended one
//!
//! The chain's `ALLOW` is not wrong. The policy did allow — that is the fact the row states, and it
//! is the fact an auditor needs in order to understand that the restriction came from an
//! *obligation* rather than from an ACL. Both things are true and the log has to carry both.
//!
//! Amending is not available in any case, and deliberately so: `audit_events` is append-only and
//! hash-linked per tenant (`crates/audit/src/chain.rs`), so `event_hash` for every later row is
//! computed over this one. Rewriting a row to say `DENY` would invalidate the chain from that
//! sequence onwards — which is precisely what the chain exists to detect. The integrity property is
//! not negotiable to make the fix easier, so the fix is a second row.
//!
//! The two rows share a `request_id`. That is what makes the pair legible without either row
//! having to assert anything about the other: an investigator selects on `request_id` and sees the
//! chain's `ALLOW` beside the handler's `DENY`, in write order. Nothing here writes "the chain
//! allowed" into the denial row, because a claim about another row is a claim that can be wrong.
//!
//! # What the row has to carry to be *useful*
//!
//! Presence is the easy half. The three questions an incident starts from (`§1.3` of the
//! walkthrough, `docs/12 §4.10` U1) are:
//!
//! | Question | Column | Value here |
//! |---|---|---|
//! | Was it refused? | `outcome` | `DENY` — so `WHERE outcome = 'DENY'` returns it |
//! | Why? | `reason_code` | the same word the caller was given: `PREVIEW_ONLY`, `DLP_JUSTIFICATION_REQUIRED`, … |
//! | By what? | `policy_refs` | [`Control::as_str`] — `handler:obligation` or `handler:actor` |
//!
//! The `handler:` prefix is load-bearing. `policy_refs` is where the chain records the *stage* that
//! refused, and a handler refusal is not a stage: an investigator who read `dlp` there would go
//! looking for a DLP rule that refused, and there is none — DLP allowed, with a condition this
//! surface could not meet. The prefixed vocabulary cannot collide with [`enclave_core::Stage`]'s
//! names, and `a_handler_control_can_never_be_mistaken_for_a_chain_stage` asserts it.
//!
//! `detail` carries `refused_by: "handler"` — one containment predicate,
//! `detail @> '{"refused_by":"handler"}'`, finds every refusal taken at the edge — and, where there
//! is one, the *kind* of obligation that could not be discharged.
//!
//! **Never the obligation's payload.** [`kind_of`] returns the variant's name and nothing else:
//! `RECLASSIFY`, never the rank it wanted; no matched values, no file content, no justification
//! text (`CLAUDE.md` rule 10). The justification a caller supplies is user-authored text about a
//! file and does not enter this row even when its absence is the reason for the refusal.
//!
//! # Why the refusal is a type rather than an `Error`
//!
//! [`Refused`] has private fields and no conversion into [`Error`] or [`ApiError`]. The only thing
//! that produces one of those from it is [`HandlerAudit::refuse`], which writes the row first. So
//! "this class of refusal is audited" is a property of the type system rather than of a review
//! convention — the same argument that makes a `StageDecision` audited by construction, one layer
//! up. `cargo run -p xtask -- audit-coverage` enumerates every `Refused::…` site and classifies it
//! by the enclosing function's return type, exactly as it does for `StageDecision`.

use core::fmt;
use std::sync::Arc;

use enclave_audit::{AuditEvent, AuditSink, Detail, Outcome, PolicyRef};
use enclave_core::{
    Action, Error, Obligation, Obligations, ReasonCode, RequestContext, ResourceRef,
};

use crate::error::ApiError;

/// The `detail.refused_by` marker every row written here carries.
///
/// A fixed literal rather than a per-handler name: the question the field answers is "was this
/// decision taken by the chain or at the edge", and a value that varied per endpoint would make
/// the one query an investigator needs into a list of names they have to know in advance.
pub(crate) const REFUSED_BY: &str = "handler";

/// Which edge control refused, for `policy_refs`.
///
/// A closed vocabulary for the same reason [`ReasonCode`] is one: this string is inside the
/// canonically hashed bytes, so it is part of what tamper evidence covers and cannot be
/// retroactively reinterpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// The chain allowed with an obligation this surface cannot discharge (`CLAUDE.md` rule 8).
    ObligationDischarge,
    /// The principal is not one this operation can be performed by or attributed to — a service
    /// account with no name to stamp into a watermark, an MCP client with no `users` row to own a
    /// conditional-access rule.
    ActorEligibility,
}

impl Control {
    /// The stored form. Prefixed with `handler:` so it can never be read as a chain stage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObligationDischarge => "handler:obligation",
            Self::ActorEligibility => "handler:actor",
        }
    }

    /// Every variant, for exhaustive filters and for tests that must assert the whole vocabulary
    /// rather than the two entries they remember. The same reason [`Outcome::all`] exists.
    pub const ALL: [Self; 2] = [Self::ObligationDischarge, Self::ActorEligibility];
}

/// A refusal taken by a handler, which has not been audited yet.
///
/// `#[must_use]` and un-convertible on purpose: see the module documentation. Dropping one would
/// turn a refusal into a silent allow, which is the failure rule 8 forbids; converting one without
/// [`HandlerAudit::refuse`] would turn it into the silent success rule 10 forbids. Neither is
/// expressible.
#[must_use = "a refusal that is neither returned nor recorded is an operation that silently \
              proceeded — CLAUDE.md rules 8 and 10"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    code: ReasonCode,
    control: Control,
    /// The obligation that could not be discharged, where the refusal came from one. Only its
    /// *kind* is ever recorded — see [`kind_of`].
    obligation: Option<Obligation>,
}

impl Refused {
    /// The refusal an undischargeable obligation forces, with D29's standard code for it.
    ///
    /// The code comes from [`Obligation::unsatisfied_code`] rather than being chosen here, because
    /// D29 says it must not be invented per call site: two handlers refusing the same obligation
    /// with two different codes is a client that cannot offer a coherent next step.
    pub fn obligation(obligation: Obligation) -> Self {
        Self {
            code: obligation.unsatisfied_code(),
            control: Control::ObligationDischarge,
            obligation: Some(obligation),
        }
    }

    /// The same, where the standard code would mislead *this* caller.
    ///
    /// One case today and it is worth stating: a watermark that cannot be composited refuses a
    /// **preview**, and [`Obligation::unsatisfied_code`] would answer `PREVIEW_ONLY` — advice to
    /// use the endpoint the caller is already using. The audit row still records the obligation, so
    /// the divergence is visible rather than lost.
    pub const fn obligation_with(obligation: Obligation, code: ReasonCode) -> Self {
        Self { code, control: Control::ObligationDischarge, obligation: Some(obligation) }
    }

    /// The refusal a principal's *kind* forces, independent of any obligation.
    pub const fn actor(code: ReasonCode) -> Self {
        Self { code, control: Control::ActorEligibility, obligation: None }
    }

    /// The code the caller will be given, and the one the row will carry. They are the same value
    /// by construction, which is what stops the auditor and the refused user reading different
    /// words.
    #[must_use]
    pub const fn code(self) -> ReasonCode {
        self.code
    }

    /// Which edge control took the decision.
    #[must_use]
    pub const fn control(self) -> Control {
        self.control
    }
}

/// The refusal an obligation set forces on a path that can discharge none of them.
///
/// The `crates/core` equivalent is [`Obligations::require_none`], which returns an [`Error`] — and
/// an `Error` is exactly what this class of refusal must *not* be, because an `Error` can reach a
/// caller without a row. Same rule, same code, in the type that has to be audited before it becomes
/// one. A free function rather than an associated one so that `Refused::` names constructors and
/// nothing else, which is what lets the audit-coverage gate match it bluntly.
///
/// # Errors
///
/// [`Refused`] carrying [`Obligation::unsatisfied_code`] for the first outstanding obligation.
pub fn none_dischargeable(obligations: &Obligations) -> Result<(), Refused> {
    match obligations.iter().next() {
        None => Ok(()),
        Some(obligation) => Err(Refused::obligation(*obligation)),
    }
}

/// An obligation's kind, and nothing else about it.
///
/// An exhaustive match rather than a serde round trip, for the reason the `satisfy` functions are
/// exhaustive: a new obligation must break this and force someone to decide what to call it.
/// `the_recorded_kind_is_the_frozen_serde_name` asserts each arm equals the wire vocabulary, so the
/// two cannot drift into an audit row that names an obligation by a word nothing else uses.
///
/// [`Obligation::Reclassify`] deliberately drops its rank. The row says *that* a reclassification
/// could not be applied, not what it would have been: the payload of an obligation is DLP's
/// finding about content, and `CLAUDE.md` rule 10 keeps that out of the audit table.
const fn kind_of(obligation: Obligation) -> &'static str {
    match obligation {
        Obligation::Watermark => "WATERMARK",
        Obligation::RequireJustification => "REQUIRE_JUSTIFICATION",
        Obligation::RequireApproval => "REQUIRE_APPROVAL",
        Obligation::ReadOnly => "READ_ONLY",
        Obligation::NoDownload => "NO_DOWNLOAD",
        Obligation::NoSync => "NO_SYNC",
        Obligation::Reclassify { .. } => "RECLASSIFY",
    }
}

/// The handler's audit port: record a refusal, and nothing else.
///
/// Deliberately narrower than [`AuditSink`], which can write any row at all. `crates/audit`'s own
/// documentation gives the reason — *a handler that could write the table directly could also write
/// a row that says something other than what the engine decided* — so what a handler is given is
/// one method that can only produce an [`Outcome::Deny`] attributed to an edge control. There is no
/// way to write an `ALLOW` from here, which keeps "the chain records decisions" true.
#[derive(Clone)]
pub struct HandlerAudit {
    sink: Arc<dyn AuditSink>,
}

impl fmt::Debug for HandlerAudit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerAudit").finish_non_exhaustive()
    }
}

impl HandlerAudit {
    /// Wraps a sink.
    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    /// Records the refusal and returns the error the caller will be given.
    ///
    /// Returning the error rather than taking it as an argument is what makes the ordering
    /// unwritable in the wrong sequence: there is no path from a [`Refused`] to an [`ApiError`]
    /// that does not pass through this write.
    ///
    /// # Why an audit failure does not become a `500`
    ///
    /// `docs/12 §4.10` U6 requires that an audit write failure fail the operation it describes, and
    /// it already has: this operation is a refusal. Turning a sink outage into an `Error::Internal`
    /// here would replace a correct, specific `403` with an ambiguous `500` — and would hand anyone
    /// who could induce audit-write failures a way to make every refusal look like a server fault.
    /// The refusal therefore stands, and the failure is logged at `error` level so that a missing
    /// row is loud rather than silent. `a_sink_failure_does_not_turn_a_refusal_into_anything_else`
    /// asserts the direction.
    pub async fn refuse(
        &self,
        ctx: &RequestContext,
        action: Action,
        resource: &ResourceRef,
        refused: Refused,
    ) -> ApiError {
        let event = AuditEvent::builder(ctx, action, Outcome::Deny)
            .resource(resource)
            .reason(refused.code)
            .policy_ref(PolicyRef::builtin(refused.control.as_str()))
            .detail(detail_for(refused))
            .build();

        if let Err(error) = self.sink.record(event).await {
            // Not `?`, and not a panic. The row is lost; the control is not.
            tracing::error!(
                %error,
                %ctx.request_id,
                reason_code = refused.code.as_str(),
                control = refused.control.as_str(),
                "a handler refusal could not be audited; the refusal stands and the row is missing"
            );
        }

        ApiError::new(Error::denied(refused.code), ctx.request_id)
    }
}

/// The `detail` payload for one refusal.
///
/// Built here rather than inline so the two facts it may carry are in one place with the reasoning
/// about what may not be. A rejected key loses one field and is logged; it never loses the row,
/// because a refusal recorded without its detail is still a refusal an auditor can find, and one
/// not recorded at all is the defect this module exists to close.
fn detail_for(refused: Refused) -> Detail {
    let mut detail = Detail::empty();
    if let Err(error) = detail.try_insert("refused_by", REFUSED_BY) {
        tracing::error!(%error, "the refusal marker could not be attached to an audit event");
    }
    if let Some(obligation) = refused.obligation {
        if let Err(error) = detail.try_insert("obligation", kind_of(obligation)) {
            tracing::error!(%error, "the obligation kind could not be attached to an audit event");
        }
    }
    detail
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: the workspace warns on these constructs elsewhere.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::net::{IpAddr, Ipv4Addr};

    use enclave_audit::{ChainMode, MemoryAuditSink};
    use enclave_core::{
        Actor, AuthStrength, ClassificationRank, ClientType, DeviceContext, DevicePosture,
        FileAction, FileId, NetworkContext, RequestId, ScopeSet, SessionId, Stage, TenantId,
        UserId,
    };

    use super::*;

    const ALL_OBLIGATIONS: [Obligation; 7] = [
        Obligation::Watermark,
        Obligation::RequireJustification,
        Obligation::RequireApproval,
        Obligation::ReadOnly,
        Obligation::NoDownload,
        Obligation::NoSync,
        Obligation::Reclassify { to: ClassificationRank::new(40) },
    ];

    fn context(tenant: TenantId) -> RequestContext {
        RequestContext {
            request_id: RequestId::new_v7(),
            tenant_id: tenant,
            actor: Actor::User(UserId::new_v7()),
            session_id: Some(SessionId::new_v7()),
            auth_strength: AuthStrength::MultiFactor,
            auth_time: chrono::Utc::now(),
            scopes: ScopeSet::from(vec!["files:read".to_owned()]),
            client: ClientType::Web,
            network: NetworkContext {
                source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                country: Some("IN".to_owned()),
                asn: None,
                zones: Vec::new(),
                via_trusted_proxy: false,
            },
            device: DeviceContext { device_id: None, posture: DevicePosture::Managed },
        }
    }

    /// The row a handler refusal leaves answers all three of an investigator's questions.
    ///
    /// Contents, not presence. `ENC-606` was a row that existed and said the opposite of what
    /// happened, so "a row was written" is the assertion that was already true.
    #[tokio::test]
    async fn a_refusal_leaves_a_row_that_says_it_was_refused_why_and_by_what() {
        let sink = Arc::new(MemoryAuditSink::new(ChainMode::Enabled));
        let audit = HandlerAudit::new(Arc::clone(&sink) as Arc<dyn AuditSink>);

        let tenant = TenantId::new_v7();
        let ctx = context(tenant);
        let resource = ResourceRef::file(tenant, FileId::new_v7());

        let error = audit
            .refuse(
                &ctx,
                Action::File(FileAction::Download),
                &resource,
                Refused::obligation(Obligation::NoDownload),
            )
            .await;

        let events = sink.events().expect("read the sink");
        assert_eq!(events.len(), 1, "one refusal must leave exactly one row");
        let event = &events[0];

        assert_eq!(event.outcome, Outcome::Deny, "WHERE outcome = 'DENY' would not return this");
        assert_eq!(
            event.reason_code,
            Some(ReasonCode::PreviewOnly),
            "the row must carry the word the caller was given"
        );
        let attributed: Vec<&str> =
            event.policy_refs.iter().map(|reference| reference.kind.as_str()).collect();
        assert_eq!(
            attributed,
            vec![Control::ObligationDischarge.as_str()],
            "the row does not say which control refused"
        );
        assert_eq!(
            event.detail.get("obligation").and_then(serde_json::Value::as_str),
            Some("NO_DOWNLOAD"),
            "the row does not say which obligation could not be discharged"
        );
        assert_eq!(
            event.detail.get("refused_by").and_then(serde_json::Value::as_str),
            Some(REFUSED_BY)
        );

        // Correlation is what pairs this row with the chain's ALLOW for the same request.
        assert_eq!(event.request_id, ctx.request_id);
        assert_eq!(event.tenant_id, tenant, "the row must be attributed to a real tenant");
        assert_eq!(event.actor, ctx.actor, "the row must be attributed to a real actor");
        assert_eq!(event.resource_id(), Some(resource.id));
        assert_eq!(event.action, Action::File(FileAction::Download));

        // And the caller is told the same thing.
        assert!(
            matches!(error.error(), Error::PolicyDenied { code: ReasonCode::PreviewOnly, .. }),
            "the caller and the row disagree about the reason: {:?}",
            error.error()
        );
    }

    /// A handler control can never be read as a chain stage, and the reverse.
    ///
    /// `policy_refs` is one column with two vocabularies in it. An investigator who saw `dlp` on a
    /// handler refusal would go looking for a DLP rule that refused; there is none — DLP allowed,
    /// with a condition the surface could not meet.
    #[test]
    fn a_handler_control_can_never_be_mistaken_for_a_chain_stage() {
        for control in Control::ALL {
            assert!(
                control.as_str().starts_with("handler:"),
                "{} is not marked as an edge control",
                control.as_str()
            );
            for stage in Stage::ORDER {
                assert_ne!(
                    control.as_str(),
                    stage.as_str(),
                    "a handler control collides with a chain stage"
                );
            }
        }
        // The positive control: the two vocabularies are both non-empty, so the assertion above is
        // not passing against an empty list of either. An empty `Stage::ORDER` would make the
        // inner loop vacuous and the collision assertion free.
        assert_eq!(Control::ALL.len(), 2);
        assert!(Stage::ORDER.contains(&Stage::Dlp), "the chain's stage list is not being read");
    }

    /// D29's codes are taken from the obligation rather than invented at the call site.
    #[test]
    fn the_standard_code_for_an_obligation_is_the_one_recorded() {
        for obligation in ALL_OBLIGATIONS {
            let refused = Refused::obligation(obligation);
            assert_eq!(refused.code(), obligation.unsatisfied_code());
            assert_eq!(refused.control(), Control::ObligationDischarge);
        }
        // And the override still records the obligation, so a diverging code is visible rather
        // than lost.
        let overridden = Refused::obligation_with(Obligation::Watermark, ReasonCode::AccessDenied);
        assert_eq!(overridden.code(), ReasonCode::AccessDenied);
        assert_eq!(
            detail_for(overridden).get("obligation").and_then(serde_json::Value::as_str),
            Some("WATERMARK")
        );
    }

    /// The recorded kind is the frozen wire name, and never the obligation's payload.
    #[test]
    fn the_recorded_kind_is_the_frozen_serde_name() {
        for obligation in ALL_OBLIGATIONS {
            let wire = serde_json::to_value(obligation).expect("serialize the obligation");
            let tag = wire.get("type").and_then(serde_json::Value::as_str).expect("a tagged form");
            assert_eq!(kind_of(obligation), tag, "the audit name and the wire name have drifted");
        }

        // `Reclassify`'s rank is DLP's finding about content and must not reach the row.
        let payload =
            Refused::obligation(Obligation::Reclassify { to: ClassificationRank::new(40) });
        let detail =
            serde_json::to_string(&serde_json::Value::Object(detail_for(payload).into_map()))
                .expect("serialize the detail");
        assert!(detail.contains("RECLASSIFY"), "detail = {detail}");
        assert!(!detail.contains("40"), "the obligation's payload reached the row: {detail}");
    }

    /// `none_dischargeable` is `require_none` in the type that has to be audited.
    #[test]
    fn a_path_that_can_discharge_nothing_refuses_on_the_first_obligation() {
        assert!(none_dischargeable(&Obligations::none()).is_ok());
        let obligations: Obligations =
            [Obligation::RequireApproval].into_iter().collect::<Obligations>();
        let refused =
            none_dischargeable(&obligations).expect_err("an obligation here is a refusal");
        assert_eq!(refused.code(), ReasonCode::DlpApprovalRequired);
    }

    /// A sink that cannot write does not turn a refusal into anything else.
    ///
    /// The direction matters both ways: the operation must still be refused (rule 8), and the
    /// caller must still be told the reason rather than a `500` that hides which control acted.
    #[tokio::test]
    async fn a_sink_failure_does_not_turn_a_refusal_into_anything_else() {
        /// A sink standing in for a database that is down.
        #[derive(Debug)]
        struct Failing;

        #[async_trait::async_trait]
        impl AuditSink for Failing {
            async fn record(
                &self,
                _event: AuditEvent,
            ) -> enclave_audit::Result<enclave_audit::Recorded> {
                Err(enclave_audit::AuditError::Internal("the audit sink is unavailable"))
            }
        }

        let audit = HandlerAudit::new(Arc::new(Failing));
        let tenant = TenantId::new_v7();
        let ctx = context(tenant);
        let resource = ResourceRef::file(tenant, FileId::new_v7());

        let error = audit
            .refuse(
                &ctx,
                Action::File(FileAction::Download),
                &resource,
                Refused::obligation(Obligation::NoDownload),
            )
            .await;
        assert!(
            matches!(error.error(), Error::PolicyDenied { code: ReasonCode::PreviewOnly, .. }),
            "an unwritable sink changed the decision or the reason: {:?}",
            error.error()
        );
    }
}
