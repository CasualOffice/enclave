//! `enclave-retention` — Retention policies and schedules
//!
//! Security and governance — a policy service in the canonical chain, and **the last stage in it**
//! (`docs/03-LLD.md §12`, `docs/06-SECURITY-DLP-ACCESS.md §15`). That position is a control, not an
//! ordering detail: a caller who lacks permission is told they lack permission rather than learning
//! that a matter-specific legal hold exists. [`policy`] carries the full argument, including why the
//! `WHERE` clause this could have been is the wrong answer.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.
//!
//! # Two implementations, and the difference is visible at start-up
//!
//! * [`UnconfiguredRetention`] is the correct answer for a deployment with no policy tables to
//!   read. It allows everything and is *named* for that, so `ApiState::unconfigured_stages` can
//!   warn an operator which controls are inert.
//! * [`PgRetention`] reads `retention_policies` and `retention_assignments`. It refuses a delete —
//!   of a file, or of any folder whose subtree contains one — when the governing policy's
//!   `allow_user_delete` is false, with [`enclave_core::ReasonCode::RetentionBlocksDelete`].
//!
//! Both are here for the reason `crates/authorization` keeps both of its own: a product that only
//! works once every table is populated cannot be stood up, and a product that quietly allows
//! everything while looking configured is worse.

pub mod policy;

use async_trait::async_trait;
use enclave_core::{Action, RequestContext, ResourceRef, Result, RetentionService, StageDecision};

pub use policy::{
    cascade_probes, cascade_probes_on, purge_deadline, purge_deadline_on, CascadeLimits,
    PgRetention, PurgeDeadline, RetentionError,
};

/// Retention policies and schedules, evaluated against **no configured policy**.
///
/// This is the correct answer to the empty case rather than a stub that shrugs: with nothing
/// configured, this stage has nothing to object to, so it allows and says so (docs/06-SECURITY-DLP-ACCESS.md §15).
///
/// It is named for that state deliberately. A type called `DefaultRetention` would read as "the usual
/// one" in a wiring block; this one reads as a question — is anything actually configured? The
/// answer is visible at start-up (`ApiState::unconfigured_stages`), and the `enterprise`
/// deployment profile refuses to boot while any remain.
///
/// **It is kept now that [`PgRetention`] exists**, and not as a courtesy to the tests. A deployment
/// with no retention tables populated must still run, and the start-up warning that names this type
/// is how an operator learns that nothing blocks deletion in it. Deleting it would replace a stated
/// absence with an unstated one.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredRetention;

#[async_trait]
impl RetentionService for UnconfiguredRetention {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }
}
