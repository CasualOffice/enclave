//! `enclave-classification` — Labels, ranks, inheritance, ceilings
//!
//! Security and governance — a policy service in the canonical chain.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.
//!
//! # What `ENC-574` changed here
//!
//! This crate was thirty-four lines: a policy stage that allows, and no way to answer the question
//! its name promises. Three separate things in the codebase took a
//! [`ClassificationRank`](enclave_core::ClassificationRank) and none of them could be given one,
//! because `classifications` was created by no migration.
//!
//! It is now also a **resolver**. [`Classifications`] turns a file into the rank of the most
//! sensitive label on its chain, under a tenant policy that says what to do when there is no label
//! at all. `migrations/0022_classifications.sql` is the table, `enclave_db::classifications` is the
//! walk, and `enclave_core::policy` holds the vocabulary — the same three-layer split
//! `crates/dlp` uses for security facts, for the same reason: the walk belongs below every domain
//! crate and the vocabulary belongs where more than one of them can name it.
//!
//! # Unresolved is a state, not a number
//!
//! The row this closes sat open because *"both plausible defaults are wrong in opposite,
//! undetectable directions"*. Nothing here picks one.
//! [`ClassificationResolution::unlabelled`](enclave_core::ClassificationResolution::unlabelled) is a
//! value, [`ClassificationOutcome`](enclave_core::ClassificationOutcome) is `#[must_use]` with three
//! arms and no arm a caller can mistake for a rank, and what an absence *means* is
//! [`Unlabelled`](enclave_core::Unlabelled) — tenant configuration, `FAIL_CLOSED` by default, and
//! deliberately not deserializable so a request cannot carry an override even as a field somebody
//! meant to ignore (D27).

use async_trait::async_trait;
use enclave_core::{
    Action, ClassificationPolicy, ClassificationResolution, ClassificationService, Error, FileId,
    RequestContext, ResourceRef, Result, StageDecision, TenantId,
};
use enclave_db::{effective_classification_on, DbPool};
use sqlx::PgConnection;

/// Labels, ranks, inheritance, ceilings, evaluated against **no configured policy**.
///
/// This is the correct answer to the empty case rather than a stub that shrugs: with nothing
/// configured, this stage has nothing to object to, so it allows and says so (docs/06-SECURITY-DLP-ACCESS.md §9).
///
/// It is named for that state deliberately. A type called `DefaultClassification` would read as "the usual
/// one" in a wiring block; this one reads as a question — is anything actually configured? The
/// answer is visible at start-up (`ApiState::unconfigured_stages`), and the `enterprise`
/// deployment profile refuses to boot while any remain.
///
/// It stays a stage that allows even now that [`Classifications`] can resolve a rank. Giving a
/// label's `watermark_required` / `download_restricted` / `external_share_blocked` / `sync_blocked`
/// columns effect in the chain is a separate change with its own leakage rows, and it is `ENC-657`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredClassification;

#[async_trait]
impl ClassificationService for UnconfiguredClassification {
    async fn evaluate(
        &self,
        _ctx: &RequestContext,
        _action: Action,
        _resource: &ResourceRef,
    ) -> Result<StageDecision> {
        Ok(StageDecision::allow())
    }
}

/// Resolves a resource's **effective** classification against a tenant's label set.
///
/// Cheap to clone; the pool is shared. Construct once at start-up from the tenant's classification
/// configuration, exactly as `enclave_dlp::PgSecurityFacts` is constructed from its DLP
/// configuration.
///
/// # Two entry points, and why the connection-taking one is the important one
///
/// [`Self::resolve_in`] takes a `&mut PgConnection` so it can run **inside the caller's
/// transaction**. That is not ergonomics, it is D26: the rank a policy decision compares must be
/// read in the same breath as the security facts and the resource's exposure, or two stages of one
/// request can answer "how sensitive is this document" differently. `ENC-614`'s closing note says
/// exactly this — *"the rank must be read in the same transaction as the facts, or two stages can
/// answer it differently, which is the whole of D26"*.
///
/// [`Self::resolve`] opens its own transaction and is for callers that have none — the indexing
/// pipeline's own pass, and tests. It is the convenience; `resolve_in` is the contract.
#[derive(Debug, Clone)]
pub struct Classifications {
    pool: DbPool,
    policy: ClassificationPolicy,
}

impl Classifications {
    /// Builds the resolver over a pool and the tenant's policy for unlabelled resources.
    #[must_use]
    pub fn new(pool: DbPool, policy: ClassificationPolicy) -> Self {
        Self { pool, policy }
    }

    /// The tenant policy this resolver stamps every resolution with.
    #[must_use]
    pub const fn policy(&self) -> ClassificationPolicy {
        self.policy
    }

    /// Resolves a file's effective classification inside the caller's transaction.
    ///
    /// The tenant is a parameter rather than something read from the connection because the
    /// connection has no opinion; it comes from [`RequestContext`], which is built from the
    /// verified token or from custom-domain routing and never from anything the client sent
    /// (`CLAUDE.md` rule 3). Row-level security is what makes a mismatch return nothing rather than
    /// another tenant's label, and the statement's own `tenant_id = $1` predicates are the second
    /// layer behind it (`docs/04 §3`).
    ///
    /// # Errors
    ///
    /// Any database failure, and a chain deeper than `enclave_db::MAX_CHAIN_DEPTH`. Neither becomes
    /// "unlabelled": an absence is a policy answer, and under
    /// [`Unlabelled::Assume`](enclave_core::Unlabelled::Assume) that answer is *proceed*.
    pub async fn resolve_in(
        &self,
        conn: &mut PgConnection,
        tenant: TenantId,
        file: FileId,
    ) -> Result<ClassificationResolution> {
        let effective =
            effective_classification_on(conn, tenant, file).await.map_err(Error::from)?;

        Ok(match effective {
            Some(effective) => ClassificationResolution::resolved(self.policy, effective),
            None => ClassificationResolution::unlabelled(self.policy),
        })
    }

    /// Resolves a file's effective classification in a transaction of its own.
    ///
    /// # Errors
    ///
    /// As [`Self::resolve_in`], plus any failure to obtain a tenant-scoped transaction.
    pub async fn resolve(
        &self,
        tenant: TenantId,
        file: FileId,
    ) -> Result<ClassificationResolution> {
        let mut tx = self.pool.begin(tenant).await.map_err(Error::from)?;
        let resolved = self.resolve_in(&mut tx, tenant, file).await;
        tx.commit().await.map_err(Error::from)?;
        resolved
    }
}
