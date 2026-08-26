//! What every handler is given, and what the process refuses to start without.

use std::sync::Arc;

use enclave_audit::{AuditSink, ChainMode, PgAuditSink};
use enclave_auth::{AccessTokenVerifier, KeySet};
use enclave_core::PolicyEngine;
use enclave_db::DbPool;

use crate::admin::conditional_access::SharedRuleCache;
use crate::admin::dlp::SharedDlpRuleCache;
use crate::edge::Edge;
use crate::refusal::HandlerAudit;

/// Shared, cheaply cloneable application state.
#[derive(Clone)]
pub struct ApiState {
    /// The policy chain. Handlers call this; nothing else evaluates policy.
    pub policy: Arc<PolicyEngine>,
    /// Tenant-scoped database access.
    pub db: Arc<DbPool>,
    /// Verifies bearer tokens. Holds the public half only.
    pub tokens: Arc<AccessTokenVerifier>,
    /// Where a request's network origin comes from. The *only* thing that may populate
    /// `NetworkContext`; see `crates/api/src/edge.rs`.
    pub edge: Arc<Edge>,
    /// The conditional-access rule cache this replica reads, when the binary has one to hand.
    ///
    /// `None` is a supported deployment rather than a defect: `ENC-590`'s staleness bound is the
    /// cache TTL, and invalidation is only the shortcut for the replica that made a change — *a
    /// message reaches one replica; a deployment is several*. Nothing in the admin surface's
    /// behaviour turns on it, which is exactly why it is an `Option` and not a required argument.
    pub rule_cache: Option<SharedRuleCache>,
    /// Whether a privileged administrative action demands a recent second factor.
    ///
    /// `security.mfa.admins_required`, which existed, was documented, defaulted to `true`, and was
    /// **read by nothing** — `require_step_up` compared against a hard-coded constant instead. So
    /// every `/admin/**` mutation demanded MFA, the binary wired an `MfaVerifier` that refuses every
    /// code, and no principal in any deployment could satisfy it. A tenant administrator was locked
    /// out of their own policy surface with a `403` naming a factor they had no way to present.
    ///
    /// That is worse than either honest answer. Requiring MFA is defensible; not requiring it is
    /// defensible; requiring something unsatisfiable is a control that cannot be operated, which is
    /// the failure `plans/M4-GOVERNANCE.md §2` is written against. Now the configured value decides,
    /// and `main.rs` refuses to start if it demands a factor no verifier can check (`ENC-771`).
    pub step_up: StepUpPolicy,
    /// The DLP rule cache this replica reads, when the binary has one to hand.
    ///
    /// `None` is a supported deployment for [`ApiState::rule_cache`]'s reason, and one extra: a
    /// deployment whose `dlp.default_mode` is `DISABLED` builds `DisabledDlp`, which holds no rule
    /// cache because it reads no rules. There is nothing to invalidate, and that is a posture
    /// rather than a gap (`ENC-633`).
    pub dlp_rule_cache: Option<SharedDlpRuleCache>,
    /// What `/api/v1/auth/*` issues, rotates and revokes with (`ENC-685`).
    ///
    /// Not `Option`, for [`crate::Delivery`]'s reason: the routes register unconditionally, so a
    /// dependency a deployment could omit would be an unexplained `500` rather than a refusal. A
    /// deployment that has wired no token service carries
    /// [`AuthSurface::unconfigured`](crate::routes::auth::AuthSurface::unconfigured), which refuses
    /// every route with `503` and says so at start-up — distinguishable from a wrong password,
    /// which is the property that matters when someone is deciding whether to look at the
    /// configuration or at the user.
    pub auth: Arc<crate::routes::auth::AuthSurface>,
    /// Where a refusal *this layer* takes is recorded (`ENC-606`).
    ///
    /// Not `Option`, and not a builder step that a deployment could forget. `ENC-606` was a class
    /// of refusal that reached callers with no row behind it; a sink a binary could omit would
    /// reintroduce exactly that, silently, in the deployment rather than in the code. It is derived
    /// from the same pool the chain's own sink is built over in `crates/api/src/main.rs`, so both
    /// write into one chain and the two rows for one request are adjacent in it.
    ///
    /// It cannot write an allow — see [`HandlerAudit`]. The chain remains the only thing that
    /// records a decision it took.
    pub audit: HandlerAudit,
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No key material, no connection string.
        f.debug_struct("ApiState").finish_non_exhaustive()
    }
}

impl ApiState {
    /// Assembles the state.
    #[must_use]
    pub fn new(
        policy: PolicyEngine,
        db: DbPool,
        issuer: &str,
        audience: &str,
        keys: KeySet,
    ) -> Self {
        // Built here rather than taken as an argument, deliberately. `ApiState::new` already holds
        // the pool the chain's sink is built over, and a required *argument* would have to be
        // threaded through `crates/api/src/main.rs` and every test harness — which is how the
        // `ENC-170` shape starts: a dependency the binary can forget while every test supplies it.
        // `ChainMode::Enabled` matches the binary's own sink; `with_audit` exists for a deployment
        // that runs unchained, and for a test that wants to read what was written.
        let audit = HandlerAudit::new(
            Arc::new(PgAuditSink::new(db.clone(), ChainMode::Enabled)) as Arc<dyn AuditSink>
        );
        Self {
            policy: Arc::new(policy),
            db: Arc::new(db),
            tokens: Arc::new(AccessTokenVerifier::new(issuer, audience, keys)),
            edge: Arc::new(Edge::untrusting()),
            rule_cache: None,
            // The safe default, and the same value `MfaConfig::default()` carries. `main.rs`
            // overrides it from configuration and refuses to start on the unsatisfiable pairing.
            step_up: StepUpPolicy::Required { max_age_secs: 900 },
            dlp_rule_cache: None,
            auth: Arc::new(crate::routes::auth::AuthSurface::unconfigured()),
            audit,
        }
    }

    /// Supplies the authentication surface `/api/v1/auth/*` runs on.
    ///
    /// A builder step rather than a constructor argument for the same reason [`ApiState::with_edge`]
    /// is one — and with a consequence that is loud rather than quiet when it is forgotten: every
    /// auth route answers `503` and `main.rs` warns about it at boot. That is the direction to fail
    /// in; the alternative, a surface assembled from defaults, would be a deployment issuing tokens
    /// signed by a key nobody chose.
    #[must_use]
    pub fn with_auth(mut self, auth: crate::routes::auth::AuthSurface) -> Self {
        self.auth = Arc::new(auth);
        self
    }

    /// Supplies the sink handler refusals are recorded into.
    ///
    /// The default is a [`PgAuditSink`] over the same pool, which is what a deployment wants. This
    /// exists for the chain-disabled posture of `docs/08-BYO-INFRA.md §14`, and for tests that need
    /// to read the rows back out of an in-memory sink rather than out of PostgreSQL.
    #[must_use]
    pub fn with_audit(mut self, audit: HandlerAudit) -> Self {
        self.audit = audit;
        self
    }

    /// Supplies the conditional-access rule cache the admin surface tells about a change.
    ///
    /// A builder step for the same reason [`ApiState::with_edge`] is one, and with the opposite
    /// consequence when it is forgotten: forgetting the edge makes every client address the socket
    /// peer, which is wrong in a direction nobody can exploit; forgetting this makes a rule change
    /// take up to the cache TTL to apply on *this* replica as well as the others, which is the
    /// documented bound rather than a defect (`ENC-590`).
    #[must_use]
    pub fn with_rule_cache(mut self, cache: SharedRuleCache) -> Self {
        self.rule_cache = Some(cache);
        self
    }

    /// Supplies the DLP rule cache the admin surface tells about a change.
    ///
    /// Separate from [`ApiState::with_rule_cache`] rather than one handle carrying both, because
    /// the two stages are two independently wired things: a deployment can run `DISABLED` DLP
    /// beside enforced conditional access, and a single combined handle would make one of them
    /// require the other to exist.
    #[must_use]
    pub fn with_dlp_rule_cache(mut self, cache: SharedDlpRuleCache) -> Self {
        self.dlp_rule_cache = Some(cache);
        self
    }

    /// Supplies the configured edge.
    ///
    /// A builder step rather than a constructor argument, and deliberately so: the default is
    /// [`Edge::untrusting`], which believes no forwarding header. A caller that forgets this gets a
    /// deployment where every client address is its socket peer — wrong behind a load balancer,
    /// but wrong in the direction that cannot be exploited. Making it a required argument would
    /// have the same effect on the binary and would force every test harness to supply one.
    #[must_use]
    pub fn with_edge(mut self, edge: Edge) -> Self {
        self.edge = Arc::new(edge);
        self
    }
}

/// The policy stages that are running in their "nothing configured" form.
///
/// Returned as data rather than logged from deep inside the wiring, so that both the start-up
/// banner and the `enterprise` profile's refusal can be driven from one list — and so a stage that
/// becomes real cannot be forgotten here.
///
/// The point is that an operator can see, in one line at boot, exactly which controls are not yet
/// deciding anything. A system that silently allows everything looks identical to one that is
/// carefully permitting each request.
#[must_use]
pub fn unconfigured_stages() -> &'static [&'static str] {
    &[
        "conditional_access (no policies — every network and device permitted)",
        "information_barriers (no segments — no mandatory separation)",
        "classification (no ceilings — no label restricts any action)",
        "dlp (DISABLED — no content inspection on any enforcement point)",
        "retention (no policies — nothing blocks deletion)",
        // Half of this stage is wired and half is not, and the entry says which half: `ENC-619`
        // gave the binary an authorization service that can answer an `Action::Admin` from
        // `users.is_admin`, and content is still self-read only. An operator reading "authorization"
        // here must not conclude that the admin surface is closed, and one reading nothing at all
        // must not conclude that ACLs are being resolved.
        "authorization (content is self-read only — ENC-126 brings ACL resolution; administrative \
         actions are decided from users.is_admin)",
    ]
}

impl ApiState {
    /// Sets what a privileged administrative action demands of the caller's session.
    #[must_use]
    pub fn with_step_up(mut self, policy: StepUpPolicy) -> Self {
        self.step_up = policy;
        self
    }
}

/// What a privileged administrative action requires of the caller's session.
///
/// Two values rather than a `bool` because the disabled case has to say *why* it is disabled where
/// an operator reads it, and because `Required` carries the freshness window that the refusal
/// echoes back to the client as `maxAge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpPolicy {
    /// A second factor, no older than this many seconds.
    Required { max_age_secs: i64 },
    /// No second factor is demanded of administrators.
    ///
    /// `security.mfa.admins_required: false`. Reachable, and deliberately so: a deployment with no
    /// MFA verifier configured cannot satisfy `Required`, and a requirement nobody can satisfy is
    /// not a stricter control — it is an administrative surface that does not exist.
    NotRequired,
}

impl StepUpPolicy {
    /// Whether this session may take a privileged administrative action.
    #[must_use]
    pub fn satisfied_by(self, strength: enclave_core::AuthStrength, age_secs: i64) -> bool {
        match self {
            Self::NotRequired => true,
            Self::Required { max_age_secs } => {
                strength.meets(enclave_core::AuthStrength::MultiFactor) && age_secs <= max_age_secs
            }
        }
    }

    /// The window a refusal reports, so the client can say how fresh a sign-in must be.
    #[must_use]
    pub const fn max_age_secs(self) -> i64 {
        match self {
            Self::Required { max_age_secs } => max_age_secs,
            // Unreachable in a refusal — `NotRequired` never refuses — but a total function here
            // keeps the envelope's shape from depending on an unwrap.
            Self::NotRequired => 0,
        }
    }
}
