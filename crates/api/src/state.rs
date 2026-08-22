//! What every handler is given, and what the process refuses to start without.

use std::sync::Arc;

use enclave_auth::{AccessTokenVerifier, KeySet};
use enclave_core::PolicyEngine;
use enclave_db::DbPool;

use crate::admin::conditional_access::SharedRuleCache;
use crate::edge::Edge;

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
        Self {
            policy: Arc::new(policy),
            db: Arc::new(db),
            tokens: Arc::new(AccessTokenVerifier::new(issuer, audience, keys)),
            edge: Arc::new(Edge::untrusting()),
            rule_cache: None,
        }
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
        "authorization (self-read only — ENC-126 brings ACL resolution)",
    ]
}
