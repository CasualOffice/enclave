//! The Prometheus exposition listener — a socket of its own, serving `/metrics` and nothing else.
//!
//! # Why it is here rather than in `enclave-api`
//!
//! `ENC-548`. It was in `crates/api/src/metrics_listener.rs` while the API was the only process
//! publishing anything. `crates/worker/src/coverage.rs` broke that assumption: the instruments are
//! process-wide statics, so a pass scheduled in the worker publishes into a registry that process
//! does not expose, and `SearchIndexCoverageUnreported` — literally
//! `absent(enclave_search_index_observed_chunks)` — would keep describing the deployment exactly.
//! That is `ENC-521`'s failure a second time: **a metric nobody serves reads as zero forever, which
//! is indistinguishable from a healthy system.**
//!
//! Of the two ways to close it, giving the worker its own listener is the one that does not move a
//! cross-tenant background pass into the request-serving process. It needs the listener to live
//! somewhere both binaries can reach, and `worker → api` is backwards, so it lives beside
//! [`render_prometheus`](crate::metrics::render_prometheus) — the function it exists to call. One
//! listener, one exposition, no second copy to drift.
//!
//! Behind the `exposition` feature so that this crate, which sits at the bottom of the graph and
//! which every other crate depends on, does not oblige all of them to compile an HTTP server. Only
//! the two binaries that bind a socket turn it on.
//!
//! # Why this is a separate listener and not a route on the API router
//!
//! The exposition carries `tenant_id` labels — which tenants exist, how much each one searches, how
//! far behind each one's invalidation has fallen. `xtask policy-routing` allows an endpoint to skip
//! `PolicyEngine::enforce` only when it can say nothing about a tenant, and its note on the `ready`
//! probe states the bar directly: such a response "must never include a detail that identifies a
//! tenant or a resource". Metrics fail that bar on purpose — per-tenant series are the point of
//! them.
//!
//! Both alternatives are worse. Putting `/metrics` behind the policy chain means Prometheus must
//! hold a tenant, and there is no tenant a cross-tenant aggregate could honestly claim. Adding it to
//! the unauthenticated allowlist publishes that data to anyone who can reach the API port.
//!
//! A separate socket lets an operator bind this to a private interface — the default is loopback —
//! while the API faces the world. That is emphatically *not* authentication, and
//! `enclave_config::ServerConfig::metrics_port` says so where an operator will read it: this is a
//! listener they place where they want it, absent unless they ask for it.

use core::future::Future;

use axum::http::header::CONTENT_TYPE;
use axum::routing::get;
use axum::Router;

use crate::metrics::{render_prometheus, EXPOSITION_CONTENT_TYPE};

/// Serves `GET /metrics` until `shutdown` resolves.
///
/// Both binaries spawn this rather than awaiting it, and both hand it the same shutdown signal they
/// hand their real work, so the scrape target stays answerable for as long as the process is doing
/// anything worth scraping.
pub async fn serve(
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    // A failure here must not take the process down with it: losing metrics is a degraded
    // deployment, losing the API — or the indexer — is an outage, and a process should not turn the
    // first into the second.
    if let Err(error) = axum::serve(listener, router()).with_graceful_shutdown(shutdown).await {
        tracing::error!(%error, "metrics listener stopped");
    }
}

/// The router [`serve`] runs, built separately so a test can exercise it without binding a socket.
pub fn router() -> Router {
    Router::new().route(
        "/metrics",
        get(|| async { ([(CONTENT_TYPE, EXPOSITION_CONTENT_TYPE)], render_prometheus()) }),
    )
}
