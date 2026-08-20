//! The metrics listener — a socket of its own, serving the Prometheus exposition and nothing else.
//!
//! `ENC-521` added the metrics themselves and left this gap: `render_prometheus()` existed and
//! nothing called it, so the scrape target was a 404 and no alert in
//! `deploy/monitoring/alerts/search.yml` could ever fire. A metric nobody serves reads as "zero"
//! forever, which is indistinguishable from a healthy system.

use core::future::Future;

use axum::http::header::CONTENT_TYPE;
use axum::routing::get;
use axum::Router;
use enclave_observability::metrics::{render_prometheus, EXPOSITION_CONTENT_TYPE};

/// Serves `GET /metrics` until `shutdown` resolves.
///
/// # Why this is a separate listener and not a route on [`crate::router`]
///
/// The exposition carries `tenant_id` labels — which tenants exist, how much each one searches, how
/// far behind each one's invalidation has fallen. `xtask policy-routing` allows an endpoint to skip
/// `PolicyEngine::enforce` only when it can say nothing about a tenant, and its note on the `ready`
/// probe states the bar directly: such a response "must never include a detail that identifies a
/// tenant or a resource". Metrics fail that bar on purpose — per-tenant series are the point of
/// them.
///
/// Both alternatives are worse. Putting `/metrics` behind the policy chain means Prometheus must
/// hold a tenant, and there is no tenant a cross-tenant aggregate could honestly claim. Adding it
/// to the unauthenticated allowlist publishes that data to anyone who can reach the API port.
///
/// A separate socket lets an operator bind this to a private interface — the default is loopback —
/// while the API faces the world. That is emphatically *not* authentication, and
/// [`ServerConfig::metrics_port`](enclave_config::ServerConfig) says so where an operator will read
/// it: this is a listener they place where they want it, absent unless they ask for it.
///
/// It lives in its own module because `xtask policy-routing` refuses a `/metrics` registration
/// anywhere else under `crates/api/src`. See that lint for why an allowlist entry was not the
/// answer.
pub async fn serve(
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    // A failure here must not take the API down with it: losing metrics is a degraded deployment,
    // losing the API is an outage, and the process should not turn the first into the second.
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    use super::*;

    /// The gap ENC-521 left: something has to actually answer the scrape.
    #[tokio::test]
    async fn the_listener_serves_the_exposition() {
        let response = router()
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).expect("a request"))
            .await
            .expect("a response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some(EXPOSITION_CONTENT_TYPE),
            "Prometheus dispatches on the content type; the wrong one is a scrape that parses as \
             nothing and reports no error"
        );
    }

    /// This listener serves one path. A second one would be a second thing to reason about on a
    /// port whose whole justification is that it carries only the exposition.
    #[tokio::test]
    async fn it_serves_nothing_else() {
        for path in ["/", "/health/live", "/me", "/metrics/../me"] {
            let response = router()
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).expect("a request"))
                .await
                .expect("a response");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path} was served");
        }
    }
}
