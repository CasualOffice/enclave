//! The API's metrics listener — the socket, not the exposition.
//!
//! `ENC-521` added the metrics themselves and left this gap: `render_prometheus()` existed and
//! nothing called it, so the scrape target was a 404 and no rule in
//! `deploy/monitoring/alerts/search.yml` could ever fire. A metric nobody serves reads as "zero"
//! forever, which is indistinguishable from a healthy system.
//!
//! # Why the router moved, and why this file stayed
//!
//! `ENC-548` moved [`serve`] and [`router`] to
//! [`enclave_observability::exposition`](enclave_observability::exposition), because the worker
//! process now publishes gauges too (`crates/worker/src/coverage.rs`) and had no socket of its own —
//! the same shape as `ENC-521`, one process along. `worker → api` is the wrong direction for a
//! dependency, so the listener lives beside `render_prometheus`, which is the function it exists to
//! call. That module holds the argument for why the exposition is a *separate socket* rather than a
//! route on [`crate::router`]; it has not changed and it is not restated here.
//!
//! This module stayed as the API's binding point rather than being deleted, for two reasons. It is
//! the one file `xtask policy-routing` permits to register `/metrics`, and that exemption is worth
//! keeping pointed at a file whose whole contents are the metrics listener. And the tests below —
//! that the API's `/metrics` answers with the exposition content type, and answers nothing else —
//! are assertions about *this binary's* scrape target, which is what an operator actually curls.

pub use enclave_observability::exposition::{router, serve};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Request, StatusCode};
    use enclave_observability::metrics::EXPOSITION_CONTENT_TYPE;
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
