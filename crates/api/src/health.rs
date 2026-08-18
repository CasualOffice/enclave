//! Liveness and readiness.
//!
//! Both are on the policy-routing lint's allowlist. They must be: an orchestrator probes them
//! without a token, and a readiness endpoint that required authentication would report a healthy
//! service as unhealthy the moment authentication broke — precisely when you need the truth.
//!
//! Neither reports anything tenant-specific. `docs/06-SECURITY-DLP-ACCESS.md §1` assumes the
//! caller is hostile, and an unauthenticated endpoint is the most hostile of all.

use axum::extract::State;
use axum::http::StatusCode;

use crate::state::ApiState;

/// The process is up.
pub async fn live() -> StatusCode {
    StatusCode::OK
}

/// The process can serve traffic: PostgreSQL answers.
///
/// Deliberately narrow. Milvus, the embedding provider, SMTP and antivirus can all be degraded
/// without making file APIs unready (`docs/03-LLD.md §19`) — folding them in here would take the
/// whole service out of rotation for a degraded search index.
pub async fn ready(State(state): State<ApiState>) -> StatusCode {
    match state.db.health_check().await {
        Ok(()) => StatusCode::OK,
        Err(error) => {
            tracing::warn!(?error, "readiness check failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}
