//! `enclave-api` — HTTP surface, policy enforcement, MCP gateway
//!
//! Binary — composes the layers below it. The router lives in the library half so integration
//! tests can build an app without a listening socket.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.

pub mod auth;
pub mod error;
pub mod health;
pub mod me;
pub mod state;

use axum::routing::get;
use axum::Router;

pub use state::{unconfigured_stages, ApiState};

/// Builds the router.
///
/// Every route registered here is checked by the ENC-110 policy-routing lint: a handler that does
/// not reach `PolicyEngine::enforce` fails the build unless it is on that lint's allowlist with a
/// written reason. Health and readiness are on it; `me` is not.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/me", get(me::me))
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .with_state(state)
}
