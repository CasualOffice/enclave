//! `enclave-api` — HTTP surface, policy enforcement, MCP gateway
//!
//! Binary — composes the layers below it. The router lives in the library half so integration
//! tests can build an app without a listening socket.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.

pub mod auth;
pub mod content;
pub mod download;
pub mod error;
pub mod health;
pub mod me;
pub mod preview;
pub mod state;

use axum::routing::{get, post};
use axum::Router;

pub use state::{unconfigured_stages, ApiState};

/// Builds the router.
///
/// Every route registered here is checked by the ENC-110 policy-routing lint: a handler that does
/// not reach `PolicyEngine::enforce` fails the build unless it is on that lint's allowlist with a
/// written reason. Health and readiness are on it; nothing under `/api/v1` is.
///
/// Grouped by resource family and in the order `docs/05-API.md` lists them, so that a new endpoint
/// has an obvious place to go and a reviewer can check the router against the document by reading
/// down both. Paths are written out in full rather than composed with `nest`, because `nest` moves
/// half of each path away from the handler it belongs to and the policy-routing lint reads these
/// registrations to find the handlers it must walk.
pub fn router(state: ApiState) -> Router {
    Router::new()
        // Identity (docs/05-API.md §3).
        .route("/api/v1/me", get(me::me))
        // Files and folders (docs/05-API.md §7).
        .route("/api/v1/libraries/{id}/items", get(content::browse))
        .route("/api/v1/files/{id}", get(content::file_metadata))
        .route("/api/v1/files/{id}/versions", get(content::file_versions))
        // Delivery (docs/05-API.md §9). Download is a POST because it has side effects: it spends
        // a share-link budget, writes an audit row, and may demand a justification. Preview is a
        // separate route because it is a separate permission — collapsing them is the failure the
        // split exists to prevent (docs/01-PRD.md §18).
        .route("/api/v1/files/{id}/download", post(download::download))
        .route("/api/v1/files/{id}/preview", get(preview::preview))
        // Operational probes. On the policy-routing allowlist: no tenant, no actor, no resource.
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        .with_state(state)
}
