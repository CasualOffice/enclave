//! `enclave-api` — HTTP surface, policy enforcement, MCP gateway
//!
//! Binary — composes the layers below it. The router lives in the library half so integration
//! tests can build an app without a listening socket.
//!
//! See `docs/02-HLD.md §4` for where this crate sits in the architecture.

pub mod admin;
pub mod auth;
pub mod content;
pub mod download;
pub mod edge;
pub mod error;
pub mod health;
pub mod me;
pub mod metrics_listener;
pub mod preview;
pub mod refusal;
pub mod routes;
pub mod state;

use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
use axum::{Extension, Router};
use enclave_preview::PreviewPipeline;
use enclave_storage::BlobStore;

pub use edge::Edge;
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
/// What the delivery routes need, and cannot be registered without.
///
/// # Why this is a parameter and not two `.layer()` calls
///
/// `ENC-170`: `router` registered `POST /files/{id}/download` and `GET /files/{id}/preview`, both
/// of which extract an axum `Extension`, and `main.rs` provided neither. Both returned `500` in the
/// binary — while passing every integration test, because the tests build their own router with the
/// extensions attached. Nothing in the workspace ran the binary against a real request, so it was
/// invisible from PR #22 until M2.
///
/// Adding the two missing layers to `main.rs` would have fixed those two routes and left the shape
/// that produced them. Taking the dependencies here means a route whose extension nobody supplies
/// cannot be registered: the third one is a compile error rather than a `500` somebody finds in
/// production.
///
/// Neither field is optional. A deployment without object storage or without a renderer passes
/// [`UnconfiguredBlobStore`](enclave_storage::UnconfiguredBlobStore) and
/// [`UnconfiguredPipeline`](enclave_preview::UnconfiguredPipeline), which refuse loudly and are
/// warned about at start-up — the same treatment the policy stages already get, and for the same
/// reason: a deployment missing a capability must look different from one that has it.
#[derive(Clone)]
pub struct Delivery {
    /// Object storage. Reached by the download path, and by nothing on the preview path.
    pub store: Arc<dyn BlobStore>,
    /// The rendition pipeline. Holds no `BlobStore` handle that the preview handler can reach.
    pub preview: Arc<dyn PreviewPipeline>,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither field is printable, and a store's Debug could carry an endpoint or a bucket.
        f.debug_struct("Delivery").finish_non_exhaustive()
    }
}

impl Delivery {
    /// The delivery a deployment has when it has configured neither.
    ///
    /// Named rather than `Default` so that reaching for it is a decision at the call site, visible
    /// in review, instead of what happens when somebody writes `..Default::default()`.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            store: Arc::new(enclave_storage::UnconfiguredBlobStore),
            preview: Arc::new(enclave_preview::UnconfiguredPipeline),
        }
    }

    /// Which delivery capabilities are absent, for the start-up warning.
    ///
    /// The counterpart to [`unconfigured_stages`]: `main.rs` warns about unconfigured policy
    /// stages already, on the grounds that a deployment permitting everything looks identical from
    /// outside to one deciding carefully. A deployment that cannot serve a byte deserves the same
    /// sentence.
    #[must_use]
    pub fn unconfigured_capabilities(&self) -> Vec<&'static str> {
        let mut absent = Vec::new();
        if self.store.capabilities().backend == "unconfigured" {
            absent.push("object storage — uploads, downloads and rendition reads will be refused");
        }
        absent
    }
}

pub fn router(state: ApiState, delivery: Delivery) -> Router {
    let Delivery { store, preview } = delivery;
    Router::new()
        // Identity (docs/05-API.md §3).
        .route("/api/v1/me", get(me::me))
        // Files and folders (docs/05-API.md §7).
        .route("/api/v1/libraries/{id}/items", get(content::browse))
        .route("/api/v1/files/{id}", get(content::file_metadata))
        .route("/api/v1/files/{id}/versions", get(content::file_versions))
        // Upload (docs/05-API.md §8). The bytes never pass through here: `POST /uploads` decides,
        // then hands back signed URLs the client writes to directly, which is why the API's memory
        // is flat for a 5 GB upload and a 5 KB one alike. `complete` answers `202 SCANNING` and
        // cannot answer anything else — rule 9 is a property of the state machine, not of this
        // registration (crates/api/src/routes/uploads.rs).
        .route("/api/v1/uploads", post(routes::uploads::create))
        .route("/api/v1/uploads/{id}/complete", post(routes::uploads::complete))
        .route(
            "/api/v1/uploads/{id}",
            get(routes::uploads::progress).delete(routes::uploads::abort),
        )
        // Sharing (docs/05-API.md §10). Creating a link is a `file.share` question and creating one
        // that leaves the tenant is a `file.share_external` question; they are separate actions
        // because external sharing is the highest-consequence grant in the system, and the handler
        // picks between them from the requested audience alone.
        //
        // `GET /shares/{token}` — the unauthenticated redemption — is **not** registered. It has no
        // way to resolve a token to a tenant: `share_links` is under FORCE row-level security, so
        // the digest lookup sees one tenant on a scoped connection and raises on an unscoped one,
        // and the only connection that would work is refused outside `crates/db` by the no-raw-pool
        // gate. `ENC-692` carries the finding and the two candidate designs; registering a route
        // that could only 503 is the ENC-170 shape this router already refuses to have.
        .route("/api/v1/files/{id}/shares", get(routes::shares::list).post(routes::shares::create))
        .route("/api/v1/shares/{id}", patch(routes::shares::update).delete(routes::shares::revoke))
        // Delivery (docs/05-API.md §9). Download is a POST because it has side effects: it spends
        // a share-link budget, writes an audit row, and may demand a justification. Preview is a
        // separate route because it is a separate permission — collapsing them is the failure the
        // split exists to prevent (docs/01-PRD.md §18).
        .route("/api/v1/files/{id}/download", post(download::download))
        .route("/api/v1/files/{id}/preview", get(preview::preview))
        // Administration (docs/05-API.md §14). Registered here rather than in a router of its own
        // so that `main.rs` needs no second line to serve it: the routes need nothing the rest of
        // the surface does not already have, and the one thing they *can* use — the rule cache —
        // is optional by design (crates/api/src/admin/conditional_access.rs).
        //
        // `DELETE` at the edge is the withdrawal `UPDATE` underneath. `migrations/0019` grants the
        // application role no `DELETE` on this table, and the handler's doc comment carries why.
        .route(
            "/api/v1/admin/conditional-access/rules",
            get(admin::conditional_access::list_rules).post(admin::conditional_access::create_rule),
        )
        .route(
            "/api/v1/admin/conditional-access/rules/{id}",
            patch(admin::conditional_access::change_rule_mode)
                .delete(admin::conditional_access::withdraw_rule),
        )
        // DLP rules (docs/05-API.md §14.2). There is no `PATCH`: a DLP rule carries no mode, which
        // is D28's structural guarantee rather than an omission — see `admin/dlp.rs`.
        .route("/api/v1/admin/dlp/rules", get(admin::dlp::list_rules).post(admin::dlp::create_rule))
        .route("/api/v1/admin/dlp/rules/{id}", delete(admin::dlp::withdraw_rule))
        // Operational probes. On the policy-routing allowlist: no tenant, no actor, no resource.
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        // Attached here rather than at each route: axum extensions are per-router, and a layer on
        // one route would silently not apply to the other.
        .layer(Extension(store))
        .layer(Extension(preview))
        .with_state(state)
}
