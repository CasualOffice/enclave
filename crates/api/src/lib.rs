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
pub mod sync;
pub mod workflows;

use std::sync::Arc;

use axum::routing::{delete, get, patch, post};
use axum::{Extension, Router};
use enclave_preview::PreviewPipeline;
use enclave_storage::BlobStore;

pub use edge::Edge;
pub use state::{unconfigured_stages, ApiState, VectorRetrieval};

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
        // Authentication (docs/05-API.md §3). The first three are the credential exchange the
        // chain's auth stage presupposes and are on the policy-routing allowlist by name; the last
        // four are authenticated and go through the chain like everything else.
        .route("/api/v1/auth/login", post(routes::auth::login))
        .route("/api/v1/auth/mfa/verify", post(routes::auth::mfa_verify))
        .route("/api/v1/auth/refresh", post(routes::auth::refresh))
        .route("/api/v1/auth/logout", post(routes::auth::logout))
        .route("/api/v1/auth/logout-all", post(routes::auth::logout_all))
        .route("/api/v1/auth/sessions", get(routes::auth::sessions))
        .route("/api/v1/auth/sessions/{sid}", delete(routes::auth::revoke_session))
        // Identity (docs/05-API.md §3).
        .route("/api/v1/me", get(me::me))
        // Bootstrap (docs/05-API.md §19). The first request a client makes and the only one it
        // makes holding nothing, so it is registered beside `/me` rather than beside the health
        // probes: it is an `/api/v1` surface with an authenticated half that reads a tenant's row
        // and goes through the chain. It is *not* on the policy-routing allowlist, and must not be
        // — an exemption is granted per handler, not per branch, so allowlisting it would exempt
        // the half that reads tenant data. `crates/api/src/routes/bootstrap.rs` carries the
        // argument, and `crates/api/tests/bootstrap.rs` carries the assertion the lint cannot
        // make: that the authenticated half is refused when the chain refuses.
        .route("/api/v1/bootstrap", get(routes::bootstrap::bootstrap))
        // Navigation — workspaces and libraries (docs/05-API.md §7.1). Registered before the file
        // surface because they are how a client *reaches* it: `GET /libraries/{id}/items` was
        // registered from M1 and nothing told a caller which id to pass, so the library picker in
        // the web shell was drawn as unbuilt (`ENC-778`). Every one of the four is a read; the
        // create and update halves are `/admin/workspaces` and `/admin/libraries`, unbuilt.
        .route("/api/v1/workspaces", get(routes::workspaces::list))
        .route("/api/v1/workspaces/{id}", get(routes::workspaces::read))
        .route("/api/v1/workspaces/{id}/libraries", get(routes::libraries::list_in_workspace))
        .route("/api/v1/libraries/{id}", get(routes::libraries::read))
        // Files and folders (docs/05-API.md §7).
        // Files and folders (docs/05-API.md §7). `POST /libraries/{id}/folders` is the document's
        // own row 175 and the only write in that table anything serves: `FileRepository::create_folder`
        // had no caller in any binary, so `POST /uploads`' `parentId` named a folder no client could
        // have obtained and every upload landed at a library root (`ENC-788`). Registered beside the
        // browse it makes non-trivial, and before `/files/{id}`, in the document's order.
        .route("/api/v1/libraries/{id}/items", get(content::browse))
        .route("/api/v1/libraries/{id}/folders", post(routes::folders::create))
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
        // `GET /shares/{token}` — the unauthenticated redemption — is **not** registered, and the
        // reason is no longer the one `ENC-692` recorded. The tenant is now available on an
        // unauthenticated route: `enclave_db::resolve_routed_tenant` resolves a verified custom
        // domain and a slug (`ENC-686`), `main.rs` configures the platform URL it needs, and the
        // `RoutedTenant` extractor is already how `POST /auth/login` gets a tenant. What blocks it
        // is `ENC-879`: a redemption arrives with **no principal** the policy chain can name — there
        // is no `Actor` variant for a link's bearer, no `acl_entries.principal_type` that could hold
        // one, and `ResourceKind::Share` is an unsupported target — so `enforce` can only deny, for
        // every caller. Registering a route that refuses every redemption is the ENC-170 shape this
        // router already refuses to have, and a denial rendered as anything but `404` would confirm
        // to an anonymous caller that the token is live (rule 7).
        // `crates/api/src/routes/shares.rs` carries the argument and the tests that hold it.
        .route("/api/v1/files/{id}/shares", get(routes::shares::list).post(routes::shares::create))
        .route("/api/v1/shares/{id}", patch(routes::shares::update).delete(routes::shares::revoke))
        // Delivery (docs/05-API.md §9). Download is a POST because it has side effects: it spends
        // a share-link budget, writes an audit row, and may demand a justification. Preview is a
        // separate route because it is a separate permission — collapsing them is the failure the
        // split exists to prevent (docs/01-PRD.md §18).
        .route("/api/v1/files/{id}/download", post(download::download))
        .route("/api/v1/files/{id}/preview", get(preview::preview))
        // Search (docs/05-API.md §11). A POST because the query is a body — a filter set in a URL
        // is a tenant's document titles in every proxy log — and because it is not idempotent in
        // the sense that matters here: it writes an audit row. Every result it returns has been
        // confirmed against PostgreSQL by `enclave_search::PostFilter` (CLAUDE.md rule 5).
        .route("/api/v1/search", post(routes::search::search))
        // The other three of rule 6's five verbs (`ENC-719`–`ENC-721`). Each asks the chain a
        // different question — `file.export`, `file.print`, `file.preview` — and none of them can
        // reach a `BlobStore`: `export` and `thumbnail` hold only the rendition pipeline, and
        // `print_token` holds neither, because it mints a capability rather than serving a byte.
        // `crates/api/src/routes/delivery.rs` carries the reasoning for each.
        .route("/api/v1/files/{id}/thumbnail", get(routes::delivery::thumbnail))
        .route("/api/v1/files/{id}/export", post(routes::delivery::export))
        .route("/api/v1/files/{id}/print-token", post(routes::delivery::print_token))
        // The redemption (`ENC-724`). It holds the pipeline and no `BlobStore` either, and it asks
        // `file.print` a second time rather than trusting the grant — a grant is a decision about
        // an earlier request, not this one.
        .route("/api/v1/files/{id}/print", post(routes::delivery::print))
        // Sync (docs/05-API.md §13). `reserve` extracts the `BlobStore` extension attached below —
        // it claims an ordinary upload session rather than a sync-only one, which is docs/10 §2's
        // "the sync client gets no privileged endpoint" held structurally rather than promised.
        .route("/api/v1/sync/devices", get(sync::list_devices).post(sync::register_device))
        .route("/api/v1/sync/devices/{id}/wipe", post(sync::wipe_device))
        .route("/api/v1/sync/delta", get(sync::delta))
        .route("/api/v1/sync/reserve", post(sync::reserve))
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
        // Workflows (docs/05-API.md §16, docs/15-WORKFLOWS-AND-SIGNING.md). `ENC-739`.
        //
        // `/tasks` is registered before `/instances/{id}` and `/steps/{id}` deliberately: axum
        // matches literals ahead of captures, so the order is presentational, and reading down this
        // block in the order `docs/05-API.md §16` lists them is what lets a reviewer check the
        // router against the document.
        //
        // Every handler here reaches `PolicyEngine::enforce` — the ENC-110 lint proves it, and none
        // of them is on its allowlist. What the lint cannot see, and `crates/api/src/workflows.rs`
        // carries: `simulate` enforces the *same action on the same resource* as `start`, which is
        // D28's requirement that a simulation not take a cheaper path than the thing it rehearses.
        .route("/api/v1/workflows/tasks", get(workflows::tasks))
        .route("/api/v1/files/{id}/workflows", post(workflows::start))
        .route("/api/v1/workflows/definitions/{id}/simulate", post(workflows::simulate))
        .route("/api/v1/workflows/instances/{id}", get(workflows::instance))
        .route("/api/v1/workflows/instances/{id}/cancel", post(workflows::cancel))
        .route("/api/v1/workflows/steps/{id}/approve", post(workflows::approve))
        .route("/api/v1/workflows/steps/{id}/reject", post(workflows::reject))
        .route("/api/v1/workflows/steps/{id}/delegate", post(workflows::delegate))
        // Operational probes. On the policy-routing allowlist: no tenant, no actor, no resource.
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        // The third probe, and the one with two halves (docs/05-API.md §19). Outside `/api/v1`
        // with its siblings, because an operator's probe configuration names `/health/**` and a
        // report that lived under the versioned prefix would be the one dependency page nobody
        // could find. Unlike them it is *not* allowlisted: the authenticated half reaches the
        // chain, and the anonymous half discloses one word. `crates/api/src/health.rs` states what
        // never appears on either — a host, a port, a URL, a bucket or a version.
        .route("/health/dependencies", get(health::dependencies))
        // Attached here rather than at each route: axum extensions are per-router, and a layer on
        // one route would silently not apply to the other.
        .layer(Extension(store))
        .layer(Extension(preview))
        .with_state(state)
}
