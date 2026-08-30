//! The reachability smoke test — **the real binary, a real login, every registered route**.
//!
//! `plans/M5A-API-COMPLETION.md` step 2. Every other test in this directory builds an
//! `axum::Router` in-process and drives it with `tower::ServiceExt::oneshot`. That is the right
//! shape for asserting what a handler decides, and it is structurally incapable of seeing the four
//! defects that made a 130k-line backend unusable, because every one of them lived in
//! `crates/api/src/main.rs` — the file no in-process test executes:
//!
//! 1. `crates/api` registered ten of `docs/05-API.md`'s forty-three endpoints, and no `/auth/*` at
//!    all. A test that builds the router itself never asks what the router contains.
//! 2. Once registered they answered `503`: the binary built an empty `KeySet` and an
//!    `AuthSurface::unconfigured`. Tests supply a real key, so the surface they exercise is not the
//!    one that shipped.
//! 3. Once wired, every authenticated route answered `403`: the binary composed
//!    `SelfServiceAuthorization` with no ACL resolver. Tests compose both.
//! 4. Once composed, `GET /me` **still** answered `403`: the token's `iss` came from
//!    `server.public_url` at the minting site and from an unset `auth.access_token.issuer` at the
//!    verifying site. Every token the deployment issued was rejected by the deployment that issued
//!    it — and no test both minted and verified through that composition.
//!
//! All four are seams between two individually correct components. **A unit test cannot see a
//! seam.** So this test starts `target/<profile>/enclave-api` as a child process, against a real
//! PostgreSQL, with a real `enclave.yaml`, logs in over TCP with a password a real Argon2 hash was
//! written for, and calls every route the router registers with the token that came back.
//!
//! # What it asserts, and why each half is needed
//!
//! * **No route answers `401`, `403` or `503`** to a caller who holds every grant. A `503` is an
//!   unwired dependency (defect 2); a `401` on a token this deployment just minted is defect 4; a
//!   `403` is defect 3.
//! * **No route answers `500`.** `ENC-170` is the precedent: `download` and `preview` were
//!   registered without the extensions they extract and answered `500` in the binary while every
//!   integration test passed.
//! * **A route probed against a fixture the caller was granted everything on must not answer
//!   `404`** either. This one is load-bearing and easy to miss: `CLAUDE.md` rule 7 turns a barrier
//!   or cross-tenant denial into a `404`, so a probe that names a resource which does not exist
//!   cannot distinguish "authorization is unwired" from "no such row". Only a request for a real,
//!   granted resource can, which is why the fixture spine below is built and granted before the
//!   server starts.
//!
//! # Seven routes cannot meet that bar today, and are quarantined rather than excused
//!
//! The first green run of this test was not green. Three defects it found are somebody else's rows
//! — `ENC-770`, `ENC-771` and `ENC-736` — and none of them is fixable from a test file. Each is an
//! [`Expect::Unreachable`] entry naming the status it answers, the row that carries the fix and the
//! reason the composed binary cannot serve it, and the entry **asserts that exact status**. So the
//! list cannot grow silently (a new route joins it only by an edit that has to state a reason) and
//! cannot rot (the day the wiring is fixed, the assertion fails and the entry must go). It is
//! printed on every run for `xtask/src/policy_routing.rs`'s reason: an exemption nobody meets is an
//! exemption nobody revisits.
//!
//! # The route list is derived, never written down
//!
//! `ENC-543`'s failure mode is a hand-maintained list that silently stops covering new work, so the
//! set of routes comes from [`registered_routes`], which parses the `.route(…)` registrations out
//! of `crates/api/src/lib.rs` — the same source `xtask/src/policy_routing.rs` reads, for the same
//! reason: `router()` deliberately writes every path out in full rather than composing it with
//! `nest`, precisely so it can be read by a machine.
//!
//! A derivation alone would not catch a *deleted* registration, because deleting one shrinks the
//! derived list too. Two further checks close that:
//!
//! * [`every_registered_route_has_a_request_specification`] asserts the derived set and the
//!   [`SPECS`] table agree **exactly**, in both directions. A new route with no spec fails; a spec
//!   for a route that no longer exists fails.
//! * [`every_handler_in_the_crate_is_registered`] finds every `pub async fn` in `crates/api/src`
//!   that takes axum's `State<ApiState>` — i.e. every function that *is* a handler — and asserts
//!   the router registers it. This is the check that would have failed on defect 1: the handlers
//!   existed, and nothing routed to them.
//!
//! # Running it
//!
//! `DATABASE_URL` must point at a PostgreSQL a database can be created on; `README.md` §"Running
//! the server" has the whole recipe, including the four environment variables the binary's own
//! configuration references and the `env://` form `CLAUDE.md` rule 11 requires for the two DSNs.

// Assertions are the point of a test; the workspace warns on these in non-test code.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use enclave_core::{Action, ContainerAction, FileAction, ShareAction};
use enclave_testing::content::{grant, AclEffect, AclPrincipal, AclScope, Spine};
use enclave_testing::TestDb;

// -------------------------------------------------------------------------------------------
// What the smoke run does to each route
// -------------------------------------------------------------------------------------------

/// What a route is allowed to answer.
///
/// Three values rather than two, because "this route is reachable" and "this route is reachable and
/// the fixture can hand it a resource that exists" are different claims and only the second can
/// forbid a `404`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The request names a resource the caller holds every grant on, or names none at all. It must
    /// answer something — `2xx`, a validation `4xx` — that is not a refusal and not a `404`.
    Served,
    /// The request necessarily names an identifier no fixture can create (a session, an upload
    /// session, a workflow instance), so `404` is the correct answer and is permitted. Everything
    /// else [`Expect::Served`] forbids is still forbidden.
    ServedOrAbsent,
    /// **The route is unreachable in the composed binary today**, for a reason that is understood,
    /// recorded and not this test's to fix. The exact status is asserted, so the entry cannot rot:
    /// when the wiring is fixed the assertion fails and the entry must be deleted. Printed on every
    /// run — an exemption nobody sees is an exemption nobody revisits.
    Unreachable {
        /// The status it answers today.
        status: u16,
        /// The tracker row that carries the fix.
        tracker: &'static str,
        /// Why the composed binary cannot serve it.
        why: &'static str,
    },
}

/// Which credential a request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Credential {
    /// No `Authorization` header. The probes, and the credential exchange itself.
    None,
    /// `Authorization: Bearer <access token>`, from the login below.
    Bearer,
    /// The refresh cookie and its CSRF header — the only thing `POST /auth/refresh` accepts, and
    /// the reason it is not simply a `Bearer` route: without them it correctly answers `401
    /// CSRF_TOKEN_INVALID`, which would be indistinguishable here from defect 4.
    RefreshCookie,
}

/// One route, and the request that proves it answers.
///
/// `method` and `path` are matched against the derived registrations and must agree exactly;
/// `target` is the URI actually sent, with the placeholders [`Fixtures::fill`] substitutes.
#[derive(Debug, Clone, Copy)]
struct Spec {
    method: &'static str,
    /// The path **as registered**, `{id}` placeholders and all.
    path: &'static str,
    /// The URI to request. `{lib}`, `{file}`, `{share}` and `{unknown}` are substituted.
    target: &'static str,
    body: Option<&'static str>,
    credential: Credential,
    expect: Expect,
}

/// The five admin mutations, which every caller is refused. See `ENC-771`.
/// The five `/admin/**` mutations, no longer quarantined.
///
/// They were `Expect::Unreachable { status: 403, tracker: "ENC-771" }` — the handler demanded a
/// second factor within fifteen minutes and the binary wired an `MfaVerifier` that refuses every
/// code, so the tenant's own administrator could not change a rule. That entry did exactly what a
/// quarantine is for: it recorded the defect as an assertion, printed it on every run, and failed
/// the moment the wiring changed.
///
/// `security.mfa.admins_required` now decides, and `main.rs` refuses to start when it is `true`
/// with no verifier configured, so the unsatisfiable pairing cannot be deployed. This test's own
/// `enclave.yaml` sets it to `false` and says why.
const STEP_UP: Expect = Expect::Served;
/// Every registered route, in the order `crates/api/src/lib.rs` registers them.
///
/// Order is presentational — the agreement check compares sets — with one exception the runner
/// enforces rather than this table: `logout` and `logout-all` are probed last, because a probe that
/// destroys the caller's session must not decide the verdict of the probes after it.
const SPECS: &[Spec] = &[
    // Authentication (docs/05-API.md §3).
    Spec {
        method: "POST",
        path: "/api/v1/auth/login",
        target: "/api/v1/auth/login",
        // Filled in by the runner: this is the one request whose body is a credential, and a
        // credential does not belong in a table of constants.
        body: None,
        credential: Credential::None,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/auth/mfa/verify",
        target: "/api/v1/auth/mfa/verify",
        // Deliberately an empty body. A well-formed one names a challenge that was never issued,
        // which is correctly a `401` — so what this probe asserts is that the route is registered
        // and reaches its extractor, and no more. Said plainly here rather than left as a
        // surprisingly weak assertion: nothing in this workspace can complete an MFA challenge
        // (ENC-688), so nothing here can prove the handler body runs.
        body: Some("{}"),
        credential: Credential::None,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/auth/refresh",
        target: "/api/v1/auth/refresh",
        body: None,
        credential: Credential::RefreshCookie,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/auth/logout",
        target: "/api/v1/auth/logout",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/auth/logout-all",
        target: "/api/v1/auth/logout-all",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/auth/sessions",
        target: "/api/v1/auth/sessions",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "DELETE",
        path: "/api/v1/auth/sessions/{sid}",
        target: "/api/v1/auth/sessions/{unknown}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Identity (docs/05-API.md §3). The request defect 4 was found on.
    Spec {
        method: "GET",
        path: "/api/v1/me",
        target: "/api/v1/me",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Bootstrap (docs/05-API.md §19, `ENC-725`). Probed **twice, on one registration**, because it
    // is one route with two callers and the interesting failure is not the same one for each. The
    // set-agreement check below compares `(method, path)` sets, so two specs for one route agree
    // with one registration; nothing here requires the table to be a bijection.
    //
    // The anonymous probe is the ENC-170 shape: a handler that reaches an extractor the binary
    // never composed answers `500` in the binary and `200` in every in-process test. The
    // authenticated probe is defect 3's shape: the composed authorization service refusing a caller
    // who holds everything. Neither probe reads the *body* — that the anonymous half carries no
    // tenant and the authenticated half does is `crates/api/tests/bootstrap.rs`'s claim, and it is
    // the one claim that needs a second tenant to be worth anything.
    Spec {
        method: "GET",
        path: "/api/v1/bootstrap",
        target: "/api/v1/bootstrap",
        body: None,
        credential: Credential::None,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/bootstrap",
        target: "/api/v1/bootstrap",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // Navigation — workspaces and libraries (docs/05-API.md §7.1, `ENC-791`). All four name the
    // fixture spine's own workspace and library, which the caller holds every container action on,
    // so `Expect::Served` forbids `404` here and the two listings must come back non-empty for the
    // right reason. That is the assertion this table can make and a unit test cannot: the workspace
    // listing's audited decision is `container.read` on the caller's own `users` row, answered by
    // `SelfServiceOr` — which only the composed binary wires — and every row on the page is then
    // trimmed by `PgAclAuthorization`. A binary composing either service alone answers `200` with an
    // empty list rather than failing, so `ENC-746`'s row is load-bearing for these two as well.
    // `ENC-930`. The home screen's first request after `/me`. It answers `200` with an empty
    // list on a fixture that has opened nothing, which is the correct answer and not a skip:
    // `filteredCount` is what tells that apart from a list the chain emptied.
    // `ENC-938`. Answers `200` with an empty list on a fixture that has deleted nothing, which is
    // the correct answer: `filteredCount` is what separates that from a bin the chain emptied.
    Spec {
        method: "GET",
        path: "/api/v1/trash",
        target: "/api/v1/trash",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/me/recent",
        target: "/api/v1/me/recent",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // `ENC-954`. `Served`: the caller holds every grant on the fixture, and a share list with no
    // rows is a `200` with an empty array — the correct answer, and the one this suite asks about.
    Spec {
        method: "GET",
        path: "/api/v1/me/shared",
        target: "/api/v1/me/shared",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/workspaces",
        target: "/api/v1/workspaces",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/workspaces/{id}",
        target: "/api/v1/workspaces/{ws}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/workspaces/{id}/libraries",
        target: "/api/v1/workspaces/{ws}/libraries",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // `ENC-916`. Creating a library is `container.create` against the *workspace*, so unlike its
    // `GET` sibling it is answered by that workspace's own ACL rather than by the library's. The
    // probe therefore says as much about the fixture as about the route: it passes because the
    // seeded caller holds the grant on the workspace it names, and a `404` here means the fixture
    // stopped granting it, not that the route stopped existing.
    // `ENC-917`. Five routes, and what they probe is that a caller holding `manage_permissions`
    // reaches them at all — the whole item exists because `enclave_authorization::grant` was
    // complete, tested and callable by no request. The `PUT` bodies resend an empty set rather than
    // a real one: this test asserts reachability, and a body that granted something would make the
    // probe depend on the fixture's ACL staying exactly as it is.
    Spec {
        method: "GET",
        path: "/api/v1/workspaces/{id}/permissions",
        target: "/api/v1/workspaces/{ws}/permissions",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "PUT",
        path: "/api/v1/workspaces/{id}/permissions",
        target: "/api/v1/workspaces/{ws}/permissions",
        body: Some(r#"{"entries":[]}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/libraries/{id}/permissions",
        target: "/api/v1/libraries/{lib}/permissions",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "PUT",
        path: "/api/v1/libraries/{id}/permissions",
        target: "/api/v1/libraries/{lib}/permissions",
        body: Some(r#"{"entries":[]}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/libraries/{id}/permissions/break-inheritance",
        target: "/api/v1/libraries/{lib}/permissions/break-inheritance",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/workspaces/{id}/libraries",
        target: "/api/v1/workspaces/{ws}/libraries",
        body: Some(r#"{"name":"reachability-probe","slug":"reachability-probe"}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/libraries/{id}",
        target: "/api/v1/libraries/{lib}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // Files and folders (docs/05-API.md §7).
    Spec {
        method: "GET",
        path: "/api/v1/libraries/{id}/items",
        target: "/api/v1/libraries/{lib}/items",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/files/{id}",
        target: "/api/v1/files/{file}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // `ENC-807`. All three deliberately send **no** `If-Match` and no body. They answer
    // `400 IF_MATCH_REQUIRED`, which is a validation `4xx` and therefore `Expect::Served` — and,
    // which is the point, they then mutate nothing: a `DELETE` probe that reached the repository
    // would trash the smoke fixture on every run, and every probe after it would be measuring a
    // deleted tree. Do not "fix" the missing header.
    Spec {
        method: "PATCH",
        path: "/api/v1/files/{id}",
        target: "/api/v1/files/{file}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "DELETE",
        path: "/api/v1/files/{id}",
        target: "/api/v1/files/{file}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/restore",
        target: "/api/v1/files/{file}/restore",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // `ENC-946`. `ServedOrAbsent` for the same reason `POST /download` above carries it, and it is
    // the same cause rather than a coincidence: both resolve through `readable_version_for`, and
    // the fixture file has no committed version with bytes — an upload this probe cannot perform,
    // because it would have to PUT to a pre-signed URL and then wait for an antivirus pass. The
    // tier arms are proved against a real archived version in `crates/api/tests/tiering.rs`.
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/rehydrate",
        target: "/api/v1/files/{file}/rehydrate",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "GET",
        path: "/api/v1/files/{id}/permissions",
        target: "/api/v1/files/{file}/permissions",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "PUT",
        path: "/api/v1/files/{id}/permissions",
        target: "/api/v1/files/{file}/permissions",
        body: Some(r#"{"entries":[]}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/permissions/break-inheritance",
        target: "/api/v1/files/{file}/permissions/break-inheritance",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/files/{id}/versions",
        target: "/api/v1/files/{file}/versions",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // Folder creation (docs/05-API.md §7, `ENC-788`). The name carries the fixture's `unknown`
    // uuid rather than a literal, because this table is probed against a database the smoke run
    // may re-enter: a fixed name would answer `201` on the first pass and `409 NAME_IN_USE` on the
    // second, and a probe whose status depends on how often it has run is a probe that fails for a
    // reason unrelated to what it is checking. `Expect::Served` therefore forbids `404` as well —
    // the caller holds `container.create` on the spine's workspace, so a refusal here is wiring.
    Spec {
        method: "POST",
        path: "/api/v1/libraries/{id}/folders",
        target: "/api/v1/libraries/{lib}/folders",
        body: Some(r#"{"name":"smoke-{unknown}"}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // Upload (docs/05-API.md §8).
    Spec {
        method: "POST",
        path: "/api/v1/uploads",
        target: "/api/v1/uploads",
        body: Some(
            r#"{"libraryId":"{lib}","name":"smoke.txt","sizeBytes":11,"mimeType":"text/plain"}"#,
        ),
        credential: Credential::Bearer,
        // Was `Expect::Unreachable { status: 500, tracker: "ENC-770" }` — the binary bound
        // `Delivery::unconfigured()` unconditionally and never read the `storage:` section, so the
        // whole write path answered `500 INTERNAL` on a fully specified S3 deployment. `080c689`
        // composes the real store from `storage.s3`, and this probe now answers `201` with a signed
        // `PutObject` URL. The quarantine's own instruction was to delete the entry when the wiring
        // was fixed rather than keep asserting a status that had stopped being true, and this is
        // that deletion — the entry did exactly what a quarantine is for.
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/uploads/{id}/complete",
        target: "/api/v1/uploads/{unknown}/complete",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "GET",
        path: "/api/v1/uploads/{id}",
        target: "/api/v1/uploads/{unknown}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "DELETE",
        path: "/api/v1/uploads/{id}",
        target: "/api/v1/uploads/{unknown}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Sharing (docs/05-API.md §10). The link created here is what makes the two `/shares/{id}`
    // probes below name a share that exists, rather than asserting nothing against a `404`.
    Spec {
        method: "GET",
        path: "/api/v1/files/{id}/shares",
        target: "/api/v1/files/{file}/shares",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/shares",
        target: "/api/v1/files/{file}/shares",
        body: Some(r#"{"audience":"INTERNAL","permission":"VIEW"}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "PATCH",
        path: "/api/v1/shares/{id}",
        target: "/api/v1/shares/{share}",
        body: Some(r#"{"permission":"VIEW"}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "DELETE",
        path: "/api/v1/shares/{id}",
        target: "/api/v1/shares/{share}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // Delivery (docs/05-API.md §9). All five name a real file the caller may download, print and
    // export — and answer `404`, because the fixture file has no committed version and therefore no
    // bytes. That is the correct answer, and it is also the *ceiling* of what this test can say
    // about these five: the spine seeds rows, not content, so nothing here distinguishes "the
    // pipeline refused" from "there was nothing to render".
    //
    // What that ceiling no longer hides is the wiring. `ENC-770` gave this deployment a real
    // `BlobStore` and `ENC-798` gave it a real rendition pipeline, so a file that *did* have bytes
    // would now be served rather than answered `500`. Proving that needs an upload the probe cannot
    // perform — it would have to PUT to a pre-signed URL and then wait for an antivirus pass — so it
    // is proved in `crates/preview/tests/pipeline.rs` against the same composition instead.
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/download",
        target: "/api/v1/files/{file}/download",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "GET",
        path: "/api/v1/files/{id}/preview",
        target: "/api/v1/files/{file}/preview",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Search (docs/05-API.md §11).
    Spec {
        method: "POST",
        path: "/api/v1/search",
        target: "/api/v1/search",
        body: Some(r#"{"query":"smoke"}"#),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/files/{id}/thumbnail",
        target: "/api/v1/files/{file}/thumbnail",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/export",
        target: "/api/v1/files/{file}/export",
        body: Some(r#"{"format":"pdf"}"#),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/print-token",
        target: "/api/v1/files/{file}/print-token",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/print",
        target: "/api/v1/files/{file}/print",
        // A token this suite cannot have — the seeded spine has no grant, and minting one would
        // make this a functional test of the redemption rather than a check that the route is on
        // the router. What it proves is the thing it exists to prove: the path resolves to a
        // handler, the handler runs the chain, and the answer is a `404` rather than the `405` or
        // the connection-refused an unregistered route gives. The redemption's actual behaviour is
        // `crates/api/tests/delivery_routes.rs`.
        body: Some(r#"{"token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Sync (docs/05-API.md §13).
    Spec {
        method: "GET",
        path: "/api/v1/sync/devices",
        target: "/api/v1/sync/devices",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/sync/devices",
        target: "/api/v1/sync/devices",
        body: Some(r#"{"name":"smoke","platform":"LINUX","clientVersion":"0.0.0"}"#),
        credential: Credential::Bearer,
        expect: Expect::Unreachable {
            status: 403,
            tracker: "ENC-736",
            why: "enrolling a device asks `container.create` on the caller's own `users` row. \
                  `SelfServiceAuthorization` permits a principal to *read* itself and nothing \
                  more, and `PgAclAuthorization` calls a `USER` resource `Unsupported`, so the \
                  composed binary has no service that can answer the question at all — the \
                  tenant's own administrator, holding every ACL grant, is refused",
        },
    },
    Spec {
        method: "POST",
        path: "/api/v1/sync/devices/{id}/wipe",
        target: "/api/v1/sync/devices/{unknown}/wipe",
        body: Some("{}"),
        credential: Credential::Bearer,
        // The same refusal as the row above, rendered as `404` by the handler's deliberate
        // AccessDenied → NotFound mapping. Permitted here rather than quarantined, because a
        // device that does not exist is also a `404` and this probe cannot tell the two apart.
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "GET",
        path: "/api/v1/sync/delta",
        target: "/api/v1/sync/delta?scope=library:{lib}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/sync/reserve",
        target: "/api/v1/sync/reserve",
        body: Some(
            r#"{"fileId":"{file}","deviceId":"{unknown}","sizeBytes":11,"checksumSha256":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
        ),
        credential: Credential::Bearer,
        // The device is not registered — and cannot be, per `ENC-736` above — so the reservation
        // correctly finds nothing.
        expect: Expect::ServedOrAbsent,
    },
    // Administration (docs/05-API.md §14). The caller is the tenant administrator, so the two reads
    // answer `200`; every mutation is refused for want of a second factor nothing can supply.
    Spec {
        method: "GET",
        path: "/api/v1/admin/conditional-access/rules",
        target: "/api/v1/admin/conditional-access/rules",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/admin/conditional-access/rules",
        target: "/api/v1/admin/conditional-access/rules",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: STEP_UP,
    },
    Spec {
        method: "PATCH",
        path: "/api/v1/admin/conditional-access/rules/{id}",
        target: "/api/v1/admin/conditional-access/rules/{unknown}",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "DELETE",
        path: "/api/v1/admin/conditional-access/rules/{id}",
        target: "/api/v1/admin/conditional-access/rules/{unknown}",
        body: None,
        credential: Credential::Bearer,
        // `ServedOrAbsent`: the probe withdraws a rule id nothing created, so `404` is the correct
        // answer and not a refusal. It was `STEP_UP` while ENC-771 made every admin mutation
        // unreachable, and the quarantine's own instruction was to delete the entry once the wiring
        // was fixed rather than to keep asserting a status that had stopped being true.
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "GET",
        path: "/api/v1/admin/dlp/rules",
        target: "/api/v1/admin/dlp/rules",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // `ENC-943`'s four routes, **added by `ENC-946` because they were never added at all**. They
    // shipped without entries here, this test went red on `main` the moment they merged, and
    // nothing said so: the CI queue had not drained a run since. That is `ENC-941`'s cost paid in
    // full — a gate that works, on a merge nobody built, is a gate that is off.
    Spec {
        method: "GET",
        path: "/api/v1/admin/retention/policies",
        target: "/api/v1/admin/retention/policies",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    // The body is a valid policy the schema accepts: `KEEP` needs no duration, and `CREATED` needs
    // no event key. A body the constraints refuse would answer `422` — still `Served`, and still a
    // pass, but it would stop proving that the route reaches its handler rather than its parser.
    Spec {
        method: "POST",
        path: "/api/v1/admin/retention/policies",
        target: "/api/v1/admin/retention/policies",
        body: Some(r#"{"name":"reachability-probe","action":"KEEP","basis":"CREATED"}"#),
        credential: Credential::Bearer,
        expect: STEP_UP,
    },
    // `{id}` names no policy this fixture created, so the composite foreign key refuses the insert
    // and the handler renders `422 POLICY_REJECTED` — an answer, from the handler, which is what
    // this suite asks about.
    Spec {
        method: "POST",
        path: "/api/v1/admin/retention/policies/{id}/assignments",
        target: "/api/v1/admin/retention/policies/00000000-0000-0000-0000-000000000000/assignments",
        body: Some(r#"{"scopeType":"TENANT"}"#),
        credential: Credential::Bearer,
        expect: STEP_UP,
    },
    // `ServedOrAbsent`: withdrawing an assignment that does not exist is `404 ASSIGNMENT_NOT_FOUND`
    // by design — already-withdrawn and never-existed are deliberately one answer — so the `404`
    // this route gives a probe is the correct answer rather than an unreachable handler.
    Spec {
        method: "DELETE",
        path: "/api/v1/admin/retention/policies/{id}/assignments",
        target: "/api/v1/admin/retention/policies/00000000-0000-0000-0000-000000000000/assignments?scopeType=TENANT",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // `ENC-916`. Provisioning is an administrative act against the tenant, not a container action:
    // `classify` calls a tenant reference `Target::Unsupported`, so `crates/authorization/admin.rs`
    // is the only door that opens it. It carries the same step-up requirement as its neighbours
    // here, which is why it sits in this block rather than beside `GET /workspaces`.
    Spec {
        method: "POST",
        path: "/api/v1/admin/workspaces",
        target: "/api/v1/admin/workspaces",
        body: Some(r#"{"name":"Reachability Probe","slug":"reachability-probe-ws"}"#),
        credential: Credential::Bearer,
        expect: STEP_UP,
    },
    Spec {
        method: "POST",
        path: "/api/v1/admin/dlp/rules",
        target: "/api/v1/admin/dlp/rules",
        body: Some(
            r#"{"name":"reachability-probe","scope":["external_sharing"],"conditions":[],"action":"BLOCK"}"#,
        ),
        credential: Credential::Bearer,
        expect: STEP_UP,
    },
    Spec {
        method: "DELETE",
        path: "/api/v1/admin/dlp/rules/{id}",
        target: "/api/v1/admin/dlp/rules/{unknown}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Workflows (docs/05-API.md §16).
    Spec {
        method: "GET",
        path: "/api/v1/workflows/tasks",
        target: "/api/v1/workflows/tasks",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/files/{id}/workflows",
        target: "/api/v1/files/{file}/workflows",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "POST",
        path: "/api/v1/workflows/definitions/{id}/simulate",
        target: "/api/v1/workflows/definitions/{unknown}/simulate",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/api/v1/workflows/instances/{id}",
        target: "/api/v1/workflows/instances/{unknown}",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/workflows/instances/{id}/cancel",
        target: "/api/v1/workflows/instances/{unknown}/cancel",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/workflows/steps/{id}/approve",
        target: "/api/v1/workflows/steps/{unknown}/approve",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/workflows/steps/{id}/reject",
        target: "/api/v1/workflows/steps/{unknown}/reject",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    Spec {
        method: "POST",
        path: "/api/v1/workflows/steps/{id}/delegate",
        target: "/api/v1/workflows/steps/{unknown}/delegate",
        body: Some("{}"),
        credential: Credential::Bearer,
        expect: Expect::ServedOrAbsent,
    },
    // Operational probes. Unauthenticated by design; on the policy-routing allowlist.
    Spec {
        method: "GET",
        path: "/health/live",
        target: "/health/live",
        body: None,
        credential: Credential::None,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/health/ready",
        target: "/health/ready",
        body: None,
        credential: Credential::None,
        expect: Expect::Served,
    },
    // The dependency report (docs/05-API.md §19, `ENC-726`), probed on both of its halves for the
    // reason `/api/v1/bootstrap` above gives. This one has a *second* ENC-170 exposure the others
    // do not: `dependencies` extracts `Extension<Arc<dyn BlobStore>>`, and `download` and `preview`
    // are the two routes that shipped extracting an extension the binary never attached and
    // answered `500` for a milestone while every in-process test passed. The anonymous probe is
    // what would see it, because it reaches the extractor before it reaches anything else.
    Spec {
        method: "GET",
        path: "/health/dependencies",
        target: "/health/dependencies",
        body: None,
        credential: Credential::None,
        expect: Expect::Served,
    },
    Spec {
        method: "GET",
        path: "/health/dependencies",
        target: "/health/dependencies",
        body: None,
        credential: Credential::Bearer,
        expect: Expect::Served,
    },
];

// -------------------------------------------------------------------------------------------
// Deriving the route list from the source (never writing it down)
// -------------------------------------------------------------------------------------------

/// One `.route(path, method(handler))` registration, as read out of the source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Registration {
    method: String,
    path: String,
    /// The handler's path as written at the registration, e.g. `routes::uploads::create`.
    handler: String,
}

/// The method-router constructors `axum::routing` exports, and therefore the ones a registration
/// can name. The same list `xtask/src/policy_routing.rs` matches on.
const METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options", "trace"];

/// `crates/api/src`, from the manifest directory rather than the working directory — `cargo test`
/// runs a test binary from the workspace root and `cargo test -p` does not.
fn api_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every route the router registers, parsed out of `crates/api/src/lib.rs`.
///
/// A parser rather than a list, and a parser of *that* file rather than of a generated artefact,
/// because `router()`'s own doc comment commits to the shape this reads: full path literals, one
/// named handler function per method, no `nest`. The policy-routing gate depends on the same
/// property, so a change that broke this parse would already be failing CI elsewhere.
fn registered_routes() -> Vec<Registration> {
    let source = std::fs::read_to_string(api_src().join("lib.rs")).expect("read lib.rs");
    let source = strip_comments(&source);

    let mut routes = Vec::new();
    let mut rest = source.as_str();
    while let Some(at) = rest.find(".route(") {
        let call = balanced(&rest[at + ".route(".len() - 1..]).expect("unbalanced .route( call");
        rest = &rest[at + ".route(".len()..];

        let path = string_literal(call).expect("a route registration with no path literal");
        for (method, handler) in method_routers(call) {
            routes.push(Registration {
                method: method.to_uppercase(),
                path: path.clone(),
                handler,
            });
        }
    }
    routes
}

/// The `(method, handler)` pairs inside one `.route(…)` call, including a chained
/// `get(a).post(b)`.
fn method_routers(call: &str) -> Vec<(String, String)> {
    let bytes = call.as_bytes();
    let mut found = Vec::new();
    for method in METHODS {
        let mut from = 0;
        while let Some(at) = call[from..].find(&format!("{method}(")) {
            let start = from + at;
            from = start + method.len();
            // `delete(` inside `.delete(` is the same call; `get(` inside `widget(` is not.
            let preceded_by_ident = start > 0 && {
                let previous = bytes[start - 1];
                previous.is_ascii_alphanumeric() || previous == b'_'
            };
            if preceded_by_ident {
                continue;
            }
            let args = &call[start + method.len()..];
            let args = balanced(args).expect("unbalanced method-router call");
            let handler = args.trim_matches(|c| c == '(' || c == ')').trim();
            if handler.is_empty()
                || !handler.chars().all(|c| c.is_alphanumeric() || c == '_' || c == ':')
            {
                continue;
            }
            found.push(((*method).to_owned(), handler.to_owned()));
        }
    }
    found
}

/// The slice from an opening `(` to its matching `)`, inclusive. String literals are respected so a
/// bracket inside a path cannot unbalance the scan.
fn balanced(from: &str) -> Option<&str> {
    let bytes = from.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&from[..=index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The first string literal in a slice.
fn string_literal(from: &str) -> Option<String> {
    let start = from.find('"')? + 1;
    let end = start + from[start..].find('"')?;
    Some(from[start..end].to_owned())
}

/// Replaces `//` comments with spaces, leaving string literals alone.
///
/// The router's registrations are interleaved with paragraphs of prose that mention paths and
/// method names; without this the parse would find routes in the commentary.
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => {
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Every `pub async fn` in `crates/api/src` that takes axum's `State<ApiState>` — which is to say,
/// every function that is an HTTP handler.
///
/// Returned as `module::name`, the same spelling a registration in `lib.rs` uses, so the two are
/// comparable without name resolution. Bare names would not be: `create` is a handler in both
/// `routes/shares.rs` and `routes/uploads.rs`, and `list_rules` in both admin modules, so a
/// bare-name comparison would report a deleted registration as still covered by its namesake.
fn handlers_with_state() -> BTreeSet<String> {
    let mut handlers = BTreeSet::new();
    for file in rust_files(&api_src()) {
        let module = module_path(&file);
        // The router and the composition root are not modules a handler is reached through.
        if module.is_empty() || module == "main" {
            continue;
        }
        let source = strip_comments(&std::fs::read_to_string(&file).expect("read a source file"));
        let mut rest = source.as_str();
        while let Some(at) = rest.find("pub async fn ") {
            rest = &rest[at + "pub async fn ".len()..];
            let Some(open) = rest.find('(') else { break };
            let name = rest[..open].trim();
            let Some(params) = balanced(&rest[open..]) else { break };
            if params.contains("State<ApiState>") {
                handlers.insert(format!("{module}::{name}"));
            }
        }
    }
    handlers
}

/// Every `.rs` file under a directory, recursively.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).expect("read a source directory") {
            let path = entry.expect("read a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// The module path a file defines, relative to the crate root: `src/admin/dlp.rs` → `admin::dlp`.
fn module_path(file: &Path) -> String {
    let relative = file.strip_prefix(api_src()).expect("a file under src/");
    let mut segments: Vec<String> = relative
        .with_extension("")
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if segments.last().is_some_and(|last| last == "mod" || last == "lib") {
        segments.pop();
    }
    segments.join("::")
}

// -------------------------------------------------------------------------------------------
// The two source-only checks
// -------------------------------------------------------------------------------------------

/// The derived registrations and [`SPECS`] must agree exactly, in both directions.
///
/// This is what stops the table above from becoming the hand-maintained list `ENC-543` warns
/// about. A route added to the router with no spec fails here rather than going unprobed for a
/// milestone; a spec whose route was deleted fails here rather than silently asserting nothing.
#[test]
fn every_registered_route_has_a_request_specification() {
    let registered: BTreeSet<(String, String)> =
        registered_routes().into_iter().map(|route| (route.method, route.path)).collect();
    let specified: BTreeSet<(String, String)> =
        SPECS.iter().map(|spec| (spec.method.to_owned(), spec.path.to_owned())).collect();

    // The positive control. "The two sets are equal" also holds when both are empty, which is what
    // a parser that silently stopped matching would produce.
    assert!(
        registered.len() >= 40,
        "only {} route registrations were parsed out of crates/api/src/lib.rs. The router \
         registers more than that, so the parse in `registered_routes` has stopped matching the \
         source it reads",
        registered.len()
    );
    // One named route, as the second half of the same control — a parse that returned forty
    // plausible-looking entries from the wrong file would still pass the count. `login` and not
    // `/me`, deliberately: an anchor naming a route this test also specifies would report the
    // *deletion* of that route as "the parser broke", which is the diff below's job to say.
    assert!(
        registered.contains(&("POST".to_owned(), "/api/v1/auth/login".to_owned())),
        "the parse did not find POST /api/v1/auth/login, so it is not reading the router"
    );

    let unspecified: Vec<_> = registered.difference(&specified).collect();
    assert!(
        unspecified.is_empty(),
        "these routes are registered and this test does not probe them — add a Spec for each, \
         with the request that proves it answers: {unspecified:#?}"
    );

    let stale: Vec<_> = specified.difference(&registered).collect();
    assert!(
        stale.is_empty(),
        "these routes have a Spec and are no longer registered on the router. Either the \
         registration was deleted — in which case the endpoint is unreachable and that is the \
         defect this suite exists to catch — or it was renamed and the Spec must follow: {stale:#?}"
    );
}

/// Every handler in the crate is registered on the router.
///
/// **This is the check that would have caught the original defect.** `crates/api` held handlers for
/// endpoints `docs/05-API.md` documents and registered ten of them; the handlers compiled, were
/// unit-tested, and could not be reached by any client. A route list derived from the router alone
/// cannot see that, because an unregistered handler is absent from it by definition.
#[test]
fn every_handler_in_the_crate_is_registered() {
    let registered: BTreeSet<String> =
        registered_routes().into_iter().map(|route| route.handler).collect();
    let handlers = handlers_with_state();

    assert!(
        handlers.len() >= 40,
        "only {} handlers were found under crates/api/src. The crate has more, so the scan in \
         `handlers_with_state` has stopped recognising a handler signature",
        handlers.len()
    );

    let unrouted: Vec<&String> =
        handlers.iter().filter(|handler| !registered.contains(*handler)).collect();
    assert!(
        unrouted.is_empty(),
        "these functions take axum's State<ApiState> — they are HTTP handlers — and no route \
         registers them, so no client can reach them however correct they are: {unrouted:#?}"
    );
}

// -------------------------------------------------------------------------------------------
// The running server
// -------------------------------------------------------------------------------------------

/// The host every request is sent to. `resolve_routed_tenant` reads the first label as the tenant's
/// slug and requires at least two labels, so `localhost` would route no tenant and every login
/// would answer `404`.
const HOST: &str = "tenant-alpha.enclave.test";

/// The fixture account. The tenant administrator, because `AdminAuthorization` decides
/// `Action::Admin` from `users.is_admin` and the two admin read endpoints would otherwise be a
/// legitimate `403` this test could not tell from an unwired one.
const EMAIL: &str = "admin@tenant-alpha.example";

/// The fixture account's password.
///
/// Assembled at run time rather than written as a literal, which is `CLAUDE.md` rule 11's practice
/// in miniature and the shape `crates/api/tests/auth_postgres.rs` already uses: a test that reads
/// server responses must not be able to find its own credential in its own source. Long enough for
/// `security.password.min_length`, which the hasher checks before it hashes.
fn fixture_password() -> String {
    format!("reachability-{}-passphrase", 767)
}

/// A child `enclave-api`, its scratch directory and its log, killed and removed on drop.
struct Server {
    child: Child,
    port: u16,
    directory: PathBuf,
}

impl Server {
    /// Starts the binary against `database_url`, in a scratch directory holding its `enclave.yaml`.
    ///
    /// # The configuration is written here, not fetched from `deploy/`
    ///
    /// Deliberately: `deploy/config/enclave.example.yaml` is tuned for the Compose stack and names
    /// ports a test must not bind. What this writes is the same *shape* — `env://` references for
    /// both DSNs, the `*_env` spellings for the rest — so the recipe in `README.md` and the one
    /// exercised here cannot drift into two different things.
    fn start(database_url: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("enclave-reachability-{}", std::process::id()));
        let _ignored = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create the scratch directory");

        // The port is chosen here rather than left to the OS. `server.port: 0` does bind an
        // ephemeral port, and the start-up banner then reports `127.0.0.1:0` — it logs the address
        // the process was *asked* for, before the listener resolves it — so there is no way to
        // learn the port from outside. Bind-then-release has a window; a bound port is retried.
        let port = free_port();
        std::fs::write(directory.join("enclave.yaml"), config(port)).expect("write enclave.yaml");

        let binary = env!("CARGO_BIN_EXE_enclave-api");
        let log = std::fs::File::create(directory.join("api.log")).expect("create the log");
        let child = Command::new(binary)
            .current_dir(&directory)
            // `ConfigLoader::new().with_file("enclave.yaml")` reads the *working directory*. There
            // is no environment variable for the path, which is the single most surprising thing
            // about starting this binary and is why README.md now says it first.
            .env("DATABASE_URL", database_url)
            // Without this every login answers `404`: `tenants` carries no `tenant_id`, so it has
            // no row-level-security policy and `enclave_app` is granted nothing on it. The routed
            // tenant lookup runs as `enclave_platform` or not at all.
            .env("DATABASE_PLATFORM_URL", database_url)
            // Neither service is contacted by `enclave-api`. They are here because the
            // configuration *references* them, and an unresolvable reference is a start-up failure
            // — which is the right behaviour and a surprising one to meet for the first time at
            // 2am.
            .env("REDIS_URL", "redis://127.0.0.1:6379")
            .env("NATS_URL", "nats://127.0.0.1:4222")
            // **Inherited, not invented** (`ENC-796`). These were the literals `"reachability"`,
            // which was correct while `main.rs` bound `Delivery::unconfigured()` and never touched
            // object storage. `ENC-770` made it compose the real store from `storage.s3` *and*
            // self-check the bucket at start-up, so the binary now refuses to start with
            // `InvalidAccessKeyId` and this test fails before it reads a single route — which is
            // the right behaviour from `main.rs` and a stale fixture here.
            //
            // Taking them from the test process's own environment is what keeps
            // `Server::start`'s promise above true: the recipe in `README.md` §"Running the server"
            // and the one exercised here are now literally the same two variables. No value is
            // written down (`CLAUDE.md` rule 11); an unset variable falls back to a placeholder,
            // which fails loudly at start-up with the log attached rather than silently.
            .env("S3_ACCESS_KEY_ID", inherited("S3_ACCESS_KEY_ID"))
            .env("S3_SECRET_ACCESS_KEY", inherited("S3_SECRET_ACCESS_KEY"))
            .env("RUST_LOG", "info")
            .stdout(log.try_clone().expect("clone the log handle"))
            .stderr(log)
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {binary}: {error}"));

        let server = Self { child, port, directory };
        server.wait_until_ready();
        server
    }

    /// Polls the liveness probe until the process answers, or fails carrying the log.
    fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let answered = try_request(self.port, "GET", "/health/live", &[], None)
                .is_some_and(|response| response.status == 200);
            if answered {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "enclave-api never answered /health/live on port {}. Its log follows:\n{}",
            self.port,
            self.log()
        );
    }

    /// The child's log, for a failure message. A test that says only "it did not start" is a test
    /// somebody has to reproduce by hand.
    fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("api.log")).unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ignored = self.child.kill();
        let _ignored = self.child.wait();
        let _ignored = std::fs::remove_dir_all(&self.directory);
    }
}

/// One environment variable, passed through to the child, or a placeholder that will fail loudly.
///
/// The placeholder is deliberately not a plausible credential: if the variable is unset, the child
/// refuses to start and `wait_until_ready` prints its log, which names the variable in the S3
/// error. A default that happened to work on one machine would make the test's requirement
/// invisible everywhere else.
fn inherited(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| format!("unset-{name}"))
}

/// A port nothing is listening on, released immediately before the child is told to bind it.
fn free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind :0");
    listener.local_addr().expect("read the bound address").port()
}

/// The `enclave.yaml` the child reads.
fn config(port: u16) -> String {
    format!(
        "profile: community\n\
         \n\
         # ENC-771: this binary configures no MFA verifier, so demanding a second factor of\n\
         # administrators would make every /admin/** mutation unsatisfiable. `main.rs` refuses to\n\
         # start on that pairing rather than serving a surface nobody can use, and this is the test\n\
         # deployment saying which of the two honest answers it wants.\n\
         security:\n  \
           mfa:\n    \
             admins_required: false\n\
         \n\
         server:\n  \
           bind: \"127.0.0.1\"\n  \
           port: {port}\n  \
           public_url: \"http://127.0.0.1:{port}\"\n\
         \n\
         database:\n  \
           url_env: \"DATABASE_URL\"\n  \
           platform_url_env: \"DATABASE_PLATFORM_URL\"\n  \
           application_role: \"enclave_app\"\n\
         \n\
         redis:\n  url_env: \"REDIS_URL\"\n\
         \n\
         events:\n  nats_url_env: \"NATS_URL\"\n\
         \n\
         auth:\n  \
           access_token:\n    \
             audience: \"enclave-api\"\n  \
           signing_keys:\n    \
             directory: \"dev-keys\"\n\
         \n\
         storage:\n  \
           provider: \"s3\"\n  \
           s3:\n    \
             bucket: \"enclave-content\"\n    \
             region: \"us-east-1\"\n    \
             endpoint: \"http://127.0.0.1:9000\"\n    \
             flavor: \"minio\"\n    \
             path_style: true\n    \
             access_key_id: \"env://S3_ACCESS_KEY_ID\"\n    \
             secret_access_key: \"env://S3_SECRET_ACCESS_KEY\"\n"
    )
}

// -------------------------------------------------------------------------------------------
// An HTTP/1.1 client, because the workspace has no client and does not need one
// -------------------------------------------------------------------------------------------

/// One response, reduced to what the assertions read.
#[derive(Debug, Clone)]
struct Response {
    status: u16,
    /// Every `Set-Cookie`, verbatim.
    cookies: Vec<String>,
    body: String,
}

/// Sends one request and reads the whole response.
///
/// Hand-written rather than a client dependency: `reqwest` is not in this workspace and adding a
/// TLS stack, a connection pool and forty transitive crates to speak plaintext HTTP/1.1 to
/// `127.0.0.1` would be a poor trade. `Connection: close` makes the response frame trivially
/// `read_to_end`, and every request opens its own connection.
fn try_request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, String)],
    body: Option<&str>,
) -> Option<Response> {
    let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok()?;

    let mut request =
        format!("{method} {target} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }

    stream.write_all(request.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let raw = String::from_utf8_lossy(&raw).into_owned();

    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let cookies = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.trim().to_owned())
        .collect();

    Some(Response { status, cookies, body: body.to_owned() })
}

/// [`try_request`], for a request that must succeed at the transport level.
fn request(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, String)],
    body: Option<&str>,
) -> Response {
    try_request(port, method, target, headers, body)
        .unwrap_or_else(|| panic!("{method} {target}: the server did not answer at all"))
}

/// The value of one JSON string field, without a JSON parser.
///
/// The test needs exactly two fields out of two responses and `serde_json` would do it properly —
/// this is here so that a malformed body produces `None` and a named assertion rather than a panic
/// inside a parser.
fn json_string(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let start = body.find(&needle)? + needle.len();
    let end = start + body[start..].find('"')?;
    Some(body[start..end].to_owned())
}

// -------------------------------------------------------------------------------------------
// The smoke run
// -------------------------------------------------------------------------------------------

/// The identifiers a request template can name.
#[derive(Debug, Default)]
struct Fixtures {
    /// The spine's workspace — the container the grant loop below hangs every action on, and
    /// therefore the one the navigation probes can require an answer other than `404` for.
    workspace: String,
    library: String,
    file: String,
    /// An identifier of the right shape that names nothing. Fixed rather than random, so a failure
    /// message is the same on two runs.
    unknown: String,
    /// The share link created by the `POST /files/{id}/shares` probe, so the two `/shares/{id}`
    /// probes name a share that exists rather than asserting nothing against a `404`.
    share: Option<String>,
}

impl Fixtures {
    fn fill(&self, template: &str) -> String {
        template
            .replace("{ws}", &self.workspace)
            .replace("{lib}", &self.library)
            .replace("{file}", &self.file)
            .replace("{unknown}", &self.unknown)
            .replace("{share}", self.share.as_deref().unwrap_or(&self.unknown))
    }
}

/// **The test.** Every registered route, against the binary, with a token it minted itself.
///
/// `#[ignore]` for the reason every database-backed test in this crate carries it — it needs a
/// live PostgreSQL and CI runs it with `--include-ignored`, in a job of its own. The two checks
/// above are deliberately *not* ignored: they read source and nothing else, so the derived route
/// list is compared against the router on every machine and in every job that compiles this
/// crate, whether or not a database is anywhere near it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn every_registered_route_answers_an_authenticated_caller() {
    let db = TestDb::start().await.unwrap_or_else(|error| {
        panic!(
            "this test needs a real PostgreSQL — README.md §\"Running the server\" has the whole \
             recipe: {error}"
        )
    });
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let alpha = fixtures.alpha;

    // The spine the content, sharing, sync and workflow probes name, and the grants that make the
    // caller one "who should be allowed". Every action of every family, at the top of the chain, so
    // that a `403` from any route below is a wiring defect and never a missing grant.
    let mut conn = db.connect().await.expect("connect");
    let spine = Spine::new(alpha.id);
    spine.insert(&mut conn, alpha.admin, chrono::Utc::now()).await.expect("write the spine");
    for action in every_action() {
        grant(
            &mut conn,
            alpha.id,
            AclScope::Workspace(spine.workspace),
            AclPrincipal::User(alpha.admin),
            action,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("grant an action");
    }

    // The credential. `enclave-cli set-password` is the operator's path to this row and writes
    // exactly this statement (crates/cli/src/password.rs); it is inlined rather than shelled out to
    // because `CARGO_BIN_EXE_` is only set for binaries of the package under test, and building a
    // second crate from inside a test would put a nested cargo invocation on this suite's critical
    // path.
    let hasher = enclave_auth::PasswordHasher::new(enclave_auth::PasswordPolicy::default())
        .expect("the default password policy");
    let password = fixture_password();
    let hash = hasher.hash(&password).expect("hash the fixture password");
    sqlx::query(
        "INSERT INTO user_credentials
           (user_id, tenant_id, password_hash, algorithm, changed_at, must_change,
            failed_attempts, locked_until)
         VALUES ($1, $2, $3, 'argon2id', now(), FALSE, 0, NULL)",
    )
    .bind(alpha.admin.as_uuid())
    .bind(alpha.id.as_uuid())
    .bind(&hash)
    .execute(&mut conn)
    .await
    .expect("write the credential");
    drop(conn);

    let server = Server::start(db.url());
    let port = server.port;

    // ---------------------------------------------------------------------------------------
    // The login. Everything after this depends on it, so it is asserted on its own terms first:
    // a failure here is defect 2 (no signing key, `503`) or a tenant that did not route (`404`),
    // and neither should be reported as "forty routes failed".
    // ---------------------------------------------------------------------------------------
    let credentials = format!(r#"{{"email":"{EMAIL}","password":"{password}"}}"#);
    let login = request(port, "POST", "/api/v1/auth/login", &[], Some(&credentials));
    assert_eq!(
        login.status,
        200,
        "POST /api/v1/auth/login answered {} for a seeded account with a freshly written \
         credential. Nothing downstream of this can be asserted. Body: {}\n\nThe server's log:\n{}",
        login.status,
        login.body,
        server.log(),
    );
    let token = json_string(&login.body, "accessToken")
        .unwrap_or_else(|| panic!("login answered 200 with no accessToken: {}", login.body));
    let cookies: Vec<String> = login
        .cookies
        .iter()
        .filter_map(|cookie| cookie.split(';').next())
        .map(str::to_owned)
        .collect();
    let csrf = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("enclave_csrf="))
        .unwrap_or_default()
        .to_owned();

    let mut fixture_ids = Fixtures {
        workspace: spine.workspace.as_uuid().to_string(),
        library: spine.library.as_uuid().to_string(),
        file: spine.file.as_uuid().to_string(),
        unknown: "00000000-0000-4000-8000-000000000000".to_owned(),
        share: None,
    };

    // ---------------------------------------------------------------------------------------
    // Every route.
    // ---------------------------------------------------------------------------------------
    println!("\nreachability — every registered route, against target/debug/enclave-api");
    println!("  caller: {EMAIL} (tenant administrator, every ACL action granted at the workspace)");
    print_quarantine();
    println!();

    let mut failures: Vec<String> = Vec::new();
    for spec in probe_order() {
        let target = fixture_ids.fill(spec.target);
        let body = spec.body.map(|body| fixture_ids.fill(body));
        let body = if spec.path == "/api/v1/auth/login" { Some(credentials.clone()) } else { body };

        let mut headers: Vec<(&str, String)> = Vec::new();
        match spec.credential {
            Credential::None => {}
            Credential::Bearer => headers.push(("Authorization", format!("Bearer {token}"))),
            Credential::RefreshCookie => {
                headers.push(("Cookie", cookies.join("; ")));
                headers.push(("x-csrf-token", csrf.clone()));
            }
        }

        let response = request(port, spec.method, &target, &headers, body.as_deref());
        println!("  {:>6} {:<52} {}", spec.method, target, response.status);

        if spec.path == "/api/v1/files/{id}/shares" && spec.method == "POST" {
            fixture_ids.share = json_string(&response.body, "id");
        }

        if let Some(failure) = verdict(spec, &response) {
            failures.push(failure);
        }
    }

    assert!(
        failures.is_empty(),
        "\n{} of {} registered routes are unreachable to a caller who holds every grant. Each of \
         these was answered by the composed binary, not by a router a test assembled.{}\n\n{}\n\n\
         The server's log:\n{}",
        failures.len(),
        SPECS.len(),
        breadth_hint(failures.len(), SPECS.len()),
        failures.join("\n\n"),
        server.log(),
    );
}

/// The specs, with the two session-destroying probes moved to the end.
///
/// `logout` revokes the caller's refresh family and `logout-all` bumps `token_epoch`. Neither
/// invalidates the access token this test holds — the window is the access token's own lifetime,
/// which is `docs/03-LLD.md §5`'s design — but a probe whose side effect could decide the verdict
/// of a later one has no business running before it.
fn probe_order() -> Vec<&'static Spec> {
    let mut order: Vec<&Spec> = SPECS.iter().collect();
    order.sort_by_key(|spec| {
        u8::from(spec.path == "/api/v1/auth/logout" || spec.path == "/api/v1/auth/logout-all")
    });
    order
}

/// A sentence about the *breadth* of the failure, which is the thing a per-route message cannot
/// say and the thing that points at the right layer.
///
/// Written after watching the issuer break: pointing `ApiState`'s issuer at a second string makes
/// **thirty-six of forty-seven** routes answer `403 ACCESS_DENIED`, and each one on its own reads
/// as a permissions problem — which is exactly where the four hours went the first time. One route
/// refused is an authorization question; most of them refused at once is a question about the
/// token, upstream of authorization entirely.
fn breadth_hint(failed: usize, total: usize) -> &'static str {
    if failed * 2 > total {
        return "\n\n  Most of the surface failed at once. Before reading any single route below: \
                that is the signature of a defect *upstream* of authorization, not of many \
                separate permission bugs. The token this deployment mints and the token it \
                verifies must agree on `iss` and `aud` — see `access_token_issuer` in \
                crates/api/src/main.rs, which exists because they once did not.";
    }
    ""
}

/// What is wrong with one answer, or `None`.
fn verdict(spec: &Spec, response: &Response) -> Option<String> {
    let where_ = format!("{} {}", spec.method, spec.path);
    let body = response.body.trim();
    let body = &body[..body.len().min(300)];

    match spec.expect {
        Expect::Unreachable { status, tracker, why } => (response.status != status).then(|| {
            format!(
                "{where_}\n  answered {} and this test records it as answering {status}.\n  \
                 {tracker}: {why}\n  If the wiring was fixed, delete the quarantine entry — that \
                 is what it is for. If it changed for another reason, the entry is now wrong.\n  \
                 Body: {body}",
                response.status,
            )
        }),
        Expect::Served | Expect::ServedOrAbsent => {
            let refusal = match response.status {
                401 => Some(
                    "401 — the token this deployment minted was rejected by the deployment that \
                     minted it. That is the issuer seam (M5a step 1): one value has to reach the \
                     minting site and the verifying site from one place",
                ),
                403 => Some(
                    "403 — a caller holding every ACL action on this resource was refused. The \
                     binary is composing an authorization service that cannot answer the question",
                ),
                503 => Some(
                    "503 — a dependency this route needs was never wired into the binary. Every \
                     integration test supplies it, which is why nothing else sees this",
                ),
                500 => Some(
                    "500 — the handler faulted. ENC-170's shape: a route registered without \
                     something the binary was supposed to compose",
                ),
                404 if spec.expect == Expect::Served => Some(
                    "404 — this request named a fixture the caller was granted every action on, so \
                     the resource exists and is visible. CLAUDE.md rule 7 renders a barrier or \
                     cross-tenant denial as 404, so this is a refusal wearing another status",
                ),
                _ => None,
            };
            refusal.map(|reason| format!("{where_}\n  {reason}.\n  Body: {body}"))
        }
    }
}

/// Prints the quarantined routes and their reasons on every run.
///
/// `xtask/src/policy_routing.rs` prints its allowlist for the same reason, in the same place: an
/// exemption that lives only in a `const` is one nobody meets, and "this endpoint cannot be reached
/// by anybody" is a sentence that belongs in the log of every run.
fn print_quarantine() {
    let quarantined: Vec<&Spec> =
        SPECS.iter().filter(|spec| matches!(spec.expect, Expect::Unreachable { .. })).collect();
    println!(
        "\n  {} route(s) are UNREACHABLE in the composed binary and are asserted to stay that way \
         until their row is closed:",
        quarantined.len()
    );
    for spec in quarantined {
        let Expect::Unreachable { status, tracker, why } = spec.expect else { continue };
        println!("    {} {} — {status}, {tracker}", spec.method, spec.path);
        println!("        {why}");
    }
}

/// Every action in every family, so the grant loop cannot forget one when a variant is added.
fn every_action() -> Vec<Action> {
    let mut actions: Vec<Action> = Vec::new();
    actions.extend(FileAction::all().iter().copied().map(Action::File));
    actions.extend(ContainerAction::all().iter().copied().map(Action::Container));
    actions.extend(ShareAction::all().iter().copied().map(Action::Share));
    // `Action::Admin` is deliberately absent: administrative authority comes from `users.is_admin`
    // through `AdminAuthorization`, not from an ACL entry, and `acl_entries` has no resource an
    // admin action would hang on. The caller is the seeded administrator instead.
    actions
}

/// The parse's own tests. `docs/12-TESTING.md §1.2`: a derivation that silently matches nothing
/// passes every assertion about the routes it did not find, so the parse is asserted directly on
/// synthetic source as well as through the floors above.
mod parse {
    use super::*;

    #[test]
    fn a_chained_registration_yields_both_methods() {
        let source = r#"
            // A comment naming .route("/decoy", get(decoy)) that must not be read.
            Router::new()
                .route("/api/v1/thing/{id}", get(thing::read).delete(thing::remove))
        "#;
        let cleaned = strip_comments(source);
        let call = &cleaned[cleaned.find(".route(").expect("find") + 6..];
        let call = balanced(call).expect("balanced");
        assert_eq!(string_literal(call).as_deref(), Some("/api/v1/thing/{id}"));
        let mut methods = method_routers(call);
        methods.sort();
        assert_eq!(
            methods,
            vec![
                ("delete".to_owned(), "thing::remove".to_owned()),
                ("get".to_owned(), "thing::read".to_owned())
            ]
        );
    }

    #[test]
    fn a_route_named_only_in_a_comment_is_not_a_route() {
        let source = "// .route(\"/ghost\", get(ghost))\nlet x = 1;";
        assert!(!strip_comments(source).contains("ghost"));
    }

    #[test]
    fn a_module_path_matches_the_spelling_a_registration_uses() {
        assert_eq!(module_path(&api_src().join("admin").join("dlp.rs")), "admin::dlp");
        assert_eq!(module_path(&api_src().join("me.rs")), "me");
        assert_eq!(module_path(&api_src().join("routes").join("mod.rs")), "routes");
    }
}
