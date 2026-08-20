//! The policy-routing lint — proof that every HTTP entry point reaches the policy chain.
//!
//! `CLAUDE.md` rule 1 and `docs/12-TESTING.md §5` state the rule: every Axum route handler reaches
//! [`PolicyEngine::enforce`](../../crates/core/src/engine.rs). This module is the machine-checkable
//! form of that sentence, specified by `plans/M0-FOUNDATIONS.md` ENC-110.
//!
//! # Why a syntactic call-graph lint and not a type-level trick
//!
//! A handler that forgets `enforce` is not a type error — it compiles, it responds, and it returns
//! data. The mistake is an *absence*, and absences are invisible in review of a large diff. So the
//! check is structural: parse the `api` crate, find the route registrations, and walk outward from
//! each handler until either `enforce` appears or the depth budget runs out.
//!
//! # What this proves, and what it does not
//!
//! It proves the call *exists* somewhere in the handler's reachable call graph. It does not prove
//! the call *dominates* every return path — a handler with `if debug { return raw() }` above its
//! `enforce` still passes. Dominance analysis needs control-flow, which needs MIR, which needs the
//! compiler. The lint therefore catches the failure that actually happens (nobody wired the engine
//! in at all) and leaves the subtler one to review. Being unable to catch everything is not a
//! reason to catch nothing.
//!
//! # Why the allowlist is printed rather than merely consulted
//!
//! An exemption nobody sees is an exemption nobody revisits. The allowlist is echoed on every run
//! so that "this endpoint has no policy check" is a line in the CI log of every pull request, not a
//! `const` three files deep that was last read when it was written.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use syn::visit::Visit;

/// The tree the lint reads, relative to the workspace root.
///
/// Only `api` is scanned: it is the crate that owns the HTTP surface, and a route registered
/// anywhere else would already be a layering violation caught by the crate-graph rules (D1).
const API_SRC: &str = "crates/api/src";

/// How far the call-graph walk follows helper functions before giving up.
///
/// Bounded on purpose. An unbounded walk on a cyclic graph is a hang, and a handler that needs more
/// than twelve frames to reach the policy engine has a structural problem the lint should surface
/// rather than paper over.
const MAX_DEPTH: usize = 12;

/// The method-router constructors `axum::routing` exports.
///
/// `route(path, get(handler))` is the registration form; these are the functions that can appear in
/// the second argument.
const METHOD_ROUTER_FNS: &[&str] =
    &["get", "post", "put", "patch", "delete", "head", "options", "trace", "any"];

/// The call the lint is looking for. Matched on the final path segment, so both
/// `PolicyEngine::enforce(..)` and `self.policy.enforce(..).await` count.
const ENFORCE: &str = "enforce";

/// One route handler that is allowed to skip the policy chain, and the reason it may.
///
/// The reason is a field rather than a comment because it is printed: an exemption has to justify
/// itself in the CI log where a reviewer will actually meet it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exemption {
    /// The handler function's name, matched exactly.
    pub(crate) handler: &'static str,
    /// Why this endpoint legitimately has no policy decision to make.
    pub(crate) reason: &'static str,
}

/// Handlers that legitimately reach no policy decision.
///
/// Every entry is one of two cases: the endpoint has no tenant and no resource (probes, the public
/// key document, the API description), or the endpoint *is* the authentication step that the policy
/// chain's auth stage presupposes. Anything else belongs in the chain.
pub(crate) const ALLOWLIST: &[Exemption] = &[
    Exemption {
        handler: "live",
        reason:
            "Liveness probe. No tenant, no actor, no resource — it answers whether the process \
                 is running and returns no tenant data.",
    },
    Exemption {
        handler: "ready",
        reason: "Readiness probe. Reports dependency reachability only; it must never include a \
                 detail that identifies a tenant or a resource.",
    },
    Exemption {
        handler: "jwks",
        reason: "Public JWKS document. Deliberately unauthenticated — verifiers fetch it before \
                 they hold any token, and it contains only public key material.",
    },
    Exemption {
        handler: "login",
        reason:
            "Credential exchange. The chain's auth stage presupposes a verified token; this is \
                 the endpoint that produces one. Its controls are rate limiting and Argon2id \
                 verification (ENC-111), not the policy chain.",
    },
    Exemption {
        handler: "refresh",
        reason: "Refresh rotation. Same reason as login, plus reuse detection, which is a token \
                 lifecycle control rather than a resource authorization decision (docs/03 §5).",
    },
    Exemption {
        handler: "openapi",
        reason: "The OpenAPI document describes the API's shape, not any tenant's content. It is \
                 the same bytes for every caller and is snapshot-tested by the api-contract gate.",
    },
];

/// A route registration found in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    /// The URL path, when the registration used a string literal. `None` when the path came from a
    /// constant or was built at runtime — the handler still gets checked, only the label is poorer.
    pub(crate) path: Option<String>,
    /// The HTTP method constructor: `get`, `post`, …
    pub(crate) method: String,
    /// The handler function's name, or `None` when the registration passed something that is not a
    /// named function (a closure, a call, a service).
    pub(crate) handler: Option<String>,
    /// Repo-relative path, so the GitHub annotation lands on the right line.
    pub(crate) file: String,
    /// 1-based line of the method-router constructor.
    pub(crate) line: usize,
}

/// Why a route failed the lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViolationKind {
    /// The handler was found and analyzed, and nothing in its reachable call graph calls `enforce`.
    NoEnforce,
    /// The registration passed an expression the lint cannot resolve to a function it can read.
    UnresolvableHandler,
    /// The handler names a function that is not defined in the scanned crate, so the lint cannot
    /// see whether it enforces. Treated as a failure: unprovable is not the same as proven.
    HandlerNotFound,
}

impl ViolationKind {
    /// The remediation text, phrased as what to do rather than what went wrong.
    fn advice(self) -> &'static str {
        match self {
            Self::NoEnforce => {
                "call PolicyEngine::enforce before touching any tenant data, or add the handler to \
                 ALLOWLIST in xtask/src/policy_routing.rs with the reason it needs no policy check"
            }
            Self::UnresolvableHandler => {
                "register a named handler function rather than a closure or an expression, so the \
                 route's policy path can be checked"
            }
            Self::HandlerNotFound => {
                "define the handler in the api crate; the lint only reads crates/api/src and cannot \
                 prove a handler it cannot see reaches the policy chain"
            }
        }
    }
}

/// A failed route, with enough context for a GitHub annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Violation {
    pub(crate) route: Route,
    pub(crate) kind: ViolationKind,
}

/// The outcome of one lint run.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Report {
    /// Every route registration seen, in source order.
    pub(crate) routes: Vec<Route>,
    /// Routes that neither reach `enforce` nor are exempt.
    pub(crate) violations: Vec<Violation>,
    /// Handler names that were exempted by the allowlist on this run.
    pub(crate) exempted: BTreeSet<String>,
}

/// What one function in the crate does, reduced to the only two facts the lint needs.
#[derive(Debug, Default)]
struct FnFacts {
    /// Names of every function and method called directly in the body.
    callees: BTreeSet<String>,
}

/// The whole crate's functions, keyed by bare name.
///
/// Bare names, not paths: resolving `handlers::files::list` properly would mean implementing name
/// resolution, and the lint's job is to be right about the common case and loud about the rest. A
/// duplicated name merges its callees, which can only make the lint more permissive — the
/// `HandlerNotFound` case covers the direction that matters (a handler it cannot see at all).
type FnGraph = BTreeMap<String, FnFacts>;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the lint over `crates/api/src` and report to stdout.
///
/// # Errors
///
/// Returns an error when the sources cannot be read or parsed, or when any route fails the rule.
/// The error is the non-zero exit CI keys on; the annotations are printed before it.
pub(crate) fn run() -> Result<()> {
    let root = workspace_root()?;
    let src = root.join(API_SRC);
    let sources = load_sources(&src, &root)
        .with_context(|| format!("reading Rust sources under {}", src.display()))?;

    let report = analyze(&sources)?;

    // Checked before the enforce rule, because the answer for `/metrics` is not "allowlist it".
    if let Some(route) = telemetry_route(&report) {
        println!(
            "::error title=/metrics does not belong on the policy-routed API::{}",
            describe(route)
        );
        anyhow::bail!(
            "policy-routing: {API_SRC} registers a telemetry route. The Prometheus exposition \
             carries `tenant_id` labels — which tenants exist and how much each one searches — so \
             it fails the bar the `ready` exemption states for an unauthenticated endpoint: it \
             must never include a detail that identifies a tenant. Allowlisting it would publish \
             that to anyone who can reach the API port, and putting it behind the chain would \
             require Prometheus to hold a tenant it cannot honestly claim. It belongs on the \
             separate listener `serve_metrics` in crates/api/src/main.rs, bound to loopback by \
             default (ENC-521)."
        );
    }

    // The metrics listener is a different router on a different socket, so the enforce rule does
    // not apply to it: there is no policy chain to reach, and no tenant to reach it for. It is
    // still *listed* below, because a route excluded silently is a route nobody reviews.
    let separate: Vec<&Route> =
        report.routes.iter().filter(|route| route.file == METRICS_LISTENER).collect();
    let separate_count = separate.len();

    println!("policy-routing — every Axum route handler must reach PolicyEngine::enforce");
    println!("  rule: CLAUDE.md rule 1, docs/12-TESTING.md §5, plans/M0-FOUNDATIONS.md ENC-110");
    println!("  scanned: {} file(s) under {API_SRC}", sources.len());
    print_allowlist(&report);
    if separate_count > 0 {
        println!();
        println!(
            "  {separate_count} route(s) in {METRICS_LISTENER} are on the separate metrics \
             listener, not this router, and are exempt from the enforce rule."
        );
    }

    if report.routes.is_empty() {
        println!();
        println!("0 handlers, nothing to check — no route registrations exist in {API_SRC} yet.");
        println!(
            "This gate is live: the first `route(\"/x\", get(handler))` is checked on arrival."
        );
        return Ok(());
    }

    println!();
    println!("{} route registration(s):", report.routes.len());
    for route in &report.routes {
        let verdict = if route.file == METRICS_LISTENER {
            "separate listener"
        } else if report.violations.iter().any(|v| v.route == *route) {
            "FAIL"
        } else if route.handler.as_deref().is_some_and(|h| report.exempted.contains(h)) {
            "exempt"
        } else {
            "ok"
        };
        println!("  [{verdict}] {}", describe(route));
    }

    if report.violations.is_empty() {
        println!();
        println!(
            "All {} handler(s) reach PolicyEngine::enforce or are allowlisted.",
            report.routes.len()
        );
        return Ok(());
    }

    println!();
    for violation in &report.violations {
        emit_annotation(violation);
    }
    anyhow::bail!(
        "policy-routing: {} route handler(s) do not reach PolicyEngine::enforce and are not \
         allowlisted",
        report.violations.len()
    );
}

/// Finds a route that would serve telemetry from the policy-routed API, if one has appeared.
///
/// Separate from the enforce rule because it is not the same question. That rule asks whether a
/// handler reaches `PolicyEngine::enforce`, and its escape hatch is the allowlist. This asks
/// whether a path should be on this router at all, and for the metrics exposition the answer is no
/// regardless of what it does or does not enforce — so it must not be expressible as an exemption.
fn telemetry_route(report: &Report) -> Option<&Route> {
    report.routes.iter().find(|route| {
        let telemetry = route
            .path
            .as_deref()
            .is_some_and(|path| path == "/metrics" || path.ends_with("/metrics"));
        telemetry && route.file != METRICS_LISTENER
    })
}

/// The one file allowed to register `/metrics`: the separate listener, which is not this router.
///
/// A path rather than a handler name, unlike [`ALLOWLIST`], because the question is *which router*
/// a route joins and the handler cannot answer that. Confining it to a file whose whole contents
/// are the metrics listener is the closest a source lint gets to "not on the API router" — the
/// residual gap is that someone could build a second router in this file, which would be visible
/// in review of a file that exists for one purpose.
const METRICS_LISTENER: &str = "crates/api/src/metrics_listener.rs";

/// Emit a GitHub error annotation so the failure lands on the offending line in the diff view.
fn emit_annotation(violation: &Violation) {
    let route = &violation.route;
    println!(
        "::error file={},line={},title=GATE FAILED: policy routing::{} — {}. Fix: {}",
        route.file,
        route.line,
        describe(route),
        match violation.kind {
            ViolationKind::NoEnforce =>
                "no call to PolicyEngine::enforce is reachable from this handler",
            ViolationKind::UnresolvableHandler => "the handler expression is not a named function",
            ViolationKind::HandlerNotFound => "the handler is not defined in the api crate",
        },
        violation.kind.advice()
    );
}

/// One-line description of a route, used in both the listing and the annotation.
fn describe(route: &Route) -> String {
    let path = route.path.as_deref().unwrap_or("<computed path>");
    let handler = route.handler.as_deref().unwrap_or("<unnamed handler>");
    format!(
        "{} {path} -> {handler}() at {}:{}",
        route.method.to_uppercase(),
        route.file,
        route.line
    )
}

/// Print every exemption and whether it is still doing anything.
///
/// A stale entry — an exemption for a handler that no longer exists — is how an allowlist rots into
/// a list of names nobody dares delete, so it is marked rather than left to be discovered.
fn print_allowlist(report: &Report) {
    println!();
    println!(
        "Allowlist — {} handler(s) exempt from the policy chain, each with its reason:",
        ALLOWLIST.len()
    );
    let registered: BTreeSet<&str> =
        report.routes.iter().filter_map(|r| r.handler.as_deref()).collect();
    for exemption in ALLOWLIST {
        let marker =
            if registered.contains(exemption.handler) { "" } else { "  (not currently routed)" };
        println!("  - {}(){marker}", exemption.handler);
        println!("      {}", exemption.reason);
    }
}

// ---------------------------------------------------------------------------
// Analysis — pure, so it can be tested on source strings rather than on files
// ---------------------------------------------------------------------------

/// Analyze a set of `(display_path, source)` pairs.
///
/// Takes sources rather than paths so the lint's own tests exercise the real analysis on synthetic
/// crates. That matters here more than usual: `crates/api` has no handlers yet, so tests over
/// fixtures on disk would assert nothing.
///
/// # Errors
///
/// Returns an error if any source fails to parse.
pub(crate) fn analyze(sources: &[(String, String)]) -> Result<Report> {
    let mut graph = FnGraph::new();
    let mut routes = Vec::new();

    for (display_path, source) in sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("parsing {display_path} as Rust source"))?;
        collect_functions(&file.items, &mut graph);

        let mut collector = RouteCollector { file: display_path.clone(), routes: BTreeMap::new() };
        collector.visit_file(&file);
        routes.extend(collector.routes.into_values());
    }

    let mut report = Report { routes, ..Report::default() };

    for route in &report.routes {
        // The metrics listener is a different router on a different socket. There is no policy
        // chain for its handler to reach and no tenant to reach it for, so the enforce rule does
        // not apply — skipped here rather than in `run` so that this function is the single answer
        // and a caller cannot get a different verdict by asking directly.
        if route.file == METRICS_LISTENER {
            continue;
        }
        let Some(handler) = route.handler.clone() else {
            report
                .violations
                .push(Violation { route: route.clone(), kind: ViolationKind::UnresolvableHandler });
            continue;
        };
        if ALLOWLIST.iter().any(|e| e.handler == handler) {
            report.exempted.insert(handler);
            continue;
        }
        if !graph.contains_key(&handler) {
            report
                .violations
                .push(Violation { route: route.clone(), kind: ViolationKind::HandlerNotFound });
            continue;
        }
        if !reaches_enforce(&handler, &graph) {
            report
                .violations
                .push(Violation { route: route.clone(), kind: ViolationKind::NoEnforce });
        }
    }

    Ok(report)
}

/// Breadth-first walk of the call graph from `start`, bounded by [`MAX_DEPTH`].
///
/// Breadth-first with a visited set rather than recursion: the graph is cyclic in practice (helpers
/// call each other), and a bounded queue cannot blow the stack or the clock the way a depth-first
/// walk with a depth counter can.
fn reaches_enforce(start: &str, graph: &FnGraph) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
    queue.push_back((start, 0));
    seen.insert(start);

    while let Some((name, depth)) = queue.pop_front() {
        let Some(facts) = graph.get(name) else {
            continue;
        };
        if facts.callees.contains(ENFORCE) {
            return true;
        }
        if depth == MAX_DEPTH {
            continue;
        }
        for callee in &facts.callees {
            if let Some((key, _)) = graph.get_key_value(callee.as_str()) {
                if seen.insert(key.as_str()) {
                    queue.push_back((key.as_str(), depth + 1));
                }
            }
        }
    }
    false
}

/// Record every function defined in `items`, descending through inline modules and `impl` blocks.
///
/// Functions nested *inside* a function body are deliberately not attributed to their parent (see
/// [`CallCollector::visit_item`]): a nested helper's `enforce` should not silently vouch for the
/// function that happens to enclose it.
fn collect_functions(items: &[syn::Item], graph: &mut FnGraph) {
    for item in items {
        match item {
            syn::Item::Fn(item_fn) => {
                record_fn(&item_fn.sig.ident, &item_fn.block, graph);
            }
            syn::Item::Mod(item_mod) => {
                if let Some((_, inner)) = &item_mod.content {
                    collect_functions(inner, graph);
                }
            }
            syn::Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let syn::ImplItem::Fn(method) = impl_item {
                        record_fn(&method.sig.ident, &method.block, graph);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Reduce one function body to the set of names it calls, and merge it into the graph.
fn record_fn(ident: &syn::Ident, block: &syn::Block, graph: &mut FnGraph) {
    let mut collector = CallCollector::default();
    collector.visit_block(block);
    graph.entry(ident.to_string()).or_default().callees.extend(collector.callees);
}

/// Collects the names a single function body calls.
#[derive(Debug, Default)]
struct CallCollector {
    callees: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for CallCollector {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(name) = last_path_segment(&node.func) {
            self.callees.insert(name);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.callees.insert(node.method.to_string());
        syn::visit::visit_expr_method_call(self, node);
    }

    /// Do not descend into items declared inside the body.
    ///
    /// A nested `fn` is a separate function; letting its calls count as the outer function's would
    /// let an unrelated helper's `enforce` vouch for a handler that never calls it.
    fn visit_item(&mut self, _node: &'ast syn::Item) {}
}

/// Finds route registrations in one file.
#[derive(Debug)]
struct RouteCollector {
    file: String,
    /// Keyed by (line, column) of the method-router constructor so the two ways a registration can
    /// be seen — inside `route(..)` with its path, or standalone without one — collapse to one
    /// entry, and the one carrying the path wins.
    routes: BTreeMap<(usize, usize), Route>,
}

impl RouteCollector {
    /// Record a constructor found with the URL path it was registered under.
    fn record(&mut self, method: &syn::Ident, handler: Option<&syn::Expr>, path: Option<&str>) {
        let span = method.span().start();
        let route = Route {
            path: path.map(str::to_owned),
            method: method.to_string(),
            handler: handler.and_then(last_path_segment),
            file: self.file.clone(),
            line: span.line,
        };
        self.routes.insert((span.line, span.column), route);
    }

    /// Walk the second argument of `route(path, ..)`, recording every method router it builds.
    ///
    /// Inside this context both call forms are accepted — `get(h)` and the chained `.post(h)` —
    /// because the surrounding `route(..)` has already established that this expression is a method
    /// router and nothing else.
    fn scan_router_expr(&mut self, expr: &syn::Expr, path: &str) {
        match expr {
            syn::Expr::Call(call) => {
                if let Some(ident) = method_router_ident(&call.func) {
                    self.record(&ident, call.args.first(), Some(path));
                }
                for arg in &call.args {
                    self.scan_router_expr(arg, path);
                }
            }
            syn::Expr::MethodCall(call) => {
                if METHOD_ROUTER_FNS.contains(&call.method.to_string().as_str()) {
                    self.record(&call.method, call.args.first(), Some(path));
                }
                self.scan_router_expr(&call.receiver, path);
                for arg in &call.args {
                    self.scan_router_expr(arg, path);
                }
            }
            syn::Expr::Reference(inner) => self.scan_router_expr(&inner.expr, path),
            syn::Expr::Group(inner) => self.scan_router_expr(&inner.expr, path),
            syn::Expr::Paren(inner) => self.scan_router_expr(&inner.expr, path),
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for RouteCollector {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        // `Router::new().route("/files", get(list))` — the literal path is available here, so this
        // runs before the generic traversal below and claims the entry.
        if node.method == "route" && node.args.len() == 2 {
            if let (Some(path), Some(router)) = (string_literal(&node.args[0]), node.args.get(1)) {
                self.scan_router_expr(router, &path);
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        // A bare `routing::get(handler)` — a method router built away from its `route` call.
        //
        // Only the *call* form is accepted outside a `route(..)` argument, and only with a single
        // named-function argument. `map.get(&key)` and `headers.get("x")` are method calls on
        // unrelated types and would otherwise be reported as routes with unresolvable handlers.
        if let Some(ident) = method_router_ident(&node.func) {
            if node.args.len() == 1 {
                if let Some(arg) = node.args.first() {
                    if matches!(arg, syn::Expr::Path(_)) {
                        let key = (ident.span().start().line, ident.span().start().column);
                        if !self.routes.contains_key(&key) {
                            self.record(&ident, Some(arg), None);
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

/// The final segment of a path expression, if the expression is a path.
///
/// `handlers::files::list` and `list` both resolve to `list`; `PolicyEngine::enforce` resolves to
/// `enforce`. Turbofish generics live on the segment and are ignored.
fn last_path_segment(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
        syn::Expr::Group(inner) => last_path_segment(&inner.expr),
        syn::Expr::Paren(inner) => last_path_segment(&inner.expr),
        _ => None,
    }
}

/// The identifier of a method-router constructor call, e.g. the `get` in `axum::routing::get(h)`.
fn method_router_ident(func: &syn::Expr) -> Option<syn::Ident> {
    let syn::Expr::Path(path) = func else {
        return None;
    };
    let segment = path.path.segments.last()?;
    METHOD_ROUTER_FNS.contains(&segment.ident.to_string().as_str()).then(|| segment.ident.clone())
}

/// The value of a string-literal expression, if that is what this is.
fn string_literal(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        syn::Expr::Group(inner) => string_literal(&inner.expr),
        syn::Expr::Paren(inner) => string_literal(&inner.expr),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Source loading
// ---------------------------------------------------------------------------

/// The workspace root, derived from this crate's manifest directory.
///
/// Derived rather than taken from the current directory so the lint gives the same answer whether
/// CI runs it from the root or a developer runs it from a crate subdirectory.
fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest directory has no parent; cannot locate the workspace root")
}

/// Read every `.rs` file under `dir`, paired with its path relative to `root`.
///
/// Paths are relative because they are printed into GitHub annotations, which resolve them against
/// the repository, not the runner's filesystem.
fn load_sources(dir: &Path, root: &Path) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    collect_rs_files(dir, root, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn collect_rs_files(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry of {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, root, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let display = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            out.push((display, source));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // A failed assertion is the point of a test, and an unreadable source string is a test bug that
    // should stop the run loudly. The workspace denies these in shipped code, not here.
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;

    /// Analyze a single synthetic source file.
    ///
    /// Source strings, not fixture files: `crates/api` has no handlers yet, so the only way to
    /// prove the lint works before there is anything to lint is to feed it the code it will one day
    /// meet.
    fn analyze_src(source: &str) -> Report {
        analyze(&[("crates/api/src/routes.rs".to_owned(), source.to_owned())])
            .expect("the synthetic source should parse")
    }

    fn kinds(report: &Report) -> Vec<ViolationKind> {
        report.violations.iter().map(|v| v.kind).collect()
    }

    #[test]
    fn handler_calling_enforce_passes() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files/{id}", get(get_file))
            }

            async fn get_file(state: State<App>, id: Path<FileId>) -> Result<Json<File>> {
                let decision = state.policy.enforce(&ctx, Action::Read, resource).await?;
                Ok(Json(state.files.load(id, decision).await?))
            }
            "#,
        );

        assert_eq!(report.routes.len(), 1);
        assert_eq!(report.routes[0].path.as_deref(), Some("/files/{id}"));
        assert_eq!(report.routes[0].method, "get");
        assert_eq!(report.routes[0].handler.as_deref(), Some("get_file"));
        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn handler_without_enforce_fails() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(list_files))
            }

            async fn list_files(state: State<App>) -> Result<Json<Vec<File>>> {
                Ok(Json(state.db.all_files().await?))
            }
            "#,
        );

        assert_eq!(kinds(&report), vec![ViolationKind::NoEnforce]);
        assert_eq!(report.violations[0].route.handler.as_deref(), Some("list_files"));
    }

    #[test]
    fn enforce_reached_through_a_helper_passes() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", post(create_file))
            }

            async fn create_file(state: State<App>) -> Result<Json<File>> {
                let decision = authorize(&state).await?;
                Ok(Json(state.files.create(decision).await?))
            }

            async fn authorize(state: &App) -> Result<PolicyDecision> {
                state.policy.enforce(&ctx, Action::Create, resource).await
            }
            "#,
        );

        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn enforce_reached_through_two_helpers_passes() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", delete(delete_file))
            }

            async fn delete_file(state: State<App>) -> Result<()> { guard(&state).await }
            async fn guard(state: &App) -> Result<()> { inner(state).await }
            async fn inner(state: &App) -> Result<()> {
                let _decision = PolicyEngine::enforce(&state.policy, &ctx, action, resource).await?;
                Ok(())
            }
            "#,
        );

        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn allowlisted_handler_passes_without_enforce() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/healthz", get(live))
            }

            async fn live() -> &'static str { "ok" }
            "#,
        );

        assert!(report.violations.is_empty(), "{:?}", report.violations);
        assert!(report.exempted.contains("live"));
    }

    #[test]
    fn every_allowlist_entry_carries_a_reason() {
        for exemption in ALLOWLIST {
            assert!(
                exemption.reason.len() > 30,
                "{} has no meaningful reason; the allowlist is the review surface",
                exemption.handler
            );
        }
    }

    #[test]
    fn a_handler_defined_elsewhere_cannot_be_proven_and_fails() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(handlers::files::list))
            }
            "#,
        );

        assert_eq!(kinds(&report), vec![ViolationKind::HandlerNotFound]);
    }

    #[test]
    fn a_closure_handler_cannot_be_proven_and_fails() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(|| async { "leak" }))
            }
            "#,
        );

        assert_eq!(kinds(&report), vec![ViolationKind::UnresolvableHandler]);
    }

    #[test]
    fn chained_method_routers_are_each_checked() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(list_files).post(create_file))
            }

            async fn list_files(state: State<App>) -> Result<()> {
                state.policy.enforce(&ctx, action, resource).await?;
                Ok(())
            }

            async fn create_file(state: State<App>) -> Result<()> {
                state.db.insert().await?;
                Ok(())
            }
            "#,
        );

        assert_eq!(report.routes.len(), 2);
        assert_eq!(kinds(&report), vec![ViolationKind::NoEnforce]);
        assert_eq!(report.violations[0].route.handler.as_deref(), Some("create_file"));
    }

    #[test]
    fn a_standalone_routing_constructor_is_still_checked() {
        let report = analyze_src(
            r#"
            fn files_router() -> MethodRouter {
                axum::routing::put(replace_file)
            }

            async fn replace_file(state: State<App>) -> Result<()> {
                state.storage.put().await?;
                Ok(())
            }
            "#,
        );

        assert_eq!(report.routes.len(), 1);
        assert_eq!(report.routes[0].path, None);
        assert_eq!(kinds(&report), vec![ViolationKind::NoEnforce]);
    }

    #[test]
    fn a_registration_seen_twice_is_reported_once_with_its_path() {
        // The standalone-constructor pass and the `route(..)` pass both see `get(list_files)`.
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(list_files))
            }

            async fn list_files(state: State<App>) -> Result<()> { Ok(()) }
            "#,
        );

        assert_eq!(report.routes.len(), 1);
        assert_eq!(report.routes[0].path.as_deref(), Some("/files"));
    }

    #[test]
    fn map_get_is_not_mistaken_for_a_route() {
        let report = analyze_src(
            r#"
            fn lookup(headers: &HeaderMap, cache: &HashMap<String, String>) -> Option<String> {
                let _ = headers.get("x-request-id");
                cache.get("key").cloned()
            }
            "#,
        );

        assert!(report.routes.is_empty(), "{:?}", report.routes);
    }

    #[test]
    fn an_enforce_in_a_nested_fn_does_not_vouch_for_its_parent() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(list_files))
            }

            async fn list_files(state: State<App>) -> Result<()> {
                async fn unused(state: &App) -> Result<()> {
                    state.policy.enforce(&ctx, action, resource).await?;
                    Ok(())
                }
                state.db.all().await?;
                Ok(())
            }
            "#,
        );

        assert_eq!(kinds(&report), vec![ViolationKind::NoEnforce]);
    }

    #[test]
    fn a_cycle_in_the_call_graph_terminates() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(list_files))
            }

            async fn list_files() -> Result<()> { helper_a().await }
            async fn helper_a() -> Result<()> { helper_b().await }
            async fn helper_b() -> Result<()> { helper_a().await }
            "#,
        );

        assert_eq!(kinds(&report), vec![ViolationKind::NoEnforce]);
    }

    #[test]
    fn methods_in_impl_blocks_are_part_of_the_graph() {
        let report = analyze_src(
            r#"
            fn router() -> Router {
                Router::new().route("/files", get(list_files))
            }

            async fn list_files(state: State<App>) -> Result<()> {
                state.guard().await
            }

            impl App {
                async fn guard(&self) -> Result<()> {
                    self.policy.enforce(&ctx, action, resource).await?;
                    Ok(())
                }
            }
            "#,
        );

        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }

    #[test]
    fn no_routes_is_not_a_failure() {
        let report = analyze_src("fn main() { println!(\"nothing here\"); }");

        assert!(report.routes.is_empty());
        assert!(report.violations.is_empty());
    }

    #[test]
    fn the_api_crate_as_it_stands_today_passes() {
        let root = workspace_root().expect("the workspace root should be resolvable");
        let sources =
            load_sources(&root.join(API_SRC), &root).expect("crates/api/src should be readable");
        assert!(!sources.is_empty(), "{API_SRC} has no Rust sources");

        let report = analyze(&sources).expect("the api crate should parse");
        assert!(report.violations.is_empty(), "{:?}", report.violations);
    }
}
