//! The audit-coverage gate — proof that every refusal the system can produce is one the audit
//! trail can explain.
//!
//! `CLAUDE.md` rule 10, `plans/M4-GOVERNANCE.md` D32, `docs/12-TESTING.md §4.10` U5/U6.
//! M4's exit criterion asks that **every row in the audit table map to a real enforcement point,
//! with no silent successes** — a coverage claim, and coverage claims decay.
//!
//! # Why this is a gate rather than a review item
//!
//! `ENC-543`. The composite-FK rule was guarded by a CI job whose assertion was conditional on a
//! test file existing; absent, the job printed `GATE PENDING` and exited zero. Its name said
//! `RULE: every FK between tenant-scoped tables includes tenant_id`, so a pull request's checks
//! list read **pass**, in green, having never looked at a foreign key. It stayed that way for a
//! milestone. A sweep that is a document decays the same way, only faster, because a document does
//! not even claim to have run.
//!
//! # What an enforcement point is, mechanically
//!
//! A refusal has to be *constructed* before it can be returned, and the workspace's vocabulary has
//! exactly three constructors for one:
//!
//! | Construct | Meaning |
//! |---|---|
//! | `StageDecision::deny(code)` | a policy stage refuses |
//! | `Error::denied(code)` / `Error::denied_with(code, remediation)` | a policy refusal as an error |
//! | `Refused::…(..)` | a handler refuses, after the chain has allowed (`ENC-606`) |
//!
//! So *an enforcement point is a call site of one of those*. Nothing else can refuse on policy
//! grounds without going through one of them, because [`enclave_core::Error::PolicyDenied`]'s
//! fields are private, `StageOutcome::Deny` is only reachable through `StageDecision::deny`, and
//! `enclave_api::refusal::Refused`'s fields are private with no conversion into either.
//!
//! # What "audits" means, mechanically
//!
//! Two things record a denial: `PolicyEngine::enforce`, which is the only code that calls
//! `PolicyAuditSink::record_deny`, and `HandlerAudit::refuse`, which is the only code that can turn
//! a `Refused` into a client's error. A refusal is audited exactly when one of those is what carries
//! it to the caller — and that is decidable from the *enclosing function's return type*:
//!
//! * a site inside a function returning `StageDecision` (or `Result<StageDecision>`, or
//!   `Result<Vec<StageDecision>>`) hands its refusal to the engine, which records it before
//!   returning `Err` — **audited by construction**;
//! * a site inside a function returning `Refused` hands it to `HandlerAudit::refuse`, which is the
//!   only thing that can accept one, and which records it before returning the error — **audited
//!   (handler)**, by exactly the same argument one layer up;
//! * a site inside `PolicyEngine::enforce` itself writes the row inline — **the engine**;
//! * a site inside `HandlerAudit::refuse` is the handler port's own — **audited (handler port)**;
//! * anything else returns `Error::PolicyDenied` to a caller that is neither, and no row is
//!   written — **unaudited**.
//!
//! # Why the `Refused` matcher is blunt
//!
//! Every `Refused::…` path call counts, whatever the member is named, because `Refused` has no
//! associated function that is not a constructor — the helpers that *return* one, such as
//! `none_dischargeable`, are free functions for precisely this reason. A matcher keyed to three
//! remembered names would be escaped by the fourth constructor somebody adds.
//!
//! # The hole that classification would otherwise leave, and the third check that closes it
//!
//! "A `StageDecision` is audited because the engine consumes it" is only true while the engine is
//! the only thing that consumes one into an error. [`StageDecision::ensure_allowed`] is that
//! conversion, and it is public. A handler that called a stage service directly and used it would
//! produce a client-visible denial that no row records — and the first two checks would call the
//! *construction* site audited, because it does sit in a `Result<StageDecision>` function.
//!
//! So every `ensure_allowed()` call site outside the engine is enumerated too and must be
//! acknowledged with a reason. There are two today, both provably non-denying (each is guarded by
//! `is_allowed()` first), and both are listed below where a reviewer meets them.
//!
//! # What this does not prove
//!
//! It is a syntactic check, like `policy_routing`. It proves a refusal is *constructed* in a
//! position the engine audits; it does not prove the engine's write succeeded, that the row's
//! contents are usable, or that the denial dominates every return path. The row's contents are
//! `crates/audit/tests/policy_audit_coverage.rs`'s job — that test drives the real engine into the
//! real record format and asserts, per stage, that exactly one row comes out naming it. The two
//! are halves of one claim and neither is sufficient alone.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use syn::spanned::Spanned as _;
use syn::visit::Visit;

/// The trees the gate reads, relative to the workspace root.
///
/// Every crate, not just `api`: a refusal constructed in `crates/sharing` reaches a caller exactly
/// as a refusal constructed in a handler does, and the question this gate asks — is a row written —
/// has the same answer wherever the site lives.
const CRATES_DIR: &str = "crates";

/// The one file that turns a stage's refusal into the caller's error *and* writes the row.
const ENGINE_FILE: &str = "crates/core/src/engine.rs";

/// The one file that turns a *handler's* refusal into the caller's error *and* writes the row.
///
/// `ENC-606`'s fix, and the engine's arrangement repeated one layer up: the type that carries a
/// handler refusal has private fields and no conversion, so this file is the only place it can
/// become an `ApiError`, and the row is written before it does.
const REFUSAL_FILE: &str = "crates/api/src/refusal.rs";

/// The handler port's recording function, which audits inline.
const RECORD_FN: &str = "refuse";

/// Where [`enclave_core::Error`]'s constructors are defined.
///
/// A `Self::denied(..)` inside the type's own `impl` is the vocabulary being defined, not a
/// decision being taken.
const ERROR_FILE: &str = "crates/core/src/error.rs";

/// The engine functions that audit inline.
///
/// A function may be listed here only if it calls `PolicyAuditSink::record_deny` on the same path
/// that constructs the refusal, so that the `Err` this gate sees is provably preceded by a row. Both
/// entries do; `PolicyEngine` holds the sink privately, so nothing outside `engine.rs` can be added
/// to this list even by mistake.
///
/// `reevaluate_conditional_access` is the refresh path's single-stage re-evaluation (`ENC-709`). It
/// is a second entry rather than a widening of the file-level rule: a future helper in `engine.rs`
/// that refused *without* recording must still fail this gate, and it will, because it will not be
/// named here.
const AUDITING_ENGINE_FNS: &[&str] = &["enforce", "reevaluate_conditional_access"];

/// The conversion from a stage's decision into the caller's error.
const CONVERSION_FN: &str = "ensure_allowed";

/// What a site does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SiteKind {
    /// `StageDecision::deny(code)` — a stage refuses.
    StageRefusal,
    /// `Error::denied(..)` / `Error::denied_with(..)` — a policy refusal as an error.
    ErrorRefusal,
    /// `ensure_allowed()` — a stage decision becomes the caller's error.
    Conversion,
    /// `Refused::…(..)` — a handler refuses after the chain allowed (`ENC-606`).
    HandlerRefusal,
}

impl SiteKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::StageRefusal => "StageDecision::deny",
            Self::ErrorRefusal => "Error::denied",
            Self::Conversion => "ensure_allowed()",
            Self::HandlerRefusal => "Refused::",
        }
    }

    /// What to do about a site of this kind that is not in an audited position.
    ///
    /// Per kind rather than one sentence, because the two answers are genuinely different and the
    /// wrong one is unhelpful advice at the moment somebody is trying to follow it: "move it into a
    /// stage" is not what a handler that refuses on an obligation should do — the chain already
    /// allowed, correctly, and the stage has nothing left to say.
    pub(crate) const fn remedy(self) -> &'static str {
        match self {
            Self::StageRefusal | Self::ErrorRefusal | Self::Conversion => {
                "take the decision inside a stage (return a StageDecision, which the engine \
                 records before it returns Err)"
            }
            Self::HandlerRefusal => {
                "construct the `Refused` inside a function that *returns* one — a `satisfy`, an \
                 eligibility check — and let the handler hand it to `HandlerAudit::refuse`, which \
                 is what writes the row (ENC-606, ENC-625)"
            }
        }
    }

    /// Every kind, so the liveness check cannot silently stop covering one.
    pub(crate) const ALL: [Self; 4] =
        [Self::StageRefusal, Self::ErrorRefusal, Self::Conversion, Self::HandlerRefusal];
}

/// Whether the refusal this site constructs reaches a caller through an audited path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Position {
    /// The enclosing function returns a `StageDecision`, so the engine records it.
    AuditedByStage,
    /// The enclosing function returns a `Refused`, so `HandlerAudit::refuse` records it — the only
    /// thing that can consume one (`ENC-606`).
    AuditedByHandler,
    /// `PolicyEngine::enforce` — writes the row itself.
    EngineAudits,
    /// `HandlerAudit::refuse` — writes the row itself, for a refusal taken at the edge.
    HandlerAudits,
    /// A constructor or conversion definition, not a decision.
    Vocabulary,
    /// Returns `Error::PolicyDenied` to something that is not the engine. No row is written.
    Unaudited,
}

impl Position {
    pub(crate) const fn verdict(self) -> &'static str {
        match self {
            Self::AuditedByStage => "audited (stage)",
            Self::AuditedByHandler => "audited (handler)",
            Self::EngineAudits => "audited (engine)",
            Self::HandlerAudits => "audited (handler port)",
            Self::Vocabulary => "vocabulary",
            Self::Unaudited => "UNAUDITED",
        }
    }
}

/// One refusal-constructing site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Site {
    /// Repo-relative path, so a GitHub annotation lands on the right line.
    pub(crate) file: String,
    /// 1-based line of the call.
    pub(crate) line: usize,
    /// The enclosing function's name, or `<top level>`.
    pub(crate) function: String,
    pub(crate) kind: SiteKind,
    pub(crate) position: Position,
}

/// A site that constructs a refusal outside an audited position, and the reason it may.
///
/// The fields are what an exemption has to supply before it is one: *where*, *why*, and *which
/// tracker row owns the gap*. Modelled after `crates/db/tests/composite_fk_coverage.rs`'s `EXEMPT`
/// — the shape is fixed in advance so that adding an entry is a reviewable act rather than an
/// invention under pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Acknowledged {
    pub(crate) file: &'static str,
    pub(crate) function: &'static str,
    pub(crate) kind: SiteKind,
    /// Why this refusal legitimately writes no audit row, or which row owns the fact that it
    /// should and does not.
    pub(crate) reason: &'static str,
}

impl Acknowledged {
    /// Whether this entry covers a site.
    ///
    /// Keyed by file, function *and* kind rather than by file alone. A blanket exemption for a file
    /// would silently absorb the next refusal added to it, which is the failure mode an allowlist
    /// is supposed to prevent rather than cause.
    pub(crate) fn covers(&self, site: &Site) -> bool {
        self.file == site.file && self.function == site.function && self.kind == site.kind
    }
}

/// Every unaudited refusal in the tree, with the reason it is tolerated.
///
/// **The groups are not equivalent and the comment headings say which is which.** Groups 1 and 2
/// are legitimate: those refusals happen before a tenant is established, or are the vocabulary's
/// own converters whose decision is taken at a caller that is itself classified. **Group 3 was a
/// real `CLAUDE.md` rule 10 defect** — the chain allowed, the handler could not satisfy an
/// obligation and refused, and the row said `ALLOW`. It was found by this gate on its first run,
/// owned by `ENC-606`, and printed in the log of every pull request until `ENC-625` closed it; the
/// heading is kept, empty, because *how* it emptied is the argument for the staleness check. Group
/// 4 is the `ensure_allowed()` conversions, each provably non-denying.
///
/// **Re-opening group 3 is not a way to make this gate green.** An entry there is a place where a
/// user is refused and the audit trail does not say so. Since `ENC-625` there is a supported way to
/// refuse from a handler and be recorded — return an `enclave_api::refusal::Refused` — so a new
/// group 3 entry means someone chose not to use it.
///
/// A stale entry — one naming a site that no longer constructs a refusal — fails the gate. An
/// exemption list nobody prunes is how a list of names nobody dares delete gets started.
pub(crate) const ACKNOWLEDGED: &[Acknowledged] = &[
    // -- Group 1: before a tenant exists ------------------------------------------------------
    Acknowledged {
        file: "crates/api/src/auth.rs",
        function: "from_request_parts",
        kind: SiteKind::ErrorRefusal,
        reason: "A missing or unparseable bearer token. The audit chain is keyed by tenant and \
                 sequenced per tenant; this refusal happens before a token has been verified, so \
                 there is no tenant to attribute it to and no chain to append to. Attributing it \
                 to a tenant named by the rejected token would let an unauthenticated caller \
                 write into any tenant's audit chain, which is worse than the gap. Authentication \
                 failures are counted and logged by `crates/observability` instead. Same reasoning \
                 as the `login`/`refresh` entries in xtask/src/policy_routing.rs's ALLOWLIST.",
    },
    Acknowledged {
        file: "crates/api/src/auth.rs",
        function: "map_auth_error",
        kind: SiteKind::ErrorRefusal,
        reason: "Collapses every token-verification failure to one client-visible outcome. Same \
                 position as the extractor above: no verified tenant, so no chain.",
    },
    Acknowledged {
        file: "crates/api/src/routes/auth.rs",
        function: "refresh_failure",
        kind: SiteKind::ErrorRefusal,
        reason: "Renames a refusal `TokenService::refresh` already took, on the rotation path, \
                 which is on the policy-routing ALLOWLIST for the same reason the extractor above \
                 is acknowledged: the chain has not run, because refresh *is* the step that \
                 produces the principal the chain presupposes. **The conditional-access half is no \
                 longer a gap** (`ENC-709`, closing `ENC-710`): `ChainRefreshGuard` takes that \
                 decision inside `PolicyEngine::reevaluate_conditional_access`, which writes the \
                 DENY row against the tenant the stored refresh family names — so by the time an \
                 `AuthError::ConditionalAccessDenied` reaches this function the refusal is already \
                 in `audit_events` and this really is a rename. What is left unaudited here is the \
                 residue: a signing key that cannot be read and a store that did not answer, \
                 neither of which is a decision about a caller, and neither of which has a verified \
                 tenant to key a chain by when it fires before the family is resolved.",
    },
    Acknowledged {
        file: "crates/auth/src/error.rs",
        function: "from",
        kind: SiteKind::ErrorRefusal,
        reason: "The `AuthError -> Error` mapping itself. It takes no decision — it renames one \
                 already taken by token verification, which runs before the chain.",
    },
    // -- Group 2: the vocabulary's own helpers -------------------------------------------------
    Acknowledged {
        file: "crates/core/src/policy.rs",
        function: "into_denial",
        kind: SiteKind::ErrorRefusal,
        reason: "`FactsOutcome::into_denial` builds the error a DLP stage returns when security \
                 facts are missing under a fail-closed policy. It is a converter, not a decision: \
                 every caller is inside a `Result<StageDecision>` function and is classified \
                 `audited (stage)` above.",
    },
    Acknowledged {
        file: "crates/core/src/policy.rs",
        function: "require_none",
        kind: SiteKind::ErrorRefusal,
        reason: "`Obligations::require_none` raises the refusal *at its caller* — it is the \
                 `CLAUDE.md` rule 8 helper for a path that cannot satisfy an obligation, and it \
                 returns an `Error`, which is a refusal that can reach a client without a row. \
                 ENC-625 therefore moved every API caller onto `enclave_api::refusal::\
                 none_dischargeable`, which is the same rule and the same code in a type that has \
                 to be audited first; `crates/api` no longer calls this. It stays because \
                 `crates/core` may not depend on the API layer and a domain crate outside the HTTP \
                 surface — a worker, an MCP tool — still needs the check. A caller of it is an \
                 unaudited refusal and must be acknowledged in its own right.",
    },
    // -- Group 3: ENC-606's class, now audited rather than acknowledged ------------------------
    //
    // This group is deliberately **empty**, and the emptiness is the record of what changed. It
    // held six entries covering fourteen sites — five in `download.rs::satisfy`, seven across
    // `preview.rs`, one in `me.rs::me` and one in `admin/conditional_access.rs::author` — each of
    // them a refusal the chain had already written an `ALLOW` for. Every one now constructs a
    // `Refused` instead, in a function that returns one, so it is classified `audited (handler)`
    // above rather than tolerated here. `ENC-625`.
    //
    // The staleness check is what emptied it: the fix made all six entries name sites that no
    // longer existed, and the gate refused to pass until they were removed. That is the intended
    // life cycle of an acknowledgement and worth seeing happen once.
    //
    // -- Group 4: StageDecision consumed by something that is not the engine -------------------
    Acknowledged {
        file: "crates/api/src/content.rs",
        function: "readable_children",
        kind: SiteKind::Conversion,
        reason:
            "The listing trim. Guarded by `if !decision.is_allowed() { continue }` on the line \
                 above, so this conversion cannot produce an `Err` and cannot refuse anything — it \
                 exists to carry the admitted row's obligations forward rather than drop them. The \
                 listing operation itself is audited by the chain (`container.read`); per-row \
                 trimming is deliberately not a separate audit event (docs/07 §6.2).",
    },
    Acknowledged {
        file: "crates/api/src/content.rs",
        function: "capabilities_for_many",
        kind: SiteKind::Conversion,
        reason: "The capabilities probe of docs/05-API.md §7, which `PolicyEngine::authorization` \
                 documents as a hint that writes no audit row: it cannot allow anything, and the \
                 enforcement happens when the action is actually attempted. Guarded the same way.",
    },
    Acknowledged {
        file: "crates/api/src/routes/recent.rs",
        function: "admit",
        kind: SiteKind::Conversion,
        reason: "The per-row trim behind `GET /me/recent` (`ENC-930`), and the same shape as \
                 `routes::workspaces::admit` below. Guarded by `if !decision.is_allowed() { \
                 continue }` on the line above, so the conversion cannot produce an `Err` and \
                 refuses nothing — it exists to carry an admitted row's obligations forward rather \
                 than drop them, which is what keeps a `READ_ONLY` attached to a metadata read from \
                 evaporating between the trim and the capabilities built from it. The request \
                 itself is audited by the chain. Per-row trimming is deliberately not a separate \
                 audit event (docs/07 §6.2): auditing it would write one speculative ALLOW per \
                 candidate for a question nobody asked, and this endpoint over-fetches on purpose, \
                 so most candidates are ones the caller never named. What the caller is told \
                 instead is `filteredCount` — how many, never which (rule 7).",
    },
    Acknowledged {
        file: "crates/api/src/routes/workspaces.rs",
        function: "admit",
        kind: SiteKind::Conversion,
        reason: "`content.rs::readable_children` for containers (`ENC-791`): the trim behind \
                 `GET /workspaces` and `GET /workspaces/{id}/libraries`. Guarded by \
                 `if !decision.is_allowed() { continue }` on the line above, so the conversion \
                 cannot produce an `Err` and refuses nothing — it exists to carry the admitted \
                 row's obligations forward rather than drop them. The listing itself is audited by \
                 the chain; per-row trimming is deliberately not a separate audit event \
                 (docs/07 §6.2), because auditing it would write one speculative ALLOW per \
                 candidate for a question nobody asked.",
    },
    Acknowledged {
        file: "crates/api/src/routes/workspaces.rs",
        function: "capabilities_for_containers",
        kind: SiteKind::Conversion,
        reason: "The container half of the docs/05-API.md §7 capabilities probe (`ENC-793`), \
                 shared by both navigation modules. A hint that writes no audit row: it cannot \
                 allow anything, and the enforcement happens when the action is attempted. \
                 Guarded the same way.",
    },
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the gate over `crates/*/src` and report to stdout.
///
/// # Errors
///
/// Returns an error when the sources cannot be read or parsed, when a refusal is constructed in an
/// unaudited position without an acknowledgement, when an acknowledgement is stale, or when an
/// enumeration comes back empty — which would mean the gate is inspecting nothing.
pub(crate) fn run() -> Result<()> {
    let root = workspace_root()?;
    let dir = root.join(CRATES_DIR);
    let sources = load_sources(&dir, &root)
        .with_context(|| format!("reading Rust sources under {}", dir.display()))?;

    let sites = analyze(&sources)?;

    println!("audit-coverage — every refusal the system constructs is one the audit trail records");
    println!("  rule: CLAUDE.md rule 10, plans/M4-GOVERNANCE.md D32, docs/12-TESTING.md §4.10");
    println!("  scanned: {} file(s) under {CRATES_DIR}/*/src", sources.len());

    liveness(&sites)?;
    print_inventory(&sites);
    print_acknowledgements(&sites, ACKNOWLEDGED);
    decide(&sites, ACKNOWLEDGED)?;

    println!();
    println!(
        "All {} refusal site(s) construct their denial where PolicyEngine::enforce records it, or \
         are acknowledged with a reason.",
        sites.len()
    );
    Ok(())
}

/// The gate's own liveness check — a run that inspected nothing must fail.
///
/// Not ceremony. This gate asserts an **absence** — no refusal is constructed outside an audited
/// position — and `docs/12-TESTING.md §1.2` records that an assertion about an absence passes for
/// free. A visitor that stopped matching `syn`'s AST, a glob that stopped matching the tree, or a
/// filter that excluded everything would each produce an empty inventory and a green check that
/// had inspected nothing. That is `ENC-543` exactly, and it is not hypothetical here: the first
/// run of this gate failed on the second assertion below, because `PolicyEngine::enforce` takes
/// its denials inside a `macro_rules!` body that an AST walk never enters.
///
/// # Errors
///
/// When any refusal constructor has no site at all, or when the engine's own audited refusal is
/// not among them.
pub(crate) fn liveness(sites: &[Site]) -> Result<()> {
    for kind in SiteKind::ALL {
        if !sites.iter().any(|site| site.kind == kind) {
            anyhow::bail!(
                "audit-coverage: no `{}` site was found anywhere in {CRATES_DIR}/*/src. Either the \
                 scan stopped matching the tree or the construct was renamed. Both mean this gate \
                 is proving nothing, which is the state ENC-543 exists to end rather than repeat.",
                kind.label()
            );
        }
    }
    if !sites.iter().any(|site| site.position == Position::EngineAudits) {
        anyhow::bail!(
            "audit-coverage: nothing in {ENGINE_FILE} was classified as the engine's own audited \
             refusal. {AUDITING_ENGINE_FNS:?} are the functions that record a denial inline; if \
             none of them constructs one, either the chain has been rewritten or this gate has \
             stopped reading it."
        );
    }
    // The same check for the handler port, and it earns its place the same way: `ENC-606` was a
    // whole class of refusal with no row behind it, and the fix is one function. If that function
    // stops existing — renamed, moved, inlined into a handler — every `Refused` site would still
    // classify as `audited (handler)` off its return type alone, and the classification would be
    // describing a path that no longer records anything.
    if !sites.iter().any(|site| site.position == Position::HandlerAudits) {
        anyhow::bail!(
            "audit-coverage: nothing in {REFUSAL_FILE} was classified as the handler port's own \
             audited refusal. `HandlerAudit::{RECORD_FN}` is the one place a handler's refusal \
             becomes the caller's error, and the one place it is recorded; if it is no longer \
             there, `ENC-606` is open again and every site this gate calls `audited (handler)` is \
             mis-classified."
        );
    }
    Ok(())
}

/// Fail on the difference between what refuses and what audits.
///
/// Takes the acknowledgement list as an argument rather than reading the `const` directly, so the
/// gate's own tests can exercise the decision against a synthetic inventory. A test that could only
/// call this with the real list would be asserting the tree's current state, not the rule.
///
/// # Errors
///
/// When a refusal is constructed in an unaudited position with no acknowledgement, or when an
/// acknowledgement names a site that no longer exists.
pub(crate) fn decide(sites: &[Site], acknowledged: &[Acknowledged]) -> Result<()> {
    let unaudited: Vec<&Site> = sites
        .iter()
        .filter(|site| {
            site.position == Position::Unaudited && covering(site, acknowledged).is_none()
        })
        .collect();

    let stale: Vec<&Acknowledged> =
        acknowledged.iter().filter(|ack| !sites.iter().any(|site| ack.covers(site))).collect();

    for site in &unaudited {
        println!(
            "::error file={},line={},title=GATE FAILED: audit coverage::{}() constructs a refusal \
             with `{}` and returns it to something this gate cannot see recording it, so no audit \
             row is proven. Fix: {}, or add an entry to ACKNOWLEDGED in \
             xtask/src/audit_coverage.rs with the reason and the tracker row that owns the gap.",
            site.file,
            site.line,
            site.function,
            site.kind.label(),
            site.kind.remedy(),
        );
    }
    for ack in &stale {
        println!(
            "::error file={},title=GATE FAILED: audit coverage::the ACKNOWLEDGED entry for {}() \
             names no `{}` site any more. Delete it — an exemption for something that no longer \
             exists is how an allowlist rots into a list of names nobody dares remove.",
            ack.file,
            ack.function,
            ack.kind.label(),
        );
    }

    if unaudited.is_empty() && stale.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "audit-coverage: {} unaudited refusal site(s) and {} stale acknowledgement(s)",
        unaudited.len(),
        stale.len()
    )
}

/// The acknowledgement covering a site, if there is one.
fn covering<'a>(site: &Site, acknowledged: &'a [Acknowledged]) -> Option<&'a Acknowledged> {
    acknowledged.iter().find(|ack| ack.covers(site))
}

/// Print every site with its verdict, grouped by file.
///
/// Printed in full rather than only on failure, for the reason `policy_routing` prints its
/// allowlist: an inventory nobody sees is an inventory nobody revisits, and the number of places
/// this system can refuse a request is exactly the sort of figure that should move visibly.
fn print_inventory(sites: &[Site]) {
    println!();
    println!("{} refusal site(s):", sites.len());
    let mut current = "";
    for site in sites {
        if site.file != current {
            current = &site.file;
            println!("  {current}");
        }
        println!(
            "    [{}] {}:{} {}() — {}",
            site.position.verdict(),
            site.file,
            site.line,
            site.function,
            site.kind.label()
        );
    }
}

/// Print the acknowledgement list and whether each entry is still doing anything.
///
/// Printed on every run, not only on failure, for the reason `policy_routing` prints its allowlist:
/// "this refusal writes no audit row" belongs in the log of every pull request, where a reviewer
/// meets it, rather than in a `const` three files deep that was last read when it was written.
fn print_acknowledgements(sites: &[Site], acknowledged: &[Acknowledged]) {
    println!();
    println!(
        "Acknowledged — {} site(s) that construct a refusal outside an audited position, each \
         with its reason:",
        acknowledged.len()
    );
    for ack in acknowledged {
        let live = sites.iter().any(|site| ack.covers(site));
        let marker = if live { "" } else { "  (STALE — no such site)" };
        println!("  - {}::{}() [{}]{marker}", ack.file, ack.function, ack.kind.label());
        println!("      {}", ack.reason);
    }
}

// ---------------------------------------------------------------------------
// Analysis — pure, so it can be tested on source strings rather than on files
// ---------------------------------------------------------------------------

/// Analyze a set of `(display_path, source)` pairs into a sorted inventory of refusal sites.
///
/// Takes sources rather than paths for the reason `policy_routing::analyze` does: the gate's own
/// tests then exercise the real classification on synthetic crates, including the violation it
/// exists to catch, which no fixture on disk can contain without breaking the build.
///
/// # Errors
///
/// Returns an error if any source fails to parse.
pub(crate) fn analyze(sources: &[(String, String)]) -> Result<Vec<Site>> {
    let mut sites = Vec::new();
    for (display_path, source) in sources {
        let file = syn::parse_file(source)
            .with_context(|| format!("parsing {display_path} as Rust source"))?;
        let mut visitor = SiteCollector {
            file: display_path.clone(),
            function: Vec::new(),
            returns_stage_decision: Vec::new(),
            returns_refused: Vec::new(),
            sites: &mut sites,
        };
        visitor.visit_file(&file);
    }
    sites.sort();
    sites.dedup();
    Ok(sites)
}

/// Walks one file, tracking which function each call sits in and what that function returns.
struct SiteCollector<'a> {
    file: String,
    /// Enclosing function names, innermost last. A stack because `impl` blocks and inline modules
    /// nest, and a closure inside a function is still that function's code.
    function: Vec<String>,
    /// Whether each enclosing function's return type mentions `StageDecision`.
    returns_stage_decision: Vec<bool>,
    /// Whether each enclosing function's return type mentions `Refused`.
    returns_refused: Vec<bool>,
    sites: &'a mut Vec<Site>,
}

impl SiteCollector<'_> {
    fn current_function(&self) -> String {
        self.function.last().cloned().unwrap_or_else(|| "<top level>".to_owned())
    }

    /// Where the innermost enclosing function puts this refusal.
    fn position(&self, kind: SiteKind) -> Position {
        let function = self.current_function();
        if kind != SiteKind::Conversion && self.returns_stage_decision.last().copied() == Some(true)
        {
            return Position::AuditedByStage;
        }
        // The same argument as the line above, one layer up: a `Refused` returned to a caller can
        // only become that caller's error through `HandlerAudit::refuse`, which records it first.
        if kind != SiteKind::Conversion && self.returns_refused.last().copied() == Some(true) {
            return Position::AuditedByHandler;
        }
        if self.file == ENGINE_FILE {
            if AUDITING_ENGINE_FNS.contains(&function.as_str()) {
                return Position::EngineAudits;
            }
            // `StageDecision::ensure_allowed`'s own body: the definition of the conversion, not a
            // use of it. Its `Error::denied` is how the vocabulary is written down.
            if function == CONVERSION_FN {
                return Position::Vocabulary;
            }
        }
        // `HandlerAudit::refuse`'s own body, which writes the row and *then* builds the error the
        // caller receives. Anywhere else in that file is classified by return type like any other.
        if self.file == REFUSAL_FILE && function == RECORD_FN {
            return Position::HandlerAudits;
        }
        if self.file == ERROR_FILE {
            return Position::Vocabulary;
        }
        Position::Unaudited
    }

    fn record(&mut self, kind: SiteKind, line: usize) {
        let position = self.position(kind);
        let function = self.current_function();
        let file = self.file.clone();
        self.sites.push(Site { file, line, function, kind, position });
    }

    /// Visit a function body with its name and return type pushed onto the stacks.
    fn in_function(&mut self, sig: &syn::Signature, block: &syn::Block) {
        self.function.push(sig.ident.to_string());
        self.returns_stage_decision.push(mentions(&sig.output, "StageDecision"));
        self.returns_refused.push(mentions(&sig.output, "Refused"));
        syn::visit::visit_block(self, block);
        self.function.pop();
        self.returns_stage_decision.pop();
        self.returns_refused.pop();
    }
}

impl<'ast> Visit<'ast> for SiteCollector<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_test_only(&node.attrs) {
            return;
        }
        self.in_function(&node.sig, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if is_test_only(&node.attrs) {
            return;
        }
        self.in_function(&node.sig, &node.block);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        // `#[cfg(test)] mod tests` is not shipped code. A test constructing a refusal to assert
        // something about it is not an enforcement point, and counting it would fill the inventory
        // with noise that trains people to stop reading it.
        if is_test_only(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(kind) = refusal_constructor(&node.func) {
            self.record(kind, line_of(&node.func));
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == CONVERSION_FN {
            self.record(SiteKind::Conversion, node.method.span().start().line);
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    /// Scan `macro_rules!` bodies as tokens, because `syn` does not parse them as code.
    ///
    /// Found by this gate's own liveness check on its first run, and it is the more important half
    /// of what that check bought. `PolicyEngine::enforce` runs its six stages through a
    /// `macro_rules! stage` defined in its own body — so *every* denial the engine takes, and the
    /// `record_deny` call that audits it, live inside tokens an AST walk never enters. The gate
    /// reported that it could not find the engine's refusal and refused to pass, which is the
    /// correct behaviour and would have been a green check under any other design.
    ///
    /// It also closes the obvious way around the gate: a lint that ignores macro bodies is a lint
    /// you evade by writing a macro.
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if is_test_only(&node.attrs) {
            return;
        }
        for (kind, line) in scan_tokens(node.mac.tokens.clone()) {
            self.record(kind, line);
        }
        syn::visit::visit_item_macro(self, node);
    }
}

/// Find refusal constructors in a raw token stream, descending into delimited groups.
///
/// Pattern matching on a flattened token list rather than parsing: a `macro_rules!` body is not
/// valid Rust on its own — `$stage:expr` is not an expression — so there is nothing to hand to
/// `syn::parse2`. Three patterns, each anchored on the owning type's identifier so that a bare
/// `deny(..)` helper is not mistaken for `StageDecision::deny`.
fn scan_tokens(tokens: proc_macro2::TokenStream) -> Vec<(SiteKind, usize)> {
    let mut flat = Vec::new();
    flatten(tokens, &mut flat);

    let mut found = Vec::new();
    for window in flat.windows(4) {
        let [a, b, c, d] = window else { continue };
        // `Owner :: member`
        if let (
            proc_macro2::TokenTree::Ident(owner),
            proc_macro2::TokenTree::Punct(first),
            proc_macro2::TokenTree::Punct(second),
            proc_macro2::TokenTree::Ident(member),
        ) = (a, b, c, d)
        {
            if first.as_char() == ':' && second.as_char() == ':' {
                if let Some(kind) = constructor(&owner.to_string(), &member.to_string()) {
                    found.push((kind, owner.span().start().line));
                }
            }
        }
    }
    for window in flat.windows(2) {
        let [a, b] = window else { continue };
        if let (proc_macro2::TokenTree::Punct(dot), proc_macro2::TokenTree::Ident(member)) = (a, b)
        {
            if dot.as_char() == '.' && member == CONVERSION_FN {
                found.push((SiteKind::Conversion, member.span().start().line));
            }
        }
    }
    found
}

/// Flatten a token stream, descending through every delimited group.
fn flatten(tokens: proc_macro2::TokenStream, out: &mut Vec<proc_macro2::TokenTree>) {
    for tree in tokens {
        if let proc_macro2::TokenTree::Group(group) = &tree {
            flatten(group.stream(), out);
        }
        out.push(tree);
    }
}

/// Which refusal constructor a call path names, if any.
///
/// Matched on the last two path segments so that `Error::denied`,
/// `enclave_core::Error::denied` and `core::Error::denied_with` all count, while a local
/// `denied(..)` helper — which is not the constructor — does not. `Self::` counts as well: the
/// `From<AuthError> for Error` conversion writes it that way, and a matcher that missed it would
/// have let an entire crate's refusals out of the inventory.
fn refusal_constructor(func: &syn::Expr) -> Option<SiteKind> {
    let syn::Expr::Path(path) = func else {
        return None;
    };
    let mut segments = path.path.segments.iter().rev();
    let last = segments.next()?.ident.to_string();
    let owner = segments.next()?.ident.to_string();
    constructor(&owner, &last)
}

/// The one table of refusal constructors, shared by the AST walk and the token scan.
///
/// One table rather than two, because the token scan exists to cover `macro_rules!` bodies and a
/// constructor added to only one of them would be invisible in exactly the place a syntactic gate
/// is most easily evaded.
///
/// `Refused::` matches on the owner alone: the type has no associated function that is not a
/// constructor — its helpers are free functions for this reason — so listing member names would
/// only create a fourth name somebody could add without the gate noticing.
fn constructor(owner: &str, member: &str) -> Option<SiteKind> {
    match (owner, member) {
        ("Error" | "Self", "denied" | "denied_with") => Some(SiteKind::ErrorRefusal),
        ("StageDecision" | "Self", "deny") => Some(SiteKind::StageRefusal),
        ("Refused", _) => Some(SiteKind::HandlerRefusal),
        _ => None,
    }
}

/// Whether a return type mentions a named type anywhere in it.
///
/// Textual on the token stream rather than a structural match, because each type appears in at
/// least four shapes — `StageDecision`, `Result<StageDecision>`, `Result<Vec<StageDecision>>` and
/// `Result<StageDecision, Error>` — and a structural match would need extending for each. The
/// direction of any error here is what makes that acceptable: an over-broad match classifies a
/// site as audited when it is not, so it is *checked* rather than assumed. For `StageDecision` the
/// `Conversion` enumeration is that check; for `Refused` it is the type itself — private fields,
/// no `From`, and one consumer — so there is no `ensure_allowed` equivalent to enumerate.
fn mentions(output: &syn::ReturnType, name: &str) -> bool {
    match output {
        syn::ReturnType::Default => false,
        syn::ReturnType::Type(_, ty) => {
            let mut found = false;
            let mut visitor = TypeNames { name, found: &mut found };
            visitor.visit_type(ty);
            found
        }
    }
}

/// Looks for a named path segment anywhere inside a type.
struct TypeNames<'a> {
    name: &'a str,
    found: &'a mut bool,
}

impl<'ast> Visit<'ast> for TypeNames<'_> {
    fn visit_path_segment(&mut self, node: &'ast syn::PathSegment) {
        if node.ident == self.name {
            *self.found = true;
        }
        syn::visit::visit_path_segment(self, node);
    }
}

/// Whether an item is compiled only under `cfg(test)`.
///
/// Matches `#[cfg(test)]` and `#[cfg(any(test, …))]` by looking for a bare `test` token inside a
/// `cfg` attribute. Deliberately not clever: the failure direction of a miss is a *larger*
/// inventory, which is noisy rather than unsafe.
fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr.meta.require_list().is_ok_and(|list| {
                list.tokens.to_string().split(|c: char| !c.is_alphanumeric()).any(|t| t == "test")
            })
    })
}

/// The 1-based line an expression starts on.
fn line_of(expr: &syn::Expr) -> usize {
    expr.span().start().line
}

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

/// Every `.rs` file under `crates/*/src`, as `(repo-relative path, source)`.
fn load_sources(dir: &Path, root: &Path) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    collect_rs(dir, &mut files)?;
    files.sort();

    let mut sources = Vec::with_capacity(files.len());
    for path in files {
        let display = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        sources.push((display, text));
    }
    Ok(sources)
}

/// Recurse into `crates/<name>/src` only — never `tests/`, `benches/` or `examples/`.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut crate_dirs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            crate_dirs.push(path);
        }
    }
    crate_dirs.sort();
    for crate_dir in crate_dirs {
        let src = crate_dir.join("src");
        if src.is_dir() {
            walk(&src, out)?;
        }
    }
    Ok(())
}

/// Depth-first walk collecting `.rs` files.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::result::Result<_, _>>()?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The workspace root, found by walking up from this crate's manifest directory.
fn workspace_root() -> Result<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join(CRATES_DIR).is_dir() && dir.join("Cargo.toml").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            anyhow::bail!("could not find the workspace root above {}", env!("CARGO_MANIFEST_DIR"));
        }
    }
}

#[cfg(test)]
mod tests {
    // A failed assertion is the point of a test, and an unparseable source string is a test bug
    // that should stop the run loudly. The workspace denies these in shipped code, not here.
    #![allow(clippy::panic, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    /// Analyze one synthetic source file under a chosen path.
    ///
    /// Source strings rather than fixtures on disk, for the reason `policy_routing`'s tests use
    /// them: the violation this gate exists to catch cannot be committed to the tree — it would be
    /// a rule 10 defect sitting in `crates/` — so the only way to watch the gate catch it is to
    /// hand it the code.
    fn sites(path: &str, source: &str) -> Vec<Site> {
        analyze(&[(path.to_owned(), source.to_owned())]).expect("the synthetic source should parse")
    }

    fn find<'a>(sites: &'a [Site], function: &str) -> &'a Site {
        sites
            .iter()
            .find(|site| site.function == function)
            .unwrap_or_else(|| panic!("no site inside {function}(), got {sites:?}"))
    }

    /// The gate, run against the real tree, so `cargo test --workspace` fails on a new unaudited
    /// refusal as well as the CI job does.
    ///
    /// Two ways to run one rule is usually a smell. Here it is the point: `ENC-543`'s failure was
    /// a *job* that passed while inspecting nothing, and a developer who runs the test suite before
    /// pushing should not have to also remember a second command to find out that they added a
    /// refusal nothing records.
    #[test]
    fn the_workspace_has_no_unaudited_refusal() {
        let root = workspace_root().expect("workspace root");
        let sources = load_sources(&root.join(CRATES_DIR), &root).expect("read crate sources");
        let sites = analyze(&sources).expect("parse crate sources");

        liveness(&sites).expect("the gate must inspect something");
        decide(&sites, ACKNOWLEDGED).expect("every refusal is audited or acknowledged");
    }

    /// The positive control, and the reason this file is not `ENC-543` again.
    ///
    /// Both halves are in one test on purpose. The audited half alone passes against a classifier
    /// that calls everything audited; the unaudited half alone passes against one that calls
    /// everything unaudited. The two together only pass if the return type is actually being read.
    #[test]
    fn a_refusal_outside_a_stage_is_reported_and_the_same_refusal_inside_one_is_not() {
        let found = sites(
            "crates/sharing/src/service.rs",
            r#"
            impl Service {
                async fn share(&self, ctx: &RequestContext) -> Result<Link> {
                    if self.blocked {
                        return Err(Error::denied(ReasonCode::ExternalShareBlocked));
                    }
                    self.issue(ctx).await
                }

                async fn evaluate(&self, ctx: &RequestContext) -> Result<StageDecision> {
                    if self.blocked {
                        return Ok(StageDecision::deny(ReasonCode::ExternalShareBlocked));
                    }
                    Ok(StageDecision::allow())
                }
            }
            "#,
        );

        assert_eq!(find(&found, "share").position, Position::Unaudited);
        assert_eq!(find(&found, "evaluate").position, Position::AuditedByStage);

        // And the decision, not merely the classification: the gate must actually fail.
        let error = decide(&found, &[]).expect_err("an unaudited refusal must fail the gate");
        assert!(
            error.to_string().contains("1 unaudited refusal site"),
            "the gate failed for the wrong reason: {error}"
        );

        // The same inventory, with the site acknowledged, passes — which is what proves the
        // failure above came from the classification rather than from anything else in `decide`.
        let ack = [Acknowledged {
            file: "crates/sharing/src/service.rs",
            function: "share",
            kind: SiteKind::ErrorRefusal,
            reason: "synthetic",
        }];
        decide(&found, &ack).expect("an acknowledged site passes");
    }

    /// The same rule for a handler's refusal, and the reason `ENC-606` cannot come back quietly.
    ///
    /// Both halves again, and here the negative half is the one that matters: the fix for `ENC-606`
    /// introduced a *new* way to refuse, and a gate that classified every `Refused::…` as audited
    /// would be blessing the construct rather than checking where it is used. A `Refused` built
    /// inline in a handler is consumed by nothing that records, so it is reported.
    #[test]
    fn a_handler_refusal_is_audited_only_when_it_is_returned_to_the_port() {
        let found = sites(
            "crates/api/src/files.rs",
            r#"
            fn satisfy(obligations: &Obligations) -> Result<(), Refused> {
                for obligation in obligations {
                    return Err(Refused::obligation(*obligation));
                }
                Ok(())
            }

            async fn get_file(state: State<ApiState>) -> Result<Json<File>, ApiError> {
                if ctx.actor.subject_id().is_none() {
                    return Err(ApiError::new(Refused::actor(code).into(), ctx.request_id));
                }
                Ok(Json(state.files.load(&resource).await?))
            }
            "#,
        );

        let audited = find(&found, "satisfy");
        assert_eq!(audited.kind, SiteKind::HandlerRefusal);
        assert_eq!(audited.position, Position::AuditedByHandler);

        let inline = find(&found, "get_file");
        assert_eq!(inline.kind, SiteKind::HandlerRefusal);
        assert_eq!(
            inline.position,
            Position::Unaudited,
            "a Refused built inline in a handler reaches the client through whatever the handler \
             does with it, which is not necessarily the audit port"
        );

        let error = decide(&found, &[]).expect_err("the inline refusal must fail the gate");
        assert!(
            error.to_string().contains("1 unaudited refusal site"),
            "the gate failed for the wrong reason: {error}"
        );
    }

    /// The handler port is checked for liveness, exactly as the engine is.
    ///
    /// `docs/12-TESTING.md §1.2`: every classification above is an assertion about where a site
    /// sits, and all of them stay true if the function they assume exists is deleted. A tree with
    /// `Refused` sites and no `HandlerAudit::refuse` is `ENC-606` re-opened with a green gate.
    #[test]
    fn an_inventory_with_no_handler_audit_port_fails_liveness() {
        // A tree that has one of every kind, and no `refuse()`.
        let mut found = sites(
            "crates/api/src/files.rs",
            r#"
            fn satisfy(obligations: &Obligations) -> Result<(), Refused> {
                Err(Refused::obligation(Obligation::NoDownload))
            }
            async fn evaluate(&self) -> Result<StageDecision> {
                Ok(StageDecision::deny(ReasonCode::AccessDenied))
            }
            async fn share(&self) -> Result<Link> {
                let obligations = decision.ensure_allowed()?;
                Err(Error::denied(ReasonCode::ExternalShareBlocked))
            }
            "#,
        );
        // The engine's own port, so that this test fails on the *handler* port's absence rather
        // than on the check above it.
        found.extend(sites(
            ENGINE_FILE,
            r#"
            impl PolicyEngine {
                pub async fn enforce(&self) -> Result<PolicyDecision> {
                    self.audit.record_deny(ctx, action, resource, stage, code).await?;
                    Err(Error::denied(code))
                }
            }
            "#,
        ));
        let error = liveness(&found).expect_err("no handler audit port must fail liveness");
        assert!(
            error.to_string().contains("ENC-606"),
            "the liveness failure must name what it is protecting: {error}"
        );

        // The positive control: the identical inventory *with* the port passes, which is what
        // proves the failure above came from the port's absence and not from the rest of it.
        found.extend(sites(
            REFUSAL_FILE,
            r#"
            impl HandlerAudit {
                pub async fn refuse(&self, refused: Refused) -> ApiError {
                    let _ = self.sink.record(event).await;
                    ApiError::new(Error::denied(refused.code), ctx.request_id)
                }
            }
            "#,
        ));
        liveness(&found).expect("an inventory with the port is live");
    }

    /// A refusal hidden in a `macro_rules!` body is still found.
    ///
    /// This is the shape `PolicyEngine::enforce` is actually written in, and the shape a plain AST
    /// walk misses entirely — which the gate's liveness check discovered on its first run. It is
    /// also the obvious way around a syntactic lint: write a macro.
    #[test]
    fn a_refusal_inside_a_macro_body_is_not_invisible() {
        let found = sites(
            "crates/sharing/src/service.rs",
            r#"
            impl Service {
                async fn share(&self, ctx: &RequestContext) -> Result<Link> {
                    macro_rules! stage {
                        ($call:expr) => {{
                            let decision = $call.await?;
                            if let StageOutcome::Deny(code) = *decision.outcome() {
                                return Err(Error::denied(code));
                            }
                            decision.ensure_allowed()?
                        }};
                    }
                    stage!(self.check(ctx));
                    self.issue(ctx).await
                }
            }
            "#,
        );

        let kinds: BTreeSet<SiteKind> = found.iter().map(|site| site.kind).collect();
        assert!(
            kinds.contains(&SiteKind::ErrorRefusal),
            "the Error::denied inside the macro body was not seen: {found:?}"
        );
        assert!(
            kinds.contains(&SiteKind::Conversion),
            "the ensure_allowed() inside the macro body was not seen: {found:?}"
        );

        // And the third constructor, which is the one most recently added and therefore the one a
        // token scanner is most likely to have been left without. The two matchers read one table
        // (`constructor`) for exactly this reason.
        let hidden = sites(
            "crates/api/src/files.rs",
            r#"
            async fn get_file(state: State<ApiState>) -> Result<Json<File>, ApiError> {
                macro_rules! discharge {
                    ($obligation:expr) => {
                        return Err(Refused::obligation($obligation))
                    };
                }
                discharge!(Obligation::NoDownload);
            }
            "#,
        );
        assert!(
            hidden.iter().any(|site| site.kind == SiteKind::HandlerRefusal),
            "the Refused:: inside the macro body was not seen: {hidden:?}"
        );
    }

    /// `ensure_allowed()` outside the engine is enumerated, because it is the one operation that
    /// turns a stage's refusal into the caller's error without the engine in between.
    ///
    /// Without this the first two checks would call the *construction* site audited — it does sit
    /// in a `Result<StageDecision>` function — and the denial would still reach a client with no
    /// row behind it.
    #[test]
    fn a_stage_decision_consumed_outside_the_engine_is_reported() {
        let found = sites(
            "crates/api/src/files.rs",
            r#"
            async fn get_file(state: State<App>) -> Result<Json<File>> {
                let decision = state.authorization.authorize(&ctx, action, &resource).await?;
                let obligations = decision.ensure_allowed()?;
                Ok(Json(state.files.load(&resource, obligations).await?))
            }
            "#,
        );

        let site = find(&found, "get_file");
        assert_eq!(site.kind, SiteKind::Conversion);
        assert_eq!(site.position, Position::Unaudited);
        decide(&found, &[]).expect_err("an unaudited conversion must fail the gate");
    }

    /// An acknowledgement for a site that no longer exists fails the gate.
    ///
    /// An allowlist nobody prunes becomes a list of names nobody dares delete, and every stale
    /// entry is a place a *new* refusal can be added under cover of an old reason.
    #[test]
    fn a_stale_acknowledgement_fails_the_gate() {
        let found = sites(
            "crates/sharing/src/service.rs",
            r#"
            impl Service {
                async fn evaluate(&self, ctx: &RequestContext) -> Result<StageDecision> {
                    Ok(StageDecision::deny(ReasonCode::ExternalShareBlocked))
                }
            }
            "#,
        );

        let ack = [Acknowledged {
            file: "crates/sharing/src/service.rs",
            function: "share",
            kind: SiteKind::ErrorRefusal,
            reason: "a refusal that was moved into the stage and never removed from here",
        }];
        let error = decide(&found, &ack).expect_err("a stale acknowledgement must fail the gate");
        assert!(
            error.to_string().contains("1 stale acknowledgement"),
            "the gate failed for the wrong reason: {error}"
        );

        decide(&found, &[]).expect("the same inventory with no acknowledgements passes");
    }

    /// An empty inventory fails, which is the whole of what `ENC-543` was missing.
    ///
    /// The composite-FK job exited zero having looked at no foreign key. This is that scenario,
    /// asserted: a gate that found nothing must say so rather than report success.
    #[test]
    fn an_inventory_that_found_nothing_fails_liveness() {
        let error = liveness(&[]).expect_err("an empty inventory must fail");
        assert!(
            error.to_string().contains("ENC-543"),
            "the liveness failure must say why it is a failure: {error}"
        );

        // A *partial* inventory fails too: finding stage refusals while finding no `Error::denied`
        // anywhere would mean half the scan had stopped working.
        let partial = sites(
            "crates/sharing/src/service.rs",
            r#"
            impl Service {
                async fn evaluate(&self, ctx: &RequestContext) -> Result<StageDecision> {
                    Ok(StageDecision::deny(ReasonCode::ExternalShareBlocked))
                }
            }
            "#,
        );
        liveness(&partial).expect_err("an inventory missing a whole constructor must fail");
    }

    /// A refusal written in a test is not an enforcement point.
    ///
    /// Counting them would fill the inventory with noise, and an inventory people stop reading is
    /// an inventory that stops working.
    #[test]
    fn a_test_only_module_contributes_no_sites() {
        let found = sites(
            "crates/sharing/src/service.rs",
            r#"
            #[cfg(test)]
            mod tests {
                #[test]
                fn a_blocked_share_is_refused() {
                    assert_eq!(service.share(), Err(Error::denied(ReasonCode::AccessDenied)));
                }
            }
            "#,
        );
        assert!(found.is_empty(), "test code was counted as an enforcement point: {found:?}");
    }

    /// `Self::denied` counts, because that is how the `AuthError -> Error` conversion writes it.
    ///
    /// Found by the acknowledgement list rather than by design: the entry for
    /// `crates/auth/src/error.rs` was reported **stale** on the first run and the site was real —
    /// the matcher was only looking for `Error::`. An entire crate's refusals were outside the
    /// inventory, and the staleness check is what said so.
    #[test]
    fn the_self_form_of_the_constructor_is_matched() {
        let found = sites(
            "crates/auth/src/error.rs",
            r#"
            impl From<AuthError> for Error {
                fn from(value: AuthError) -> Self {
                    match value.reason_code() {
                        Some(code) => Self::denied(code),
                        None => Self::Internal,
                    }
                }
            }
            "#,
        );
        assert_eq!(find(&found, "from").kind, SiteKind::ErrorRefusal);
    }
}
