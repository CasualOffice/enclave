//! ENC-167 — several actions resolved in one pass, against a real PostgreSQL.
//!
//! # What is actually at risk here
//!
//! Widening `ACL_ENTRIES_SQL` to `action = ANY(…)` makes one statement return rows for several
//! questions at once, and every one of those rows has to end up attached to the question it answers.
//! The failure that matters is not "the query is wrong" — a wrong query denies everything and is
//! noticed immediately — but a *grouping* mistake: one action's `DENY` filed under another action,
//! which either suppresses a grant the caller holds or, in the other direction, lets a caller keep
//! an action a tenant explicitly took away. That is a privilege change, so these tests are arranged
//! to make it impossible for the same verdict to be reached for two different reasons.
//!
//! Three properties, in the order they matter:
//!
//! 1. one resource can genuinely resolve *differently* per action — a suite where every action
//!    agreed would pass against a resolver that answered the first action nine times;
//! 2. a `DENY` written for one action changes no other action's answer, asserted over a batch whose
//!    verdict matrix is different in every row and every column, so a zip or a chunk that slipped by
//!    one is visible rather than plausible;
//! 3. the multi-action answer is *identical* to what the per-action calls return, decision by
//!    decision, so this stays an optimisation rather than a second access model.
//!
//! Everything measured runs over [`enclave_testing::TestDb::pool`], which `SET ROLE enclave_app`s;
//! fixtures are written over the harness's administrative connection. A test that resolved on the
//! admin connection would bypass row-level security and pass no matter what the policies said
//! (PR #22).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use chrono::Utc;
use enclave_authorization::{AclResolver, Effective, PgAclAuthorization};
use enclave_core::{
    Action, Actor, AuthorizationService as _, FileAction, FileId, RequestContext, ResourceRef,
    TenantId, UserId,
};
use enclave_testing::content::{grant, AclEffect, AclPrincipal, AclScope, Spine};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;

/// Four actions that a policy is entitled to answer four different ways.
///
/// `preview` and `download` are the pair `CLAUDE.md` rule 6 exists for — "view it in the browser,
/// but it never leaves the browser" is exactly one `ALLOW` and one `DENY` on the same file — and
/// `print` and `export` are the two a naive download-blocking policy misses.
const ACTIONS: [Action; 4] = [
    Action::File(FileAction::Preview),
    Action::File(FileAction::Download),
    Action::File(FileAction::Print),
    Action::File(FileAction::Export),
];

/// Spines in the batch. Coprime with [`ACTIONS`]'s length, so the verdict matrix below repeats no
/// row and no column: a transposition or an off-by-one has nowhere to hide.
const SPINES: usize = 5;

fn ctx(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::User(user);
    ctx
}

async fn setup() -> (TestDb, Fixtures) {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    (db, fixtures)
}

/// What the corpus below is built to say about one `(spine, action)` pair.
///
/// Written as a function rather than a table so the expectation is generated from the same
/// arithmetic the fixtures are, and cannot be quietly edited to match a wrong answer one cell at a
/// time.
fn expected(spine: usize, action: usize) -> Effective {
    if action == spine % ACTIONS.len() {
        Effective::Allowed
    } else if action == (spine + 1) % ACTIONS.len() {
        Effective::Denied
    } else {
        Effective::NotGranted
    }
}

/// Builds [`SPINES`] independent spines whose verdicts rotate through [`ACTIONS`].
///
/// Each spine grants one action on its file and denies the *next* one — while granting that next
/// one on the library above, so the refusal is a `DENY` that had something to beat rather than a
/// grant nobody wrote. That distinction is the whole point: without the library `ALLOW`, a resolver
/// that dropped every `DENY` on the floor would still produce `NotGranted` and still pass.
async fn rotating_corpus(
    conn: &mut PgConnection,
    tenant: TenantId,
    fixtures: &Fixtures,
    caller: UserId,
) -> Vec<Spine> {
    let mut spines = Vec::with_capacity(SPINES);
    for index in 0..SPINES {
        let spine = Spine::new(tenant);
        spine.insert(conn, fixtures.alpha.owner, Utc::now()).await.expect("insert the spine");

        let allowed = ACTIONS[index % ACTIONS.len()];
        let denied = ACTIONS[(index + 1) % ACTIONS.len()];

        grant(
            conn,
            tenant,
            AclScope::File(spine.file),
            AclPrincipal::User(caller),
            allowed,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("allow one action on the file");
        grant(
            conn,
            tenant,
            AclScope::Library(spine.library),
            AclPrincipal::User(caller),
            denied,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("allow the next action on the library");
        grant(
            conn,
            tenant,
            AclScope::File(spine.file),
            AclPrincipal::User(caller),
            denied,
            AclEffect::Deny,
            None,
        )
        .await
        .expect("deny the next action on the file");

        spines.push(spine);
    }
    spines
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn one_resource_resolves_differently_for_different_actions() {
    // The smallest arrangement that proves the pass is answering per action at all: one file, one
    // caller, three actions, three different verdicts. `preview` is granted, `download` is granted
    // on the library and denied on the file, `print` was never mentioned by anybody.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let spine = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("insert the spine");
    for (scope, action, effect) in [
        (AclScope::File(spine.file), FileAction::Preview, AclEffect::Allow),
        (AclScope::Library(spine.library), FileAction::Download, AclEffect::Allow),
        (AclScope::File(spine.file), FileAction::Download, AclEffect::Deny),
    ] {
        grant(
            &mut admin,
            alpha,
            scope,
            AclPrincipal::User(caller),
            Action::File(action),
            effect,
            None,
        )
        .await
        .expect("write the entry");
    }

    let actions = [
        Action::File(FileAction::Preview),
        Action::File(FileAction::Download),
        Action::File(FileAction::Print),
    ];

    let pool = db.pool().await.expect("application-role pool");
    let mut tx = enclave_db::TenantScoped::begin(&pool, alpha).await.expect("begin");
    let grid = AclResolver::new()
        .effective_actions_in_tx(
            &mut tx,
            alpha,
            &Actor::User(caller),
            &actions,
            &[spine.file_ref()],
            Utc::now(),
        )
        .await
        .expect("resolve");
    tx.commit().await.expect("commit");

    assert_eq!(grid.actions(), actions.len());
    assert_eq!(grid.resources(), 1);
    // Three-valued rather than a boolean, so "the DENY won" is told apart from "nothing matched" —
    // the two ways this assertion could otherwise pass for the wrong reason.
    assert_eq!(
        grid.get(0, 0),
        Some(Effective::Allowed),
        "the preview grant did not reach the file"
    );
    assert_eq!(
        grid.get(1, 0),
        Some(Effective::Denied),
        "the download DENY on the file lost to the ALLOW on the library, or never arrived"
    );
    assert_eq!(
        grid.get(2, 0),
        Some(Effective::NotGranted),
        "an action nobody wrote an entry for came back granted or explicitly denied"
    );
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn a_deny_written_for_one_action_changes_no_other_actions_answer() {
    // Twenty cells — five resources by four actions — with a rotating pattern, so every action has
    // an `ALLOW` somewhere, a `DENY` somewhere and silence somewhere, and no two resources agree.
    // A grouping bug that filed one action's rows under its neighbour would move the diagonal; a
    // zip that slipped a resource would rotate it. Both show up as a named cell rather than as a
    // count that happens to still add up.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;

    let mut admin = db.connect().await.expect("admin connection");
    let spines = rotating_corpus(&mut admin, alpha, &fixtures, caller).await;
    let resources: Vec<ResourceRef> = spines.iter().map(Spine::file_ref).collect();

    let pool = db.pool().await.expect("application-role pool");
    let mut tx = enclave_db::TenantScoped::begin(&pool, alpha).await.expect("begin");
    let grid = AclResolver::new()
        .effective_actions_in_tx(
            &mut tx,
            alpha,
            &Actor::User(caller),
            &ACTIONS,
            &resources,
            Utc::now(),
        )
        .await
        .expect("resolve");
    tx.commit().await.expect("commit");

    assert_eq!(grid.actions(), ACTIONS.len());
    assert_eq!(grid.resources(), resources.len());
    for (spine, _) in spines.iter().enumerate().take(SPINES) {
        for (action, name) in ACTIONS.iter().enumerate() {
            assert_eq!(
                grid.get(action, spine),
                Some(expected(spine, action)),
                "resource {spine} resolved {name} wrongly: the entries written for it are an \
                 ALLOW on {} and a DENY on {}",
                ACTIONS[spine % ACTIONS.len()],
                ACTIONS[(spine + 1) % ACTIONS.len()]
            );
        }
    }

    // Stated separately from the loop because it is the security property rather than a shape
    // check: for every resource there is an action that is denied and an action that is allowed,
    // and neither ever became the other.
    for spine in 0..SPINES {
        let allowed = spine % ACTIONS.len();
        let denied = (spine + 1) % ACTIONS.len();
        assert_eq!(
            grid.get(allowed, spine),
            Some(Effective::Allowed),
            "the DENY on {} suppressed the ALLOW on {} — one action's refusal reached another",
            ACTIONS[denied],
            ACTIONS[allowed]
        );
        assert_eq!(
            grid.get(denied, spine),
            Some(Effective::Denied),
            "the ALLOW on {} satisfied {} — one action's grant reached another",
            ACTIONS[allowed],
            ACTIONS[denied]
        );
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn the_multi_action_pass_returns_exactly_what_the_per_action_calls_return() {
    // The equality that keeps this an optimisation rather than a second access model. Whole
    // `StageDecision`s are compared, not `is_allowed()`: a decision carries its obligations, and an
    // obligation dropped on the way through a wider query is `CLAUDE.md` rule 8 broken silently.
    //
    // The batch deliberately holds more than the well-behaved cases: a file in another tenant, a
    // file that does not exist, and a duplicate — the three inputs whose answers come from a
    // different branch of the resolver, and the three most likely to lose their place in a grid.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;
    let caller = fixtures.alpha.member;

    let mut admin = db.connect().await.expect("admin connection");
    let spines = rotating_corpus(&mut admin, alpha, &fixtures, caller).await;

    // Beta grants everyone everything on a file of its own — the most permissive entry that can
    // exist, so if a multi-action pass ever leaked across the tenant boundary it would leak here.
    let foreign = Spine::new(beta);
    foreign.insert(&mut admin, fixtures.beta.owner, Utc::now()).await.expect("insert beta's spine");
    for action in ACTIONS {
        grant(
            &mut admin,
            beta,
            AclScope::File(foreign.file),
            AclPrincipal::Everyone,
            action,
            AclEffect::Allow,
            None,
        )
        .await
        .expect("beta grants everyone");
    }

    let mut resources: Vec<ResourceRef> = spines.iter().map(Spine::file_ref).collect();
    resources.push(foreign.file_ref());
    resources.push(ResourceRef::file(alpha, FileId::new_v7()));
    resources.push(spines[0].file_ref());

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);
    let ctx = ctx(alpha, caller);

    let rows = authz.authorize_many_actions(&ctx, &ACTIONS, &resources).await.expect("resolve");
    assert_eq!(rows.len(), ACTIONS.len(), "the pass lost or invented an action");

    for (index, action) in ACTIONS.iter().enumerate() {
        let separately =
            authz.authorize_many(&ctx, *action, &resources).await.expect("resolve one action");
        assert_eq!(
            rows[index].len(),
            resources.len(),
            "the row for {action} lost or invented a verdict"
        );
        assert_eq!(
            rows[index], separately,
            "the multi-action pass disagreed with authorize_many for {action}"
        );

        // And with the singular form, which is the one an endpoint calls. Compared per resource so
        // a failure names the resource rather than the whole row.
        for (position, resource) in resources.iter().enumerate() {
            let single = authz.authorize(&ctx, *action, resource).await.expect("resolve singly");
            assert_eq!(
                rows[index][position], single,
                "the multi-action pass disagreed with authorize for {action} on {resource}"
            );
        }
    }

    // The three awkward inputs, spelled out so this test fails loudly if they ever stop being
    // awkward — an equality assertion alone would still pass if every path allowed everything.
    let foreign_at = SPINES;
    let missing_at = SPINES + 1;
    let duplicate_at = SPINES + 2;
    for (index, action) in ACTIONS.iter().enumerate() {
        assert!(
            !rows[index][foreign_at].is_allowed(),
            "beta's EVERYONE grant on {action} reached a caller in alpha"
        );
        assert!(
            !rows[index][missing_at].is_allowed(),
            "a file that does not exist was allowed {action}"
        );
        assert_eq!(
            rows[index][duplicate_at], rows[index][0],
            "the duplicate of the first resource got a different answer for {action}"
        );
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn the_grid_is_full_sized_even_when_nothing_is_queried() {
    // The early returns — no ACL principal, nothing resolvable, no actions — have to produce an
    // answer of the shape the caller asked for. A caller that asked four questions and got two rows
    // has to invent the other two, and the invented answer is exactly where a default of "allow"
    // creeps in.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let spine = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("insert the spine");
    grant(
        &mut admin,
        alpha,
        AclScope::File(spine.file),
        AclPrincipal::Everyone,
        ACTIONS[0],
        AclEffect::Allow,
        None,
    )
    .await
    .expect("grant to everyone");

    let pool = db.pool().await.expect("application-role pool");
    let resolver = AclResolver::new();
    let resources = [spine.file_ref(), ResourceRef::user(alpha, fixtures.alpha.member)];

    let mut tx = enclave_db::TenantScoped::begin(&pool, alpha).await.expect("begin");

    // An MCP client is not an ACL principal, so nothing is queried — and `EVERYONE` must not reach
    // it (`crates/authorization/src/resolve.rs`), for all four actions.
    let mcp = Actor::McpClient(enclave_core::McpClientId::new_v7());
    let grid = resolver
        .effective_actions_in_tx(&mut tx, alpha, &mcp, &ACTIONS, &resources, Utc::now())
        .await
        .expect("resolve");
    assert_eq!(grid.actions(), ACTIONS.len());
    assert_eq!(grid.resources(), resources.len());
    assert!(
        grid.rows().flatten().all(|verdict| *verdict == Effective::NotGranted),
        "an actor no ACL entry can name was granted something"
    );

    // A batch of nothing this resolver has an inheritance model for: same shape, same refusals.
    let unsupported = [ResourceRef::user(alpha, fixtures.alpha.member)];
    let grid = resolver
        .effective_actions_in_tx(
            &mut tx,
            alpha,
            &Actor::User(fixtures.alpha.member),
            &ACTIONS,
            &unsupported,
            Utc::now(),
        )
        .await
        .expect("resolve");
    assert_eq!(grid.actions(), ACTIONS.len());
    assert!(grid.rows().flatten().all(|verdict| *verdict == Effective::NotGranted));

    // No actions at all: no rows, and no statement worth issuing.
    let grid = resolver
        .effective_actions_in_tx(
            &mut tx,
            alpha,
            &Actor::User(fixtures.alpha.member),
            &[],
            &resources,
            Utc::now(),
        )
        .await
        .expect("resolve");
    assert_eq!(grid.actions(), 0);
    assert_eq!(grid.for_action(0), None);
    tx.commit().await.expect("commit");
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migration 0004 applied; CI runs it with --include-ignored"]
async fn an_action_asked_about_twice_is_answered_twice() {
    // A capability table that happens to name an action twice must get the same answer at both
    // positions. The bucketing keyed by the action's text is where this could go wrong: a map from
    // action to *one* index would leave the second position empty, and an empty answer reads as
    // "not granted", which is a permission removed rather than an error raised.
    let (db, fixtures) = setup().await;
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;
    let spine = Spine::new(alpha);

    let mut admin = db.connect().await.expect("admin connection");
    spine.insert(&mut admin, fixtures.alpha.owner, Utc::now()).await.expect("insert the spine");
    grant(
        &mut admin,
        alpha,
        AclScope::File(spine.file),
        AclPrincipal::User(caller),
        ACTIONS[0],
        AclEffect::Allow,
        None,
    )
    .await
    .expect("grant the repeated action");

    let repeated = [ACTIONS[0], ACTIONS[1], ACTIONS[0]];
    let pool = db.pool().await.expect("application-role pool");
    let mut tx = enclave_db::TenantScoped::begin(&pool, alpha).await.expect("begin");
    let grid = AclResolver::new()
        .effective_actions_in_tx(
            &mut tx,
            alpha,
            &Actor::User(caller),
            &repeated,
            &[spine.file_ref()],
            Utc::now(),
        )
        .await
        .expect("resolve");
    tx.commit().await.expect("commit");

    assert_eq!(grid.get(0, 0), Some(Effective::Allowed));
    assert_eq!(grid.get(1, 0), Some(Effective::NotGranted));
    assert_eq!(
        grid.get(2, 0),
        Some(Effective::Allowed),
        "the repeated action was answered at its first position only"
    );
}
