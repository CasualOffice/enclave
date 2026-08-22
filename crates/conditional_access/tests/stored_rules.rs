//! `ENC-590` — a tenant's stored rules decide that tenant's requests, and nobody else's.
//!
//! `ENC-583` proved the evaluator. These tests are about the two things that only exist once rules
//! are rows: that one tenant's rules never reach another tenant's request, and that the stage
//! `crates/api/src/main.rs` now wires actually refuses something.
//!
//! # Every assertion here is watched against its control
//!
//! `docs/12-TESTING.md §1.2`: **an assertion about an absence passes for free.** "`tenant-beta`'s
//! request was not denied" is true of an evaluator that denies nothing, of a rule that was never
//! stored, of a fixture whose tenants collide, and of a stage that is never called. So the
//! cross-tenant test denies `tenant-alpha`'s *identical* request from the *same* rule in the same
//! run, and the fixtures are the seeded `tenant-alpha`/`tenant-beta` pair, which carry the same
//! names on purpose (`docs/12 §3`).
//!
//! Every test runs over the **application** role, never the harness superuser: a superuser bypasses
//! row-level security entirely, and a cross-tenant assertion run as one proves nothing (PR #22,
//! `ENC-124`).
//!
//! # Which mechanism `one_tenants_rules_never_decide_another_tenants_request` proves
//!
//! Recorded because a deliberate break did **not** fail it, which `docs/12 §1.2` says is a finding
//! rather than a shrug. Removing the repository's `tenant_id = $1` predicate — layer 1 — leaves this
//! test green: row-level security holds the property on its own, which is exactly what `§4.1`'s `T5`
//! asserts as a designed property of the two layers rather than a redundancy.
//!
//! So this test proves *isolation*, not the predicate. The predicate is held by
//! `enclave_db::conditional_access`'s own `the_load_statement_reads_only_live_rules_of_one_tenant`,
//! which fails on that break. And the isolation claim is not vacuous: with the predicate removed
//! **and** the migration's policy weakened to `USING (true)`, this test fails with
//! *"tenant-beta was decided against tenant-alpha's rule: Some(AccessDenied)"* — so it is capable of
//! catching the leak it is named for.
//!
//! Ignored by default because they need a live PostgreSQL. CI runs them with `--include-ignored`;
//! locally, start `deploy/compose/dev.yml` and set `DATABASE_URL`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use core::net::IpAddr;
use core::time::Duration;

use enclave_conditional_access::{
    encode_human, encode_machine, Effect, HumanCondition, HumanRule, MachineCondition, MachineRule,
    NetworkZone, RuleMode, TenantConditionalAccess, ZoneMap,
};
use enclave_core::{
    Action, Actor, ClientType, ConditionalAccessService, FileAction, FileId, ReasonCode,
    RequestContext, ResourceRef, ServiceAccountId, StageDecision, StageOutcome, TenantId, UserId,
};
use enclave_db::{insert_rule, load_rules, set_rule_mode, withdraw_rule, DbPool, RuleId, RuleRow};
use enclave_testing::{Fixtures, TestDb};
use sqlx::Row as _;

const DOWNLOAD: Action = Action::File(FileAction::Download);
const PREVIEW: Action = Action::File(FileAction::Preview);

/// A migrated, seeded database and an application-role pool over it.
async fn harness() -> (TestDb, Fixtures, DbPool) {
    let db = TestDb::start().await.expect(
        "these tests need a PostgreSQL they may create databases on; CI provides a service \
         container, locally use deploy/compose/dev.yml and set DATABASE_URL",
    );
    let fixtures = db.seed().await.expect("seed tenant-alpha and tenant-beta");
    let pool = db.pool_with_connections(4).await.expect("application pool");
    (db, fixtures, pool)
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("a fixture address")
}

/// A person on an untrusted network, on the web client, in `tenant`.
fn person(tenant: TenantId, user: UserId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::User(user);
    ctx.client = ClientType::Web;
    ctx.network.source_ip = ip("192.0.2.44");
    ctx
}

/// A service account in `tenant`, calling the API from the same address.
fn service_account(tenant: TenantId) -> RequestContext {
    let mut ctx = RequestContext::system(tenant);
    ctx.actor = Actor::ServiceAccount(ServiceAccountId::new_v7());
    ctx.client = ClientType::Api;
    ctx.network.source_ip = ip("192.0.2.44");
    ctx
}

fn denied_with(decision: &StageDecision) -> Option<ReasonCode> {
    match decision.outcome() {
        StageOutcome::Deny(code) => Some(*code),
        StageOutcome::Allow => None,
    }
}

/// The stage as `main.rs` builds it, with caching switched off so that a test asserting *rules* is
/// not accidentally asserting the cache. The cache has its own test below.
fn stage(pool: &DbPool) -> TenantConditionalAccess {
    TenantConditionalAccess::new(pool.clone(), zones()).with_cache_ttl(Duration::ZERO)
}

fn zones() -> ZoneMap {
    ZoneMap::new([NetworkZone::new(
        "Corporate India",
        ["203.0.113.0/24".parse().expect("a fixture prefix")],
    )])
}

/// Stores a human rule for `tenant`, authored by `author`, and returns its id.
async fn store_human(pool: &DbPool, tenant: TenantId, author: UserId, rule: &HumanRule) -> RuleId {
    let id = RuleId::new_v7();
    let row = encode_human(id, rule).expect("encodes");
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_rule(&mut tx, &row, author).await.expect("insert the rule");
    tx.commit().await.expect("commit");
    id
}

/// Stores a machine rule for `tenant`.
async fn store_machine(
    pool: &DbPool,
    tenant: TenantId,
    author: UserId,
    rule: &MachineRule,
) -> RuleId {
    let id = RuleId::new_v7();
    let row = encode_machine(id, rule).expect("encodes");
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_rule(&mut tx, &row, author).await.expect("insert the rule");
    tx.commit().await.expect("commit");
    id
}

/// The rule used wherever a test needs one that visibly refuses something.
///
/// Two conditions rather than one, and the second is what makes every test in this file able to
/// tell a working stage from a broken one: with `ClientIs([Web])` alone the rule matches *every*
/// action from a browser, so `Preview` would be refused too and "the rule did not fire" would be
/// indistinguishable from "the stage denied everything". Conditions are conjunctive, so this fires
/// on a web download and on nothing else.
fn block_downloads() -> HumanRule {
    HumanRule::new(
        "no downloads from the web",
        vec![
            HumanCondition::ClientIs(vec![ClientType::Web]),
            HumanCondition::ActionIs(vec![DOWNLOAD]),
        ],
        Effect::Block,
    )
}

// --- The assertion that matters most: one tenant's rules, one tenant's requests -----------------

/// `tenant-alpha`'s rule refuses `tenant-alpha` and is invisible to `tenant-beta`.
///
/// The negative half — beta is not denied — is the one that passes for free, so it never stands
/// alone. In the same run, against the same stage, over the same pool: alpha's identical request is
/// **denied** by that rule, and beta's rule set comes back empty from the repository while alpha's
/// comes back with one row. Both fixtures are the seeded tenants, whose rules have the same name.
///
/// The mirror leg matters as much: beta stores a rule of its own, and alpha must not be denied by
/// *that* one either. A leak in only one direction is still a leak, and a test that checked one
/// direction would pass against a decoder that hard-coded the first tenant it ever saw.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn one_tenants_rules_never_decide_another_tenants_request() {
    let (_db, fixtures, pool) = harness().await;
    let alpha = fixtures.alpha.id;
    let beta = fixtures.beta.id;
    let stage = stage(&pool);
    let resource = ResourceRef::file(alpha, FileId::new_v7());

    store_human(&pool, alpha, fixtures.alpha.admin, &block_downloads()).await;

    // The positive control, asserted first: the rule engages for the tenant that wrote it.
    let alpha_ctx = person(alpha, fixtures.alpha.member);
    let alpha_decision =
        stage.evaluate(&alpha_ctx, DOWNLOAD, &resource).await.expect("evaluation succeeds");
    assert_eq!(
        denied_with(&alpha_decision),
        Some(ReasonCode::AccessDenied),
        "the tenant that wrote the rule must be refused by it, or the absence below is vacuous"
    );

    // The absence, against a request that differs only in whose tenant it is.
    let beta_ctx = person(beta, fixtures.beta.member);
    let beta_decision =
        stage.evaluate(&beta_ctx, DOWNLOAD, &resource).await.expect("evaluation succeeds");
    assert!(
        beta_decision.is_allowed(),
        "tenant-beta was decided against tenant-alpha's rule: {:?}",
        denied_with(&beta_decision)
    );

    // The same claim one layer down, where a leak would actually happen.
    let mut tx = pool.begin(beta).await.expect("begin");
    let beta_rules = load_rules(&mut tx).await.expect("load");
    tx.commit().await.expect("commit");
    assert!(beta_rules.is_empty(), "tenant-beta loaded {} of alpha's rules", beta_rules.len());

    let mut tx = pool.begin(alpha).await.expect("begin");
    let alpha_rules = load_rules(&mut tx).await.expect("load");
    tx.commit().await.expect("commit");
    assert_eq!(alpha_rules.len(), 1, "tenant-alpha must see its own rule");

    // The mirror: beta's own rule refuses beta and not alpha. Same name, deliberately.
    store_human(&pool, beta, fixtures.beta.admin, &block_downloads()).await;
    let beta_now = stage.evaluate(&beta_ctx, DOWNLOAD, &resource).await.expect("evaluation");
    assert_eq!(
        denied_with(&beta_now),
        Some(ReasonCode::AccessDenied),
        "tenant-beta's own rule must refuse tenant-beta"
    );
    let alpha_still = stage.evaluate(&alpha_ctx, PREVIEW, &resource).await.expect("evaluation");
    assert!(alpha_still.is_allowed(), "tenant-alpha was refused by tenant-beta's rule");
}

/// A rule cannot name another tenant's administrator as its author.
///
/// PostgreSQL runs referential-integrity checks with row security deliberately **not** enforced, so
/// a single-column `REFERENCES users (id)` would accept `tenant-beta`'s admin as the author of a
/// `tenant-alpha` rule — two individually well-formed rows, and RLS refuses neither
/// (`docs/04 §3.3`, `ENC-543`). The composite key is what closes it, and this is the test that
/// would notice if the key were ever simplified.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_cannot_be_authored_by_another_tenants_administrator() {
    let (_db, fixtures, pool) = harness().await;
    let row = encode_human(RuleId::new_v7(), &block_downloads()).expect("encodes");

    let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
    let refused = insert_rule(&mut tx, &row, fixtures.beta.admin).await;
    assert!(
        refused.is_err(),
        "a tenant-alpha rule was accepted with tenant-beta's administrator as its author"
    );
    drop(tx);

    // The control: the same row, the same statement, this tenant's own administrator.
    let mut tx = pool.begin(fixtures.alpha.id).await.expect("begin");
    insert_rule(&mut tx, &row, fixtures.alpha.admin).await.expect("this tenant's admin may author");
    tx.commit().await.expect("commit");
}

// --- The vocabularies the database enforces -----------------------------------------------------

/// `ALLOW` cannot be written, on any path.
///
/// `docs/06 §7.4` explains why there is no allow: under most-restrictive-wins it can never change
/// an outcome, so accepting one would let an administrator write an exception, see it stored, and
/// have it do nothing. `Effect::from_sql` refuses the string; this asserts the half that holds for
/// callers who never went through the enum, which is the half that survives a repair script.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_database_refuses_an_allow_effect_and_an_invented_audience() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let base = encode_human(RuleId::new_v7(), &block_downloads()).expect("encodes");

    for (label, row) in [
        ("an ALLOW effect", RuleRow { effect: "ALLOW".to_owned(), ..base.clone() }),
        ("an invented audience", RuleRow { audience: "EVERYONE".to_owned(), ..base.clone() }),
        ("an invented mode", RuleRow { mode: "ADVISORY".to_owned(), ..base.clone() }),
        (
            "conditions that are not an array",
            RuleRow { conditions: "{\"client_is\":[]}".to_owned(), ..base.clone() },
        ),
    ] {
        let mut tx = pool.begin(tenant).await.expect("begin");
        let row = RuleRow { id: RuleId::new_v7(), ..row };
        assert!(
            insert_rule(&mut tx, &row, fixtures.alpha.admin).await.is_err(),
            "the database accepted {label}"
        );
        drop(tx);
    }

    // The control: the same statement with every vocabulary right must succeed, so the four
    // refusals above are about the values rather than about the statement.
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_rule(&mut tx, &base, fixtures.alpha.admin).await.expect("a well-formed rule is stored");
    tx.commit().await.expect("commit");
}

/// The application role cannot delete a rule, and can do everything else.
///
/// `migrations/0019` withholds `DELETE` because one such statement lifts every network restriction
/// a tenant has and leaves nothing behind to say it existed. Asserted both as the grant and as the
/// statement, because a grant nobody exercises is a claim: the `DELETE` is actually attempted, over
/// the application role, and must fail.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn the_application_role_may_withdraw_a_rule_but_never_delete_one() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let id = store_human(&pool, tenant, fixtures.alpha.admin, &block_downloads()).await;

    let mut tx = pool.begin(tenant).await.expect("begin");
    let privileges = sqlx::query(
        "SELECT has_table_privilege('enclave_app', 'conditional_access_rules', 'SELECT') AS s,
                has_table_privilege('enclave_app', 'conditional_access_rules', 'INSERT') AS i,
                has_table_privilege('enclave_app', 'conditional_access_rules', 'UPDATE') AS u,
                has_table_privilege('enclave_app', 'conditional_access_rules', 'DELETE') AS d",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read the grants");
    // The controls come first: a role with no privileges at all would satisfy the `DELETE`
    // assertion on its own.
    assert!(privileges.get::<bool, _>("s"), "the application role must be able to read rules");
    assert!(privileges.get::<bool, _>("i"), "the application role must be able to write rules");
    assert!(privileges.get::<bool, _>("u"), "the application role must be able to withdraw rules");
    assert!(!privileges.get::<bool, _>("d"), "the application role holds DELETE on the rules");

    let attempted = sqlx::query("DELETE FROM conditional_access_rules WHERE id = $1")
        .bind(id.as_uuid())
        .execute(&mut *tx)
        .await;
    assert!(attempted.is_err(), "the application role deleted a conditional-access rule");
    drop(tx);

    // Withdrawal is the supported route, and it leaves the row.
    let mut tx = pool.begin(tenant).await.expect("begin");
    assert!(withdraw_rule(&mut tx, id).await.expect("withdraw"), "the live rule was withdrawn");
    assert!(
        !withdraw_rule(&mut tx, id).await.expect("withdraw again"),
        "withdrawing twice must not move the timestamp a second time"
    );
    let remaining: i64 = sqlx::query(
        "SELECT count(*) FROM conditional_access_rules WHERE id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(id.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("count")
    .get(0);
    tx.commit().await.expect("commit");
    assert_eq!(remaining, 1, "a withdrawn rule must keep its row and its text");
}

/// A withdrawn rule stops deciding.
///
/// Both halves in one fixture: the rule refuses the request, it is withdrawn, and the identical
/// request is then allowed. Without the first half this is a test that a rule which never existed
/// denies nothing.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_withdrawn_rule_stops_deciding() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let stage = stage(&pool);
    let ctx = person(tenant, fixtures.alpha.member);
    let resource = ResourceRef::file(tenant, FileId::new_v7());

    let id = store_human(&pool, tenant, fixtures.alpha.admin, &block_downloads()).await;
    let before = stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation");
    assert_eq!(denied_with(&before), Some(ReasonCode::AccessDenied));

    let mut tx = pool.begin(tenant).await.expect("begin");
    assert!(withdraw_rule(&mut tx, id).await.expect("withdraw"));
    tx.commit().await.expect("commit");

    let after = stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation");
    assert!(after.is_allowed(), "a withdrawn rule still decided the request");
}

// --- Q19, end to end from the table -------------------------------------------------------------

/// The two rule sets stay apart when they come out of a table.
///
/// A human rule and a machine rule are stored for the same tenant, both enforcing, both `Block`.
/// The person is refused by the human one and the service account by the machine one — and neither
/// is refused by the other's, which is the absence, carried by the same evaluation that produced
/// the refusals. A decoder that put every row into one set would deny both requests twice and this
/// test would not notice; so each denial is checked against a request the *other* rule's condition
/// does not match.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_stored_human_rule_and_a_stored_machine_rule_decide_different_principals() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let stage = stage(&pool);
    let resource = ResourceRef::file(tenant, FileId::new_v7());

    // Conditions chosen so that neither rule's condition can match the other's principal: the human
    // rule is about the web client, the machine rule about the API client.
    store_human(&pool, tenant, fixtures.alpha.admin, &block_downloads()).await;
    store_machine(
        &pool,
        tenant,
        fixtures.alpha.admin,
        &MachineRule::new(
            "api callers may not download",
            vec![MachineCondition::ClientIs(vec![ClientType::Api])],
            Effect::Block,
        ),
    )
    .await;

    let person = person(tenant, fixtures.alpha.member);
    let machine = service_account(tenant);

    assert_eq!(
        denied_with(&stage.evaluate(&person, DOWNLOAD, &resource).await.expect("evaluation")),
        Some(ReasonCode::AccessDenied),
        "the human rule must refuse the person"
    );
    assert_eq!(
        denied_with(&stage.evaluate(&machine, DOWNLOAD, &resource).await.expect("evaluation")),
        Some(ReasonCode::AccessDenied),
        "the machine rule must refuse the service account"
    );

    // The absence, and it is carried by the same evaluation that produced the two refusals above:
    // each principal is put behind the *other* rule's client type. A decoder that pooled both rows
    // into one set would refuse these too.
    let mut api_person = person.clone();
    api_person.client = ClientType::Api;
    assert!(
        stage.evaluate(&api_person, DOWNLOAD, &resource).await.expect("evaluation").is_allowed(),
        "a person was refused by the machine rule (which names the API client)"
    );

    let mut web_machine = machine.clone();
    web_machine.client = ClientType::Web;
    assert!(
        stage.evaluate(&web_machine, DOWNLOAD, &resource).await.expect("evaluation").is_allowed(),
        "a service account was refused by the human rule (which names the web client)"
    );
}

/// A stored rule that cannot be decoded refuses the request rather than disappearing from the set.
///
/// This is the row Q19 forbids, written by hand through the repository — a `MACHINE` rule whose
/// conditions are a person's. PostgreSQL cannot type-check a JSONB document, so it accepts the row;
/// the decoder must not. And it must not *skip* it either: a stage that dropped the rule would
/// carry on with one refusal fewer than the administrator wrote, silently.
///
/// The control is in the same fixture — the tenant's other, valid rule is one this stage does
/// evaluate, proved by the refusal asserted before the bad row is written.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_rule_that_cannot_be_decoded_fails_the_request_rather_than_vanishing() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let stage = stage(&pool);
    let ctx = person(tenant, fixtures.alpha.member);
    let resource = ResourceRef::file(tenant, FileId::new_v7());

    store_human(&pool, tenant, fixtures.alpha.admin, &block_downloads()).await;
    assert_eq!(
        denied_with(&stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation")),
        Some(ReasonCode::AccessDenied),
        "the valid rule must engage first, or the failure below could be any failure"
    );
    assert!(
        stage.evaluate(&ctx, PREVIEW, &resource).await.expect("evaluation").is_allowed(),
        "and an action the rule does not name must be allowed, or nothing below is distinguishable"
    );

    // The row PostgreSQL cannot refuse: a machine rule carrying a person's condition.
    let hostile = RuleRow {
        id: RuleId::new_v7(),
        audience: "MACHINE".to_owned(),
        name: "posture, against a service account".to_owned(),
        conditions: r#"[{"posture_below":"MANAGED"}]"#.to_owned(),
        effect: "BLOCK".to_owned(),
        mode: "ENFORCE".to_owned(),
    };
    let mut tx = pool.begin(tenant).await.expect("begin");
    insert_rule(&mut tx, &hostile, fixtures.alpha.admin)
        .await
        .expect("the database cannot type-check a JSONB document, and does not pretend to");
    tx.commit().await.expect("commit");

    let outcome = stage.evaluate(&ctx, PREVIEW, &resource).await;
    assert!(
        outcome.is_err(),
        "a rule set containing an undecodable rule was evaluated anyway: {:?}",
        outcome.map(|decision| denied_with(&decision))
    );
}

// --- The cache, and the staleness it is allowed to have ------------------------------------------

/// A tightened rule applies within the cache TTL, and the cache is genuinely there.
///
/// Both halves are required and each is the other's control. If the "immediately after tightening"
/// assertion is dropped, the test passes against a stage with no cache at all — which is not what
/// this deployment runs. If the "after the TTL" assertion is dropped, it passes against a cache that
/// never expires, which is the security defect: a stale rule set is **permissive**, because there is
/// no `ALLOW` effect and every rule this stage holds denies.
///
/// The rule is tightened from `SIMULATION` to `ENFORCE`, which is the rollout step
/// `plans/M4-GOVERNANCE.md §2` is about, and the one an administrator takes at the end of an
/// incident.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_tightened_rule_applies_within_the_cache_ttl_and_not_before_it() {
    const TTL: Duration = Duration::from_millis(400);

    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let stage = TenantConditionalAccess::new(pool.clone(), zones()).with_cache_ttl(TTL);
    let ctx = person(tenant, fixtures.alpha.member);
    let resource = ResourceRef::file(tenant, FileId::new_v7());

    let rehearsing = HumanRule { mode: RuleMode::Simulation, ..block_downloads() };
    let id = store_human(&pool, tenant, fixtures.alpha.admin, &rehearsing).await;

    assert!(
        stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation").is_allowed(),
        "a rehearsing rule must not refuse anything (D28: simulation records, it does not act)"
    );

    let mut tx = pool.begin(tenant).await.expect("begin");
    assert!(set_rule_mode(&mut tx, id, RuleMode::Enforce.as_sql()).await.expect("tighten"));
    tx.commit().await.expect("commit");

    // Immediately: the cached rule set is still the rehearsing one. This is the half that proves a
    // cache exists, and therefore that the half below is measuring something.
    assert!(
        stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation").is_allowed(),
        "the rules were re-read within the TTL; there is no cache to bound"
    );

    tokio::time::sleep(TTL + Duration::from_millis(200)).await;

    assert_eq!(
        denied_with(&stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation")),
        Some(ReasonCode::AccessDenied),
        "the tightened rule was still not applied after the TTL elapsed — a stale rule set is \
         permissive, because every rule this stage holds denies"
    );
}

/// Invalidation is the immediate route on the process that made the change.
///
/// The TTL is the bound that holds everywhere; this is the shortcut for the replica that already
/// knows. Asserted against its own control — before invalidating, the stale answer is still being
/// given — so it cannot pass against a stage that never cached.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn invalidating_a_tenant_applies_a_tightened_rule_at_once() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let stage = TenantConditionalAccess::new(pool.clone(), zones())
        .with_cache_ttl(Duration::from_secs(3600));
    let ctx = person(tenant, fixtures.alpha.member);
    let resource = ResourceRef::file(tenant, FileId::new_v7());

    let id = store_human(
        &pool,
        tenant,
        fixtures.alpha.admin,
        &HumanRule { mode: RuleMode::Simulation, ..block_downloads() },
    )
    .await;
    assert!(stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation").is_allowed());

    let mut tx = pool.begin(tenant).await.expect("begin");
    assert!(set_rule_mode(&mut tx, id, RuleMode::Enforce.as_sql()).await.expect("tighten"));
    tx.commit().await.expect("commit");

    assert!(
        stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation").is_allowed(),
        "with an hour-long TTL the change must not be visible until the cache is told"
    );

    stage.invalidate(tenant);
    assert_eq!(
        denied_with(&stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation")),
        Some(ReasonCode::AccessDenied),
        "invalidation did not make the tightened rule apply"
    );
}

/// A tenant with no rules is allowed, and reaches that answer through the same code.
///
/// The empty case is what every deployment starts in, and it is the case a wiring mistake looks
/// exactly like. So the control is the same stage, the same tenant, one rule later.
#[tokio::test]
#[ignore = "requires a live PostgreSQL; CI runs it with --include-ignored"]
async fn a_tenant_with_no_rules_is_allowed_and_a_tenant_with_one_is_not() {
    let (_db, fixtures, pool) = harness().await;
    let tenant = fixtures.alpha.id;
    let stage = stage(&pool);
    let ctx = person(tenant, fixtures.alpha.member);
    let resource = ResourceRef::file(tenant, FileId::new_v7());

    assert!(stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation").is_allowed());

    store_human(&pool, tenant, fixtures.alpha.admin, &block_downloads()).await;
    assert_eq!(
        denied_with(&stage.evaluate(&ctx, DOWNLOAD, &resource).await.expect("evaluation")),
        Some(ReasonCode::AccessDenied),
        "the stage allowed everything, which is what UnconfiguredConditionalAccess did"
    );
}
