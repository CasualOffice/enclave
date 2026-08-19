//! ENC-145 — what `authorize_many` costs at the batch size the search post-filter runs at.
//!
//! # Why the number is needed now and not in M3
//!
//! `docs/07-SEARCH-INDEXING.md §6.2` makes the post-filter mandatory and unconditional: every
//! candidate the vector index proposes is confirmed against PostgreSQL before it reaches the
//! caller. The same section asserts a cost — "typically under 10 ms for 200 candidates" — which
//! nothing has ever checked. If that estimate is wrong by an order of magnitude the correction is a
//! change to how search pages and over-fetches, not a tuning pass, so
//! `plans/M2-ACCESS-DELIVERY.md §3.2` schedules the measurement here, before the design that
//! depends on it is written.
//!
//! # The number
//!
//! **7–8 ms** at the median for 200 candidates, in a debug build, against a corpus built to make
//! all three round trips do real work — see [`MEDIAN_BUDGET_MS`] for the machine and the spread,
//! and the `println!` output of any run for that run's own figures. One candidate costs 1.4 ms
//! through the same corpus, so nearly all of it is fixed cost and an extra candidate is worth about
//! 0.03 ms. The estimate the search document already carries is therefore correct rather than
//! optimistic, and M3 can spend its latency budget elsewhere.
//!
//! # Why an ignored integration test and not a criterion bench
//!
//! Because this one runs. CI's test job is `cargo test --workspace --locked -- --include-ignored`
//! (`.github/workflows/ci.yml`), so an `#[ignore]`d test in this directory is exercised on every
//! pull request against the same PostgreSQL the rest of the suite uses. A `benches/` target would
//! need a `[[bench]]` section, a criterion dependency and a CI step that nobody has written, and an
//! unrun benchmark is a number that was true once.
//!
//! The trade is real and worth naming: criterion would give confidence intervals, outlier
//! classification and a stored baseline to regress against, and this gives a sorted vector of
//! thirty samples. For the question actually being asked — is the post-filter's budget tens of
//! milliseconds or hundreds — thirty samples in the harness that already exists answer it, and
//! answer it again on every pull request rather than on the day someone remembers to run `cargo
//! bench`.
//!
//! It also measures the build CI runs. `cargo test` is a debug build — the workspace sets no
//! `opt-level` for `dev` — so the samples include unoptimised chain merging and index building on
//! the client side. That is the pessimistic end of the range and the right end to put a bound on.
//!
//! # Why the fixture is this elaborate
//!
//! Two hundred rows in one flat folder with one ACL entry would measure an empty recursive CTE and
//! a single index probe, and would report a number the post-filter can never reproduce. The corpus
//! below is built so that each of the three round trips (`crates/authorization/src/repo.rs`) does
//! the work it does in production: the inheritance walk climbs up to five folders per candidate,
//! the group closure is only satisfied by following six levels of nesting, and the entry fetch
//! covers a union of three hundred chain nodes carrying `ALLOW`s, `DENY`s, expired rows and rows
//! belonging to other principals and other actions.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use enclave_authorization::PgAclAuthorization;
use enclave_core::{
    Action, Actor, AuthorizationService as _, FileAction, FileId, GroupId, RequestContext,
    ResourceRef, StageDecision, TenantId, UserId,
};
use enclave_testing::content::{grant, AclEffect, AclPrincipal, AclScope, Spine};
use enclave_testing::{Fixtures, TestDb};
use sqlx::PgConnection;
use uuid::Uuid;

/// The action the post-filter actually asks about: seeing that a hit exists at all
/// (`docs/07-SEARCH-INDEXING.md §6.2`).
const ACTION: Action = Action::File(FileAction::MetadataRead);

/// Independent folder chains hanging off the library root.
const CHAINS: usize = 20;
/// Folders in each chain, so the deepest candidate is five folders below its library.
const DEPTH: usize = 5;
/// Files in every folder, at every level — candidates are not all leaves.
const FILES_PER_FOLDER: usize = 2;
/// The batch size the whole exercise is about: `CHAINS * DEPTH * FILES_PER_FOLDER`.
const CANDIDATES: usize = CHAINS * DEPTH * FILES_PER_FOLDER;

/// Chains whose root folder carries a group `DENY`, so the walk has to reach the top to find it.
const DENIED_CHAINS: usize = 4;
/// Levels of group nesting between the caller and the group the library `ALLOW` names.
const GROUP_NESTING: usize = 6;

/// Files denied outright by an entry naming the caller.
const EXPLICIT_DENIES: usize = 10;
/// Files carrying a `DENY` that has already lapsed, which must not deny.
const EXPIRED_DENIES: usize = 10;
/// Files granted directly as well as by inheritance, so the index has duplicates to fold.
const DIRECT_ALLOWS: usize = 6;

/// Verdicts the corpus is built to produce: everything except the denied chains and the live
/// explicit denials.
const EXPECTED_ALLOWED: usize =
    CANDIDATES - DENIED_CHAINS * DEPTH * FILES_PER_FOLDER - EXPLICIT_DENIES;

/// Iterations thrown away before sampling, so the pool's connections, PostgreSQL's plan cache and
/// the shared buffers are all warm — the post-filter runs on a server that has been up for days,
/// not on a cold one.
const WARMUP: usize = 5;
/// Iterations kept. Thirty is enough for a median that does not move between runs and few enough
/// that the whole test stays inside a few seconds of the suite's budget.
const SAMPLES: usize = 30;

/// The bound the median must stay under, in milliseconds.
///
/// **What was measured.** 6.9–8.1 ms median and 7.4–10.1 ms p95 across five runs of this test on an
/// Apple M-series laptop (macOS 15, debug build) against PostgreSQL 16 in Docker over the loopback;
/// the worst single sample of any run was 16.9 ms, on a run where the laptop was doing other work.
/// One candidate through the same corpus costs 1.4–1.5 ms, which puts the marginal cost of a
/// candidate at 0.028–0.033 ms. The estimate in `docs/07-SEARCH-INDEXING.md §6.2` — "typically
/// under 10 ms for 200 candidates" — holds, with the caveat that this is a loopback and a
/// production deployment pays real network latency three times.
///
/// **Why the bound is ten times that.** CI runs the entire workspace's tests concurrently against a
/// single PostgreSQL service container on a shared two-core runner, so the same call there competes
/// with every other suite's fixtures for the same server. A bound that assumed an idle database
/// would fail for reasons that have nothing to do with this code, and a benchmark that cries wolf
/// is one people disable rather than investigate.
///
/// So this bound catches only the order-of-magnitude class: three round trips becoming two hundred,
/// a chain walk that stopped using `files_pkey`, an entry fetch that lost `idx_acl_resource`. The
/// assertion that catches an N+1 *regardless* of how fast the machine is, is
/// [`BATCH_RATIO_CEILING`] — that one is the real regression test, and this is the sanity check.
const MEDIAN_BUDGET_MS: f64 = 70.0;

/// The bound the 95th percentile must stay under, in milliseconds.
///
/// Wider than a simple multiple of the median on purpose: with thirty samples the 95th percentile
/// is the second-worst one, and on a shared runner the second-worst sample is largely a measure of
/// what else that runner was doing. It is asserted at all so that a regression which is bimodal —
/// fast when a plan is cached, catastrophic when it is not — cannot hide behind a healthy median.
const P95_BUDGET_MS: f64 = 200.0;

/// How many times the cost of one candidate two hundred candidates may reach.
///
/// Measured at 4.7–4.9×, which is what "three round trips whatever the batch size" looks like from
/// the outside: the fixed cost of a transaction and three statements, plus about 0.028 ms of rows
/// per extra candidate. A per-resource loop would put this near 200 on any hardware, and 25× leaves
/// five times the measured headroom while still catching that by a factor of eight.
///
/// Unlike the millisecond bounds, this one does not care how fast the machine is: contention
/// inflates the numerator and the denominator together.
const BATCH_RATIO_CEILING: f64 = 25.0;

/// The corpus: one spine, a forest of folder chains under it, and the candidate list.
#[derive(Debug)]
struct Corpus {
    spine: Spine,
    /// Every candidate, in the order the post-filter would present them.
    files: Vec<FileId>,
    /// Index-aligned with [`Corpus::files`]: whether a `DENY` sits above this file.
    denied_by_chain: Vec<bool>,
}

impl Corpus {
    /// Candidate references, which is what `authorize_many` actually takes.
    fn candidates(&self) -> Vec<ResourceRef> {
        self.files.iter().map(|file| ResourceRef::file(self.spine.tenant, *file)).collect()
    }
}

/// Writes every row the measurement needs over an administrative connection.
///
/// Setup goes through the harness's superuser connection, as everywhere else in this crate's tests;
/// only the measured calls go through the `enclave_app` pool, because it is under forced row-level
/// security that the cost is worth knowing (`crates/authorization/src/repo.rs`).
async fn build(conn: &mut PgConnection, tenant: TenantId, fixtures: &Fixtures) -> Corpus {
    let spine = Spine::new(tenant);
    spine.insert(conn, fixtures.alpha.owner, Utc::now()).await.expect("insert the spine");

    // Folders, one level at a time. A single statement per level rather than per folder because the
    // self-referencing foreign key needs the parent row to exist, and because a hundred round trips
    // of setup is a hundred round trips someone eventually decides to shrink by making the tree
    // shallower — which would quietly delete the thing being measured.
    let mut levels: Vec<Vec<FileId>> = Vec::with_capacity(DEPTH);
    for _ in 0..DEPTH {
        let ids: Vec<FileId> = (0..CHAINS).map(|_| FileId::new_v7()).collect();
        let parents: Vec<Option<Uuid>> = match levels.last() {
            None => vec![None; CHAINS],
            Some(above) => above.iter().map(|parent| Some(parent.as_uuid())).collect(),
        };
        insert_nodes(conn, &spine, fixtures.alpha.owner, "FOLDER", &ids, &parents).await;
        levels.push(ids);
    }

    // Files, level-major so that consecutive candidates sit in different chains. A batch ordered by
    // insertion would arrive grouped by subtree; a relevance-ranked one never does.
    let mut files = Vec::with_capacity(CANDIDATES);
    let mut denied_by_chain = Vec::with_capacity(CANDIDATES);
    let mut parents = Vec::with_capacity(CANDIDATES);
    for level in &levels {
        for (chain, folder) in level.iter().enumerate() {
            for _ in 0..FILES_PER_FOLDER {
                files.push(FileId::new_v7());
                parents.push(Some(folder.as_uuid()));
                denied_by_chain.push(chain < DENIED_CHAINS);
            }
        }
    }
    insert_nodes(conn, &spine, fixtures.alpha.owner, "FILE", &files, &parents).await;

    let caller = fixtures.alpha.member;
    let outermost = nest_groups(conn, tenant, caller).await;

    // The grant everything hangs off, on the library and naming the group furthest from the caller.
    // Six levels of closure have to resolve before this entry matches anyone at all, so a closure
    // that silently stopped at one level would turn every verdict into a refusal — and be visible
    // as a failed assertion below rather than as a suspiciously fast benchmark.
    grant(
        conn,
        tenant,
        AclScope::Library(spine.library),
        AclPrincipal::Group(outermost),
        ACTION,
        AclEffect::Allow,
        None,
    )
    .await
    .expect("grant on the library");

    // Denials on four chain roots, naming the group the seeded fixtures already put the caller in
    // directly. The files underneath sit up to five folders below the entry, so each one resolves
    // correctly only if the walk climbs — and the deny arrives through a different group from the
    // allow, which is the arrangement real tenants produce and the one deny-wins exists for.
    for root in levels[0].iter().take(DENIED_CHAINS) {
        grant(
            conn,
            tenant,
            AclScope::Folder(*root),
            AclPrincipal::Group(fixtures.alpha.engineering),
            ACTION,
            AclEffect::Deny,
            None,
        )
        .await
        .expect("deny on a chain root");
    }

    // Entries on individual files, spread across the chains. The strides are disjoint by
    // construction — `16k`, `16k + 1`, `16k + 2` — because two entries naming the same principal
    // and action on one resource violate `uq_acl_entry`, and a setup failure there would read as a
    // fixture that could not be built rather than as the arithmetic mistake it is.
    let allowed: Vec<FileId> = files
        .iter()
        .zip(&denied_by_chain)
        .filter_map(|(file, denied)| (!denied).then_some(*file))
        .collect();
    for (offset, effect, expires, count) in [
        (0, AclEffect::Deny, None, EXPLICIT_DENIES),
        (1, AclEffect::Deny, Some(Utc::now() - ChronoDuration::hours(1)), EXPIRED_DENIES),
        (2, AclEffect::Allow, None, DIRECT_ALLOWS),
    ] {
        for step in 0..count {
            let file = allowed[step * 16 + offset];
            grant(
                conn,
                tenant,
                AclScope::File(file),
                AclPrincipal::User(caller),
                ACTION,
                effect,
                expires,
            )
            .await
            .expect("grant on a file");
        }
    }

    // Noise on the same resources: entries for another principal, and entries for another action.
    //
    // These are the rows the prefilter in `ACL_ENTRIES_SQL` has to reject, and they sit on exactly
    // the `idx_acl_resource` pages the fetch reads, so they cost something to skip. Note what is
    // *not* padded: `group_members`. The closure enters from `idx_group_members_member`, so rows
    // for other members are pages it never touches, and adding them would be decoration rather
    // than load.
    let ids: Vec<Uuid> = files.iter().map(|file| file.as_uuid()).collect();
    noise(conn, tenant, &ids, fixtures.alpha.viewer, ACTION).await;
    noise(conn, tenant, &ids, caller, Action::File(FileAction::Download)).await;

    // Without statistics the planner picks its plan from an empty table's defaults, and the first
    // measured call would be timing a plan no production database would ever choose.
    sqlx::raw_sql("ANALYZE files, acl_entries, group_members, libraries, workspaces")
        .execute(&mut *conn)
        .await
        .expect("analyze");

    // Inheritance is left intact everywhere. Breaking it at a folder shortens the walk
    // (`crates/authorization/src/materialise.rs`), so a corpus that used it would measure a cheaper
    // question than the one the post-filter asks.
    Corpus { spine, files, denied_by_chain }
}

/// Inserts one level of the tree in a single statement, returning nothing because the caller
/// already holds the identifiers it generated.
async fn insert_nodes(
    conn: &mut PgConnection,
    spine: &Spine,
    owner: UserId,
    node_type: &str,
    ids: &[FileId],
    parents: &[Option<Uuid>],
) {
    let ids: Vec<Uuid> = ids.iter().map(|id| id.as_uuid()).collect();
    sqlx::query(
        "INSERT INTO files
           (id, tenant_id, workspace_id, library_id, parent_id, node_type, name, normalized_name,
            mime_type, inherit_permissions, created_by, modified_by, created_at, modified_at)
         SELECT n.id, $1, $2, $3, n.parent, $4, n.id::text, n.id::text,
                'application/octet-stream', TRUE, $5, $5, $6, $6
           FROM unnest($7::uuid[], $8::uuid[]) AS n(id, parent)",
    )
    .bind(spine.tenant.as_uuid())
    .bind(spine.workspace.as_uuid())
    .bind(spine.library.as_uuid())
    .bind(node_type)
    .bind(owner.as_uuid())
    .bind(Utc::now())
    .bind(&ids)
    .bind(parents)
    .execute(&mut *conn)
    .await
    .expect("insert a level of the tree");
}

/// Nests `caller` inside a chain of [`GROUP_NESTING`] groups and returns the outermost one.
///
/// The seeded fixtures give `member` one direct group and `owner` two levels; neither is enough to
/// make the closure's depth visible in a timing. Six is under the resolver's cap of eight
/// (`docs/04-DATA-MODEL.md §5`), so the whole chain resolves rather than being truncated — a
/// truncated chain would refuse everything and be caught by the verdict assertion, but slowly and
/// confusingly.
async fn nest_groups(conn: &mut PgConnection, tenant: TenantId, caller: UserId) -> GroupId {
    let groups: Vec<GroupId> = (0..GROUP_NESTING).map(|_| GroupId::new_v7()).collect();
    let now = Utc::now();

    for group in &groups {
        sqlx::query(
            "INSERT INTO groups (id, tenant_id, name, normalized_name, source, created_at, updated_at)
             VALUES ($1, $2, $3, $3, 'LOCAL', $4, $4)",
        )
        .bind(group.as_uuid())
        .bind(tenant.as_uuid())
        .bind(format!("nested-{}", group.as_uuid()))
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert a nested group");
    }

    // The caller joins the innermost group; every group after it contains the one before.
    for (index, group) in groups.iter().enumerate() {
        let (member, kind) = match index.checked_sub(1).and_then(|below| groups.get(below)) {
            None => (caller.as_uuid(), "USER"),
            Some(below) => (below.as_uuid(), "GROUP"),
        };
        sqlx::query(
            "INSERT INTO group_members (tenant_id, group_id, member_id, member_type, added_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant.as_uuid())
        .bind(group.as_uuid())
        .bind(member)
        .bind(kind)
        .bind(now)
        .execute(&mut *conn)
        .await
        .expect("insert a nested membership");
    }

    *groups.last().expect("GROUP_NESTING is not zero")
}

/// Writes one `ALLOW` per file for a principal and action the caller's query must reject.
async fn noise(
    conn: &mut PgConnection,
    tenant: TenantId,
    files: &[Uuid],
    principal: UserId,
    action: Action,
) {
    sqlx::query(
        "INSERT INTO acl_entries
           (id, tenant_id, resource_type, resource_id, principal_type, principal_id, action,
            effect, granted_by, granted_at, expires_at)
         SELECT gen_random_uuid(), $1, 'FILE', n.id, 'USER', $2, $3, 'ALLOW', $4, $5, NULL
           FROM unnest($6::uuid[]) AS n(id)",
    )
    .bind(tenant.as_uuid())
    .bind(principal.as_uuid())
    .bind(action.to_string())
    .bind(Uuid::nil())
    .bind(Utc::now())
    .bind(files)
    .execute(&mut *conn)
    .await
    .expect("insert acl noise");
}

/// The sample at a percentile by nearest rank, over an already-sorted slice.
fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    let rank = (sorted.len() * percent).div_ceil(100).max(1);
    sorted[rank - 1]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

/// One batch size's timings, in milliseconds.
#[derive(Debug, Clone, Copy)]
struct Timings {
    min: f64,
    p50: f64,
    mean: f64,
    p95: f64,
    max: f64,
}

impl Timings {
    /// Times [`SAMPLES`] calls after [`WARMUP`] discarded ones, checking every result.
    ///
    /// `verify` runs on every iteration, warm-up included, and is not optional. A resolver that got
    /// fast by answering a different question — an empty chain, a closure that matched nobody, a
    /// batch that lost its alignment — would otherwise report an excellent number for work it did
    /// not do, and that is the failure mode a benchmark is least able to notice about itself.
    async fn measure(
        authz: &PgAclAuthorization,
        ctx: &RequestContext,
        resources: &[ResourceRef],
        verify: &dyn Fn(&[StageDecision]),
    ) -> Self {
        let mut samples: Vec<Duration> = Vec::with_capacity(SAMPLES);
        for iteration in 0..WARMUP + SAMPLES {
            let started = Instant::now();
            let decisions =
                authz.authorize_many(ctx, ACTION, resources).await.expect("resolve the batch");
            let elapsed = started.elapsed();

            verify(&decisions);
            if iteration >= WARMUP {
                samples.push(elapsed);
            }
        }

        samples.sort_unstable();
        let total: Duration = samples.iter().sum();
        Self {
            min: millis(samples[0]),
            p50: millis(percentile(&samples, 50)),
            mean: millis(total) / samples.len() as f64,
            p95: millis(percentile(&samples, 95)),
            max: millis(*samples.last().expect("SAMPLES is not zero")),
        }
    }

    fn report(&self, label: &str) -> String {
        let Self { min, p50, mean, p95, max } = *self;
        format!(
            "{label}: min {min:.1} ms · p50 {p50:.1} ms · mean {mean:.1} ms · p95 {p95:.1} ms · \
             max {max:.1} ms over {SAMPLES} samples after {WARMUP} warm-up calls"
        )
    }
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL with migrations 0004 and 0005 applied; CI runs it with --include-ignored"]
async fn the_search_post_filter_resolves_two_hundred_candidates_inside_its_budget() {
    let db = TestDb::start().await.expect("start the test database");
    let fixtures = db.seed().await.expect("seed the tenant fixtures");
    let alpha = fixtures.alpha.id;
    let caller = fixtures.alpha.member;

    let mut admin = db.connect().await.expect("admin connection");
    let corpus = build(&mut admin, alpha, &fixtures).await;
    let candidates = corpus.candidates();
    assert_eq!(candidates.len(), CANDIDATES, "the corpus is not the batch size under test");

    let pool = db.pool().await.expect("application-role pool");
    let authz = PgAclAuthorization::new(pool);
    let mut ctx = RequestContext::system(alpha);
    ctx.actor = Actor::User(caller);

    let batch = Timings::measure(&authz, &ctx, &candidates, &|decisions| {
        assert_eq!(decisions.len(), CANDIDATES, "the batch lost or invented a verdict");
        let allowed = decisions.iter().filter(|decision| decision.is_allowed()).count();
        assert_eq!(
            allowed, EXPECTED_ALLOWED,
            "the corpus resolved to an unexpected mix, so the timing is of the wrong question: \
             expected {EXPECTED_ALLOWED} of {CANDIDATES} allowed"
        );
        for (index, decision) in decisions.iter().enumerate() {
            assert!(
                !(corpus.denied_by_chain[index] && decision.is_allowed()),
                "a file below a denied chain root was allowed, so the walk did not climb"
            );
        }
    })
    .await;

    // The same call for one candidate — the deepest, so it climbs the full chain and resolves
    // through the whole group closure. It is the denominator of the ratio below, and it is also the
    // per-request floor: whatever the post-filter costs, it costs at least this.
    let deepest = [*candidates.last().expect("CANDIDATES is not zero")];
    let single = Timings::measure(&authz, &ctx, &deepest, &|decisions| {
        assert_eq!(decisions.len(), 1);
        assert!(
            decisions[0].is_allowed(),
            "the single-candidate baseline resolves to a refusal, so it is timing a short path \
             the batch does not take"
        );
    })
    .await;

    // In the CI log rather than only in an assertion, because the point of ENC-145 is the number
    // itself: M3's post-filter is designed against it, and a bound that merely passes tells nobody
    // whether the cost is 3 ms or 60.
    println!(
        "{}",
        batch.report(&format!(
            "ENC-145 authorize_many({CANDIDATES} candidates, {DEPTH}-deep chains, \
         {GROUP_NESTING}-level group nesting, debug build)"
        ))
    );
    println!("{}", single.report("ENC-145 authorize_many(1 candidate, same corpus, debug build)"));

    let ratio = batch.p50 / single.p50;
    println!(
        "ENC-145 {CANDIDATES}× the candidates cost {ratio:.2}× the time \
         ({:.1} ms → {:.1} ms), i.e. {:.3} ms per additional candidate",
        single.p50,
        batch.p50,
        (batch.p50 - single.p50) / (CANDIDATES - 1) as f64
    );

    // The bound that does not depend on how fast the machine is.
    //
    // `crates/authorization/src/repo.rs` claims three round trips for a batch of any size. If that
    // ever became one round trip per resource, this ratio would go to roughly 200 on any hardware,
    // while the absolute bounds below could still pass on a machine fast enough. A ratio is the
    // only form of this assertion that a faster CI runner cannot silently satisfy.
    assert!(
        ratio < BATCH_RATIO_CEILING,
        "resolving {CANDIDATES} candidates costs {ratio:.1}× resolving one, over the \
         {BATCH_RATIO_CEILING:.0}× ceiling. The batch path has stopped being a batch: check that \
         `AclResolver::effective_in_tx` still issues one inheritance walk, one group closure and \
         one entry fetch for the whole slice rather than looping over it."
    );
    assert!(
        batch.p50 < MEDIAN_BUDGET_MS,
        "authorize_many's median for {CANDIDATES} candidates is {:.1} ms, over the \
         {MEDIAN_BUDGET_MS:.0} ms bound. This bound catches order-of-magnitude regressions, not \
         noise, so treat it as real: run `EXPLAIN (ANALYZE, BUFFERS)` on the three statements in \
         crates/authorization/src/repo.rs and check that `idx_acl_resource` and `idx_files_parent` \
         are still there and still chosen. If the plans are unchanged and the machine is simply \
         slower, raise the bound here, say what it was measured on, and correct the estimate in \
         docs/07-SEARCH-INDEXING.md §6.2, which is the document that quotes it.",
        batch.p50
    );
    assert!(
        batch.p95 < P95_BUDGET_MS,
        "authorize_many's p95 for {CANDIDATES} candidates is {:.1} ms against a median of \
         {:.1} ms, over the {P95_BUDGET_MS:.0} ms bound. A healthy median with an unhealthy tail is \
         usually a plan that is only sometimes cached, or connection acquisition waiting on the \
         pool — rule both out before widening this.",
        batch.p95,
        batch.p50
    );
}
