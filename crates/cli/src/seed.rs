//! `enclave-cli seed` — write the development fixture tenants.
//!
//! # Where the fixtures come from
//!
//! From [`enclave_testing::Fixtures`], and from nowhere else. `docs/12-TESTING.md §3` defines one
//! seeded tenant set, `tenant-alpha` and `tenant-beta`, and every integration and security test
//! asserts against it. A second definition living in this command would drift — slowly, and in the
//! worst direction: a contributor looking at the stack would be looking at something subtly unlike
//! what the suite proves things about, and the divergence would show up as a test that passes for a
//! reason nobody can reproduce locally.
//!
//! # Why it can refuse
//!
//! Seeding writes to whatever `DATABASE_URL` points at, and that is one exported variable away from
//! being a database that matters. So the command reads the tenant list first, and refuses when it
//! finds tenants it did not put there — unless `--force` says the operator meant it. Everything it
//! is about to do is printed before any of it happens, so that the refusal is not the only defence.
//!
//! Nothing here deletes or overwrites. Every statement is `ON CONFLICT DO NOTHING`, so a second run
//! is a no-op and a run against a database with real data adds fixture rows rather than replacing
//! anything. `--force` widens what it will write to, never what it will destroy.
//!
//! # Why writes go through `TenantScoped`
//!
//! `users`, `groups` and `group_members` have RLS enabled **and forced**, so even the schema owner
//! cannot insert into them without `app.tenant_id` set (`migrations/0002_rls_policies.sql`). Going
//! through [`enclave_db::DbPool::begin`] is therefore both the rule (`CLAUDE.md`) and the only way
//! this works as any role other than a superuser — which is exactly the property worth having, since
//! a seeder that only works as a superuser is a seeder that proves nothing about the schema.

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use enclave_core::{GroupId, TenantId, UserId};
use enclave_testing::{Fixtures, TenantFixture};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::cli::SeedArgs;
use crate::connect::Target;
use crate::schema::{applied_migrations, pending, table_exists};

/// 2026-01-01T00:00:00Z, the instant `enclave-testing` stamps its fixtures with.
///
/// Fixed rather than `now()` for the reason the harness gives: a deterministic fixture is one whose
/// failures are reproducible from a log alone. Held as an epoch second so the constant is a value
/// rather than a fallible parse; the unit test below pins it to the date it claims to be.
const FIXTURE_EPOCH_SECOND: i64 = 1_767_225_600;

/// One tenant's worth of rows.
#[derive(Debug, Clone)]
struct TenantPlan {
    slug: String,
    id: TenantId,
    users: Vec<UserRow>,
    groups: Vec<GroupRow>,
    memberships: Vec<MembershipRow>,
}

/// A user, with the local part of its email — the harness derives the address from the slug.
#[derive(Debug, Clone, Copy)]
struct UserRow {
    id: UserId,
    local: &'static str,
    is_admin: bool,
}

/// A group and its name.
#[derive(Debug, Clone, Copy)]
struct GroupRow {
    id: GroupId,
    name: &'static str,
}

/// A membership edge. `member` is a bare `Uuid` because it is either a user or a group.
#[derive(Debug, Clone, Copy)]
struct MembershipRow {
    group: GroupId,
    member: Uuid,
    kind: &'static str,
}

/// How many rows a tenant actually wrote, as opposed to found already there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Written {
    tenants: u64,
    users: u64,
    groups: u64,
    memberships: u64,
}

/// What the pre-flight found in the database.
#[derive(Debug, Clone)]
struct PreFlight {
    /// Tenant slugs already present, or an empty list on an unmigrated database.
    existing: Vec<String>,
    /// Migration versions this binary would have to apply first.
    pending: Vec<i64>,
}

/// Whether seeding may proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Nothing unexpected is present.
    Proceed,
    /// Non-fixture tenants are present and `--force` was passed.
    Overridden,
    /// Non-fixture tenants are present and `--force` was not passed.
    Refuse,
}

/// Runs the seed.
///
/// # Errors
///
/// Connection, migration or statement failures, and the deliberate refusal when the database holds
/// tenants this command did not create.
pub(crate) async fn run(target: &Target, args: &SeedArgs) -> anyhow::Result<()> {
    let fixtures = Fixtures::default();
    let plans = [plan_for(&fixtures.alpha), plan_for(&fixtures.beta)];

    println!("enclave-cli seed --profile {}", args.profile.as_str());
    println!("  target: {}", target.summary());
    println!("  from:   {}", target.origin());
    println!();

    let mut conn = target.connect().await?;
    let state = pre_flight(&mut conn).await?;

    let slugs: Vec<&str> = plans.iter().map(|plan| plan.slug.as_str()).collect();
    let foreign = foreign_tenants(&state.existing, &slugs);
    let verdict = verdict(&foreign, args.force);

    print_plan(&plans, &state, &foreign, verdict);

    if verdict == Verdict::Refuse {
        anyhow::bail!(
            "refusing to seed {}: it holds {} tenant(s) this command did not create ({}).\n  \
             re-run with --force if this really is the database you meant",
            target.summary(),
            foreign.len(),
            foreign.join(", ")
        );
    }

    if !state.pending.is_empty() {
        enclave_db::run_migrations_on(&mut conn).await.with_context(|| {
            format!(
                "could not apply migrations to {}.\n  migrations run as the schema owner; a \
                 permission error here usually means {} holds application credentials",
                target.summary(),
                target.origin()
            )
        })?;
        println!("  applied {} migration(s)", state.pending.len());
    }

    // Closed before the pool opens: the pre-flight connection has done its job, and a development
    // PostgreSQL is often the one with the smallest connection limit anyone will meet.
    drop(conn);

    let pool = target.pool().await?;
    println!("  writing:");
    for plan in &plans {
        let written = insert_tenant(&pool, plan).await?;
        println!(
            "    {:<14} {}/{} tenants, {}/{} users, {}/{} groups, {}/{} memberships",
            plan.slug,
            written.tenants,
            1,
            written.users,
            plan.users.len(),
            written.groups,
            plan.groups.len(),
            written.memberships,
            plan.memberships.len(),
        );
    }
    pool.close().await;

    println!();
    println!("  done. rows already present were left as they were.");
    Ok(())
}

/// Reads everything the decision depends on, without writing anything.
async fn pre_flight(conn: &mut PgConnection) -> anyhow::Result<PreFlight> {
    let applied = applied_migrations(&mut *conn).await?;
    let pending = pending(&applied);

    // An unmigrated database has no `tenants` table, which is "no tenants", not an error: seeding a
    // freshly created database is the common case.
    let existing = if table_exists(&mut *conn, "tenants").await? {
        let rows = sqlx::query("SELECT slug FROM tenants ORDER BY slug")
            .fetch_all(&mut *conn)
            .await
            .context("could not read the existing tenants")?;
        rows.into_iter()
            .map(|row| row.try_get::<String, _>("slug"))
            .collect::<Result<Vec<_>, sqlx::Error>>()
            .context("unexpected shape reading tenant slugs")?
    } else {
        Vec::new()
    };

    Ok(PreFlight { existing, pending })
}

/// Tenants in the database that this command does not own.
///
/// The comparison is by slug rather than by id because the slug is what a human recognises in the
/// refusal message, and because a tenant carrying the fixture slug with a different id is still a
/// database somebody set up deliberately.
fn foreign_tenants(existing: &[String], fixtures: &[&str]) -> Vec<String> {
    existing.iter().filter(|slug| !fixtures.contains(&slug.as_str())).cloned().collect()
}

/// The safety decision, kept separate from the I/O so it can be tested exhaustively.
const fn verdict(foreign: &[String], force: bool) -> Verdict {
    if foreign.is_empty() {
        // `--force` on a clean database is not an override of anything.
        Verdict::Proceed
    } else if force {
        Verdict::Overridden
    } else {
        Verdict::Refuse
    }
}

/// Prints what is about to happen, in full, before any of it happens.
fn print_plan(plans: &[TenantPlan], state: &PreFlight, foreign: &[String], verdict: Verdict) {
    println!("  it will:");
    if state.pending.is_empty() {
        println!("    - apply no migrations (the schema is up to date)");
    } else {
        let versions: Vec<String> =
            state.pending.iter().map(|version| format!("{version:04}")).collect();
        println!("    - apply {} migration(s): {}", state.pending.len(), versions.join(", "));
    }
    for plan in plans {
        println!(
            "    - insert {} ({}) — {} users, {} groups, {} memberships",
            plan.slug,
            plan.id,
            plan.users.len(),
            plan.groups.len(),
            plan.memberships.len(),
        );
    }
    println!(
        "    - delete nothing, and overwrite nothing (every insert is ON CONFLICT DO NOTHING)"
    );
    println!();

    match verdict {
        Verdict::Proceed => {
            println!("  no non-fixture tenants are present.");
        }
        Verdict::Overridden => {
            println!(
                "  --force: proceeding although {} non-fixture tenant(s) are present: {}",
                foreign.len(),
                foreign.join(", ")
            );
        }
        Verdict::Refuse => {
            println!("  this database holds {} tenant(s) that are not fixtures:", foreign.len());
            for slug in foreign {
                println!("      {slug}");
            }
        }
    }
    println!();
}

/// Writes one tenant, in one transaction, with its tenant context established.
///
/// One transaction per tenant rather than one for everything: a failure halfway through leaves the
/// database with either all of a tenant or none of it, and `app.tenant_id` is a per-tenant setting,
/// so the transaction boundary and the isolation boundary are the same boundary.
async fn insert_tenant(pool: &enclave_db::DbPool, plan: &TenantPlan) -> anyhow::Result<Written> {
    let now = fixture_time();
    let mut written = Written::default();

    let mut tx = pool
        .begin(plan.id)
        .await
        .with_context(|| format!("could not open a transaction for {}", plan.slug))?;

    written.tenants = sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at)
         VALUES ($1, $2, $3, 'ACTIVE', $4, $4)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(plan.id.as_uuid())
    .bind(&plan.slug)
    .bind(&plan.slug)
    .bind(now)
    .execute(&mut *tx)
    .await
    .with_context(|| format!("could not insert the {} tenant row", plan.slug))?
    .rows_affected();

    for user in &plan.users {
        let email = format!("{}@{}.example", user.local, plan.slug);
        written.users += sqlx::query(
            "INSERT INTO users
               (id, tenant_id, email, normalized_email, display_name, status, is_admin,
                source, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, 'LOCAL', $7, $7)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(user.id.as_uuid())
        .bind(plan.id.as_uuid())
        .bind(&email)
        .bind(email.to_lowercase())
        .bind(user.local)
        .bind(user.is_admin)
        .bind(now)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("could not insert {email}"))?
        .rows_affected();
    }

    for group in &plan.groups {
        written.groups += sqlx::query(
            "INSERT INTO groups
               (id, tenant_id, name, normalized_name, source, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'LOCAL', $5, $5)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(group.id.as_uuid())
        .bind(plan.id.as_uuid())
        .bind(group.name)
        .bind(group.name.to_lowercase())
        .bind(now)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("could not insert the {} group", group.name))?
        .rows_affected();
    }

    for membership in &plan.memberships {
        written.memberships += sqlx::query(
            "INSERT INTO group_members (tenant_id, group_id, member_id, member_type, added_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING",
        )
        .bind(plan.id.as_uuid())
        .bind(membership.group.as_uuid())
        .bind(membership.member)
        .bind(membership.kind)
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("could not insert a group membership")?
        .rows_affected();
    }

    tx.commit().await.with_context(|| format!("could not commit the {} rows", plan.slug))?;
    Ok(written)
}

/// Derives the rows for one tenant from the harness fixture.
///
/// Every id and every name is read off the [`TenantFixture`]; nothing is invented here. The nested
/// `finance > finance-leads` edge is reproduced deliberately — it is what makes group-closure
/// resolution have anything to resolve, and a dev database without it looks fine right up until
/// someone tests inheritance against it.
fn plan_for(fixture: &TenantFixture) -> TenantPlan {
    TenantPlan {
        slug: fixture.slug.clone(),
        id: fixture.id,
        users: vec![
            UserRow { id: fixture.owner, local: "owner", is_admin: false },
            UserRow { id: fixture.member, local: "member", is_admin: false },
            UserRow { id: fixture.viewer, local: "viewer", is_admin: false },
            UserRow { id: fixture.admin, local: "admin", is_admin: true },
            UserRow { id: fixture.auditor, local: "auditor", is_admin: false },
        ],
        groups: vec![
            GroupRow { id: fixture.engineering, name: "engineering" },
            GroupRow { id: fixture.finance, name: "finance" },
            GroupRow { id: fixture.finance_leads, name: "finance-leads" },
        ],
        memberships: vec![
            MembershipRow {
                group: fixture.finance,
                member: fixture.finance_leads.as_uuid(),
                kind: "GROUP",
            },
            MembershipRow {
                group: fixture.engineering,
                member: fixture.member.as_uuid(),
                kind: "USER",
            },
            MembershipRow {
                group: fixture.finance_leads,
                member: fixture.owner.as_uuid(),
                kind: "USER",
            },
        ],
    }
}

/// The fixed fixture timestamp.
fn fixture_time() -> DateTime<Utc> {
    // The constant is in range, so the fallback is unreachable; it exists because a seeding command
    // must not be able to panic, and a timestamp that is a second off is not worth aborting over.
    DateTime::from_timestamp(FIXTURE_EPOCH_SECOND, 0).unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test; the workspace warns on these in non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use crate::cli::SeedProfile;

    use super::*;

    fn slugs(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn the_plan_is_the_harness_fixture_and_not_a_copy_of_it() {
        // The one property worth pinning: if someone hardcodes a slug or an id here, the tests that
        // assert against tenant-alpha are asserting about a different tenant than the one a
        // contributor is looking at.
        let fixtures = Fixtures::default();
        let alpha = plan_for(&fixtures.alpha);
        assert_eq!(alpha.slug, "tenant-alpha");
        assert_eq!(alpha.id, fixtures.alpha.id);
        assert!(alpha.users.iter().any(|user| user.id == fixtures.alpha.owner));
        assert!(alpha.groups.iter().any(|group| group.id == fixtures.alpha.finance_leads));

        let beta = plan_for(&fixtures.beta);
        assert_eq!(beta.slug, "tenant-beta");
        assert_ne!(beta.id, alpha.id, "the two tenants must not collide");
    }

    #[test]
    fn the_fixture_set_matches_what_the_docs_describe() {
        // docs/12-TESTING.md §3: five principals and three groups per tenant, with finance-leads
        // nested inside finance so closure resolution has something to resolve.
        let alpha = plan_for(&Fixtures::default().alpha);
        assert_eq!(alpha.users.len(), 5);
        assert_eq!(alpha.groups.len(), 3);
        assert_eq!(alpha.memberships.len(), 3);
        assert_eq!(alpha.users.iter().filter(|user| user.is_admin).count(), 1);
        assert!(alpha.memberships.iter().any(|edge| edge.kind == "GROUP"), "no nested group");
    }

    #[test]
    fn the_fixture_timestamp_is_the_date_it_claims_to_be() {
        // A magic epoch second that quietly means 2025 would make every fixture row disagree with
        // the harness's, which stamps the same instant.
        assert_eq!(fixture_time().to_rfc3339(), "2026-01-01T00:00:00+00:00");
    }

    #[test]
    fn a_database_holding_only_fixtures_is_not_foreign() {
        // Re-seeding is the common case, and it must not need --force.
        let existing = slugs(&["tenant-alpha", "tenant-beta"]);
        let foreign = foreign_tenants(&existing, &["tenant-alpha", "tenant-beta"]);
        assert!(foreign.is_empty());
        assert_eq!(verdict(&foreign, false), Verdict::Proceed);
    }

    #[test]
    fn an_empty_database_proceeds() {
        let foreign = foreign_tenants(&[], &["tenant-alpha", "tenant-beta"]);
        assert_eq!(verdict(&foreign, false), Verdict::Proceed);
    }

    #[test]
    fn a_single_unknown_tenant_is_enough_to_refuse() {
        // The failure this exists for: DATABASE_URL still pointing at something real.
        let existing = slugs(&["acme-corp", "tenant-alpha"]);
        let foreign = foreign_tenants(&existing, &["tenant-alpha", "tenant-beta"]);
        assert_eq!(foreign, slugs(&["acme-corp"]));
        assert_eq!(verdict(&foreign, false), Verdict::Refuse);
    }

    #[test]
    fn force_overrides_the_refusal_and_says_that_it_did() {
        let existing = slugs(&["acme-corp"]);
        let foreign = foreign_tenants(&existing, &["tenant-alpha", "tenant-beta"]);
        assert_eq!(verdict(&foreign, true), Verdict::Overridden);
    }

    #[test]
    fn force_on_a_clean_database_is_not_recorded_as_an_override() {
        // Otherwise the word "override" appears in the output of a routine run and stops meaning
        // anything when it appears in the output of a dangerous one.
        assert_eq!(verdict(&[], true), Verdict::Proceed);
    }

    #[test]
    fn the_comparison_is_exact_rather_than_by_prefix() {
        // `tenant-alpha-staging` is somebody's real tenant, not a fixture.
        let existing = slugs(&["tenant-alpha-staging"]);
        let foreign = foreign_tenants(&existing, &["tenant-alpha", "tenant-beta"]);
        assert_eq!(foreign, slugs(&["tenant-alpha-staging"]));
    }

    fn dev_args(force: bool) -> SeedArgs {
        SeedArgs { profile: SeedProfile::Dev, force }
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL; set DATABASE_URL to a server this may create databases on"]
    async fn seeding_twice_writes_nothing_the_second_time() {
        let db = enclave_testing::TestDb::start().await.expect("a test database");
        let target = Target::from_url(db.url());

        run(&target, &dev_args(false)).await.expect("first seed");
        // Idempotence is not a nicety here: `docker compose up` re-runs this, and a second run that
        // failed would make the dev stack unrepeatable.
        run(&target, &dev_args(false)).await.expect("second seed must be a no-op");
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL; set DATABASE_URL to a server this may create databases on"]
    async fn a_foreign_tenant_stops_the_seed_until_force_is_given() {
        let db = enclave_testing::TestDb::start().await.expect("a test database");
        let mut conn = db.connect().await.expect("connect");
        sqlx::query(
            "INSERT INTO tenants (id, slug, display_name, status, created_at, updated_at)
             VALUES ($1, 'acme-corp', 'Acme', 'ACTIVE', now(), now())",
        )
        .bind(Uuid::new_v4())
        .execute(&mut conn)
        .await
        .expect("insert a tenant this command did not create");

        let target = Target::from_url(db.url());
        let err = run(&target, &dev_args(false)).await.expect_err("must refuse");
        let message = format!("{err}");
        assert!(message.contains("acme-corp"), "{message}");
        assert!(message.contains("--force"), "{message}");

        run(&target, &dev_args(true)).await.expect("--force proceeds");
    }
}
