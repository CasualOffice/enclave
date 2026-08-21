//! The coverage probe: the background loop `crates/search/src/health.rs` was written for.
//!
//! # What was missing, and what was not
//!
//! `ENC-516` built the reading — `index_manifests` against what the store says it holds — and
//! `ENC-521` built everything downstream of it: four gauges, the exposition that renders them, and
//! three rules in `deploy/monitoring/alerts/search.yml`. What nothing did was *take* the reading.
//! `SearchIndexCoverageUnreported` — `absent(enclave_search_index_observed_chunks)` — describes the
//! deployment exactly as it stands, and the two alerts above it are not merely quiet but
//! structurally incapable of firing.
//!
//! This pass is that producer, and nothing else. Both of its numbers are measured:
//! [`enclave_search::health::expected_chunks`] aggregates PostgreSQL's `READY` manifests, and
//! [`enclave_search::health::IndexCensus`] asks the store. Neither is inferred, defaulted, or filled
//! in from a related fact — which is the bar `ENC-528` set, and the bar the other half of that row
//! still does not clear (see below).
//!
//! # Why it publishes to metrics and nowhere else
//!
//! `ENC-528` recorded the obstacle to scheduling the probe as needing "somewhere for the last
//! reading to live that a search can read". That store is still absent, and this pass deliberately
//! does not create it. An operator reading `enclave_search_index_observed_chunks` does not need a
//! search to have consulted it — depletion is a fact about a tenant's index, not about a request —
//! so the whole of this pass's value is realised at the exposition.
//!
//! The refused version is worth naming, because it is the natural next commit: a table, or a
//! process-wide cache, holding the last [`enclave_search::health::IndexHealth`] per tenant, which a
//! request reads to decide whether it may trust the index. That is a freshness surface a search
//! path consults, which `crates/worker/src/lib.rs` refusal 1 exists to keep out of this crate, and
//! it is a step from there to the per-file form. When the API grows a place for a health state to
//! live, the thing that lives there should be a state a search *already* has — reachability's
//! shape — decided in `enclave-search`, not a reading this loop stashed.
//!
//! Two consequences follow, and neither is a defect:
//!
//! - **A depleted tenant does not become degraded because this ran.** [`enclave_search::Retrieval`]
//!   takes a [`enclave_search::VectorStore`] from whatever holds the store's health, and nothing
//!   here hands it one. `ENC-514`'s rule is untouched: degraded mode still engages on a state that
//!   persists across requests, and this pass adds no per-request signal to it.
//! - **The gauges only reach an operator from a process that serves the exposition.** That is
//!   `crates/api/src/metrics_listener.rs`, and the worker binary is still a stub with no socket of
//!   its own. Where this pass is scheduled is the scheduler's decision (`crates/worker/src/lib.rs`),
//!   and whichever process it picks has to answer a scrape.
//!
//! # It reads. It writes nothing at all.
//!
//! Say it as a rule, because there is a specific wrong commit this module invites.
//!
//! A pass that has just established that a tenant's store holds everything PostgreSQL expects looks
//! like it is holding the answer to `retrieval_denylist.indexed_seq` — the column `ENC-520` added
//! and `ENC-528` records as having no producer. It is not. A census is a `count(*)` over a tenant's
//! partition; it cannot say that *this* file's chunks were removed, which is the only thing
//! [`enclave_search::confirm_indexed`] claims. Deriving one from the other would fill an "unknown"
//! column with an inference — the guess `ENC-520` refused to make from a manifest join, arriving
//! from a different direction — and it would be indistinguishable in the table from a confirmation
//! a real removal reported.
//!
//! `a_coverage_pass_leaves_the_catch_up_column_unasserted` in `tests/coverage.rs` is that rule made
//! executable, and it is paired with a gauge assertion so it cannot pass by the pass doing nothing.
//!
//! # A tenant that cannot be read is counted, not fatal
//!
//! [`invalidation::sweep`](crate::invalidation::sweep) stops at the first tenant that fails, and is
//! right to: it is doing work, and work left undone is the caller's business. This pass does no
//! work. Stopping here would blind every tenant *after* the failing one — their gauges would freeze
//! at whatever the last successful pass wrote, which is the reading that looks healthiest — for the
//! sake of a tenant that is already reporting a problem.
//!
//! So a failed reading is counted in [`CoverageOutcome::unreadable`], logged with the tenant, and
//! the pass moves on. That is also the only treatment consistent with `health.rs`, which refuses to
//! turn a census failure into `Depleted`: a probe that could not run is not evidence about the
//! store, and a pass that aborted on one would be making it evidence about every other tenant.
//!
//! # No per-tenant reading escapes
//!
//! [`probe_pass`] reports counts. The per-tenant function underneath it is private, so this crate's
//! public surface cannot be asked "what is tenant X's coverage?" — the question is
//! [`enclave_search::health::probe`]'s to answer, where the module documentation warning about what
//! a coverage number does and does not mean is attached to it.

use enclave_core::TenantId;
use enclave_db::DbPool;
use enclave_search::health::{self, CoverageFloor, IndexCensus, IndexHealth};
use tracing::{debug, warn};

use crate::error::Result;
use crate::Stop;

/// What one pass over a set of tenants observed.
///
/// Counts, never readings — see this module's documentation. The four tenant counters partition the
/// list: `stocked + depleted + unknown + unreadable` is every tenant the pass reached before
/// [`Stop`] was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CoverageOutcome {
    /// Tenants whose store holds at least the floor's share of what PostgreSQL expects.
    pub stocked: usize,
    /// Tenants whose store is answering and holds materially less than PostgreSQL expects.
    ///
    /// The number `SearchIndexDepletedAndTenantIsDegraded` pages on, counted here as well so that a
    /// pass which found depletion is visible to whoever drove it without going to Prometheus.
    pub depleted: usize,
    /// Tenants the signal could say nothing about — nothing indexed, or manifests recording no
    /// chunk counts.
    ///
    /// **Not a health verdict.** `enclave_search::health::Unknown` documents both cases; the second
    /// one is a deployment whose depletion signal is blind while looking green, which is why it is
    /// counted apart from [`Self::stocked`] rather than folded into it.
    pub unknown: usize,
    /// Tenants whose reading failed — PostgreSQL, the store, or the connection to either.
    ///
    /// Distinct from [`Self::unknown`], and the distinction is the point: unknown means the signal
    /// has nothing to say about a tenant that is otherwise fine, unreadable means nobody knows
    /// because the probe did not complete. A counter that folded them together would report a
    /// store-wide outage as a fleet of new tenants.
    pub unreadable: usize,
    /// Whether the pass returned early because [`Stop`] was raised.
    pub stopped: bool,
}

impl CoverageOutcome {
    /// Tenants this pass reached, whatever it found.
    #[must_use]
    pub const fn tenants(&self) -> usize {
        self.stocked + self.depleted + self.unknown + self.unreadable
    }
}

/// Probes each tenant in turn, publishing a coverage reading for each, until the list ends or
/// [`Stop`] is raised.
///
/// The tenant list is a parameter: see this crate's documentation for why housekeeping does not
/// enumerate tenants for itself.
///
/// One tenant-scoped transaction per reading, and the reading is published by
/// [`enclave_search::health::probe`] where it is computed — this pass records no metric of its own,
/// for the reason `crates/search/src/postfilter.rs` gives about the drop ratio: a second pass that
/// gathered the numbers again would be a second answer, and it would be the one on the dashboard.
///
/// Never returns an error. A tenant that cannot be read is counted and logged; see this module's
/// documentation for why a pass that only observes must not stop at the first failure.
pub async fn probe_pass(
    pool: &DbPool,
    tenants: &[TenantId],
    census: &dyn IndexCensus,
    floor: CoverageFloor,
    stop: &Stop,
) -> CoverageOutcome {
    let mut outcome = CoverageOutcome::default();

    for &tenant in tenants {
        if stop.is_stopped() {
            outcome.stopped = true;
            break;
        }

        match probe_tenant(pool, tenant, census, floor).await {
            Ok(IndexHealth::Stocked { .. }) => outcome.stocked += 1,
            Ok(IndexHealth::Depleted { .. }) => outcome.depleted += 1,
            Ok(IndexHealth::Unknown { .. }) => outcome.unknown += 1,
            Err(error) => {
                outcome.unreadable += 1;
                // The tenant, because a probe failing for one tenant and for all of them are
                // different incidents. Not the reading — there is not one.
                warn!(tenant = %tenant, %error, "coverage probe failed for a tenant");
            }
        }
    }

    debug!(
        stocked = outcome.stocked,
        depleted = outcome.depleted,
        unknown = outcome.unknown,
        unreadable = outcome.unreadable,
        stopped = outcome.stopped,
        "coverage probe pass complete"
    );
    outcome
}

/// One tenant's reading, in one tenant-scoped transaction.
///
/// **Private, and it is the private one that matters.** A public `probe_tenant` returning an
/// `IndexHealth` is a per-tenant freshness answer on this crate's surface, and the next step from
/// there — caching it so a request need not wait for it — is the dependency
/// `crates/worker/src/lib.rs` refusal 1 forbids. Anyone who genuinely wants a single reading calls
/// [`enclave_search::health::probe`], where the documentation about what a coverage number cannot
/// tell you is attached to the function.
///
/// The transaction is read-only and committed rather than dropped, so a connection that cannot be
/// returned is reported here instead of by `Drop`. An error on the way in leaves the transaction to
/// roll back, which is what it would do anyway: nothing in it wrote.
async fn probe_tenant(
    pool: &DbPool,
    tenant: TenantId,
    census: &dyn IndexCensus,
    floor: CoverageFloor,
) -> Result<IndexHealth> {
    let mut tx = pool.begin(tenant).await?;
    let health = health::probe(&mut tx, tenant, census, floor).await?;
    tx.commit().await?;
    Ok(health)
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// A tenant nobody could read is not a tenant with nothing indexed.
    ///
    /// The same distinction `TenantSweep::Contended` exists for, and the same failure if it is
    /// lost: a store-wide outage makes every reading fail, and a counter that folded those into
    /// `unknown` would render it as a fleet of brand-new tenants — the one shape an operator reads
    /// as "nothing to do here".
    ///
    /// Be clear about what this catches, because half of it is free (`docs/12-TESTING.md §1.2`).
    /// Merging the two counters would fail to *compile* here rather than fail this assertion, and
    /// the behavioural half — which counter a failed reading actually lands in — is
    /// `a_reading_that_failed_publishes_nothing_and_is_not_recorded_as_a_verdict` in
    /// `tests/coverage.rs`, which was watched to fail against a pass that recorded one as the
    /// other. What is not free is the second line: a [`CoverageOutcome::tenants`] that forgot
    /// either counter makes the two totals disagree.
    #[test]
    fn an_unreadable_tenant_is_not_reported_as_an_unknown_one() {
        let outage = CoverageOutcome { unreadable: 3, ..CoverageOutcome::default() };
        let fresh = CoverageOutcome { unknown: 3, ..CoverageOutcome::default() };
        assert_ne!(outage, fresh);
        assert_eq!(outage.tenants(), fresh.tenants(), "both reached three tenants");
    }

    /// The counters partition the tenants reached, so a pass cannot report more verdicts than
    /// tenants — which is what a reading counted twice, or counted and then re-counted as failed,
    /// would look like.
    #[test]
    fn every_tenant_reached_is_counted_exactly_once() {
        let outcome =
            CoverageOutcome { stocked: 2, depleted: 1, unknown: 4, unreadable: 1, stopped: true };
        assert_eq!(outcome.tenants(), 8);
    }
}
