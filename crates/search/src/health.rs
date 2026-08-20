//! Index health: catching a vector store that is up and **wrong**.
//!
//! # The failure this closes
//!
//! [`crate::degraded`] names the gap its own trigger has, and this module is the answer to it. The
//! reachability trigger covers *loud* failures — the connection is refused, the collection is not
//! there, the circuit is open. A collection that was dropped and recreated empty, a rebuild that
//! failed halfway, a tenant whose documents were never indexed at all: none of those move
//! [`VectorStore::Unreachable`]. The store answers, quickly, with nothing, and the response says
//! `degraded: false`.
//!
//! That is the worst shape available — **confidently complete, and wrong**. A caller who is told
//! their search was complete and sees two hits concludes the document is not there. A caller told
//! their recall is reduced goes and looks somewhere else. `plans/M3-DISCOVERY.md` D25 makes that
//! distinction a contract, and a trigger that cannot see an empty store leaves the contract stating
//! something false.
//!
//! # The signal, and why it is a state rather than a measurement
//!
//! `index_manifests` is PostgreSQL's record of what the pipeline believes it wrote: for each file,
//! a status and a `chunk_count`. Summed over a tenant's `READY` manifests, that is how many chunks
//! the authority says the store holds. The store can be asked how many it *does* hold. When the
//! second is a small fraction of the first, the index is not stale — it is absent.
//!
//! `ENC-514` forbids a per-request trigger and the reasoning applies here unchanged: a signal
//! sampled inside a request makes the same query answer completely at 10:00:01 and degraded at
//! 10:00:02 with no state change, which nobody can reproduce and nobody can debug. So:
//!
//! - [`probe`] is for a **background health loop**, at the same cadence a circuit breaker probes
//!   reachability. It costs one aggregate per tenant against PostgreSQL and one `count(*)` against
//!   the store — cheap once a minute, and not something to put in a search's latency budget.
//! - What a search is handed is the [`VectorStore`] value the last probe produced, exactly as it is
//!   handed the last reachability observation. Two identical queries seconds apart get the same
//!   answer, because the input only changes when something writes to or wipes the store.
//!
//! # What this deliberately does not know
//!
//! Say it plainly, because a count looks more authoritative than it is.
//!
//! 1. **Counts agreeing does not mean the store is right.** The right number of wrong chunks
//!    reads as healthy here. Nothing about content, embeddings, or `acl_tokens` is checked — and
//!    nothing needs to be, because the post-filter is what makes a wrong candidate harmless
//!    (`CLAUDE.md` rule 5). What is being detected is *absence*, which the post-filter cannot
//!    detect and cannot repair.
//! 2. **A tenant whose manifests record no chunks is unknown, not healthy.** `chunk_count` defaults
//!    to `0`, so an indexer that never populates it produces a tenant that expects nothing and can
//!    therefore never be found depleted. That is reported as [`Unknown::ChunkCountsUnrecorded`]
//!    rather than folded into "fine": the difference between "this tenant has nothing indexed" and
//!    "this signal is blind for this tenant" is the difference between a quiet dashboard and a
//!    broken one.
//! 3. **Unknown never degrades.** A fresh install, a tenant that has uploaded nothing, an indexer
//!    that has not run: all of them legitimately expect zero chunks. Degrading on them would make
//!    degraded mode the steady state, and a flag that is always set carries no information — the
//!    same reason `crate::degraded`'s tests assert that a quiet denylist stays `Complete`. The
//!    unknown states are for the operator, through metrics and an alert, not for the caller.
//! 4. **It is per tenant, and there is no per-file form.** `crates/worker/src/lib.rs` refusal 1: a
//!    predicate answering "is *this* file's index current?" is the function a search path
//!    eventually calls to skip work. [`EXPECTED_CHUNKS_SQL`] aggregates, and a test asserts it
//!    names no `file_id`, so growing that predicate here means breaking a test rather than adding a
//!    line.
//!
//! # Where the numbers come from
//!
//! PostgreSQL's half is [`expected_chunks`]. The store's half is [`IndexCensus`], which is
//! deliberately **not** a method on [`crate::vector::VectorIndex`]: the port a search holds should
//! offer candidates and nothing else, and a census hanging off it is an invitation to sample it
//! inside a request. `crates/search/src/milvus.rs` implements both traits on one client, which is
//! the correct place for that to meet — a client can do two jobs; a port should describe one.

use async_trait::async_trait;
use enclave_core::TenantId;
use enclave_observability::metrics::search::IndexCoverage;
use sqlx::{PgConnection, Row as _};

use crate::degraded::VectorStore;
use crate::error::SearchError;

/// The share of PostgreSQL's expectation the store must hold to count as stocked, in percent.
///
/// Fifty, and the number is a judgement rather than a measurement, so here is the judgement. This
/// signal exists to catch an index that is *categorically* absent — a collection recreated, a
/// restore that missed a volume, a tenant nothing ever indexed. It does not exist to measure lag: a
/// store that is behind by a few thousand chunks is the ordinary state of a system with an
/// indexing queue, and the post-filter plus the denylist already make that harmless.
///
/// A high floor (the 99% `docs/07-SEARCH-INDEXING.md §9` uses to decide an alias flip) would put
/// every tenant with a backlog into degraded mode, which is both wrong and self-defeating: the flag
/// would stop distinguishing anything. A low floor errs the other way, and the cost of erring there
/// is that a half-empty index reads as stocked — which is the state the drop-ratio and denylist
/// alerts already describe.
pub const DEFAULT_COVERAGE_FLOOR: CoverageFloor = CoverageFloor(50);

/// How empty a store may be before it stops counting as a candidate generator.
///
/// A percentage of what PostgreSQL says is indexed, held as an integer so the comparison is exact
/// and so this can travel through a `const fn`. See [`DEFAULT_COVERAGE_FLOOR`] for why the default
/// is where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CoverageFloor(u32);

impl CoverageFloor {
    /// A floor of `percent`, clamped to 100.
    ///
    /// Clamped rather than rejected: a floor above 100 asks for a store holding more than the
    /// authority says exists, which is unsatisfiable, and the failure mode of an unsatisfiable
    /// floor is a tenant permanently degraded for a configuration typo.
    #[must_use]
    pub const fn percent(percent: u32) -> Self {
        Self(if percent > 100 { 100 } else { percent })
    }

    /// The floor, as a percentage.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Why coverage could not be concluded.
///
/// Every variant means *this signal has nothing to say about this tenant*. None of them means the
/// store is healthy, and none of them degrades a search — see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unknown {
    /// PostgreSQL holds no `READY` manifest for this tenant, so it asserts nothing about what the
    /// store should contain. The ordinary state of a new tenant, and indistinguishable from a
    /// tenant whose manifests were lost.
    NothingIndexed,
    /// `READY` manifests exist and record no chunks between them.
    ///
    /// `index_manifests.chunk_count` defaults to `0`, so this is what an indexer that never
    /// populates it looks like — and it is worth naming, because in that deployment this whole
    /// signal is blind while looking green.
    ChunkCountsUnrecorded {
        /// How many `READY` manifests were counted, all of them claiming no chunks.
        ready_files: u64,
    },
}

/// What PostgreSQL says the store should hold for a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// A non-zero number of chunks across `READY` manifests.
    Chunks(u64),
    /// Nothing can be concluded, and why.
    Unknown(Unknown),
}

/// One reading of a tenant's index coverage.
///
/// Produced by [`probe`], consumed by a health loop and by metrics. It carries the observed count
/// in every variant, including the unknown ones, because "PostgreSQL expects nothing and the store
/// holds four million chunks" is a real state — an orphaned tenant — and a reading that discarded
/// the number would make it invisible. Acting on it is out of scope here; not throwing it away
/// costs nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexHealth {
    /// Coverage could not be concluded.
    Unknown {
        /// Which of the unknowable cases this is.
        reason: Unknown,
        /// What the store reported anyway.
        observed_chunks: u64,
    },
    /// The store holds at least the floor's share of what PostgreSQL says is indexed.
    Stocked {
        /// Chunks across the tenant's `READY` manifests.
        expected_chunks: u64,
        /// Chunks the store reports for the tenant.
        observed_chunks: u64,
    },
    /// The store is answering and holds materially less than PostgreSQL says is indexed.
    Depleted {
        /// Chunks across the tenant's `READY` manifests.
        expected_chunks: u64,
        /// Chunks the store reports for the tenant.
        observed_chunks: u64,
    },
}

impl IndexHealth {
    /// Compares one tenant's two numbers.
    ///
    /// Pure, and separated from both queries on purpose: it is the whole of the decision, so it is
    /// the thing that has to be exercised at its boundaries by tests that need neither a database
    /// nor a vector store.
    ///
    /// A store holding *exactly* the floor's share is stocked. The floor is the point at which the
    /// store stops being usable, and a boundary that degraded on equality would make
    /// [`CoverageFloor::percent(100)`](CoverageFloor::percent) — "the store must be complete" —
    /// degrade a complete store.
    #[must_use]
    pub const fn assess(expected: Expected, observed_chunks: u64, floor: CoverageFloor) -> Self {
        match expected {
            Expected::Unknown(reason) => Self::Unknown { reason, observed_chunks },
            Expected::Chunks(expected_chunks) => {
                // Widened, because a tenant with billions of chunks times a percentage is not a
                // number to discover the edge of during an incident.
                let held = (observed_chunks as u128) * 100;
                let required = (expected_chunks as u128) * (floor.get() as u128);
                if held >= required {
                    Self::Stocked { expected_chunks, observed_chunks }
                } else {
                    Self::Depleted { expected_chunks, observed_chunks }
                }
            }
        }
    }

    /// The store state this reading contributes to [`crate::Retrieval::decide`].
    ///
    /// [`IndexHealth::Unknown`] maps to [`VectorStore::Available`], which is the load-bearing line
    /// in this module: not knowing is not a reason to tell every caller their results are
    /// incomplete. The unknown cases are an operator's problem and reach them through metrics.
    ///
    /// [`VectorStore::Unreachable`] is never produced here. Reachability is
    /// [`crate::vector::VectorIndex::reachability`]'s answer, and a census that fails is an error
    /// rather than a verdict — see [`probe`].
    #[must_use]
    pub const fn store_state(self) -> VectorStore {
        match self {
            Self::Unknown { .. } | Self::Stocked { .. } => VectorStore::Available,
            Self::Depleted { expected_chunks, observed_chunks } => {
                VectorStore::Depleted { expected_chunks, observed_chunks }
            }
        }
    }

    /// What the store reported, whatever the verdict.
    #[must_use]
    pub const fn observed_chunks(self) -> u64 {
        match self {
            Self::Unknown { observed_chunks, .. }
            | Self::Stocked { observed_chunks, .. }
            | Self::Depleted { observed_chunks, .. } => observed_chunks,
        }
    }

    /// What PostgreSQL expected, or `None` when it asserted nothing usable.
    #[must_use]
    pub const fn expected_chunks(self) -> Option<u64> {
        match self {
            Self::Unknown { .. } => None,
            Self::Stocked { expected_chunks, .. } | Self::Depleted { expected_chunks, .. } => {
                Some(expected_chunks)
            }
        }
    }

    /// Why coverage could not be concluded, for the metric that says this signal is blind.
    #[must_use]
    pub const fn unknown_reason(self) -> Option<Unknown> {
        match self {
            Self::Unknown { reason, .. } => Some(reason),
            Self::Stocked { .. } | Self::Depleted { .. } => None,
        }
    }
}

/// How many chunks a store holds for one tenant.
///
/// **Not a method on [`crate::vector::VectorIndex`]**, and the separation is the point: that port
/// is what a search holds, and everything reachable from it is something a search can be made to do
/// per request. This is a probe, taken by a health loop, at a cadence — see the module
/// documentation for why a per-request measurement is forbidden as a degradation trigger.
///
/// Per tenant and aggregate. There is no method here that answers for a file, and there must not be
/// one: `crates/worker/src/lib.rs` sets out at length why a per-file freshness predicate is the
/// function that eventually gets called to skip a post-filter.
#[async_trait]
pub trait IndexCensus: Send + Sync + std::fmt::Debug {
    /// Chunks the store reports for `tenant`.
    ///
    /// # Errors
    ///
    /// Whatever the store's client fails with. An error rather than a zero, because a census that
    /// could not be taken and a store that holds nothing are the two readings this module exists to
    /// tell apart — and defaulting the failure to zero would report the healthiest deployment as
    /// the emptiest one, in the one direction that degrades every tenant at once.
    async fn chunks(&self, tenant: TenantId) -> Result<u64, SearchError>;
}

/// What PostgreSQL says should be in the store for `tenant`.
///
/// # Errors
///
/// Storage failures.
pub async fn expected_chunks(
    conn: &mut PgConnection,
    tenant: TenantId,
) -> Result<Expected, SearchError> {
    let row = sqlx::query(EXPECTED_CHUNKS_SQL).bind(tenant.as_uuid()).fetch_one(&mut *conn).await?;

    let read = |column: &'static str| -> Result<u64, SearchError> {
        let count: i64 = row
            .try_get(column)
            .map_err(|_| SearchError::MalformedRow { column, reason: "missing or not a bigint" })?;
        u64::try_from(count)
            .map_err(|_| SearchError::MalformedRow { column, reason: "a count came back negative" })
    };

    let ready_files = read("ready_files")?;
    let ready_chunks = read("ready_chunks")?;

    Ok(match (ready_files, ready_chunks) {
        (0, _) => Expected::Unknown(Unknown::NothingIndexed),
        (ready_files, 0) => Expected::Unknown(Unknown::ChunkCountsUnrecorded { ready_files }),
        (_, chunks) => Expected::Chunks(chunks),
    })
}

/// One tenant's coverage reading: ask PostgreSQL, ask the store, compare.
///
/// **For a health loop, never for a request.** The module documentation says why at length; the
/// short form is `ENC-514`: a degradation trigger sampled per request makes the same query answer
/// differently seconds apart, and neither the user nor the engineer they escalate to can reproduce
/// that.
///
/// The census is taken even when PostgreSQL turns out to assert nothing, so that a tenant the
/// database has forgotten and the store has not is visible rather than skipped.
///
/// # It publishes the reading
///
/// Where it computes it, for the reason `crate::postfilter` gives about the drop ratio: a metric
/// gathered by a second pass is a second answer, and the one on the dashboard is always the one
/// nobody wrote a test for. A probe that ran and did not report is also the failure mode the
/// `SearchIndexCoverageUnreported` alert exists to catch, so the two have to be the same call.
///
/// # Errors
///
/// A storage failure, or a census the store could not answer. Deliberately not a verdict: an
/// unreachable store is [`crate::vector::VectorIndex::reachability`]'s answer and already degrades,
/// and turning a failed census into `Depleted` here would degrade a tenant for a broken probe.
pub async fn probe(
    conn: &mut PgConnection,
    tenant: TenantId,
    census: &dyn IndexCensus,
    floor: CoverageFloor,
) -> Result<IndexHealth, SearchError> {
    let expected = expected_chunks(conn, tenant).await?;
    let observed = census.chunks(tenant).await?;
    let health = IndexHealth::assess(expected, observed, floor);

    IndexCoverage {
        expected_chunks: health.expected_chunks(),
        observed_chunks: health.observed_chunks(),
        floor_percent: floor.get(),
    }
    .record(tenant);

    Ok(health)
}

/// What the pipeline says it wrote, aggregated.
///
/// `READY` only: any other status is a file the indexer has not finished with, and counting those
/// would make an ordinary backlog look like a missing index. The two numbers come from one pass so
/// they describe one snapshot.
///
/// The projection is aggregate — no `file_id`, no per-row output — and a test asserts that. See the
/// module documentation, refusal 4.
const EXPECTED_CHUNKS_SQL: &str = "
SELECT count(*) FILTER (WHERE status = 'READY')                          AS ready_files,
       coalesce(sum(chunk_count) FILTER (WHERE status = 'READY'), 0)     AS ready_chunks
  FROM index_manifests
 WHERE tenant_id = $1
";

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// **The `ENC-516` case.** A collection recreated empty, against a tenant PostgreSQL says has
    /// ten thousand chunks indexed.
    ///
    /// The store is up. The circuit is closed. `reachability` says `Available` and is right. This
    /// is the only thing in the tree that notices.
    #[test]
    fn an_empty_store_against_a_populated_tenant_is_depleted() {
        let health = IndexHealth::assess(Expected::Chunks(10_000), 0, DEFAULT_COVERAGE_FLOOR);
        assert_eq!(
            health,
            IndexHealth::Depleted { expected_chunks: 10_000, observed_chunks: 0 },
            "an empty store reported as stocked is the confidently-wrong answer M3 is arranged \
             against"
        );
        assert_eq!(
            health.store_state(),
            VectorStore::Depleted { expected_chunks: 10_000, observed_chunks: 0 }
        );
    }

    /// The assertion that keeps the one above meaningful.
    ///
    /// `crate::degraded`'s tests make the same move for the denylist: if a healthy store degraded,
    /// every search would be degraded and the flag would carry no information at all.
    #[test]
    fn a_store_holding_what_postgres_expects_is_stocked() {
        let health = IndexHealth::assess(Expected::Chunks(10_000), 10_000, DEFAULT_COVERAGE_FLOOR);
        assert_eq!(
            health,
            IndexHealth::Stocked { expected_chunks: 10_000, observed_chunks: 10_000 }
        );
        assert_eq!(health.store_state(), VectorStore::Available);
    }

    /// A store ahead of PostgreSQL is stocked, not suspicious.
    ///
    /// It is the ordinary state mid-indexing: chunks are written to the store before the manifest
    /// that records them commits. Reading "more than expected" as a fault would degrade a tenant
    /// for indexing successfully.
    #[test]
    fn a_store_ahead_of_the_manifests_is_stocked() {
        assert_eq!(
            IndexHealth::assess(Expected::Chunks(100), 250, DEFAULT_COVERAGE_FLOOR).store_state(),
            VectorStore::Available
        );
    }

    /// The boundary, in both directions, because an off-by-one here is a threshold nobody can see.
    #[test]
    fn the_floor_is_inclusive_and_one_chunk_below_it_is_not() {
        let floor = CoverageFloor::percent(50);
        assert!(
            matches!(
                IndexHealth::assess(Expected::Chunks(1_000), 500, floor),
                IndexHealth::Stocked { .. }
            ),
            "exactly at the floor must be stocked, or a floor of 100% degrades a complete store"
        );
        assert!(
            matches!(
                IndexHealth::assess(Expected::Chunks(1_000), 499, floor),
                IndexHealth::Depleted { .. }
            ),
            "one chunk below the floor must degrade, or the floor is decorative"
        );
    }

    /// A floor of 100% is satisfiable by a complete store — the property the inclusive comparison
    /// above exists for, asserted where somebody would configure it.
    #[test]
    fn a_hundred_percent_floor_accepts_a_complete_store_and_refuses_a_short_one() {
        let strict = CoverageFloor::percent(100);
        assert!(matches!(
            IndexHealth::assess(Expected::Chunks(7), 7, strict),
            IndexHealth::Stocked { .. }
        ));
        assert!(matches!(
            IndexHealth::assess(Expected::Chunks(7), 6, strict),
            IndexHealth::Depleted { .. }
        ));
    }

    /// Unknown is not healthy, and it is not degraded either.
    ///
    /// Both halves matter. If unknown degraded, every fresh tenant would be permanently degraded
    /// and the flag would mean nothing. If unknown were silently folded into stocked, a deployment
    /// whose indexer never records `chunk_count` would have a blind signal that reports green —
    /// which is this module's own failure mode, and the one it has to be able to say out loud.
    #[test]
    fn unknown_never_degrades_and_still_says_it_is_unknown() {
        let no_manifests = IndexHealth::assess(
            Expected::Unknown(Unknown::NothingIndexed),
            0,
            DEFAULT_COVERAGE_FLOOR,
        );
        assert_eq!(no_manifests.store_state(), VectorStore::Available);
        assert_eq!(no_manifests.unknown_reason(), Some(Unknown::NothingIndexed));
        assert_eq!(no_manifests.expected_chunks(), None);

        let blind = IndexHealth::assess(
            Expected::Unknown(Unknown::ChunkCountsUnrecorded { ready_files: 40 }),
            0,
            DEFAULT_COVERAGE_FLOOR,
        );
        assert_eq!(blind.store_state(), VectorStore::Available);
        assert_eq!(
            blind.unknown_reason(),
            Some(Unknown::ChunkCountsUnrecorded { ready_files: 40 }),
            "a blind signal has to be distinguishable from a quiet one"
        );
    }

    /// An orphaned tenant — PostgreSQL expects nothing, the store is full — keeps its number.
    #[test]
    fn an_unknown_reading_still_carries_what_the_store_reported() {
        let health = IndexHealth::assess(
            Expected::Unknown(Unknown::NothingIndexed),
            4_000_000,
            DEFAULT_COVERAGE_FLOOR,
        );
        assert_eq!(health.observed_chunks(), 4_000_000);
    }

    /// No per-file freshness answer, asserted where it would be written.
    ///
    /// `crates/worker/src/lib.rs` refusal 1. The dangerous version of this change is not a wrong
    /// comparison — it is somebody adding `file_id` to this projection because a dashboard wanted a
    /// list, and a per-file freshness read existing in the search crate at all.
    #[test]
    fn the_expectation_query_is_an_aggregate_and_cannot_answer_for_one_file() {
        assert!(
            !EXPECTED_CHUNKS_SQL.contains("file_id"),
            "the coverage query grew a per-file projection, which is the freshness oracle ENC-518 \
             refuses"
        );
        assert!(
            EXPECTED_CHUNKS_SQL.contains("'READY'"),
            "counting non-READY manifests makes an ordinary indexing backlog look like a missing \
             index"
        );
    }

    /// A floor is a percentage; an unsatisfiable one is a configuration typo, not a policy.
    #[test]
    fn a_floor_above_a_hundred_percent_is_clamped_rather_than_honoured() {
        assert_eq!(CoverageFloor::percent(400).get(), 100);
        assert_eq!(DEFAULT_COVERAGE_FLOOR.get(), 50);
    }
}
