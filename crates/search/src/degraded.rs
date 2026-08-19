//! Degraded mode: when it engages, and the envelope that cannot hide that it did.
//!
//! # The contract, from `plans/M3-DISCOVERY.md` D25
//!
//! Milvus down means lexical search over PostgreSQL with `degraded: true` in the response. The flag
//! is part of the **contract**, not an internal detail: a caller that cannot tell degraded results
//! from complete ones will report "the document isn't there" to a user, and the user will conclude
//! it was deleted. The document they then re-upload, or the deletion they then escalate, are both
//! caused by a boolean nobody plumbed through.
//!
//! And degraded mode is still post-filtered. It is a worse *recall* guarantee, never a worse
//! *authorization* guarantee — [`SearchResults::confirm_degraded`] runs the same
//! [`PostFilter::confirm`] the vector path runs, with no parameter that changes what it checks.
//!
//! # Why the flag cannot be forgotten
//!
//! [`SearchResults`] holds its `degraded` state in a private field with no setter, and there is no
//! constructor that takes a `bool`. Results exist only as the output of one of two `async` functions
//! on this type: [`SearchResults::confirm`], which post-filters a `Vec<Candidate>` from the vector
//! path and is complete, and [`SearchResults::confirm_degraded`], which post-filters a
//! [`LexicalCandidates`] and is degraded. Those two argument types are disjoint and neither converts
//! into the other, so the flag is not a thing a caller sets — it is decided by which generator
//! produced the candidates, and the compiler is what decides it.
//!
//! There is deliberately no `into_hits`. A method handing back a bare `Vec<Confirmed>` is one an API
//! layer calls on a Tuesday, and the flag would then be dropped at exactly the boundary D25 exists
//! to protect. Callers borrow the hits and serialise them alongside `is_degraded`.
//!
//! # When degraded mode engages, and why not on latency
//!
//! [`Retrieval::decide`] engages it on exactly two signals, both of which are *states that persist
//! across requests*:
//!
//! 1. **The vector store is unreachable** — the circuit is open, the collection will not load, the
//!    connection cannot be made.
//! 2. **The denylist has outgrown its limit** (`docs/07-SEARCH-INDEXING.md §6.4`), which means
//!    invalidation is so far behind that the index is known to be wrong at scale. Serving from it
//!    would burn over-fetch budget on candidates the post-filter is about to drop, and crowd out the
//!    results that would have survived.
//!
//! What is **not** a trigger is a slow query, a single timeout, or a request that missed its budget.
//! [`VectorStore`] has no `Slow` variant and that absence is the design. A latency trigger engages
//! under load — which is exactly when the vector path is most valuable and when its slowness is
//! least informative — and it engages *per request*, so the same query answers completely at
//! 10:00:01 and degraded at 10:00:02 with no state change in between. Neither the user nor the
//! engineer they escalate to can reproduce that. A single timed-out vector query is an error
//! (`crate::error`: an outage is never an empty result); it is the retry and circuit-breaking around
//! it that eventually turn a sustained failure into [`VectorStore::Unreachable`], and only then does
//! this decision change.
//!
//! ## The failure mode this trigger has
//!
//! Say it plainly, because every trigger has one. This one covers *loud* failures. A vector store
//! that is up and answering but **wrong** — a collection dropped and recreated empty, a botched
//! rebuild, a tenant whose documents were never indexed — keeps the circuit closed, returns few or
//! no candidates, and the response says `degraded: false`. That is the confident wrong answer this
//! whole milestone is arranged against, and no amount of connection health detects it. Catching it
//! needs a different signal: `index_manifests` counting `READY` files against what the store holds,
//! and an alert when those diverge. That is not built here, and it is the gap to close next.
//!
//! The second, milder failure mode is on the recovery side: a circuit breaker holds open through its
//! probe interval, so the fallback stays engaged for a short while after the store is healthy again.
//! That costs recall for seconds, which is the side of this trade to err on.

use enclave_core::{AuthorizationService, RequestContext};
use sqlx::PgConnection;

use crate::error::SearchError;
use crate::lexical::LexicalCandidates;
use crate::postfilter::{Candidate, Confirmed, DropCounts, PostFilter};

/// The denylist size above which the index is treated as known-wrong at scale.
///
/// `docs/07-SEARCH-INDEXING.md §6.4` sets the default at ten thousand files. It is a tenant-level
/// figure: one tenant's reorganisation degrades that tenant, and no other.
pub const DEFAULT_DENYLIST_LIMIT: usize = 10_000;

/// Whether the vector store can be reached, as observed across requests rather than within one.
///
/// **There is no `Slow` variant, and there must not be one.** See the module documentation: a
/// latency-triggered fallback engages under load, which is when the vector path is worth the most,
/// and it engages per request, which makes the same query answer differently seconds apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorStore {
    /// Reachable — the circuit is closed. This says nothing about how fast the last query was, and
    /// deliberately cannot be made to.
    Available,
    /// Not reachable: the circuit is open, the collection is not loaded, or the connection failed.
    Unreachable,
}

/// What put retrieval into degraded mode.
///
/// A newtype around [`Cause`] with a private field, so the only way to hold one is to have called
/// [`Retrieval::decide`]. That matters because [`crate::lexical::candidates`] demands one: lexical
/// retrieval finds a fraction of what the vector path finds, and requiring the token means no call
/// site can slide into the fallback without the decision having been taken first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DegradedReason(Cause);

impl DegradedReason {
    /// The underlying cause, for diagnostics and metrics.
    ///
    /// The cause is operator-facing. The `degraded` boolean is caller-facing, and it is the part
    /// D25 makes a contract — an external caller needs to know their recall is reduced, not which
    /// internal component is unwell.
    #[must_use]
    pub const fn cause(self) -> Cause {
        self.0
    }
}

/// Why retrieval degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Cause {
    /// The vector store could not be reached.
    VectorStoreUnreachable,
    /// Invalidation is backed up far enough that the index is wrong at scale.
    DenylistOverflowing {
        /// Suppressed files for this tenant.
        entries: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
}

/// Which retrieval path a search should take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retrieval {
    /// The vector path, with its full recall.
    Complete,
    /// The lexical fallback, with the reason recorded.
    Degraded(DegradedReason),
}

impl Retrieval {
    /// Decides the path from store health and denylist pressure.
    ///
    /// Both arguments are states that outlive a single request, which is the whole point — see the
    /// module documentation for why no per-request signal appears here.
    ///
    /// Unreachability wins over denylist pressure when both hold: a store that cannot be reached
    /// makes the size of the denylist moot, and reporting the reason that is actionable
    /// (*the store is down*) beats reporting the one that is merely also true.
    #[must_use]
    pub const fn decide(
        store: VectorStore,
        denylist_entries: usize,
        denylist_limit: usize,
    ) -> Self {
        match store {
            VectorStore::Unreachable => {
                Self::Degraded(DegradedReason(Cause::VectorStoreUnreachable))
            }
            VectorStore::Available if denylist_entries > denylist_limit => {
                Self::Degraded(DegradedReason(Cause::DenylistOverflowing {
                    entries: denylist_entries,
                    limit: denylist_limit,
                }))
            }
            VectorStore::Available => Self::Complete,
        }
    }
}

/// A finished search: what the caller may see, what was dropped getting there, and whether the
/// answer is complete.
///
/// Construct one only through [`SearchResults::confirm`] or [`SearchResults::confirm_degraded`].
/// Both post-filter; the difference between them is which generator produced the candidates, and
/// that is what sets `degraded`.
#[derive(Debug)]
#[must_use = "the degraded flag has to reach the caller; dropping the envelope drops it"]
pub struct SearchResults {
    hits: Vec<Confirmed>,
    counts: DropCounts,
    degraded: Option<DegradedReason>,
}

impl SearchResults {
    /// Post-filters candidates from the vector path. The result is **not** degraded.
    ///
    /// # Errors
    ///
    /// Whatever [`PostFilter::confirm`] can fail with, propagated rather than flattened into an
    /// empty result.
    pub async fn confirm(
        conn: &mut PgConnection,
        authorization: &dyn AuthorizationService,
        ctx: &RequestContext,
        candidates: Vec<Candidate>,
    ) -> Result<Self, SearchError> {
        let (hits, counts) = PostFilter::confirm(conn, authorization, ctx, candidates).await?;
        Ok(Self { hits, counts, degraded: None })
    }

    /// Post-filters candidates from the lexical fallback. The result **is** degraded, and says so.
    ///
    /// The only consumer of a [`LexicalCandidates`] anywhere in this crate. Every lexical hit
    /// therefore passes through the same [`PostFilter::confirm`] a Milvus hit does — same denylist
    /// read, same two-action resolution, no argument that softens either. D25's sentence, made
    /// structural: a worse recall guarantee, never a worse authorization guarantee.
    ///
    /// # Errors
    ///
    /// As [`SearchResults::confirm`].
    pub async fn confirm_degraded(
        conn: &mut PgConnection,
        authorization: &dyn AuthorizationService,
        ctx: &RequestContext,
        lexical: LexicalCandidates,
    ) -> Result<Self, SearchError> {
        let reason = lexical.reason();
        let (hits, counts) =
            PostFilter::confirm(conn, authorization, ctx, lexical.candidates).await?;
        Ok(Self { hits, counts, degraded: Some(reason) })
    }

    /// Whether recall was reduced. Serialised as `diagnostics.degraded`
    /// (`docs/07-SEARCH-INDEXING.md §6.6`).
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        self.degraded.is_some()
    }

    /// Why, if it was. `None` on a complete result.
    #[must_use]
    pub const fn degraded_reason(&self) -> Option<DegradedReason> {
        self.degraded
    }

    /// What the caller may see, in rank order.
    #[must_use]
    pub fn hits(&self) -> &[Confirmed] {
        &self.hits
    }

    /// What the post-filter discarded, for the drop-ratio metric the exit criteria require.
    #[must_use]
    pub const fn counts(&self) -> DropCounts {
        self.counts
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn an_unreachable_store_degrades_and_names_the_store() {
        let decision = Retrieval::decide(VectorStore::Unreachable, 0, DEFAULT_DENYLIST_LIMIT);
        assert_eq!(
            decision,
            Retrieval::Degraded(DegradedReason(Cause::VectorStoreUnreachable)),
            "an unreachable vector store is the one signal degraded mode exists for"
        );
    }

    #[test]
    fn a_reachable_store_with_a_quiet_denylist_is_complete() {
        // The assertion that keeps the other tests meaningful: if this returned `Degraded`, every
        // search would be degraded and the flag would carry no information at all.
        assert_eq!(
            Retrieval::decide(VectorStore::Available, 9_999, DEFAULT_DENYLIST_LIMIT),
            Retrieval::Complete
        );
    }

    #[test]
    fn a_denylist_past_its_limit_degrades_and_reports_both_numbers() {
        let decision = Retrieval::decide(VectorStore::Available, 10_001, DEFAULT_DENYLIST_LIMIT);
        let Retrieval::Degraded(reason) = decision else {
            panic!("an overflowing denylist must degrade: {decision:?}");
        };
        assert_eq!(
            reason.cause(),
            Cause::DenylistOverflowing { entries: 10_001, limit: DEFAULT_DENYLIST_LIMIT },
            "the operator needs both numbers to tell 'just over' from 'invalidation has stopped'"
        );
    }

    #[test]
    fn an_unreachable_store_outranks_denylist_pressure() {
        let decision = Retrieval::decide(VectorStore::Unreachable, 10_001, DEFAULT_DENYLIST_LIMIT);
        let Retrieval::Degraded(reason) = decision else { panic!("must degrade") };
        assert_eq!(
            reason.cause(),
            Cause::VectorStoreUnreachable,
            "with the store down, the denylist size is a true fact that fixes nothing"
        );
    }

    /// Latency cannot be expressed as a degradation trigger, and that is asserted as a type
    /// property because the dangerous version of this bug is not a wrong branch — it is somebody
    /// adding `VectorStore::Slow` in six months because a dashboard asked for it. This match is
    /// exhaustive over the enum, so a third variant does not compile until whoever added it has
    /// read the module documentation and decided what it means here.
    #[test]
    fn the_only_states_are_available_and_unreachable() {
        for store in [VectorStore::Available, VectorStore::Unreachable] {
            let degrades = match store {
                VectorStore::Available => false,
                VectorStore::Unreachable => true,
            };
            assert_eq!(
                Retrieval::decide(store, 0, DEFAULT_DENYLIST_LIMIT) != Retrieval::Complete,
                degrades
            );
        }
    }
}
