//! The authoritative post-filter: the one thing that makes search unable to leak.
//!
//! # The sentence this module exists to enforce
//!
//! **The vector index is a candidate generator. PostgreSQL is the authority.** (`CLAUDE.md` rule 5,
//! `docs/07-SEARCH-INDEXING.md §6.2`.)
//!
//! Every other read path in the product answers one question about one resource the caller named.
//! Search answers a question the caller did not phrase, about resources they did not name, by
//! consulting a *second* store that holds a copy of the content and its own idea of who may see it.
//! Both of those are new failure modes: the copy can be stale, and the second idea can be wrong.
//!
//! So nothing the index says about permissions is believed. `acl_tokens` in the vector store are an
//! optimisation — they make the candidate set smaller and are allowed to be wrong in the permissive
//! direction — and this module is what makes that safe.
//!
//! # Why it is not conditional, and must never become so
//!
//! The tempting optimisation is to skip the post-filter when some other signal looks confident: the
//! index was rebuilt recently, the ACL epoch matches, a cache is warm. Each of those is a claim
//! *about* the thing being checked, made by the thing being checked.
//!
//! A post-filter skipped when another signal looks confident is a post-filter that is absent
//! exactly when that signal is wrong — and a stale `acl_epoch` is not a rare pathology, it is the
//! ordinary state of an index between a permission change and the worker catching up.
//!
//! [`PostFilter::confirm`] therefore takes the candidates and resolves them, every time. There is no
//! parameter that turns it off and no path around it. `plans/M3-DISCOVERY.md` records this as the
//! decision the milestone is built on.
//!
//! # Two disclosure levels, one resolution
//!
//! `docs/07 §6.2` checks two things: `MetadataRead` to see a hit at all, and `ContentRead` to see
//! its excerpt. A user who may know a document exists but not read it gets the title and no snippet.
//!
//! That section resolves them separately, which was right when `authorize_many` batched resources
//! only. `ENC-145` then measured resolution as **~80% fixed cost** — 1.4 ms for one candidate,
//! 7.0 ms for two hundred — so a second pass very nearly doubles the post-filter's price while
//! raising over-fetch is close to free. `ENC-167` made one call possible, and
//! `plans/M3-DISCOVERY.md` D20 locks it: both levels come from a single
//! `authorize_many_actions`. `ENC-505` tracks the document catching up.
//!
//! # The denylist is consulted here, not in the index
//!
//! S3 asks that a revoked file vanish immediately, before any index update; S4 asks that this hold
//! with the invalidation worker stopped. A design that removes the document from the index cannot
//! satisfy both — a stopped worker leaves the file findable, and the search answers confidently.
//!
//! So revocation writes `retrieval_denylist` in the same transaction as the ACL change (D22), and
//! this module drops denylisted candidates *before* resolving. Not for safety — the authorization
//! resolution below would refuse them anyway, because it reads the same `acl_entries` the
//! revocation changed. The denylist is what makes the answer right when the *index* is stale in
//! some way the ACL does not capture: a file whose content was purged, a document re-classified
//! above the caller's ceiling. Dropping first is also cheaper than resolving rows that are about to
//! be discarded.
//!
//! # The drop counts are published from here, and only from here
//!
//! `plans/M3-DISCOVERY.md §6` requires the drop ratio as a metric. [`DropCounts`] is where that
//! number is produced, so [`confirm`](PostFilter::confirm) is where it is published — a second
//! tally assembled anywhere else would be the copy that eventually disagrees with this one, and the
//! disagreement would surface as a dashboard and a test that cannot both be right.
//!
//! Note that the *ratio* is still not computed twice. [`DropCounts::drop_ratio`] answers it in
//! process; the recording rule in `deploy/monitoring/alerts/search.yml` answers it at query time.
//! Both divide the same two counters, and neither is stored.

use enclave_core::{
    Action, AuthorizationService, FileAction, FileId, RequestContext, ResourceRef, Result,
};
use enclave_observability::metrics::search::PostFilterPass;
use sqlx::PgConnection;

use crate::error::SearchError;
use crate::excerpt::Excerpt;

/// One thing the index proposed.
///
/// Deliberately carries no permission field. The vector store's `acl_tokens` do not appear in this
/// type, and that is the point: a struct with a `visible: bool` on it is one somebody eventually
/// trusts.
///
/// [`Debug`] is hand-written and withholds the excerpt. See [`Confirmed`] for why.
#[derive(Clone, PartialEq)]
pub struct Candidate {
    /// The file the index believes matched.
    pub file_id: FileId,
    /// The index's own score, passed through untouched.
    pub score: f32,
    /// The quotation the index would show as an excerpt, if the caller may read content.
    ///
    /// Held here rather than fetched later because the index already has it; whether it is
    /// *disclosed* is decided below.
    ///
    /// One field, not two. `ENC-542` put the highlighting offsets *inside* [`Excerpt`] rather than
    /// beside it, so that withholding is one `None` and there is no second field to forget — see
    /// that type for the argument.
    pub excerpt: Option<Excerpt>,
}

/// One thing the caller may actually see.
///
/// [`Debug`] is hand-written and withholds the excerpt. See the impl for why.
#[derive(Clone, PartialEq)]
pub struct Confirmed {
    /// The file.
    pub file_id: FileId,
    /// The index's score.
    pub score: f32,
    /// The excerpt, present only if the caller may read the content.
    ///
    /// `None` here is not "the index had none" — it is also "you may know this exists and not read
    /// it". The two are deliberately indistinguishable to the caller: telling them apart would say
    /// *there is content here you may not see*, which is a fact about a document they cannot read.
    ///
    /// That is why the highlighting offsets `ENC-542` added live **inside** [`Excerpt`]. A
    /// `highlights` field beside this one would carry the distinction this `Option` refuses to make:
    /// a response with `excerpt: null` and offsets on it says there was a passage. There is no
    /// arrangement of this type that can disclose one without the other.
    pub excerpt: Option<Excerpt>,
}

/// An excerpt field, rendered without its contents.
///
/// `CLAUDE.md` rule 10: never log file content. An excerpt **is** file content — until `ENC-529`
/// only the Milvus path ever put any in a [`Candidate`], and the lexical path now does too, so the
/// hazard is on both. The realistic way it happens is not somebody printing a snippet on purpose; it
/// is `tracing::debug!(?candidates)` in an incident, and the derived `Debug` on the envelope types
/// (`LexicalCandidates`, `SearchResults`) reaching these through it.
///
/// Present-versus-absent is still shown, because that is what makes a `Debug` line worth reading and
/// it is not content. It says nothing a caller could not already determine: they are holding the
/// excerpt, or they are not.
///
/// [`Excerpt`]'s own `Debug` renders the same string, so this is now the outer of two defences
/// rather than the only one. Both are kept: this one is what protects these two fields whatever
/// [`Excerpt`] later grows, and that one is what protects every other place an excerpt can reach a
/// format string.
struct WithheldExcerpt<'a>(Option<&'a Excerpt>);

impl std::fmt::Debug for WithheldExcerpt<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => formatter.write_str("None"),
            Some(_) => formatter.write_str("Some(<content withheld>)"),
        }
    }
}

impl std::fmt::Debug for Candidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Candidate")
            .field("file_id", &self.file_id)
            .field("score", &self.score)
            .field("excerpt", &WithheldExcerpt(self.excerpt.as_ref()))
            .finish()
    }
}

impl std::fmt::Debug for Confirmed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Confirmed")
            .field("file_id", &self.file_id)
            .field("score", &self.score)
            .field("excerpt", &WithheldExcerpt(self.excerpt.as_ref()))
            .finish()
    }
}

/// What a post-filter pass discarded, for the metric the exit criteria require.
///
/// Exported so an operator can watch the drop ratio. A ratio that climbs means the index is drifting
/// more permissive than the ACLs — which is the post-filter working, and a signal that invalidation
/// is falling behind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DropCounts {
    /// Candidates the index proposed.
    pub proposed: usize,
    /// Dropped because the file is on the retrieval denylist.
    pub denylisted: usize,
    /// Dropped because the caller may not see the file at all.
    pub unauthorized: usize,
    /// Kept, but with the excerpt withheld because the caller may not read content.
    pub excerpt_withheld: usize,
}

impl DropCounts {
    /// How many survived.
    #[must_use]
    pub const fn confirmed(&self) -> usize {
        self.proposed - self.denylisted - self.unauthorized
    }

    /// The fraction discarded, as a ratio in `0.0..=1.0`.
    ///
    /// Zero candidates is a drop ratio of zero, not a division by zero: nothing was proposed, so
    /// nothing was wrongly proposed.
    #[must_use]
    pub fn drop_ratio(&self) -> f64 {
        if self.proposed == 0 {
            return 0.0;
        }
        let dropped = self.denylisted + self.unauthorized;
        dropped as f64 / self.proposed as f64
    }
}

/// The two actions every candidate is resolved against, in one pass.
///
/// Order matters only in that the results come back index-aligned with it; both are resolved
/// together. See the module documentation for why this is one call and not two.
const DISCLOSURE_ACTIONS: [Action; 2] =
    [Action::File(FileAction::MetadataRead), Action::File(FileAction::ContentRead)];

/// Confirms candidates against PostgreSQL.
#[derive(Debug, Clone, Copy)]
pub struct PostFilter;

impl PostFilter {
    /// Drops every candidate the caller may not see, and withholds every excerpt they may not read.
    ///
    /// Runs inside the caller's tenant-scoped transaction: the denylist read and the authorization
    /// resolution must see the same snapshot, or a revocation landing between them would be applied
    /// by one and not the other.
    ///
    /// # Errors
    ///
    /// Storage failures, and resolution failures — which are propagated rather than converted into
    /// an empty result. An outage that returned "no matches" would be a search that quietly claims
    /// the tenant has no such document, which is worse than one that fails.
    pub async fn confirm(
        conn: &mut PgConnection,
        authorization: &dyn AuthorizationService,
        ctx: &RequestContext,
        candidates: Vec<Candidate>,
    ) -> Result<(Vec<Confirmed>, DropCounts), SearchError> {
        let outcome = Self::resolve(conn, authorization, ctx, candidates).await;
        if let Ok((_, counts)) = &outcome {
            publish(*counts);
        }
        outcome
    }

    /// The pass itself. Split from [`PostFilter::confirm`] purely so that the metric has exactly one
    /// publication point.
    ///
    /// The alternative — a `publish` call beside each `Ok` below — offers three chances to forget
    /// one, and the one that gets forgotten is the early return taken when *everything* was
    /// denylisted. That is a 100% drop ratio: the single pass an operator most needs to see, missing
    /// from the metric precisely when invalidation is furthest behind.
    ///
    /// Nothing is published on the error path. A failed pass has no complete tally — `counts` stops
    /// wherever the failure was — and feeding a partial one to a ratio would move the ratio for a
    /// reason that has nothing to do with the index drifting.
    async fn resolve(
        conn: &mut PgConnection,
        authorization: &dyn AuthorizationService,
        ctx: &RequestContext,
        candidates: Vec<Candidate>,
    ) -> Result<(Vec<Confirmed>, DropCounts), SearchError> {
        let mut counts = DropCounts { proposed: candidates.len(), ..DropCounts::default() };
        if candidates.is_empty() {
            return Ok((Vec::new(), counts));
        }

        // Denylist first: cheaper than resolving rows that are about to be discarded, and it covers
        // the staleness the ACL does not (see the module documentation).
        let suppressed = crate::denylist::suppressed(
            conn,
            ctx.tenant_id,
            &candidates.iter().map(|candidate| candidate.file_id).collect::<Vec<_>>(),
        )
        .await?;

        let surviving: Vec<Candidate> = candidates
            .into_iter()
            .filter(|candidate| !suppressed.contains(&candidate.file_id))
            .collect();
        counts.denylisted = counts.proposed - surviving.len();

        if surviving.is_empty() {
            return Ok((Vec::new(), counts));
        }

        let resources: Vec<ResourceRef> = surviving
            .iter()
            .map(|candidate| ResourceRef::file(ctx.tenant_id, candidate.file_id))
            .collect();

        let grid = authorization
            .authorize_many_actions(ctx, &DISCLOSURE_ACTIONS, &resources)
            .await
            .map_err(SearchError::Resolution)?;

        // Index-aligned with `DISCLOSURE_ACTIONS`. A short outer vector leaves an action unanswered
        // and a short inner one leaves a candidate unanswered; both must drop the candidate rather
        // than admit it, which is what the `get`/`is_none_or` shape below does — an absent verdict
        // is never a grant.
        let metadata = grid.first();
        let content = grid.get(1);

        let mut confirmed = Vec::with_capacity(surviving.len());
        for (index, candidate) in surviving.into_iter().enumerate() {
            let may_see = metadata
                .and_then(|row| row.get(index))
                .is_some_and(enclave_core::StageDecision::is_allowed);
            if !may_see {
                counts.unauthorized += 1;
                continue;
            }

            let may_read = content
                .and_then(|row| row.get(index))
                .is_some_and(enclave_core::StageDecision::is_allowed);

            let excerpt = if may_read {
                candidate.excerpt
            } else {
                if candidate.excerpt.is_some() {
                    counts.excerpt_withheld += 1;
                }
                None
            };

            confirmed.push(Confirmed {
                file_id: candidate.file_id,
                score: candidate.score,
                excerpt,
            });
        }

        Ok((confirmed, counts))
    }
}

/// Publishes one completed pass to the process metric registry.
///
/// A field-by-field hand-off rather than a conversion, because `observability` sits below `search`
/// in the dependency graph and cannot name [`DropCounts`]. What crosses the boundary is four
/// tallies and nothing derived from them, so this remains a transport rather than a second
/// implementation of the drop ratio.
///
/// The `usize` to `u64` widening is lossless on every target this ships to, and a saturating cast
/// would be dishonest anyway: a candidate set that overflowed `u64` is not a metric problem.
fn publish(counts: DropCounts) {
    PostFilterPass {
        proposed: counts.proposed as u64,
        denylisted: counts.denylisted as u64,
        unauthorized: counts.unauthorized as u64,
        excerpt_withheld: counts.excerpt_withheld as u64,
    }
    .record();
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal, not a
    // production hazard. The workspace warns on these constructs for non-test code.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::sync::{Mutex, MutexGuard, PoisonError};

    use enclave_observability::metrics::search::{
        CANDIDATES_DROPPED_DENYLISTED, CANDIDATES_DROPPED_UNAUTHORIZED, CANDIDATES_PROPOSED,
        EXCERPTS_WITHHELD, POST_FILTER_PASSES,
    };

    use super::*;

    /// The instruments are process-global and the harness is threaded, so a test that reads one has
    /// to be the only test moving one.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every counter, in one read, so a test can assert on what did *not* move as cheaply as on
    /// what did.
    fn snapshot() -> [u64; 5] {
        [
            POST_FILTER_PASSES.value(),
            CANDIDATES_PROPOSED.value(),
            CANDIDATES_DROPPED_DENYLISTED.value(),
            CANDIDATES_DROPPED_UNAUTHORIZED.value(),
            EXCERPTS_WITHHELD.value(),
        ]
    }

    /// The document body used by the redaction tests. Distinctive enough that finding it anywhere
    /// in a formatted string is unambiguous.
    const BODY: &str = "the perihelion review procedure";

    /// Where in [`BODY`] the query matched — `perihelion`, at bytes 4..14.
    ///
    /// Written out rather than derived so that the assertion "this string does not appear in the
    /// rendering" has a literal to look for. It is the shape of the redacted thing, which is what
    /// `ENC-542` decided must not survive a `Debug` either.
    const OFFSETS: &str = "4..14";

    /// An excerpt of [`BODY`] carrying the offsets of the term that matched.
    fn located() -> Excerpt {
        assert_eq!(&BODY[4..14], "perihelion", "the fixture's offsets do not name a term");
        Excerpt::located(BODY.to_owned(), std::iter::once(4..14).collect())
            .expect("a well-formed span")
    }

    /// **`CLAUDE.md` rule 10, on the type that carries the content.** A candidate's `Debug` must not
    /// print the excerpt.
    ///
    /// The failure this prevents is not a deliberate one. It is `tracing::debug!(?candidates)` added
    /// during an incident: `LexicalCandidates` derives `Debug` over a `Vec<Candidate>`, so a single
    /// such line writes document bodies into the log aggregator — and search logs have a much
    /// broader audience than the documents they quote, which is the same argument `docs/06 §…` makes
    /// for keeping DLP match values out of incident records.
    #[test]
    fn a_candidates_debug_output_never_carries_the_excerpt() {
        let candidate =
            Candidate { file_id: FileId::new_v7(), score: 0.5, excerpt: Some(located()) };

        let rendered = format!("{candidate:?}");
        assert!(
            !rendered.contains(BODY),
            "a candidate's Debug printed document content: {rendered}"
        );
        assert!(
            rendered.contains("<content withheld>"),
            "the excerpt's presence must still be visible: {rendered}"
        );
        assert!(
            !rendered.contains(OFFSETS),
            "a candidate's Debug printed the highlighting offsets: {rendered}. They are derived \
             from the content — a span says a matched term of this length occurs at this position — \
             so printing them beside a redacted body gives back part of what the redaction removed"
        );

        // The envelope reaches it through a derived `Debug`, which is how it would actually happen.
        let batch = format!("{:?}", vec![candidate]);
        assert!(
            !batch.contains(BODY),
            "a Vec<Candidate>'s Debug printed document content: {batch}"
        );
    }

    /// The same, on the type that reaches an API layer.
    ///
    /// `SearchResults` derives `Debug` over a `Vec<Confirmed>`, so this is the one that a handler
    /// logging its own response would hit.
    #[test]
    fn a_confirmed_hits_debug_output_never_carries_the_excerpt() {
        let hit = Confirmed { file_id: FileId::new_v7(), score: 0.5, excerpt: Some(located()) };

        let rendered = format!("{hit:?}");
        assert!(!rendered.contains(BODY), "a hit's Debug printed document content: {rendered}");
        assert!(rendered.contains("<content withheld>"));
        assert!(
            !rendered.contains(OFFSETS),
            "a hit's Debug printed the highlighting offsets: {rendered}"
        );
    }

    /// **`ENC-542`.** Withholding an excerpt takes its offsets with it, because there is nowhere for
    /// them to be left behind.
    ///
    /// The property `Confirmed::excerpt` documents, asserted on the value rather than trusted to the
    /// field list: a hit whose excerpt was withheld renders exactly as one that never had an
    /// excerpt, offsets included. The regression this guards is the obvious next feature — a
    /// `highlights: Vec<Range<usize>>` field beside `excerpt`, which the post-filter would have to
    /// remember to clear, and which would say *there was a passage here* on the response the moment
    /// somebody forgot.
    ///
    /// The `located` control is what stops this passing against a type that dropped highlighting
    /// altogether.
    #[test]
    fn a_withheld_excerpt_is_indistinguishable_from_an_absent_one_offsets_included() {
        let file = FileId::new_v7();
        let withheld = Confirmed { file_id: file, score: 0.5, excerpt: None };
        let absent = Confirmed { file_id: file, score: 0.5, excerpt: None };
        let disclosed = Confirmed { file_id: file, score: 0.5, excerpt: Some(located()) };

        assert_eq!(withheld, absent, "the two meanings of `None` became distinguishable");
        assert_eq!(format!("{withheld:?}"), format!("{absent:?}"));
        assert_ne!(
            withheld, disclosed,
            "the control: an excerpt that *was* disclosed must differ, or this test holds against \
             a type that carries nothing"
        );
        assert!(matches!(
            disclosed.excerpt.as_ref().map(Excerpt::highlights),
            Some(crate::excerpt::Highlights::Terms(_))
        ));
    }

    /// An absent excerpt renders as `None`, so the redaction is not itself a signal.
    ///
    /// Worth asserting because the tempting implementation prints something like
    /// `<0 characters withheld>` for both cases, and a `Debug` that distinguishes "withheld" from
    /// "there was none" reintroduces at the log line exactly the distinction `Confirmed::excerpt`
    /// refuses to make in the response.
    #[test]
    fn an_absent_excerpt_renders_the_same_as_it_always_did() {
        let hit = Confirmed { file_id: FileId::new_v7(), score: 0.5, excerpt: None };
        assert!(format!("{hit:?}").contains("excerpt: None"), "{hit:?}");
    }

    #[test]
    fn every_tally_the_pass_produced_reaches_the_metric_it_belongs_to() {
        let _guard = serial();
        let before = snapshot();

        publish(DropCounts { proposed: 30, denylisted: 4, unauthorized: 6, excerpt_withheld: 2 });

        let after = snapshot();
        assert_eq!(
            [
                after[0] - before[0],
                after[1] - before[1],
                after[2] - before[2],
                after[3] - before[3],
                after[4] - before[4]
            ],
            [1, 30, 4, 6, 2],
            "each tally must land on its own counter; a swapped pair reads as the wrong runbook"
        );
    }

    #[test]
    fn a_pass_that_dropped_nothing_still_reports_that_it_ran() {
        // The zero case is the one the "drop ratio at zero" alert reads. If a clean pass published
        // nothing, the ratio would be computed over the drops of the *unclean* passes alone and
        // could never fall to zero — the alert would be structurally incapable of firing.
        let _guard = serial();
        let before = snapshot();

        publish(DropCounts { proposed: 20, denylisted: 0, unauthorized: 0, excerpt_withheld: 0 });

        let after = snapshot();
        assert_eq!(after[0], before[0] + 1, "the pass must be counted");
        assert_eq!(after[1], before[1] + 20, "the denominator must move");
        assert_eq!(after[2], before[2], "nothing was denylisted");
        assert_eq!(after[3], before[3], "nothing was unauthorized");
    }

    #[test]
    fn an_empty_candidate_set_moves_the_pass_counter_and_nothing_else() {
        // `confirm` returns early on an empty candidate set, and this is the tally it returns.
        // Publishing it keeps "the post-filter ran" true for a query that matched nothing, which is
        // what separates a quiet system from one that stopped post-filtering.
        let _guard = serial();
        let before = snapshot();

        publish(DropCounts::default());

        let after = snapshot();
        assert_eq!(after[0], before[0] + 1);
        assert_eq!(&after[1..], &before[1..], "no candidates means no candidate counts");
    }

    #[test]
    fn the_published_counters_agree_with_the_ratio_the_pass_computed() {
        // `DropCounts::drop_ratio` is the in-process implementation and the recording rule in
        // deploy/monitoring/alerts/search.yml is the query-time one. They are only allowed to be
        // two implementations of one number if they divide the same two numbers.
        let _guard = serial();
        let counts =
            DropCounts { proposed: 40, denylisted: 3, unauthorized: 5, excerpt_withheld: 7 };
        let before = snapshot();

        publish(counts);

        let after = snapshot();
        let proposed = after[1] - before[1];
        let dropped = (after[2] - before[2]) + (after[3] - before[3]);
        let ratio = dropped as f64 / proposed as f64;
        assert!(
            (ratio - counts.drop_ratio()).abs() < 1e-9,
            "metric ratio {ratio} disagrees with DropCounts::drop_ratio {}",
            counts.drop_ratio()
        );
    }

    #[test]
    fn a_withheld_excerpt_is_reported_but_is_not_a_drop() {
        // `DropCounts::confirmed` does not subtract it, and neither may the ratio: a hit the caller
        // can see without its snippet was disclosed, not discarded.
        let _guard = serial();
        let counts =
            DropCounts { proposed: 10, denylisted: 0, unauthorized: 0, excerpt_withheld: 10 };
        assert_eq!(counts.confirmed(), 10);
        assert!((counts.drop_ratio() - 0.0).abs() < f64::EPSILON);

        let before = snapshot();
        publish(counts);
        let after = snapshot();

        assert_eq!(after[4], before[4] + 10, "the withheld excerpts must still be visible");
        assert_eq!(after[2], before[2]);
        assert_eq!(after[3], before[3], "and must not move either drop counter");
    }
}
