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

use enclave_core::{
    Action, AuthorizationService, FileAction, FileId, RequestContext, ResourceRef, Result,
};
use sqlx::PgConnection;

use crate::error::SearchError;

/// One thing the index proposed.
///
/// Deliberately carries no permission field. The vector store's `acl_tokens` do not appear in this
/// type, and that is the point: a struct with a `visible: bool` on it is one somebody eventually
/// trusts.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// The file the index believes matched.
    pub file_id: FileId,
    /// The index's own score, passed through untouched.
    pub score: f32,
    /// The text the index would show as an excerpt, if the caller may read content.
    ///
    /// Held here rather than fetched later because the index already has it; whether it is
    /// *disclosed* is decided below.
    pub excerpt: Option<String>,
}

/// One thing the caller may actually see.
#[derive(Debug, Clone, PartialEq)]
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
    pub excerpt: Option<String>,
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
