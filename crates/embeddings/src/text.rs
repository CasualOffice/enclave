//! The type that carries the text, and the one comparison that decides where it may go.
//!
//! `plans/M3-DISCOVERY.md` D23: *"the routing lives in the type that carries the text, not in the
//! caller's choice of client."* This module is that sentence.
//!
//! # The mechanism, stated as a claim that can be checked
//!
//! [`ClassifiedText`] holds the chunks and the rank of the content they came from, and **has no
//! method that returns the chunks**. The only two functions in this workspace that read its
//! `chunks` field are [`TextBatch::<Local>::admit`] and [`TextBatch::<Remote>::admit`], both defined
//! below, because the field is private and this module is the only one that can name it.
//!
//! [`TextBatch::<Remote>::admit`] returns `Err` at or above the ceiling. So:
//!
//! > `EmbeddingProvider<Remote>::embed` takes a `TextBatch<Remote>`. A `TextBatch<Remote>` can only
//! > come from `TextBatch::<Remote>::admit`. That function compares the rank against the ceiling
//! > before it constructs one. Therefore holding a `TextBatch<Remote>` *is* the proof that the text
//! > it carries was below the ceiling — and no code anywhere, in this crate or a future one, can
//! > call a remote provider without first holding that proof.
//!
//! That is the difference from the obvious design, where the router compares the rank and then
//! calls the right client. Under the obvious design the comparison protects the call sites that
//! existed when it was written. Under this one it protects the call site added at 3am by someone
//! whose local provider is timing out, because that call site cannot be compiled without going
//! through the comparison, and the comparison hands them `Err` for the text they were trying to
//! route.
//!
//! It is also why the router below contains no `if rank >= ceiling`. There is exactly one such
//! comparison in the crate, and it is [`TextBatch::<Remote>::admit`].
//!
//! # What this does not claim
//!
//! Being precise about the boundary is the point of having one.
//!
//! * A caller holding a `TextBatch<Local>` can read its texts, build a fresh [`ClassifiedText`]
//!   around them with a lower rank, and admit *that* to a remote provider. Nothing here prevents
//!   it. That is not the failure mode D23 is about: it is not a retry, it is not a helpful
//!   fallback, and it is not four lines that look like error handling — it is a deliberate
//!   re-labelling of restricted content as public, three lines long and unmistakable in review.
//!   The guarantee is that the *accidental* path is closed, and it is closed completely.
//! * The rank is only as good as its source. `ClassifiedText::new` is where a rank is attached, and
//!   indexing must attach the file's effective classification — the label after the classification
//!   stage has run, not the one on the upload. A truthful ceiling applied to a false rank routes
//!   confidently to the wrong place.
//!
//! # No content in a log line
//!
//! `CLAUDE.md` rule 10: file content is never logged. Both types here hold extracted document text,
//! which is the most content-shaped thing in the product, so both have hand-written [`Debug`] impls
//! that print the rank and a chunk count and nothing else. A derive here would put whole documents
//! into any `tracing` line that captured a batch — and the lines most likely to capture one are the
//! error paths, which are the lines most likely to be turned up to `debug` during an incident.

use core::fmt;
use core::marker::PhantomData;

use enclave_core::ClassificationRank;

use crate::locality::{Local, Locality, Remote};

/// Text to embed, inseparable from the classification of the content it was extracted from.
///
/// The two travel together because separating them is how they come to disagree. A function taking
/// `(rank, texts)` has two arguments that can be passed from different places, and a pipeline that
/// carries text in one variable and its label in another has a stage where only one of them was
/// updated.
///
/// One chunk or many: a batch shares a rank because it comes from one version of one file
/// (`docs/07 §2.2`). Mixing ranks in a batch would mean the batch's routing is the routing of its
/// most sensitive member, which is a rule this type would then have to enforce; carrying a single
/// rank makes that rule unstatable instead.
pub struct ClassifiedText {
    rank: ClassificationRank,
    chunks: Vec<String>,
}

impl ClassifiedText {
    /// Attaches a rank to extracted chunks.
    ///
    /// The rank must be the resource's *effective* classification — after the classification stage
    /// of the pipeline has run and possibly raised it (`docs/07 §2`), never the label the uploader
    /// declared. Everything below is a faithful consequence of this number, and nothing below can
    /// detect that it is wrong.
    #[must_use]
    pub const fn new(rank: ClassificationRank, chunks: Vec<String>) -> Self {
        Self { rank, chunks }
    }

    /// What this text is classified as.
    #[must_use]
    pub const fn rank(&self) -> ClassificationRank {
        self.rank
    }

    /// How many chunks are waiting to be embedded.
    ///
    /// Exposed because the router checks it against the number of vectors that come back — a
    /// provider that returns fewer is a document that is partially indexed and looks whole.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Whether there is anything to embed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

impl fmt::Debug for ClassifiedText {
    /// Rank and shape, never text. See the module documentation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClassifiedText")
            .field("rank", &self.rank)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

/// The rank at and above which text must stay on local compute.
///
/// A configured value rather than a constant, because the ranks themselves are tenant-defined —
/// `enclave_core::ClassificationRank` exists as a rank and not a label for exactly that reason, and
/// one deployment's `RESTRICTED` is another's fourth tier of five. `docs/07 §2.3` describes the
/// default mapping; this is where a deployment writes down which rank it means.
///
/// Tightening it is always safe and always available: a lower ceiling moves *more* text onto local
/// compute, and moving text local is never a refusal — the local provider embeds every rank
/// (`TextBatch::<Local>::admit` is infallible). An operator who has just had a scare can set
/// [`LocalCeiling::EVERYTHING`] and keep indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalCeiling(ClassificationRank);

impl LocalCeiling {
    /// Nothing may leave local compute, whatever its classification.
    ///
    /// The air-gapped and BYO-nothing setting of `docs/08 §18`, and the value
    /// [`EmbeddingRouter::air_gapped`](crate::EmbeddingRouter::air_gapped) wires in. It is
    /// `i32::MIN` rather than a flag on the router because a flag is a second thing to consult:
    /// with the ceiling at the bottom of the rank space, every rank is "at or above" it and the
    /// ordinary comparison already produces the ordinary answer. There is no air-gapped code path.
    pub const EVERYTHING: Self = Self(ClassificationRank::new(i32::MIN));

    /// The ceiling a deployment configured.
    #[must_use]
    pub const fn at(rank: ClassificationRank) -> Self {
        Self(rank)
    }

    /// The rank this ceiling sits at, for configuration surfaces and audit.
    #[must_use]
    pub const fn rank(self) -> ClassificationRank {
        self.0
    }

    /// Whether text of this rank is permitted to leave local compute.
    ///
    /// Public because an admin screen showing "where will this tenant's `CONFIDENTIAL` content be
    /// embedded?" needs to ask, and because a metric wants to label the answer. Asking it does not
    /// get anybody any closer to a remote provider: the answer is a `bool`, and a `bool` is not a
    /// [`TextBatch<Remote>`].
    #[must_use]
    pub const fn permits_remote(self, rank: ClassificationRank) -> bool {
        rank.get() < self.0.get()
    }
}

/// Text that has been admitted to a locality, and the only thing a provider will accept.
///
/// The type parameter is the whole point — see the module documentation and [`crate::locality`].
/// There is no constructor other than the two `admit` functions, no way to change `L` on a batch
/// that already exists, and no `From` between the two instantiations.
///
/// # The two admissions are deliberately asymmetric
///
/// ```
/// # use enclave_core::ClassificationRank;
/// # use enclave_embeddings::{ClassifiedText, LocalCeiling, Local, Remote, TextBatch};
/// let restricted = ClassifiedText::new(ClassificationRank::new(40), vec!["…".to_owned()]);
/// let ceiling = LocalCeiling::at(ClassificationRank::new(40));
///
/// // Remote admission can fail, and here it does.
/// let restricted = TextBatch::<Remote>::admit(restricted, ceiling)
///     .expect_err("at the ceiling, text stays local");
///
/// // Local admission cannot fail. There is no rank a local model may not see.
/// let _local: TextBatch<Local> = TextBatch::<Local>::admit(restricted);
/// ```
///
/// One returns `Self` and the other returns a `Result`, and that shape *is* the security property:
/// the fallible direction is the one that leaves the tenant's network.
///
/// # There is no way around it
///
/// No constructor that skips the ceiling:
///
/// ```compile_fail,E0599
/// # use enclave_core::ClassificationRank;
/// # use enclave_embeddings::{ClassifiedText, Remote, TextBatch};
/// let restricted = ClassifiedText::new(ClassificationRank::new(40), vec!["…".to_owned()]);
/// let batch: TextBatch<Remote> = TextBatch::new(restricted);
/// ```
///
/// and no way to read the text out of a [`ClassifiedText`] and hand it over directly:
///
/// ```compile_fail,E0616
/// # use enclave_core::ClassificationRank;
/// # use enclave_embeddings::ClassifiedText;
/// let restricted = ClassifiedText::new(ClassificationRank::new(40), vec!["…".to_owned()]);
/// let texts = restricted.chunks;
/// ```
pub struct TextBatch<L: Locality> {
    rank: ClassificationRank,
    chunks: Vec<String>,
    locality: PhantomData<L>,
}

impl TextBatch<Local> {
    /// Admits text to local compute. Always succeeds.
    ///
    /// Infallible because there is no rank a model running on the tenant's own hardware may not
    /// see, and because a fallible local admission would give the above-ceiling path an error to
    /// handle — which is the one place in this crate where "handle" could plausibly be spelled
    /// "try the other provider".
    ///
    /// `NO_INDEX` content (`docs/07 §2.3`) never gets here: it is not extracted, not chunked and
    /// not offered for embedding. That decision belongs to indexing, which knows the library's
    /// `ai_indexing_enabled` and the label's policy; this crate is not asked, and cannot tell the
    /// difference between text it should not have been given and text it should.
    #[must_use]
    pub fn admit(text: ClassifiedText) -> Self {
        Self { rank: text.rank, chunks: text.chunks, locality: PhantomData }
    }
}

impl TextBatch<Remote> {
    /// Admits text to a provider outside the tenant's network, or refuses and gives it back.
    ///
    /// **This is the S8 enforcement point, and it is the only one.** Every route to a remote
    /// provider passes through this comparison, because a `TextBatch<Remote>` is what
    /// `EmbeddingProvider<Remote>::embed` takes and this function is the only thing that makes one.
    ///
    /// # Errors
    ///
    /// `Err` carries the text back unchanged when its rank is at or above the ceiling, so the
    /// caller can route it locally without cloning a document's worth of strings — and so that the
    /// refusal is impossible to write as a silent drop. `Err(text)` is not an outcome you can
    /// discard and continue from; it is the text, still needing an embedding, still in your hand.
    ///
    /// *At* the ceiling, not merely above it: the configured rank is the first rank that must stay
    /// local. `docs/07 §2.3` maps `RESTRICTED -> LOCAL_ONLY`, so a ceiling naming `RESTRICTED` must
    /// keep `RESTRICTED` local, and an exclusive comparison here would send exactly the label S8
    /// names to a hosted endpoint.
    pub fn admit(text: ClassifiedText, ceiling: LocalCeiling) -> Result<Self, ClassifiedText> {
        if ceiling.permits_remote(text.rank) {
            Ok(Self { rank: text.rank, chunks: text.chunks, locality: PhantomData })
        } else {
            Err(text)
        }
    }
}

impl<L: Locality> TextBatch<L> {
    /// The chunks to embed, in order.
    ///
    /// The order is the contract: the provider returns one vector per string, positionally, and the
    /// router checks the count. A provider that reorders or coalesces produces vectors attached to
    /// the wrong chunk coordinates, which surfaces as a search result deep-linking to the wrong
    /// page rather than as an error.
    #[must_use]
    pub fn texts(&self) -> &[String] {
        &self.chunks
    }

    /// What this batch is classified as.
    ///
    /// Carried past admission so a provider can label a metric or an audit line with it. Not so it
    /// can re-check: by the time a provider holds a batch, the check has happened, and a provider
    /// that repeated it would be a second copy of the rule to keep in step with this one.
    #[must_use]
    pub const fn rank(&self) -> ClassificationRank {
        self.rank
    }

    /// How many vectors this batch must produce.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Whether there is anything to embed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

impl<L: Locality> fmt::Debug for TextBatch<L> {
    /// Locality, rank and shape, never text. See the module documentation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TextBatch")
            .field("locality", &L::LABEL)
            .field("rank", &self.rank)
            .field("chunks", &self.chunks.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    const RESTRICTED: ClassificationRank = ClassificationRank::new(40);
    const CONFIDENTIAL: ClassificationRank = ClassificationRank::new(30);

    fn text(rank: ClassificationRank) -> ClassifiedText {
        ClassifiedText::new(rank, vec!["a paragraph".to_owned()])
    }

    #[test]
    fn the_ceiling_rank_itself_stays_local() {
        // The off-by-one that would defeat S8 entirely. `docs/07 §2.3` maps `RESTRICTED` to
        // `LOCAL_ONLY`, so a ceiling naming `RESTRICTED` must keep `RESTRICTED` local; an exclusive
        // comparison would send precisely the label the exit criterion names to a hosted endpoint,
        // and every test using a rank one above the ceiling would still pass.
        let ceiling = LocalCeiling::at(RESTRICTED);
        assert!(TextBatch::<Remote>::admit(text(RESTRICTED), ceiling).is_err());
        assert!(TextBatch::<Remote>::admit(text(ClassificationRank::new(41)), ceiling).is_err());
        assert!(TextBatch::<Remote>::admit(text(CONFIDENTIAL), ceiling).is_ok());
    }

    #[test]
    fn a_refusal_hands_the_text_back_rather_than_consuming_it() {
        // So the above-ceiling path can route locally without cloning a document, and so the
        // refusal cannot be written as `let _ = admit(...)` and forgotten: the `Err` *is* the text,
        // still unembedded.
        let ceiling = LocalCeiling::at(RESTRICTED);
        let returned = TextBatch::<Remote>::admit(text(RESTRICTED), ceiling)
            .expect_err("at the ceiling this must refuse");
        assert_eq!(returned.rank(), RESTRICTED);
        assert_eq!(returned.chunk_count(), 1);
    }

    #[test]
    fn the_air_gapped_ceiling_refuses_the_least_sensitive_rank_there_is() {
        // `EVERYTHING` has to hold at the bottom of the rank space, not just for realistic labels:
        // an air-gapped install that leaked its `PUBLIC` chunks to a hosted endpoint would have
        // leaked its document *count*, its chunk sizes and its language — and would have made a
        // network call from a network that is supposed to have none.
        for rank in [i32::MIN, i32::MIN + 1, 0, 10] {
            let admitted = TextBatch::<Remote>::admit(
                text(ClassificationRank::new(rank)),
                LocalCeiling::EVERYTHING,
            );
            assert!(admitted.is_err(), "rank {rank} escaped an air-gapped deployment");
        }
    }

    #[test]
    fn local_admission_accepts_every_rank() {
        // The property the no-fallback rule rests on: moving text local is never a refusal, so
        // tightening the ceiling costs recall or latency and never correctness.
        for rank in [i32::MIN, 0, 40, i32::MAX] {
            let batch = TextBatch::<Local>::admit(text(ClassificationRank::new(rank)));
            assert_eq!(batch.chunk_count(), 1);
        }
    }

    #[test]
    fn neither_carrier_can_put_document_text_in_a_log_line() {
        // Rule 10. The most content-shaped values in the product, on the paths most likely to be
        // turned up to `debug` during an incident.
        let secret = "the merger closes on Tuesday";
        let classified = ClassifiedText::new(RESTRICTED, vec![secret.to_owned()]);
        assert!(!format!("{classified:?}").contains(secret));

        let batch = TextBatch::<Local>::admit(classified);
        let rendered = format!("{batch:?}");
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("local"), "the locality is the useful half: {rendered}");
    }
}
