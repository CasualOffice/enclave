//! What a quotation from a document may look like.
//!
//! `ENC-529`. `ENC-515` put document text in PostgreSQL and deliberately did **not** cut an excerpt
//! from it, because there was no answer yet to the question in the title, and a snippet assembled
//! from the wrong source is a worse defect than no snippet at all: an empty one is a visible gap, a
//! wrong one is an invisible one.
//!
//! # The rule
//!
//! > An excerpt is a **verbatim, contiguous substring of the indexed text of one chunk**, containing
//! > at least one term the query matched on, cut at word boundaries, bounded in length, and marked
//! > with `…` at whichever end text was elided. If the matched term cannot be located in that chunk
//! > by the same rule the index matched on, **there is no excerpt**.
//!
//! Everything below is that sentence, and the reasons each clause is in it.
//!
//! # `ENC-538`: the same rule where there is no term to centre on
//!
//! The rule above was written for the lexical path, and the dense path cannot obey the middle
//! clause. A chunk retrieved by embedding similarity has **no matched span**: the caller may not
//! have typed a word that occurs in it at all, and finding documents that do not contain the words
//! you typed is the entire reason the dense path exists. [`quote`] would return [`None`] for every
//! dense hit, and [`crate::vector::VectorQuery`] carries no query text to hand it in the first
//! place.
//!
//! What stood there before `ENC-538` was not an answer to that, it was the absence of one:
//! `crate::milvus`'s decoder passed Milvus's `text` field through untouched, so the same document
//! was quoted at up to 3 200 characters when the store was healthy and at 240 when it was not. The
//! caller-visible half of that inconsistency is the *size*, and size has nothing to do with
//! anchoring — it was the decoder not cutting.
//!
//! So the rule splits in exactly one place:
//!
//! > On the dense path an excerpt is the **head** of the matched chunk, under the same budget, the
//! > same word boundaries and the same elision marks. Every property a caller can check of it is a
//! > property [`quote`] also has; the only difference is which window, because only one of the two
//! > paths has an anchor with which to choose one.
//!
//! [`preview`] is that, and it is built from the same [`tokenize`], the same [`render`] and the same
//! [`MAX_CHARS`] rather than restating any of them — so the shape guarantees are one implementation
//! and not two that happen to agree today.
//!
//! ## Why a head cut is not the failure `ts_headline` has
//!
//! It reads like the same defect — "return the opening words when you cannot find the term" is
//! precisely what the section below refuses — and it is not the same thing, so be exact about the
//! difference.
//!
//! Raw-text `ts_headline` returns the opening of the **document** when the match was elsewhere in
//! it: a window *outside* the matched span, presented as the matched span. Here the matched unit
//! **is the chunk**. The embedding was computed over the whole of it and the whole of it is what
//! scored, so there is no narrower true span for a head cut to miss, and every window inside the
//! chunk is inside the match. The head is not a guess about where the match is; it is what the match
//! having no narrower location looks like when you have to show 240 characters of it.
//!
//! That is also the test of whether it may be shown at all. What `ENC-529` refuses is *claiming* a
//! span that did not match. A dense excerpt claims a chunk that did.
//!
//! ## Why not locate the query's words where they happen to appear
//!
//! This is the tempting middle option: run [`quote`] against the query text, fall back to the head
//! when it finds nothing. It was rejected for two reasons, the second larger than the first.
//!
//! It would mean adding the query string to [`crate::vector::VectorQuery`], which today carries an
//! embedding and no text — a field added for excerpting, sitting on the type whose documentation is
//! about what a pre-filter may narrow on.
//!
//! And it would make the meaning of an excerpt depend on an accident. Sometimes the caller would
//! hold "here is a passage containing a word you typed" and sometimes "here is the top of the
//! passage that matched", with nothing in the response saying which — the same class of defect as
//! `ts_headline` returning a real highlight and a document opening through one field. Worse, it is
//! backwards: dense retrieval earns its keep on queries whose words are *not* in the document, so a
//! rule that quotes the typed word wherever it occurs produces its best excerpts exactly where the
//! dense path added least, and its worst where it added most.
//!
//! One rule per path, and each path's rule stated. Two rules through one field, chosen per result by
//! whether a word happened to occur, is not a contract.
//!
//! ## Why not the whole chunk with the contract made explicit
//!
//! [`MAX_CHARS`]'s own argument is unchanged by anything here: twenty results of 3 200 characters is
//! 64 KB of document body in a response where 5 KB says the same. And it would keep the property the
//! row objects to — the size of a result depending on which path answered — while relabelling it a
//! contract. Writing an inconsistency down does not make a caller sizing a response able to act on
//! it any better than they could before.
//!
//! ## Why not nothing at all
//!
//! The argument for it is real: an excerpt implies *this is why it matched*, and a dense match
//! cannot honour that at the granularity a quotation implies. Two things weigh against it.
//!
//! It would make a **healthy** search return strictly less than a degraded one. `plans/M3-DISCOVERY`
//! D25 is that degraded mode is a worse recall guarantee and never a worse anything-else; a
//! disclosure that arrives only when Milvus is down inverts the relationship the flag exists to
//! describe, and the first bug report is "search shows snippets during outages".
//!
//! And the premise over-claims. `docs/05-API.md §11` describes the field as a snippet of the
//! document, and a chunk *is* why a dense hit matched. What a dense excerpt cannot say is *which
//! sentence*, which is a smaller claim to give up than the whole field.
//!
//! ## What is given up, said here rather than discovered later
//!
//! **No offsets, so no highlighting.** `ENC-542` carried them on the lexical path — see the section
//! below. There are none *here*, on the dense path: nothing matched at a position, so `docs/05
//! §11`'s `<em>` is a lexical-path property. A dense excerpt arrives unmarked, and
//! [`Highlights::Unlocated`] is that stated in the type rather than left to be inferred from an
//! empty list.
//!
//! **The head of a chunk can be a heading, a caption or boilerplate.** It is bounded and it is
//! honestly what it says it is, and it is not always the sentence a reader would have picked. Doing
//! better means scoring the chunk's sentences against the query embedding, which is a second
//! retrieval per hit; that is worth measuring, and it is not worth guessing at now.
//!
//! ## What did not change, and must not
//!
//! An excerpt is content. It is released only where every other disclosure is decided —
//! [`crate::PostFilter::confirm`] resolving `ContentRead` (`CLAUDE.md` rule 5) — and this module is
//! not consulted about that on either path. [`preview`] returns an [`Option`] whose [`None`] (an
//! empty or whitespace-only chunk) is the same value the withheld case produces, so "there was no
//! excerpt" and "you may not read the content" remain indistinguishable, as
//! [`crate::Confirmed::excerpt`] requires — and `ENC-542`'s offsets are inside that [`Option`],
//! never beside it, so nothing was added that could tell the two apart. The hand-written
//! [`std::fmt::Debug`] on
//! [`crate::Candidate`] and [`crate::Confirmed`] still renders `Some(<content withheld>)` and still
//! renders an absent excerpt as `None` (`docs/12 §4` S11).
//!
//! # Why not `ts_headline`, on either expression
//!
//! `ts_headline` is the obvious answer and both of its forms are wrong here, in different ways.
//!
//! Over the **normalized** expression — `regexp_replace(text, '[^[:alnum:]]+', ' ', 'g')`, the one
//! migrations 0012 and 0013 index — it highlights the right span, because that is the string the
//! match was actually computed over. What it returns is `Clause 7 2 sets out…`: the punctuation
//! stripped form, which is not a sentence any document contains. Quoting a contract inaccurately is
//! not a cosmetic defect. A clause number is *made of* the punctuation, and a caller who reads
//! `Clause 7 2` and searches the document for it finds nothing.
//!
//! Over the **raw** text it returns real sentences, and it is a second tokenization. PostgreSQL's
//! default parser reads `clause-7.2(b)` as one indivisible `file`-class token, which is precisely
//! why migration 0012 folds punctuation to spaces before indexing — so a `tsquery` term of `clause`,
//! which matched the *normalized* text, does not match the *raw* text's token. `ts_headline` then
//! finds nothing to highlight and, rather than saying so, returns **the opening words of the
//! document**. That output is indistinguishable from a real highlight. A caller is handed the first
//! sentence of a file, presented as the passage that matched their query, with nothing anywhere
//! reporting an error.
//!
//! That asymmetry is the whole design: the failure mode of the approach below is an **absent**
//! excerpt, and the failure mode of raw-text `ts_headline` is a **plausible wrong** one.
//!
//! # Why the locator here is not a third tokenization
//!
//! It is the same rule, restated, and the rule is small enough to state in one line. The indexed
//! expression is `to_tsvector('simple', regexp_replace(text, '[^[:alnum:]]+', ' ', 'g'))`. After
//! that `regexp_replace` the parser is handed nothing but maximal runs of `[[:alnum:]]` separated by
//! spaces, and the `simple` dictionary lowercases a token and keeps it — no stemming, no stopwords,
//! no synonyms (that is exactly why migration 0012 chose `simple`, and its reasoning is worth
//! re-reading). So:
//!
//! > a term of the query is the lowercase of a maximal alphanumeric run, and a match is equality
//! > between such a run in the query and such a run in the text.
//!
//! [`terms`] and [`tokenize`] implement that and nothing else. The query side is the *user's query
//! string*, tokenized by the same function — not a `tsquery` parsed back out of PostgreSQL, which
//! would be a genuinely different thing.
//!
//! # Where it can still disagree with PostgreSQL, and what happens then
//!
//! Two places. `char::is_alphanumeric` is Unicode's answer and `[[:alnum:]]` is the database
//! collation's, and they can differ at the margins. And the default parser may subdivide an
//! alphanumeric run this module treats as one token.
//!
//! Both are handled by the same property rather than by hoping they do not happen: this module only
//! ever returns a span it located, so a disagreement yields [`None`] — the caller gets the hit with
//! no excerpt, which is the pre-`ENC-529` behaviour and is already indistinguishable from an excerpt
//! withheld for want of `ContentRead`. It fails closed and it fails to the *same value* the security
//! property already produces, which is why the disagreement cannot become a disclosure.
//!
//! It can never quote a span that did not match: the chunk was selected by `@@` against the query,
//! and the returned window is required to contain a run equal to one of the query's runs.
//!
//! # Word boundaries, and no sentence boundaries
//!
//! The window is snapped outward to token boundaries so a quotation does not begin or end mid-word.
//! It is deliberately **not** snapped to sentence boundaries: finding a sentence end requires
//! knowing the language — `。` in Japanese, no full stop at all in Thai, and `Nr.` in German is not
//! a sentence end — and `docs/14-I18N-L10N.md` has tenants in many languages. That is the same
//! argument migration 0012 makes for choosing `simple` over a stemmer, and it lands the same way: a
//! wrong guess about language fails silently.
//!
//! # `…` is the one character that is not from the document
//!
//! A fragment presented as if it were whole misrepresents a document too. So elision is marked, with
//! U+2026, at whichever end text was dropped — matching `docs/05-API.md §11`'s response shape. It is
//! not alphanumeric, so it can never be mistaken for a token of the quoted text, and it is added
//! only at the ends: the body between the marks is byte-for-byte from the chunk.
//!
//! No markup is produced. `docs/05`'s example wraps the matched term in `<em>`; emitting that here
//! would mean interpolating untrusted document content into a markup string in the crate furthest
//! from any renderer, which is how stored XSS is delivered (`docs/12 §4.2` A9 is the same defect on
//! the watermark path). Highlighting is the API layer's, from the offsets the next section carries.
//!
//! # `ENC-542`: the offsets, and why they are inside the excerpt rather than beside it
//!
//! `docs/05 §11` shows `<em>` on an excerpt and retrieval returns plain text, so something has to
//! carry *where the match is*. The alternative to carrying it is the API layer re-locating the
//! query's terms in the excerpt — a **third** tokenization of document content, in the crate that
//! also builds the markup string, and the section above is the argument for why a second one was
//! already wrong. So [`quote`] hands on what it already knows: [`Highlights::Terms`], the byte spans
//! of the returned string that hold a term of the query.
//!
//! They ride **inside** [`Excerpt`], and that placement is the security property rather than
//! ergonomics. [`crate::Confirmed::excerpt`] is an [`Option`] whose [`None`] means *there was no
//! excerpt* and *you may not read the content* at once, and the two must stay indistinguishable
//! (`docs/12 §4.3` S6). A `highlights` field next to it breaks that on the first response where an
//! excerpt is withheld: `excerpt: null` with offsets beside it says *there is a passage here you may
//! not see*. Inside the value there is no such response to write, and the post-filter withholds both
//! with the one `None` it already writes.
//!
//! Offsets are also withheld from [`std::fmt::Debug`], on both [`Excerpt`] and [`Highlights`]. They
//! are derived from the content — a span says a matched term of this length occurs at this position,
//! and their number says how often the query's words occur in the passage — so printing them beside
//! a redacted body hands back part of what the redaction removed (`docs/12 §4.3` S11).
//!
//! # Bidi: an excerpt is a fragment, and a fragment's directional state can be unbalanced
//!
//! A document may open a right-to-left override with U+202E and close it a page later. Both are
//! ordinary text and the document is balanced. Cut a 240-character window out of the middle and the
//! quotation is **not**: the override is open and never closed, and it reverses everything after it
//! — which, in a list of search results, is the surrounding interface and not only the snippet.
//! Nothing above prevents this, because every clause above is about quoting the document faithfully
//! and an unbalanced control is what a faithful quotation of that passage contains.
//!
//! The remedy is at the renderer — `unicode-bidi: isolate`, or a `<bdi>` element, which confines the
//! embedding level to the element and is `docs/14-I18N-L10N.md §7`'s existing rule for file names
//! mixing scripts. It is **not** stripping the characters here, for the reason the whole module
//! exists: the body between the elision marks is the document's own text, character for character,
//! and a caller who searches the file for what they were shown has to find it. Direction marks can
//! be load-bearing in the source, and an excerpt quietly missing one is a wrong quotation of a
//! document — the invisible failure this module is arranged against, arriving through the fix.
//!
//! `a_directional_control_is_quoted_verbatim_rather_than_stripped` pins it from this side, so a
//! later sanitizer added here fails rather than silently trading one defect for another. There is no
//! `web/` yet (`docs/01 §37`: the frontend starts at M5), so the other half is written down where
//! the renderer will read it rather than implemented against a component that does not exist.
//!
//! # What is quoted is what matched, including when that is not the current version
//!
//! `chunk_text` holds the text of the version that was **last indexed**, which is not always the
//! current one. The excerpt is cut from that text, so a document at version 4 whose index still
//! holds version 3 is quoted from version 3 — the text that actually caused the hit. Quoting version
//! 4 instead would show a caller a passage that had nothing to do with their query.
//!
//! This is not a disclosure question. Whether a caller may see any of it is settled after this
//! module runs, by [`crate::PostFilter`] resolving `ContentRead`, and a file whose content has been
//! purged or reclassified is dropped by the denylist before resolution ever happens.
//!
//! # Why the module is public and the cutters are not
//!
//! The rule above is a product decision and belongs where somebody can find it, so the module is
//! `pub`. [`MAX_CHARS`] is the one figure a caller sizing a response needs, and [`Excerpt`] and
//! [`Highlights`] are what an excerpt *is* — the API layer holds them and a candidate generator
//! outside this crate produces them. `quote` and `preview` stay crate-private: their input is raw
//! chunk text, and a public function taking document content and returning document content is one
//! that gets called from somewhere with no post-filter behind it.
//!
//! There are exactly two callers, one per path, and each produces something only the post-filter can
//! consume. [`crate::lexical::candidates`] calls `quote` and returns a `LexicalCandidates`;
//! `crate::milvus`'s decoder calls `preview` and returns `Vec<Candidate>`, which reaches a caller
//! only through [`crate::SearchResults::confirm`].

use std::ops::Range;

/// The longest body this module will quote, in characters.
///
/// Chunks run to `ChunkBudget::max_chars` — 3 200 characters by default — so this is a real cut
/// rather than a formality. It is a *quotation*, not the retrieval unit: a caller scanning a page of
/// twenty results needs to see why each one is there, and returning the whole chunk would put
/// 64 KB of document body in a response where 5 KB says the same thing.
///
/// The returned string can exceed this by the two elision marks, and by nothing else.
pub const MAX_CHARS: usize = 240;

/// How much of the budget may precede the matched term.
///
/// Enough context to read the term in its sentence, weighted forward because what follows a term is
/// usually what a reader wants — `indemnity against third-party claims` rather than
/// `The supplier shall provide an`.
const LEAD_CHARS: usize = 60;

/// Marks an end at which text was elided. U+2026, and never alphanumeric, so it cannot be read as a
/// token of the quoted text.
const ELISION: char = '…';

/// How many distinct query terms are considered when choosing which passage to quote.
///
/// `plainto_tsquery` ANDs its terms, so a chunk that matched contains every one of them and any
/// window is a legitimate quotation; this bound only decides which window is *best*. Sixty-four
/// keeps the coverage set a single `u64`. A query with more distinct words than this is not a query
/// a person typed.
const MAX_TERMS: usize = 64;

/// A quotation from one chunk, and where in it the query matched.
///
/// `ENC-542`. **One field, deliberately**, and that is the security property rather than tidiness.
/// [`crate::Confirmed::excerpt`] is an `Option` whose [`None`] means *there was no excerpt* and *you
/// may not read the content* at once, and the two must stay indistinguishable. Offsets sitting
/// *beside* the text would break that the moment an excerpt was withheld: a caller holding
/// `excerpt: null` and `highlights: [4, 14]` has been told there is a passage here they may not see
/// — which is precisely the fact `docs/12 §4.3` S6 refuses to disclose. Inside the value, there is
/// no way to have the offsets without the text, and the post-filter drops both with one `None`.
///
/// It also settles the disclosure question without a second decision. Offsets into a string the
/// caller is holding are not additional disclosure: they are the positions of the caller's own query
/// terms in text they have already been given, which they could compute themselves. They are only
/// safe *because* they travel with the text, which is the same reason they may not travel without
/// it.
///
/// [`std::fmt::Debug`] is hand-written and renders neither the text nor the offsets. See the impl.
#[derive(Clone, PartialEq, Eq)]
pub struct Excerpt {
    text: String,
    highlights: Highlights,
}

/// Where in an [`Excerpt`] the match is — if it is anywhere narrower than the whole quotation.
///
/// An enum rather than a possibly-empty `Vec`, because the dense path having no offsets is a
/// consequence of what a dense match *is* (`ENC-538`: the matched unit is the whole chunk, so there
/// is no narrower true span) and not a case where the locator happened to find nothing. An empty
/// vector says those two things with one value, and the reader cannot tell which they are holding.
///
/// [`std::fmt::Debug`] is hand-written and renders the variant without the offsets. See the impl.
#[derive(Clone, PartialEq, Eq)]
pub enum Highlights {
    /// The spans of [`Excerpt::text`] that hold a term the query matched on.
    ///
    /// **Byte** ranges into [`Excerpt::text`] as returned — elision marks included, so a renderer
    /// slices with them directly and does not have to know whether a `…` was prepended. Always on
    /// character boundaries, always non-empty, ascending and non-overlapping; [`Excerpt::located`]
    /// is the only constructor and refuses anything else.
    ///
    /// Bytes rather than characters because the marker is Rust: `&text[span]` takes a byte range,
    /// and a character offset would be converted at the one place a mistake becomes a panic on
    /// multi-byte text. A client-side renderer needing UTF-16 indices converts once, at the edge
    /// that knows it needs them.
    Terms(Vec<Range<usize>>),
    /// Nothing matched *at a position*, so there is nothing to mark.
    ///
    /// The dense path (`ENC-538`). A renderer emits **no** markup for this variant — not markup
    /// around the whole passage. "The whole chunk is the match" is true of the retrieval and says
    /// nothing about which words answered the query, and a quotation entirely in `<em>` claims it
    /// does.
    Unlocated,
}

impl Excerpt {
    /// A quotation with no located match — the dense path's shape.
    ///
    /// Public because a candidate generator can live outside this crate — [`crate::vector::VectorIndex`]
    /// is the port — and one whose excerpts have no located match needs a way to say so.
    #[must_use]
    pub fn unlocated(text: String) -> Self {
        Self { text, highlights: Highlights::Unlocated }
    }

    /// A quotation with the spans of `text` that matched, or [`None`] if `terms` does not describe
    /// them.
    ///
    /// Rejects an empty set, a span outside `text`, a span that is not on a character boundary, and
    /// spans that are not ascending and disjoint. Validated rather than documented because every one
    /// of those is a panic in whichever renderer slices with them, on input derived from a document
    /// — and because [`Highlights::Terms`]'s guarantees are worth something only if one function
    /// enforces them.
    #[must_use]
    pub fn located(text: String, terms: Vec<Range<usize>>) -> Option<Self> {
        if terms.is_empty() {
            return None;
        }
        let mut previous = 0;
        for span in &terms {
            if span.start < previous || span.end <= span.start || span.end > text.len() {
                return None;
            }
            if !text.is_char_boundary(span.start) || !text.is_char_boundary(span.end) {
                return None;
            }
            previous = span.end;
        }
        Some(Self { text, highlights: Highlights::Terms(terms) })
    }

    /// The quotation itself: verbatim chunk text, with `…` at whichever end was elided.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Where the match is, for a renderer that marks it up.
    #[must_use]
    pub const fn highlights(&self) -> &Highlights {
        &self.highlights
    }
}

/// `CLAUDE.md` rule 10, on the type that *is* the content (`docs/12 §4.3` S11).
///
/// The second line of defence behind `crate::postfilter`'s field-level redaction: that one protects
/// `Candidate` and `Confirmed`, and this one protects every other way an excerpt could reach a
/// format string — `tracing::debug!(?excerpt)` in the API layer, an `Option<Excerpt>` in some future
/// envelope, a `#[derive(Debug)]` added to a type that holds one.
///
/// The rendering is exactly what the field-level redaction produces, so an excerpt logged either way
/// reads the same and `Some(<content withheld>)` keeps meaning one thing.
impl std::fmt::Debug for Excerpt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<content withheld>")
    }
}

/// The offsets are withheld too, and that is not belt-and-braces.
///
/// They are derived from the content: a span says *a matched term of this length occurs at this
/// position*, and how many of them there are says how often the query's words appear in a passage.
/// In a log line whose body has been redacted, printing the shape of the redacted thing gives back
/// part of what the redaction removed — and the audience of a search log is far broader than the
/// audience of the documents it quotes.
///
/// The **variant** is printed, because that is a fact about which retrieval path produced the hit
/// rather than about the document, and it is what makes the line worth reading at all.
impl std::fmt::Debug for Highlights {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terms(_) => formatter.write_str("Terms(<offsets withheld>)"),
            Self::Unlocated => formatter.write_str("Unlocated"),
        }
    }
}

/// Cuts a quotation of `chunk` around a term of `query`, or returns [`None`].
///
/// [`None`] is returned when the query has no alphanumeric run, when no run of the query occurs in
/// the chunk, or when the located window trims to nothing. Every one of those is *this module
/// declining to quote*, never a permission decision — disclosure is [`crate::PostFilter`]'s, and it
/// is asked whether an excerpt exists or not.
///
/// Deterministic: the same `chunk` and `query` always produce the same string. An excerpt that
/// varied between two identical queries would be the same class of defect as an unstable sort order
/// — reported as "search changed its mind" and reproducible by nobody.
///
/// The returned [`Excerpt`] carries [`Highlights::Terms`]: the byte spans of its own text holding a
/// term of the query, so the API layer can mark up without tokenizing document content a second time
/// (`ENC-542`).
pub(crate) fn quote(chunk: &str, query: &str) -> Option<Excerpt> {
    let terms = terms(query);
    if terms.is_empty() {
        return None;
    }

    let chars: Vec<(usize, char)> = chunk.char_indices().collect();
    let tokens = tokenize(&chars);

    // Which query term each token is, if any. Positional rather than by string, so choosing a window
    // below is bit arithmetic instead of repeated string comparison.
    let term_of: Vec<Option<u32>> = tokens
        .iter()
        .map(|span| {
            let token = slice(chunk, &chars, span).to_lowercase();
            terms.iter().position(|term| *term == token).and_then(|index| u32::try_from(index).ok())
        })
        .collect();

    let anchor = best_anchor(&tokens, &term_of)?;
    let window = window_for(&tokens[anchor], chars.len());
    let window = snap_to_words(window, &tokens[anchor], &tokens, chars.len());

    let rendered = render(chunk, &chars, &window)?;
    let byte = |index: usize| chars.get(index).map_or(chunk.len(), |&(offset, _)| offset);
    let origin = byte(rendered.body.start);

    // Every query term visible in the rendered body, translated from character indices into the
    // chunk to byte offsets into the string the caller receives. `rendered.prefix` is the leading
    // elision mark, and forgetting it shifts every span by its three bytes — which is silent,
    // because the offsets still land on a character boundary and still slice.
    //
    // Clamped to the body rather than dropped when a token overruns it. That is not defensive
    // tidying, it is the one case [`window_for`] produces: a token longer than the whole budget is
    // cut mid-token, and the visible part of it is still the term that matched. Dropping it instead
    // would leave a lexical excerpt with nothing marked — and, before the clamp, with no excerpt at
    // all, which `a_token_longer_than_the_budget_is_cut_rather_than_blowing_it` caught.
    let spans: Vec<Range<usize>> = tokens
        .iter()
        .enumerate()
        .filter(|(index, _)| term_of.get(*index).copied().flatten().is_some())
        .filter_map(|(_, span)| {
            let start = span.start.max(rendered.body.start);
            let end = span.end.min(rendered.body.end);
            (start < end).then(|| {
                (rendered.prefix + byte(start) - origin)..(rendered.prefix + byte(end) - origin)
            })
        })
        .collect();

    // Unreachable by construction — the anchor is a matched token, [`window_for`] keeps at least its
    // start inside the window, and it is alphanumeric so trimming cannot remove it. Kept as a
    // refusal rather than an `expect` because the state it would guard against is a lexical excerpt
    // arriving with nothing marked, and [`None`] is the value this module already fails to.
    Excerpt::located(rendered.text, spans)
}

/// Cuts the head of `chunk` as an excerpt, or returns [`None`].
///
/// The dense path's rule. `ENC-538` and the module documentation carry the argument; the short form
/// is that a chunk selected by embedding similarity has no matched span to centre a window on, so
/// the window is the start of the chunk — and every other property of the returned string is
/// [`quote`]'s, because the code that produces them is [`quote`]'s.
///
/// [`None`] when the chunk holds nothing but whitespace. Like [`quote`]'s, that is *this module
/// declining to quote* and never a permission decision: disclosure is [`crate::PostFilter`]'s and it
/// is asked whether an excerpt exists or not.
///
/// Takes no query, and that is the point rather than an omission — see the module documentation on
/// why the query's words are not looked for here.
///
/// The returned [`Excerpt`] carries [`Highlights::Unlocated`], which is the same statement in the
/// type: nothing matched at a position, so there is nothing for a renderer to mark.
///
/// Deterministic, for the same reason [`quote`] is.
pub(crate) fn preview(chunk: &str) -> Option<Excerpt> {
    let chars: Vec<(usize, char)> = chunk.char_indices().collect();
    let end = MAX_CHARS.min(chars.len());

    // Only when there is something past the cut. A chunk that fits whole is returned whole, with no
    // elision mark, exactly as `quote` returns a short chunk untouched.
    let window = if end < chars.len() {
        // Back to the last token boundary at or before the budget, so the quotation does not end
        // mid-word. A leading token longer than the whole budget leaves no such boundary, and then
        // the hard cut stands: that is the one case `window_for` also cuts mid-token in, and for the
        // same reason — a single "word" must not blow the budget by an unbounded amount.
        //
        // A chunk whose *second* token runs past the budget yields a short excerpt rather than a
        // mid-word one — `a_word_then_a_token_longer_than_the_budget…` pins it. That is the honest
        // answer for a chunk that is a filename and a base64 blob, and a minimum-length rule to
        // avoid it would be a threshold with no argument behind it.
        let tokens = tokenize(&chars);
        let snapped = tokens.iter().rev().find(|span| span.end <= end).map_or(end, |span| span.end);
        0..snapped
    } else {
        0..end
    };

    render(chunk, &chars, &window).map(|rendered| Excerpt::unlocated(rendered.text))
}

/// The distinct alphanumeric runs of `query`, lowercased, in order of first appearance.
///
/// The same function tokenizes the document, which is the point: one rule, applied to both sides,
/// exactly as migrations 0012 and 0013 apply one `regexp_replace` to both sides. Two tokenizers that
/// are *supposed* to agree are two tokenizers that eventually do not.
fn terms(query: &str) -> Vec<String> {
    let chars: Vec<(usize, char)> = query.char_indices().collect();
    let mut terms: Vec<String> = Vec::new();
    for span in tokenize(&chars) {
        let term = slice(query, &chars, &span).to_lowercase();
        if !terms.contains(&term) {
            terms.push(term);
        }
        if terms.len() == MAX_TERMS {
            break;
        }
    }
    terms
}

/// Maximal runs of alphanumeric characters, as half-open ranges of *character* indices.
///
/// This is `regexp_replace(…, '[^[:alnum:]]+', ' ', 'g')` followed by splitting on spaces, with the
/// intermediate string never built. Character indices rather than byte offsets so the length budget
/// is measured in what a reader would call characters, and so no arithmetic on it can land inside a
/// UTF-8 sequence.
fn tokenize(chars: &[(usize, char)]) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    let mut open: Option<usize> = None;
    for (index, &(_, ch)) in chars.iter().enumerate() {
        if ch.is_alphanumeric() {
            let _ = open.get_or_insert(index);
        } else if let Some(start) = open.take() {
            spans.push(start..index);
        }
    }
    if let Some(start) = open {
        spans.push(start..chars.len());
    }
    spans
}

/// The token to build the window around: the one whose window covers the most distinct query terms,
/// earliest occurrence winning ties.
///
/// Coverage rather than "first match" because a two-word query whose words appear together at the
/// end of a chunk and separately at its start should quote the passage that answers it. Ties break
/// on position so the choice is deterministic.
fn best_anchor(tokens: &[Range<usize>], term_of: &[Option<u32>]) -> Option<usize> {
    let total = tokens.last().map_or(0, |span| span.end);
    let mut best: Option<(u32, usize)> = None;

    for (index, span) in tokens.iter().enumerate() {
        if term_of.get(index).copied().flatten().is_none() {
            continue;
        }
        let window = window_for(span, total);
        let covered = coverage(tokens, term_of, &window).count_ones();
        if best.is_none_or(|(best_covered, _)| covered > best_covered) {
            best = Some((covered, index));
        }
    }

    best.map(|(_, index)| index)
}

/// The set of distinct query terms whose tokens lie wholly inside `window`, as a bitmask.
///
/// Tokens are position-ordered, so the ones inside a window are a contiguous run: the scan starts at
/// the first token beginning at or after the window and stops at the first that would overrun it.
fn coverage(tokens: &[Range<usize>], term_of: &[Option<u32>], window: &Range<usize>) -> u64 {
    let first = tokens.partition_point(|span| span.start < window.start);
    let mut mask = 0_u64;
    for (index, span) in tokens.iter().enumerate().skip(first) {
        if span.end > window.end {
            break;
        }
        if let Some(term) = term_of.get(index).copied().flatten() {
            mask |= 1_u64 << term;
        }
    }
    mask
}

/// The character window around `anchor`, before word boundaries are applied.
///
/// The anchor is always inside it. A token longer than the whole budget — a base64 blob, a long
/// identifier — is quoted from its own start for `MAX_CHARS`, which is the one case where the cut
/// lands mid-token; the alternative is a single "word" blowing the budget by an unbounded amount.
fn window_for(anchor: &Range<usize>, total: usize) -> Range<usize> {
    let start = anchor.start.saturating_sub(LEAD_CHARS);
    let end = start.saturating_add(MAX_CHARS).min(total);
    if end < anchor.end {
        let start = anchor.start;
        return start..start.saturating_add(MAX_CHARS).min(total);
    }
    start..end
}

/// Moves the window's ends onto token boundaries, so a quotation never begins or ends mid-word.
///
/// Only where there is text to elide: an end that is already the document's own edge stays there.
/// The anchor is never cut — unless it did not fit in the first place, which [`window_for`] has
/// already decided, and in that case the window is returned untouched so the budget still holds.
fn snap_to_words(
    window: Range<usize>,
    anchor: &Range<usize>,
    tokens: &[Range<usize>],
    total: usize,
) -> Range<usize> {
    if anchor.end > window.end {
        return window;
    }

    let mut start = window.start;
    if start > 0 {
        let from = start;
        start = tokens
            .iter()
            .find(|span| span.start >= from)
            .map_or(anchor.start, |span| span.start)
            .min(anchor.start);
    }

    let mut end = window.end;
    if end < total {
        let until = end;
        end = tokens
            .iter()
            .rev()
            .find(|span| span.end <= until)
            .map_or(anchor.end, |span| span.end)
            .max(anchor.end);
    }

    start..end
}

/// A rendered window, and enough about how it was built to locate a chunk offset inside it.
///
/// The two extra fields exist only so [`quote`] can translate the spans it located in the *chunk*
/// into spans of the *string it returns*. Doing that translation here rather than re-deriving it at
/// the call site is the same rule the rest of the module follows: the elision marks and the trim are
/// this function's, so the arithmetic that accounts for them is too.
struct Rendered {
    /// The string a caller sees.
    text: String,
    /// The character window of the chunk that `text`'s body came from, after trimming.
    body: Range<usize>,
    /// Bytes of `text` before the body: the leading elision mark, or nothing.
    prefix: usize,
}

/// Builds the returned string: the window's characters verbatim, with `…` at each end that dropped
/// something.
///
/// "Dropped something" means a non-whitespace character, so a chunk that merely begins with a
/// newline is not reported as elided. The body is `trim`med, which can only remove whitespace the
/// window's own edges introduced.
fn render(chunk: &str, chars: &[(usize, char)], window: &Range<usize>) -> Option<Rendered> {
    let raw = slice(chunk, chars, window);
    let body = raw.trim();
    if body.is_empty() {
        return None;
    }

    // The trimmed body as a character window of the chunk. `str::trim` removes exactly
    // `char::is_whitespace`, which is what these two counts measure, so the three agree by
    // construction rather than by resemblance.
    let leading = raw.chars().take_while(|ch| ch.is_whitespace()).count();
    let trailing = raw.chars().rev().take_while(|ch| ch.is_whitespace()).count();
    let kept = (window.start + leading)..(window.end - trailing);

    let elided_before = chars.get(..kept.start).is_some_and(has_text);
    let elided_after = chars.get(kept.end..).is_some_and(has_text);

    let mut text = String::with_capacity(body.len() + ELISION.len_utf8() * 2);
    if elided_before {
        text.push(ELISION);
    }
    text.push_str(body);
    if elided_after {
        text.push(ELISION);
    }

    let prefix = if elided_before { ELISION.len_utf8() } else { 0 };
    Some(Rendered { text, body: kept, prefix })
}

/// Whether a run of characters holds anything but whitespace.
fn has_text(chars: &[(usize, char)]) -> bool {
    chars.iter().any(|&(_, ch)| !ch.is_whitespace())
}

/// The substring covered by a range of *character* indices.
///
/// The byte offsets come from `char_indices`, so they are always on a character boundary and this
/// cannot panic on multi-byte text.
fn slice<'a>(text: &'a str, chars: &[(usize, char)], span: &Range<usize>) -> &'a str {
    let start = chars.get(span.start).map_or(text.len(), |&(offset, _)| offset);
    let end = chars.get(span.end).map_or(text.len(), |&(offset, _)| offset);
    text.get(start..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    // Assertions are the point of a test: a panic here is the failure signal.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    /// Why the assertions below say `shown = excerpt.text()` rather than `{excerpt:?}`.
    ///
    /// [`Excerpt`]'s [`std::fmt::Debug`] renders `<content withheld>` (`docs/12 §4.3` S11), which is
    /// right everywhere in the product and useless in a failure message. These fixtures are written
    /// three lines above the assertion that reads them, so showing one costs nothing and a message
    /// that cannot say what came back costs an afternoon. The call is explicit at each site rather
    /// than a `Display` impl, so nothing outside a test acquires a shorter way to print an excerpt
    /// than [`Excerpt::text`].
    ///
    /// The body of an excerpt, with the elision marks removed. Used by the property assertions
    /// below, all of which are about the part that claims to come from the document.
    fn body(excerpt: &Excerpt) -> &str {
        excerpt.text().trim_matches(ELISION)
    }

    /// **The property the whole module exists for.** Whatever is returned between the elision marks
    /// is a substring of the document, character for character.
    ///
    /// This is the assertion that a `ts_headline` over the normalized expression fails: it returns
    /// `Clause 7 2 sets out…`, which the document does not contain.
    #[test]
    fn the_body_of_an_excerpt_is_always_a_verbatim_substring_of_the_chunk() {
        let cases = [
            ("Clause 7.2(b) sets out the perihelion review procedure.", "perihelion"),
            ("The supplier shall provide an indemnity against third-party claims.", "indemnity"),
            ("Größe: 42 mm — siehe Anhang B.", "größe"),
            ("a-b-c budget_forecast.xlsx v2", "budget"),
            (LONG, "tantalum"),
        ];
        for (chunk, query) in cases {
            let excerpt = quote(chunk, query).expect("the term is present in the chunk");
            assert!(
                chunk.contains(body(&excerpt)),
                "excerpt body is not text from the document\n  chunk: {chunk:?}\n  body:  {:?}",
                body(&excerpt)
            );
        }
    }

    /// Punctuation survives, which is the difference between quoting the document and quoting the
    /// index. `Clause 7.2(b)` is *made of* its punctuation; a caller handed `Clause 7 2 b` cannot
    /// find it in the file.
    #[test]
    fn punctuation_is_preserved_because_the_quotation_is_of_the_document_not_of_the_index() {
        let chunk = "Clause 7.2(b) sets out the perihelion review procedure.";
        let excerpt = quote(chunk, "perihelion").expect("quotable");
        assert!(
            excerpt.text().contains("7.2(b)"),
            "the excerpt was cut from the punctuation-stripped form: {shown:?}",
            shown = excerpt.text()
        );
    }

    /// The quotation contains the word that caused the hit. An excerpt that does not is a snippet of
    /// something else, which is the failure `ts_headline` over raw text produces silently.
    #[test]
    fn the_excerpt_contains_a_term_the_query_matched_on() {
        let excerpt = quote(LONG, "tantalum").expect("quotable");
        assert!(
            excerpt.text().to_lowercase().contains("tantalum"),
            "the excerpt does not contain the matched term: {shown:?}",
            shown = excerpt.text()
        );
    }

    /// A term that is not in the chunk yields nothing. The fail-closed direction, and the value it
    /// fails to is the same `None` a withheld excerpt produces.
    #[test]
    fn a_term_that_cannot_be_located_yields_no_excerpt_rather_than_the_opening_of_the_document() {
        assert_eq!(quote("The supplier shall deliver the goods.", "perihelion"), None);
    }

    /// `simple` has no stemmer, so neither does this. `invoices` does not find `invoice` in the
    /// index either — quoting on a looser rule than the index matched on would put a passage in
    /// front of a caller that the index never claimed was a hit.
    #[test]
    fn matching_is_exact_because_the_index_it_mirrors_does_not_stem() {
        assert_eq!(quote("Attached are the invoices for March.", "invoice"), None);
        assert!(quote("Attached are the invoices for March.", "invoices").is_some());
    }

    /// Case folding is the one transformation `simple` does apply.
    #[test]
    fn matching_is_case_folded_the_way_the_simple_dictionary_folds_it() {
        assert!(quote("The INDEMNITY clause is unchanged.", "indemnity").is_some());
        assert!(quote("The indemnity clause is unchanged.", "INDEMNITY").is_some());
    }

    /// A query with no alphanumeric run has no terms, so there is nothing to centre on.
    /// `lexical::candidates` refuses such a query before the database, and this is the same refusal
    /// one layer down rather than a second opinion about it.
    #[test]
    fn a_query_with_no_alphanumeric_characters_yields_no_excerpt() {
        assert_eq!(quote("Clause 7.2 applies.", "  --- ??? "), None);
    }

    /// The budget holds, and the only thing allowed past it is the two elision marks.
    #[test]
    fn an_excerpt_never_exceeds_its_budget() {
        for query in ["tantalum", "allowance", "quarter"] {
            let excerpt = quote(LONG, query).expect("quotable");
            assert!(
                excerpt.text().chars().count() <= MAX_CHARS + 2,
                "excerpt is {} characters, budget is {MAX_CHARS}",
                excerpt.text().chars().count()
            );
        }
    }

    /// A single token longer than the whole budget is the one case that cuts mid-word, and it is
    /// bounded rather than being allowed to return the token.
    #[test]
    fn a_token_longer_than_the_budget_is_cut_rather_than_blowing_it() {
        let blob = "x".repeat(1_000);
        let chunk = format!("prefix {blob} suffix");
        let excerpt = quote(&chunk, &blob).expect("the token is its own term");
        assert!(excerpt.text().chars().count() <= MAX_CHARS + 2);
    }

    /// Neither end of the body lands inside a word, unless that end is the document's own edge.
    #[test]
    fn a_quotation_does_not_begin_or_end_in_the_middle_of_a_word() {
        let excerpt = quote(LONG, "tantalum").expect("quotable");
        let quoted = body(&excerpt);
        let start = LONG.find(quoted).expect("verbatim substring");
        let end = start + quoted.len();

        let before = LONG[..start].chars().next_back();
        let after = LONG[end..].chars().next();
        let first = quoted.chars().next().expect("non-empty");
        let last = quoted.chars().next_back().expect("non-empty");

        assert!(
            !(before.is_some_and(char::is_alphanumeric) && first.is_alphanumeric()),
            "the quotation starts inside a word: {shown:?}",
            shown = excerpt.text()
        );
        assert!(
            !(after.is_some_and(char::is_alphanumeric) && last.is_alphanumeric()),
            "the quotation ends inside a word: {shown:?}",
            shown = excerpt.text()
        );
    }

    /// Elision is reported where it happened and nowhere else. A chunk short enough to quote whole
    /// carries no marks at all, so `…` means something.
    #[test]
    fn elision_is_marked_only_at_an_end_where_text_was_actually_dropped() {
        let whole = quote("A short note about tantalum.", "tantalum").expect("quotable");
        assert_eq!(
            whole.text(),
            "A short note about tantalum.",
            "nothing was elided, so nothing is marked"
        );

        let cut = quote(LONG, "tantalum").expect("quotable");
        assert!(
            cut.text().starts_with(ELISION) || cut.text().ends_with(ELISION),
            "text was dropped unmarked"
        );
    }

    /// A two-word query quotes the passage where both words appear, not the first place either one
    /// does.
    #[test]
    fn a_multi_term_query_quotes_the_passage_that_holds_the_most_of_it() {
        let chunk = "Tantalum is a metal. \
                     Padding padding padding padding padding padding padding padding padding \
                     padding padding padding padding padding padding padding padding padding \
                     padding padding padding padding padding padding padding padding padding. \
                     The tantalum allowance is paid each quarter.";
        let excerpt = quote(chunk, "tantalum allowance").expect("quotable");
        assert!(
            excerpt.text().contains("tantalum allowance"),
            "the window was centred on the lone first occurrence: {shown:?}",
            shown = excerpt.text()
        );
    }

    /// The same inputs always give the same answer.
    #[test]
    fn the_same_chunk_and_query_always_produce_the_same_excerpt() {
        let first = quote(LONG, "allowance");
        for _ in 0..8 {
            assert_eq!(quote(LONG, "allowance"), first);
        }
    }

    /// Multi-byte text is quoted without panicking and without splitting a character, which is what
    /// the character-index arithmetic in this module is for.
    #[test]
    fn multibyte_text_is_quoted_on_character_boundaries() {
        let chunk = "Die Größe beträgt 42 mm — 🛠 siehe Anhang. ".repeat(20);
        let excerpt = quote(&chunk, "größe").expect("quotable");
        assert!(chunk.contains(body(&excerpt)));
        assert!(excerpt.text().to_lowercase().contains("größe"));
    }

    /// An empty chunk, an empty query, and a chunk of nothing but punctuation. None of them panic
    /// and none of them quote.
    #[test]
    fn degenerate_inputs_decline_rather_than_panic() {
        assert_eq!(quote("", "tantalum"), None);
        assert_eq!(quote("some text", ""), None);
        assert_eq!(quote("--- ... ---", "tantalum"), None);
        assert_eq!(quote("", ""), None);
    }

    // ---------------------------------------------------------------------------------------
    // `ENC-538` — the dense path, which has no matched span.
    // ---------------------------------------------------------------------------------------

    /// A chunk of roughly the size the chunker actually produces, so that a budget assertion over it
    /// is a real cut and not a formality. `ChunkBudget::max_chars` is 3 200.
    fn full_chunk() -> String {
        let mut chunk = String::from(
            "Section 4.1 Allowances. Employees may claim the standard allowance each quarter, \
             subject to approval by their line manager. ",
        );
        while chunk.chars().count() < 3_000 {
            chunk.push_str(
                "Nothing in this section affects the statutory minimum, and the appendix governs \
                 where the two disagree. ",
            );
        }
        chunk.push_str("The tantalum allowance is a separate entitlement, paid annually.");
        chunk
    }

    /// **The positive control for every assertion below.** A dense hit on an ordinary chunk produces
    /// an excerpt, it is text from that chunk, and it comes from the start of it.
    ///
    /// Without this, an implementation returning `None` unconditionally satisfies the absence
    /// assertions in this section for free — which is exactly the vacuous-test shape `docs/12 §1.2`
    /// records having caught eight times, once on an `excerpt == None` assertion.
    #[test]
    fn a_dense_excerpt_is_present_and_is_verbatim_text_from_the_head_of_the_chunk() {
        let chunk = full_chunk();
        let excerpt = preview(&chunk).expect("an ordinary chunk previews");
        let quoted = body(&excerpt);

        assert!(!quoted.is_empty(), "the preview body is empty: {shown:?}", shown = excerpt.text());
        assert!(chunk.contains(quoted), "the preview body is not text from the chunk: {quoted:?}");
        assert!(
            chunk.starts_with(quoted),
            "the preview was cut from somewhere other than the head: {quoted:?}"
        );
        assert!(
            quoted.starts_with("Section 4.1 Allowances."),
            "punctuation did not survive, so this is a quotation of something other than the \
             document: {quoted:?}"
        );
    }

    /// **The `ENC-538` assertion.** Both paths cut to the same budget, so the same document is not
    /// quoted at 240 characters when search is degraded and at 3 200 when it is healthy.
    ///
    /// The third assertion is what keeps the first two from being about nothing: the chunk really is
    /// an order of magnitude larger than the budget, so a decoder passing it through fails here.
    #[test]
    fn a_dense_excerpt_is_held_to_the_same_budget_a_quotation_is() {
        let chunk = full_chunk();
        let dense = preview(&chunk).expect("previewable");
        let lexical = quote(&chunk, "tantalum").expect("quotable");

        assert!(
            chunk.chars().count() > MAX_CHARS * 4,
            "the fixture is not large enough for this test to mean anything: {} characters",
            chunk.chars().count()
        );
        assert!(
            dense.text().chars().count() <= MAX_CHARS + 2,
            "the dense excerpt is {} characters, budget is {MAX_CHARS}",
            dense.text().chars().count()
        );
        assert!(
            lexical.text().chars().count() <= MAX_CHARS + 2,
            "the lexical excerpt is {} characters, budget is {MAX_CHARS}",
            lexical.text().chars().count()
        );
    }

    /// The two paths differ in the one place they are supposed to: which window.
    ///
    /// Asserted so that the budget test above cannot quietly become a comparison of one string with
    /// itself — and so that a later change collapsing `preview` into `quote` is a failure here
    /// rather than a silent loss of the dense path's excerpt whenever the caller's words are absent.
    #[test]
    fn the_two_paths_choose_different_windows_of_the_same_chunk() {
        let chunk = full_chunk();
        let dense = preview(&chunk).expect("previewable");
        let lexical = quote(&chunk, "tantalum").expect("quotable");

        assert_ne!(
            body(&dense),
            body(&lexical),
            "the anchored window and the head window are the same span, so this fixture proves \
             nothing about either"
        );
        assert!(
            body(&lexical).to_lowercase().contains("tantalum"),
            "the anchored window lost its term: {shown:?}",
            shown = lexical.text()
        );
        assert!(
            !body(&dense).to_lowercase().contains("tantalum"),
            "the term happens to be in the head of this fixture, so the assertion above is not \
             about anchoring: {shown:?}",
            shown = dense.text()
        );
    }

    /// A dense excerpt is cut from a chunk with no query in hand, and the chunk need not contain a
    /// word anybody typed — which is the case the dense path exists for.
    #[test]
    fn a_chunk_holding_none_of_the_callers_words_still_previews() {
        // `quote` declines, because there is no term to locate. `preview` does not ask.
        let chunk = "Revenue recognition follows the five-step model in the standard.";
        assert_eq!(
            quote(chunk, "turnover"),
            None,
            "the fixture accidentally contains the term, so the next assertion is not about a \
             dense-only match"
        );
        assert_eq!(preview(chunk).as_ref().map(Excerpt::text), Some(chunk));
    }

    /// Elision is marked where text was dropped and nowhere else. The head of a chunk is the chunk's
    /// own edge, so a dense excerpt never opens with `…`.
    ///
    /// Both directions from one fixture pair, so an implementation that marked unconditionally and
    /// one that never marked both fail.
    #[test]
    fn a_dense_excerpt_marks_the_end_it_cut_and_not_the_start_it_did_not() {
        let cut = preview(&full_chunk()).expect("previewable");
        assert!(
            !cut.text().starts_with(ELISION),
            "the head of a chunk elides nothing before it: {shown:?}",
            shown = cut.text()
        );
        assert!(
            cut.text().ends_with(ELISION),
            "text was dropped from the end unmarked: {shown:?}",
            shown = cut.text()
        );

        let whole = preview("A short note about tantalum.").expect("previewable");
        assert_eq!(
            whole.text(),
            "A short note about tantalum.",
            "a chunk that fits was marked as though something had been dropped"
        );
    }

    /// The cut does not land inside a word.
    #[test]
    fn a_dense_excerpt_does_not_end_in_the_middle_of_a_word() {
        let chunk = full_chunk();
        let excerpt = preview(&chunk).expect("previewable");
        let quoted = body(&excerpt);
        let after = chunk[quoted.len()..].chars().next();
        let last = quoted.chars().next_back().expect("non-empty");

        assert!(
            !(after.is_some_and(char::is_alphanumeric) && last.is_alphanumeric()),
            "the preview ends inside a word: {shown:?}",
            shown = excerpt.text()
        );
    }

    /// A leading token longer than the whole budget is the one case with no boundary to snap to, and
    /// it is bounded rather than returned.
    #[test]
    fn a_leading_token_longer_than_the_budget_is_cut_rather_than_blowing_it() {
        let chunk = format!("{} tail", "x".repeat(1_000));
        let excerpt = preview(&chunk).expect("previewable");
        assert!(
            excerpt.text().chars().count() <= MAX_CHARS + 2,
            "{shown:?}",
            shown = excerpt.text()
        );
        assert!(chunk.contains(body(&excerpt)));
    }

    /// A chunk whose second token runs past the budget is cut short rather than cut mid-word.
    ///
    /// Pinned rather than left to be discovered: `attachment.bin` followed by a base64 blob previews
    /// as `attachment.bin…` and nothing else. It is verbatim, bounded and marked, and it is thin —
    /// which is the honest answer for a chunk that is a filename and a blob, and better than a
    /// minimum-length threshold nobody could justify.
    #[test]
    fn a_word_then_a_token_longer_than_the_budget_previews_short_rather_than_mid_word() {
        let chunk = format!("attachment.bin {}", "Q".repeat(1_000));
        assert_eq!(preview(&chunk).as_ref().map(Excerpt::text), Some("attachment.bin…"));
    }

    /// Multi-byte text is cut on character boundaries, which is what the character-index arithmetic
    /// is for. A byte-indexed head cut panics here.
    #[test]
    fn a_dense_excerpt_is_cut_on_character_boundaries() {
        let chunk = "Die Größe beträgt 42 mm — 🛠 siehe Anhang. ".repeat(40);
        let excerpt = preview(&chunk).expect("previewable");
        assert!(chunk.contains(body(&excerpt)));
        assert!(excerpt.text().chars().count() <= MAX_CHARS + 2);
    }

    /// The same chunk always previews the same. An excerpt that varied between two identical
    /// searches is the defect `quote` is deterministic to avoid, and it is no better here.
    #[test]
    fn the_same_chunk_always_previews_the_same() {
        let chunk = full_chunk();
        let first = preview(&chunk);
        assert!(first.is_some(), "a `None` here would make the loop below vacuous");
        for _ in 0..8 {
            assert_eq!(preview(&chunk), first);
        }
    }

    /// A chunk with nothing to quote declines, and does not panic.
    ///
    /// Paired with a chunk that *does* preview, because every assertion above is about an absence
    /// and an absence passes for free.
    #[test]
    fn a_chunk_with_no_text_declines_rather_than_returning_an_empty_string() {
        assert_eq!(preview(""), None);
        assert_eq!(preview("   \n\t  "), None);
        assert_eq!(
            preview("x").as_ref().map(Excerpt::text),
            Some("x"),
            "and the control: text previews"
        );
    }

    // ---------------------------------------------------------------------------------------
    // `ENC-542` — the offsets a renderer marks up from, and the bidi state a fragment can break.
    // ---------------------------------------------------------------------------------------

    /// A one-span vector, built rather than written as `vec![4..14]`.
    ///
    /// `clippy::single_range_in_vec_init` reads that literal as a `vec![4; 14]` typo, and both of
    /// its suggested rewrites mean something other than "one span".
    fn one_span(start: usize, end: usize) -> Vec<Range<usize>> {
        std::iter::once(start..end).collect()
    }

    /// The substrings an excerpt's offsets actually select, sliced out of the excerpt itself.
    ///
    /// Everything below asserts on these rather than on the numbers, because the numbers are only
    /// ever *used* to slice: an off-by-three from a forgotten elision mark is a plausible-looking
    /// pair of integers and a wrong word.
    fn marked(excerpt: &Excerpt) -> Vec<&str> {
        match excerpt.highlights() {
            Highlights::Terms(spans) => spans
                .iter()
                .map(|span| {
                    excerpt
                        .text()
                        .get(span.start..span.end)
                        .expect("Excerpt::located refuses a span that does not slice")
                })
                .collect(),
            Highlights::Unlocated => Vec::new(),
        }
    }

    /// **The property the offsets exist for.** Every span selects a term the caller typed.
    ///
    /// This is what lets the API layer emit `docs/05 §11`'s `<em>` without tokenizing document
    /// content a second time — and a second tokenization is the thing this module's argument is
    /// about, so the offsets are worth nothing if they do not survive being handed on.
    #[test]
    fn every_offset_selects_a_term_the_query_matched_on() {
        for (chunk, query) in [
            ("Clause 7.2(b) sets out the perihelion review procedure.", "perihelion"),
            ("The supplier shall provide an indemnity against third-party claims.", "indemnity"),
            ("Größe: 42 mm — siehe Anhang B.", "größe"),
            (LONG, "tantalum"),
        ] {
            let excerpt = quote(chunk, query).expect("quotable");
            let selected = marked(&excerpt);
            assert!(
                !selected.is_empty(),
                "a lexical excerpt marked nothing: {shown:?}",
                shown = excerpt.text()
            );
            for term in selected {
                assert_eq!(
                    term.to_lowercase(),
                    query,
                    "an offset selects {term:?}, which is not the term the caller typed"
                );
            }
        }
    }

    /// **The off-by-one that would be invisible.** Offsets index the string the caller receives,
    /// elision marks included — not the body between them, and not the chunk they were cut from.
    ///
    /// `…` is three bytes. A span measured from the body instead lands three bytes early, still on a
    /// character boundary, still slices without error, and selects `…Th` where `The` was meant. The
    /// fixture is chosen so the leading mark is present, and the assertion is the *word*, so the
    /// shift cannot pass.
    #[test]
    fn offsets_are_into_the_returned_string_and_count_its_leading_elision_mark() {
        let excerpt = quote(LONG, "tantalum").expect("quotable");
        assert!(
            excerpt.text().starts_with(ELISION),
            "this fixture has no leading elision mark, so it cannot catch the shift it exists to \
             catch: {shown:?}",
            shown = excerpt.text()
        );
        assert_eq!(marked(&excerpt), vec!["tantalum"]);
    }

    /// Multi-byte text: the offsets slice without panicking and select the right word.
    ///
    /// A locator that counted characters and a renderer that slices bytes agree on ASCII and part
    /// company at the first `ö`, and the symptom is a panic in whichever crate does the marking.
    #[test]
    fn offsets_land_on_character_boundaries_in_multibyte_text() {
        let chunk = "Die Größe beträgt 42 mm — 🛠 siehe Anhang. ".repeat(20);
        let excerpt = quote(&chunk, "größe").expect("quotable");
        for term in marked(&excerpt) {
            assert_eq!(term.to_lowercase(), "größe", "{shown:?}", shown = excerpt.text());
        }
    }

    /// A two-term query marks both, in order and without overlapping.
    ///
    /// The ordering guarantee is not decoration: a renderer walking the spans and splicing markup
    /// tracks one cursor through the string, and an out-of-order or overlapping pair either panics
    /// on a reversed slice or emits nested `<em>`.
    #[test]
    fn each_matched_term_is_marked_once_in_ascending_order() {
        let chunk = "The tantalum allowance is paid each quarter, in arrears.";
        let excerpt = quote(chunk, "tantalum allowance").expect("quotable");

        assert_eq!(marked(&excerpt), vec!["tantalum", "allowance"]);

        let Highlights::Terms(spans) = excerpt.highlights() else {
            panic!("a lexical excerpt is not marked: {shown:?}", shown = excerpt.text());
        };
        assert!(
            spans.windows(2).all(|pair| pair[0].end <= pair[1].start),
            "the spans overlap or run backwards"
        );
    }

    /// The one token that is cut mid-word is marked as far as it is shown.
    ///
    /// [`window_for`] cuts inside a token longer than the whole budget, so the matched term runs
    /// past the end of the excerpt. Clamping to what is visible is the honest answer; **dropping**
    /// it was the first implementation, and it did not merely lose the highlight — with no span left
    /// to carry, [`Excerpt::located`] refused and the hit lost its excerpt entirely. Caught by
    /// `a_token_longer_than_the_budget_is_cut_rather_than_blowing_it`, and pinned here so the cause
    /// is named rather than rediscovered.
    #[test]
    fn a_term_cut_by_the_budget_is_marked_as_far_as_it_is_shown() {
        let blob = "x".repeat(1_000);
        let chunk = format!("prefix {blob} suffix");
        let excerpt = quote(&chunk, &blob).expect("the token is its own term");

        assert_eq!(
            marked(&excerpt),
            vec![body(&excerpt)],
            "the visible part of the matched token is the whole body, so that is what is marked"
        );
        assert_eq!(body(&excerpt).chars().count(), MAX_CHARS, "and it is still bounded");
    }

    /// **The `ENC-538` consequence, in the type.** A dense excerpt has no offsets, and it says so
    /// with a variant rather than with an empty list.
    ///
    /// The distinction is the point. `Terms(vec![])` would mean *the locator found nothing* and
    /// *there was nothing to find* with one value, and the second is what a dense match is: the
    /// matched unit is the whole chunk, so there is no narrower span for anything to locate. A
    /// renderer told `Unlocated` marks nothing — and, in particular, does not mark the whole
    /// passage.
    #[test]
    fn a_dense_excerpt_carries_no_offsets_and_the_type_says_which_kind_of_none_that_is() {
        let dense = preview(&full_chunk()).expect("previewable");
        assert_eq!(dense.highlights(), &Highlights::Unlocated);
        assert!(
            !matches!(dense.highlights(), Highlights::Terms(_)),
            "a dense excerpt claims located matches: {shown:?}",
            shown = dense.text()
        );

        // The control: the other path does produce them, so this test is not passing against a
        // module that stopped locating anything at all.
        let lexical = quote(&full_chunk(), "tantalum").expect("quotable");
        assert!(
            matches!(lexical.highlights(), Highlights::Terms(_)),
            "{shown:?}",
            shown = lexical.text()
        );
    }

    /// **Bidi.** An excerpt is a *fragment*, and its directional controls are quoted verbatim.
    ///
    /// A document can open a right-to-left override and close it long after the passage a query
    /// matched. Cut a 240-character window out of the middle and the quotation inherits an
    /// **unbalanced** control: an unterminated U+202E reverses everything after it, and in a result
    /// list that is the surrounding UI, not just the snippet.
    ///
    /// The remedy is `unicode-bidi: isolate` at render — `docs/14-I18N-L10N.md §7`, which is where a
    /// renderer will look — and **not** stripping the characters here. Stripping would break the one
    /// property the whole module is built on: that the body between the marks is the document's own
    /// text, character for character. A caller who searches the file for what they were shown must
    /// find it, and an excerpt silently missing a control character is a wrong quotation of a
    /// document whose direction marks may be load-bearing.
    ///
    /// So this asserts the hazard rather than its absence: the control survives, and the excerpt is
    /// the chunk exactly.
    #[test]
    fn a_directional_control_is_quoted_verbatim_rather_than_stripped() {
        // Assembled rather than written out, so the fixture cannot be mistaken for stray bytes.
        let rlo = '\u{202E}';
        let chunk = format!("The tantalum schedule {rlo}drawkcab runs to the appendix.");

        let excerpt = quote(&chunk, "tantalum").expect("quotable");
        assert_eq!(
            excerpt.text(),
            chunk,
            "the excerpt is not the chunk character for character, so a caller cannot find what \
             they were shown in the file"
        );
        assert!(
            excerpt.text().contains(rlo),
            "the directional control was stripped: the excerpt is no longer verbatim, and the fix \
             belongs at the renderer (unicode-bidi: isolate), not here"
        );

        // And on the dense path, which cuts a different window out of the same hazard.
        let dense = preview(&chunk).expect("previewable");
        assert!(
            dense.text().contains(rlo),
            "the dense path stripped it: {shown:?}",
            shown = dense.text()
        );
    }

    /// `docs/12 §4.3` S11, at the type that holds the content.
    ///
    /// `crate::postfilter` redacts the *field*; this is the same refusal one layer in, so an excerpt
    /// formatted anywhere else — a future envelope, `tracing::debug!(?excerpt)` in an API handler —
    /// is redacted too. The offsets go with it: a span published beside a redacted body says a term
    /// of that length occurs at that position, which is part of what the redaction removed.
    #[test]
    fn an_excerpts_own_debug_carries_neither_its_text_nor_its_offsets() {
        let chunk = "Clause 7.2(b) sets out the perihelion review procedure.";
        let excerpt = quote(chunk, "perihelion").expect("quotable");

        let rendered = format!("{excerpt:?}");
        assert!(!rendered.contains("perihelion"), "the body reached a format string: {rendered}");
        assert!(!rendered.contains(".."), "the offsets reached a format string: {rendered}");
        assert_eq!(
            rendered, "<content withheld>",
            "the rendering must match the field-level redaction, so `Some(<content withheld>)` \
             keeps meaning one thing"
        );

        // The control: a `Debug` that printed nothing at all would satisfy the two assertions
        // above, and an `Option` of it must still show present-versus-absent.
        assert_eq!(format!("{:?}", Some(excerpt)), "Some(<content withheld>)");
        assert_eq!(format!("{:?}", Option::<Excerpt>::None), "None");
    }

    /// [`Excerpt::located`] refuses offsets that do not describe the text.
    ///
    /// Each of these is a panic in whichever crate slices with them, on input derived from a
    /// document — so the constructor is where they stop, and the guarantees on
    /// [`Highlights::Terms`] are enforced rather than described.
    #[test]
    fn located_refuses_offsets_that_do_not_describe_the_text() {
        let text = "Größe: 42 mm".to_owned();
        assert!(Excerpt::located(text.clone(), Vec::new()).is_none(), "an empty set is not marked");
        assert!(Excerpt::located(text.clone(), one_span(0, 99)).is_none(), "past the end");
        assert!(Excerpt::located(text.clone(), one_span(4, 4)).is_none(), "empty span");
        assert!(Excerpt::located(text.clone(), one_span(0, 5)).is_none(), "inside a character");
        assert!(Excerpt::located(text.clone(), vec![7..9, 0..2]).is_none(), "out of order");
        assert!(Excerpt::located(text.clone(), vec![0..6, 3..9]).is_none(), "overlapping");
        assert!(
            Excerpt::located(text, one_span(0, 6)).is_some(),
            "and the control: a well-formed span is accepted, or every assertion above is free"
        );
    }

    /// A chunk long enough that a window is a real cut.
    const LONG: &str = "Employees may claim the standard allowance each quarter, subject to \
        approval by their line manager and to the limits set out in the appendix. \
        The tantalum allowance is a separate entitlement and is paid annually, in arrears, \
        against receipts submitted before the end of the following quarter. \
        Nothing in this section affects the statutory minimum.";
}
