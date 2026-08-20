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
//! the watermark path). Highlighting is the API layer's, from offsets, and is `ENC-529`'s follow-up.
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
//! # Why the module is public and the cutter is not
//!
//! The rule above is a product decision and belongs where somebody can find it, so the module is
//! `pub` and [`MAX_CHARS`] is the one figure a caller sizing a response needs. `quote` itself stays
//! crate-private: its input is raw chunk text, and a public function taking document content and
//! returning document content is one that gets called from somewhere with no post-filter behind it.
//! The only caller is [`crate::lexical::candidates`], whose output is a `LexicalCandidates` that
//! nothing but the post-filter can consume.

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
pub(crate) fn quote(chunk: &str, query: &str) -> Option<String> {
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

    render(chunk, &chars, &window)
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

/// Builds the returned string: the window's characters verbatim, with `…` at each end that dropped
/// something.
///
/// "Dropped something" means a non-whitespace character, so a chunk that merely begins with a
/// newline is not reported as elided. The body is `trim`med, which can only remove whitespace the
/// window's own edges introduced.
fn render(chunk: &str, chars: &[(usize, char)], window: &Range<usize>) -> Option<String> {
    let body = slice(chunk, chars, window).trim();
    if body.is_empty() {
        return None;
    }

    let elided_before = chars.get(..window.start).is_some_and(has_text);
    let elided_after = chars.get(window.end..).is_some_and(has_text);

    let mut excerpt = String::with_capacity(body.len() + ELISION.len_utf8() * 2);
    if elided_before {
        excerpt.push(ELISION);
    }
    excerpt.push_str(body);
    if elided_after {
        excerpt.push(ELISION);
    }
    Some(excerpt)
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

    /// The body of an excerpt, with the elision marks removed. Used by the property assertions
    /// below, all of which are about the part that claims to come from the document.
    fn body(excerpt: &str) -> &str {
        excerpt.trim_matches(ELISION)
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
            excerpt.contains("7.2(b)"),
            "the excerpt was cut from the punctuation-stripped form: {excerpt:?}"
        );
    }

    /// The quotation contains the word that caused the hit. An excerpt that does not is a snippet of
    /// something else, which is the failure `ts_headline` over raw text produces silently.
    #[test]
    fn the_excerpt_contains_a_term_the_query_matched_on() {
        let excerpt = quote(LONG, "tantalum").expect("quotable");
        assert!(
            excerpt.to_lowercase().contains("tantalum"),
            "the excerpt does not contain the matched term: {excerpt:?}"
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
                excerpt.chars().count() <= MAX_CHARS + 2,
                "excerpt is {} characters, budget is {MAX_CHARS}",
                excerpt.chars().count()
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
        assert!(excerpt.chars().count() <= MAX_CHARS + 2);
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
            "the quotation starts inside a word: {excerpt:?}"
        );
        assert!(
            !(after.is_some_and(char::is_alphanumeric) && last.is_alphanumeric()),
            "the quotation ends inside a word: {excerpt:?}"
        );
    }

    /// Elision is reported where it happened and nowhere else. A chunk short enough to quote whole
    /// carries no marks at all, so `…` means something.
    #[test]
    fn elision_is_marked_only_at_an_end_where_text_was_actually_dropped() {
        let whole = quote("A short note about tantalum.", "tantalum").expect("quotable");
        assert_eq!(
            whole, "A short note about tantalum.",
            "nothing was elided, so nothing is marked"
        );

        let cut = quote(LONG, "tantalum").expect("quotable");
        assert!(cut.starts_with(ELISION) || cut.ends_with(ELISION), "text was dropped unmarked");
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
            excerpt.contains("tantalum allowance"),
            "the window was centred on the lone first occurrence: {excerpt:?}"
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
        assert!(excerpt.to_lowercase().contains("größe"));
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

    /// A chunk long enough that a window is a real cut.
    const LONG: &str = "Employees may claim the standard allowance each quarter, subject to \
        approval by their line manager and to the limits set out in the appendix. \
        The tantalum allowance is a separate entitlement and is paid annually, in arrears, \
        against receipts submitted before the end of the following quarter. \
        Nothing in this section affects the statutory minimum.";
}
