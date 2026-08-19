//! The identity layer: composed per request, over the base rendition, and never stored.
//!
//! `docs/06-SECURITY-DLP-ACCESS.md §5.1` states the problem this solves in one sentence: *"A
//! watermark identifies the viewer, so a naively cached watermarked page would either leak one
//! user's identity to another or defeat caching entirely."* The resolution is the two-layer split —
//! an identity-free base rendition that is cached, and this layer, which is not.
//!
//! # Why this cannot be cached, structurally
//!
//! Not "is not cached". *Cannot be.* The only thing this crate can write to the rendition store is
//! keyed by a [`RenditionKey`](crate::RenditionKey), and that type has three fields — version,
//! profile, generator — with nowhere to put a principal. There is no constructor that takes a
//! [`WatermarkFacts`], and no function anywhere that accepts a [`Watermarked`] and stores it.
//!
//! So a future edit that wanted to cache this would have to widen `RenditionKey` first, and that is
//! a diff whose whole purpose is legible in review. `crates/preview/tests/watermark.rs` asserts the
//! consequence — that two viewers of the same page share a base object key and differ only in the
//! layer composed over it — because a property nobody checks is a property that erodes.
//!
//! `docs/08-BYO-INFRA.md` previously listed `preview.watermark_cache: false` as a deployment
//! setting. It is not one any more, and `ENC-147` removed it: a control expressed as a default is a
//! control somebody can turn off, and there is no deployment for which turning this one off is
//! correct. Nothing in `crates/config` ever parsed it.
//!
//! # Escaping is a security property here, not tidiness
//!
//! The layer is SVG, and it embeds strings a user controls — their own display name, their email,
//! a classification label an administrator wrote. An unescaped `</text><script>` in a display name
//! is stored cross-site scripting delivered on the preview path, to every viewer of the document,
//! from a field the attacker sets on their own profile.
//!
//! [`escape_text`] is therefore applied to every interpolated value without exception, and
//! `tests/watermark.rs` attacks each field rather than trusting that. `docs/05-API.md §…` already
//! sends `Content-Security-Policy: sandbox` for HTML renditions; that is a second layer, and this
//! module does not lean on it.
//!
//! # Locale
//!
//! `docs/14-I18N-L10N.md`: *"Watermarks are rendered in the viewer's locale, with the timestamp in
//! the viewer's time zone."* This module therefore takes **pre-formatted, pre-localized** strings
//! and interpolates them. It does not format a date, choose a word, or decide a direction — the
//! caller does, from the catalog, because a wording decision inside a rendering primitive is one
//! the catalog cannot reach.

use core::fmt;

use crate::model::RenditionProfile;

/// What the layer states about the viewer and the document.
///
/// The five fields `docs/06 §5.1` names — user, email, timestamp, file id, session id,
/// classification — plus nothing. A field added here is a field that appears on every watermarked
/// page in the product, so the list is deliberately short and deliberately the document's.
///
/// Every string is **already localized and already formatted**. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatermarkFacts {
    /// The viewer's display name, as they would recognise it.
    pub viewer_name: String,
    /// The viewer's email — the part that makes a leaked screenshot attributable to a person
    /// rather than to a name several people share.
    pub viewer_email: String,
    /// When this view happened, formatted in the viewer's locale and time zone.
    pub issued_at: String,
    /// The file, so a photographed screen still identifies the document.
    pub file_reference: String,
    /// The session, so a leak is attributable to one sign-in rather than to an account.
    pub session_reference: String,
    /// The classification label, already localized.
    ///
    /// `None` for unclassified content: an empty line is better than the word "None" repeated
    /// across a page, and `docs/09-UX-WHITE-LABELING.md` treats classification colour as locked
    /// precisely because the label carries meaning.
    pub classification: Option<String>,
}

/// A composed identity layer.
///
/// Carries SVG, meant to be applied over a base rendition in the response stream. Deliberately not
/// `Clone` and deliberately not accepted by anything that writes to the rendition store — see the
/// module documentation for why that is the guarantee rather than a convention.
#[derive(Debug)]
#[must_use = "a composed watermark that is not applied is an unsatisfied Obligation::Watermark, \
              which docs/03-LLD.md §12 requires to fail the operation rather than be dropped"]
pub struct Watermarked {
    svg: String,
}

impl Watermarked {
    /// The overlay markup.
    #[must_use]
    pub fn svg(&self) -> &str {
        &self.svg
    }

    /// The overlay as bytes, for writing into a response.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.svg.into_bytes()
    }
}

/// How the layer is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatermarkStyle {
    /// Page width the overlay is sized for, in SVG user units.
    pub width: u32,
    /// Page height.
    pub height: u32,
    /// Opacity in percent. Low enough to read the document through, high enough to survive a
    /// photograph of a screen — which is the threat `docs/06 §5.2` is honest about not preventing.
    pub opacity_percent: u8,
    /// Degrees of rotation for the repeated text.
    pub rotation_degrees: i16,
}

impl WatermarkStyle {
    /// A sensible default for a portrait page.
    pub const DEFAULT: Self =
        Self { width: 1_240, height: 1_754, opacity_percent: 18, rotation_degrees: -30 };
}

impl Default for WatermarkStyle {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Builds the identity layer for one request.
///
/// Takes no store, no connection and no cache — see the module documentation. The only thing it can
/// do with its output is return it.
///
/// `profile` selects the geometry only; the facts stated are the same for every profile, because a
/// watermark that says less on a thumbnail is a watermark with a smaller version to screenshot.
pub fn compose(
    facts: &WatermarkFacts,
    style: WatermarkStyle,
    profile: RenditionProfile,
) -> Watermarked {
    let lines: Vec<String> = [
        Some(facts.viewer_name.as_str()),
        Some(facts.viewer_email.as_str()),
        Some(facts.issued_at.as_str()),
        Some(facts.file_reference.as_str()),
        Some(facts.session_reference.as_str()),
        facts.classification.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|line| !line.is_empty())
    .map(escape_text)
    .collect();

    // Tiled rather than a single centred stamp: a single stamp is croppable, and the whole point of
    // the layer is that a fragment of a screenshot still names who leaked it.
    let (step_x, step_y) = match profile {
        RenditionProfile::Thumb => (style.width / 2, style.height / 2),
        _ => (style.width / 3, style.height / 4),
    };
    let step_x = step_x.max(1);
    let step_y = step_y.max(1);

    let mut svg = String::with_capacity(1024);
    // `pointer-events="none"` so the overlay never eats a click meant for the document beneath, and
    // `aria-hidden` so a screen reader announces the document rather than the stamp repeated
    // thirty times — the text is a deterrent for whoever photographs the screen, not content.
    append(
        &mut svg,
        format_args!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" aria-hidden="true" style="pointer-events:none">"#,
            w = style.width,
            h = style.height
        ),
    );
    append(
        &mut svg,
        // `r##` rather than `r#`: the colour literal contains `"#`, which would close a
        // single-hash raw string in the middle of the attribute.
        format_args!(
            r##"<g fill="#404040" fill-opacity="{opacity}%" font-family="sans-serif" font-size="16">"##,
            opacity = style.opacity_percent.min(100)
        ),
    );

    let mut y = step_y / 2;
    while y < style.height {
        let mut x = step_x / 2;
        while x < style.width {
            append(
                &mut svg,
                format_args!(
                    r#"<text transform="translate({x} {y}) rotate({rot})">"#,
                    rot = style.rotation_degrees
                ),
            );
            for (index, line) in lines.iter().enumerate() {
                let dy = if index == 0 { 0 } else { 18 };
                append(&mut svg, format_args!(r#"<tspan x="0" dy="{dy}">{line}</tspan>"#));
            }
            svg.push_str("</text>");
            x += step_x;
        }
        y += step_y;
    }

    svg.push_str("</g></svg>");
    Watermarked { svg }
}

/// Appends formatted output to a `String`.
///
/// `write!` yields a `Result` even though `String`'s [`fmt::Write`] is infallible — its `write_str`
/// returns `Ok(())` unconditionally. The workspace denies `let _ = <must_use>`, which is the lint
/// guarding `PolicyDecision` (`plans/M0-FOUNDATIONS.md` D2), and it is right to refuse to
/// distinguish *"this Result cannot fail"* from *"I did not think about this Result"*. So the
/// infallibility is asserted once, here, rather than waved through at every call site.
fn append(target: &mut String, args: fmt::Arguments<'_>) {
    if fmt::Write::write_fmt(target, args).is_err() {
        // Dead as written. If a future `String` could fail, silently emitting a partial watermark
        // would be worse than a loud stop in the build that introduced it.
        debug_assert!(false, "writing into a String returned Err");
    }
}

/// Escapes a value for interpolation into SVG text content.
///
/// Applied to **every** interpolated value with no exceptions, because the one field somebody
/// decides is safe — an email, surely — is the field an attacker uses. The five XML predefined
/// entities, plus control characters dropped rather than encoded: nothing legitimate in a display
/// name is a `NUL` or an escape, and a bare control character in markup is a parser-differential
/// waiting to be found.
#[must_use]
pub fn escape_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 16);
    for character in raw.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Tab and newline are legitimate whitespace in a name in some scripts; the rest are
            // not, and are dropped rather than escaped so no decoder can reconstitute them.
            c if c.is_control() && c != '\t' && c != '\n' => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_xml_metacharacter_is_escaped() {
        assert_eq!(escape_text("a&b"), "a&amp;b");
        assert_eq!(escape_text("<script>"), "&lt;script&gt;");
        assert_eq!(escape_text(r#"say "hi""#), "say &quot;hi&quot;");
        assert_eq!(escape_text("it's"), "it&apos;s");
    }

    #[test]
    fn control_characters_are_dropped_rather_than_encoded() {
        // Encoded, a decoder somewhere downstream can turn them back into the thing they were.
        assert_eq!(escape_text("na\u{0}me"), "name");
        assert_eq!(escape_text("na\u{1b}[31mme"), "na[31mme");
        // Ordinary whitespace survives: a name containing a tab is odd, not hostile.
        assert_eq!(escape_text("a\tb\nc"), "a\tb\nc");
    }

    #[test]
    fn non_ascii_names_are_left_intact() {
        // `docs/14-I18N-L10N.md`: watermarks render in the viewer's locale. An escaper that
        // mangled non-Latin scripts would make the layer unreadable for most of the world.
        assert_eq!(escape_text("陳大文"), "陳大文");
        assert_eq!(escape_text("Ægir Þórsdóttir"), "Ægir Þórsdóttir");
        assert_eq!(escape_text("محمد"), "محمد");
    }
}
