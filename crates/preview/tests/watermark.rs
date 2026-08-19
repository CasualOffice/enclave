//! The identity layer: composed per request, never cached, and never a script.
//!
//! Three properties, in the order they would hurt if broken.
//!
//! 1. **Nothing identity-bearing reaches the rendition store.** `docs/06 §5.1`. A cached
//!    watermarked page leaks one viewer's identity to the next.
//! 2. **A user-controlled string cannot become markup.** The layer embeds a display name and an
//!    email into SVG. Unescaped, a display name is stored XSS delivered on the preview path — from
//!    a field the attacker sets on their own profile, to every viewer of the document.
//! 3. **Two viewers get different layers.** Otherwise the watermark identifies nobody, and every
//!    assertion above is about a control that does not do anything.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use enclave_core::VersionId;
use enclave_preview::{
    compose, GeneratorVersion, RenditionKey, RenditionProfile, WatermarkFacts, WatermarkStyle,
};

fn facts(name: &str, email: &str) -> WatermarkFacts {
    WatermarkFacts {
        viewer_name: name.to_owned(),
        viewer_email: email.to_owned(),
        issued_at: "19 August 2026 at 14:07 GMT+1".to_owned(),
        file_reference: "Q3-forecast.xlsx".to_owned(),
        session_reference: "sess-4417".to_owned(),
        classification: Some("Confidential".to_owned()),
    }
}

/// Every interpolated field is attacked, not just the one that looks dangerous.
///
/// The field somebody decides is safe — an email, surely; a classification label, an administrator
/// wrote that — is the field that carries the payload. So each is tested with the same escape, and
/// the assertion is on the *rendered output* rather than on the escaper in isolation.
#[test]
fn no_field_can_inject_markup() {
    const PAYLOAD: &str = r#"</text></g></svg><script>alert(1)</script>"#;

    let variants = [
        ("viewer_name", WatermarkFacts { viewer_name: PAYLOAD.to_owned(), ..facts("n", "e") }),
        ("viewer_email", WatermarkFacts { viewer_email: PAYLOAD.to_owned(), ..facts("n", "e") }),
        ("issued_at", WatermarkFacts { issued_at: PAYLOAD.to_owned(), ..facts("n", "e") }),
        (
            "file_reference",
            WatermarkFacts { file_reference: PAYLOAD.to_owned(), ..facts("n", "e") },
        ),
        (
            "session_reference",
            WatermarkFacts { session_reference: PAYLOAD.to_owned(), ..facts("n", "e") },
        ),
        (
            "classification",
            WatermarkFacts { classification: Some(PAYLOAD.to_owned()), ..facts("n", "e") },
        ),
    ];

    for (field, facts) in variants {
        let svg = compose(&facts, WatermarkStyle::DEFAULT, RenditionProfile::PagePng1x);
        let markup = svg.svg();

        assert!(
            !markup.contains("<script"),
            "`{field}` injected a script element into the overlay"
        );
        assert!(
            !markup.contains("</svg><"),
            "`{field}` closed the overlay early and appended to it"
        );
        // The payload must still be *present*, escaped — a watermark that silently dropped a name
        // it found suspicious would be a watermark an attacker can make say nothing by choosing a
        // hostile display name.
        assert!(
            markup.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "`{field}` was dropped rather than escaped, so the layer can be blanked on demand"
        );
    }
}

/// The layer names the viewer, so two viewers must not receive the same layer.
#[test]
fn two_viewers_of_the_same_page_get_different_layers() {
    let style = WatermarkStyle::DEFAULT;
    let one = compose(&facts("Ada Lovelace", "ada@example.test"), style, RenditionProfile::Thumb);
    let two = compose(&facts("Alan Turing", "alan@example.test"), style, RenditionProfile::Thumb);

    assert_ne!(one.svg(), two.svg());
    assert!(one.svg().contains("Ada Lovelace"));
    assert!(!one.svg().contains("Alan Turing"));
}

/// The base rendition both viewers share is keyed by nothing that names either of them.
///
/// This is the assertion behind D16. The two layers above differ; the object underneath them is one
/// object, and its key is the whole reason that is safe.
#[test]
fn the_base_object_both_viewers_share_is_keyed_without_them() {
    let version = VersionId::new_v7();
    let generator = GeneratorVersion::new("preview/1.0");

    // The same key, arrived at independently, for two different viewers — because there is no way
    // to involve a viewer in constructing one. `RenditionKey::new` takes three arguments and none
    // of them is a principal; that is the guarantee, and this test is what notices if a fourth
    // argument ever appears.
    let for_ada = RenditionKey::new(version, RenditionProfile::PagePng1x, generator);
    let for_alan = RenditionKey::new(version, RenditionProfile::PagePng1x, generator);
    assert_eq!(for_ada, for_alan);
}

/// A watermark is a deterrent against a photograph of a screen, so a crop must still name someone.
///
/// `docs/06 §5.2` is honest that the product cannot prevent screenshots. What it can do is make an
/// escaped fragment attributable, and a single centred stamp is croppable in a way a tiled one is
/// not.
#[test]
fn the_layer_is_tiled_rather_than_a_single_stamp() {
    let composed = compose(
        &facts("Ada Lovelace", "ada@example.test"),
        WatermarkStyle::DEFAULT,
        RenditionProfile::PagePng1x,
    );
    let stamps = composed.svg().matches("<text ").count();
    assert!(stamps > 4, "only {stamps} stamps — a crop of this page would name nobody");
}

/// Unclassified content gets no classification line rather than the word for "nothing".
#[test]
fn an_unclassified_document_omits_the_line_entirely() {
    let unclassified =
        WatermarkFacts { classification: None, ..facts("Ada Lovelace", "ada@example.test") };
    let composed = compose(&unclassified, WatermarkStyle::DEFAULT, RenditionProfile::Thumb);
    assert!(composed.svg().contains("Ada Lovelace"));
    assert!(!composed.svg().contains("Confidential"));
}

/// The overlay never intercepts input meant for the document beneath it.
#[test]
fn the_overlay_is_inert() {
    let composed = compose(
        &facts("Ada Lovelace", "ada@example.test"),
        WatermarkStyle::DEFAULT,
        RenditionProfile::Thumb,
    );
    assert!(composed.svg().contains("pointer-events:none"));
    // Announced to nobody: a screen reader should read the document, not the stamp thirty times.
    assert!(composed.svg().contains(r#"aria-hidden="true""#));
}
